"""Correlador: une lo que dicen las distintas fuentes sobre un mismo paquete.

Pasos, para cada paquete@versión (la lógica completa está en docs/scoring.md):

1. Unir por alias: dos hallazgos que comparten algún ID (CVE, GHSA, MAL, PYSEC...)
   son el mismo problema visto desde dos bases de datos.
2. Si algo dice que el paquete es MALICIOSO, todo lo que apunte a compromiso
   (maliciosos, sospechosos y riesgo de origen) se funde en UN solo hallazgo: un
   paquete no es "malicioso tres veces".
3. Las señales débiles (sospechoso, riesgo de origen) se funden en un hallazgo
   por paquete, para que se refuercen entre sí.
4. Confianza: dentro de cada fuente se toma su señal más fuerte (las señales de
   una misma herramienta no son independientes). Entre fuentes distintas se
   combinan como evidencia independiente ("OR ruidoso"):
       confianza = 1 − Π (1 − p_fuente)
5. Severidad: malicioso → crítica; vulnerabilidad → la del CVSS; señales débiles →
   por bandas de confianza.
"""

from __future__ import annotations

import math
from collections import defaultdict

from eslabon.modelos import Evidencia, Finding, Severidad, Tipo, ordenar_ids
from eslabon.senales import tipo_dominante

# Bandas de severidad para hallazgos basados en señales débiles (docs/scoring.md).
BANDAS_CONFIANZA = [
    (0.80, Severidad.ALTA),
    (0.50, Severidad.MEDIA),
    (0.25, Severidad.BAJA),
    (0.0, Severidad.INFO),
]

_COMPROMISO = {Tipo.MALICIOSO, Tipo.SOSPECHOSO, Tipo.RIESGO_ORIGEN}


def correlacionar(hallazgos: list[Finding]) -> list[Finding]:
    por_paquete: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    for h in hallazgos:
        por_paquete[h.clave].append(h)

    resultado = []
    for grupo in por_paquete.values():
        componentes = _unir_por_alias(grupo)
        # Todo lo que apunta a compromiso (malicioso, sospechoso, riesgo de origen) se funde
        # en un solo hallazgo por paquete; las vulnerabilidades quedan aparte.
        compromiso = [c for c in componentes if _tipo(c) in _COMPROMISO]
        if len(compromiso) > 1:
            resto = [c for c in componentes if _tipo(c) not in _COMPROMISO]
            componentes = [[h for c in compromiso for h in c], *resto]
        resultado.extend(fusionar(c) for c in componentes)

    resultado.sort(key=lambda h: (-h.severidad.rango, -h.confianza, h.clave, h.ids[0]))
    return resultado


def _tipo(componente: list[Finding]) -> Tipo:
    return tipo_dominante([h.tipo for h in componente])


def _unir_por_alias(hallazgos: list[Finding]) -> list[list[Finding]]:
    """Agrupa hallazgos que comparten algún ID (componentes conexos, con union-find)."""
    padre = list(range(len(hallazgos)))

    def raiz(i: int) -> int:
        while padre[i] != i:
            padre[i] = padre[padre[i]]
            i = padre[i]
        return i

    primero_con_id: dict[str, int] = {}
    for i, h in enumerate(hallazgos):
        for id_ in h.ids:
            if id_ in primero_con_id:
                padre[raiz(i)] = raiz(primero_con_id[id_])
            else:
                primero_con_id[id_] = i

    grupos: dict[int, list[Finding]] = defaultdict(list)
    for i, h in enumerate(hallazgos):
        grupos[raiz(i)].append(h)
    return list(grupos.values())


def confianza_combinada(evidencias: list[Evidencia]) -> tuple[float, dict[str, float]]:
    """OR ruidoso entre fuentes, tomando la señal más fuerte de cada fuente."""
    por_fuente: dict[str, float] = {}
    for e in evidencias:
        if e.peso is not None:
            por_fuente[e.fuente] = max(por_fuente.get(e.fuente, 0.0), e.peso)
    return round(1.0 - math.prod(1.0 - p for p in por_fuente.values()), 4), por_fuente


def severidad_por_confianza(confianza: float) -> Severidad:
    return next(sev for umbral, sev in BANDAS_CONFIANZA if confianza >= umbral)


def fusionar(componente: list[Finding]) -> Finding:
    base = componente[0]
    evidencias = _sin_duplicados([e for h in componente for e in h.evidencia])
    tipo = tipo_dominante([h.tipo for h in componente])
    confianza, por_fuente = confianza_combinada(evidencias)

    if tipo is Tipo.MALICIOSO:
        severidad = Severidad.CRITICA
    elif tipo is Tipo.VULN:
        severidad = max((h.severidad for h in componente), key=lambda s: s.rango)
    else:
        severidad = severidad_por_confianza(confianza)

    # Todo hallazgo, de una fuente o de varias, lleva la misma explicación (con la fórmula).
    # Para vulnerabilidades se añade el razonamiento del colector (el CVSS y su banda).
    explicacion = _explicar(tipo, confianza, por_fuente, evidencias, severidad)
    if tipo is Tipo.VULN:
        explicacion += " " + " ".join(dict.fromkeys(h.explicacion for h in componente))

    principal = next((h for h in componente if h.tipo is tipo), base)
    return Finding(
        ecosistema=base.ecosistema,
        paquete=base.paquete,
        version=base.version,
        tipo=tipo,
        ids=ordenar_ids([i for h in componente for i in h.ids]),
        titulo=principal.titulo,
        severidad=severidad,
        confianza=confianza,
        evidencia=evidencias,
        explicacion=explicacion,
        # Vulnerabilidades: la versión corregida que calculó el colector. Resto: por tipo.
        remediacion=next((h.remediacion for h in componente
                          if tipo is Tipo.VULN and h.remediacion), REMEDIACION.get(tipo)),
    )


def _sin_duplicados(evidencias: list[Evidencia]) -> list[Evidencia]:
    vistas: dict[tuple[str, str], Evidencia] = {}
    for e in evidencias:
        vistas.setdefault((e.fuente, e.descripcion), e)
    return list(vistas.values())


def _explicar(tipo: Tipo, confianza: float, por_fuente: dict[str, float],
              evidencias: list[Evidencia], severidad: Severidad) -> str:
    formula = " · ".join(f"(1 − {p:.2f})" for p in por_fuente.values())
    senales = "; ".join(f"[{e.fuente}] {e.descripcion} (peso {e.peso:.2f})"
                        for e in evidencias if e.peso is not None)
    return (
        f"Clasificado como {tipo.value}: {len(evidencias)} señal(es) de "
        f"{len(por_fuente)} fuente(s) independiente(s) ({', '.join(por_fuente)}). "
        f"Por fuente se toma la señal más fuerte y se combinan como evidencia "
        f"independiente: confianza = 1 − {formula} = {confianza:.3f}. "
        f"Severidad {severidad.value}: {MOTIVO_SEVERIDAD[tipo]}. Señales: {senales}."
    )


# Regla 4 de docs/scoring.md: de dónde sale la severidad según el tipo.
MOTIVO_SEVERIDAD = {
    Tipo.MALICIOSO: "un paquete malicioso siempre es crítico",
    Tipo.VULN: "la del CVSS del aviso (bandas de FIRST)",
    Tipo.SOSPECHOSO: "por bandas de confianza",
    Tipo.RIESGO_ORIGEN: "por bandas de confianza",
}

REMEDIACION = {
    Tipo.SOSPECHOSO: ("Revisar el paquete antes de usarlo: fijar una versión anterior "
                      "conocida y comprobar sus cambios y su mantenedor."),
    Tipo.RIESGO_ORIGEN: ("Evaluar la salud del repositorio de origen; considerar fijar "
                         "versiones por hash y vigilar las nuevas publicaciones."),
    Tipo.MALICIOSO: ("Retirar el paquete de inmediato y rotar los secretos del entorno "
                     "donde se instaló."),
}
