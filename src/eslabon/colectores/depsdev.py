"""Colector de deps.dev: el estado de cada paquete en su registro (npm, PyPI).

No mira vulnerabilidades (eso lo hace OSV, y deps.dev las toma de la misma base: contarlas
dos veces inflaría la confianza). Mira la historia de publicación:
- ¿la versión sigue en el registro? Los registros retiran las versiones maliciosas;
- ¿npm lo reemplazó por un tapón "0.0.1-security"? Es lo que hace al retirar malware;
- ¿la versión es muy nueva, o reactiva un paquete dormido? Es el patrón típico de una
  cuenta de mantenedor robada.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from eslabon.colectores.base import Colector, Contexto, en_paralelo, entregar
from eslabon.modelos import Finding, Paquete, es_tapon_seguridad
from eslabon.senales import evidencia, hallazgo_de_senales

# Umbrales (justificados en docs/scoring.md).
DIAS_VERSION_RECIENTE = 14
DIAS_INACTIVIDAD_PREVIA = 365


class ColectorDepsDev(Colector):
    nombre = "depsdev"

    def recolectar(self, paquetes: list[Paquete], ctx: Contexto) -> list[Finding]:
        resultados, errores = en_paralelo(paquetes, lambda p: analizar_paquete(p, ctx))
        return entregar([h for h in resultados if h], errores, len(paquetes))


def analizar_paquete(p: Paquete, ctx: Contexto) -> Finding | None:
    evidencias = []
    fuente = ColectorDepsDev.nombre
    url = f"https://deps.dev/{p.ecosistema.tipo_purl}/{p.nombre}"
    info = ctx.depsdev.paquete(p)

    if info is None:
        evidencias.append(evidencia(fuente, "depsdev-paquete-inexistente",
                                    f"{p.nombre} no figura en {p.ecosistema.value}"))
        return hallazgo_de_senales(p, evidencias)

    versiones = info.get("versions", [])
    publicadas = [v["versionKey"]["version"] for v in versiones]
    if publicadas and all(es_tapon_seguridad(p.ecosistema, v) for v in publicadas):
        evidencias.append(evidencia(fuente, "depsdev-tapon-seguridad",
                                    f"única versión disponible: {', '.join(publicadas)}",
                                    referencia=url, datos={"versiones": publicadas}))

    detalle = ctx.depsdev.version(p)
    if detalle is None:
        if not evidencias:  # el tapón ya explica por qué falta la versión
            evidencias.append(evidencia(fuente, "depsdev-version-retirada",
                                        f"{p.version} no está entre las "
                                        f"{len(publicadas)} versiones publicadas",
                                        referencia=url))
        return hallazgo_de_senales(p, evidencias)

    publicada = _fecha(detalle.get("publishedAt"))
    if publicada:
        edad = ctx.ahora - publicada
        if edad < timedelta(days=DIAS_VERSION_RECIENTE):
            evidencias.append(evidencia(fuente, "depsdev-version-reciente",
                                        f"publicada el {publicada.date()} "
                                        f"(hace {edad.days} días)",
                                        referencia=url, datos={"publicada": str(publicada)}))
        anterior = _publicacion_anterior(versiones, publicada)
        if anterior and publicada - anterior > timedelta(days=DIAS_INACTIVIDAD_PREVIA):
            evidencias.append(evidencia(fuente, "depsdev-reactivacion",
                                        f"la publicación anterior fue el {anterior.date()} "
                                        f"({(publicada - anterior).days} días antes)",
                                        referencia=url))
    if detalle.get("isDeprecated"):
        evidencias.append(evidencia(fuente, "depsdev-obsoleto",
                                    detalle.get("deprecatedReason") or "sin motivo indicado",
                                    referencia=url))

    return hallazgo_de_senales(p, evidencias) if evidencias else None


def _fecha(texto: str | None) -> datetime | None:
    if not texto:
        return None
    return datetime.fromisoformat(texto)  # desde Python 3.11 acepta el sufijo "Z"


def _publicacion_anterior(versiones: list[dict], publicada: datetime) -> datetime | None:
    fechas = [f for v in versiones if (f := _fecha(v.get("publishedAt"))) and f < publicada]
    return max(fechas, default=None)
