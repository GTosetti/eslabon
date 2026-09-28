"""Colector de GuardDog (Datadog): heurísticas sobre el código y los metadatos del paquete.

GuardDog descarga el paquete del registro y lo analiza de forma ESTÁTICA (reglas YARA
sobre el código, más reglas de metadatos). Nunca lo instala ni lo ejecuta.

En Windows solo funciona dentro de Docker (ver docs/instalacion.md):
    ESLABON_GUARDDOG="docker run --rm ghcr.io/datadog/guarddog:v3.2.0"
Importante: la etiqueta ":latest" de esa imagen es todavía la versión 2.x.

Formato de salida (guarddog 3.2.0, `--output-format json`):
    {"package": ..., "issues": N, "errors": {...},
     "results": {regla: null | "mensaje" | {} | [ {location, code, match, message} ]},
     "risk_score": {"score": 0-10, "label": ...}, "risks": [ {threat_rule, severity, ...} ]}
Una regla de metadatos que coincide vale un texto; una regla YARA, una lista no vacía.
"""

from __future__ import annotations

from eslabon.colectores.base import Colector, Contexto, en_paralelo, entregar
from eslabon.ejecutor import Herramienta, HerramientaFallo, ejecutar_json
from eslabon.modelos import Evidencia, Finding, Paquete
from eslabon.senales import CATALOGO, evidencia, hallazgo_si_hay_senal

GUARDDOG = Herramienta(
    "guarddog", "guarddog", "ESLABON_GUARDDOG",
    ayuda=("En Windows GuardDog corre en Docker: definí ESLABON_GUARDDOG=\"docker run --rm "
           "ghcr.io/datadog/guarddog:v3.2.0@sha256:...\" en ESTA terminal o como variable de "
           "usuario (ver docs/instalacion.md). Para no usarlo: --guarddog-max 0"))

# GuardDog descarga y analiza cada paquete: es caro. Por defecto se analizan los primeros
# N del inventario, y si se omiten paquetes se avisa en fuentes_omitidas.
MAX_PAQUETES_POR_DEFECTO = 20

# Salida 1 = hubo hallazgos (con --exit-non-zero-on-finding) o hubo un error. Se distingue
# porque en el segundo caso no hay JSON en la salida estándar.
_CODIGOS_OK = (0, 1)

_PESO_SEVERIDAD = {"high": "guarddog-amenaza-alta", "medium": "guarddog-amenaza-media",
                   "low": "guarddog-amenaza-baja"}


class ColectorGuardDog(Colector):
    nombre = "guarddog"

    def __init__(self, max_paquetes: int = MAX_PAQUETES_POR_DEFECTO) -> None:
        if max_paquetes < 0:
            raise ValueError("max_paquetes no puede ser negativo")
        self.max_paquetes = max_paquetes

    def recolectar(self, paquetes: list[Paquete], ctx: Contexto) -> list[Finding]:
        elegidos = paquetes[: self.max_paquetes]
        # Menos hilos: cada análisis descarga un paquete y arranca un proceso (o contenedor).
        resultados, errores = en_paralelo(elegidos, lambda p: _analizar(p, ctx), hilos=4)
        avisos = []
        if len(paquetes) > len(elegidos):
            avisos.append(f"se analizaron {len(elegidos)} de {len(paquetes)} paquetes "
                          f"(límite --guarddog-max)")
        return entregar([h for h in resultados if h], errores, len(elegidos), avisos)


def _analizar(p: Paquete, ctx: Contexto) -> Finding | None:
    # Las opciones van antes y el nombre del paquete después de "--": aunque un nombre
    # empezara por "-", GuardDog (click) nunca lo leería como una opción.
    doc = ejecutar_json(GUARDDOG, [p.ecosistema.tipo_purl, "scan", f"--version={p.version}",
                                   "--output-format", "json", "--", p.nombre],
                        timeout=ctx.timeout, codigos_ok=_CODIGOS_OK)
    if not doc:
        raise HerramientaFallo("guarddog no devolvió JSON")
    if "results" not in doc:  # p. ej. falló la descarga del paquete
        raise HerramientaFallo("; ".join(f"{k}: {v}" for k, v in (doc.get("errors") or {}).items()))
    # Las capacidades ("puede abrir conexiones", "puede borrar ficheros") describen a casi
    # cualquier paquete sano (grabación real: requests y lodash): son señales de contexto.
    return hallazgo_si_hay_senal(p, evidencias_de_guarddog(doc))


def evidencias_de_guarddog(doc: dict) -> list[Evidencia]:
    fuente = ColectorGuardDog.nombre
    severidades = {r.get("threat_rule"): r.get("severity") for r in doc.get("risks") or []}
    evidencias = []

    etiqueta = (doc.get("risk_score") or {}).get("label", "")
    if f"guarddog-veredicto-{etiqueta}" in CATALOGO:
        puntaje = doc["risk_score"].get("score")
        evidencias.append(evidencia(fuente, f"guarddog-veredicto-{etiqueta}",
                                    f"puntaje de riesgo {puntaje}/10",
                                    datos={"risk_score": doc["risk_score"]}))

    for regla, valor in sorted((doc.get("results") or {}).items()):
        if isinstance(valor, str) and valor:  # regla de metadatos que coincidió
            clave = f"guarddog-{regla}"
            if clave in CATALOGO:
                evidencias.append(evidencia(fuente, clave, valor, datos={"regla": regla}))
        elif isinstance(valor, list) and valor:  # regla YARA sobre el código
            if regla.startswith("capability-"):
                clave = "guarddog-capacidad"
            else:
                clave = _PESO_SEVERIDAD.get(severidades.get(regla, ""), "guarddog-amenaza-media")
            primero = valor[0]
            evidencias.append(evidencia(
                fuente, clave,
                f"{regla} en {primero.get('location', '?')}: {primero.get('message', '')}",
                datos={"regla": regla, "coincidencias": valor[:5]},
            ))
    return evidencias
