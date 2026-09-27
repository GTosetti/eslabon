"""Salida SARIF 2.1.0: el formato estándar (OASIS) de resultados de análisis de seguridad.

Lo entienden GitHub Code Scanning, Azure DevOps y muchos IDEs. Decisiones:
- Reglas (`rules[]`):
  * vulnerabilidad → una regla por aviso (mismo aviso = mismo CVSS = misma severidad);
  * malicioso / sospechoso / riesgo de origen → una regla por tipo y severidad
    (p. ej. ESL-SOSPECHOSO-ALTA). GitHub toma la severidad de la regla, así que dos
    paquetes con severidades distintas no pueden compartirla.
- La severidad va en la regla (`defaultConfiguration.level`) Y en cada resultado
  (`level`): algunos consumidores leen solo una de las dos.
- `properties.security-severity` es el número (0-10) que GitHub usa para ordenar.
- `partialFingerprints` ha de ser ESTABLE entre escaneos, o GitHub cierra la alerta y abre
  otra. Por eso no usa el ID principal (cambia si se publica un CVE para un GHSA, o si una
  señal aparece o desaparece):
  * compromiso → el paquete (el correlador deja un único hallazgo de compromiso por
    paquete, así que si pasa de sospechoso a malicioso, la alerta sube de nivel);
  * vulnerabilidad → el ID de la familia más estable (GHSA, luego PYSEC, luego CVE).
- La "ubicación" es el manifiesto o lockfile donde se declaró el paquete, relativa al
  directorio desde el que se ejecuta eslabon (normalmente la raíz del repositorio:
  `%SRCROOT%`). Si no se puede expresar así (o el paquete vino por línea de comandos),
  se usa una ubicación lógica con su purl.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import quote

from eslabon import __version__
from eslabon.correlador import MOTIVO_SEVERIDAD
from eslabon.modelos import Finding, ResultadoScan, Severidad, Tipo

ESQUEMA = "https://json.schemastore.org/sarif-2.1.0.json"
RAIZ = "%SRCROOT%"

_NIVEL = {
    Severidad.CRITICA: "error",
    Severidad.ALTA: "error",
    Severidad.MEDIA: "warning",
    Severidad.BAJA: "note",
    Severidad.INFO: "note",
}
# Escala de GitHub: >= 9 critical, >= 7 high, >= 4 medium, > 0 low.
_SECURITY_SEVERITY = {
    Severidad.CRITICA: "9.5",
    Severidad.ALTA: "8.0",
    Severidad.MEDIA: "5.5",
    Severidad.BAJA: "2.0",
    Severidad.INFO: "0.0",
}
_DESCRIPCION_COMPROMISO = {
    Tipo.MALICIOSO: "Paquete malicioso en las dependencias",
    Tipo.SOSPECHOSO: "Dependencia sospechosa: señales de compromiso correlacionadas",
    Tipo.RIESGO_ORIGEN: "Repositorio de origen débil (compromiso previo a la publicación)",
}
_FAMILIAS_ESTABLES = ("GHSA-", "PYSEC-", "MAL-", "CVE-")


def renderizar(resultado: ResultadoScan) -> str:
    return json.dumps(construir(resultado), indent=2, ensure_ascii=False)


def construir(resultado: ResultadoScan) -> dict:
    ubicaciones = {p.clave: p for p in resultado.paquetes}
    raiz = Path.cwd().resolve()
    base = _directorio_escaneado(resultado.objetivo)
    reglas: dict[str, dict] = {}
    indices: dict[str, int] = {}
    resultados = []
    for h in resultado.hallazgos:
        id_regla = regla_de(h)
        if id_regla not in reglas:
            indices[id_regla] = len(reglas)
            reglas[id_regla] = _regla(id_regla, h)
        paquete = ubicaciones.get(h.clave)
        uris = [u for f in (paquete.ubicaciones if paquete else [])
                if (u := _uri(f, base, raiz))]
        resultados.append(_resultado(h, id_regla, indices[id_regla], uris))

    return {
        "$schema": ESQUEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "eslabon",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": list(reglas.values()),
            }},
            "invocations": [{
                # Si el análisis quedó degradado (sin inventario o sin OSV), NO fue un éxito:
                # un SARIF "exitoso" con 0 resultados haría que GitHub cerrara las alertas.
                "executionSuccessful": resultado.completo,
                "toolExecutionNotifications": [
                    {"level": "warning",
                     "message": {"text": f"Fuente omitida: {o.fuente}: {o.motivo}"}}
                    for o in resultado.fuentes_omitidas
                ],
            }],
            "results": resultados,
            "properties": {
                "objetivo": _objetivo_relativo(resultado.objetivo, raiz),
                "completo": resultado.completo,
                "fuentes_usadas": resultado.fuentes_usadas,
                "fuentes_omitidas": [o.model_dump() for o in resultado.fuentes_omitidas],
                "paquetes_inventariados": len(resultado.paquetes),
            },
        }],
    }


def id_estable(h: Finding) -> str:
    """El ID de aviso que menos cambia con el tiempo (los alias se van sumando)."""
    avisos = [i for i in h.ids if not i.startswith("ESL-")] or h.ids
    for familia in _FAMILIAS_ESTABLES:
        de_familia = sorted(i for i in avisos if i.startswith(familia))
        if de_familia:
            return de_familia[0]
    return sorted(avisos)[0]


def regla_de(h: Finding) -> str:
    if h.tipo is Tipo.VULN:
        return id_estable(h)
    base = f"ESL-{h.tipo.value.upper().replace('_', '-')}"
    return base if h.tipo is Tipo.MALICIOSO else f"{base}-{h.severidad.value.upper()}"


def huella(h: Finding) -> str:
    """Identificador estable del hallazgo, independiente de la máquina, la ruta y los alias."""
    ecosistema, nombre, version = h.clave
    que = id_estable(h) if h.tipo is Tipo.VULN else "compromiso"
    return hashlib.sha256(f"{ecosistema}|{nombre}|{version}|{que}".encode()).hexdigest()[:32]


def _regla(id_regla: str, h: Finding) -> dict:
    titulo = (h.titulo or id_regla) if h.tipo is Tipo.VULN else _DESCRIPCION_COMPROMISO[h.tipo]
    regla = {
        "id": id_regla,
        "name": re.sub(r"[^A-Za-z0-9]", "", id_regla),
        "shortDescription": {"text": titulo},
        "fullDescription": {"text": f"{titulo}. Severidad: {MOTIVO_SEVERIDAD[h.tipo]}."},
        "defaultConfiguration": {"level": _NIVEL[h.severidad]},
        "properties": {
            "tags": ["security", "supply-chain", h.tipo.value, *h.attack],
            "security-severity": _SECURITY_SEVERITY[h.severidad],
        },
    }
    if h.tipo is Tipo.VULN:
        regla["helpUri"] = f"https://osv.dev/vulnerability/{id_regla}"
    return regla


def _resultado(h: Finding, id_regla: str, indice_regla: int, uris: list[str]) -> dict:
    texto = f"{h.paquete}@{h.version}: {h.titulo or h.ids[0]}. {h.explicacion}"
    if h.remediacion:
        texto += f" Remediación: {h.remediacion}"
    return {
        "ruleId": id_regla,
        "ruleIndex": indice_regla,
        "level": _NIVEL[h.severidad],
        "message": {"text": texto},
        "locations": _ubicaciones(uris, h.purl),
        "partialFingerprints": {"eslabon/v1": huella(h)},
        "properties": {
            "purl": h.purl,
            "tipo": h.tipo.value,
            "severidad": h.severidad.value,
            "confianza": h.confianza,
            "ids": h.ids,
            "fuentes": h.fuentes,
            "attack": h.attack,
            "security-severity": _SECURITY_SEVERITY[h.severidad],
        },
    }


def _ubicaciones(uris: list[str], purl: str) -> list[dict]:
    logica = [{"fullyQualifiedName": purl, "kind": "module"}]
    if not uris:
        return [{"logicalLocations": logica}]
    return [{
        "physicalLocation": {
            "artifactLocation": {"uri": u, "uriBaseId": RAIZ},
            "region": {"startLine": 1},
        },
        "logicalLocations": logica,
    } for u in dict.fromkeys(uris)]


def _directorio_escaneado(objetivo: str) -> Path | None:
    ruta = Path(objetivo)
    if ruta.is_dir():
        return ruta.resolve()
    if ruta.is_file():
        return ruta.resolve().parent
    return None  # paquete suelto (purl)


def _relativa(ruta: Path, raiz: Path) -> str | None:
    """`ruta` relativa a `raiz`, con "/", o None si está fuera (resolve sigue los enlaces)."""
    ruta = ruta.resolve()
    return ruta.relative_to(raiz).as_posix() if ruta.is_relative_to(raiz) else None


def _uri(ubicacion: str, base: Path | None, raiz: Path) -> str | None:
    """Ruta de Syft (relativa a lo escaneado) → URI relativa a la raíz (%SRCROOT%).

    Devuelve None si no se puede expresar de forma segura (fuera de la raíz, unidad de
    Windows, o sin fichero).
    """
    if not ubicacion or ubicacion.startswith("("):
        return None
    relativa = ubicacion.replace("\\", "/").lstrip("/")
    if base is not None:
        # Si lo escaneado está fuera del directorio actual, queda relativa a lo escaneado.
        relativa = _relativa(base / relativa, raiz) or relativa
    partes = relativa.split("/")
    if not relativa or ".." in partes or re.match(r"^[A-Za-z]:", relativa):
        return None
    return quote(relativa, safe="/")


def _objetivo_relativo(objetivo: str, raiz: Path) -> str:
    """Sin rutas absolutas de la máquina local (el SARIF se suele subir a GitHub)."""
    ruta = Path(objetivo)
    if not ruta.exists():
        return objetivo  # purl
    return (_relativa(ruta, raiz) or ruta.name) or "."
