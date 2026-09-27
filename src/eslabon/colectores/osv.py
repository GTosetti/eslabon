"""Colector de OSV-Scanner: vulnerabilidades conocidas y paquetes maliciosos.

OSV (https://osv.dev) es una base de datos abierta que agrega avisos de muchas
fuentes: GitHub (GHSA), PyPA (PYSEC), NVD (CVE) y OpenSSF Malicious Packages (MAL).
El mismo problema puede tener un ID en cada una: esos son los "alias".
"""

from __future__ import annotations

import functools
import re

from eslabon.colectores.base import Colector, Contexto
from eslabon.ejecutor import Herramienta, HerramientaFallo, ejecutar_json
from eslabon.modelos import (
    Ecosistema,
    Finding,
    Paquete,
    Severidad,
    Tipo,
    normalizar_nombre,
    ordenar_ids,
)
from eslabon.sbom import escribir_cyclonedx
from eslabon.senales import confianza_de, evidencia, tipo_dominante

OSV_SCANNER = Herramienta("osv-scanner", "osv-scanner", "ESLABON_OSV_SCANNER")

# Códigos de salida documentados de osv-scanner: 0 = sin hallazgos, 1 = hay hallazgos,
# 128 = no encontró paquetes que analizar. eslabon siempre le pasa un SBOM con paquetes,
# así que 128 significa que NO entendió el SBOM: es un fallo, no un resultado limpio.
_CODIGOS_OK = (0, 1)

# Tipos de rango con versiones publicadas. Los rangos "GIT" usan hashes de commit.
_RANGOS_DE_VERSION = {"ECOSYSTEM", "SEMVER"}


class ColectorOSV(Colector):
    nombre = "osv"
    esencial = True  # es la fuente de avisos publicados (CVE y MAL-)

    def recolectar(self, paquetes: list[Paquete], ctx: Contexto) -> list[Finding]:
        sbom = ctx.dir_trabajo / "eslabon-osv.cdx.json"
        escribir_cyclonedx(paquetes, sbom)
        documento = ejecutar_json(OSV_SCANNER,
                                  ["scan", "source", "-L", str(sbom), "--format", "json"],
                                  timeout=ctx.timeout, codigos_ok=_CODIGOS_OK)
        if not documento:
            raise HerramientaFallo("osv-scanner no devolvió resultados (salida vacía)")
        return hallazgos_desde_osv(documento)


def hallazgos_desde_osv(documento: dict) -> list[Finding]:
    """Traduce la salida JSON de osv-scanner a Finding (uno por grupo de alias)."""
    hallazgos: list[Finding] = []
    for resultado in documento.get("results", []):
        for entrada in resultado.get("packages", []):
            pkg = entrada["package"]
            try:
                ecosistema = Ecosistema(pkg["ecosystem"])
            except ValueError:
                continue  # ecosistema fuera de alcance (p. ej. Go)
            avisos = {v["id"]: v for v in entrada.get("vulnerabilities", [])}
            # osv-scanner ya agrupa los avisos que son alias entre sí ("groups").
            for grupo in entrada.get("groups", []):
                hallazgos.append(_hallazgo_de_grupo(ecosistema, pkg, grupo, avisos))
    return hallazgos


def _hallazgo_de_grupo(ecosistema: Ecosistema, pkg: dict, grupo: dict,
                       avisos: dict[str, dict]) -> Finding:
    ids = ordenar_ids([*grupo["ids"], *grupo.get("aliases", [])])
    del_grupo = [avisos[i] for i in grupo["ids"] if i in avisos]
    cvss = _a_float(grupo.get("max_severity"))

    evidencias = [
        evidencia(ColectorOSV.nombre, clasificar_aviso(a, pkg["name"]),
                  f"{a['id']}: {_resumen(a) or 'sin resumen'}",
                  referencia=f"https://osv.dev/vulnerability/{a['id']}",
                  datos={"publicado": a.get("published"), "modificado": a.get("modified")})
        for a in del_grupo
    ]
    # Un aviso MAL- puede aparecer solo como alias de otro, sin su registro completo: el
    # ID basta para saber que es un paquete malicioso.
    # ordenar_ids pone los MAL- primero.
    if ids[0].startswith("MAL-") and not any(e.senal == "osv-mal" for e in evidencias):
        evidencias.append(evidencia(ColectorOSV.nombre, "osv-mal", f"{ids[0]} (alias)",
                                    referencia=f"https://osv.dev/vulnerability/{ids[0]}"))
    evidencias = evidencias or [evidencia(ColectorOSV.nombre, "osv-vuln", ids[0])]
    tipo = tipo_dominante([e.tipo for e in evidencias if e.tipo])

    # El colector aporta HECHOS (CVSS, versiones corregidas). La política (malicioso →
    # crítico, remediación por tipo, confianza) la aplica el correlador.
    if cvss is not None:
        severidad = Severidad.desde_cvss(cvss)
        motivo = f"CVSS máximo del grupo: {cvss} → {severidad.value}"
    else:
        severidad = Severidad.MEDIA
        motivo = "el aviso no publica CVSS; se asume media por prudencia"
    remediacion = None
    if tipo is Tipo.VULN:
        correcciones = _versiones_corregidas(del_grupo, ecosistema, pkg["name"])
        remediacion = (f"Actualizar a {', '.join(correcciones)} o posterior." if correcciones
                       else "No hay versión corregida publicada; evaluar reemplazo o mitigación.")

    alias = f" (alias: {', '.join(ids[1:])})" if len(ids) > 1 else ""
    return Finding(
        ecosistema=ecosistema,
        paquete=pkg["name"],
        version=pkg["version"],
        tipo=tipo,
        ids=ids,
        titulo=next((r for a in del_grupo if (r := _resumen(a))), ""),
        severidad=severidad,
        confianza=confianza_de(evidencias),
        evidencia=evidencias,
        explicacion=(f"OSV-Scanner encontró {pkg['name']}@{pkg['version']} dentro del rango "
                     f"afectado por {ids[0]}{alias}; {motivo}."),
        remediacion=remediacion,
    )


# Frases con las que los avisos describen malware cuando no traen MAL- ni CWE-506.
# Se busca solo en el resumen (o, si no hay, en la primera oración del detalle) y la frase
# tiene que nombrar AL PAQUETE como portador del malware. Las CVE corrientes dicen cosas
# como "a malicious user can...", "installing a malicious package can overwrite files" o
# "accounts can be taken over": describen al atacante, no al paquete, y no deben coincidir.
# {p} se reemplaza por el nombre del paquete (escapado).
_PLANTILLAS_MALICIOSO = [
    r"(embedded )?malicious (code|package|version) in {p}",   # "Malicious Package in X"
    r"(malware|backdoor) in {p}",                              # "Embedded malware in X"
    r"{p}[^.]{{0,80}}\b(is|was) (considered )?malicious\b",    # "X ... is considered malicious"
    r"{p}[^.]{{0,80}}\bwas taken over\b",                      # "The X project ... was taken over"
]


@functools.lru_cache(maxsize=1024)
def _patron_malicioso(nombre: str) -> re.Pattern[str]:
    """Una sola expresión por paquete (se reutiliza para todos sus avisos)."""
    # El nombre, como palabra completa (los nombres de npm pueden llevar "@", "/" y "-").
    p = rf"(?<![\w@/-]){re.escape(nombre)}(?![\w/-])"
    return re.compile("|".join(f"(?:{t.format(p=p)})" for t in _PLANTILLAS_MALICIOSO),
                      re.IGNORECASE)


def _frase_maliciosa(texto: str, nombre: str) -> bool:
    return bool(_patron_malicioso(nombre).search(texto))


def clasificar_aviso(aviso: dict, nombre: str) -> str:
    """Señal del catálogo que corresponde a un aviso OSV, de la más fuerte a la más débil."""
    if aviso["id"].startswith("MAL-"):
        return "osv-mal"
    if "CWE-506" in ((aviso.get("database_specific") or {}).get("cwe_ids") or []):
        return "osv-cwe-506"
    if _frase_maliciosa(_resumen(aviso), nombre):
        return "osv-texto-malicioso"
    return "osv-vuln"


def _resumen(aviso: dict) -> str:
    """El resumen del aviso o, si no tiene, la primera oración de su detalle."""
    if aviso.get("summary"):
        return aviso["summary"][:200]
    detalle = (aviso.get("details") or "").strip()
    return re.split(r"(?<=[.!?])\s|\n", detalle, maxsplit=1)[0][:200]


def _a_float(valor: object) -> float | None:
    try:
        return float(valor)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _versiones_corregidas(avisos: list[dict], ecosistema: Ecosistema, nombre: str) -> list[str]:
    buscado = normalizar_nombre(ecosistema, nombre)
    fijas: set[str] = set()
    for aviso in avisos:
        for afectado in aviso.get("affected", []):
            nombre_aviso = afectado.get("package", {}).get("name", "")
            if normalizar_nombre(ecosistema, nombre_aviso) != buscado:
                continue
            for rango in afectado.get("ranges", []):
                if rango.get("type") in _RANGOS_DE_VERSION:
                    fijas.update(e["fixed"] for e in rango.get("events", []) if "fixed" in e)
    return sorted(fijas, key=_clave_version)


def _clave_version(v: str) -> list[int]:
    return [int(n[:18]) for n in re.findall(r"\d+", v)]  # acota números absurdos
