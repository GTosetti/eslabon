"""Colector de OSV-Scanner: vulnerabilidades conocidas y paquetes maliciosos (avisos MAL-).

OSV (https://osv.dev) es una base de datos abierta que agrega avisos de muchas
fuentes: GitHub (GHSA), PyPA (PYSEC), NVD (CVE) y OpenSSF Malicious Packages (MAL).
El mismo problema puede tener un ID en cada una: esos son los "alias".
"""

from __future__ import annotations

import re

from eslabon.colectores.base import Colector, Contexto
from eslabon.ejecutor import Herramienta, ejecutar_json
from eslabon.modelos import (
    Ecosistema,
    Evidencia,
    Finding,
    Paquete,
    Severidad,
    Tipo,
    normalizar_nombre,
    ordenar_ids,
)
from eslabon.sbom import escribir_cyclonedx

OSV_SCANNER = Herramienta("osv-scanner", "osv-scanner", "ESLABON_OSV_SCANNER")

# Códigos de salida documentados de osv-scanner: 0 = sin hallazgos, 1 = hay hallazgos,
# 128 = no encontró paquetes que analizar. Los tres son ejecuciones correctas.
_CODIGOS_OK = (0, 1, 128)

# Confianza de que el aviso aplica a este paquete@versión. OSV compara la versión
# exacta contra los rangos afectados que publica el aviso, así que la coincidencia es
# muy fiable. No es 1.0 porque no sabemos si el código vulnerable se usa de verdad.
CONFIANZA_AVISO_OSV = 0.9

# Tipos de rango con versiones publicadas. Los rangos "GIT" usan hashes de commit.
_RANGOS_DE_VERSION = {"ECOSYSTEM", "SEMVER"}


class ColectorOSV(Colector):
    nombre = "osv"

    def recolectar(self, paquetes: list[Paquete], ctx: Contexto) -> list[Finding]:
        sbom = ctx.dir_trabajo / "eslabon-osv.cdx.json"
        escribir_cyclonedx(paquetes, sbom)
        documento = ejecutar_json(OSV_SCANNER,
                                  ["scan", "source", "-L", str(sbom), "--format", "json"],
                                  timeout=ctx.timeout, codigos_ok=_CODIGOS_OK)
        return hallazgos_desde_osv(documento or {})


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
    resumenes = {i: _resumen(avisos[i]) for i in grupo["ids"] if i in avisos}
    cvss = _a_float(grupo.get("max_severity"))

    if any(i.startswith("MAL-") for i in ids):
        tipo = Tipo.MALICIOSO
        severidad = Severidad.CRITICA
        motivo_sev = "es un aviso MAL- (paquete malicioso confirmado): se trata como crítico"
        remediacion = ("Retirar el paquete de inmediato y rotar los secretos del entorno "
                       "donde se instaló.")
    else:
        tipo = Tipo.VULN
        if cvss is not None:
            severidad = Severidad.desde_cvss(cvss)
            motivo_sev = f"puntaje CVSS máximo del grupo: {cvss}"
        else:
            severidad = Severidad.MEDIA
            motivo_sev = "el aviso no publica puntaje CVSS; se asume severidad media por prudencia"
        correcciones = _versiones_corregidas([avisos[i] for i in resumenes], ecosistema,
                                             pkg["name"])
        remediacion = (f"Actualizar a {', '.join(correcciones)} o posterior." if correcciones
                       else "No hay versión corregida publicada; evaluar reemplazo o mitigación.")

    alias = f" (alias: {', '.join(ids[1:])})" if len(ids) > 1 else ""
    return Finding(
        ecosistema=ecosistema,
        paquete=pkg["name"],
        version=pkg["version"],
        tipo=tipo,
        ids=ids,
        titulo=next((r for r in resumenes.values() if r), ""),
        severidad=severidad,
        confianza=CONFIANZA_AVISO_OSV,
        evidencia=[
            Evidencia(
                fuente=ColectorOSV.nombre,
                descripcion=f"{i}: {resumen or 'sin resumen'}",
                referencia=f"https://osv.dev/vulnerability/{i}",
                datos={"publicado": avisos[i].get("published"),
                       "modificado": avisos[i].get("modified")},
            )
            for i, resumen in resumenes.items()
        ],
        explicacion=(f"OSV-Scanner encontró {pkg['name']}@{pkg['version']} dentro del rango "
                     f"afectado por {ids[0]}{alias}. Severidad {severidad.value} porque "
                     f"{motivo_sev}."),
        remediacion=remediacion,
    )


def _resumen(aviso: dict) -> str:
    texto = aviso.get("summary") or (aviso.get("details") or "").strip().split("\n", 1)[0]
    return texto[:200]


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
    return [int(n) for n in re.findall(r"\d+", v)]
