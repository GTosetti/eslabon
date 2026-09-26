"""Inventario de dependencias (SBOM) con Syft, e interpretación de la entrada."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote

from eslabon.ejecutor import Herramienta, ejecutar_json
from eslabon.modelos import Ecosistema, Paquete

SYFT = Herramienta("syft", "syft", "ESLABON_SYFT")

# Tipos de paquete de Syft que soportamos, y su ecosistema.
_TIPOS_SYFT = {"python": Ecosistema.PYPI, "npm": Ecosistema.NPM}


def interpretar_objetivo(texto: str) -> Path | Paquete:
    """Un directorio o lockfile existente, o bien un paquete suelto.

    Lanza ValueError si no es ninguna de las dos cosas.
    """
    ruta = Path(texto)
    return ruta if ruta.exists() else paquete_desde_texto(texto)


def objetivo_syft(objetivo: Path) -> str:
    """Syft distingue un directorio ("dir:") de un fichero suelto como un lockfile ("file:")."""
    return f"dir:{objetivo}" if objetivo.is_dir() else f"file:{objetivo}"


def generar_sbom(objetivo: Path, timeout: float) -> list[Paquete]:
    documento = ejecutar_json(SYFT, ["scan", objetivo_syft(objetivo), "-o", "syft-json", "-q"],
                              timeout=timeout)
    return paquetes_desde_syft(documento or {})


def paquetes_desde_syft(documento: dict) -> list[Paquete]:
    """Traduce el JSON de Syft a nuestra lista de Paquete (sin duplicados)."""
    vistos: dict[tuple[str, str, str], Paquete] = {}
    for artefacto in documento.get("artifacts", []):
        ecosistema = _TIPOS_SYFT.get(artefacto.get("type", ""))
        if ecosistema is None or not artefacto.get("version"):
            continue
        ubicaciones = [loc.get("path", "") for loc in artefacto.get("locations", [])]
        paquete = Paquete(ecosistema=ecosistema, nombre=artefacto["name"],
                          version=artefacto["version"], ubicaciones=ubicaciones)
        if paquete.clave in vistos:
            vistos[paquete.clave].ubicaciones.extend(ubicaciones)
        else:
            vistos[paquete.clave] = paquete
    return [vistos[clave] for clave in sorted(vistos)]


def paquete_desde_texto(texto: str) -> Paquete:
    """Interpreta "pypi:requests@2.19.0", "npm:@scope/pkg@1.0.0" o un purl completo."""
    if texto.startswith("pkg:"):
        tipo, _, resto = texto[4:].partition("/")
        resto = unquote(resto)
    else:
        tipo, sep, resto = texto.partition(":")
        if not sep:
            raise ValueError("Formato esperado: <ecosistema>:<paquete>@<versión>, "
                             "por ejemplo pypi:requests@2.19.0")
    ecosistema = Ecosistema.desde_tipo_purl(tipo)
    nombre, sep, version = resto.rpartition("@")
    if not sep or not nombre or not version:
        raise ValueError(f"Falta la versión en {texto!r} (formato paquete@versión)")
    return Paquete(ecosistema=ecosistema, nombre=nombre, version=version,
                   ubicaciones=["(línea de comandos)"])


def escribir_cyclonedx(paquetes: list[Paquete], destino: Path) -> None:
    """SBOM CycloneDX mínimo, para pasárselo a herramientas que leen SBOMs (OSV-Scanner).

    OSV-Scanner solo reconoce el formato por el nombre: debe terminar en ".cdx.json".
    """
    documento = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {"type": "library", "name": p.nombre, "version": p.version, "purl": p.purl}
            for p in paquetes
        ],
    }
    destino.write_text(json.dumps(documento, indent=2), encoding="utf-8")
