"""Inventario de dependencias (SBOM) con Syft, e interpretación de la entrada."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from pydantic import ValidationError

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


@dataclass
class Inventario:
    paquetes: list[Paquete]
    # Entradas con nombre o versión que no cumplen la gramática del registro (posible
    # lockfile manipulado): se descartan y se informa.
    descartados: list[str] = field(default_factory=list)
    # Artefactos de ecosistemas que eslabon todavía no analiza (Go, Maven...): cobertura
    # parcial, que también se informa.
    no_soportados: Counter[str] = field(default_factory=Counter)
    # Artefactos sin versión concreta: sin versión no se pueden consultar avisos. Si se
    # omitieran en silencio, el escaneo parecería completo sin haberlos mirado. (Ojo: Syft
    # ni siquiera emite los requisitos sin fijar de un requirements.txt, como "flask>=2".)
    sin_version: list[str] = field(default_factory=list)

    def avisos(self) -> list[str]:
        avisos = []
        if self.descartados:
            avisos.append(f"{len(self.descartados)} entradas descartadas por nombre o versión "
                          f"no válidos: {', '.join(self.descartados[:3])}")
        if self.no_soportados:
            detalle = ", ".join(f"{n} {t}" for t, n in self.no_soportados.most_common())
            avisos.append(f"artefactos de ecosistemas no soportados, sin analizar: {detalle}")
        if self.sin_version:
            avisos.append(f"{len(self.sin_version)} dependencias sin versión fijada, sin "
                          f"analizar: {', '.join(self.sin_version[:3])}")
        return avisos


def generar_sbom(objetivo: Path, timeout: float) -> Inventario:
    documento = ejecutar_json(SYFT, ["scan", objetivo_syft(objetivo), "-o", "syft-json", "-q"],
                              timeout=timeout)
    return inventario_desde_syft(documento or {})


def paquetes_desde_syft(documento: dict) -> list[Paquete]:
    return inventario_desde_syft(documento).paquetes


def inventario_desde_syft(documento: dict) -> Inventario:
    """Traduce el JSON de Syft a nuestro inventario de Paquete (sin duplicados).

    Excluye el propio proyecto: Syft lista la raíz de un package-lock.json como un paquete
    más, pero no es una dependencia (no se descargó de ningún registro).
    """
    descartados: list[str] = []
    no_soportados: Counter[str] = Counter()
    sin_version: list[str] = []
    # En Syft, "A dependency-of B" se guarda como parent=A, child=B.
    son_dependencia = {r["parent"] for r in documento.get("artifactRelationships", [])
                       if r.get("type") == "dependency-of"}
    vistos: dict[tuple[str, str, str], Paquete] = {}
    for artefacto in documento.get("artifacts", []):
        ecosistema = _TIPOS_SYFT.get(artefacto.get("type", ""))
        if ecosistema is None:
            no_soportados[artefacto.get("type") or "desconocido"] += 1
            continue
        if _es_raiz_del_proyecto(artefacto, son_dependencia):
            continue
        if not artefacto.get("version"):
            sin_version.append(repr(artefacto.get("name", ""))[:60])
            continue
        ubicaciones = [loc.get("path", "") for loc in artefacto.get("locations", [])]
        try:
            paquete = Paquete(ecosistema=ecosistema, nombre=artefacto["name"],
                              version=artefacto["version"], ubicaciones=ubicaciones)
        except ValidationError:
            descartados.append(repr(artefacto.get("name", ""))[:60])
            continue
        if paquete.clave in vistos:
            vistos[paquete.clave].ubicaciones.extend(ubicaciones)
        else:
            vistos[paquete.clave] = paquete
    return Inventario([vistos[clave] for clave in sorted(vistos)], descartados, no_soportados,
                      sin_version)


def _es_raiz_del_proyecto(artefacto: dict, son_dependencia: set[str]) -> bool:
    metadatos = artefacto.get("metadata") or {}
    return (artefacto.get("type") == "npm"
            and "resolved" in metadatos and not metadatos["resolved"]
            and artefacto.get("id") not in son_dependencia)


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
