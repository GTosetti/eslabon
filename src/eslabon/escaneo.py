"""Orquestador: entrada → SBOM → colectores → resultado.

Principio central: degradar con elegancia. Si una herramienta falta o falla,
se anota en `fuentes_omitidas` y el escaneo sigue con las demás.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from pathlib import Path

from eslabon import __version__
from eslabon.colectores import Colector, Contexto
from eslabon.modelos import Finding, FuenteOmitida, Paquete, ResultadoScan
from eslabon.sbom import generar_sbom


def escanear(objetivo: Path | Paquete, colectores: Sequence[Colector],
             timeout: float) -> ResultadoScan:
    omitidas: list[FuenteOmitida] = []
    usadas: list[str] = []
    hallazgos: list[Finding] = []

    if isinstance(objetivo, Paquete):
        paquetes = [objetivo]
        etiqueta = objetivo.purl
    else:
        etiqueta = str(objetivo)
        try:
            paquetes = generar_sbom(objetivo, timeout=timeout)
            usadas.append("syft")
        except Exception as exc:  # noqa: BLE001 - cualquier fallo se reporta, no aborta
            paquetes = []
            omitidas.append(FuenteOmitida(fuente="syft", motivo=f"{type(exc).__name__}: {exc}"))

    # Sin inventario no hay nada que analizar: los colectores no se ejecutan ni se marcan
    # como "usados", para no dar a entender que el escaneo salió limpio.
    if paquetes:
        with tempfile.TemporaryDirectory(prefix="eslabon-") as tmp:
            ctx = Contexto(dir_trabajo=Path(tmp), timeout=timeout)
            for colector in colectores:
                try:
                    hallazgos.extend(colector.recolectar(paquetes, ctx))
                    usadas.append(colector.nombre)
                except Exception as exc:  # noqa: BLE001
                    omitidas.append(FuenteOmitida(fuente=colector.nombre,
                                                  motivo=f"{type(exc).__name__}: {exc}"))

    hallazgos.sort(key=lambda h: (-h.severidad.rango, h.clave, h.ids[0]))
    return ResultadoScan(
        objetivo=etiqueta,
        eslabon_version=__version__,
        paquetes=paquetes,
        hallazgos=hallazgos,
        fuentes_usadas=usadas,
        fuentes_omitidas=omitidas,
    )
