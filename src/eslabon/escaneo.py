"""Orquestador: entrada → SBOM → colectores → resultado.

Principio central: degradar con elegancia. Si una herramienta falta o falla,
se anota en `fuentes_omitidas` y el escaneo sigue con las demás.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from eslabon import __version__
from eslabon.api_depsdev import ClienteDepsDev
from eslabon.colectores import AnalisisParcial, Colector, Contexto
from eslabon.correlador import correlacionar
from eslabon.modelos import Finding, FuenteOmitida, Paquete, ResultadoScan
from eslabon.sbom import generar_sbom


def escanear(objetivo: Path | Paquete, colectores: Sequence[Colector], timeout: float,
             depsdev: ClienteDepsDev | None = None) -> ResultadoScan:
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
            ctx = Contexto(dir_trabajo=Path(tmp), timeout=timeout,
                           depsdev=depsdev or ClienteDepsDev(timeout=min(timeout, 30)))
            # Los colectores son independientes y pasan casi todo el tiempo esperando
            # (procesos externos, red), así que se ejecutan en paralelo.
            with ThreadPoolExecutor(max_workers=max(len(colectores), 1)) as grupo:
                futuros = [grupo.submit(c.recolectar, paquetes, ctx) for c in colectores]
            for colector, futuro in zip(colectores, futuros, strict=True):
                try:
                    hallazgos.extend(futuro.result())
                    usadas.append(colector.nombre)
                except AnalisisParcial as exc:
                    hallazgos.extend(exc.hallazgos)
                    usadas.append(colector.nombre)
                    omitidas.append(FuenteOmitida(fuente=colector.nombre, motivo=str(exc)))
                except Exception as exc:  # noqa: BLE001
                    omitidas.append(FuenteOmitida(fuente=colector.nombre,
                                                  motivo=f"{type(exc).__name__}: {exc}"))

    hallazgos = correlacionar(hallazgos)
    return ResultadoScan(
        objetivo=etiqueta,
        eslabon_version=__version__,
        paquetes=paquetes,
        hallazgos=hallazgos,
        fuentes_usadas=usadas,
        fuentes_omitidas=omitidas,
    )
