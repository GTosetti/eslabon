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

    def omitir(fuente: str, motivo: str) -> None:
        omitidas.append(FuenteOmitida(fuente=fuente, motivo=motivo))  # se redacta al crearse

    if isinstance(objetivo, Paquete):
        paquetes = [objetivo]
        etiqueta = objetivo.purl
    else:
        etiqueta = str(objetivo)
        try:
            inventario = generar_sbom(objetivo, timeout=timeout)
            paquetes = inventario.paquetes
            usadas.append("syft")
            for aviso in inventario.avisos():
                omitir("syft", f"parcial: {aviso}")
            if not paquetes:
                omitir("syft", "inventario vacío: no se encontró ningún paquete npm ni PyPI")
        except Exception as exc:  # noqa: BLE001 - cualquier fallo se reporta, no aborta
            paquetes = []
            omitir("syft", f"{type(exc).__name__}: {exc}")

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
                    omitir(colector.nombre, str(exc))
                except Exception as exc:  # noqa: BLE001
                    omitir(colector.nombre, f"{type(exc).__name__}: {exc}")

    hallazgos = correlacionar(hallazgos)
    return ResultadoScan(
        objetivo=etiqueta,
        eslabon_version=__version__,
        paquetes=paquetes,
        hallazgos=hallazgos,
        fuentes_usadas=usadas,
        fuentes_omitidas=omitidas,
        # Degradado: sin inventario, o sin la fuente de avisos publicados (OSV).
        completo=bool(paquetes) and all(c.nombre in usadas for c in colectores if c.esencial),
    )
