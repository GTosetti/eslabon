"""Interfaz de línea de comandos (CLI)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from eslabon import __version__
from eslabon.colectores import colectores_por_defecto
from eslabon.colectores.guarddog import MAX_PAQUETES_POR_DEFECTO
from eslabon.ejecutor import TIMEOUT_POR_DEFECTO
from eslabon.escaneo import escanear
from eslabon.salidas import RENDERIZADORES, Formato, tabla
from eslabon.sbom import interpretar_objetivo

app = typer.Typer(
    help="eslabon: el eslabón débil de tu cadena de suministro de software.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def _inicio() -> None:
    # En Windows, si la salida va a una tubería o fichero, Python usa la codificación
    # heredada (cp1252) y los acentos se rompen. Forzamos UTF-8 siempre.
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8")


@app.command()
def scan(
    objetivo: Annotated[str, typer.Argument(
        help="Directorio, lockfile o paquete (pypi:requests@2.19.0, npm:lodash@4.17.15)")],
    formato: Annotated[Formato, typer.Option("--formato", "-f")] = Formato.TABLA,
    salida: Annotated[Path | None, typer.Option("--salida", "-o",
                                                help="Fichero donde escribir el resultado")] = None,
    timeout: Annotated[float, typer.Option(help="Segundos máximos por herramienta")] =
        TIMEOUT_POR_DEFECTO,
    guarddog_max: Annotated[int, typer.Option(
        min=0, help="Máximo de paquetes que analiza GuardDog (descarga cada uno)")] =
        MAX_PAQUETES_POR_DEFECTO,
) -> None:
    """Analiza las dependencias del objetivo y muestra los hallazgos."""
    try:
        entrada = interpretar_objetivo(objetivo)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    resultado = escanear(entrada, colectores_por_defecto(guarddog_max), timeout=timeout)

    if salida:
        salida.write_text(RENDERIZADORES[formato](resultado), encoding="utf-8")
    elif formato is Formato.TABLA:
        tabla.mostrar(resultado)  # en la terminal, con colores
    else:
        typer.echo(RENDERIZADORES[formato](resultado))


@app.command()
def version() -> None:
    """Muestra la versión de eslabon."""
    typer.echo(f"eslabon {__version__}")


if __name__ == "__main__":
    app()
