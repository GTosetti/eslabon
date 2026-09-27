"""Interfaz de línea de comandos (CLI)."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from eslabon import __version__
from eslabon.colectores import colectores_por_defecto
from eslabon.colectores.guarddog import MAX_PAQUETES_POR_DEFECTO
from eslabon.ejecutor import TIMEOUT_POR_DEFECTO
from eslabon.escaneo import escanear
from eslabon.modelos import ResultadoScan, Severidad
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


# Severidad mínima que hace fallar el comando (útil en CI): las de Severidad, más "nunca".
# Se deriva de Severidad para que las dos listas no puedan desincronizarse.
Umbral = StrEnum("Umbral", {**{s.name: s.value for s in reversed(Severidad)},
                            "NUNCA": "nunca"})

# Códigos de salida (documentados en el README).
SALIDA_LIMPIA = 0
SALIDA_HALLAZGOS = 1
SALIDA_USO = 2
SALIDA_INCOMPLETO = 3


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
        min=0, help="Máximo de paquetes que analiza GuardDog (0 = desactivado)")] =
        MAX_PAQUETES_POR_DEFECTO,
    fallar_en: Annotated[Umbral, typer.Option(
        help="Salir con código 1 si hay hallazgos de esta severidad o mayor")] = Umbral.ALTA,
    permitir_degradado: Annotated[bool, typer.Option(
        help="No salir con código 3 si el análisis quedó incompleto")] = False,
    anexar: Annotated[bool, typer.Option(
        help="Añadir al fichero de --salida en vez de sobrescribirlo (útil con -f siem)")] = False,
) -> None:
    """Analiza las dependencias del objetivo y muestra los hallazgos.

    Códigos de salida: 0 = sin hallazgos por encima del umbral; 1 = hay hallazgos de
    severidad --fallar-en o mayor; 2 = error de uso; 3 = análisis incompleto (sin
    inventario o sin la fuente de avisos): un 0 ahí sería un falso "limpio".
    """
    try:
        entrada = interpretar_objetivo(objetivo)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=SALIDA_USO) from exc

    resultado = escanear(entrada, colectores_por_defecto(guarddog_max), timeout=timeout)

    if salida:
        # UTF-8 sin BOM, escrito por eslabon: pasar la salida por una tubería de PowerShell
        # rompería los acentos y podría añadir un BOM al principio del fichero.
        with salida.open("a" if anexar else "w", encoding="utf-8", newline="\n") as fichero:
            fichero.write(RENDERIZADORES[formato](resultado))
    elif formato is Formato.TABLA:
        tabla.mostrar(resultado)  # en la terminal, con colores
    else:
        typer.echo(RENDERIZADORES[formato](resultado).rstrip("\n"))

    raise typer.Exit(code=codigo_de_salida(resultado, fallar_en, permitir_degradado))


def codigo_de_salida(resultado: ResultadoScan, fallar_en: Umbral,
                     permitir_degradado: bool) -> int:
    if not resultado.completo and not permitir_degradado:
        return SALIDA_INCOMPLETO
    if fallar_en is not Umbral.NUNCA:
        minimo = Severidad(fallar_en.value).rango
        if any(h.severidad.rango >= minimo for h in resultado.hallazgos):
            return SALIDA_HALLAZGOS
    return SALIDA_LIMPIA


@app.command()
def version() -> None:
    """Muestra la versión de eslabon."""
    typer.echo(f"eslabon {__version__}")


if __name__ == "__main__":
    app()
