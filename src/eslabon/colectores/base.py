"""Interfaz común de todos los colectores.

Un colector recibe el inventario de paquetes (nunca vacío) y devuelve hallazgos
(Finding). Si no puede trabajar (falta la herramienta, error de red, salida
inválida), lanza una excepción. El orquestador la captura, la anota en
`fuentes_omitidas` y sigue con los demás colectores.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, TypeVar

from eslabon.api_depsdev import ClienteDepsDev
from eslabon.modelos import Finding, Paquete

T = TypeVar("T")
R = TypeVar("R")


@dataclass
class Contexto:
    dir_trabajo: Path  # carpeta temporal para ficheros intermedios
    timeout: float  # segundos máximos por herramienta
    # Compartido entre colectores: guarda en memoria las respuestas de deps.dev.
    depsdev: ClienteDepsDev = field(default_factory=ClienteDepsDev)
    # "Ahora", fijo para todo el escaneo (y reemplazable en los tests).
    ahora: datetime = field(default_factory=lambda: datetime.now(UTC))


class AnalisisParcial(Exception):
    """El colector trabajó, pero no pudo analizar todo. Se informa y se conservan los hallazgos."""

    def __init__(self, motivo: str, hallazgos: list[Finding]) -> None:
        super().__init__(motivo)
        self.hallazgos = hallazgos


class ColectorFallo(Exception):
    """El colector no pudo analizar ningún elemento."""


class Colector(ABC):
    nombre: ClassVar[str]

    @abstractmethod
    def recolectar(self, paquetes: list[Paquete], ctx: Contexto) -> list[Finding]: ...


# Peticiones simultáneas por colector. Las APIs son públicas: no hay que abusar.
HILOS_POR_DEFECTO = 8


def en_paralelo(elementos: list[T], funcion: Callable[[T], R], hilos: int = HILOS_POR_DEFECTO,
                etiqueta: Callable[[T], str] = str) -> tuple[list[R | None], list[str]]:
    """Aplica `funcion` a cada elemento en paralelo, aislando los fallos.

    Un error en un elemento (p. ej. un 429 de la API para un paquete de cientos) no
    debe tirar el trabajo hecho con los demás. Devuelve (resultados, errores), con los
    resultados en el mismo orden que los elementos y None donde hubo error.
    """

    def seguro(x: T) -> tuple[R | None, str | None]:
        try:
            return funcion(x), None
        except Exception as exc:  # noqa: BLE001 - se informa como análisis parcial
            return None, f"{etiqueta(x)}: {type(exc).__name__}: {exc}"

    with ThreadPoolExecutor(max_workers=hilos) as grupo:
        pares = list(grupo.map(seguro, elementos))
    return [r for r, _ in pares], [e for _, e in pares if e]


def entregar(hallazgos: list[Finding], errores: list[str], total: int,
             avisos: list[str] | None = None) -> list[Finding]:
    """Devuelve los hallazgos, o avisa si el análisis fue parcial o falló del todo."""
    if total and len(errores) == total:
        raise ColectorFallo("; ".join(errores[:3]))
    avisos = list(avisos or [])
    if errores:
        avisos.append(f"fallaron {len(errores)} de {total}: {'; '.join(errores[:3])}")
    if avisos:
        raise AnalisisParcial("parcial: " + " · ".join(avisos), hallazgos)
    return hallazgos
