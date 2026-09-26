"""Interfaz común de todos los colectores.

Un colector recibe el inventario de paquetes (nunca vacío) y devuelve hallazgos
(Finding). Si no puede trabajar (falta la herramienta, error de red, salida
inválida), lanza una excepción. El orquestador la captura, la anota en
`fuentes_omitidas` y sigue con los demás colectores.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from eslabon.modelos import Finding, Paquete


@dataclass
class Contexto:
    dir_trabajo: Path  # carpeta temporal para ficheros intermedios
    timeout: float  # segundos máximos por herramienta


class Colector(ABC):
    nombre: ClassVar[str]

    @abstractmethod
    def recolectar(self, paquetes: list[Paquete], ctx: Contexto) -> list[Finding]: ...
