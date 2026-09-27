"""Formatos de salida. Cada uno convierte un ResultadoScan en texto."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from eslabon.modelos import ResultadoScan
from eslabon.salidas import sarif, siem, tabla


class Formato(StrEnum):
    TABLA = "tabla"
    JSON = "json"
    SARIF = "sarif"
    SIEM = "siem"  # JSON Lines para Wazuh u otro SIEM


def _json(resultado: ResultadoScan) -> str:
    return resultado.model_dump_json(indent=2)


RENDERIZADORES: dict[Formato, Callable[[ResultadoScan], str]] = {
    Formato.TABLA: tabla.renderizar,
    Formato.JSON: _json,
    Formato.SARIF: sarif.renderizar,
    Formato.SIEM: siem.renderizar,
}
