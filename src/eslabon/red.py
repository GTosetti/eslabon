"""Consultas HTTP a APIs públicas (deps.dev), solo con la biblioteca estándar.

Una herramienta de supply chain debería tener las menos dependencias posibles:
cada librería extra es un eslabón más que puede romperse.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from eslabon import __version__

_CABECERAS = {"User-Agent": f"eslabon/{__version__}", "Accept": "application/json"}


class ErrorRed(Exception):
    """La API no respondió o respondió con un error distinto de 404."""


def obtener_json(url: str, timeout: float) -> Any | None:
    """GET a una URL https y devuelve el JSON. Devuelve None si el recurso no existe (404)."""
    if not url.startswith("https://"):
        raise ValueError(f"solo se permiten URLs https: {url}")
    peticion = urllib.request.Request(url, headers=_CABECERAS)  # noqa: S310 - validada arriba
    try:
        with urllib.request.urlopen(peticion, timeout=timeout) as respuesta:  # noqa: S310
            return json.load(respuesta)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ErrorRed(f"{url} respondió {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ErrorRed(f"{url}: {exc}") from exc
