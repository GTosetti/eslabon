"""Consultas HTTP a APIs públicas (deps.dev), solo con la biblioteca estándar.

Una herramienta de supply chain debería tener las menos dependencias posibles:
cada librería extra es un eslabón más que puede romperse.

Defensas:
- Solo https, y las redirecciones solo se siguen si siguen siendo https al MISMO host
  (sin esto, una redirección podría bajar a http o llevar a otro servidor).
- Tamaño máximo de respuesta: un JSON gigante no agota la memoria.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from eslabon import __version__

_CABECERAS = {"User-Agent": f"eslabon/{__version__}", "Accept": "application/json"}
MAX_BYTES = 20 * 1024 * 1024  # 20 MB: las respuestas de deps.dev ocupan KB


class ErrorRed(Exception):
    """La API no respondió o respondió con un error distinto de 404."""


class _RedireccionSegura(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        origen, destino = urlsplit(req.full_url), urlsplit(newurl)
        if destino.scheme != "https" or destino.hostname != origen.hostname:
            raise ErrorRed(f"redirección rechazada: {req.full_url} -> {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_ABRIDOR = urllib.request.build_opener(_RedireccionSegura)


def obtener_json(url: str, timeout: float) -> Any | None:
    """GET a una URL https y devuelve el JSON. Devuelve None si el recurso no existe (404)."""
    if not url.startswith("https://"):
        raise ValueError(f"solo se permiten URLs https: {url}")
    peticion = urllib.request.Request(url, headers=_CABECERAS)  # noqa: S310 - validada arriba
    try:
        with _ABRIDOR.open(peticion, timeout=timeout) as respuesta:
            cuerpo = respuesta.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ErrorRed(f"{url} respondió {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ErrorRed(f"{url}: {exc}") from exc
    if len(cuerpo) > MAX_BYTES:
        raise ErrorRed(f"{url}: respuesta mayor que {MAX_BYTES} bytes")
    try:
        return json.loads(cuerpo)
    except json.JSONDecodeError as exc:
        raise ErrorRed(f"{url}: JSON inválido: {exc}") from exc
