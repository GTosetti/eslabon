"""Cliente de la API pública de deps.dev (https://docs.deps.dev/api/v3/).

Lo comparten varios colectores (deps.dev y Scorecard), así que guarda en memoria
cada respuesta: dos colectores que preguntan lo mismo generan una sola petición.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any
from urllib.parse import quote

from eslabon.modelos import Paquete, es_tapon_seguridad
from eslabon.red import obtener_json

BASE = "https://api.deps.dev/v3"

# Función que hace el GET: (ruta relativa a BASE, timeout) -> JSON o None si 404.
# Los tests la sustituyen por respuestas grabadas.
Obtener = Callable[[str, float], Any | None]


def _obtener_de_internet(ruta: str, timeout: float) -> Any | None:
    return obtener_json(BASE + ruta, timeout)


class ClienteDepsDev:
    def __init__(self, obtener: Obtener = _obtener_de_internet, timeout: float = 30) -> None:
        self._obtener = obtener
        self._timeout = timeout
        self._cache: dict[str, Future] = {}
        self._cerrojo = threading.Lock()

    def _get(self, ruta: str) -> Any | None:
        # En la caché se guarda un Future por ruta: si dos colectores piden lo mismo a la
        # vez, el segundo espera la respuesta del primero en vez de repetir la petición.
        # Un error también queda guardado, para no reintentarlo una vez por colector.
        with self._cerrojo:
            futuro = self._cache.get(ruta)
            propio = futuro is None
            if propio:
                futuro = self._cache[ruta] = Future()
        if propio:
            try:
                futuro.set_result(self._obtener(ruta, self._timeout))
            except Exception as exc:  # noqa: BLE001 - se entrega a quien espere la ruta
                futuro.set_exception(exc)
        return futuro.result()

    @staticmethod
    def _ruta_paquete(p: Paquete) -> str:
        return f"/systems/{p.ecosistema.tipo_purl}/packages/{quote(p.nombre, safe='')}"

    def paquete(self, p: Paquete) -> dict | None:
        """Todas las versiones publicadas del paquete (None si no existe en el registro)."""
        return self._get(self._ruta_paquete(p))

    def version(self, p: Paquete, version: str | None = None) -> dict | None:
        """Detalle de una versión (None si no existe en el registro)."""
        v = quote(version or p.version, safe="")
        return self._get(f"{self._ruta_paquete(p)}/versions/{v}")

    def proyecto(self, id_proyecto: str) -> dict | None:
        """Datos del repositorio de origen, incluido su OpenSSF Scorecard."""
        return self._get(f"/projects/{quote(id_proyecto, safe='')}")

    def repositorio_origen(self, p: Paquete) -> str | None:
        """Repositorio de código fuente del paquete, p. ej. "github.com/psf/requests".

        Las versiones antiguas a menudo no lo declaran; entonces se usa el de la versión
        por defecto (la última estable) del paquete.
        """
        repo = _repo_declarado(self.version(p))
        if repo:
            return repo
        info = self.paquete(p) or {}
        por_defecto = next((v["versionKey"]["version"] for v in info.get("versions", [])
                            if v.get("isDefault")), None)
        # Un tapón "-security" de npm apunta al repositorio de npm (npm/security-holder),
        # no al del paquete original: no sirve como origen.
        if (por_defecto and por_defecto != p.version
                and not es_tapon_seguridad(p.ecosistema, por_defecto)):
            return _repo_declarado(self.version(p, por_defecto))
        return None


def _repo_declarado(detalle: dict | None) -> str | None:
    for relacion in (detalle or {}).get("relatedProjects", []):
        if relacion.get("relationType") == "SOURCE_REPO":
            return relacion["projectKey"]["id"]
    return None
