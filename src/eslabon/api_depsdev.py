"""Cliente de la API pública de deps.dev (https://docs.deps.dev/api/v3/).

Lo comparten varios colectores (deps.dev, Scorecard y el del registro de npm), así que
guarda en memoria cada respuesta (ver ClienteCacheado en red.py).
"""

from __future__ import annotations

import re
from urllib.parse import quote

from eslabon.modelos import Paquete, es_tapon_seguridad
from eslabon.red import ClienteCacheado

_SEMVER = re.compile(r"v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?")


def clave_semver(version: str) -> tuple[int, int, int, bool] | None:
    """(mayor, menor, parche, es_estable) para ordenar versiones semver; None si no lo es.

    Una pre-versión (1.0.0-beta) va antes que la estable (1.0.0): por eso es_estable ordena
    False < True.
    """
    m = _SEMVER.fullmatch(version)
    if not m:
        return None
    return int(m[1][:18]), int(m[2][:18]), int(m[3][:18]), m[4] is None


class ClienteDepsDev(ClienteCacheado):
    BASE = "https://api.deps.dev/v3"

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

    def version_anterior(self, p: Paquete) -> str | None:
        anteriores = self.versiones_anteriores(p, 1)
        return anteriores[0] if anteriores else None

    def versiones_anteriores(self, p: Paquete, cuantas: int) -> list[str]:
        """Las `cuantas` versiones estables inmediatamente inferiores en NÚMERO de versión
        (semver), de la más cercana a la más lejana.

        No se usa la fecha: un paquete con varias ramas publica backports (3.10.2) después
        de versiones de otra rama (4.x), y compararlas daría "publicador nuevo" sin cambio
        de dueño. Tampoco sirven las fechas de deps.dev para versiones antiguas: muchas
        comparten la misma fecha de importación. Se ignoran los tapones "-security" y las
        pre-versiones (1.0.0-beta). Lista vacía si esta versión no figura en el registro.
        """
        esta = clave_semver(p.version)
        publicadas = {v["versionKey"]["version"]
                      for v in (self.paquete(p) or {}).get("versions", [])}
        if esta is None or p.version not in publicadas:
            return []
        previas = [(clave, v) for v in publicadas
                   if not es_tapon_seguridad(p.ecosistema, v)
                   and (clave := clave_semver(v)) is not None and clave[3] and clave < esta]
        return [v for _, v in sorted(previas, reverse=True)[:cuantas]]

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
