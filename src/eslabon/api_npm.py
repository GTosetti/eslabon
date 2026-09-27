"""Cliente del registro público de npm (https://registry.npmjs.org), solo lectura.

Se pide el documento de UNA versión (`/<paquete>/<versión>`): trae quién la publicó
(`_npmUser`) y sus scripts, y pesa KB. El documento completo del paquete puede ocupar MB.
"""

from __future__ import annotations

from urllib.parse import quote

from eslabon.modelos import Paquete
from eslabon.red import ClienteCacheado


class ClienteNpm(ClienteCacheado):
    BASE = "https://registry.npmjs.org"

    def version(self, p: Paquete, version: str | None = None) -> dict | None:
        """Metadatos de una versión publicada (None si no existe: p. ej. retirada)."""
        # Los paquetes con scope van como "@scope%2Fnombre" (la "/" codificada).
        return self._get(f"/{quote(p.nombre, safe='@')}/{quote(version or p.version, safe='')}")
