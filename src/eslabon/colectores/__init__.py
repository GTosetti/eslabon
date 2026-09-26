from eslabon.colectores.base import Colector, Contexto
from eslabon.colectores.osv import ColectorOSV


def colectores_por_defecto() -> list[Colector]:
    """Colectores que usa `eslabon scan` si no se indica otra cosa."""
    return [ColectorOSV()]


__all__ = ["Colector", "ColectorOSV", "Contexto", "colectores_por_defecto"]
