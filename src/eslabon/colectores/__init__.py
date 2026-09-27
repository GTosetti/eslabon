from eslabon.colectores.base import AnalisisParcial, Colector, ColectorFallo, Contexto
from eslabon.colectores.depsdev import ColectorDepsDev
from eslabon.colectores.guarddog import MAX_PAQUETES_POR_DEFECTO, ColectorGuardDog
from eslabon.colectores.osv import ColectorOSV
from eslabon.colectores.scorecard import ColectorScorecard


def colectores_por_defecto(guarddog_max: int = MAX_PAQUETES_POR_DEFECTO) -> list[Colector]:
    """Colectores que usa `eslabon scan` si no se indica otra cosa.

    Con guarddog_max=0 GuardDog queda desactivado del todo (no genera "fuente omitida").
    """
    colectores: list[Colector] = [ColectorOSV(), ColectorDepsDev(), ColectorScorecard()]
    if guarddog_max > 0:
        colectores.append(ColectorGuardDog(max_paquetes=guarddog_max))
    return colectores


__all__ = [
    "AnalisisParcial", "Colector", "ColectorDepsDev", "ColectorFallo", "ColectorGuardDog",
    "ColectorOSV", "ColectorScorecard", "Contexto", "colectores_por_defecto",
]
