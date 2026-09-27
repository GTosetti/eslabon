"""Salida legible para humanos en la consola.

Todo texto que viene de fuera (resúmenes de avisos, nombres de paquetes, errores de
herramientas) pasa por `_seguro()`:
- se quitan los caracteres de control (ESC inicia las secuencias ANSI: un texto hostil
  podría ocultar líneas, reescribir la pantalla o inyectar enlaces en la terminal del
  analista) y las marcas de dirección bidi;
- se escapan los [corchetes], que rich interpreta como marcas de formato ("[/algo]" en
  un resumen podría romper la salida).
"""

from __future__ import annotations

import io
import re

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from eslabon.modelos import ResultadoScan, Severidad

_COLORES = {
    Severidad.CRITICA: "bold white on red",
    Severidad.ALTA: "bold red",
    Severidad.MEDIA: "yellow",
    Severidad.BAJA: "cyan",
    Severidad.INFO: "dim",
}
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def _seguro(texto: str) -> str:
    return escape(_CONTROL.sub("", texto))


def mostrar(resultado: ResultadoScan, consola: Console | None = None) -> None:
    consola = consola or Console()
    consola.print(f"[bold]eslabon {resultado.eslabon_version}[/] · objetivo: "
                  f"{_seguro(resultado.objetivo)}")
    consola.print(f"Paquetes inventariados: {len(resultado.paquetes)} · "
                  f"fuentes usadas: {', '.join(resultado.fuentes_usadas) or 'ninguna'}")

    if resultado.hallazgos:
        tabla = Table(header_style="bold")
        for columna in ("Severidad", "Tipo", "Paquete", "Versión", "ID", "Alias", "Fuentes",
                        "Resumen"):
            tabla.add_column(columna, overflow="fold")
        for h in resultado.hallazgos:
            tabla.add_row(
                f"[{_COLORES[h.severidad]}]{h.severidad.value}[/]",
                h.tipo.value,
                _seguro(f"{h.ecosistema.value}/{h.paquete}"),
                _seguro(h.version),
                _seguro(h.ids[0]),
                _seguro(", ".join(h.ids[1:])),
                _seguro(", ".join(h.fuentes)),
                _seguro(h.titulo),
            )
        consola.print(tabla)
    consola.print(f"Hallazgos: {len(resultado.hallazgos)}")

    for omitida in resultado.fuentes_omitidas:
        consola.print(f"[yellow]⚠ fuente omitida[/] {_seguro(omitida.fuente)}: "
                      f"{_seguro(omitida.motivo)}")
    if not resultado.completo:
        consola.print("[bold yellow]⚠ ANÁLISIS INCOMPLETO:[/] sin inventario o sin la fuente de "
                      "avisos (OSV). 0 hallazgos NO significa que esté limpio.")


def renderizar(resultado: ResultadoScan) -> str:
    """La misma tabla como texto plano (sin colores), para escribirla en un fichero."""
    consola = Console(file=io.StringIO(), width=200, no_color=True, record=True)
    mostrar(resultado, consola)
    return consola.export_text()
