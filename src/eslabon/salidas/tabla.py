"""Salida legible para humanos en la consola.

Todo texto que viene de fuera (resúmenes de avisos, nombres de paquetes, errores de
herramientas) pasa por `escape()`. rich interpreta los [corchetes] como marcas de formato,
y un aviso con "[/algo]" en el resumen podría romper la salida o alterar su aspecto.
"""

from __future__ import annotations

import io

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


def mostrar(resultado: ResultadoScan, consola: Console | None = None) -> None:
    consola = consola or Console()
    consola.print(f"[bold]eslabon {resultado.eslabon_version}[/] · objetivo: "
                  f"{escape(resultado.objetivo)}")
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
                escape(f"{h.ecosistema.value}/{h.paquete}"),
                escape(h.version),
                escape(h.ids[0]),
                escape(", ".join(h.ids[1:])),
                escape(", ".join(h.fuentes)),
                escape(h.titulo),
            )
        consola.print(tabla)
    consola.print(f"Hallazgos: {len(resultado.hallazgos)}")

    for omitida in resultado.fuentes_omitidas:
        consola.print(f"[yellow]⚠ fuente omitida[/] {escape(omitida.fuente)}: "
                      f"{escape(omitida.motivo)}")


def renderizar(resultado: ResultadoScan) -> str:
    """La misma tabla como texto plano (sin colores), para escribirla en un fichero."""
    consola = Console(file=io.StringIO(), width=200, no_color=True, record=True)
    mostrar(resultado, consola)
    return consola.export_text()
