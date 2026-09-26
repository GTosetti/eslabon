from rich.console import Console

from eslabon.modelos import (
    Ecosistema,
    Finding,
    FuenteOmitida,
    ResultadoScan,
    Severidad,
    Tipo,
)
from eslabon.salidas import tabla


def test_texto_externo_con_corchetes_no_rompe_la_tabla():
    hallazgo = Finding(ecosistema=Ecosistema.NPM, paquete="x", version="1", tipo=Tipo.VULN,
                       ids=["GHSA-1"], titulo="Bug en [/ruta] y [bold]falso[/bold]",
                       severidad=Severidad.ALTA, confianza=0.9, evidencia=[],
                       explicacion="-")
    resultado = ResultadoScan(objetivo="[/objetivo]", eslabon_version="0", paquetes=[],
                              hallazgos=[hallazgo], fuentes_usadas=["osv"],
                              fuentes_omitidas=[FuenteOmitida(fuente="syft",
                                                              motivo="error [/x] en stderr")])
    consola = Console(record=True, width=300)
    tabla.mostrar(resultado, consola)
    texto = consola.export_text()
    assert "[/ruta]" in texto
    assert "[bold]falso[/bold]" in texto
    assert "error [/x] en stderr" in texto
