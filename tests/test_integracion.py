"""Tests de integración: ejecutan Syft y OSV-Scanner de verdad y consultan api.osv.dev y
api.deps.dev.

Se saltan si las herramientas no están instaladas. Correr con: pytest -m integracion
"""

import shutil

import pytest
from typer.testing import CliRunner

from eslabon import cli
from eslabon.colectores import colectores_por_defecto
from eslabon.escaneo import escanear

pytestmark = [
    pytest.mark.integracion,
    pytest.mark.skipif(not (shutil.which("syft") and shutil.which("osv-scanner")),
                       reason="Syft u OSV-Scanner no están en el PATH"),
]


def test_scan_real_del_proyecto_demo(proyecto_demo):
    resultado = escanear(proyecto_demo, colectores_por_defecto(), timeout=300)
    # GuardDog solo funciona vía Docker en Windows; si no está, es la única omisión aceptable.
    assert {o.fuente for o in resultado.fuentes_omitidas} <= {"guarddog"}
    assert {"syft", "osv", "depsdev", "scorecard"} <= set(resultado.fuentes_usadas)
    afectados = {h.paquete for h in resultado.hallazgos}
    assert {"requests", "jinja2", "urllib3", "lodash", "minimist"} <= afectados


def test_cli_muestra_tabla(proyecto_demo):
    # Terminal ancha: con 80 columnas rich parte los IDs en varias líneas.
    r = CliRunner().invoke(cli.app, ["scan", str(proyecto_demo)], env={"COLUMNS": "250"})
    assert r.exit_code == 0, r.output
    assert "lodash" in r.output
    assert "CVE-2019-10906" in r.output
