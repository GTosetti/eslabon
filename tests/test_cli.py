import json

from typer.testing import CliRunner

from eslabon import cli
from eslabon.modelos import ResultadoScan

runner = CliRunner()


def _resultado_vacio(objetivo, colectores, timeout):
    return ResultadoScan(objetivo=objetivo.purl, eslabon_version="0.1.0", paquetes=[], hallazgos=[],
                         fuentes_usadas=["osv"], fuentes_omitidas=[])


def test_version():
    r = runner.invoke(cli.app, ["version"])
    assert r.exit_code == 0
    assert "eslabon" in r.output


def test_objetivo_invalido_sale_con_codigo_2():
    r = runner.invoke(cli.app, ["scan", "esto-no-existe"])
    assert r.exit_code == 2
    assert "Formato esperado" in r.output


def test_scan_json_a_fichero(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "escanear", _resultado_vacio)
    destino = tmp_path / "r.json"
    r = runner.invoke(cli.app, ["scan", "pypi:requests@2.19.0", "-f", "json", "-o", str(destino)])
    assert r.exit_code == 0, r.output
    assert json.loads(destino.read_text(encoding="utf-8"))["objetivo"] == "pkg:pypi/requests@2.19.0"


def test_scan_tabla(monkeypatch):
    monkeypatch.setattr(cli, "escanear", _resultado_vacio)
    r = runner.invoke(cli.app, ["scan", "npm:lodash@4.17.15"])
    assert r.exit_code == 0, r.output
    assert "Hallazgos: 0" in r.output


def test_scan_tabla_a_fichero(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "escanear", _resultado_vacio)
    destino = tmp_path / "r.txt"
    r = runner.invoke(cli.app, ["scan", "npm:lodash@4.17.15", "-o", str(destino)])
    assert r.exit_code == 0, r.output
    assert "Hallazgos: 0" in destino.read_text(encoding="utf-8")
