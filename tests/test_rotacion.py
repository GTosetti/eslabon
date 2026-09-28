"""F6: rotación del fichero de eventos (el SIEM lo lee con --anexar)."""

from typer.testing import CliRunner

from eslabon import cli
from eslabon.modelos import ResultadoScan
from eslabon.salidas.fichero import escribir
from eslabon.sbom import paquete_desde_texto


def test_sin_limite_no_rota(tmp_path):
    f = tmp_path / "eventos.jsonl"
    for _ in range(3):
        assert escribir(f, "x" * 100 + "\n", anexar=True) is None
    assert f.read_text(encoding="utf-8").count("\n") == 3
    assert list(tmp_path.iterdir()) == [f]


def test_rota_al_superar_el_limite_y_conserva_n_copias(tmp_path):
    f = tmp_path / "eventos.jsonl"
    linea = "x" * 99 + "\n"  # 100 bytes
    rotaciones = [escribir(f, linea, anexar=True, rotar_bytes=250, conservar=2) for _ in range(9)]
    # Caben 2 líneas por fichero: rota antes de la 3.ª, la 5.ª, la 7.ª y la 9.ª.
    assert [r is not None for r in rotaciones] == [False, False, True, False, True, False,
                                                   True, False, True]
    nombres = sorted(p.name for p in tmp_path.iterdir())
    assert nombres == ["eventos.jsonl", "eventos.jsonl.1", "eventos.jsonl.2"]  # conservar=2
    assert f.stat().st_size == 100  # el actual empezó de cero con la 9.ª línea
    assert all(p.stat().st_size == 200 for p in tmp_path.glob("eventos.jsonl.*"))


def test_sin_anexar_no_rota(tmp_path):
    f = tmp_path / "r.json"
    f.write_text("y" * 1000, encoding="utf-8")
    assert escribir(f, "nuevo", rotar_bytes=10) is None
    assert f.read_text(encoding="utf-8") == "nuevo"


def test_cli_rotar_requiere_salida_y_anexar():
    r = CliRunner().invoke(cli.app, ["scan", "npm:x@1.0.0", "--rotar-mb", "1"])
    assert r.exit_code == 2 and "--anexar" in r.output


def test_cli_rota(monkeypatch, tmp_path):
    vacio = ResultadoScan(objetivo="x", eslabon_version="0", hallazgos=[], fuentes_usadas=["osv"],
                          fuentes_omitidas=[], paquetes=[paquete_desde_texto("npm:x@1.0.0")])
    monkeypatch.setattr(cli, "escanear", lambda *a, **k: vacio)
    f = tmp_path / "eventos.jsonl"
    f.write_bytes(b"z" * 2000 + b"\n")  # bytes exactos: write_text pondría "\r\n" en Windows
    r = CliRunner().invoke(cli.app, ["scan", "npm:x@1.0.0", "-f", "siem", "-o", str(f),
                                     "--anexar", "--rotar-mb", "0.001"])
    assert r.exit_code == 0, r.output
    assert (tmp_path / "eventos.jsonl.1").stat().st_size == 2001
    assert '"evento": "resumen"' in f.read_text(encoding="utf-8")


def test_si_windows_impide_renombrar_usa_copiar_y_truncar(monkeypatch, tmp_path):
    # Un lector que abrió el fichero sin FILE_SHARE_DELETE impide el rename en Windows.
    import pathlib

    original = pathlib.Path.replace

    def replace_bloqueado(self, destino):
        if self.name == "eventos.jsonl":
            raise PermissionError("el fichero está abierto por otro proceso")
        return original(self, destino)

    monkeypatch.setattr(pathlib.Path, "replace", replace_bloqueado)
    f = tmp_path / "eventos.jsonl"
    f.write_bytes(b"a" * 300)
    rotado = escribir(f, "nuevo\n", anexar=True, rotar_bytes=100)
    assert rotado.read_bytes() == b"a" * 300       # la copia tiene todo lo anterior
    assert f.read_text(encoding="utf-8") == "nuevo\n"  # el original empezó de cero
