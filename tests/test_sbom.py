import json

import pytest

from eslabon.modelos import Ecosistema, construir_purl
from eslabon.sbom import (
    escribir_cyclonedx,
    interpretar_objetivo,
    objetivo_syft,
    paquete_desde_texto,
    paquetes_desde_syft,
)


def test_paquetes_desde_syft_lee_ambos_ecosistemas(syft_demo):
    paquetes = paquetes_desde_syft(syft_demo)
    nombres = {(p.ecosistema, p.nombre, p.version) for p in paquetes}
    assert (Ecosistema.PYPI, "requests", "2.19.0") in nombres
    assert (Ecosistema.PYPI, "jinja2", "2.10") in nombres
    assert (Ecosistema.NPM, "lodash", "4.17.15") in nombres
    assert (Ecosistema.NPM, "minimist", "1.2.0") in nombres
    lodash = next(p for p in paquetes if p.nombre == "lodash")
    assert lodash.purl == "pkg:npm/lodash@4.17.15"
    assert any("package-lock.json" in u for u in lodash.ubicaciones)


def test_paquetes_desde_syft_ignora_tipos_no_soportados_y_duplicados():
    doc = {"artifacts": [
        {"type": "go-module", "name": "x", "version": "1"},
        {"type": "npm", "name": "a", "version": "1.0.0", "locations": [{"path": "/p1"}]},
        {"type": "npm", "name": "a", "version": "1.0.0", "locations": [{"path": "/p2"}]},
        {"type": "npm", "name": "sin-version", "version": ""},
    ]}
    paquetes = paquetes_desde_syft(doc)
    assert len(paquetes) == 1
    assert paquetes[0].ubicaciones == ["/p1", "/p2"]
    assert paquetes[0].purl == "pkg:npm/a@1.0.0"


@pytest.mark.parametrize(("texto", "eco", "nombre", "version", "purl"), [
    ("pypi:requests@2.19.0", Ecosistema.PYPI, "requests", "2.19.0", "pkg:pypi/requests@2.19.0"),
    ("npm:lodash@4.17.15", Ecosistema.NPM, "lodash", "4.17.15", "pkg:npm/lodash@4.17.15"),
    ("npm:@babel/core@7.0.0", Ecosistema.NPM, "@babel/core", "7.0.0",
     "pkg:npm/%40babel/core@7.0.0"),
    ("pkg:npm/%40babel/core@7.0.0", Ecosistema.NPM, "@babel/core", "7.0.0",
     "pkg:npm/%40babel/core@7.0.0"),
    ("PyPI:Jinja2@2.10", Ecosistema.PYPI, "Jinja2", "2.10", "pkg:pypi/jinja2@2.10"),
])
def test_paquete_desde_texto(texto, eco, nombre, version, purl):
    p = paquete_desde_texto(texto)
    assert (p.ecosistema, p.nombre, p.version, p.purl) == (eco, nombre, version, purl)


@pytest.mark.parametrize("texto", ["requests", "pypi:requests", "cargo:serde@1.0", "npm:@1.0"])
def test_paquete_desde_texto_rechaza_formatos_invalidos(texto):
    with pytest.raises(ValueError):
        paquete_desde_texto(texto)


def test_construir_purl_normaliza_pypi():
    assert construir_purl(Ecosistema.PYPI, "Typing_Extensions", "4.0") == \
        "pkg:pypi/typing-extensions@4.0"


def test_objetivo_syft_distingue_directorio_y_fichero(tmp_path):
    fichero = tmp_path / "requirements.txt"
    fichero.write_text("x==1\n")
    assert objetivo_syft(tmp_path) == f"dir:{tmp_path}"
    assert objetivo_syft(fichero) == f"file:{fichero}"


def test_escribir_cyclonedx(tmp_path, syft_demo):
    destino = tmp_path / "x.cdx.json"
    escribir_cyclonedx(paquetes_desde_syft(syft_demo), destino)
    doc = json.loads(destino.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert "pkg:pypi/urllib3@1.23" in {c["purl"] for c in doc["components"]}


def test_interpretar_objetivo(tmp_path):
    assert interpretar_objetivo(str(tmp_path)) == tmp_path
    assert interpretar_objetivo("npm:lodash@4.17.15").nombre == "lodash"
    with pytest.raises(ValueError):
        interpretar_objetivo("no-existe-ni-es-paquete")
