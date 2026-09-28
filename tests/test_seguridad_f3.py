"""Regresiones de la revisión de código y de seguridad de F3."""

import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from eslabon import cli, red
from eslabon.colectores import ColectorGuardDog, colectores_por_defecto
from eslabon.colectores.osv import ColectorOSV
from eslabon.ejecutor import HerramientaFallo
from eslabon.modelos import (
    Ecosistema,
    Evidencia,
    Finding,
    Paquete,
    ResultadoScan,
    Severidad,
    Tipo,
)
from eslabon.salidas import sarif, siem
from eslabon.sbom import inventario_desde_syft, paquete_desde_texto
from eslabon.senales import evidencia, hallazgo_de_senales

runner = CliRunner()


def _resultado(hallazgos=(), completo=True):
    return ResultadoScan(objetivo="pkg:npm/x@1.0.0", eslabon_version="0.1.0",
                         paquetes=[paquete_desde_texto("npm:x@1.0.0")],
                         hallazgos=list(hallazgos), fuentes_usadas=["osv"],
                         fuentes_omitidas=[], completo=completo)


def _vuln(ids, sev=Severidad.ALTA, paquete="x"):
    return Finding(ecosistema=Ecosistema.NPM, paquete=paquete, version="1.0.0", tipo=Tipo.VULN,
                   ids=ids, severidad=sev, confianza=0.9, explicacion="-",
                   evidencia=[Evidencia(fuente="osv", descripcion=ids[0], tipo=Tipo.VULN,
                                        peso=0.9)])


# --- H2: el CLI no falla "en abierto" ---------------------------------------------------
@pytest.mark.parametrize(("severidades", "umbral", "completo", "degradado_ok", "codigo"), [
    ([], "alta", True, False, 0),
    ([Severidad.MEDIA], "alta", True, False, 0),
    ([Severidad.ALTA], "alta", True, False, 1),
    ([Severidad.CRITICA], "critica", True, False, 1),
    ([Severidad.CRITICA], "nunca", True, False, 0),
    ([], "alta", False, False, 3),     # incompleto con 0 hallazgos: NO es "limpio"
    ([], "alta", False, True, 0),      # salvo que se pida explícitamente
])
def test_codigos_de_salida(severidades, umbral, completo, degradado_ok, codigo):
    hallazgos = [_vuln([f"CVE-{i}"], s) for i, s in enumerate(severidades)]
    assert cli.codigo_de_salida(_resultado(hallazgos, completo), cli.Umbral(umbral),
                                degradado_ok) == codigo


def test_anexar_escribe_utf8_sin_bom_ni_lineas_vacias(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "escanear", lambda *a, **k: _resultado())
    destino = tmp_path / "eventos.jsonl"
    for _ in range(2):
        r = runner.invoke(cli.app, ["scan", "npm:x@1.0.0", "-f", "siem", "-o", str(destino),
                                    "--anexar"])
        assert r.exit_code == 0, r.output
    datos = destino.read_bytes()
    assert not datos.startswith(b"\xef\xbb\xbf")
    lineas = datos.decode("utf-8").split("\n")
    assert lineas[-1] == "" and all(lineas[:-1])  # 2 resúmenes, sin líneas en blanco
    assert len(lineas[:-1]) == 2


def test_guarddog_max_cero_lo_desactiva_del_todo():
    assert not any(isinstance(c, ColectorGuardDog) for c in colectores_por_defecto(0))
    assert any(isinstance(c, ColectorGuardDog) for c in colectores_por_defecto(5))


# --- SARIF: reglas y huellas ---------------------------------------------------------------
def test_regla_separada_por_severidad_en_senales():
    p1, p2 = paquete_desde_texto("npm:a@1.0.0"), paquete_desde_texto("npm:b@1.0.0")
    alto = hallazgo_de_senales(p1, [evidencia("guarddog", "guarddog-veredicto-high_risk")])
    alto = alto.model_copy(update={"severidad": Severidad.ALTA})
    medio = hallazgo_de_senales(p2, [evidencia("guarddog", "guarddog-veredicto-high_risk")])
    medio = medio.model_copy(update={"severidad": Severidad.MEDIA})
    run = sarif.construir(_resultado([alto, medio]))["runs"][0]
    reglas = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(reglas) == {"ESL-SOSPECHOSO-ALTA", "ESL-SOSPECHOSO-MEDIA"}
    assert reglas["ESL-SOSPECHOSO-ALTA"]["properties"]["security-severity"] == "8.0"
    assert "a@" not in reglas["ESL-SOSPECHOSO-ALTA"]["shortDescription"]["text"]


def test_huella_estable_si_se_publica_un_cve():
    antes = _vuln(["GHSA-aaaa-bbbb-cccc"])
    despues = _vuln(["GHSA-aaaa-bbbb-cccc", "CVE-2026-1"])  # el CVE pasa a ser ids[0]
    assert despues.ids[0] == "CVE-2026-1"
    assert sarif.huella(antes) == sarif.huella(despues)
    assert sarif.regla_de(antes) == sarif.regla_de(despues) == "GHSA-aaaa-bbbb-cccc"


def test_huella_de_compromiso_estable_al_cambiar_las_senales():
    p = paquete_desde_texto("npm:a@1.0.0")
    una = hallazgo_de_senales(p, [evidencia("depsdev", "depsdev-version-reciente")])
    otra = hallazgo_de_senales(p, [evidencia("guarddog", "guarddog-amenaza-alta")])
    assert sarif.huella(una) == sarif.huella(otra)


def test_sarif_incompleto_no_es_exitoso():
    run = sarif.construir(_resultado(completo=False))["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False


RAIZ = Path.cwd()


def test_uri_codificada_y_sin_escapar_de_la_raiz():
    assert sarif._uri("\\mi proyecto\\requirements.txt", None, RAIZ) == \
        "mi%20proyecto/requirements.txt"
    assert sarif._uri("/a#b/package-lock.json", None, RAIZ) == "a%23b/package-lock.json"
    assert sarif._uri("../../fuera/package-lock.json", None, RAIZ) is None
    assert sarif._uri("C:/Users/x/package-lock.json", None, RAIZ) is None


# --- M1: nombres hostiles en el lockfile --------------------------------------------------
@pytest.mark.parametrize("nombre", ["--help", "-x", "..", ".", 'x"&calc&"', "a b",
                                    "x\x1b[31m", "../etc"])
def test_nombres_hostiles_se_rechazan(nombre):
    with pytest.raises(ValidationError):
        Paquete(ecosistema=Ecosistema.NPM, nombre=nombre, version="1.0.0")


@pytest.mark.parametrize("version", ["--exit-non-zero-on-finding", "..", "", "1.0 && x"])
def test_versiones_hostiles_se_rechazan(version):
    with pytest.raises(ValidationError):
        Paquete(ecosistema=Ecosistema.PYPI, nombre="requests", version=version)


@pytest.mark.parametrize(("eco", "nombre", "version"), [
    (Ecosistema.NPM, "@babel/core", "7.0.0-beta.1"),
    (Ecosistema.NPM, "JSONStream", "1.3.5"),
    (Ecosistema.PYPI, "zope.interface", "1!2.0+local.1"),
])
def test_nombres_reales_se_aceptan(eco, nombre, version):
    Paquete(ecosistema=eco, nombre=nombre, version=version)


def test_inventario_informa_descartados_y_no_soportados():
    doc = {"artifacts": [
        {"type": "npm", "name": "--help", "version": "1.0.0"},
        {"type": "npm", "name": "ok", "version": "1.0.0"},
        {"type": "go-module", "name": "x", "version": "1"},
        {"type": "go-module", "name": "y", "version": "1"},
    ]}
    inventario = inventario_desde_syft(doc)
    assert [p.nombre for p in inventario.paquetes] == ["ok"]
    avisos = " ".join(inventario.avisos())
    assert "1 entradas descartadas" in avisos and "2 go-module" in avisos


def test_inventario_informa_dependencias_sin_version():
    # Revisión insecure-defaults (F1): un artefacto de Syft sin versión se omitía en silencio.
    # (Syft 1.52 no emite "flask>=2" de un requirements.txt: lo omite él mismo, límite
    # documentado en docs/revision-insecure-defaults.md. Esto cubre los catalogadores que sí
    # lo emiten sin versión.)
    doc = {"artifacts": [{"type": "python", "name": "flask", "version": ""},
                         {"type": "python", "name": "requests", "version": "2.32.3"}]}
    inventario = inventario_desde_syft(doc)
    assert [p.nombre for p in inventario.paquetes] == ["requests"]
    assert "1 dependencias sin versión fijada" in " ".join(inventario.avisos())
    assert "'flask'" in " ".join(inventario.avisos())


# --- M2: OSV que no analizó nada no es "limpio" --------------------------------------------
def test_osv_sin_salida_es_fallo(ctx, monkeypatch):
    monkeypatch.setattr("eslabon.colectores.osv.ejecutar_json", lambda *a, **k: None)
    with pytest.raises(HerramientaFallo, match="salida vacía"):
        ColectorOSV().recolectar([paquete_desde_texto("npm:x@1.0.0")], ctx)


# --- L2: eventos SIEM a prueba de saltos de línea Unicode ----------------------------------
def test_siem_escapa_separadores_unicode():
    h = _vuln(["CVE-1"]).model_copy(update={"titulo": "a\u2028b\u0085c\nd"})
    texto = siem.renderizar(_resultado([h]))
    assert all(ord(c) < 128 for c in texto)
    assert len(texto.splitlines()) == 2  # hallazgo + resumen
    assert json.loads(texto.splitlines()[0])["eslabon"]["titulo"] == "a\u2028b\u0085c\nd"


# --- L5: cliente HTTP ---------------------------------------------------------------------
def test_red_rechaza_redireccion_a_http():
    manejador = red._RedireccionSegura()
    peticion = urllib.request.Request("https://api.deps.dev/v3/x")
    with pytest.raises(red.ErrorRed, match="redirección rechazada"):
        manejador.redirect_request(peticion, None, 302, "Found", {}, "http://api.deps.dev/v3/x")
    with pytest.raises(red.ErrorRed):
        manejador.redirect_request(peticion, None, 302, "Found", {}, "https://evil.test/x")


def test_red_limite_de_tamano(monkeypatch):
    monkeypatch.setattr(red, "MAX_BYTES", 10)
    monkeypatch.setattr(red._ABRIDOR, "open",
                        lambda *a, **k: io.BytesIO(b'{"a": "' + b"x" * 50 + b'"}'))
    with pytest.raises(red.ErrorRed, match="mayor que"):
        red.obtener_json("https://api.deps.dev/v3/x", timeout=5)


def test_red_404_es_none(monkeypatch):
    def no_existe(*a, **k):
        raise urllib.error.HTTPError("https://api.deps.dev/v3/x", 404, "Not Found", {}, None)

    monkeypatch.setattr(red._ABRIDOR, "open", no_existe)
    assert red.obtener_json("https://api.deps.dev/v3/x", timeout=5) is None
