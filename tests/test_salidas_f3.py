"""F3: los tres formatos de salida (SARIF 2.1.0, JSON, eventos SIEM) y las reglas Wazuh/Sigma.

Condición de salida de F3: los formatos se generan y se validan aquí. Las reglas de Wazuh se
comprueban por estructura y por lógica, pero NO contra un wazuh-manager real (ver
integrations/wazuh/README.md).
"""

import functools
import json
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

from eslabon.colectores.guarddog import evidencias_de_guarddog
from eslabon.colectores.osv import hallazgos_desde_osv
from eslabon.correlador import correlacionar
from eslabon.modelos import FuenteOmitida, ResultadoScan, Tipo
from eslabon.salidas import RENDERIZADORES, Formato, sarif, siem
from eslabon.sbom import paquete_desde_texto, paquetes_desde_syft
from eslabon.senales import evidencia, hallazgo_de_senales

RAIZ = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
WAZUH = RAIZ / "integrations" / "wazuh"
SIGMA = RAIZ / "integrations" / "sigma"


@pytest.fixture
def resultado(osv_demo, osv_maliciosos, syft_demo, guarddog_sintetico) -> ResultadoScan:
    """Un resultado con todos los tipos de hallazgo: vuln, malicioso, sospechoso y origen."""
    ficticio = paquete_desde_texto("pypi:paquete-ficticio@1.0.0")
    otro = paquete_desde_texto("pypi:otro-ficticio@2.0.0")
    senales = [
        # Tres fuentes sobre el mismo paquete: 1 − 0.3·0.8·0.7 = 0.83 → sospechoso ALTO.
        hallazgo_de_senales(ficticio, evidencias_de_guarddog(guarddog_sintetico)),
        hallazgo_de_senales(ficticio, [evidencia("depsdev", "depsdev-version-reciente")]),
        hallazgo_de_senales(ficticio, [evidencia("scorecard", "scorecard-dangerous-workflow")]),
        # Una sola fuente (GuardDog, 0.70) → sospechoso MEDIO.
        hallazgo_de_senales(otro, evidencias_de_guarddog(guarddog_sintetico)),
        # Solo el repositorio de origen → riesgo_origen.
        hallazgo_de_senales(paquete_desde_texto("npm:event-stream@4.0.1"), [
            evidencia("scorecard", "scorecard-dangerous-workflow", "github.com/x/y")]),
    ]
    hallazgos = correlacionar([*hallazgos_desde_osv(osv_demo),
                               *hallazgos_desde_osv(osv_maliciosos), *senales])
    return ResultadoScan(
        objetivo="tests/fixtures/proyecto_demo", eslabon_version="0.1.0",
        paquetes=paquetes_desde_syft(syft_demo), hallazgos=hallazgos,
        fuentes_usadas=["syft", "osv", "depsdev", "scorecard"],
        fuentes_omitidas=[FuenteOmitida(fuente="guarddog", motivo="no está en el PATH")])


def test_hay_todos_los_tipos(resultado):
    assert {h.tipo for h in resultado.hallazgos} == set(Tipo)


# --- SARIF ------------------------------------------------------------------------------
def test_sarif_valido_contra_el_esquema_oficial(resultado):
    esquema = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    documento = json.loads(sarif.renderizar(resultado))
    jsonschema.Draft7Validator(esquema).validate(documento)  # lanza si no es válido
    assert documento["version"] == "2.1.0"


def test_sarif_consistente(resultado):
    run = sarif.construir(resultado)["runs"][0]
    reglas = run["tool"]["driver"]["rules"]
    assert len(run["results"]) == len(resultado.hallazgos)
    assert len({r["id"] for r in reglas}) == len(reglas)
    for r in run["results"]:
        regla = reglas[r["ruleIndex"]]
        assert regla["id"] == r["ruleId"]
        # La severidad está en el resultado Y en la regla (algunos lectores solo miran una).
        assert r["level"] == regla["defaultConfiguration"]["level"]
        assert r["partialFingerprints"]["eslabon/v1"]
    avisos = run["invocations"][0]["toolExecutionNotifications"]
    assert "guarddog" in avisos[0]["message"]["text"]


def test_sarif_ubicacion_fisica_y_logica(resultado):
    run = sarif.construir(resultado)["runs"][0]
    por_paquete = {r["properties"]["purl"]: r for r in run["results"]}
    jinja = por_paquete["pkg:pypi/jinja2@2.10"]
    fisica = jinja["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    # Relativa a la raíz del repositorio (%SRCROOT%), con "/" y sin rutas absolutas.
    assert fisica == "tests/fixtures/proyecto_demo/requirements.txt"
    assert jinja["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] == \
        "%SRCROOT%"
    # Un paquete que no vino de un fichero tiene solo ubicación lógica (su purl).
    ficticio = por_paquete["pkg:pypi/paquete-ficticio@1.0.0"]
    assert "physicalLocation" not in ficticio["locations"][0]
    assert ficticio["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == \
        "pkg:pypi/paquete-ficticio@1.0.0"


def test_sarif_srcroot_cambia_la_raiz_de_las_rutas(resultado):
    def uri(raiz):
        run = sarif.construir(resultado, raiz)["runs"][0]
        jinja = next(r for r in run["results"] if r["properties"]["purl"] == "pkg:pypi/jinja2@2.10")
        return jinja["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    # Con la raíz en el proyecto demo (p. ej. un repo escaneado desde fuera), la ruta es la
    # que GitHub espera: relativa a ese repositorio.
    assert uri(FIXTURES / "proyecto_demo") == "requirements.txt"
    assert uri(RAIZ) == "tests/fixtures/proyecto_demo/requirements.txt"


def test_cli_srcroot_solo_con_sarif(tmp_path):
    from typer.testing import CliRunner

    from eslabon import cli

    r = CliRunner().invoke(cli.app, ["scan", "npm:x@1.0.0", "--srcroot", str(tmp_path)])
    assert r.exit_code == 2 and "-f sarif" in r.output


def test_cli_srcroot_por_pantalla_y_a_fichero(monkeypatch, resultado, tmp_path):
    from typer.testing import CliRunner

    from eslabon import cli

    monkeypatch.setattr(cli, "escanear", lambda *a, **k: resultado)
    comando = ["scan", "npm:x@1.0.0", "-f", "sarif", "--fallar-en", "nunca",
               "--permitir-degradado", "--srcroot", str(FIXTURES / "proyecto_demo")]
    pantalla = CliRunner().invoke(cli.app, comando)
    fichero = CliRunner().invoke(cli.app, [*comando, "-o", str(tmp_path / "r.sarif")])
    assert pantalla.exit_code == fichero.exit_code == 0
    for texto in (pantalla.output, (tmp_path / "r.sarif").read_text(encoding="utf-8")):
        assert '"uri": "requirements.txt"' in texto


def test_huella_estable_e_independiente_de_la_ruta(resultado):
    otra_ruta = resultado.model_copy(update={"objetivo": "/otra/maquina/proyecto"})
    huellas = [[r["partialFingerprints"] for r in sarif.construir(x)["runs"][0]["results"]]
               for x in (resultado, otra_ruta)]
    assert huellas[0] == huellas[1]


# --- JSON y eventos SIEM ------------------------------------------------------------------
def test_json_es_el_modelo_completo(resultado):
    doc = json.loads(RENDERIZADORES[Formato.JSON](resultado))
    assert ResultadoScan.model_validate(doc).hallazgos[0].ids == resultado.hallazgos[0].ids


def _eventos(resultado):
    return siem.eventos(resultado, ahora=datetime(2026, 9, 26, tzinfo=UTC),
                        escaneo_id="00000000-0000-0000-0000-000000000000", equipo="pc-test")


def test_siem_json_lines(resultado):
    lineas = siem.renderizar(resultado).splitlines()
    assert len(lineas) == len(resultado.hallazgos) + len(resultado.fuentes_omitidas) + 1
    eventos = [json.loads(linea) for linea in lineas]  # cada línea es un JSON completo
    assert all(list(e) == ["eslabon"] for e in eventos)
    assert len({e["eslabon"]["escaneo_id"] for e in eventos}) == 1


def test_siem_campos_simples_para_el_decoder(resultado):
    for e in _eventos(resultado):
        for clave, valor in e["eslabon"].items():
            es_lista_simple = isinstance(valor, list) and all(isinstance(v, str) for v in valor)
            assert isinstance(valor, str | int | float) or es_lista_simple, clave


def test_siem_huella_coincide_con_sarif(resultado):
    de_sarif = {r["partialFingerprints"]["eslabon/v1"]
                for r in sarif.construir(resultado)["runs"][0]["results"]}
    de_siem = {e["eslabon"]["huella"] for e in _eventos(resultado)
               if e["eslabon"]["evento"] == "hallazgo"}
    assert de_sarif == de_siem


def test_siem_resumen(resultado):
    resumen = _eventos(resultado)[-1]["eslabon"]
    assert resumen["evento"] == "resumen"
    assert resumen["hallazgos"] == len(resultado.hallazgos)
    assert resumen["hallazgos_critica"] >= 3  # flatmap-stream, event-stream, ctx


# --- Reglas de Wazuh (estructura y lógica; NO validadas contra un manager) ---------------
@functools.cache
def _xml(nombre):
    # Los ficheros de reglas de Wazuh tienen varios elementos raíz: se envuelven en uno.
    texto = (WAZUH / nombre).read_text(encoding="utf-8")
    return ET.fromstring(f"<raiz>{texto}</raiz>")  # noqa: S314 - fichero propio del repo


def _reglas():
    return _xml("eslabon_rules.xml").findall(".//rule")


def test_wazuh_xml_bien_formado_y_rango_de_ids():
    ids = [int(r.get("id")) for r in _reglas()]
    assert len(ids) == len(set(ids))
    assert all(100100 <= i <= 100199 for i in ids)
    assert all(0 <= int(r.get("level")) <= 15 for r in _reglas())
    for r in _reglas():
        for padre in (r.findtext("if_sid") or "").replace(" ", "").split(","):
            assert not padre or int(padre) in ids
        for tecnica in r.findall("mitre/id"):
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", tecnica.text)


def _os_regex(patron: str, valor: str) -> bool:
    """Simulación mínima de OS_Regex para el subconjunto usado (^, $, |, \\.+).

    En OS_Regex, "\\." significa "cualquier carácter" (en Python es ".").
    """
    return re.search(patron.replace(r"\.", "."), valor) is not None


def _regla_que_dispara(evento: dict, decoder: str = "json") -> int:
    # El decoder json de Wazuh deja los booleanos como "true"/"false" (no "True").
    campos = {f"eslabon.{k}": json.dumps(v) if isinstance(v, bool) else str(v)
              for k, v in evento["eslabon"].items()}
    reglas = _reglas()

    def cumple(regla):
        if regla.findtext("decoded_as") not in (None, decoder):
            return False
        return all(f.get("name") in campos and _os_regex(f.text, campos[f.get("name")])
                   for f in regla.findall("field"))

    base = [r for r in reglas if r.find("if_sid") is None and cumple(r)]
    assert len(base) == 1, "debe coincidir exactamente una regla base"
    hijas = [r for r in reglas if base[0].get("id") in (r.findtext("if_sid") or "") and cumple(r)]
    assert len(hijas) == 1, f"coinciden {len(hijas)} reglas hijas para {evento}"
    return int(hijas[0].get("id"))


# Regla de Wazuh esperada para cada (tipo, severidad) de hallazgo (ver README de Wazuh).
_REGLA_ESPERADA = {
    ("malicioso", "critica"): 100110,
    ("sospechoso", "alta"): 100120, ("sospechoso", "critica"): 100120,
    ("sospechoso", "media"): 100121,
    ("sospechoso", "baja"): 100122, ("sospechoso", "info"): 100122,
    ("vuln", "critica"): 100140, ("vuln", "alta"): 100141,
    ("vuln", "media"): 100142, ("vuln", "baja"): 100143, ("vuln", "info"): 100143,
}


def _esperada(e: dict) -> int:
    e = e["eslabon"]
    if e["evento"] != "hallazgo":
        if e["evento"] == "resumen":
            return 100160 if e["completo"] else 100161
        return {"fuente_omitida": 100150, "error_programado": 100170}[e["evento"]]
    if e["tipo"] == "riesgo_origen":
        return 100130
    return _REGLA_ESPERADA[(e["tipo"], e["severidad"])]


def test_wazuh_cada_evento_dispara_la_regla_esperada(resultado):
    vistas = set()
    for e in _eventos(resultado):
        esperada = _esperada(e)
        assert _regla_que_dispara(e) == esperada
        vistas.add(esperada)
    assert {100110, 100120, 100121, 100130, 100140, 100141, 100142, 100150, 100160} <= vistas


# Evento que escribe scripts/escaneo_programado.ps1 si eslabon no pudo ejecutarse.
_ERROR_PROGRAMADO = {"eslabon": {"evento": "error_programado", "fecha": "2026-09-29T09:00:00-03:00",
                                 "equipo": "pc-test", "objetivo": "C:/proyectos/app",
                                 "codigo": 2, "motivo": "error de uso"}}


def test_wazuh_escaneo_incompleto_y_error_programado(resultado):
    incompleto = resultado.model_copy(update={"completo": False})
    [resumen] = [e for e in _eventos(incompleto) if e["eslabon"]["evento"] == "resumen"]
    assert _regla_que_dispara(resumen) == 100161
    assert _regla_que_dispara(_ERROR_PROGRAMADO) == 100170


def test_wazuh_variables_de_la_descripcion_existen(resultado):
    campos = {f"eslabon.{k}" for k in _ERROR_PROGRAMADO["eslabon"]}
    for e in _eventos(resultado):
        campos |= {f"eslabon.{k}" for k in e["eslabon"]}
    for r in _reglas():
        for variable in re.findall(r"\$\(([^)]+)\)", r.findtext("description")):
            assert variable in campos, (r.get("id"), variable)


def test_wazuh_mitre_coincide_con_el_mapeo_de_eslabon():
    por_tipo = {"malicioso": {"T1195.001"}, "sospechoso": {"T1195.001"},
                "riesgo_origen": {"T1195.002"}, "vuln": set()}
    for r in _reglas():
        tipo = next((f.text.strip("^$") for f in r.findall("field")
                     if f.get("name") == "eslabon.tipo"), None)
        mitre = {m.text for m in r.findall("mitre/id")}
        if tipo and r.get("level") not in ("0", "3"):
            assert mitre == por_tipo[tipo], r.get("id")


# --- Reglas Sigma -------------------------------------------------------------------------
def _sigma():
    return SigmaCollection.load_ruleset([str(p) for p in sorted(SIGMA.glob("*.yml"))])


def test_sigma_validas_con_pysigma():
    coleccion = _sigma()
    assert len({r.id for r in coleccion.rules}) == len(coleccion.rules) == 6  # UUID únicos
    assert all(not r.errors for r in coleccion.rules)
    assert SigmaValidator(validators.values()).validate_rules(coleccion) == []


def _coincide_sigma(regla: dict, evento: dict) -> bool:
    """Evaluador mínimo del subconjunto usado: una "selection" con igualdades (lista = OR)."""
    assert regla["detection"]["condition"] == "selection"
    for campo, esperado in regla["detection"]["selection"].items():
        valor = evento["eslabon"].get(campo.removeprefix("eslabon."))
        opciones = esperado if isinstance(esperado, list) else [esperado]
        if valor not in opciones:
            return False
    return True


def test_sigma_equivale_a_wazuh(resultado):
    """Cada regla Sigma detecta exactamente los eventos de su regla Wazuh equivalente."""
    equivalencias = {
        "eslabon_paquete_malicioso.yml": {100110},
        "eslabon_paquete_sospechoso_alto.yml": {100120},
        "eslabon_paquete_sospechoso_medio.yml": {100121},
        "eslabon_riesgo_origen.yml": {100130},
        "eslabon_vulnerabilidad_critica.yml": {100140},
        "eslabon_fuente_omitida.yml": {100150},
    }
    eventos = _eventos(resultado)
    for fichero, wazuh in equivalencias.items():
        regla = yaml.safe_load((SIGMA / fichero).read_text(encoding="utf-8"))
        for e in eventos:
            assert _coincide_sigma(regla, e) == (_esperada(e) in wazuh), (fichero, e)


def test_sigma_tags_attack_coinciden_con_el_mapeo():
    esperado = {"eslabon_paquete_malicioso.yml": "attack.t1195.001",
                "eslabon_paquete_sospechoso_alto.yml": "attack.t1195.001",
                "eslabon_paquete_sospechoso_medio.yml": "attack.t1195.001",
                "eslabon_riesgo_origen.yml": "attack.t1195.002"}
    for fichero, tag in esperado.items():
        regla = yaml.safe_load((SIGMA / fichero).read_text(encoding="utf-8"))
        assert tag in regla["tags"]
