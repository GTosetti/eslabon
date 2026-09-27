import pytest

from eslabon.colectores.osv import clasificar_aviso, hallazgos_desde_osv
from eslabon.correlador import correlacionar
from eslabon.modelos import Severidad, Tipo


def _buscar(hallazgos, paquete, id_):
    return next(h for h in hallazgos if h.paquete == paquete and id_ in h.ids)


def test_un_hallazgo_por_grupo_de_alias(osv_demo):
    hallazgos = hallazgos_desde_osv(osv_demo)
    grupos = sum(len(p["groups"]) for r in osv_demo["results"] for p in r["packages"])
    assert len(hallazgos) == grupos
    # Ningún ID aparece en dos hallazgos del mismo paquete: los alias quedan juntos.
    for paquete in {h.paquete for h in hallazgos}:
        ids = [i for h in hallazgos if h.paquete == paquete for i in h.ids]
        assert len(ids) == len(set(ids)), paquete


def test_alias_ordenados_cve_primero(osv_demo):
    h = _buscar(hallazgos_desde_osv(osv_demo), "jinja2", "PYSEC-2019-217")
    assert h.ids[0] == "CVE-2019-10906"
    assert set(h.ids) >= {"GHSA-462w-v97r-4m45", "PYSEC-2019-217"}


def test_severidad_desde_cvss_y_explicacion(osv_demo):
    h = _buscar(hallazgos_desde_osv(osv_demo), "jinja2", "CVE-2019-10906")
    assert h.severidad is Severidad.ALTA  # max_severity 8.6
    assert h.tipo is Tipo.VULN
    assert h.fuentes == ["osv"]
    assert h.attack == []
    assert "8.6" in h.explicacion
    assert h.remediacion and "2.10.1" in h.remediacion
    assert all(e.referencia.startswith("https://osv.dev/vulnerability/") for e in h.evidencia)


def test_minimist_critica(osv_demo):
    h = _buscar(hallazgos_desde_osv(osv_demo), "minimist", "GHSA-xvch-5gv4-984h")
    assert h.severidad is Severidad.CRITICA  # 9.8


def _doc_sintetico(ids, max_severity, vulns):
    """Documento con la misma forma que la salida de osv-scanner (datos sintéticos)."""
    return {"results": [{"source": {"path": "x", "type": "sbom"}, "packages": [{
        "package": {"name": "paquete-falso", "version": "1.0.0", "ecosystem": "npm"},
        "groups": [{"ids": ids, "aliases": ids, "max_severity": max_severity}],
        "vulnerabilities": vulns,
    }]}]}


def test_aviso_mal_es_malicioso_critico_y_mapea_t1195_001():
    doc = _doc_sintetico(["MAL-2099-0001"], "", [{
        "id": "MAL-2099-0001", "summary": "Malicious code in paquete-falso (npm)",
        "affected": [{"package": {"name": "paquete-falso", "ecosystem": "npm"}}],
    }])
    # El colector clasifica; la política (crítico, remediación) la aplica el correlador.
    [h] = correlacionar(hallazgos_desde_osv(doc))
    assert h.tipo is Tipo.MALICIOSO
    assert h.severidad is Severidad.CRITICA
    assert h.attack == ["T1195.001"]
    assert "Retirar" in h.remediacion


def test_sin_cvss_se_asume_media_y_se_explica():
    doc = _doc_sintetico(["GHSA-aaaa-bbbb-cccc"], "", [{
        "id": "GHSA-aaaa-bbbb-cccc", "details": "Primera línea.\nResto.",
        "affected": [{"package": {"name": "paquete-falso"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}],
    }])
    [h] = hallazgos_desde_osv(doc)
    assert h.severidad is Severidad.MEDIA
    assert "no publica CVSS" in h.explicacion
    assert h.titulo == "Primera línea."
    assert h.remediacion == "Actualizar a 1.0.1 o posterior."


def test_ecosistemas_fuera_de_alcance_se_ignoran():
    doc = _doc_sintetico(["GO-2020-0001"], "7.5", [])
    doc["results"][0]["packages"][0]["package"]["ecosystem"] = "Go"
    assert hallazgos_desde_osv(doc) == []


def test_rangos_git_no_se_proponen_como_version():
    doc = _doc_sintetico(["GHSA-dddd-eeee-ffff"], "5.0", [{
        "id": "GHSA-dddd-eeee-ffff", "summary": "x",
        "affected": [{"package": {"name": "paquete-falso"}, "ranges": [
            {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "8a7f1c2e9b"}]},
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]},
        ]}],
    }])
    [h] = hallazgos_desde_osv(doc)
    assert h.remediacion == "Actualizar a 1.2.0 o posterior."


def test_nombres_pypi_se_normalizan_pep503():
    doc = _doc_sintetico(["PYSEC-2099-1"], "5.0", [{
        "id": "PYSEC-2099-1", "summary": "x",
        "affected": [{"package": {"name": "Typing.Extensions"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.1"}]}]}],
    }])
    pkg = doc["results"][0]["packages"][0]["package"]
    pkg.update(name="typing_extensions", ecosystem="PyPI")
    [h] = hallazgos_desde_osv(doc)
    assert h.remediacion == "Actualizar a 4.1 o posterior."


# --- Detección de paquetes maliciosos (revisión de F2) ---------------------------------


@pytest.mark.parametrize(("resumen", "nombre", "senal"), [
    # Avisos reales de malware (OSV/GHSA):
    ("Malicious code in flatmap-stream (npm)", "flatmap-stream", "osv-texto-malicioso"),
    ("Embedded Malicious Code in ctx", "ctx", "osv-texto-malicioso"),
    ("Embedded malware in ua-parser-js", "ua-parser-js", "osv-texto-malicioso"),
    ("The ctx hosted project on PyPI was taken over via user account compromise", "ctx",
     "osv-texto-malicioso"),
    # Vulnerabilidades corrientes que describen al atacante, no al paquete:
    ("Installing a malicious package can overwrite arbitrary files", "npm", "osv-vuln"),
    ("Accounts can be taken over via password reset", "django", "osv-vuln"),
    ("A malicious user can bypass authentication in requests", "requests", "osv-vuln"),
    ("Malicious code in other-package", "package", "osv-vuln"),  # otro paquete
])
def test_texto_malicioso_solo_si_nombra_al_paquete(resumen, nombre, senal):
    assert clasificar_aviso({"id": "GHSA-x", "summary": resumen}, nombre) == senal


def test_mal_solo_como_alias_sigue_siendo_malicioso():
    # El grupo trae un MAL- como alias pero solo el registro completo del GHSA.
    doc = _doc_sintetico(["GHSA-zzzz"], "7.5", [{"id": "GHSA-zzzz", "summary": "algo"}])
    doc["results"][0]["packages"][0]["groups"][0]["aliases"] = ["GHSA-zzzz", "MAL-2099-7"]
    [h] = correlacionar(hallazgos_desde_osv(doc))
    assert h.tipo is Tipo.MALICIOSO
    assert h.ids[0] == "MAL-2099-7"
    assert h.severidad is Severidad.CRITICA
