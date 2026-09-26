import pytest
from pydantic import ValidationError

from eslabon.modelos import (
    Ecosistema,
    Evidencia,
    Finding,
    Paquete,
    Severidad,
    Tipo,
    ordenar_ids,
)


def _finding(**cambios):
    datos = dict(ecosistema=Ecosistema.PYPI, paquete="Typing_Extensions", version="1.0",
                 tipo=Tipo.VULN, ids=["GHSA-x", "CVE-2020-1", "GHSA-x"],
                 severidad=Severidad.ALTA, confianza=0.5, explicacion="-",
                 evidencia=[Evidencia(fuente="osv", descripcion="a"),
                            Evidencia(fuente="depsdev", descripcion="b"),
                            Evidencia(fuente="osv", descripcion="c")])
    datos.update(cambios)
    return Finding(**datos)


def test_ids_quedan_ordenados_y_sin_duplicados():
    assert _finding().ids == ["CVE-2020-1", "GHSA-x"]
    assert ordenar_ids(["PYSEC-1", "MAL-2", "OTRO-3", "GHSA-4"]) == \
        ["MAL-2", "GHSA-4", "PYSEC-1", "OTRO-3"]


def test_finding_sin_ids_es_invalido():
    with pytest.raises(ValidationError):
        _finding(ids=[])


def test_fuentes_y_attack_se_derivan():
    f = _finding()
    assert f.fuentes == ["osv", "depsdev"]
    assert f.attack == []
    assert _finding(tipo=Tipo.MALICIOSO).attack == ["T1195.001"]
    assert _finding(tipo=Tipo.RIESGO_ORIGEN).attack == ["T1195.002"]
    volcado = f.model_dump()
    assert volcado["fuentes"] == ["osv", "depsdev"]
    assert "attack" in volcado


def test_clave_normalizada():
    assert _finding().clave == ("PyPI", "typing-extensions", "1.0")


def test_purl_se_calcula():
    p = Paquete(ecosistema=Ecosistema.NPM, nombre="@babel/core", version="7.0.0")
    assert p.purl == "pkg:npm/%40babel/core@7.0.0"
    assert p.model_dump()["purl"] == p.purl


@pytest.mark.parametrize(("puntaje", "esperada"), [
    (0.0, Severidad.INFO), (3.9, Severidad.BAJA), (4.0, Severidad.MEDIA),
    (8.9, Severidad.ALTA), (9.0, Severidad.CRITICA),
])
def test_bandas_cvss(puntaje, esperada):
    assert Severidad.desde_cvss(puntaje) is esperada
