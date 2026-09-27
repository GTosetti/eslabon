"""Colectores de deps.dev, Scorecard y GuardDog con respuestas grabadas (sin red)."""

from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

from eslabon import cli
from eslabon.api_depsdev import ClienteDepsDev
from eslabon.colectores import (
    AnalisisParcial,
    ColectorDepsDev,
    ColectorFallo,
    ColectorGuardDog,
    ColectorScorecard,
)
from eslabon.colectores.depsdev import analizar_paquete
from eslabon.colectores.guarddog import evidencias_de_guarddog
from eslabon.colectores.scorecard import evidencias_de_checks
from eslabon.ejecutor import HerramientaFallo, HerramientaNoDisponible
from eslabon.modelos import Tipo
from eslabon.red import ErrorRed
from eslabon.sbom import paquete_desde_texto
from eslabon.senales import hallazgo_de_senales


def _senales(hallazgo):
    return [e.senal for e in hallazgo.evidencia]


# --- deps.dev --------------------------------------------------------------------------
def test_depsdev_detecta_tapon_de_seguridad_de_npm(ctx):
    h = analizar_paquete(paquete_desde_texto("npm:flatmap-stream@0.1.1"), ctx)
    assert _senales(h) == ["depsdev-tapon-seguridad"]
    assert h.tipo is Tipo.MALICIOSO
    assert "0.0.1-security" in h.evidencia[0].descripcion


def test_depsdev_version_retirada(ctx):
    h = analizar_paquete(paquete_desde_texto("npm:event-stream@3.3.6"), ctx)
    assert _senales(h) == ["depsdev-version-retirada"]
    assert h.tipo is Tipo.SOSPECHOSO


def test_depsdev_paquete_inexistente(ctx):
    h = analizar_paquete(paquete_desde_texto("pypi:ctx@0.2.2"), ctx)
    assert _senales(h) == ["depsdev-paquete-inexistente"]


def test_depsdev_version_normal_sin_senales(ctx):
    assert analizar_paquete(paquete_desde_texto("pypi:requests@2.19.0"), ctx) is None


def test_depsdev_version_reciente(ctx):
    # Mismo dato real (requests 2.19.0, publicada el 2018-06-12 14:46), "ahora" el 15 a las 0:00.
    ctx.ahora = datetime(2018, 6, 15, tzinfo=UTC)
    h = analizar_paquete(paquete_desde_texto("pypi:requests@2.19.0"), ctx)
    assert _senales(h) == ["depsdev-version-reciente"]
    assert "hace 2 días" in h.evidencia[0].descripcion  # 2 días y 9 horas


def test_depsdev_reactivacion_tras_inactividad(ctx):
    respuestas = {
        "/systems/npm/packages/dormido": {"versions": [
            {"versionKey": {"version": "1.0.0"}, "publishedAt": "2020-01-01T00:00:00Z"},
            {"versionKey": {"version": "1.0.1"}, "publishedAt": "2026-09-20T00:00:00Z"}]},
        "/systems/npm/packages/dormido/versions/1.0.1": {
            "publishedAt": "2026-09-20T00:00:00Z"},
    }
    ctx.depsdev = ClienteDepsDev(obtener=lambda ruta, t: respuestas[ruta])
    h = analizar_paquete(paquete_desde_texto("npm:dormido@1.0.1"), ctx)
    assert _senales(h) == ["depsdev-version-reciente", "depsdev-reactivacion"]


def test_repositorio_de_origen_usa_la_version_por_defecto(depsdev_grabado):
    # requests 2.19.0 no declara repositorio; la versión por defecto sí.
    p = paquete_desde_texto("pypi:requests@2.19.0")
    assert depsdev_grabado.repositorio_origen(p) == "github.com/psf/requests"


# --- Scorecard -------------------------------------------------------------------------
def test_scorecard_via_depsdev_sin_token(ctx, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    paquetes = [paquete_desde_texto("pypi:requests@2.19.0")]
    assert ColectorScorecard().recolectar(paquetes, ctx) == []  # requests está sano


def test_scorecard_marca_solo_checks_concretos_y_evaluables():
    checks = [
        {"name": "Dangerous-Workflow", "score": -1, "reason": "no evaluable"},
        {"name": "Maintained", "score": 0, "reason": "0 commits"},
        {"name": "Binary-Artifacts", "score": 7, "reason": "binarios"},
        {"name": "Code-Review", "score": 0, "reason": "no se usa como señal"},
    ]
    evidencias = evidencias_de_checks("github.com/o/r", checks, "deps.dev")
    assert [e.senal for e in evidencias] == ["scorecard-sin-mantenimiento",
                                             "scorecard-binary-artifacts"]
    assert all(e.tipo is Tipo.RIESGO_ORIGEN for e in evidencias)


def test_scorecard_event_stream_grabado(ctx, monkeypatch):
    # El repositorio real de event-stream: Maintained 0, Dangerous-Workflow -1 (no evaluable).
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    [h] = ColectorScorecard().recolectar([paquete_desde_texto("npm:event-stream@3.3.6")], ctx)
    assert _senales(h) == ["scorecard-sin-mantenimiento"]
    assert h.evidencia[0].datos["origen"] == "deps.dev"


# --- GuardDog --------------------------------------------------------------------------
def test_guarddog_interpreta_salida(guarddog_sintetico):
    evidencias = evidencias_de_guarddog(guarddog_sintetico)
    senales = [e.senal for e in evidencias]
    assert senales == [
        "guarddog-veredicto-high_risk",
        "guarddog-capacidad",                              # capability-network-outbound
        "guarddog-potentially_compromised_email_domain",   # metadatos (texto)
        "guarddog-amenaza-alta",                           # threat-setup-network-in-install
    ]
    # Una regla YARA sin coincidencias ({}) y las de metadatos en null no son evidencia.
    assert not any("base64exec" in e.descripcion for e in evidencias)
    assert "setup.py:14" in evidencias[-1].descripcion


class _Ejecutor:
    def __init__(self, respuestas):
        self.respuestas = respuestas

    def __call__(self, herramienta, args, **kw):
        assert args[-2] == "--"  # el nombre nunca puede leerse como opción
        r = self.respuestas[args[-1]]
        if isinstance(r, Exception):
            raise r
        return r


def test_guarddog_limite_y_fallos_parciales(ctx, monkeypatch, guarddog_sintetico):
    monkeypatch.setattr("eslabon.colectores.guarddog.ejecutar_json", _Ejecutor({
        "a": guarddog_sintetico,
        "b": {"package": "b", "issues": 0, "errors": {"download-package": "404"}},
        "c": {"issues": 0, "errors": {}, "results": {},
              "risk_score": {"label": "no_risks_detected"}},
    }))
    paquetes = [paquete_desde_texto(f"npm:{n}@1.0.0") for n in "abcd"]
    with pytest.raises(AnalisisParcial) as info:
        ColectorGuardDog(max_paquetes=3).recolectar(paquetes, ctx)
    assert "3 de 4" in str(info.value)
    assert "download-package" in str(info.value)
    assert [h.paquete for h in info.value.hallazgos] == ["a"]


def test_guarddog_si_todo_falla_es_error(ctx, monkeypatch):
    monkeypatch.setattr("eslabon.colectores.guarddog.ejecutar_json",
                        _Ejecutor({"a": HerramientaFallo("sandbox no disponible")}))
    with pytest.raises(ColectorFallo, match="sandbox"):
        ColectorGuardDog().recolectar([paquete_desde_texto("npm:a@1.0.0")], ctx)


def test_tapon_de_seguridad_no_es_repositorio_de_origen(depsdev_grabado):
    # La versión por defecto de flatmap-stream es el tapón de npm (npm/security-holder).
    p = paquete_desde_texto("npm:flatmap-stream@0.1.1")
    assert depsdev_grabado.repositorio_origen(p) is None


def test_un_error_de_red_aislado_no_tira_la_fuente(ctx, depsdev_grabado):

    def obtener(ruta, timeout):
        if "event-stream" in ruta:
            raise ErrorRed("429 Too Many Requests")
        return depsdev_grabado._obtener(ruta, timeout)

    ctx.depsdev = ClienteDepsDev(obtener=obtener)
    paquetes = [paquete_desde_texto(t) for t in ("npm:flatmap-stream@0.1.1",
                                                 "npm:event-stream@3.3.6")]
    with pytest.raises(AnalisisParcial) as info:
        ColectorDepsDev().recolectar(paquetes, ctx)
    assert "fallaron 1 de 2" in str(info.value) and "429" in str(info.value)
    # El tapón -security de flatmap-stream, ya detectado, no se pierde.
    assert [h.paquete for h in info.value.hallazgos] == ["flatmap-stream"]


def test_guarddog_max_negativo_se_rechaza():
    with pytest.raises(ValueError):
        ColectorGuardDog(max_paquetes=-1)
    r = CliRunner().invoke(cli.app, ["scan", "npm:a@1.0.0", "--guarddog-max", "-1"])
    assert r.exit_code == 2


def test_guarddog_ausente_se_dice_claro(ctx, monkeypatch):
    monkeypatch.delenv("ESLABON_GUARDDOG", raising=False)
    monkeypatch.setenv("PATH", "")
    with pytest.raises(HerramientaNoDisponible, match="guarddog no está en el PATH"):
        ColectorGuardDog().recolectar([paquete_desde_texto("npm:a@1.0.0")], ctx)


# --- Salidas REALES de GuardDog v3.2.0 (F4) ------------------------------------------------
def test_guarddog_real_paquete_legitimo_no_genera_hallazgo(ctx, monkeypatch,
                                                         guarddog_real_requests):
    real = guarddog_real_requests
    assert real["risk_score"]["label"] == "no_risks_detected"
    # Solo capacidades: contexto, no hallazgo.
    assert {e.senal for e in evidencias_de_guarddog(real)} == {"guarddog-capacidad"}
    monkeypatch.setattr("eslabon.colectores.guarddog.ejecutar_json", lambda *a, **k: real)
    assert ColectorGuardDog().recolectar([paquete_desde_texto("pypi:requests@2.32.3")], ctx) == []


def test_guarddog_real_muestras_oficiales_de_amenaza(guarddog_real_muestra):
    real = guarddog_real_muestra
    senales = [e.senal for e in evidencias_de_guarddog(real)]
    assert "guarddog-veredicto-high_risk" in senales
    assert senales.count("guarddog-amenaza-alta") == 3  # exfiltración + 2 reglas de setup.py
    [h] = [hallazgo_de_senales(paquete_desde_texto("pypi:muestra@1.0"),
                               evidencias_de_guarddog(real))]
    assert h.tipo is Tipo.SOSPECHOSO
