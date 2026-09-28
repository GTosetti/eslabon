"""El escaneo debe degradar con elegancia: una fuente rota no tumba las demás."""

from eslabon import escaneo
from eslabon.colectores import Colector
from eslabon.ejecutor import HerramientaNoDisponible
from eslabon.modelos import Ecosistema, Evidencia, Finding, Severidad, Tipo
from eslabon.sbom import Inventario, paquete_desde_texto


class _ColectorRoto(Colector):
    nombre = "roto"

    def recolectar(self, paquetes, ctx):
        raise HerramientaNoDisponible("no instalada")


class _ColectorFijo(Colector):
    nombre = "fijo"

    def __init__(self, severidades):
        self.severidades = severidades

    def recolectar(self, paquetes, ctx):
        assert ctx.dir_trabajo.is_dir()
        return [
            Finding(ecosistema=Ecosistema.PYPI, paquete=p.nombre, version=p.version,
                    tipo=Tipo.VULN, ids=[f"X-{n}"], severidad=sev, confianza=0.5,
                    evidencia=[Evidencia(fuente="fijo", descripcion="-")],
                    explicacion="prueba")
            for p in paquetes for n, sev in enumerate(self.severidades)
        ]


def test_colector_roto_se_anota_y_los_demas_siguen():
    resultado = escaneo.escanear(
        paquete_desde_texto("pypi:requests@2.19.0"),
        [_ColectorRoto(), _ColectorFijo([Severidad.BAJA, Severidad.CRITICA])],
        timeout=30,
    )
    assert [o.fuente for o in resultado.fuentes_omitidas] == ["roto"]
    assert "HerramientaNoDisponible" in resultado.fuentes_omitidas[0].motivo
    assert resultado.fuentes_usadas == ["fijo"]
    # Ordenados de más a menos grave.
    assert [h.severidad for h in resultado.hallazgos] == [Severidad.CRITICA, Severidad.BAJA]


def test_si_syft_falla_se_anota(monkeypatch, tmp_path):
    def falla(*a, **k):
        raise HerramientaNoDisponible("syft no está en el PATH")

    monkeypatch.setattr(escaneo, "generar_sbom", falla)
    resultado = escaneo.escanear(tmp_path, [_ColectorFijo([Severidad.ALTA])], timeout=30)
    assert resultado.fuentes_omitidas[0].fuente == "syft"
    assert resultado.paquetes == []
    assert resultado.hallazgos == []


def test_paquete_suelto_no_usa_syft(monkeypatch):
    monkeypatch.setattr(escaneo, "generar_sbom", lambda *a, **k: 1 / 0)
    resultado = escaneo.escanear(paquete_desde_texto("npm:lodash@4.17.15"), [], timeout=30)
    assert [p.purl for p in resultado.paquetes] == ["pkg:npm/lodash@4.17.15"]
    assert resultado.fuentes_omitidas == []


def test_sin_paquetes_los_colectores_no_cuentan_como_usados(monkeypatch, tmp_path):
    monkeypatch.setattr(escaneo, "generar_sbom", lambda *a, **k: Inventario(paquetes=[]))
    resultado = escaneo.escanear(tmp_path, [_ColectorFijo([Severidad.ALTA])], timeout=30)
    assert resultado.fuentes_usadas == ["syft"]
    # Un inventario vacío no es un resultado limpio: se informa y el análisis es incompleto.
    assert "inventario vacío" in resultado.fuentes_omitidas[0].motivo
    assert resultado.completo is False


def test_si_syft_falla_el_analisis_es_incompleto(monkeypatch, tmp_path):
    def falla(*a, **k):
        raise HerramientaNoDisponible("syft no está en el PATH")

    monkeypatch.setattr(escaneo, "generar_sbom", falla)
    assert escaneo.escanear(tmp_path, [], timeout=30).completo is False


def test_motivos_redactados(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_TOKEN", "token-super-secreto-99")

    def falla(*a, **k):
        raise RuntimeError("error con token-super-secreto-99 en la salida")

    monkeypatch.setattr(escaneo, "generar_sbom", falla)
    resultado = escaneo.escanear(tmp_path, [], timeout=30)
    assert "token-super-secreto-99" not in resultado.fuentes_omitidas[0].motivo


# --- Revisión insecure-defaults (F2): fuentes requeridas -----------------------------------
class _ColectorCaido(Colector):
    nombre = "guarddog"

    def recolectar(self, paquetes, ctx):
        raise HerramientaNoDisponible("Docker no responde")


def test_fuente_no_esencial_caida_no_cambia_completo_salvo_si_se_requiere():
    paquete = paquete_desde_texto("npm:lodash@4.17.15")
    normal = escaneo.escanear(paquete, [_ColectorCaido()], timeout=30)
    assert normal.completo is True  # por defecto: aviso de fuente omitida, nada más
    exigido = escaneo.escanear(paquete, [_ColectorCaido()], timeout=30,
                               requeridas={"guarddog"})
    assert exigido.completo is False
    assert exigido.fuentes_omitidas[0].fuente == "guarddog"


def test_cli_requerir_fuente_desconocida_es_error_de_uso():
    from typer.testing import CliRunner

    from eslabon import cli

    r = CliRunner().invoke(cli.app, ["scan", "npm:x@1.0.0", "--requerir", "guarddog",
                                     "--guarddog-max", "0"])
    assert r.exit_code == 2 and "guarddog" in r.output
