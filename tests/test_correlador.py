"""Correlador: deduplicación por alias y confianza combinada entre fuentes."""

import pytest

from eslabon.colectores import Colector, ColectorDepsDev, ColectorScorecard
from eslabon.colectores.osv import hallazgos_desde_osv
from eslabon.correlador import confianza_combinada, correlacionar, severidad_por_confianza
from eslabon.escaneo import escanear
from eslabon.modelos import Ecosistema, Evidencia, Finding, Severidad, Tipo
from eslabon.sbom import paquete_desde_texto
from eslabon.senales import evidencia, hallazgo_de_senales


class _OSVGrabado(Colector):
    """OSV-Scanner reemplazado por su salida real grabada (sin red ni binario)."""

    nombre = "osv"

    def __init__(self, documento):
        self.documento = documento

    def recolectar(self, paquetes, ctx):
        return hallazgos_desde_osv(self.documento)


# ---------------------------------------------------------------------------
# CONDICIÓN DE SALIDA DE F2: un paquete malicioso conocido produce UN único hallazgo
# deduplicado que cita 2 o más fuentes y trae su explicación.
# ---------------------------------------------------------------------------
def test_condicion_salida_f2_flatmap_stream(osv_maliciosos, depsdev_grabado):
    resultado = escanear(
        paquete_desde_texto("npm:flatmap-stream@0.1.1"),
        [_OSVGrabado(osv_maliciosos), ColectorDepsDev(), ColectorScorecard()],
        timeout=30,
        depsdev=depsdev_grabado,
    )
    del_paquete = [h for h in resultado.hallazgos if h.paquete == "flatmap-stream"]

    # OSV por sí solo daba 3 hallazgos (MAL-2025-20690, GHSA-9x64, GHSA-mh6f):
    assert len([g for r in osv_maliciosos["results"] for p in r["packages"]
                if p["package"]["name"] == "flatmap-stream" for g in p["groups"]]) == 3
    # ...y tras correlacionar queda exactamente uno:
    assert len(del_paquete) == 1
    h = del_paquete[0]
    assert h.tipo is Tipo.MALICIOSO
    assert h.severidad is Severidad.CRITICA
    assert set(h.fuentes) >= {"osv", "depsdev"}
    assert h.ids[0] == "MAL-2025-20690"
    assert {"GHSA-9x64-5r7x-2q53", "GHSA-mh6f-8j2x-4483"} <= set(h.ids)
    assert h.attack == ["T1195.001"]
    # Confianza: osv (MAL-, 0.95) y deps.dev (tapón -security, 0.90) como independientes.
    assert h.confianza == pytest.approx(1 - (1 - 0.95) * (1 - 0.90), abs=1e-4)
    # La explicación dice de dónde sale cada cosa.
    assert "osv" in h.explicacion and "depsdev" in h.explicacion
    assert "0.9950" in h.explicacion or "0.99" in h.explicacion
    assert "0.0.1-security" in h.explicacion
    assert resultado.fuentes_omitidas == []


def test_ctx_dos_avisos_sin_alias_quedan_en_un_hallazgo(osv_maliciosos):
    hallazgos = [h for h in correlacionar(hallazgos_desde_osv(osv_maliciosos))
                 if h.paquete == "ctx"]
    assert len(hallazgos) == 1
    assert set(hallazgos[0].ids) >= {"GHSA-67r3-h899-9w95", "PYSEC-2022-199"}
    assert hallazgos[0].tipo is Tipo.MALICIOSO


def test_malware_no_contamina_paquetes_distintos(osv_maliciosos):
    # GHSA-mh6f afecta a event-stream Y a flatmap-stream: son dos paquetes, dos hallazgos.
    hallazgos = correlacionar(hallazgos_desde_osv(osv_maliciosos))
    assert sorted(h.paquete for h in hallazgos) == ["ctx", "event-stream", "flatmap-stream"]


# ---------------------------------------------------------------------------
# Unidades
# ---------------------------------------------------------------------------
def _h(ids, tipo=Tipo.VULN, fuente="osv", peso=0.9, sev=Severidad.ALTA, paquete="x"):
    return Finding(ecosistema=Ecosistema.NPM, paquete=paquete, version="1.0.0", tipo=tipo,
                   ids=ids, severidad=sev, confianza=peso, explicacion=f"de {fuente}",
                   evidencia=[Evidencia(fuente=fuente, descripcion=f"{ids[0]} vista por {fuente}",
                                        tipo=tipo, peso=peso)])


def test_alias_compartido_une_hallazgos_de_fuentes_distintas():
    a = _h(["CVE-2020-1", "GHSA-aaaa"], fuente="osv", peso=0.9)
    b = _h(["GHSA-aaaa"], fuente="otra", peso=0.5, sev=Severidad.CRITICA)
    [h] = correlacionar([a, b])
    assert h.ids == ["CVE-2020-1", "GHSA-aaaa"]
    assert h.fuentes == ["osv", "otra"]
    assert h.severidad is Severidad.CRITICA  # vuln: la mayor de las severidades
    assert h.confianza == pytest.approx(1 - 0.1 * 0.5)


def test_union_transitiva_de_alias():
    # A~B por GHSA-1 y B~C por CVE-2: los tres son el mismo problema.
    hallazgos = [_h(["GHSA-1"]), _h(["GHSA-1", "CVE-2"]), _h(["CVE-2", "PYSEC-3"])]
    [h] = correlacionar(hallazgos)
    assert h.ids == ["CVE-2", "GHSA-1", "PYSEC-3"]


def test_vulns_distintas_no_se_unen():
    assert len(correlacionar([_h(["CVE-1"]), _h(["CVE-2"])])) == 2


def test_mismo_id_en_paquetes_distintos_no_se_une():
    assert len(correlacionar([_h(["CVE-1"], paquete="a"), _h(["CVE-1"], paquete="b")])) == 2


def test_senales_debiles_de_fuentes_distintas_se_refuerzan(ctx):
    reciente = _h(["ESL-A"], Tipo.SOSPECHOSO, "depsdev", 0.20, Severidad.INFO)
    red_en_instalacion = _h(["ESL-B"], Tipo.SOSPECHOSO, "guarddog", 0.60, Severidad.INFO)
    origen = _h(["ESL-C"], Tipo.RIESGO_ORIGEN, "scorecard", 0.30, Severidad.INFO)
    vuln = _h(["CVE-9"])

    solas = [correlacionar([x])[0] for x in (reciente, red_en_instalacion, origen)]
    assert [s.severidad for s in solas] == [Severidad.INFO, Severidad.MEDIA, Severidad.BAJA]

    resultado = correlacionar([reciente, red_en_instalacion, origen, vuln])
    assert len(resultado) == 2  # la CVE no se mezcla con las señales débiles
    [combinado] = [h for h in resultado if h.tipo is not Tipo.VULN]
    assert combinado.tipo is Tipo.SOSPECHOSO
    assert combinado.confianza == pytest.approx(1 - 0.8 * 0.4 * 0.7)  # 0.776
    assert combinado.severidad is Severidad.MEDIA
    assert combinado.attack == ["T1195.001", "T1195.002"]
    assert "1 − (1 − 0.20) · (1 − 0.60) · (1 − 0.30)" in combinado.explicacion


def test_dentro_de_una_fuente_se_toma_la_senal_mas_fuerte():
    evidencias = [evidencia("guarddog", "guarddog-amenaza-alta"),
                  evidencia("guarddog", "guarddog-amenaza-media"),
                  evidencia("depsdev", "depsdev-version-reciente")]
    confianza, por_fuente = confianza_combinada(evidencias)
    assert por_fuente == {"guarddog": 0.6, "depsdev": 0.2}
    assert confianza == pytest.approx(1 - 0.4 * 0.8)


def test_malicioso_absorbe_senales_debiles_del_mismo_paquete():
    mal = _h(["MAL-1"], Tipo.MALICIOSO, "osv", 0.95)
    sosp = _h(["ESL-X"], Tipo.SOSPECHOSO, "guarddog", 0.6)
    [h] = correlacionar([mal, sosp])
    assert h.tipo is Tipo.MALICIOSO
    assert h.severidad is Severidad.CRITICA
    assert h.fuentes == ["osv", "guarddog"]


@pytest.mark.parametrize(("confianza", "sev"), [
    (0.0, Severidad.INFO), (0.24, Severidad.INFO), (0.25, Severidad.BAJA),
    (0.5, Severidad.MEDIA), (0.8, Severidad.ALTA), (0.99, Severidad.ALTA),
])
def test_bandas_de_confianza(confianza, sev):
    assert severidad_por_confianza(confianza) is sev


def test_patron_del_encargo_con_dos_senales_npm_queda_en_media():
    # El patrón del encargo: publicador nuevo + script de instalación con red + versión reciente.
    p = paquete_desde_texto("npm:x@1.0.0")
    senales = [
        hallazgo_de_senales(p, [evidencia("npm", "npm-publicador-nuevo"),
                                evidencia("npm", "npm-script-instalacion-red")]),
        hallazgo_de_senales(p, [evidencia("depsdev", "depsdev-version-reciente")]),
        hallazgo_de_senales(p, [evidencia("guarddog", "guarddog-amenaza-alta")]),
    ]
    [h] = correlacionar(senales)
    # npm aporta 0.35 (máximo de su fuente), deps.dev 0.20 y GuardDog 0.60.
    assert h.confianza == pytest.approx(1 - 0.65 * 0.8 * 0.4, abs=1e-3)  # 0.792
    assert h.severidad is Severidad.MEDIA
