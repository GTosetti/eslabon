import os
import sys

import pytest

from eslabon.ejecutor import (
    Herramienta,
    HerramientaFallo,
    HerramientaNoDisponible,
    ejecutar,
    ejecutar_json,
    entorno_seguro,
    redactar,
    resolver_comando,
)

INEXISTENTE = Herramienta("fantasma", "herramienta-que-no-existe-xyz", "ESLABON_TEST_FANTASMA")


def test_herramienta_ausente(monkeypatch):
    monkeypatch.delenv("ESLABON_TEST_FANTASMA", raising=False)
    with pytest.raises(HerramientaNoDisponible, match="ESLABON_TEST_FANTASMA"):
        resolver_comando(INEXISTENTE)


def test_variable_de_entorno_con_comando_compuesto(monkeypatch):
    # El primer elemento se resuelve a una ruta absoluta del PATH (nunca de la carpeta actual).
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", "python -c pass")
    comando = resolver_comando(INEXISTENTE)
    assert os.path.isabs(comando[0]) and comando[1:] == ["-c", "pass"]


def test_variable_de_entorno_con_ruta(monkeypatch):
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", sys.executable)
    assert resolver_comando(INEXISTENTE) == [sys.executable]


def test_ejecutar_devuelve_salida_y_detecta_errores(monkeypatch):
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", sys.executable)
    ok = ejecutar(INEXISTENTE, ["-c", "print('hola')"], timeout=30)
    assert ok.stdout.strip() == "hola"
    with pytest.raises(HerramientaFallo, match="código 3"):
        ejecutar(INEXISTENTE, ["-c", "import sys; sys.exit(3)"], timeout=30)
    tolerado = ejecutar(INEXISTENTE, ["-c", "import sys; sys.exit(1)"], timeout=30,
                        codigos_ok=(0, 1))
    assert tolerado.returncode == 1


def test_ejecutar_respeta_timeout(monkeypatch):
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", sys.executable)
    with pytest.raises(HerramientaFallo, match="tiempo límite"):
        ejecutar(INEXISTENTE, ["-c", "import time; time.sleep(5)"], timeout=0.5)


def test_ejecutar_json(monkeypatch):
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", sys.executable)
    programa = "import json; print(json.dumps({'a': 1}))"
    assert ejecutar_json(INEXISTENTE, ["-c", programa], timeout=30) == {"a": 1}
    assert ejecutar_json(INEXISTENTE, ["-c", "pass"], timeout=30) is None
    with pytest.raises(HerramientaFallo, match="JSON inválido"):
        ejecutar_json(INEXISTENTE, ["-c", "print('no es json')"], timeout=30)


# --- Seguridad (revisión de F3) ---------------------------------------------------------
def test_no_ejecuta_herramientas_de_la_carpeta_actual(monkeypatch, tmp_path):
    # Un repositorio hostil trae su propio "syft": nunca debe ejecutarse desde la carpeta
    # actual, aunque la carpeta actual esté en el PATH.
    herramienta = Herramienta("trampa", "trampa-eslabon", "ESLABON_TEST_TRAMPA")
    for nombre in ("trampa-eslabon.bat", "trampa-eslabon.cmd", "trampa-eslabon.exe",
                   "trampa-eslabon"):
        (tmp_path / nombre).write_text("echo pwned", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ESLABON_TEST_TRAMPA", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join([".", str(tmp_path), ""]))
    with pytest.raises(HerramientaNoDisponible):
        resolver_comando(herramienta)


def test_rechaza_bat_y_cmd(monkeypatch, tmp_path):
    script = tmp_path / "herramienta.bat"
    script.write_text("echo hola", encoding="utf-8")
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", str(script))
    with pytest.raises(HerramientaNoDisponible, match="bat"):
        resolver_comando(INEXISTENTE)


def test_entorno_sin_secretos(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "x" * 36)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secreto-de-prueba")
    monkeypatch.setenv("VARIABLE_NORMAL", "1")
    entorno = entorno_seguro()
    assert "GITHUB_TOKEN" not in entorno and "AWS_SECRET_ACCESS_KEY" not in entorno
    assert entorno["VARIABLE_NORMAL"] == "1"
    assert "GITHUB_TOKEN" in entorno_seguro(permitir=("GITHUB_TOKEN",))


def test_las_herramientas_no_reciben_el_token(monkeypatch):
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", sys.executable)
    monkeypatch.setenv("GITHUB_TOKEN", "valor-secreto-123")
    programa = "import os; print(os.environ.get('GITHUB_TOKEN', 'ausente'))"
    assert ejecutar(INEXISTENTE, ["-c", programa], timeout=30).stdout.strip() == "ausente"


def test_redactar_tokens(monkeypatch):
    monkeypatch.setenv("MI_API_TOKEN", "valor-muy-secreto")
    texto = ("fallo: valor-muy-secreto ghp_" + "a" * 36 + " github_pat_" + "b" * 30
             + " Authorization: Bearer abc")
    limpio = redactar(texto)
    assert "valor-muy-secreto" not in limpio
    assert "ghp_" not in limpio and "github_pat_" not in limpio and "abc" not in limpio


def test_contenedor_docker_con_nombre_y_kill_al_vencer_el_timeout(monkeypatch, tmp_path):
    # Un "docker" falso (Python) que tarda más que el timeout: el ejecutor debe darle un nombre
    # al contenedor y, al vencer el tiempo, llamar a `docker kill <nombre>`.
    llamadas = []
    real_run = __import__("subprocess").run

    def run_espia(comando, **kw):
        llamadas.append(comando)
        if comando[1] == "kill":
            return None
        return real_run([sys.executable, "-c", "import time; time.sleep(5)"], **kw)

    monkeypatch.setattr("eslabon.ejecutor.subprocess.run", run_espia)
    docker = tmp_path / "docker.exe"
    docker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", f'"{docker}" run --rm imagen:1.0')
    with pytest.raises(HerramientaFallo, match="tiempo límite"):
        ejecutar(INEXISTENTE, ["scan"], timeout=0.5)
    lanzado, matado = llamadas
    assert lanzado[:3] == [str(docker), "run", "--name"]
    nombre = lanzado[3]
    assert nombre.startswith("eslabon-fantasma-") and lanzado[4:] == ["--rm", "imagen:1.0", "scan"]
    assert matado == [str(docker), "kill", nombre]


@pytest.mark.parametrize(("comando", "esperado_prefijo", "nombre_fijo"), [
    (["/x/docker", "--context", "lab", "run", "--rm", "img"],
     ["/x/docker", "--context", "lab", "run", "--name"], None),
    (["/x/docker", "container", "run", "img"], ["/x/docker", "container", "run", "--name"], None),
    (["/x/docker", "run", "--name", "mio", "img"], ["/x/docker", "run", "--name", "mio"], "mio"),
    (["/x/docker", "run", "--name=mio", "img"], ["/x/docker", "run", "--name=mio"], "mio"),
])
def test_nombre_del_contenedor(comando, esperado_prefijo, nombre_fijo):
    from eslabon.ejecutor import _nombrar_contenedor

    resultado, nombre = _nombrar_contenedor(comando, INEXISTENTE)
    assert resultado[:len(esperado_prefijo)] == esperado_prefijo
    if nombre_fijo:
        assert nombre == nombre_fijo and resultado == comando  # no se agrega un segundo --name
    else:
        assert nombre.startswith("eslabon-fantasma-") and nombre in resultado


def test_herramienta_sin_docker_no_se_toca():
    from eslabon.ejecutor import _nombrar_contenedor

    assert _nombrar_contenedor(["/x/syft", "run"], INEXISTENTE) == (["/x/syft", "run"], None)


# --- Mensajes de error claros (pedido del usuario, tras el tutorial) -----------------------
def test_sin_json_y_con_error_se_muestra_el_error_real(monkeypatch):
    # GuardDog usa el código 1 para "encontré algo" y también para "falló": si no hay JSON,
    # el mensaje tiene que mostrar lo que la herramienta escribió en stderr.
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", sys.executable)
    programa = "import sys; sys.stderr.write('no pude descargar el paquete'); sys.exit(1)"
    with pytest.raises(HerramientaFallo, match="no pude descargar el paquete"):
        ejecutar_json(INEXISTENTE, ["-c", programa], timeout=30, codigos_ok=(0, 1))
    # Código 0 sin salida sigue siendo "nada que informar".
    assert ejecutar_json(INEXISTENTE, ["-c", "pass"], timeout=30, codigos_ok=(0, 1)) is None


def test_docker_sin_motor_es_herramienta_no_disponible(monkeypatch, tmp_path):
    import subprocess as sp

    docker = tmp_path / "docker.exe"
    docker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", f'"{docker}" run --rm imagen:1.0')
    error = ("failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine; "
             "check if the daemon is running")
    monkeypatch.setattr("eslabon.ejecutor.subprocess.run",
                        lambda comando, **kw: sp.CompletedProcess(comando, 1, "", error))
    with pytest.raises(HerramientaNoDisponible, match="Docker no responde"):
        ejecutar_json(INEXISTENTE, ["scan"], timeout=30, codigos_ok=(0, 1))


def test_guarddog_ausente_explica_como_configurarlo(monkeypatch):
    from eslabon.colectores.guarddog import GUARDDOG

    monkeypatch.delenv("ESLABON_GUARDDOG", raising=False)
    monkeypatch.setenv("PATH", "")
    with pytest.raises(HerramientaNoDisponible, match="corre en Docker.*--guarddog-max 0"):
        resolver_comando(GUARDDOG)
