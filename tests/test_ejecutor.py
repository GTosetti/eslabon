import sys

import pytest

from eslabon.ejecutor import (
    Herramienta,
    HerramientaFallo,
    HerramientaNoDisponible,
    ejecutar,
    ejecutar_json,
    resolver_comando,
)

INEXISTENTE = Herramienta("fantasma", "herramienta-que-no-existe-xyz", "ESLABON_TEST_FANTASMA")


def test_herramienta_ausente(monkeypatch):
    monkeypatch.delenv("ESLABON_TEST_FANTASMA", raising=False)
    with pytest.raises(HerramientaNoDisponible, match="ESLABON_TEST_FANTASMA"):
        resolver_comando(INEXISTENTE)


def test_variable_de_entorno_con_comando_compuesto(monkeypatch):
    monkeypatch.setenv("ESLABON_TEST_FANTASMA", "docker run --rm ghcr.io/datadog/guarddog")
    assert resolver_comando(INEXISTENTE) == ["docker", "run", "--rm", "ghcr.io/datadog/guarddog"]


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
