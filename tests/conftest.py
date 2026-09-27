import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
GRABACIONES = FIXTURES / "grabaciones"


def cargar(nombre: str) -> dict:
    return json.loads((GRABACIONES / nombre).read_text(encoding="utf-8"))


@pytest.fixture
def proyecto_demo() -> Path:
    """Proyecto de prueba: solo lockfiles, que se leen y nunca se instalan."""
    return FIXTURES / "proyecto_demo"


@pytest.fixture
def syft_demo() -> dict:
    """Salida real de `syft scan dir:tests/fixtures/proyecto_demo -o syft-json` (grabada)."""
    return cargar("syft_proyecto_demo.json")


@pytest.fixture
def osv_demo() -> dict:
    """Salida real de `osv-scanner scan source -L <sbom> --format json` (grabada)."""
    return cargar("osv_proyecto_demo.json")


@pytest.fixture
def osv_maliciosos() -> dict:
    """Salida real de osv-scanner para flatmap-stream@0.1.1, event-stream@3.3.6 y ctx@0.2.2."""
    return cargar("osv_maliciosos.json")


@pytest.fixture
def guarddog_sintetico() -> dict:
    """Salida de GuardDog 3.2.0 SINTÉTICA (ver el campo _nota del fichero)."""
    return cargar("guarddog_sintetico.json")


@pytest.fixture
def depsdev_grabado():
    """Cliente de deps.dev que responde con respuestas reales grabadas, sin red."""
    from eslabon.api_depsdev import ClienteDepsDev

    respuestas = cargar("depsdev_respuestas.json")

    def obtener(ruta, timeout):
        if ruta not in respuestas:
            raise AssertionError(f"respuesta no grabada: {ruta}")
        return respuestas[ruta]

    return ClienteDepsDev(obtener=obtener)


@pytest.fixture
def ctx(tmp_path, depsdev_grabado):
    """Contexto de colector con deps.dev grabado y un "ahora" fijo."""
    from datetime import UTC, datetime

    from eslabon.colectores import Contexto

    return Contexto(dir_trabajo=tmp_path, timeout=30, depsdev=depsdev_grabado,
                    ahora=datetime(2026, 9, 26, tzinfo=UTC))
