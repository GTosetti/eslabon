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

    return _cliente_grabado(ClienteDepsDev, "depsdev_respuestas.json")


def _cliente_grabado(clase, fichero):
    respuestas = cargar(fichero)

    def obtener(ruta, timeout):
        if ruta not in respuestas:
            raise AssertionError(f"respuesta no grabada: {ruta}")
        return respuestas[ruta]

    return clase(obtener=obtener)


@pytest.fixture
def npm_grabado():
    """Cliente del registro de npm con respuestas reales grabadas (sin correos), sin red."""
    from eslabon.api_npm import ClienteNpm

    return _cliente_grabado(ClienteNpm, "npm_respuestas.json")


@pytest.fixture
def ctx(tmp_path, depsdev_grabado, npm_grabado):
    """Contexto de colector con deps.dev y npm grabados y un "ahora" fijo."""
    from datetime import UTC, datetime

    from eslabon.colectores import Contexto

    return Contexto(dir_trabajo=tmp_path, timeout=30, depsdev=depsdev_grabado,
                    npm=npm_grabado, ahora=datetime(2026, 9, 26, tzinfo=UTC))


@pytest.fixture
def guarddog_real_requests() -> dict:
    """Salida REAL de guarddog v3.2.0 sobre requests==2.32.3 (paquete legítimo)."""
    return cargar("guarddog_real_requests.json")


@pytest.fixture
def guarddog_real_muestra() -> dict:
    """Salida REAL de guarddog v3.2.0 sobre sus propias muestras de test de amenazas."""
    return cargar("guarddog_real_muestra.json")
