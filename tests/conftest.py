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
