"""Esquema común de datos.

Todas las herramientas externas hablan "idiomas" distintos (Syft, OSV, GuardDog...).
Los colectores traducen cada uno a estos modelos, y el resto de eslabon
(correlador, salidas) solo conoce estos modelos.
"""

from __future__ import annotations

import re
from enum import StrEnum
from urllib.parse import quote

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator


class Ecosistema(StrEnum):
    """Nombres de ecosistema tal como los usa OSV (https://ossf.github.io/osv-schema/)."""

    PYPI = "PyPI"
    NPM = "npm"

    @property
    def tipo_purl(self) -> str:
        """Tipo en un purl: pkg:<tipo>/... (https://github.com/package-url/purl-spec)."""
        return _TIPO_PURL[self]

    @classmethod
    def desde_tipo_purl(cls, tipo: str) -> Ecosistema:
        for ecosistema, nombre in _TIPO_PURL.items():
            if nombre == tipo.lower():
                return ecosistema
        raise ValueError(f"Ecosistema no soportado: {tipo!r} (usar pypi o npm)")


_TIPO_PURL = {Ecosistema.PYPI: "pypi", Ecosistema.NPM: "npm"}


def normalizar_nombre(ecosistema: Ecosistema, nombre: str) -> str:
    """Forma canónica del nombre para comparar.

    En PyPI, "Typing_Extensions", "typing-extensions" y "typing.extensions" son el mismo
    paquete (PEP 503). En npm los nombres son en minúsculas y sensibles a "-"/"_".
    """
    if ecosistema is Ecosistema.PYPI:
        return re.sub(r"[-_.]+", "-", nombre).lower()
    return nombre.lower()


def construir_purl(ecosistema: Ecosistema, nombre: str, version: str) -> str:
    """purl = "package URL", un identificador estándar: pkg:<tipo>/<nombre>@<versión>.

    En npm, el "@" de los paquetes con scope (@babel/core) se codifica como %40.
    """
    if ecosistema is Ecosistema.PYPI:
        nombre = normalizar_nombre(ecosistema, nombre)
    return f"pkg:{ecosistema.tipo_purl}/{quote(nombre, safe='/')}@{quote(version, safe='')}"


class Tipo(StrEnum):
    VULN = "vuln"  # vulnerabilidad conocida (CVE/GHSA/PYSEC)
    MALICIOSO = "malicioso"  # paquete reportado como malware (avisos MAL-, CWE-506)
    SOSPECHOSO = "sospechoso"  # heurísticas: aún no confirmado
    RIESGO_ORIGEN = "riesgo_origen"  # el repositorio/proyecto de origen es débil


# Mapeo a MITRE ATT&CK, en un único lugar para todas las fuentes:
# - T1195.001 "Compromise Software Dependencies and Development Tools": un paquete
#   malicioso o sospechoso ES (o puede ser) una dependencia comprometida.
# - T1195.002 "Compromise Software Supply Chain": un repositorio de origen débil es la
#   vía por la que un atacante compromete el software antes de que se publique.
# - Una CVE corriente no es una técnica de ataque en sí misma, así que no se mapea.
TECNICAS_ATTACK: dict[Tipo, list[str]] = {
    Tipo.VULN: [],
    Tipo.MALICIOSO: ["T1195.001"],
    Tipo.SOSPECHOSO: ["T1195.001"],
    Tipo.RIESGO_ORIGEN: ["T1195.002"],
}


class Severidad(StrEnum):
    INFO = "info"
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"

    @property
    def rango(self) -> int:
        """Orden numérico (0 = info ... 4 = crítica) para comparar y ordenar."""
        return list(Severidad).index(self)

    @classmethod
    def desde_cvss(cls, puntaje: float) -> Severidad:
        """Bandas oficiales de CVSS v3/v4 (FIRST).

        0.1-3.9 baja, 4.0-6.9 media, 7.0-8.9 alta, 9.0-10 crítica.
        """
        if puntaje >= 9.0:
            return cls.CRITICA
        if puntaje >= 7.0:
            return cls.ALTA
        if puntaje >= 4.0:
            return cls.MEDIA
        if puntaje > 0.0:
            return cls.BAJA
        return cls.INFO


# Orden de preferencia del ID principal de un hallazgo: MAL primero (lo más grave),
# luego CVE (el más universal), GHSA, PYSEC y el resto.
_PRIORIDAD_IDS = ("MAL-", "CVE-", "GHSA-", "PYSEC-")


def ordenar_ids(ids: list[str]) -> list[str]:
    """Quita duplicados y ordena los IDs para que el principal quede primero."""

    def clave(i: str) -> tuple[int, str]:
        pos = next((n for n, p in enumerate(_PRIORIDAD_IDS) if i.startswith(p)),
                   len(_PRIORIDAD_IDS))
        return (pos, i)

    return sorted(set(ids), key=clave)


# Gramática de nombres de cada registro (npm admite mayúsculas en paquetes antiguos) y de
# versiones (semver de npm y PEP 440 de PyPI, incluidos epoch "!" y local "+").
_NOMBRE_VALIDO = {
    Ecosistema.NPM: re.compile(r"(@[A-Za-z0-9~][A-Za-z0-9._~-]*/)?[A-Za-z0-9~][A-Za-z0-9._~-]*"),
    Ecosistema.PYPI: re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?"),
}
_VERSION_VALIDA = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_~-]{0,127}")


class Paquete(BaseModel):
    """Una entrada del inventario (SBOM): qué paquete, qué versión, dónde se declaró."""

    ecosistema: Ecosistema
    nombre: str
    version: str
    ubicaciones: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _nombre_y_version_validos(self) -> Paquete:
        # Los nombres y versiones salen de lockfiles que pueden ser hostiles, y luego viajan
        # como argumentos a otras herramientas (guarddog), en URLs (deps.dev) y en alertas
        # del SIEM. Se exige la gramática real de cada registro: nada de "--opcion",
        # "..", espacios, comillas ni caracteres de control.
        if not _NOMBRE_VALIDO[self.ecosistema].fullmatch(self.nombre):
            raise ValueError(f"nombre de paquete no válido para {self.ecosistema.value}: "
                             f"{self.nombre!r}")
        if not _VERSION_VALIDA.fullmatch(self.version):
            raise ValueError(f"versión no válida: {self.version!r}")
        return self

    @computed_field
    @property
    def purl(self) -> str:
        return construir_purl(self.ecosistema, self.nombre, self.version)

    @property
    def clave(self) -> tuple[str, str, str]:
        return (self.ecosistema.value, normalizar_nombre(self.ecosistema, self.nombre),
                self.version)

    def __str__(self) -> str:
        return f"{self.nombre}@{self.version}"


def es_tapon_seguridad(ecosistema: Ecosistema, version: str) -> bool:
    """¿Es la versión "tapón" que publica npm al retirar un paquete malicioso?

    npm reemplaza el paquete por una versión vacía llamada "0.0.1-security" (o similar)
    cuyo repositorio es npm/security-holder, no el del paquete original.
    """
    return ecosistema is Ecosistema.NPM and "-security" in version


class Evidencia(BaseModel):
    """Qué vio una fuente concreta. Es la base de la explicabilidad.

    `senal`, `tipo` y `peso` vienen del catálogo (eslabon.senales). El correlador usa el
    peso para calcular la confianza del hallazgo combinado (ver docs/scoring.md).
    """

    fuente: str
    descripcion: str
    senal: str | None = None
    tipo: Tipo | None = None
    peso: float | None = Field(default=None, ge=0.0, le=1.0)
    referencia: str | None = None  # URL al aviso, a la regla, etc.
    datos: dict = Field(default_factory=dict)


class Finding(BaseModel):
    ecosistema: Ecosistema
    paquete: str
    version: str
    tipo: Tipo
    ids: list[str] = Field(description="Identificador principal primero, luego alias")
    titulo: str = ""
    severidad: Severidad
    confianza: float = Field(ge=0.0, le=1.0)
    evidencia: list[Evidencia]
    explicacion: str
    remediacion: str | None = None

    @field_validator("ids")
    @classmethod
    def _ids_ordenados(cls, ids: list[str]) -> list[str]:
        if not ids:
            raise ValueError("un hallazgo necesita al menos un identificador")
        return ordenar_ids(ids)

    @computed_field
    @property
    def fuentes(self) -> list[str]:
        """Fuentes que aportaron evidencia, en orden de aparición y sin repetir."""
        return list(dict.fromkeys(e.fuente for e in self.evidencia))

    @computed_field
    @property
    def attack(self) -> list[str]:
        """Técnicas MITRE ATT&CK, derivadas del tipo del hallazgo y de su evidencia.

        Un paquete malicioso cuyo repositorio además es débil mapea a T1195.001 y T1195.002.
        """
        tipos = [self.tipo, *(e.tipo for e in self.evidencia if e.tipo)]
        return sorted({t for tipo in tipos for t in TECNICAS_ATTACK[tipo]})

    @property
    def purl(self) -> str:
        return construir_purl(self.ecosistema, self.paquete, self.version)

    @property
    def clave(self) -> tuple[str, str, str]:
        """Identidad del paquete afectado, con el nombre normalizado."""
        return (self.ecosistema.value, normalizar_nombre(self.ecosistema, self.paquete),
                self.version)


class FuenteOmitida(BaseModel):
    fuente: str
    motivo: str

    @field_validator("motivo")
    @classmethod
    def _sin_secretos(cls, motivo: str) -> str:
        # El motivo suele traer la salida de error de una herramienta, y viaja al SIEM, al
        # SARIF y a la terminal: es el único punto por el que pasa, así que se redacta aquí.
        from eslabon.ejecutor import redactar

        return redactar(motivo)


class ResultadoScan(BaseModel):
    objetivo: str
    eslabon_version: str
    paquetes: list[Paquete]
    hallazgos: list[Finding]
    fuentes_usadas: list[str]
    fuentes_omitidas: list[FuenteOmitida]
    # False si el análisis quedó degradado: sin inventario o sin la fuente de avisos (OSV).
    # Un resultado incompleto con 0 hallazgos NO es un resultado limpio.
    completo: bool = True
