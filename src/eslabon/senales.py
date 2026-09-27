"""Catálogo de señales: qué puede observar cada fuente y cuánto pesa.

El peso de una señal es una estimación de la probabilidad de que el paquete esté
comprometido (o sea malicioso) si SOLO se observara esa señal. El correlador
combina los pesos de fuentes distintas. La justificación de cada número está en
docs/scoring.md: si se cambia un peso aquí, hay que actualizar ese documento.
"""

from __future__ import annotations

from dataclasses import dataclass

from eslabon.modelos import Evidencia, Finding, Paquete, Severidad, Tipo


@dataclass(frozen=True)
class Senal:
    clave: str
    tipo: Tipo
    peso: float
    descripcion: str
    # Contexto: describe al paquete pero no indica compromiso por sí sola (p. ej. "puede abrir
    # conexiones"). Acompaña a otras señales, pero sola no genera hallazgo.
    contexto: bool = False


_M, _S, _O, _V = Tipo.MALICIOSO, Tipo.SOSPECHOSO, Tipo.RIESGO_ORIGEN, Tipo.VULN

CATALOGO: dict[str, Senal] = {s.clave: s for s in [
    # --- OSV: avisos publicados (confirmados por un analista) ---
    Senal("osv-mal", _M, 0.95, "Aviso MAL- de OpenSSF Malicious Packages"),
    Senal("osv-cwe-506", _M, 0.90, "Aviso con CWE-506 (Embedded Malicious Code)"),
    Senal("osv-texto-malicioso", _M, 0.80, "El aviso describe el paquete como malicioso/malware"),
    Senal("osv-vuln", _V, 0.90, "Versión dentro del rango afectado por un aviso publicado"),
    # --- deps.dev: estado del paquete en el registro ---
    Senal("depsdev-tapon-seguridad", _M, 0.90,
          "npm reemplazó el paquete por una versión tapón '-security' (retirada por malware)"),
    Senal("depsdev-version-retirada", _S, 0.40,
          "La versión ya no existe en el registro aunque el paquete sí"),
    Senal("depsdev-paquete-inexistente", _S, 0.30,
          "El paquete no existe en el registro público "
          "(retirado, o privado: dependency confusion)"),
    Senal("depsdev-version-reciente", _S, 0.20, "Versión publicada hace menos de 14 días"),
    Senal("depsdev-reactivacion", _S, 0.25,
          "Versión publicada tras más de un año sin publicaciones del paquete"),
    Senal("depsdev-obsoleto", _O, 0.10, "El registro marca la versión como obsoleta (deprecated)"),
    # --- Registro de npm: quién publicó y qué se ejecuta al instalar ---
    Senal("npm-publicador-nuevo", _S, 0.35,
          "La versión la publicó una cuenta distinta de la que publicó la anterior"),
    Senal("npm-script-instalacion", _S, 0.05, contexto=True, descripcion=
          "Tiene script de instalación (se ejecuta al instalar): contexto, no amenaza"),
    Senal("npm-script-instalacion-red", _S, 0.35,
          "El script de instalación descarga o ejecuta código (curl, wget, URL, node -e...)"),
    # --- OpenSSF Scorecard: salud del repositorio de origen ---
    Senal("scorecard-dangerous-workflow", _O, 0.30,
          "Workflow de CI con patrón peligroso (inyección de scripts o checkout no confiable)"),
    Senal("scorecard-binary-artifacts", _O, 0.20, "Binarios versionados en el repositorio"),
    Senal("scorecard-sin-mantenimiento", _O, 0.10, "Sin actividad reciente en el repositorio"),
    # --- GuardDog: heurísticas sobre metadatos ---
    Senal("guarddog-typosquatting", _S, 0.35, "Nombre casi igual al de un paquete muy popular"),
    Senal("guarddog-potentially_compromised_email_domain", _S, 0.40,
          "El dominio del correo del mantenedor puede haber sido re-registrado"),
    Senal("guarddog-unclaimed_maintainer_email_domain", _S, 0.40,
          "El dominio del correo del mantenedor no está registrado (se puede secuestrar)"),
    Senal("guarddog-deceptive_author", _S, 0.25, "El autor usa un correo desechable"),
    Senal("guarddog-bundled_binary", _S, 0.20, "El paquete incluye binarios"),
    Senal("guarddog-metadata_mismatch", _S, 0.30,
          "Los metadatos del registro no coinciden con el manifiesto"),
    Senal("guarddog-repository_integrity_mismatch", _S, 0.30,
          "El paquete contiene ficheros que no están en su repositorio"),
    Senal("guarddog-direct_url_dependency", _S, 0.20,
          "Dependencias descargadas desde una URL directa"),
    Senal("guarddog-risky_new_dependency", _S, 0.30, "Dependencia nueva que a su vez es de riesgo"),
    Senal("guarddog-provenance_regression", _S, 0.40,
          "La versión perdió la atestación de procedencia que tenían las anteriores"),
    # --- GuardDog: reglas sobre el código (YARA), por severidad declarada por la regla ---
    Senal("guarddog-amenaza-alta", _S, 0.60, "Regla de amenaza de severidad alta"),
    Senal("guarddog-amenaza-media", _S, 0.40, "Regla de amenaza de severidad media"),
    Senal("guarddog-amenaza-baja", _S, 0.20, "Regla de amenaza de severidad baja"),
    Senal("guarddog-capacidad", _S, 0.05, contexto=True, descripcion=
          "Capacidad (red, procesos, ficheros): contexto, no amenaza"),
    # --- GuardDog: veredicto global de la herramienta ---
    Senal("guarddog-veredicto-high_risk", _S, 0.70,
          "GuardDog califica el paquete como de alto riesgo"),
    Senal("guarddog-veredicto-suspicious", _S, 0.50,
          "GuardDog califica el paquete como sospechoso"),
    Senal("guarddog-veredicto-low", _S, 0.20, "GuardDog detecta riesgos bajos"),
]}


def evidencia(fuente: str, clave: str, detalle: str = "", *, referencia: str | None = None,
              datos: dict | None = None) -> Evidencia:
    """Crea una Evidencia a partir de una señal del catálogo."""
    s = CATALOGO[clave]
    return Evidencia(fuente=fuente, senal=clave, tipo=s.tipo, peso=s.peso,
                     descripcion=f"{s.descripcion}{': ' + detalle if detalle else ''}",
                     referencia=referencia, datos=datos or {})


def confianza_de(evidencias: list[Evidencia]) -> float:
    """Confianza provisional de un colector: su señal más fuerte (el correlador la recalcula)."""
    return max((e.peso or 0.0 for e in evidencias), default=0.0)


# Si un hallazgo reúne evidencia de varios tipos, manda el más grave.
PRECEDENCIA = (Tipo.MALICIOSO, Tipo.SOSPECHOSO, Tipo.RIESGO_ORIGEN, Tipo.VULN)


def tipo_dominante(tipos: list[Tipo]) -> Tipo:
    return min(tipos, key=PRECEDENCIA.index)


def hallazgo_si_hay_senal(paquete: Paquete, evidencias: list[Evidencia]) -> Finding | None:
    """Hallazgo con esas evidencias, o None si no hay ninguna o si TODAS son de contexto."""
    if all(e.senal in CATALOGO and CATALOGO[e.senal].contexto for e in evidencias):
        return None
    return hallazgo_de_senales(paquete, evidencias)


def hallazgo_de_senales(paquete: Paquete, evidencias: list[Evidencia]) -> Finding:
    """Hallazgo "en bruto" de una fuente de heurísticas (deps.dev, Scorecard, GuardDog).

    Severidad, confianza y explicación definitivas las calcula el correlador al
    combinarlo con lo que digan las demás fuentes.
    """
    tipo = tipo_dominante([e.tipo for e in evidencias if e.tipo])
    return Finding(
        ecosistema=paquete.ecosistema,
        paquete=paquete.nombre,
        version=paquete.version,
        tipo=tipo,
        ids=[f"ESL-{e.senal.upper()}" for e in evidencias if e.senal],
        titulo=evidencias[0].descripcion,
        severidad=Severidad.INFO,
        confianza=confianza_de(evidencias),
        evidencia=evidencias,
        explicacion="; ".join(e.descripcion for e in evidencias),
    )
