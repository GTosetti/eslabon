"""Colector de OpenSSF Scorecard: la salud del repositorio de origen del paquete.

Un repositorio con un workflow de CI explotable es la puerta por la que un atacante
compromete el software ANTES de que se publique (MITRE T1195.002).

De dónde salen los datos, por orden de preferencia:
1. El CLI `scorecard`, si está instalado y hay GITHUB_TOKEN en el entorno: el análisis
   es del momento actual.
2. Si no, el último análisis semanal que publica deps.dev (sin token).

Siguiendo la metodología de Trail of Bits (supply-chain-risk-auditor), NO se usa el
puntaje global: se correlaciona con el tamaño del proyecto, no con el riesgo. Solo
marcan los checks que describen un mecanismo concreto. Un check con -1 no se pudo
evaluar, y eso no es evidencia de riesgo.
"""

from __future__ import annotations

import os

from eslabon.colectores.base import Colector, Contexto, en_paralelo, entregar
from eslabon.ejecutor import Herramienta, HerramientaNoDisponible, ejecutar_json, resolver_comando
from eslabon.modelos import Evidencia, Finding, Paquete
from eslabon.senales import evidencia, hallazgo_de_senales

# Scorecard es la ÚNICA herramienta que recibe el token (el resto recibe un entorno sin
# secretos). Son las variables que lee, según su código fuente (tokens/accessor.go).
_VARIABLES_TOKEN = ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN", "GH_AUTH_TOKEN")
SCORECARD = Herramienta("scorecard", "scorecard", "ESLABON_SCORECARD",
                       entorno_permitido=_VARIABLES_TOKEN)

# check de Scorecard -> (señal del catálogo, puntaje por debajo del cual se marca).
CHECKS = {
    "Dangerous-Workflow": ("scorecard-dangerous-workflow", 10),
    "Binary-Artifacts": ("scorecard-binary-artifacts", 10),
    "Maintained": ("scorecard-sin-mantenimiento", 1),
}

# scorecard sale con código 1 si algún check falló, pero igual imprime el JSON.
_CODIGOS_OK = (0, 1)


class ColectorScorecard(Colector):
    nombre = "scorecard"

    def recolectar(self, paquetes: list[Paquete], ctx: Contexto) -> list[Finding]:
        usar_cli = _cli_disponible()
        repos, errores = en_paralelo(paquetes, ctx.depsdev.repositorio_origen)
        # Varios paquetes pueden venir del mismo repositorio: se analiza una sola vez.
        unicos = sorted({r for r in repos if r and r.startswith("github.com/")})
        lista, errores_repo = en_paralelo(unicos, lambda r: _checks(r, ctx, usar_cli))
        checks = {r: c for r, c in zip(unicos, lista, strict=True) if c is not None}
        hallazgos = []
        for paquete, repo in zip(paquetes, repos, strict=True):
            if repo in checks:
                evidencias = evidencias_de_checks(repo, *checks[repo])
                if evidencias:
                    hallazgos.append(hallazgo_de_senales(paquete, evidencias))
        return entregar(hallazgos, errores + errores_repo, len(paquetes) + len(unicos))


def _cli_disponible() -> bool:
    if not os.environ.get("GITHUB_TOKEN"):
        return False
    try:
        resolver_comando(SCORECARD)
    except HerramientaNoDisponible:
        return False
    return True


def _checks(repo: str, ctx: Contexto, usar_cli: bool) -> tuple[list[dict], str]:
    """Devuelve (checks, origen). Normaliza los dos formatos a {name, score, reason}."""
    if usar_cli:
        # El token llega a scorecard por la variable de entorno heredada, nunca por argumento
        # (los argumentos de un proceso son visibles para otros usuarios del sistema).
        doc = ejecutar_json(SCORECARD, [f"--repo={repo}", "--format=json"],
                            timeout=ctx.timeout, codigos_ok=_CODIGOS_OK) or {}
        return doc.get("checks") or [], "scorecard CLI"
    proyecto = ctx.depsdev.proyecto(repo) or {}
    return (proyecto.get("scorecard") or {}).get("checks") or [], "deps.dev"


def evidencias_de_checks(repo: str, checks: list[dict], origen: str) -> list[Evidencia]:
    evidencias = []
    for check in checks:
        regla = CHECKS.get(check.get("name", ""))
        puntaje = check.get("score", -1)
        if regla is None or puntaje < 0:  # -1: no evaluable, no es evidencia de riesgo
            continue
        clave, umbral = regla
        if puntaje < umbral:
            evidencias.append(evidencia(
                ColectorScorecard.nombre, clave,
                f"{repo}: {check['name']} = {puntaje}/10 ({check.get('reason', '')})",
                referencia=f"https://scorecard.dev/viewer/?uri={repo}",
                datos={"check": check["name"], "puntaje": puntaje, "origen": origen},
            ))
    return evidencias
