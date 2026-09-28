"""Mide eslabon sobre calibracion/corpus.json y escribe calibracion/medicion.json.

Ejecuta los colectores reales, salvo GuardDog: GuardDog descarga el código del paquete, y
aquí hay paquetes maliciosos (regla del proyecto: solo metadatos). Todo se evalúa HOY, no el
día en que salió cada versión. Para cada paquete guarda qué señales disparó cada fuente y el
resultado correlacionado de dos formas:
- "con_osv": lo que vería hoy un usuario;
- "sin_osv": lo que verían las heurísticas antes de que exista un aviso (día cero).

Uso: .venv\\Scripts\\python calibracion\\medir.py   (luego: calibracion\\resumir.py)
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from eslabon.colectores import (
    AnalisisParcial,
    ColectorDepsDev,
    ColectorNpm,
    ColectorOSV,
    ColectorScorecard,
    Contexto,
)
from eslabon.correlador import correlacionar
from eslabon.modelos import Finding, Paquete, Tipo
from eslabon.sbom import paquete_desde_texto

CARPETA = Path(__file__).parent
COMPROMISO = {Tipo.MALICIOSO, Tipo.SOSPECHOSO, Tipo.RIESGO_ORIGEN}


def recolectar(colector, paquetes: list[Paquete], ctx: Contexto) -> tuple[list[Finding], str]:
    try:
        return colector.recolectar(paquetes, ctx), ""
    except AnalisisParcial as exc:
        return exc.hallazgos, f"parcial: {str(exc)[:300]}"
    except Exception as exc:  # noqa: BLE001 - se registra en la medición
        return [], f"{type(exc).__name__}: {str(exc)[:300]}"


def peor_compromiso(hallazgos: list[Finding]) -> dict | None:
    """El hallazgo de compromiso más grave del paquete (las vulnerabilidades no cuentan)."""
    candidatos = [h for h in hallazgos if h.tipo in COMPROMISO]
    if not candidatos:
        return None
    h = max(candidatos, key=lambda x: (x.severidad.rango, x.confianza))
    return {"tipo": h.tipo.value, "severidad": h.severidad.value,
            "confianza": round(h.confianza, 4)}


def main() -> None:
    corpus = json.loads((CARPETA / "corpus.json").read_text(encoding="utf-8"))
    entradas = {}
    for e in corpus:
        p = paquete_desde_texto(f"{e['ecosistema'].lower()}:{e['nombre']}@{e['version']}")
        entradas[p.clave] = (e, p)
    paquetes = [p for _, p in entradas.values()]

    with tempfile.TemporaryDirectory(prefix="eslabon-cal-") as tmp:
        ctx = Contexto(dir_trabajo=Path(tmp), timeout=600)
        por_fuente: dict[str, list[Finding]] = {}
        errores: dict[str, str] = {}
        for colector in (ColectorOSV(), ColectorDepsDev(), ColectorNpm(), ColectorScorecard()):
            por_fuente[colector.nombre], errores[colector.nombre] = recolectar(
                colector, paquetes, ctx)
            print(f"{colector.nombre}: {len(por_fuente[colector.nombre])} hallazgos "
                  f"{errores[colector.nombre][:120]}")

    filas = []
    for clave, (e, _) in entradas.items():
        propios = {f: [h for h in hs if h.clave == clave] for f, hs in por_fuente.items()}
        senales = sorted({ev.senal for hs in propios.values() for h in hs for ev in h.evidencia
                          if ev.senal and not (ev.fuente == "osv" and ev.senal == "osv-vuln")})
        todos = [h for hs in propios.values() for h in hs]
        sin_osv = [h for f, hs in propios.items() if f != "osv" for h in hs]
        filas.append({**e, "senales": senales,
                      "con_osv": peor_compromiso(correlacionar(todos)),
                      "sin_osv": peor_compromiso(correlacionar(sin_osv))})

    (CARPETA / "medicion.json").write_text(
        json.dumps({"errores": errores, "paquetes": filas}, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n")
    print(f"{len(filas)} paquetes medidos -> calibracion/medicion.json")


if __name__ == "__main__":
    main()
