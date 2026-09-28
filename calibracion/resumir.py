"""Resume calibracion/medicion.json en tablas Markdown (para docs/calibracion.md).

Uso: .venv\\Scripts\\python calibracion\\resumir.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

MEDICION = Path(__file__).with_name("medicion.json")
GRUPOS = ("legitimo", "comprometido", "malicioso")
NIVELES = ("ninguno", "info", "baja", "media", "alta", "critica")


def _pct(n: int, total: int) -> str:
    return f"{n} ({100 * n / total:.0f} %)" if total else "-"


def severidades(filas: list[dict], vista: str) -> str:
    lineas = [f"| Grupo | n | {' | '.join(NIVELES)} |", "|---|---|" + "---|" * len(NIVELES)]
    for grupo in GRUPOS:
        for eco in ("npm", "PyPI"):
            sub = [f for f in filas if f["grupo"] == grupo and f["ecosistema"] == eco]
            if not sub:
                continue
            cuenta = Counter((f[vista] or {}).get("severidad", "ninguno") for f in sub)
            celdas = " | ".join(_pct(cuenta[n], len(sub)) for n in NIVELES)
            lineas.append(f"| {grupo} {eco} | {len(sub)} | {celdas} |")
    return "\n".join(lineas)


def senales(filas: list[dict]) -> str:
    todas = sorted({s for f in filas for s in f["senales"]})
    cabecera = [f"{g} {e}" for g in GRUPOS for e in ("npm", "PyPI")]
    lineas = [f"| Señal | {' | '.join(cabecera)} |", "|---|" + "---|" * len(cabecera)]
    for s in todas:
        celdas = []
        for g in GRUPOS:
            for e in ("npm", "PyPI"):
                sub = [f for f in filas if f["grupo"] == g and f["ecosistema"] == e]
                celdas.append(_pct(sum(s in f["senales"] for f in sub), len(sub)))
        lineas.append(f"| `{s}` | {' | '.join(celdas)} |")
    return "\n".join(lineas)


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    filas = json.loads(MEDICION.read_text(encoding="utf-8"))["paquetes"]
    print("### Severidad del peor hallazgo de compromiso, SIN OSV (día cero)\n")
    print(severidades(filas, "sin_osv"))
    print("\n### Severidad del peor hallazgo de compromiso, CON OSV (hoy)\n")
    print(severidades(filas, "con_osv"))
    print("\n### Con qué frecuencia dispara cada señal\n")
    print(senales(filas))


if __name__ == "__main__":
    main()
