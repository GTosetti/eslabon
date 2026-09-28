"""¿Con qué frecuencia desaparecen versiones de paquetes npm LEGÍTIMOS?

Es la tasa de falsos positivos de la señal `depsdev-version-retirada` que la calibración no
podía medir: su corpus legítimo se eligió entre versiones que existen (ver docs/calibracion.md).

En npm, el campo `time` del documento del paquete conserva la fecha de TODAS las versiones que
se publicaron alguna vez, incluidas las retiradas después. Una versión que está en `time` y no
en `versions` se retiró (la despublicó su autor, o la retiró el registro).

Solo metadatos (registry.npmjs.org). Uso: .venv\\Scripts\\python calibracion\\retiradas_npm.py
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from urllib.parse import quote

from corpus import LEGITIMOS

SALIDA = Path(__file__).with_name("retiradas_npm.json")


def documento(nombre: str) -> dict:
    """GET del documento completo (puede superar los 20 MB de eslabon.red: typescript, next)."""
    url = f"https://registry.npmjs.org/{quote(nombre, safe='@')}"
    peticion = urllib.request.Request(url)  # noqa: S310 - host fijo https
    with urllib.request.urlopen(peticion, timeout=120) as r:  # noqa: S310
        return json.loads(r.read(300_000_000))


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    filas = []
    for nombre in LEGITIMOS["npm"]:
        doc = documento(nombre)
        publicadas = set(doc.get("time", {})) - {"created", "modified", "unpublished"}
        existentes = set(doc.get("versions", {}))
        retiradas = sorted(publicadas - existentes)
        filas.append({"nombre": nombre, "publicadas": len(publicadas),
                      "retiradas": retiradas})
        print(f"{nombre:14} {len(publicadas):5} publicadas, {len(retiradas):3} retiradas "
              f"{retiradas[:4]}")
    total = sum(f["publicadas"] for f in filas)
    total_ret = sum(len(f["retiradas"]) for f in filas)
    con_ret = sum(bool(f["retiradas"]) for f in filas)
    print(f"\nTOTAL: {total_ret} de {total} versiones retiradas ({100 * total_ret / total:.2f} %);"
          f" {con_ret} de {len(filas)} paquetes tienen alguna")
    SALIDA.write_text(json.dumps(filas, indent=1) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
