"""Construye calibracion/corpus.json: los paquetes sobre los que se mide eslabon.

Tres grupos (ver calibracion/README.md):
- legitimo: paquetes populares y sanos, sus 3 últimas versiones estables (deps.dev).
- comprometido: versiones de paquetes legítimos que un atacante publicó (incidentes
  públicos). Solo se conservan las que OSV confirma con un aviso para esa versión.
- malicioso: muestra aleatoria (semilla fija) de OpenSSF Malicious Packages, paquetes
  creados para atacar (typosquatting, dependency confusion...).

Solo metadatos: nunca se descarga ni se instala un paquete. APIs: deps.dev, api.osv.dev y
GitHub (lectura, sin token).

Uso: .venv\\Scripts\\python calibracion\\corpus.py
"""

from __future__ import annotations

import json
import random
import re
import sys
import urllib.request
from pathlib import Path

from eslabon.api_depsdev import ClienteDepsDev
from eslabon.red import obtener_json
from eslabon.sbom import paquete_desde_texto

SALIDA = Path(__file__).with_name("corpus.json")
SEMILLA = 2026
POR_ECOSISTEMA = 50
VERSIONES_LEGITIMAS = 3

LEGITIMOS = {
    "npm": [
        "lodash", "react", "react-dom", "express", "axios", "chalk", "debug", "commander",
        "moment", "dayjs", "uuid", "semver", "yargs", "glob", "rimraf", "mkdirp", "minimist",
        "fs-extra", "body-parser", "cors", "dotenv", "jsonwebtoken", "bcryptjs", "typescript",
        "webpack", "eslint", "prettier", "jest", "mocha", "vue", "next", "rxjs", "underscore",
        "async", "bluebird", "request", "ws", "socket.io", "mongoose", "redis", "pg", "mysql2",
        "sequelize", "cheerio", "node-fetch", "qs", "classnames", "prop-types", "tslib",
        "date-fns",
    ],
    "PyPI": [
        "requests", "urllib3", "certifi", "idna", "charset-normalizer", "numpy", "pandas",
        "boto3", "botocore", "setuptools", "six", "python-dateutil", "pyyaml", "packaging",
        "typing-extensions", "jinja2", "markupsafe", "click", "flask", "django", "sqlalchemy",
        "pydantic", "attrs", "cryptography", "cffi", "pycparser", "pytest", "pluggy", "wheel",
        "pip", "rsa", "pyasn1", "jmespath", "s3transfer", "protobuf", "grpcio", "google-auth",
        "cachetools", "tomli", "filelock", "platformdirs", "virtualenv", "colorama", "tqdm",
        "pillow", "scipy", "matplotlib", "lxml", "psutil", "werkzeug",
    ],
}

# Incidentes públicos: cuentas o tokens robados, mantenedores que sabotearon su paquete.
# Candidatos: se descartan los que OSV no confirma para esa versión exacta.
COMPROMETIDOS = [
    "npm:event-stream@3.3.6", "npm:ua-parser-js@0.7.29", "npm:ua-parser-js@0.8.0",
    "npm:ua-parser-js@1.0.0", "npm:coa@2.0.3", "npm:rc@1.2.9", "npm:eslint-scope@3.7.2",
    "npm:chalk@5.6.1", "npm:debug@4.4.2", "npm:ansi-styles@6.2.2", "npm:strip-ansi@7.1.1",
    "npm:ansi-regex@6.2.1", "npm:supports-color@10.2.1", "npm:wrap-ansi@9.0.1",
    "npm:color-convert@3.1.1", "npm:nx@21.5.0", "npm:nx@20.9.0", "npm:@ctrl/tinycolor@4.1.1",
    "npm:eslint-config-prettier@8.10.1", "npm:is@3.3.1", "npm:@solana/web3.js@1.95.6",
    "npm:xrpl@4.2.1", "npm:node-ipc@10.1.1",
    "pypi:ultralytics@8.3.41", "pypi:num2words@0.5.15", "pypi:ctx@0.2.2",
]
# Caso vivo: la versión sigue publicada y NO tiene aviso (ver docs/scoring.md, ejemplo C).
CASOS_VIVOS = ["npm:event-stream@3.3.5"]


def consultar_osv(ecosistema: str, nombre: str, version: str | None = None) -> list[dict]:
    """POST a api.osv.dev/v1/query (host fijo, https, sin credenciales)."""
    cuerpo: dict = {"package": {"name": nombre, "ecosystem": ecosistema}}
    if version:
        cuerpo["version"] = version
    peticion = urllib.request.Request(
        "https://api.osv.dev/v1/query", data=json.dumps(cuerpo).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(peticion, timeout=30) as r:  # noqa: S310 - URL fija https
        return json.loads(r.read(5_000_000)).get("vulns", [])


def _json_grande(url: str) -> dict:
    """GET de un listado que supera el límite de 20 MB de eslabon.red (el árbol de npm de
    OpenSSF Malicious Packages). Solo para este script: https y host fijo de GitHub."""
    if not url.startswith("https://api.github.com/"):
        raise ValueError(url)
    peticion = urllib.request.Request(  # noqa: S310 - comprobado arriba: https y host fijo
        url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(peticion, timeout=120) as r:  # noqa: S310 - URL fija https
        return json.loads(r.read(200_000_000))


def es_malware(aviso: dict) -> bool:
    return aviso["id"].startswith("MAL-") or "CWE-506" in json.dumps(aviso.get(
        "database_specific", {}))


def legitimos(depsdev: ClienteDepsDev) -> list[dict]:
    entradas = []
    for ecosistema, nombres in LEGITIMOS.items():
        for nombre in nombres:
            info = depsdev.paquete(paquete_desde_texto(f"{ecosistema.lower()}:{nombre}@0"))
            # Las más recientes por fecha, sin pre-versiones (1.0.0-beta, 2.0rc1, 3.0.dev0).
            # (No se usa clave_semver: en PyPI abundan las versiones de dos partes, "24.2".)
            estables = sorted((v.get("publishedAt") or "", v["versionKey"]["version"])
                              for v in (info or {}).get("versions", [])
                              if re.fullmatch(r"[0-9]+(\.[0-9]+)*", v["versionKey"]["version"]))
            for _, version in estables[-VERSIONES_LEGITIMAS:]:
                entradas.append({"grupo": "legitimo", "ecosistema": ecosistema,
                                 "nombre": nombre, "version": version})
    return entradas


def comprometidos() -> list[dict]:
    entradas = []
    for texto in COMPROMETIDOS + CASOS_VIVOS:
        p = paquete_desde_texto(texto)
        avisos = [a["id"] for a in consultar_osv(p.ecosistema.value, p.nombre, p.version)
                  if es_malware(a)]
        if texto in CASOS_VIVOS or avisos:
            entradas.append({"grupo": "comprometido", "ecosistema": p.ecosistema.value,
                             "nombre": p.nombre, "version": p.version, "avisos": avisos,
                             "caso_vivo": texto in CASOS_VIVOS})
        else:
            print(f"descartado (OSV no lo confirma): {texto}", file=sys.stderr)
    return entradas


def maliciosos() -> list[dict]:
    azar = random.Random(SEMILLA)  # noqa: S311 - muestreo reproducible, no criptografía
    entradas = []
    raiz = "https://api.github.com/repos/ossf/malicious-packages"
    carpetas = {e["name"]: e["sha"] for e in obtener_json(
        f"{raiz}/contents/osv/malicious", timeout=60) or []}
    for ecosistema, carpeta in (("npm", "npm"), ("PyPI", "pypi")):
        # La API de "contents" devuelve solo las primeras 1000 entradas (orden alfabético: una
        # sola campaña dominaba la muestra). La de árboles de git las lista todas. Se excluyen
        # los paquetes con ámbito (@x/y): son subcarpetas.
        arbol = _json_grande(f"{raiz}/git/trees/{carpetas[carpeta]}")
        if arbol.get("truncated"):
            print(f"aviso: listado de {carpeta} truncado por GitHub", file=sys.stderr)
        nombres = sorted(e["path"] for e in arbol.get("tree", [])
                         if e["type"] == "tree" and not e["path"].startswith("@"))
        azar.shuffle(nombres)
        prefijos: set[str] = set()  # uno por prefijo: las campañas publican cientos de clones
        for nombre in nombres:
            if sum(e["ecosistema"] == ecosistema for e in entradas) >= POR_ECOSISTEMA:
                break
            if nombre[:5].lower() in prefijos:
                continue
            prefijos.add(nombre[:5].lower())
            avisos = [a for a in consultar_osv(ecosistema, nombre) if es_malware(a)]
            versiones = sorted({v for a in avisos for af in a.get("affected", [])
                                for v in af.get("versions", [])})
            try:
                p = paquete_desde_texto(f"{ecosistema.lower()}:{nombre}@{versiones[-1]}")
            except (IndexError, ValueError):
                continue  # sin versión concreta en el aviso, o nombre fuera de la gramática
            entradas.append({"grupo": "malicioso", "ecosistema": ecosistema, "nombre": p.nombre,
                             "version": p.version, "avisos": [a["id"] for a in avisos]})
    return entradas


def main() -> None:
    corpus = legitimos(ClienteDepsDev(timeout=30)) + comprometidos() + maliciosos()
    SALIDA.write_text(json.dumps(corpus, indent=1, ensure_ascii=False) + "\n",
                      encoding="utf-8", newline="\n")
    for grupo in ("legitimo", "comprometido", "malicioso"):
        for eco in ("npm", "PyPI"):
            n = sum(e["grupo"] == grupo and e["ecosistema"] == eco for e in corpus)
            print(f"{grupo:13} {eco:5} {n}")


if __name__ == "__main__":
    main()
