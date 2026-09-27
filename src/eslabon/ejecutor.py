"""Ejecución de herramientas externas como procesos separados.

eslabon NO importa ni copia el código de Syft, OSV-Scanner, etc.: los lanza como
programas aparte y lee su salida JSON. Así no hay conflictos de licencia y cada
herramienta se actualiza por su cuenta.

Reglas de seguridad de este módulo:
- Nunca se usa shell=True: los argumentos van como lista, así un nombre de
  fichero raro no puede inyectar comandos.
- Siempre hay timeout: una herramienta colgada no cuelga todo el escaneo.
- Las herramientas se buscan SOLO en el PATH, nunca en la carpeta actual. En Windows,
  por defecto, se busca primero en la carpeta actual: un repositorio malicioso con un
  "syft.bat" dentro se ejecutaría al hacer `eslabon scan .`.
- No se aceptan .bat/.cmd: Windows los ejecuta a través de cmd.exe, y cmd interpreta
  caracteres como & o | dentro de los argumentos (p. ej. un nombre de paquete hostil).
- Cada herramienta recibe un entorno SIN tokens ni secretos, salvo los que necesita.
- Todo texto de error que sale del programa pasa por `redactar()`.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Segundos máximos por herramienta, si el usuario no indica otro valor.
TIMEOUT_POR_DEFECTO = 300.0

# Variables de entorno que nunca se pasan a las herramientas (salvo que se pidan).
_SENSIBLE = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|(^|_)KEY($|_)|AUTH",
                       re.IGNORECASE)
# Formatos conocidos de tokens, por si aparecen en la salida de una herramienta.
_PATRONES_SECRETOS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(authorization|token)[\"']?\s*[:=]\s*\S+"),
]
_EXTENSIONES_PROHIBIDAS = {".bat", ".cmd"}


class HerramientaNoDisponible(Exception):
    """La herramienta no está instalada o no se encuentra en el PATH."""


class HerramientaFallo(Exception):
    """La herramienta se ejecutó pero terminó con un error o con una salida inválida."""


@dataclass(frozen=True)
class Herramienta:
    nombre: str
    ejecutable: str
    variable_entorno: str  # permite sobreescribir el comando, p. ej. con "docker run ..."
    # Variables sensibles que ESTA herramienta sí necesita (el resto de secretos no le llega).
    entorno_permitido: tuple[str, ...] = ()


# En Windows, esta variable evita que CreateProcess y shutil.which busquen ejecutables en
# la carpeta actual. Se fija una vez, al cargar el módulo, para todo el proceso.
os.environ.setdefault("NoDefaultCurrentDirectoryInExePath", "1")  # noqa: SIM112 - nombre oficial


def redactar(texto: str) -> str:
    """Borra de un texto los valores de variables sensibles y los tokens reconocibles."""
    for nombre, valor in os.environ.items():
        if _SENSIBLE.search(nombre) and len(valor) >= 8:
            texto = texto.replace(valor, "***")
    for patron in _PATRONES_SECRETOS:
        texto = patron.sub("***", texto)
    return texto


def entorno_seguro(permitir: tuple[str, ...] = ()) -> dict[str, str]:
    """Copia del entorno sin variables sensibles (salvo las nombradas en `permitir`)."""
    return {k: v for k, v in os.environ.items()
            if k in permitir or not _SENSIBLE.search(k)}


def _rechazar_script(ruta: str) -> str:
    if Path(ruta).suffix.lower() in _EXTENSIONES_PROHIBIDAS:
        raise HerramientaNoDisponible(
            f"{ruta}: no se ejecutan .bat/.cmd (cmd.exe interpretaría los argumentos)")
    return ruta


def _buscar(ejecutable: str) -> str | None:
    """Como shutil.which, pero solo en el PATH: nunca en la carpeta actual."""
    ruta = _buscar_en(ejecutable, os.environ.get("PATH", ""), os.getcwd())
    return _rechazar_script(ruta) if ruta else None


@functools.lru_cache(maxsize=64)
def _buscar_en(ejecutable: str, path: str, carpeta_actual: str) -> str | None:
    # En caché por (ejecutable, PATH, carpeta actual): si cambia cualquiera, se busca de nuevo.
    actual = Path(carpeta_actual).resolve()
    rutas = []
    for d in path.split(os.pathsep):
        try:
            if d.strip() and Path(d).resolve() != actual:
                rutas.append(d)
        except OSError:
            continue
    return shutil.which(ejecutable, path=os.pathsep.join(rutas))


def resolver_comando(herramienta: Herramienta) -> list[str]:
    """Devuelve el comando base (lista de argumentos, con ruta absoluta) de la herramienta.

    Si la variable de entorno está definida, se usa su valor. Puede ser una ruta
    o un comando completo, como "docker run --rm ghcr.io/datadog/guarddog:v3.2.0".
    """
    override = os.environ.get(herramienta.variable_entorno, "").strip()
    if override:
        if os.path.isfile(override):
            partes = [override]
        else:
            # En Windows, shlex en modo POSIX se come las barras invertidas de las rutas.
            partes = [p.strip('"') for p in shlex.split(override, posix=os.name != "nt")]
        if os.path.isabs(partes[0]):
            return [_rechazar_script(partes[0]), *partes[1:]]
        ruta = _buscar(partes[0])
        if ruta is None:
            raise HerramientaNoDisponible(
                f"{partes[0]} (de {herramienta.variable_entorno}) no está en el PATH")
        return [ruta, *partes[1:]]
    ruta = _buscar(herramienta.ejecutable)
    if ruta is None:
        raise HerramientaNoDisponible(
            f"{herramienta.nombre} no está en el PATH "
            f"(se puede indicar la ruta con la variable {herramienta.variable_entorno})"
        )
    return [ruta]


def ejecutar(
    herramienta: Herramienta,
    argumentos: list[str],
    *,
    timeout: float,
    codigos_ok: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    comando = resolver_comando(herramienta) + argumentos
    try:
        proceso = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=entorno_seguro(herramienta.entorno_permitido),
        )
    except FileNotFoundError as exc:
        raise HerramientaNoDisponible(f"{herramienta.nombre}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HerramientaFallo(
            f"{herramienta.nombre} superó el tiempo límite ({timeout}s)"
        ) from exc
    if proceso.returncode not in codigos_ok:
        ultimas = "\n".join(proceso.stderr.strip().splitlines()[-5:])
        raise HerramientaFallo(redactar(
            f"{herramienta.nombre} terminó con código {proceso.returncode}: {ultimas}"
        ))
    return proceso


def ejecutar_json(
    herramienta: Herramienta,
    argumentos: list[str],
    *,
    timeout: float,
    codigos_ok: tuple[int, ...] = (0,),
) -> Any:
    """Como `ejecutar`, pero interpreta la salida estándar como JSON.

    Devuelve None si la herramienta no escribió nada.
    """
    salida = ejecutar(herramienta, argumentos, timeout=timeout, codigos_ok=codigos_ok).stdout
    if not salida or salida.isspace():
        return None
    try:
        return json.loads(salida)
    except json.JSONDecodeError as exc:
        raise HerramientaFallo(f"{herramienta.nombre} devolvió JSON inválido: {exc}") from exc
