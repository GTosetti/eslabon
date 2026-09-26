"""Ejecución de herramientas externas como procesos separados.

eslabon NO importa ni copia el código de Syft, OSV-Scanner, etc.: los lanza como
programas aparte y lee su salida JSON. Así no hay conflictos de licencia y cada
herramienta se actualiza por su cuenta.

Reglas de seguridad de este módulo:
- Nunca se usa shell=True: los argumentos van como lista, así un nombre de
  fichero raro no puede inyectar comandos.
- Siempre hay timeout: una herramienta colgada no cuelga todo el escaneo.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

# Segundos máximos por herramienta, si el usuario no indica otro valor.
TIMEOUT_POR_DEFECTO = 300.0


class HerramientaNoDisponible(Exception):
    """La herramienta no está instalada o no se encuentra en el PATH."""


class HerramientaFallo(Exception):
    """La herramienta se ejecutó pero terminó con un error o con una salida inválida."""


@dataclass(frozen=True)
class Herramienta:
    nombre: str
    ejecutable: str
    variable_entorno: str  # permite sobreescribir el comando, p. ej. con "docker run ..."


def resolver_comando(herramienta: Herramienta) -> list[str]:
    """Devuelve el comando base (lista de argumentos) para lanzar la herramienta.

    Si la variable de entorno está definida, se usa su valor. Puede ser una ruta
    o un comando completo, como "docker run --rm ghcr.io/datadog/guarddog".
    """
    override = os.environ.get(herramienta.variable_entorno, "").strip()
    if override:
        if os.path.isfile(override):
            return [override]
        # En Windows, shlex en modo POSIX se come las barras invertidas de las rutas.
        partes = shlex.split(override, posix=os.name != "nt")
        return [p.strip('"') for p in partes]
    ruta = shutil.which(herramienta.ejecutable)
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
        )
    except FileNotFoundError as exc:
        raise HerramientaNoDisponible(f"{herramienta.nombre}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HerramientaFallo(
            f"{herramienta.nombre} superó el tiempo límite ({timeout}s)"
        ) from exc
    if proceso.returncode not in codigos_ok:
        ultimas = "\n".join(proceso.stderr.strip().splitlines()[-5:])
        raise HerramientaFallo(
            f"{herramienta.nombre} terminó con código {proceso.returncode}: {ultimas}"
        )
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
