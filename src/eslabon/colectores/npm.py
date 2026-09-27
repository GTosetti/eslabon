"""Colector del registro de npm: quién publicó cada versión y qué ejecuta al instalarse.

Señales:
- Publicador nuevo: la versión la publicó una cuenta DISTINTA de la que publicó la versión
  anterior. Es el patrón de una cuenta robada o de un paquete cedido a un desconocido.
  Caso real (grabado en los tests): event-stream 3.3.4 la publicó "dominictarr" y 3.3.5,
  dos años después, "right9ctrl", la cuenta del atacante que luego añadió flatmap-stream.
  Esa versión 3.3.5 no tiene ningún aviso ni CVE: solo la delatan señales débiles.
- Script de instalación (preinstall/install/postinstall): se ejecuta en la máquina de quien
  instala. Solo es CONTEXTO (muchos paquetes sanos compilan código nativo al instalarse),
  salvo que el script descargue o ejecute código: entonces es una señal por sí mismo.

Solo analiza paquetes npm. Una versión que ya no está en el registro no genera señal aquí:
de eso se ocupa el colector de deps.dev.
"""

from __future__ import annotations

import re

from eslabon.colectores.base import Colector, Contexto, en_paralelo, entregar
from eslabon.modelos import Ecosistema, Finding, Paquete
from eslabon.senales import evidencia, hallazgo_si_hay_senal

_SCRIPTS_INSTALACION = ("preinstall", "install", "postinstall")

# Indicios de que un script de instalación descarga o ejecuta código que no viene en el
# paquete: una URL, herramientas de descarga, módulos de red o de procesos, o decodificar
# base64 para ejecutarlo. NO basta con "node -e": el postinstall de core-js es
# `node -e "try{require('./postinstall')}catch(e){}"` y no descarga nada.
_SCRIPT_CON_RED = re.compile(
    r"https?://|\b(curl|wget|Invoke-WebRequest|iwr|certutil|bitsadmin|powershell|ncat|nc)\b"
    r"|\b(child_process|https?|net|dns)['\"]\s*\)|\beval\b|\batob\b"
    r"|base64\s+(-d|--decode)|['\"]base64['\"]",
    re.IGNORECASE)

# Identidades con las que publica un CI (npm "trusted publishing" vía OIDC). Pasar de la cuenta
# del mantenedor a publicar desde su CI es una buena práctica, no un cambio de dueño.
_PUBLICADORES_CI = {"GitHub Actions"}


class ColectorNpm(Colector):
    nombre = "npm"

    def recolectar(self, paquetes: list[Paquete], ctx: Contexto) -> list[Finding]:
        de_npm = [p for p in paquetes if p.ecosistema is Ecosistema.NPM]
        resultados, errores = en_paralelo(de_npm, lambda p: analizar_paquete(p, ctx))
        return entregar([h for h in resultados if h], errores, len(de_npm))


def analizar_paquete(p: Paquete, ctx: Contexto) -> Finding | None:
    doc = ctx.npm.version(p)
    if doc is None:
        return None
    evidencias = []
    url = f"https://www.npmjs.com/package/{p.nombre}/v/{p.version}"

    publicador = (doc.get("_npmUser") or {}).get("name")
    anterior = _version_anterior(p, ctx) if publicador else None
    if anterior:
        previo = ((ctx.npm.version(p, anterior) or {}).get("_npmUser") or {}).get("name")
        # Se compara la CUENTA, no el correo: cambiar de correo no es cambiar de dueño.
        if previo and previo != publicador and _PUBLICADORES_CI.isdisjoint({previo, publicador}):
            evidencias.append(evidencia(
                ColectorNpm.nombre, "npm-publicador-nuevo",
                f"{p.version} la publicó '{publicador}'; la anterior ({anterior}), '{previo}'",
                referencia=url,
                datos={"publicador": publicador, "publicador_anterior": previo,
                       "version_anterior": anterior}))

    scripts = {k: v for k, v in (doc.get("scripts") or {}).items() if k in _SCRIPTS_INSTALACION}
    con_red = {k: v for k, v in scripts.items() if _SCRIPT_CON_RED.search(v)}
    if scripts:
        evidencias.append(evidencia(
            ColectorNpm.nombre,
            "npm-script-instalacion-red" if con_red else "npm-script-instalacion",
            "; ".join(f"{k}: {v[:120]}" for k, v in (con_red or scripts).items()),
            referencia=url, datos={"scripts": scripts}))

    # Un script de instalación "normal" es contexto: solo acompaña a otra señal.
    return hallazgo_si_hay_senal(p, evidencias)


def _version_anterior(p: Paquete, ctx: Contexto) -> str | None:
    """Versión anterior según deps.dev. Si deps.dev falla, se omite SOLO esta comparación:
    las señales del propio registro de npm (scripts) no dependen de deps.dev, y el fallo de
    deps.dev ya lo informa su propio colector en fuentes_omitidas."""
    try:
        return ctx.depsdev.version_anterior(p)
    except Exception:  # noqa: BLE001
        return None
