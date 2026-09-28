"""Colector del registro de npm: quién publicó cada versión y qué ejecuta al instalarse.

Señales:
- Publicador nuevo: la versión la publicó una cuenta DISTINTA de la que publicó la versión
  anterior, y que no era conocida en el paquete: no figuraba como mantenedora en la versión
  anterior ni publicó ninguna de las 5 anteriores. Es el patrón de una cuenta robada o de
  un paquete cedido a un desconocido. Caso real (grabado en los tests): event-stream 3.3.4
  la publicó "dominictarr" y 3.3.5, dos años después, "right9ctrl", la cuenta del atacante
  que luego añadió flatmap-stream. Esa versión 3.3.5 no tiene ningún aviso ni CVE: solo la
  delatan señales débiles. El filtro de "cuenta conocida" sale de la calibración
  (docs/calibracion.md): sin él, la señal disparaba en el 9 % de las versiones legítimas
  (equipos que rotan quién publica).
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

# Cuántas versiones anteriores se miran para saber si la cuenta ya había publicado el paquete.
# Se piden de a una (KB): el documento completo del paquete puede superar los 20 MB.
VERSIONES_HISTORIAL = 5


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
    anteriores = _versiones_anteriores(p, ctx) if publicador else []
    if anteriores:
        anterior = anteriores[0]
        doc_anterior = ctx.npm.version(p, anterior) or {}
        previo = (doc_anterior.get("_npmUser") or {}).get("name")
        # Se compara la CUENTA, no el correo: cambiar de correo no es cambiar de dueño.
        if (previo and previo != publicador
                and _PUBLICADORES_CI.isdisjoint({previo, publicador})
                and not _cuenta_conocida(publicador, doc_anterior, p, anteriores[1:], ctx)):
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


def _cuenta_conocida(publicador: str, doc_anterior: dict, p: Paquete, otras: list[str],
                     ctx: Contexto) -> bool:
    """¿La cuenta ya era de la casa? Mantenedora en la versión anterior, o publicó otra previa.

    Un equipo que rota quién publica no es un cambio de dueño (express, lodash, async...).
    """
    if publicador in {m.get("name") for m in doc_anterior.get("maintainers") or []}:
        return True
    return any(((ctx.npm.version(p, v) or {}).get("_npmUser") or {}).get("name") == publicador
               for v in otras)


def _versiones_anteriores(p: Paquete, ctx: Contexto) -> list[str]:
    """Versiones anteriores según deps.dev. Si deps.dev falla, se omite SOLO esta comparación:
    las señales del propio registro de npm (scripts) no dependen de deps.dev, y el fallo de
    deps.dev ya lo informa su propio colector en fuentes_omitidas."""
    try:
        return ctx.depsdev.versiones_anteriores(p, VERSIONES_HISTORIAL)
    except Exception:  # noqa: BLE001
        return []
