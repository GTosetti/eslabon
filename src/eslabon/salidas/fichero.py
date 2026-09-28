"""Escritura del resultado en un fichero, con rotación opcional.

Con `--anexar` (lo típico para el SIEM) el fichero crece con cada escaneo. La rotación lo
acota: si al añadir se superaría el tamaño máximo, el fichero actual pasa a llamarse
`<nombre>.1` (el `.1` anterior pasa a `.2`, etc.; el más viejo se borra) y se empieza uno
nuevo. Es el mismo esquema que logrotate, y el agente de Wazuh lo sigue sin problemas: detecta
que el fichero cambió y abre el nuevo desde el principio.
"""

from __future__ import annotations

import shutil
from pathlib import Path


def escribir(ruta: Path, texto: str, *, anexar: bool = False, rotar_bytes: int | None = None,
             conservar: int = 5) -> Path | None:
    """Escribe `texto` en `ruta` (UTF-8 sin BOM, fin de línea "\\n").

    Devuelve la ruta del fichero rotado si hubo rotación, o None.
    """
    rotado = None
    if (anexar and rotar_bytes and ruta.exists()
            and ruta.stat().st_size + len(texto.encode("utf-8")) > rotar_bytes):
        rotado = _rotar(ruta, conservar)
    with ruta.open("a" if anexar else "w", encoding="utf-8", newline="\n") as fichero:
        fichero.write(texto)
    return rotado


def _rotar(ruta: Path, conservar: int) -> Path:
    """ruta → ruta.1 → ruta.2 … hasta `conservar` copias; la más vieja se descarta."""
    def copia(n: int) -> Path:
        return ruta.with_name(f"{ruta.name}.{n}")

    copia(conservar).unlink(missing_ok=True)
    for n in range(conservar - 1, 0, -1):
        if copia(n).exists():
            copia(n).replace(copia(n + 1))
    try:
        ruta.replace(copia(1))
    except PermissionError:
        # En Windows, un lector que abrió el fichero sin permitir renombrarlo (un editor, un
        # antivirus) impide el rename. Alternativa "copytruncate": copiar y vaciar el original.
        # No se pierden líneas: eslabon es el único que escribe en él. (El agente de Wazuh sí
        # permite el rename: comprobado en el lab.)
        shutil.copyfile(ruta, copia(1))
        with ruta.open("w", encoding="utf-8"):
            pass
    return copia(1)
