"""Eventos para SIEM en JSON Lines: un objeto JSON por línea, uno por hallazgo.

Pensado para que un agente de Wazuh lea el fichero con `<log_format>json</log_format>`
(ver integrations/wazuh/README.md). Decisiones:
- Todo va dentro de una clave raíz "eslabon": en Wazuh los campos quedan como
  `eslabon.tipo`, `eslabon.severidad`..., sin chocar con campos de otras fuentes.
- Campos planos y de tipo simple (texto, número, lista de textos): los decoders JSON de
  los SIEM se llevan mal con objetos anidados profundos.
- Además de un evento por hallazgo, hay uno por fuente omitida (un escaneo que no pudo
  consultar una fuente tiene visibilidad reducida, y el SOC debe saberlo) y un resumen.
- `escaneo_id` agrupa los eventos de un mismo escaneo; `huella` es la misma que en el
  SARIF, así un hallazgo se puede seguir entre escaneos.
"""

from __future__ import annotations

import json
import socket
import uuid
from datetime import UTC, datetime

from eslabon.modelos import ResultadoScan, Severidad
from eslabon.salidas.sarif import huella

# Longitud máxima de los textos: los SIEM suelen truncar o descartar eventos muy largos
# (Wazuh, por defecto, unos 64 KB por evento), y los campos cortos acotan lo que un dato
# hostil puede meter en el título de una alerta.
_MAX_TEXTO = 2000
_MAX_CORTO = 200


def _corto(texto: str, maximo: int = _MAX_CORTO) -> str:
    return texto[:maximo]


def renderizar(resultado: ResultadoScan) -> str:
    # ensure_ascii=True: todo carácter no ASCII sale escapado. Así ni los saltos de línea
    # Unicode (U+2028, U+0085...) de un texto hostil pueden partir un evento en dos.
    return "".join(json.dumps(e, ensure_ascii=True) + "\n" for e in eventos(resultado))


def eventos(resultado: ResultadoScan, *, ahora: datetime | None = None,
            escaneo_id: str | None = None, equipo: str | None = None) -> list[dict]:
    ahora = ahora or datetime.now(UTC)
    comun = {
        "version": resultado.eslabon_version,
        "escaneo_id": escaneo_id or str(uuid.uuid4()),
        "fecha": ahora.isoformat(timespec="seconds"),
        "equipo": equipo or socket.gethostname(),
        "objetivo": _corto(resultado.objetivo),
    }
    salida = []
    for h in resultado.hallazgos:
        salida.append({"eslabon": {
            **comun,
            "evento": "hallazgo",
            "tipo": h.tipo.value,
            "severidad": h.severidad.value,
            "severidad_num": h.severidad.rango,
            "confianza": h.confianza,
            "ecosistema": h.ecosistema.value,
            "paquete": _corto(h.paquete),
            "paquete_version": _corto(h.version),
            "purl": _corto(h.purl),
            "id": _corto(h.ids[0]),
            "ids": [_corto(i) for i in h.ids[:20]],
            "fuentes": h.fuentes,
            "num_fuentes": len(h.fuentes),
            "attack": h.attack,
            "titulo": _corto(h.titulo, _MAX_TEXTO),
            "explicacion": _corto(h.explicacion, _MAX_TEXTO),
            "remediacion": _corto(h.remediacion or "", _MAX_TEXTO),
            "huella": huella(h),
        }})
    for o in resultado.fuentes_omitidas:
        salida.append({"eslabon": {**comun, "evento": "fuente_omitida", "fuente": _corto(o.fuente),
                                   "motivo": _corto(o.motivo, _MAX_TEXTO)}})
    salida.append({"eslabon": {
        **comun,
        "evento": "resumen",
        "completo": resultado.completo,
        "paquetes": len(resultado.paquetes),
        "hallazgos": len(resultado.hallazgos),
        **{f"hallazgos_{s.value}": sum(h.severidad is s for h in resultado.hallazgos)
           for s in Severidad},
        "fuentes_usadas": resultado.fuentes_usadas,
        "fuentes_omitidas": [o.fuente for o in resultado.fuentes_omitidas],
    }})
    return salida

