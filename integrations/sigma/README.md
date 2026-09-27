# Reglas Sigma de eslabon

Reglas equivalentes a las de Wazuh (`../wazuh/`), en el formato genérico
[Sigma](https://sigmahq.io/), que se puede convertir a las consultas de muchos SIEM (Splunk,
Elastic, Microsoft Sentinel…) con `sigma-cli` y el *backend* correspondiente.

| Fichero | Nivel | Equivale a (Wazuh) |
|---|---|---|
| `eslabon_paquete_malicioso.yml` | critical | 100110 |
| `eslabon_paquete_sospechoso_alto.yml` | high | 100120 |
| `eslabon_paquete_sospechoso_medio.yml` | medium | 100121 |
| `eslabon_riesgo_origen.yml` | low | 100130 |
| `eslabon_vulnerabilidad_critica.yml` | high | 100140 |
| `eslabon_fuente_omitida.yml` | low | 100150 |

**Fuente de logs:** `product: eslabon`, `service: supply_chain`. No es una fuente estándar de Sigma:
al convertir, hay que definir en un *pipeline* a qué índice o tabla corresponde, es decir, dónde
guarda el SIEM las líneas de `eslabon scan -f siem`. Los nombres de campo son los del JSON
(`eslabon.tipo`, `eslabon.severidad`…).

**Validación:** los tests de eslabon cargan cada regla con **pySigma**, la librería oficial del
proyecto Sigma, y comprueban lo siguiente:
- que la regla es válida;
- que su UUID es único;
- que las etiquetas ATT&CK coinciden con las del mapeo de eslabon;
- que la condición coincide con los eventos que debe detectar y **no** con los demás.

Las reglas **no se convirtieron ni se probaron en un SIEM real**. Tienen `status: experimental`.
