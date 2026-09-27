# Integración con Wazuh

> ⚠️ **ESTADO: NO VALIDADO CONTRA UN MANAGER.** El decoder y las reglas se escribieron siguiendo la
> sintaxis documentada de Wazuh 4.x, y los tests de eslabon comprueban la estructura:
> - el XML está bien formado;
> - los IDs están en el rango 100100–100199 y no se repiten;
> - los niveles van de 0 a 15;
> - las técnicas MITRE tienen el formato correcto;
> - cada evento de ejemplo cae en la regla esperada según las expresiones de los campos.
>
> **No se cargaron en un `wazuh-manager` real.** Esa validación se hace en el laboratorio (sección
> "Validación pendiente") y **no debe darse por hecha**.

## Qué produce eslabon

```powershell
eslabon scan C:\ruta\al\proyecto -f siem -o C:\eslabon\eventos.jsonl --anexar
```

Genera un fichero **JSON Lines**: un evento JSON por línea, todos bajo la clave `eslabon`. Hay tres
tipos de evento (campo `eslabon.evento`):

| `evento` | Cuándo | Campos principales |
|---|---|---|
| `hallazgo` | Uno por problema encontrado | `tipo`, `severidad`, `confianza`, `paquete`, `paquete_version`, `id`, `ids`, `fuentes`, `attack`, `explicacion`, `remediacion`, `huella` |
| `fuente_omitida` | Una fuente no se pudo consultar | `fuente`, `motivo` |
| `resumen` | Uno por escaneo | `paquetes`, `hallazgos`, `hallazgos_<severidad>` |

Todos llevan `escaneo_id`, `fecha`, `equipo` y `objetivo`. Ejemplo (una línea, formateada aquí):

```json
{"eslabon": {"version": "0.1.0", "escaneo_id": "3f1c…", "fecha": "2026-09-26T21:00:00+00:00",
  "equipo": "pc-dev-01", "objetivo": "pkg:npm/flatmap-stream@0.1.1", "evento": "hallazgo",
  "tipo": "malicioso", "severidad": "critica", "severidad_num": 4, "confianza": 0.995,
  "ecosistema": "npm", "paquete": "flatmap-stream", "paquete_version": "0.1.1",
  "id": "MAL-2025-20690", "fuentes": ["osv", "depsdev"], "attack": ["T1195.001"], "…": "…"}}
```

## Instalación

### 1. En el agente (la máquina donde corre eslabon)

Añadir a `ossec.conf` del agente (Windows: `C:\Program Files (x86)\ossec-agent\ossec.conf`):

```xml
<localfile>
  <log_format>json</log_format>
  <location>C:\eslabon\eventos.jsonl</location>
</localfile>
```

Reiniciar el agente. El agente lee las líneas **nuevas** que se añaden al fichero. Para que cada
escaneo genere eventos nuevos, programar eslabon (con el Programador de tareas o con cron) con
`--anexar`, que añade al final del fichero en lugar de sobrescribirlo:

```powershell
eslabon scan C:\proyectos\app -f siem -o C:\eslabon\eventos.jsonl --anexar --fallar-en nunca
```

> No usar `eslabon ... | Add-Content`. En PowerShell 5.1 la tubería rompe los acentos, y
> `Add-Content -Encoding utf8` escribe un BOM al principio del fichero. Con `-o ... --anexar`,
> eslabon escribe él mismo en UTF-8 sin BOM, una línea por evento y sin líneas vacías.

### 2. En el manager

```bash
sudo cp eslabon_rules.xml    /var/ossec/etc/rules/
sudo cp eslabon_decoders.xml /var/ossec/etc/decoders/   # solo si se usa el envío por syslog
sudo chown wazuh:wazuh /var/ossec/etc/rules/eslabon_rules.xml /var/ossec/etc/decoders/eslabon_decoders.xml
sudo systemctl restart wazuh-manager
```

### Dos formas de enviar los eventos, las mismas reglas

- **Fichero con `log_format json`** (la recomendada). Wazuh aplica su decoder JSON incorporado
  (`json`). La regla base **100100** exige `decoded_as json` y la presencia de `eslabon.evento`.
- **Syslog con el programa `eslabon`**: `logger -t eslabon '<json>'`. Wazuh separa la cabecera
  syslog y aplica el decoder `eslabon` de `eslabon_decoders.xml`. La regla base es la **100101**.

¿Por qué no un decoder propio también para el fichero? Wazuh prueba sus decoders incorporados antes
que los locales, y el decoder `json` incorporado reconoce cualquier línea que empiece por `{`. Uno
propio con la misma condición nunca llegaría a aplicarse.

## Reglas (IDs 100100–100199)

| ID | Nivel | Condición | MITRE |
|---|---|---|---|
| 100100 / 100101 | 0 | Base: cualquier evento de eslabon (fichero JSON / syslog) | — |
| 100110 | **14** | `tipo = malicioso` | T1195.001 |
| 100120 | 10 | `tipo = sospechoso` y severidad alta/crítica | T1195.001 |
| 100121 | 7 | `tipo = sospechoso` y severidad media | T1195.001 |
| 100122 | 3 | `tipo = sospechoso` y severidad baja/info | — |
| 100130 | 5 | `tipo = riesgo_origen` | T1195.002 |
| 100140 | 12 | `tipo = vuln` y severidad crítica | — |
| 100141 | 8 | `tipo = vuln` y severidad alta | — |
| 100142 | 5 | `tipo = vuln` y severidad media | — |
| 100143 | 3 | `tipo = vuln` y severidad baja/info | — |
| 100150 | 4 | `evento = fuente_omitida` (visibilidad reducida) | — |
| 100160 | 2 | `evento = resumen` | — |

Por qué esos niveles:
- **14 para malicioso.** Es un compromiso confirmado: quien instaló el paquete ejecutó código del
  atacante.
- **12 para una CVE crítica.** Es grave, pero es un riesgo, no una intrusión.
- **10 para sospechoso alto.** Hace falta investigar ya.
- La **fuente omitida** tiene nivel 4 porque un escaneo "limpio" sin todas sus fuentes no es un
  escaneo limpio, y el SOC tiene que saberlo.

## Validación pendiente (en el laboratorio, en otra sesión)

1. Copiar los ficheros al manager (sección 2) y comprobar que arranca sin errores:
   `sudo /var/ossec/bin/wazuh-analysisd -t`
2. Probar cada tipo de evento con `wazuh-logtest`, pegando líneas reales generadas con
   `eslabon scan … -f siem`. Hay que confirmar tres cosas:
   - que la fase 2 decodifica los campos `eslabon.*`;
   - que la fase 3 dispara la regla esperada (tabla de arriba), con su nivel y su técnica MITRE;
   - que `$(eslabon.paquete)` y el resto de variables se expanden en la descripción.
3. Configurar el `localfile` en un agente, ejecutar un escaneo y ver las alertas en el dashboard
   (índice `wazuh-alerts-*`, `rule.groups: eslabon`).
4. Registrar el resultado en `docs/bitacora.md`. Si algo no coincide, corregirlo aquí y quitar este
   aviso de "no validado" solo cuando todo pase.

Puntos a vigilar en esa validación (dudas concretas, no verificadas):
- Si `<field>` con `^alta$|^critica$` funciona como se espera con OS_Regex. Si no, usar
  `type="pcre2"`.
- Cómo aparecen en el mensaje de alerta los campos de tipo lista (`fuentes`, `attack`).
- Si hace falta `<options>no_full_log</options>` para no duplicar el JSON en la alerta.
