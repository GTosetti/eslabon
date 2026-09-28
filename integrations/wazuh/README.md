# Integración con Wazuh

> ✅ **ESTADO: VALIDADO CONTRA UN MANAGER REAL** (Wazuh **4.14.7**, laboratorio casero,
> 2026-09-28). Las reglas se cargaron en el manager, la configuración validó OK y **las 11 reglas**
> se probaron con logtest usando eventos generados por eslabon: 8 de escaneos reales y 3 construidos
> con el mismo código de salida para cubrir las ramas restantes. Detalle y evidencia en
> [`docs/validacion-wazuh.md`](../../docs/validacion-wazuh.md).
>
> **Ingesta de punta a punta también verificada:** un agente en el equipo donde corre eslabon lee
> `eventos.jsonl` (configuración centralizada del grupo `eslabon`), y las alertas llegan al índice
> `wazuh-alerts-*` (30 alertas de un escaneo real).
>
> ⚠️ **Pendiente de validar en el lab (F8):** las reglas nuevas **100161** y **100170**, y el cambio
> de la **100160** (ahora exige `completo = true`). Salieron de la revisión de valores inseguros
> por defecto. Hoy solo están comprobadas con el simulador de los tests.

## Qué produce eslabon

```powershell
eslabon scan C:\ruta\al\proyecto -f siem -o C:\Users\<usuario>\eslabon\eventos.jsonl --anexar
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
  <location>C:\Users\<usuario>\eslabon\eventos.jsonl</location>
</localfile>
```

> **Dónde guardar el fichero.** Conviene una carpeta dentro del perfil del usuario que ejecuta
> eslabon, no `C:\eslabon\`. Una carpeta creada en la raíz de `C:` hereda permisos de modificación
> para "Usuarios autenticados": cualquier usuario local podría inyectar eventos falsos o borrar los
> verdaderos. El agente de Wazuh corre como SYSTEM y lee el perfil sin problema.

Reiniciar el agente. El agente lee las líneas **nuevas** que se añaden al fichero. Para que cada
escaneo genere eventos nuevos, programar eslabon (con el Programador de tareas o con cron) con
`--anexar`, que añade al final del fichero en lugar de sobrescribirlo:

```powershell
eslabon scan C:\proyectos\app -f siem -o C:\Users\<usuario>\eslabon\eventos.jsonl --anexar --fallar-en nunca
```

> No usar `eslabon ... | Add-Content`. En PowerShell 5.1 la tubería rompe los acentos, y
> `Add-Content -Encoding utf8` escribe un BOM al principio del fichero. Con `-o ... --anexar`,
> eslabon escribe él mismo en UTF-8 sin BOM, una línea por evento y sin líneas vacías.

### 2. En el manager

```bash
sudo cp eslabon_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/eslabon_rules.xml
sudo systemctl restart wazuh-manager
```

### Cómo se decodifican los eventos

El agente lee el fichero con `log_format json` y Wazuh aplica su decoder `json` incorporado. La regla
base **100100** exige `decoded_as json` y la presencia de `eslabon.evento`. **No hace falta ningún
decoder propio.**

> Hasta la validación en el lab existía también una vía por syslog, con un decoder `eslabon` y una
> regla base 100101. Se eliminó: la regla apuntaba a un decoder que había que instalar aparte, y sin
> él el manager rechazaba el fichero **entero** con un engañoso *"XML syntax error"*. Un decoder
> propio para el fichero tampoco serviría: el decoder `json` incorporado se aplica primero a toda
> línea que empiece por `{`.

## Escaneo programado y rotación

`scripts\escaneo_programado.ps1` escanea cada objetivo de `resultados\objetivos.txt` (hay un ejemplo
en `scripts\objetivos.ejemplo.txt`) y añade los eventos a `resultados\eventos.jsonl` con
`--anexar --rotar-mb 50 --fallar-en nunca`. Deja una línea por objetivo en
`resultados\escaneo_programado.log`, y sale con el código más grave (3 si algún análisis quedó
incompleto).

- **Rotación.** Si el fichero superaría los 50 MB, pasa a `eventos.jsonl.1` (se conservan 5 copias)
  y se empieza uno nuevo. Se comprobó en el lab que el agente de Wazuh permite renombrar el fichero
  mientras lo lee. Si otro programa lo impidiera, eslabon copia y vacía el original ("copytruncate")
  sin perder líneas.
- **GuardDog** usa la variable de usuario `ESLABON_GUARDDOG`. Si Docker no está abierto, se informa
  como fuente omitida (alerta 100150) y el resto del escaneo sigue.

Registro en el Programador de tareas (a diario, a las 09:00, con el usuario actual):

```powershell
schtasks /Create /TN "eslabon\escaneo-diario" /SC DAILY /ST 09:00 /F /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\Users\user1\Desktop\eslabon\scripts\escaneo_programado.ps1\""
schtasks /Run /TN "eslabon\escaneo-diario"          # probarla ahora
schtasks /Delete /TN "eslabon\escaneo-diario" /F    # quitarla
```

## Reglas (IDs 100100–100199)

| ID | Nivel | Condición | MITRE |
|---|---|---|---|
| 100100 | 0 | Base: cualquier evento de eslabon (fichero JSON) | — |
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
| 100160 | 2 | `evento = resumen` y `completo = true` | — |
| 100161 | **6** | `evento = resumen` y `completo = false`: escaneo **incompleto** (código 3) ⚠️ | — |
| 100170 | **7** | `evento = error_programado`: el escaneo programado no pudo ejecutarse ⚠️ | — |

Por qué esos niveles:
- **14 para malicioso.** Es un compromiso confirmado: quien instaló el paquete ejecutó código del
  atacante.
- **12 para una CVE crítica.** Es grave, pero es un riesgo, no una intrusión.
- **10 para sospechoso alto.** Hace falta investigar ya.
- **Escaneo incompleto (6) y escaneo programado fallido (7):** son más altos que la fuente omitida,
  porque ahí directamente no se miró. Cero hallazgos en un escaneo incompleto no significa limpio,
  y un escaneo que no corrió no puede ser silencio.
- La **fuente omitida** tiene nivel 4 porque un escaneo "limpio" sin todas sus fuentes no es un
  escaneo limpio, y el SOC tiene que saberlo.

## Validación en el laboratorio (hecha)

1. ✅ Reglas cargadas en el manager (`/var/ossec/etc/rules/eslabon_rules.xml`), configuración
   validada (`GET /manager/configuration/validation` → OK) y manager reiniciado.
2. ✅ Logtest con eventos de eslabon: la fase 2 decodifica los campos `eslabon.*` (decoder `json`),
   la fase 3 dispara la regla esperada con su nivel y su técnica MITRE, y `$(eslabon.paquete)` se
   expande en la descripción.
3. ✅ Agente en el equipo de eslabon (grupo `eslabon`, `localfile` centralizado) y alertas en el
   dashboard (`wazuh-alerts-*`, `rule.groups:eslabon`). Captura en `docs/img/wazuh-discover-eslabon.png`.

Dudas que quedaron resueltas:
- **`^alta$|^critica$` funciona con OS_Regex**: el evento "sospechoso alta" disparó la 100120.
- **Campos de tipo lista:** en la descripción aparecen como `["osv", "depsdev"]`.
- **Números:** Wazuh convierte `confianza` a texto con 6 decimales (`0.850000`). Es estético.
- **Error encontrado y corregido:** la antigua regla 100101 (vía syslog) usaba `decoded_as eslabon`,
  un decoder que había que instalar aparte. Sin él, el manager rechazaba el fichero **entero** con un
  engañoso *"XML syntax error"*, que ningún test local podía detectar. Se eliminó la vía por syslog.
- Sin revisar todavía: si conviene `<options>no_full_log</options>` para no duplicar el JSON en la
  alerta.
