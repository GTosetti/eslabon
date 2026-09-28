# Manual de usuario de eslabon

eslabon analiza las dependencias de un proyecto (npm y PyPI) y avisa si alguna es **maliciosa**,
**sospechosa**, tiene un **repositorio de origen débil** o tiene **vulnerabilidades conocidas**.
Los resultados se pueden leer en la terminal, subir a GitHub (SARIF) o enviar a un SIEM (Wazuh).

**Qué lo distingue:** no se limita a buscar avisos ya publicados. Cruza señales débiles de varias
fuentes: quién publicó cada versión, cuándo, qué ejecuta al instalarse y cómo está mantenido su
repositorio. Así puede detectar un compromiso que todavía no tiene CVE, como `event-stream@3.3.5`.

**Qué NO hace:** nunca instala ni ejecuta los paquetes que analiza. Todo el análisis es estático o
por metadatos.

---

## 1. Instalación

Requisitos: Windows 10/11 (o Linux/macOS), Python 3.12, y opcionalmente Docker Desktop para
GuardDog. La guía completa, con la verificación de cada herramienta, está en
[`instalacion.md`](instalacion.md). En resumen, en PowerShell:

```powershell
cd C:\ruta\a\eslabon
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install --require-hashes --no-deps -r requirements.txt
.venv\Scripts\python -m pip install --no-deps -e .
.venv\Scripts\eslabon version
```

`--require-hashes` hace que pip compruebe el hash de cada dependencia de eslabon. Si alguien
alterara un paquete en el camino, la instalación fallaría.

### Herramientas externas

eslabon usa estas herramientas. Si falta alguna, lo avisa y sigue con las demás.

| Herramienta | Para qué | Cómo se instala | ¿Imprescindible? |
|---|---|---|---|
| **Syft** | Hacer el inventario (SBOM) de un directorio o lockfile | Binario en `%LOCALAPPDATA%\Programs\syft` | Solo para escanear directorios y lockfiles |
| **OSV-Scanner** | Avisos publicados: CVE, GHSA y malware (MAL-) | Binario en `%LOCALAPPDATA%\Programs\osv-scanner` | **Sí**: sin él, el análisis queda incompleto |
| **GuardDog** | Mira el **código** del paquete (heurísticas y reglas YARA) | Imagen de Docker (en Windows no se instala nativo) | No, pero es la única fuente que mira el código |
| deps.dev, registro de npm, Scorecard | Historia de publicación, quién publicó, salud del repositorio | Nada: son APIs públicas | No |

**GuardDog con Docker.** Se define una variable de usuario una sola vez, con la imagen fijada por
su hash y el contenedor restringido:

```powershell
[Environment]::SetEnvironmentVariable('ESLABON_GUARDDOG', 'docker run --rm --cap-drop=ALL --security-opt no-new-privileges --memory 1g --pids-limit 256 ghcr.io/datadog/guarddog:v3.2.0@sha256:5b0804d480e83405120fc90c62b60ad844310418c836e567055b1ba8843e033d', 'User')
```

Después hay que **abrir una terminal nueva**: las que ya estaban abiertas no ven la variable.

---

## 2. Primer escaneo

eslabon acepta tres tipos de objetivo:

```powershell
eslabon scan C:\proyectos\mi-app                     # un directorio: Syft busca los lockfiles
eslabon scan C:\proyectos\mi-app\package-lock.json   # un lockfile concreto
eslabon scan npm:lodash@4.17.15                      # un paquete suelto, sin ficheros
eslabon scan pypi:requests@2.19.0
```

**Conviene escanear lockfiles** (`package-lock.json`, o un `requirements.txt` con versiones fijas
generado por `pip-compile`). Un requisito sin versión fija, como `flask>=2.0`, **no se analiza**:
Syft no lo incluye en el inventario (ver §9).

### Cómo leer la tabla

Ejemplo real con la primera versión que publicó el atacante de event-stream (sin CVE):

```text
eslabon 0.1.0 · objetivo: pkg:npm/event-stream@3.3.5
Paquetes inventariados: 1 · fuentes usadas: osv, depsdev, npm, scorecard
┌───────────┬────────────┬──────────────┬─────────┬──────────────────────┬──────────────────────┐
│ Severidad │ Tipo       │ Paquete      │ Versión │ Fuentes              │ Resumen              │
│ media     │ sospechoso │ event-stream │ 3.3.5   │ depsdev, npm,        │ Versión publicada    │
│           │            │              │         │ scorecard            │ tras más de un año…  │
└───────────┴────────────┴──────────────┴─────────┴──────────────────────┴──────────────────────┘
```

Qué significa cada columna:

- **Tipo:**
  - `malicioso`: malware confirmado por un aviso o por el registro. Siempre es crítico.
  - `sospechoso`: señales de compromiso que coinciden entre sí, sin confirmación.
  - `riesgo_origen`: el repositorio de origen tiene prácticas peligrosas (por ejemplo, un CI
    inyectable).
  - `vuln`: vulnerabilidad conocida (CVE o GHSA).
- **Severidad:** crítica, alta, media, baja o info. En `vuln` sale del CVSS del aviso. En
  sospechoso y riesgo de origen sale de la **confianza** (§3).
- **Fuentes:** quién aportó evidencia. Varias fuentes independientes que coinciden pesan más que
  una sola.
- **ID / Alias:** el identificador del aviso (CVE, GHSA, MAL-…). Si empieza por `ESL-`, es una
  señal propia de eslabon; por ejemplo, `ESL-NPM-PUBLICADOR-NUEVO`.

Para ver la **explicación completa** de cada hallazgo (qué dijo cada fuente y la cuenta de la
confianza), usá el formato JSON: `eslabon scan … -f json`.

---

## 3. Cómo decide eslabon: confianza y severidad

Cada señal tiene un **peso**: la probabilidad de compromiso si solo se viera esa señal. Por ejemplo:

| Señal | Peso |
|---|---|
| Aviso de malware (MAL-) | 0,95 |
| Versión retirada del registro | 0,40 |
| La publicó una cuenta desconocida en el paquete | 0,35 |
| Reactivación de un paquete tras más de un año sin publicar | 0,25 |

Varias señales de **fuentes distintas** se combinan así:

```text
confianza = 1 − (1 − p₁)(1 − p₂)…
```

Se lee como "la probabilidad de que todas se equivoquen a la vez". Si dos señales vienen de la
misma fuente, cuenta solo la más fuerte, para no inflar el resultado por repetición.

Confianza → severidad (sospechoso y riesgo de origen):

| Confianza | Severidad |
|---|---|
| ≥ 0,80 | alta |
| ≥ 0,50 | media |
| ≥ 0,25 | baja |
| < 0,25 | info |

Cada número está justificado en [`scoring.md`](scoring.md), y la medición sobre 425 paquetes reales
está en [`calibracion.md`](calibracion.md). Sobre 300 versiones legítimas populares hubo **una**
alerta "media" y ninguna alta.

---

## 4. Todas las opciones

```text
eslabon scan <objetivo> [opciones]
eslabon version
```

| Opción | Por defecto | Qué hace |
|---|---|---|
| `-f`, `--formato` | `tabla` | `tabla`, `json`, `sarif` (GitHub) o `siem` (Wazuh). Ver §6. |
| `-o`, `--salida <fichero>` | pantalla | Escribe el resultado en un fichero (UTF-8 sin BOM). |
| `--anexar` | no | Añade al fichero en lugar de sobrescribirlo. Es lo que hay que usar con `-f siem`. |
| `--rotar-mb <N>` | sin rotación | Con `--anexar`: si el fichero superaría N MB, pasa a `.1` y empieza uno nuevo. |
| `--conservar <N>` | 5 | Cuántas copias rotadas guardar (`.1` … `.N`). |
| `--fallar-en <sev>` | `alta` | Sale con código 1 si hay hallazgos de esa severidad o mayor. `nunca` lo desactiva. |
| `--requerir <fuente>` | solo OSV | Otra fuente que tiene que funcionar para que el análisis cuente como completo. Se puede repetir: `--requerir guarddog --requerir npm`. |
| `--permitir-degradado` | no | No salir con código 3 si el análisis quedó incompleto. Usarlo con cuidado (§5). |
| `--guarddog-max <N>` | 20 | Cuántos paquetes analiza GuardDog, que es lento. `0` lo desactiva. |
| `--timeout <s>` | 300 | Segundos máximos por herramienta (de 1 a 3600). |
| `--srcroot <carpeta>` | carpeta actual | Con `-f sarif`: la raíz del repositorio, para que GitHub ubique cada alerta en su fichero. |

---

## 5. Códigos de salida (para CI y scripts)

| Código | Significa | Qué hacer |
|---|---|---|
| **0** | Sin hallazgos por encima de `--fallar-en` | Nada |
| **1** | Hay hallazgos de esa severidad o mayor | Revisar los hallazgos |
| **2** | Error de uso (opción mal escrita, objetivo inválido) | Corregir el comando |
| **3** | **Análisis incompleto:** no hubo inventario, falló OSV o falló una fuente de `--requerir` | Ver qué fuente se omitió (§9) |

**El 3 es importante.** Un escaneo que no pudo mirar y devuelve 0 hallazgos **no está limpio**.
eslabon "falla en cerrado": ante la duda, no dice que todo está bien.

Ejemplo en un pipeline de CI:

```bash
eslabon scan . -f sarif -o eslabon.sarif --fallar-en alta --requerir guarddog
# 0 → sigue; 1 → hay hallazgos altos/críticos; 3 → no se pudo analizar: también bloquea
```

---

## 6. Formatos de salida

| Formato | Para qué | Notas |
|---|---|---|
| `tabla` | Leer en la terminal | Con colores si es una terminal |
| `json` | Scripts y la explicación completa | Es el modelo de datos entero |
| `sarif` | **GitHub Code Scanning** y otros IDE o plataformas | SARIF 2.1.0. Cada hallazgo tiene una huella estable, para que GitHub no cierre y reabra la misma alerta en cada escaneo. Un análisis incompleto se marca como no exitoso. |
| `siem` | **Wazuh** u otro SIEM | JSON Lines: un evento por línea, bajo la clave `eslabon`, en ASCII |

Subir el SARIF a GitHub (en un workflow):

```yaml
- run: eslabon scan . -f sarif -o eslabon.sarif --fallar-en nunca
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: eslabon.sarif }
```

---

## 7. Integración con Wazuh

Guía completa: [`integrations/wazuh/README.md`](../integrations/wazuh/README.md). Todo está
validado contra un manager real (Wazuh 4.14.7).

**En el equipo que ejecuta eslabon:**
1. Escribir los eventos siempre en el **mismo fichero, con `--anexar`**:
   ```powershell
   eslabon scan C:\proyectos\app -f siem -o C:\Users\<usuario>\eslabon\eventos.jsonl --anexar --fallar-en nunca
   ```
2. El agente de Wazuh lee ese fichero con `<log_format>json</log_format>`.

> ⚠️ **El nombre del fichero tiene que terminar en `eventos.jsonl`.** La regla base solo acepta
> eventos de un fichero así, para que otra fuente JSON no pueda fabricar alertas de eslabon. Con
> otro nombre, los eventos llegan pero **no generan alertas**.

> ⚠️ Guardarlo **dentro del perfil del usuario**, no en `C:\eslabon\`. En la raíz de `C:`,
> cualquier usuario del equipo podría escribir eventos falsos.

**En el manager:** copiar `integrations/wazuh/eslabon_rules.xml` a `/var/ossec/etc/rules/` y
reiniciar. No hace falta ningún decoder propio.

**Qué alertas vas a ver:**

| Regla | Nivel | Cuándo | MITRE |
|---|---|---|---|
| 100110 | **14** | Paquete malicioso | T1195.001 |
| 100140 | 12 | Vulnerabilidad crítica | — |
| 100120 | 10 | Sospechoso, severidad alta o crítica | T1195.001 |
| 100141 | 8 | Vulnerabilidad alta | — |
| **100170** | **7** | **El escaneo programado no pudo ejecutarse** | — |
| 100121 | 7 | Sospechoso, severidad media | T1195.001 |
| **100161** | **6** | **Escaneo incompleto** (código 3) | — |
| 100130 | 5 | Riesgo en el repositorio de origen | T1195.002 |
| 100142 | 5 | Vulnerabilidad media | — |
| 100150 | 4 | Una fuente no se pudo consultar | — |
| 100122 / 100143 | 3 | Sospechoso o vulnerabilidad de severidad baja | — |
| 100160 | 2 | Resumen de un escaneo completo | — |

En el dashboard: *Discover* → índice `wazuh-alerts-*` → filtro `rule.groups: eslabon`.

También hay reglas **Sigma** equivalentes en `integrations/sigma/`, para otros SIEM.

---

## 8. Escaneo programado (operación continua)

`scripts\escaneo_programado.ps1` escanea una lista de objetivos y escribe los eventos para Wazuh.

1. Copiar `scripts\objetivos.ejemplo.txt` a `resultados\objetivos.txt` y poner un objetivo por
   línea. Las líneas que empiezan con `#` se ignoran.
2. Probarlo a mano:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\escaneo_programado.ps1
   ```
3. Registrarlo en el Programador de tareas (a diario, a las 09:00, con tu usuario):
   ```powershell
   schtasks /Create /TN "eslabon\escaneo-diario" /SC DAILY /ST 09:00 /F /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ruta\a\eslabon\scripts\escaneo_programado.ps1"
   schtasks /Run /TN "eslabon\escaneo-diario"          # ejecutarla ahora
   schtasks /Delete /TN "eslabon\escaneo-diario" /F    # quitarla
   ```

Qué hace por vos:
- **Rota** `eventos.jsonl` al llegar a 50 MB y conserva 5 copias. El agente de Wazuh lo sigue sin
  perder eventos.
- Deja un registro en `resultados\escaneo_programado.log`.
- **Si eslabon no puede ejecutarse**, escribe él mismo un evento `error_programado`, que genera la
  alerta 100170. Un fallo del escaneo nunca queda en silencio.

**No registrar la tarea como SYSTEM** ni con privilegios elevados: con tu usuario alcanza, y es
más seguro.

---

## 9. Solución de problemas

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| "syft/osv-scanner no está disponible" | La terminal se abrió antes de instalar la herramienta, o no está en el PATH | Abrir una terminal nueva, o definir `ESLABON_SYFT` / `ESLABON_OSV_SCANNER` con la ruta del ejecutable |
| "guarddog: Docker no responde (¿está abierto Docker Desktop?)" | Docker Desktop cerrado | Abrir Docker Desktop. Sin él, GuardDog se omite (alerta 100150), salvo que uses `--requerir guarddog`, que da código 3 |
| "guarddog no disponible" aunque Docker esté abierto | `ESLABON_GUARDDOG` no está definida en esa terminal | Definirla como variable de usuario (§1) y abrir una terminal nueva |
| Código **3** | Análisis incompleto | Mirar las "fuentes omitidas" en la salida: dicen qué falló y por qué |
| Una dependencia de `requirements.txt` no aparece | Tiene una versión sin fijar (`flask>=2.0`), y Syft no la incluye | Escanear un lockfile con versiones fijas (`pip-compile --generate-hashes`) |
| Un `package.json` sin lockfile da código 3 | Syft no puede resolver versiones sin lockfile | Generar `package-lock.json` (`npm install --package-lock-only`, en **tu** proyecto) |
| Los eventos llegan a Wazuh pero **no hay alertas** | El fichero no termina en `eventos.jsonl` | Renombrarlo (§7) |
| "No encuentro las alertas de hace un momento" | El reloj del manager y el del equipo están desfasados (en el lab, el manager va ≥14 s por detrás) | Buscar con margen (unos minutos antes) y sincronizar los relojes por NTP (abajo) |
| Acentos rotos en un fichero | Se pasó la salida por una tubería de PowerShell 5.1 (`… \| Out-File`) | Usar `-o fichero` en lugar de redirigir |
| El escaneo tarda mucho | GuardDog analiza cada paquete | Bajar `--guarddog-max`, o `0` para desactivarlo |

**Sincronizar relojes (lo hace el administrador de cada equipo):**
- Windows, en una PowerShell de administrador: `w32tm /resync`. Para verificar:
  `w32tm /query /status`.
- VM Ubuntu del manager: `sudo timedatectl set-ntp true` y, para verificar, `timedatectl status`.
  Tiene que decir `System clock synchronized: yes`.

---

## 10. Variables de entorno

| Variable | Para qué |
|---|---|
| `ESLABON_SYFT`, `ESLABON_OSV_SCANNER`, `ESLABON_SCORECARD` | Ruta o comando de cada herramienta, si no está en el PATH |
| `ESLABON_GUARDDOG` | Comando de GuardDog. En Windows, el `docker run …` de §1 |
| `GITHUB_TOKEN` | Opcional. Con él (y el CLI `scorecard` instalado), Scorecard se calcula en el momento. Sin él, se usa el último análisis semanal publicado en deps.dev. **Se lee solo del entorno:** nunca lo pongas en un fichero del repositorio |

> En CI, no dejes que contribuidores no confiables definan variables `ESLABON_*`: eligen qué
> comando se ejecuta.

---

## 11. Límites (qué NO detecta)

- **Un paquete malicioso nuevo, todavía publicado y sin aviso,** solo lo puede ver GuardDog, porque
  es la única fuente que mira el código. Si GuardDog no corre, eslabon lo avisa, pero no lo detecta.
- **Un traspaso legítimo de un paquete dormido a una persona nueva** es indistinguible de un
  secuestro de cuenta con metadatos. Ejemplo medido: `cors@2.8.6`, legítimo, empata con el ataque
  a event-stream. Si aparece un "sospechoso media" así, revisá quién es el nuevo publicador.
- **"Publicador nuevo" solo existe para npm:** PyPI no publica esa información.
- Solo analiza los ecosistemas **npm y PyPI**. Los demás (Go, Maven…) se informan como "no
  soportados".

---

## 12. Dónde seguir

| Documento | Contenido |
|---|---|
| [`instalacion.md`](instalacion.md) | Instalación paso a paso y verificación |
| [`scoring.md`](scoring.md) | Por qué cada peso vale lo que vale |
| [`calibracion.md`](calibracion.md) | Medición sobre 425 paquetes reales |
| [`revision-insecure-defaults.md`](revision-insecure-defaults.md) | Revisión de seguridad del propio eslabon |
| [`validacion-wazuh.md`](validacion-wazuh.md) | Validación de las reglas en un manager real |
| [`bitacora.md`](bitacora.md) | Historia del proyecto, fase por fase |
