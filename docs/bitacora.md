# Bitácora de eslabon

## F0: Preparación (2026-09-26)

**Qué se hizo**
- Inventario del entorno: Python 3.12.10, pip, git 2.53 y gh están. Go, Docker y WSL no.
- Syft 1.52.0 y OSV-Scanner 2.6.0 instalados desde las releases oficiales de GitHub, con el
  SHA256 verificado contra el fichero de checksums publicado. Un segundo agente repitió la
  verificación de forma independiente y no encontró discrepancias.
- venv del proyecto creado en `.venv`.
- Intento de instalar GuardDog 3.2.0: **falló**. Detalle en `docs/instalacion.md`.

**Qué demostró**
- `syft version` → 1.52.0 ✅
- `osv-scanner --version` → 2.6.0 ✅
- `guarddog --help` → ❌ no instalado.

**Qué falló o quedó pendiente**
- GuardDog 3.x ya no depende de Semgrep, sino de `nono-py` (sandbox de Linux/macOS), que no
  existe para Windows. La vía oficial es Docker. Pendiente: que el usuario elija entre Docker y
  WSL2. Ambos se instalan fuera del proyecto y requieren su autorización.
- Solo se verificó la **integridad** (checksum), no la **autenticidad** (firma cosign / procedencia
  SLSA). Queda como mejora.
- El usuario pegó un token de GitHub en el chat: se recomendó revocarlo y cargar uno nuevo solo como
  variable de entorno. No se escribió en ningún fichero.

**Conceptos clave**
- Checksum SHA256 = integridad. Firma (cosign/SLSA) = autenticidad.
- Wheel = paquete de Python precompilado. Si no hay uno para tu sistema, pip intenta compilar.
- Sandbox: analizar código hostil exige aislarlo, y la sandbox depende del sistema operativo.

## F1: Esqueleto (2026-09-26)

**Qué se hizo**
- Docker Desktop 4.91.0 instalado con `winget`, que verifica el SHA256 del instalador contra su
  manifiesto. **Falta WSL2** para que el motor de Docker arranque: el usuario debe ejecutar
  `wsl --install` como administrador y reiniciar.
- `git init`, paquete `src/eslabon/`, `pyproject.toml` (hatchling), `LICENSE` (texto oficial de
  Apache-2.0 descargado de apache.org), `README.md`, `.gitignore`, `.gitattributes`, `CLAUDE.md`.
- Proyecto de prueba `tests/fixtures/proyecto_demo/`: **solo lockfiles**, que nunca se instalan.
- Salidas reales de Syft y OSV-Scanner grabadas como fixtures, sin rutas locales.
- `eslabon scan` acepta un directorio, un lockfile o `ecosistema:paquete@versión`.
- Revisión con `code-review` (5 problemas, todos corregidos y con test propio) y con `simplify`
  (4 revisores; refactor de interfaces y datos derivados).

**Qué demostró**
- `eslabon scan tests/fixtures/proyecto_demo` → 6 paquetes, 28 hallazgos, fuentes syft + osv.
- `pytest` → 52 tests pasan (2 de integración ejecutan Syft y OSV reales). `ruff check .` limpio.
- Si falta OSV-Scanner, el escaneo termina igual y lo anota en `fuentes_omitidas`.

**Qué falló o quedó pendiente**
- WSL2 (y por lo tanto Docker, y por lo tanto GuardDog) pendiente de que el usuario lo instale.
- Descubrimiento para F2: los paquetes maliciosos famosos (event-stream, ua-parser-js, ctx) figuran
  en OSV como GHSA con **CWE-506**, no con prefijo `MAL-`. Mirar solo el prefijo no alcanza.

**Conceptos clave**
- SBOM y purl: inventario de dependencias e identificador universal `pkg:tipo/nombre@versión`.
- Alias: el mismo problema tiene un ID distinto en cada base (CVE, GHSA, PYSEC).
- Degradación elegante y escape de texto no confiable (el bug de los corchetes en rich).

## F2: Colectores y correlador (2026-09-26)

**Qué se hizo**
- Colectores nuevos, con la misma interfaz: **deps.dev** (estado del paquete en el registro),
  **Scorecard** (salud del repositorio de origen: CLI con `GITHUB_TOKEN` o, si no hay, los datos
  que publica deps.dev) y **GuardDog** (vía `ESLABON_GUARDDOG`, pensado para Docker).
- Catálogo de señales con peso justificado (`senales.py`) y **correlador** (`correlador.py`): unión
  por alias, fusión de todo lo que apunta a compromiso y confianza por "OR ruidoso" entre fuentes.
  Toda la justificación está en `docs/scoring.md`.
- OSV detecta malware por 3 vías: `MAL-` (también como alias), CWE-506 y frases que nombran al
  paquete ("Malicious code in X").
- Fixtures: respuestas **reales** de OSV y deps.dev para `flatmap-stream@0.1.1`,
  `event-stream@3.3.6` y `ctx@0.2.2` (solo metadatos: nada se descargó ni se ejecutó). La salida
  de GuardDog es **sintética**, construida a partir de su código fuente, porque falta WSL2.
- Metodología contrastada con `supply-chain-risk-auditor` (Trail of Bits): no usar el puntaje global
  de Scorecard, y un dato no disponible no es evidencia de riesgo.
- `code-review`: 4 bugs (MAL- como alias ignorado, falsos positivos por texto, un error de red tumbaba
  toda la fuente, `--guarddog-max` negativo). Todos corregidos, cada uno con su test. `simplify`: la
  política pasó al correlador, la caché de deps.dev ya no duplica peticiones simultáneas y se
  eliminaron duplicaciones.

**Qué demostró (condición de salida)**
- `eslabon scan npm:flatmap-stream@0.1.1`: **1 hallazgo** (antes eran 3), malicioso, crítico, con
  **2 fuentes** (osv + depsdev), 3 IDs (MAL-2025-20690, GHSA-9x64…, GHSA-mh6f…), confianza
  `1 − (1 − 0.95)·(1 − 0.90) = 0.995`, y la explicación con cada señal y la fórmula.
- Test `test_condicion_salida_f2_flatmap_stream`, sin red. `pytest`: 94 tests pasan.
- 0 falsos positivos de "malicioso" sobre las 52 CVE reales del proyecto demo.

**Qué falló o quedó pendiente**
- GuardDog no se ejecutó de verdad: falta WSL2 → Docker. Su salida grabada es sintética.
- Scorecard CLI no instalado (no estaba autorizado). Se usan los datos de deps.dev.
- Señal "mantenedor nuevo" sin implementar: requiere `registry.npmjs.org` (no autorizado).
- Pesos ordinales, no calibrados contra un corpus (ver §6 de `scoring.md`).
- Rendimiento pendiente: HTTP sin keep-alive, las dos etapas de Scorecard no se solapan, y
  GuardDog lanza un proceso por paquete.
- La skill `static-analysis:semgrep` no se usó: GuardDog 3.x ya no usa Semgrep, sino YARA.

**Conceptos clave**
- Correlación de señales débiles: 0,20 + 0,60 + 0,30 de fuentes distintas → 0,776.
- Independencia de fuentes: dos reglas de la misma herramienta no son dos testigos.
- El tapón `0.0.1-security` de npm: el propio registro "confiesa" que retiró malware.

## F3: Salidas, integraciones SIEM y endurecimiento (2026-09-26)

**Qué se hizo**
- Salidas nuevas: **SARIF 2.1.0** (`-f sarif`) y **eventos SIEM en JSON Lines** (`-f siem`).
  JSON ya existía.
- `integrations/wazuh/`: decoder, reglas 100100–100160 con MITRE T1195.001/.002 y README con la
  configuración del agente. **No validadas contra un manager.**
- `integrations/sigma/`: 6 reglas equivalentes, validadas con pySigma (0 problemas).
- Revisiones de cierre:
  - `code-review` de F3: 6 problemas en SARIF, README y GuardDog.
  - Revisión de seguridad del repositorio completo: 2 altos, 4 medios y 6 bajos.
  - Todo corregido con tests, salvo el timeout con Docker (documentado).
  - `simplify` sobre F3.
- Auditoría de las dependencias propias, escaneándolas con el propio eslabon: ver
  `docs/dependencias.md`.

**Endurecimiento de seguridad (lo más importante de esta fase)**
- **Secuestro de herramientas (alto).** En Windows se buscaban ejecutables en la carpeta actual:
  un `syft.bat` dentro de un repositorio escaneado se habría ejecutado. Ahora se buscan solo en el
  PATH y se rechazan `.bat` y `.cmd`.
- **Fallar en abierto (alto).** El CLI siempre salía con 0. Ahora sale con 1 si hay hallazgos
  iguales o superiores a `--fallar-en` (por defecto `alta`) y con 3 si el análisis quedó incompleto.
  El SARIF ya no dice "éxito" cuando no se analizó nada.
- **Inyección de argumentos.** Los nombres y versiones de los lockfiles se validan con la gramática
  de npm y PyPI, y el nombre del paquete va después de `--`.
- **Secretos.** Las herramientas reciben un entorno sin tokens (solo Scorecard recibe
  `GITHUB_TOKEN`), y todo motivo de error se redacta.
- **"Limpio" falso.** Ya no se da por limpio un OSV que no analizó nada (código 128 o salida
  vacía), ni un inventario vacío.
- **Otros.**
  - Terminal: se quitan las secuencias ANSI y las marcas bidi.
  - SIEM en ASCII: los saltos de línea Unicode no parten un evento.
  - HTTP: sin redirecciones a `http://` ni a otro host, y con un máximo de 20 MB por respuesta.
  - El propio código tenía **caracteres bidi invisibles** en una expresión regular. Ahora son
    escapes visibles.

**Qué demostró (condición de salida)**
- Los tres formatos se generan y se validan en tests:
  - el SARIF, contra el **esquema oficial de OASIS**, que se descargó de schemastore.org (su `$id`
    apunta al repositorio `oasis-tcs/sarif-spec`), también con la salida en vivo;
  - el JSON, recargándolo en el modelo;
  - el JSONL, línea por línea, con campos simples.
- Para cada tipo de evento, un test simula qué regla de Wazuh dispara (exactamente una), y
  comprueba que la regla Sigma equivalente detecta los mismos eventos.
- `pytest`: **154 tests pasan**. `ruff check .`: limpio.

**Qué falló o quedó pendiente**
- **Wazuh no está validado contra un manager real.** Eso se hace en otra sesión, con el laboratorio
  (pasos en `integrations/wazuh/README.md`).
- La auditoría `insecure-defaults:audit` **no se pudo ejecutar**: el entorno rechazó su script por
  contener caracteres de control. La cubrió en parte la revisión de seguridad manual.
- La skill `security-review` requiere un remoto `origin`, que el proyecto no tiene. Se hizo con un
  agente dedicado.
- Al vencer el timeout con `docker run`, el contenedor sigue vivo.
- El SARIF depende del directorio desde el que se ejecuta (la raíz del repositorio). Mejora
  propuesta: una opción `--srcroot`.
- La skill `supply-chain-risk-auditor` completa, y el lockfile con hashes de las dependencias
  propias, quedan pendientes de tu decisión (ver `docs/dependencias.md`).

**Conceptos clave**
- SARIF: reglas, resultados, `partialFingerprints` estables y `security-severity`.
- Fallar en cerrado: en seguridad, "no pude mirar" nunca debe verse igual que "miré y está limpio".
- Nunca confiar en datos del objetivo analizado: nombres, rutas y texto pueden ser un ataque.

## F4: Integración real (2026-09-27)

**Qué se hizo**
- **GuardDog real.** El usuario instaló WSL2. Docker Engine 29.8.0 funciona, y la imagen
  `ghcr.io/datadog/guarddog:v3.2.0` se fijó **por digest** (`sha256:5b0804d4…`). La sandbox
  funciona dentro de Docker. Grabaciones reales:
  - `requests` y `lodash`, paquetes legítimos: solo capacidades;
  - las **muestras de test oficiales** de GuardDog, montadas en solo lectura: `high_risk` 8,8.
- **Ruido corregido.** Las capacidades solas ya no generan hallazgo: son señales de "contexto",
  marcadas así en el catálogo.
- **`docker kill` al vencer el timeout.** El contenedor lleva un nombre único (o el `--name` del
  usuario). Funciona también con `docker --context x run` y `docker container run`.
- **Colector del registro de npm** (`registry.npmjs.org`, autorizado por el usuario):
  - publicador nuevo, comparando por cuenta y no por correo, y sin contar el paso a trusted
    publishing de CI;
  - script de instalación que descarga o ejecuta código.

  La "versión anterior" se calcula por semver, no por fecha, por los backports y las fechas
  empatadas.
- **Lockfiles con hashes** con pip-tools: `requirements.txt` (13 paquetes) y
  `requirements-dev.txt` (44, con pip y setuptools fijados).
- **Auditoría completa de Trail of Bits** (`api.scorecard.dev` autorizada): coincide con eslabon.
  Las dependencias de ejecución están limpias.
- Revisiones: `code-review` (6 problemas) y calidad (7). Todo aplicado, salvo lo indicado abajo.

**Qué demostró (condiciones de salida)**
- `docker run … guarddog --version` → 3.2.0. `eslabon scan` con **las cinco fuentes activas** y
  ninguna omitida. `docker ps` sin contenedores huérfanos.
- **Caso real sin avisos: `event-stream@3.3.5`**, la primera versión del atacante:
  - sospechoso, media, confianza 0,561;
  - reactivación tras 779 días (deps.dev) + publicador `right9ctrl` en lugar de `dominictarr`
    (npm) + repositorio archivado (Scorecard);
  - verificado con respuestas grabadas y en vivo.
- **Lockfile:**
  - la instalación con `--require-hashes` en un venv nuevo funciona;
  - con los hashes de `rich` alterados, pip **se niega** a instalar ("someone may have tampered
    with them").
- `pytest`: **181 tests pasan**. `ruff` limpio.

**Qué falló o quedó pendiente**
- ⚠️ **Incidente: uso del token de gh.** El recolector de Trail of Bits obtiene un token con
  `gh auth token`. Quité `gh` del PATH, pero hay **una segunda instalación de gh** y el recolector
  usó el token de la sesión del usuario para consultas de **lectura** a GitHub. Contradice la
  regla 3.
  - Se verificó que el token no quedó en ningún fichero, ni en la caché, ni en el repositorio.
  - Se informó al usuario y quedó registrado en la memoria del proyecto: la próxima vez,
    `GH_CONFIG_DIR` vacío y comprobar `gh auth status`.
  - La caché del recolector quedó en `%TEMP%\supply-chain-risk-auditor-cache`, fuera del proyecto.
    No se borró sin permiso.
- No aplicado de la revisión de calidad:
  - agrupar los clientes (deps.dev y npm) en una sola estructura, en lugar de un parámetro por
    cliente en `escanear`: hoy son dos;
  - unificar la "versión anterior" de deps.dev (reactivación, por **fecha**, porque mide la
    inactividad del paquete) con la de npm (por **semver**, porque compara la misma línea de
    versiones). Son preguntas distintas, y quedan documentadas.
- El patrón exacto del encargo (publicador nuevo + script con red + versión reciente), junto con
  GuardDog, da 0,792 → **media**. Las dos señales de npm son de la misma fuente. Subir los pesos a
  mano sería trampa: hay que calibrarlos con datos.
- Pendientes de antes: validar Wazuh en el laboratorio, `insecure-defaults` y `--srcroot`.

**Conceptos clave**
- Fijar por digest frente a fijar por etiqueta: una etiqueta se puede mover; un hash, no.
- `--require-hashes`: el lockfile no solo fija versiones, también verifica el contenido.
- Un compromiso sin CVE solo se ve correlacionando: quién publicó, cuándo y dónde vive el código.

## Arreglo: mensajes de error de GuardDog y Docker (2026-09-28)

**Problema.** Durante el tutorial aparecieron dos cosas:
- Con Docker Desktop cerrado, eslabon decía "guarddog no devolvió JSON" en lugar de "no se pudo
  conectar con Docker".
- El usuario abrió Docker y eslabon seguía diciendo "herramienta no disponible". La causa:
  `$env:ESLABON_GUARDDOG` solo vive en la ventana de PowerShell donde se define (se reprodujo en una
  terminal nueva: la variable no estaba guardada ni a nivel de usuario ni de sistema).

**Qué se hizo**
- `ejecutar_json`: si la herramienta termina con un código distinto de 0 y sin JSON, el error muestra
  su stderr (redactado). Antes se descartaba, porque GuardDog usa el 1 tanto para "encontré algo"
  como para "falló".
- Docker sin motor ("failed to connect to the docker API"): se informa como herramienta no
  disponible, **una sola vez** y con la pista "¿está abierto Docker Desktop?".
- Si GuardDog no se encuentra, el mensaje explica que en Windows va por Docker, cómo definir
  `ESLABON_GUARDDOG` y cómo desactivarlo (`--guarddog-max 0`).
- 3 tests nuevos. `pytest`: 184 pasan. `code-review`: sin errores.

## F5: Laboratorio Wazuh (2026-09-28, en curso)

**Qué se hizo**
- Tutorial de uso de eslabon, paso a paso y en vivo. Destapó el problema de `ESLABON_GUARDDOG`
  (solo vive en la ventana donde se define) y el mensaje de error confuso, que se corrigió
  (commit aparte).
- Acceso al dashboard del lab (`https://127.0.0.1:8443`) con **Playwright**. Se usó un Chromium
  limpio en el que el usuario inició sesión él mismo; ni su perfil de Chrome ni sus contraseñas.
- Reconocimiento de solo lectura: manager 4.14.7; el único agente es `WIN11-VICTIMA` (una VM); el
  rango 100100–100199 está libre.
- Con autorización: subida de `eslabon_rules.xml`, validación, reinicio del manager y logtest.

**Qué demostró**
- **Las 11 reglas validadas contra un manager real** con eventos de eslabon: decoder `json`, regla,
  nivel y MITRE correctos. Detalle en `docs/validacion-wazuh.md`.

**Qué falló y se corrigió**
- El manager rechazó el fichero con un engañoso *"XML syntax error"*. Diagnóstico:
  - el validador oficial de Wazuh, ejecutado localmente, lo daba por válido;
  - un fichero mínimo pasaba;
  - la bisección regla por regla señaló la 100101, que usaba `decoded_as eslabon`, un decoder no
    instalado.

  Se eliminó la vía por syslog. **Ningún test local podía detectar esto**: para eso existía la
  validación en el lab.

**Pendiente**
- Ingesta continua: agente en este Windows. Faltan las redirecciones de VirtualBox para 1514 y 1515.

**Conceptos clave**
- `wazuh-logtest`/`PUT /logtest`: se prueba una regla con un evento sin generar alertas reales.
- Un "error de sintaxis" puede ser en realidad una referencia rota. Diagnosticar por bisección, no
  adivinando.

### F5: cierre (ingesta de punta a punta)
- **Red NAT `SOCLAB`:** se añadieron las redirecciones 1514 y 1515 hacia el manager. Desde el host
  antes solo se llegaba al 8443.
- **Manager:** grupo `eslabon` con `agent.conf` centralizado: `localfile` sobre
  `resultados\eventos.jsonl`, con `log_format json`.
- **Agente oficial 4.14.7 en este Windows:**
  - SHA512 verificado y firma Authenticode válida de *Wazuh, Inc*;
  - lo instaló el usuario como administrador;
  - quedó como `HOST-ESLABON` (002), activo y en el grupo `eslabon`.
- **Escaneos reales con `-f siem --anexar`:** 33 eventos, **30 alertas** en `wazuh-alerts-*` con su
  regla, nivel y MITRE. Los 3 resúmenes son de nivel 2 y no se guardan como alerta (umbral 3).
  Captura: `docs/img/wazuh-discover-eslabon.png`.
- **Pendiente:** escaneo programado y rotación del fichero de eventos.

## F6: Operación continua (2026-09-28)

**Qué se hizo**
- `--rotar-mb` / `--conservar`: rotación del fichero de eventos, al estilo de logrotate (`.1`,
  `.2`…). Si Windows impide el rename, se usa copiar y truncar.
- `scripts/escaneo_programado.ps1` (PowerShell 5.1):
  - lee la lista de `resultados\objetivos.txt`;
  - toma `ESLABON_GUARDDOG` de la variable de usuario;
  - registra cada ejecución en un log UTF-8 sin BOM;
  - se ubica en la raíz del proyecto aunque arranque en System32;
  - sale con el código más grave.
- `ESLABON_GUARDDOG` guardada como variable de usuario, a pedido del usuario.

**Qué demostró**
- **Rotación real sobre el fichero que el agente `HOST-ESLABON` tiene abierto:** funcionó (95 KB →
  `.1`, fichero nuevo de 3,5 KB). El agente de Wazuh permite renombrar mientras lee.
- **El script:** dos objetivos, código 0, 31 eventos nuevos y **GuardDog activo**. Probado también
  arrancando desde `C:\Windows\System32`.
- `pytest`: 188 pasan. `code-review`: 2 hallazgos (el riesgo del rename, comprobado y cubierto con el
  plan B; y el BOM en el log), corregidos.

**Pendiente**
- ~~Registrar la tarea en el Programador de tareas.~~ Hecho con la confirmación del usuario:
  `eslabon\escaneo-diario`, a diario a las 09:00. La prueba con `schtasks /Run` tuvo resultado 0,
  con 2 objetivos, y llegaron 29 alertas a Wazuh: 100140 ×1, 100141 ×10, 100142 ×17 y
  100121 ×1 (event-stream).
- ~~Confirmar en el dashboard las alertas posteriores a la rotación.~~ Hecho: 87 alertas en
  `wazuh-alerts-*` desde la rotación, todas del agente `HOST-ESLABON`, repartidas en tres escaneos:
  - 1 crítica (100140);
  - vulnerabilidades altas y medias (100141/100142);
  - event-stream@3.3.5 como sospechoso medio (100121, T1195.001).

  El agente siguió leyendo el fichero nuevo tras la rotación sin intervención.

## F7: Pendientes (2026-09-28, en curso)

### `--srcroot` para el SARIF

**Qué se hizo**
- Nueva opción `--srcroot <carpeta>`, solo con `-f sarif`. Define la raíz del repositorio a la que
  se refieren las rutas del SARIF (`%SRCROOT%`). Por defecto sigue siendo el directorio actual.

**Por qué**
- GitHub Code Scanning ubica cada alerta en un fichero con una ruta relativa a la raíz del
  repositorio. Si eslabon se ejecuta desde otra carpeta (una tarea programada, un pipeline que
  escanea un subdirectorio), sin esta opción las rutas quedaban relativas a lo escaneado
  (`package-lock.json` en vez de `services/api/package-lock.json`), y GitHub no encontraba el
  fichero.

**Qué demostró**
- Escaneo real del proyecto demo desde fuera del repositorio con `--srcroot` en la raíz del repo:
  28 resultados, con rutas `tests/fixtures/proyecto_demo/{requirements.txt,package-lock.json}`.
- **Error encontrado en la prueba real:** la primera ejecución no aplicaba `--srcroot` cuando el
  SARIF salía por pantalla, solo cuando iba a un fichero (`-o`). La sustitución automática de esa
  línea no se había aplicado, y ningún test cubría la salida por pantalla. Se corrigió y se añadió
  un test que cubre los dos caminos. Se comprobó que ese test falla con el código anterior.
- `pytest`: 193 pasan.

### Revisión manual de valores inseguros por defecto

**Qué se hizo**
- La auditoría `insecure-defaults:audit` volvió a fallar: el entorno rechaza el script del plugin
  por los caracteres de control. Con el acuerdo del usuario, se hizo una revisión manual con las
  seis referencias del plugin como lista de control. Detalle en `docs/revision-insecure-defaults.md`.

**Qué demostró**
- No hay hallazgos de gravedad alta.
- Se corrigieron tres:
  - F1: los artefactos sin versión ya no se omiten en silencio;
  - F4: `--timeout` tiene límites;
  - D1: los errores ya no pueden volcar variables locales.
- **Verificación real de F1:** Syft 1.52 omite él mismo los requisitos sin fijar
  (`flask>=2.0`), y su modo "adivinar" inventa una versión. Queda como límite documentado:
  hay que escanear lockfiles.
- F2, F3, P1, P2 y P3 quedan propuestos. P1 y P3 requieren probarlos antes en el lab o con
  GuardDog.
- `pytest`: 194 pasan.

### Calibración de las señales

**Qué se hizo**
- Corpus de 425 paquetes, medido con los colectores reales y solo metadatos (sin GuardDog, porque
  hay malware en el corpus):
  - 300 versiones legítimas populares;
  - 25 versiones comprometidas confirmadas por OSV;
  - 100 maliciosos de OpenSSF, muestreados con semilla fija y uno por prefijo.
- Scripts en `calibracion/` y resultados en `docs/calibracion.md`.

**Qué demostró**
- **El día cero malicioso no se puede medir hacia atrás.** Todas las versiones comprometidas que se
  sondearon ya no existen ni en deps.dev ni en npm: queda solo el rastro del borrado.
- **"Publicador nuevo" estaba mal definido.** Disparaba en el 9 % de las versiones legítimas de
  npm, por equipos que rotan quién publica. Además, cors 2.8.6 y jsonwebtoken 9.0.3 empataban
  exactamente con el ataque a event-stream (0,5613).
  - Se añadió el filtro de "cuenta conocida": mantenedora en la versión anterior, o publicó alguna
    de las 5 anteriores.
  - Resultado: la señal dispara en el 2 % de los legítimos, "media" en legítimos baja de 4 a 1, y
    event-stream 3.3.5 sigue detectado.
- **No se cambió ningún peso:** con este corpus no hay datos que lo justifiquen. Queda propuesto
  subir `version-retirada` en npm, con un argumento de política y no con una medición.
- **Límite honesto:** cors 2.8.6 (legítimo) sigue empatado con el ataque. Con metadatos son
  indistinguibles.
- Nuevas grabaciones: event-stream 3.3.0 a 3.3.3, sin correos. `pytest`: 197 pasan.
