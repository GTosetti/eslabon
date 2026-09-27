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
