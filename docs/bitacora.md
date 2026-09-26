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
