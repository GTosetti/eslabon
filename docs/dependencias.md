# Auditoría de las propias dependencias de eslabon

Una herramienta de supply chain con dependencias dudosas no es creíble. Esta página registra la
auditoría de las dependencias de eslabon hecha al cierre de F3 (2026-09-26).

## Método

1. Versiones exactas del venv: `.venv\Scripts\python -m pip freeze --exclude-editable`, que da 37
   paquetes (ejecución y desarrollo).
2. **Escaneadas con el propio eslabon**:
   `eslabon scan requirements.txt --guarddog-max 0`, con Syft, OSV, deps.dev y Scorecard. GuardDog se
   desactivó a propósito: todavía no está disponible (falta WSL2).
3. **F4: la skill `supply-chain-risk-auditor` (Trail of Bits) se ejecutó completa**, con
   `api.scorecard.dev` ya autorizada. El informe está en
   [`auditoria-trailofbits.md`](auditoria-trailofbits.md).

   > ⚠️ **Incidente, dicho sin maquillar.** El recolector de esa skill obtiene un token con
   > `gh auth token`. Para cumplir la regla 3 (no usar credenciales del sistema) se quitó `gh` del
   > PATH, pero en el equipo hay una **segunda instalación de gh** que siguió visible. El recolector
   > usó el token de la sesión de gh del usuario para sus consultas de **lectura** a la API de GitHub
   > (repositorios públicos de las dependencias). Se comprobó que el token no quedó escrito en ningún
   > fichero generado, ni en la caché, ni en el repositorio. Se informó al usuario. Para la próxima vez:
   > neutralizar gh con `GH_CONFIG_DIR` apuntando a una carpeta vacía y comprobar `gh auth status` antes
   > de ejecutar herramientas de terceros.

Las dos herramientas, eslabon y la de Trail of Bits, son independientes y **coinciden**: las
dependencias de ejecución están limpias y los hallazgos (`diskcache`, `packaging`) están en las de
desarrollo.

## Resultado

### Dependencias de ejecución

Son las que se instalan con `pip install eslabon`: `typer`, `pydantic`, `rich` y sus dependencias,
`pydantic-core`, `annotated-types`, `typing-extensions`, `typing-inspection`, `markdown-it-py`,
`mdurl`, `pygments`, `shellingham`, `colorama` y `annotated-doc`.

- **Ninguna vulnerabilidad conocida y ningún aviso de paquete malicioso.**
- Señales débiles, que no requieren acción:
  - `annotated-types 0.8.0` (baja): se publicó tras más de un año sin versiones. Coincide con un
    proyecto legítimo que retoma la actividad. Solo sería preocupante si se sumara otra señal.
  - `colorama`, `markdown-it-py`, `mdurl`, `shellingham` (info): Scorecard `Maintained = 0`, sin
    actividad en 90 días. Son librerías pequeñas y estables. Según la metodología, esto es contexto,
    no un hallazgo.

### Dependencias de desarrollo

Se usan solo para los tests: `pytest`, `ruff`, `jsonschema`, `pysigma` y sus dependencias.

- **`diskcache 5.6.3`: CVE-2025-69872** (deserialización insegura con pickle), severidad media, sin
  versión corregida en el momento de la auditoría.
  - **De dónde viene:** es una dependencia indirecta de **pySigma**, que solo se usa en los tests para
    validar las reglas Sigma.
  - **Riesgo práctico: bajo.** Explotarla exige que un atacante pueda escribir en el directorio de
    caché de diskcache en la máquina de desarrollo, y los tests no usan esa caché.
  - **Acción:** vigilarla. Si aparece una versión corregida, fijarla. La alternativa sería validar las
    reglas Sigma sin pySigma, lo que costaría perder el validador oficial.
- Versiones recientes (menos de 14 días): `idna`, `pyparsing`, `pysigma`, `ruff`, `urllib3`. Es lo
  normal en un ecosistema activo, y solo son señales informativas.

## Estado de los pendientes

- ✅ **Lockfile con hashes (F4).** `requirements.txt` y `requirements-dev.txt`, generados con
  pip-tools. Se probó que pip rechaza un lockfile manipulado (ver `docs/instalacion.md`, §4c).
- ✅ **`supply-chain-risk-auditor` completa (F4).** Ver arriba, incluido el incidente del token.
- Pendiente: `diskcache` (CVE-2025-69872) sigue sin versión corregida. Llega a través de pySigma y
  solo en desarrollo.
