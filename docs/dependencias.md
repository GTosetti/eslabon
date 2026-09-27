# Auditoría de las propias dependencias de eslabon

Una herramienta de supply chain con dependencias dudosas no es creíble. Esta página registra la
auditoría de las dependencias de eslabon hecha al cierre de F3 (2026-09-26).

## Método

1. Versiones exactas del venv: `.venv\Scripts\python -m pip freeze --exclude-editable`, que da 37
   paquetes (ejecución y desarrollo).
2. **Escaneadas con el propio eslabon**:
   `eslabon scan requirements.txt --guarddog-max 0`, con Syft, OSV, deps.dev y Scorecard. GuardDog se
   desactivó a propósito: todavía no está disponible (falta WSL2).
3. La skill `supply-chain-risk-auditor` (Trail of Bits) **no se ejecutó completa**, por dos motivos:
   - su recolector consulta `api.scorecard.dev`, que no está entre las APIs autorizadas;
   - para autenticarse lee el token de la sesión de `gh` (`gh auth token`), y la regla del proyecto
     prohíbe tomar credenciales del sistema.

   Queda pendiente de la autorización del usuario. Sí se tomó su metodología (qué señales cuentan y
   cuáles no), que está incorporada en eslabon.

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

## Pendientes (dichos sin maquillar)

- **eslabon no publica un lockfile con hashes** de sus propias dependencias. `pyproject.toml` declara
  rangos (`typer>=0.12`), así que cada instalación puede resolver versiones distintas. Lo coherente
  para una herramienta de supply chain es generar un fichero de dependencias fijadas con
  `--require-hashes` (con `pip-tools` o `uv`) y documentar la instalación a partir de él. Requiere
  instalar una herramienta nueva, así que queda propuesto.
- Ejecutar `supply-chain-risk-auditor` completa cuando el usuario autorice `api.scorecard.dev` (y
  decida si quiere usar un token).
