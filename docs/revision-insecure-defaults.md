# Revisión manual de valores inseguros por defecto (sustituye a `insecure-defaults:audit`)

**Qué es.** Es una revisión manual, de solo lectura, que usa como lista de control las seis
referencias del plugin `insecure-defaults` de Trail of Bits (versión 2.0.1). Esas referencias
cubren seis categorías:
- *fail-open*;
- secretos con valor de respaldo;
- credenciales por defecto;
- criptografía débil;
- permisos amplios;
- funciones de depuración.

**No es la auditoría oficial.** Su pipeline no pudo ejecutarse, dos veces (F4 y F7). El entorno
rechaza el script del plugin porque contiene caracteres de control, que quedarían ocultos en el
diálogo de aprobación. No se editó el plugin ni se evitó esa protección.

Alcance: `src/eslabon`, `scripts/*.ps1`, `integrations/`, `pyproject.toml` y `.gitignore`.
Resultado: **no hay hallazgos de gravedad alta.**

## Hallazgos

| ID | Gravedad | Dónde | Qué pasa | Estado |
|---|---|---|---|---|
| F1 | media | `sbom.py` | Un artefacto de Syft sin versión se omitía **en silencio**: el escaneo parecía completo sin haberlo analizado. | ✅ Corregido: se informa como `syft parcial: N dependencias sin versión fijada`. Test `test_inventario_informa_dependencias_sin_version`. |
| F1b | media | Syft (herramienta externa) | Comprobado en vivo con Syft 1.52: un `requirements.txt` con `flask>=2.0` y `requests==2.19.0` da **solo** `requests`. Syft omite los requisitos sin fijar, así que eslabon no se entera. Su opción `SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS` los emite con una versión **inventada** (el límite inferior, `2.0`), que es peor. | ⚠️ Límite documentado. Recomendación: escanear lockfiles (`pip-compile --generate-hashes`, `package-lock.json`). Un `package.json` sin lockfile da un inventario vacío, y eso ya sale con código 3. |
| F2 | media (diseño) | `escaneo.py` | Solo OSV es esencial. Si falla GuardDog (por ejemplo, con Docker cerrado), el escaneo sale con 0 y un aviso de fuente omitida (Wazuh 100150, nivel 4). Un paquete malicioso nuevo, que todavía no tiene aviso, solo lo vería GuardDog. | ✅ Corregido: `--requerir <fuente>` (repetible). Si una fuente requerida falla, el análisis queda incompleto (código 3, `completo: false`). Nueva regla Wazuh **100161** (nivel 6) para el resumen de un escaneo incompleto. Probado en vivo con GuardDog no disponible: código 0 sin la opción, código 3 con ella. |
| F3 | baja | `escaneo_programado.ps1` | Si falta `eslabon.exe` o la lista de objetivos, el error queda solo en el log del script. El SIEM ve **silencio**, no una alerta. | ✅ Corregido: el script escribe `error_programado` (en ASCII, sin BOM), con la regla **100170** (nivel 7). Probado con una lista inexistente y con un objetivo inválido (código 2), sobre un fichero de eventos temporal. |
| F4 | baja | `cli.py` | `--timeout` no tenía límites (`0`, negativos, `inf`). | ✅ Corregido: de 1 a 3600 s. |
| P1 | baja | `eslabon_rules.xml` (100100) | La regla base acepta cualquier JSON con `eslabon.evento`, venga de cualquier fichero o agente. Si otra fuente JSON controlada por un atacante llega al manager, bastan unos pocos campos para generar una alerta falsa de nivel 14. | Propuesto: limitar la 100100 con `<location>` o por grupo. Hay que **validarlo en el manager del lab** antes de cambiarlo (F8). |
| P2 | baja | `integrations/wazuh/README.md` | El ejemplo usa `C:\eslabon\`. Una carpeta en la raíz de `C:` hereda permisos de modificación para "Usuarios autenticados": cualquier usuario local podría inyectar o borrar eventos. El despliegue real, dentro del perfil del usuario, no tiene ese problema. | ✅ Corregido en el README: carpeta dentro del perfil, y el porqué. |
| P3 | baja | `ESLABON_GUARDDOG` | El `docker run` de GuardDog corre como root dentro del contenedor, sin límites de memoria ni de procesos. Descomprime paquetes potencialmente hostiles (bombas de descompresión). | Probado: con `--cap-drop=ALL --security-opt no-new-privileges --memory 1g --pids-limit 256`, GuardDog da **el mismo resultado** sobre `requests` (61 reglas, 0 errores). `--read-only` lo rompe, porque GuardDog escribe su lista de paquetes populares dentro del contenedor, así que se descarta. Cambiar la variable del usuario requiere su confirmación. |
| D1 | info | `cli.py` | `pretty_exceptions_show_locals` dependía del valor por defecto de la versión de typer. Con `True`, un error inesperado imprimiría las variables locales. | ✅ Corregido: `False` explícito. |

## Lo que parece riesgoso pero está bien

**Fail-open**
- `--permitir-degradado` viene desactivado.
- `--fallar-en` vale `alta` por defecto, y un paquete malicioso siempre es crítico.
- Una salida vacía de OSV, o GuardDog con `errors` y sin `results`, cuentan como fallo.
- El SARIF pone `executionSuccessful = completo`.

**Secretos**
- `GITHUB_TOKEN` llega solo a Scorecard, por el entorno y nunca como argumento.
- Los errores pasan por `redactar()`.
- `_SENSIBLE` es una lista negra que no reconoce nombres como `DATABASE_URL`. Esas variables pueden
  llegar a Syft y a OSV, que son herramientas locales, pero no al contenedor.

**Criptografía**
- SHA-256 truncado se usa como huella de deduplicación, y `uuid4` para nombres. Ninguno cumple una
  función de seguridad.
- TLS usa el contexto por defecto de urllib, que verifica el certificado y el nombre del host.

**`-ExecutionPolicy Bypass` en la tarea programada**
- La política de ejecución no es una barrera de seguridad.
- La tarea corre como el usuario, sin privilegios elevados, y solo ese mismo usuario puede editar
  el script.
- Sería grave **solo** si se registrara como SYSTEM con el script en una carpeta que el usuario
  puede escribir. No se debe hacer.

**Caché y redirecciones**
- La caché vive en memoria durante un solo escaneo, y sus claves salen de nombres ya validados.
- Las redirecciones se aceptan solo si siguen en https y al mismo host.

**Inyección en las salidas**
- La tabla quita los caracteres de control y bidi.
- El SIEM sale en ASCII, con un evento por línea.
- El SARIF rechaza rutas con `..` o con letra de unidad.
