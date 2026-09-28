# Calibración de las señales (F7)

**Pregunta.** ¿Cuánto acierta y cuánto se equivoca cada señal de eslabon con paquetes reales?

**Respuesta corta.**
- Sobre 300 versiones legítimas y populares, las heurísticas dan **1 alerta "media"** (0,3 %) y
  ninguna alta.
- Los paquetes maliciosos, una vez que existe su aviso, salen **todos** como críticos.
- La calibración encontró y corrigió un problema de *definición*: "publicador nuevo" disparaba con
  equipos legítimos que rotan quién publica. **No se cambió ningún peso.** Con este corpus no hay
  datos que justifiquen un número distinto, y cambiar pesos a ojo no es calibrar.

## 1. Método

**Corpus** (`calibracion/corpus.json`, generado por `calibracion/corpus.py`). Tiene tres grupos:

| Grupo | Qué es | Cómo se eligió | n |
|---|---|---|---|
| `legitimo` | Paquetes populares y sanos | 50 de npm y 50 de PyPI muy usados; sus 3 últimas versiones estables (deps.dev) | 300 |
| `comprometido` | Versiones que un atacante publicó en un paquete legítimo (cuenta o token robados, sabotaje) | Incidentes públicos (event-stream, ua-parser-js, coa, rc, chalk/debug 2025, nx, xrpl, num2words...). **Solo se conservan las que OSV confirma** para esa versión exacta. Se añade el caso vivo `event-stream@3.3.5`, que sigue publicado y no tiene aviso. | 25 |
| `malicioso` | Paquetes creados para atacar (typosquatting, dependency confusion...) | Muestra aleatoria con semilla fija de [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages), como máximo **uno por prefijo** de nombre (si no, una sola campaña de cientos de clones dominaba la muestra) | 100 |

**Medición** (`calibracion/medir.py` → `calibracion/medicion.json`):
- Se ejecutan los colectores reales, con las APIs autorizadas: OSV, deps.dev, npm y Scorecard vía
  deps.dev.
- **Sin GuardDog:** GuardDog descarga el código del paquete, y en el corpus hay malware. Regla del
  proyecto: con maliciosos, solo metadatos.
- Cada paquete se evalúa de dos formas: **con OSV** (lo que ve hoy un usuario) y **sin OSV** (lo
  que verían las heurísticas antes de que exista el aviso).

**Resumen** (`calibracion/resumir.py`): produce las tablas de la sección 3.

## 2. Primer hallazgo: el lado malicioso del día cero no se puede medir hacia atrás

Se sondearon event-stream 3.3.6, chalk 5.6.1, debug 4.4.2, ua-parser-js 0.7.29, eslint-scope 3.7.2,
nx 21.5.0, ultralytics 8.3.41 y num2words 0.5.15. **Ninguna existe ya en deps.dev ni en npm:** los
registros borran las versiones comprometidas al descubrirlas. Las señales del día cero (quién
publicó, scripts de instalación, reactivación) **no se pueden reconstruir** con estas fuentes.

Solo queda el rastro del borrado: "versión retirada", "tapón -security" y "paquete inexistente".
Por eso la columna "sin OSV" de los grupos maliciosos mide **lo que eslabon ve cuando el registro
ya actuó pero el aviso todavía no existe**, no el día cero real.

La única excepción del corpus es `event-stream@3.3.5`, que sigue publicado.

## 3. Resultados

### Severidad del peor hallazgo de compromiso, SIN OSV

| Grupo | n | ninguno | info | baja | media | alta | crítica |
|---|---|---|---|---|---|---|---|
| legítimo npm | 150 | 76 (51 %) | 52 (35 %) | 21 (14 %) | 1 (1 %) | 0 | 0 |
| legítimo PyPI | 150 | 83 (55 %) | 54 (36 %) | 13 (9 %) | 0 | 0 | 0 |
| comprometido npm | 24 | 0 | 0 | 21 (88 %) | 3 (12 %) | 0 | 0 |
| comprometido PyPI | 1 | 0 | 0 | 1 (100 %) | 0 | 0 | 0 |
| malicioso npm | 50 | 2 (4 %) | 0 | 24 (48 %) | 0 | 0 | 24 (48 %) |
| malicioso PyPI | 50 | 0 | 0 | 50 (100 %) | 0 | 0 | 0 |

### Severidad del peor hallazgo de compromiso, CON OSV

| Grupo | n | ninguno | info | baja | media | alta | crítica |
|---|---|---|---|---|---|---|---|
| legítimo npm | 150 | 76 (51 %) | 52 (35 %) | 21 (14 %) | 1 (1 %) | 0 | 0 |
| legítimo PyPI | 150 | 83 (55 %) | 54 (36 %) | 13 (9 %) | 0 | 0 | 0 |
| comprometido npm | 24 | 0 | 0 | 0 | 1 (4 %) | 0 | 23 (96 %) |
| comprometido PyPI | 1 | 0 | 0 | 0 | 0 | 0 | 1 (100 %) |
| malicioso npm / PyPI | 100 | 0 | 0 | 0 | 0 | 0 | 100 (100 %) |

El único comprometido que no sale crítico con OSV es `event-stream@3.3.5`. No tiene aviso, así que
lo detectan solo las heurísticas: sale como sospechoso, severidad media, con confianza 0,56.

### Con qué frecuencia dispara cada señal

| Señal | peso | legítimo npm | legítimo PyPI | comprometido npm | malicioso npm | malicioso PyPI |
|---|---|---|---|---|---|---|
| `depsdev-version-reciente` | 0,20 | 14 % | 17 % | 0 % | 0 % | 0 % |
| `depsdev-reactivacion` | 0,25 | 9 % | 7 % | 4 % | 0 % | 0 % |
| `npm-publicador-nuevo` (antes del filtro) | 0,35 | **9 %** | — | 4 % | 0 % | — |
| `npm-publicador-nuevo` (con el filtro) | 0,35 | **2 %** | — | 4 % | 0 % | — |
| `depsdev-obsoleto` | 0,10 | 3 % | 0 % | 0 % | 0 % | 0 % |
| `scorecard-sin-mantenimiento` | 0,10 | 24 % | 14 % | 38 % | 4 % | 0 % |
| `scorecard-binary-artifacts` | 0,20 | 6 % | 11 % | 8 % | 0 % | 0 % |
| `scorecard-dangerous-workflow` | 0,30 | 2 % | 0 % | 0 % | 0 % | 0 % |
| `depsdev-version-retirada` | 0,40 | 0 %\* | 0 %\* | 96 % | 8 % | 2 % |
| `depsdev-tapon-seguridad` | 0,90 | 0 % | 0 % | 0 % | 48 % | 0 % |
| `depsdev-paquete-inexistente` | 0,30 | 0 %\* | 0 %\* | 0 % | 40 % | 98 % |

\* Es 0 % por construcción: el grupo legítimo se eligió entre versiones que existen. Esta medición no
dice nada sobre su tasa real de falsas alarmas (ver la sección 5).

## 4. Qué se cambió y por qué

**"Publicador nuevo" ahora exige una cuenta desconocida en el paquete.**

Antes disparaba en 14 de 150 versiones legítimas de npm (9 %), casi siempre por equipos que rotan
quién publica:
- express 4.22.1 la publicó `jonchurch`, que ya era mantenedor;
- yargs 17.7.3 la publicó `shadowspawn`, que ya había publicado yargs;
- lodash, async y jsonwebtoken, por lo mismo.

Además, **cuatro versiones legítimas empataban con el ataque real**. lodash 4.17.23, async 3.2.5,
cors 2.8.6 y jsonwebtoken 9.0.3 daban la misma severidad que `event-stream@3.3.5`, y las dos últimas
exactamente la misma confianza: 0,5613, con las mismas tres señales.

Hipótesis probada con los datos: en un traspaso legítimo, la cuenta **ya era de la casa**. Es decir,
figuraba como mantenedora en la versión anterior o había publicado alguna de las anteriores.

| Criterio | Legítimos npm que disparan | event-stream 3.3.5 |
|---|---|---|
| Cuenta distinta de la anterior (antes) | 14 (9 %) | dispara |
| ... y no era mantenedora en la versión anterior | 5 | dispara |
| ... ni publicó ninguna de las 5 anteriores (**ahora**) | **3 (2 %)** | **dispara** |

Efecto en la severidad final de los legítimos de npm: "media" pasa de 4 a **1**, y "baja", de 26 a 21.

Implementación: `colectores/npm.py` (`_cuenta_conocida`) y
`ClienteDepsDev.versiones_anteriores`. Se piden 5 documentos de versión, de pocos KB cada uno, en
lugar del documento completo del paquete, que en typescript supera los 20 MB. Tests:
`test_mantenedora_de_la_version_anterior_no_es_publicador_nuevo`,
`test_quien_ya_publico_una_version_previa_no_es_publicador_nuevo` y
`test_cuenta_desconocida_si_es_publicador_nuevo`.

## 5. Límites (lo que esta calibración NO demuestra)

- **Hay un empate que ningún metadato separa.** `cors@2.8.6` es legítimo: una persona nueva del
  equipo de Express publicó tras años de inactividad. Tiene las mismas señales y la misma confianza
  (0,5613) que el ataque a event-stream. Con metadatos del registro son indistinguibles. Separarlos
  requeriría mirar el código (GuardDog) o la reputación de la cuenta (fuera del alcance).
- **No hay tasa de acierto del día cero para el lado malicioso** (sección 2). Los pesos de
  `publicador-nuevo`, `reactivacion` y los scripts de instalación siguen siendo estimaciones sobre
  un único caso vivo.
- **`version-retirada` en npm: medida después (F9); el peso se mantiene en 0,40.** Detectó el 96 %
  de los comprometidos, pero el corpus legítimo no podía medir su tasa de falsos positivos (ver la
  sección 3, \*). `calibracion/retiradas_npm.py` lo midió con el campo `time` de npm, que conserva
  todas las versiones publicadas alguna vez:
  - **128 de 22 813 versiones (0,56 %)** de los 50 paquetes legítimos desaparecieron;
  - 26 de 50 paquetes tienen alguna, casi todas antiguas o pre-versiones (`1.0.0beta` de express,
    `0.0.x` de pg), anteriores a la política de 2016 que prohíbe despublicar después de 72 h.

  La señal **discrimina muy bien**: la razón de verosimilitud es de unas 170 veces (96 % frente a
  0,56 %). Pero las versiones comprometidas son rarísimas entre las que hay en un lockfile. Con esa
  tasa base, una sola señal no alcanza para "media": el 0,40 ("baja": algo que hay que mirar) es
  coherente con el dato. No se sube; queda medido y justificado. En PyPI no se midió: su API no
  conserva las versiones borradas.
- **2 de 50 maliciosos de npm no dan ninguna señal sin OSV:** `bx-ui-view` y
  `framerate-interaction-permissions` siguen publicados y sin tapón. Contra un paquete malicioso
  todavía activo y sin aviso, eslabon depende de GuardDog, que aquí no se ejecutó.
- **Sesgos del corpus:**
  - los legítimos son muy populares (mejor mantenidos que la dependencia media);
  - hay un solo comprometido en PyPI (OSV no confirma `ultralytics@8.3.41` ni `ctx@0.2.2` como
    malware para esa versión);
  - GitHub trunca el listado de npm de OpenSSF en 100 000 entradas.
- **Todo se evalúa hoy**, no el día en que salió cada versión: "versión reciente" y el estado del
  registro son los de la fecha de la medición (2026-09-28).

## 6. Cómo reproducirlo

```powershell
.venv\Scripts\python calibracion\corpus.py    # regenera corpus.json (red: deps.dev, OSV, GitHub)
.venv\Scripts\python calibracion\medir.py     # mide (necesita osv-scanner en el PATH)
.venv\Scripts\python calibracion\resumir.py   # imprime las tablas
```

Nunca se instala ni se descarga el código de ningún paquete: solo metadatos.

**Próximo paso propuesto: un corpus prospectivo.**
- El escaneo programado podría archivar los metadatos de cada versión en el momento en que se ve,
  antes de que el registro la borre.
- Con el tiempo, eso da la tasa de acierto del día cero que hoy no se puede medir.
