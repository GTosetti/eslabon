# Cómo puntúa eslabon: correlación y confianza

Este documento justifica cada número de `src/eslabon/senales.py` y
`src/eslabon/correlador.py`. **Si cambiás un peso o un umbral en el código, actualizá este
documento.**

## 1. Qué problema resuelve

Cada herramienta de supply chain ve una parte:

| Fuente | Qué ve | Lo que se le escapa |
|---|---|---|
| OSV-Scanner | Avisos ya publicados (CVE, GHSA, MAL…) | Todo lo que todavía nadie reportó |
| deps.dev | La historia del paquete en el registro | El contenido del código |
| GuardDog | Patrones sospechosos en el código y en los metadatos | El contexto: un `urlopen` en `setup.py` puede ser legítimo |
| Scorecard | La higiene del repositorio de origen | Qué se publicó realmente en el registro |

Una señal débil sola es ruido. Por ejemplo, una versión publicada hace 5 días es algo que ocurre
miles de veces por día. Pero **versión nueva + código de red durante la instalación + dominio de
correo del mantenedor re-registrado** es el patrón de una cuenta secuestrada. eslabon junta las
piezas y dice cuánto confía en el resultado y por qué.

## 2. El modelo, en cuatro reglas

### Regla 1: cada señal tiene un peso `p` entre 0 y 1

`p` responde a esta pregunta: *si solo supiera esto, ¿qué probabilidad hay de que el paquete esté
comprometido?* Es una estimación ordinal, no una medición (ver §5, "Límites").

### Regla 2: dentro de una misma fuente, cuenta la señal más fuerte

Dos reglas de GuardDog que disparan sobre el mismo `setup.py` **no son evidencia independiente**:
salen del mismo análisis del mismo fichero. Sumarlas inflaría la confianza por repetición. Por eso
cada fuente aporta un solo número, el `p` de su señal más fuerte.

### Regla 3: entre fuentes distintas, "OR ruidoso"

Fuentes distintas miran cosas distintas: un aviso publicado por un analista, el estado del registro,
el código. Se tratan como evidencia independiente:

```
confianza = 1 − (1 − p₁) · (1 − p₂) · … · (1 − pₙ)
```

Se lee así: *"la probabilidad de que **todas** las fuentes se equivoquen a la vez es el producto de
sus probabilidades de equivocarse; la confianza es lo contrario"*. Tiene tres propiedades que
buscamos:
- **Nunca baja al agregar evidencia**, y nunca pasa de 1.
- **Señales débiles que coinciden suben mucho**: tres fuentes con 0,3 cada una dan
  1 − 0,7³ = 0,66, más que el doble de cualquiera sola.
- **Es explicable**: la fórmula con los números reales va dentro de cada hallazgo.

Es el modelo *noisy-OR* clásico de las redes bayesianas (Pearl, 1988). Se eligió por ser simple y
auditable, frente a un modelo entrenado que nadie podría explicar en una alerta de SOC.

### Regla 4: la severidad depende del tipo

| Tipo | Severidad |
|---|---|
| `malicioso` | Siempre **crítica**. Un paquete malicioso confirmado ejecuta código del atacante con los permisos de quien lo instala. |
| `vuln` | La del CVSS del aviso, con las bandas oficiales de FIRST: 0,1–3,9 baja, 4–6,9 media, 7–8,9 alta, 9–10 crítica. Sin CVSS se asume **media** y se dice en la explicación. |
| `sospechoso` / `riesgo_origen` | Por bandas de confianza (tabla siguiente). |

| Confianza | Severidad | Por qué ahí |
|---|---|---|
| ≥ 0,80 | alta | Hace falta la señal fuerte de una fuente más la corroboración de otra. Ninguna heurística del catálogo llega sola a 0,80. |
| ≥ 0,50 | media | Una heurística de amenaza fuerte (GuardDog "alta", 0,60), o dos débiles de fuentes distintas. |
| ≥ 0,25 | baja | Una señal débil concreta: hay algo que mirar, pero no merece despertar a nadie. |
| < 0,25 | info | Contexto: versión reciente sola, paquete obsoleto, capacidades de red. |

## 3. Cómo se agrupan los hallazgos (deduplicación)

Todo esto ocurre por separado para cada paquete@versión, con el nombre normalizado (PEP 503 en PyPI):

1. **Por alias.** Dos hallazgos que comparten cualquier ID (CVE, GHSA, PYSEC, MAL…) se unen. La
   unión es transitiva: si A comparte un ID con B, y B otro con C, los tres son uno.
2. **Si algo es malicioso, todo lo que apunte a compromiso se funde en uno.** Caso real:
   `flatmap-stream@0.1.1` tiene `MAL-2025-20690`, `GHSA-9x64-5r7x-2q53` y `GHSA-mh6f-8j2x-4483`, y
   OSV **no los enlaza como alias**. Sin esta regla serían tres "paquetes maliciosos". Con ella, es
   uno solo con tres IDs.
3. **Las señales débiles de un paquete se funden en un hallazgo**, para que se refuercen entre sí
   (regla 3).
4. **Las vulnerabilidades no se mezclan con las señales de compromiso**: son problemas distintos, con
   remediaciones distintas.

## 4. Catálogo de señales y justificación de cada peso

La escala sigue la metodología de Trail of Bits (`supply-chain-risk-auditor`): tienen más peso las
señales que describen un **mecanismo concreto** y casi ninguno las que solo miden **higiene**. Un dato
que no se pudo obtener **no es evidencia de riesgo** y no genera señal: por ejemplo, un check de
Scorecard con −1 o un paquete sin repositorio declarado.

### OSV (avisos publicados)

| Señal | p | Justificación |
|---|---|---|
| `osv-mal` | 0,95 | Aviso de OpenSSF Malicious Packages: un analista confirmó el malware. No es 1,0 porque existen avisos retirados por falso positivo. |
| `osv-cwe-506` | 0,90 | GitHub clasifica el aviso como *Embedded Malicious Code*. Revisado por humanos, pero la CWE a veces marca un componente comprometido y no todo el paquete. |
| `osv-texto-malicioso` | 0,80 | El resumen (o la primera oración del detalle) dice "malicious code/package/project", "malware", "backdoor" o "taken over". Es texto libre, por eso pesa menos. **No** se busca "malicious" suelto, porque muchas CVE dicen "a malicious user can…", y eso describe al atacante, no al paquete. Comprobado: 0 falsos positivos sobre las 52 CVE del proyecto demo. |
| `osv-vuln` | 0,90 | La versión está dentro del rango afectado publicado: la coincidencia es exacta. No es 1,0 porque no sabemos si el código vulnerable se usa. |

### deps.dev (estado en el registro)

| Señal | p | Justificación |
|---|---|---|
| `depsdev-tapon-seguridad` | 0,90 | npm reemplaza los paquetes maliciosos por `0.0.1-security`. Es una acción deliberada del equipo de seguridad del registro, independiente de OSV. |
| `depsdev-version-retirada` | 0,40 | La versión ya no está pero el paquete sí. Los registros retiran versiones maliciosas, pero los autores también despublican por errores. |
| `depsdev-paquete-inexistente` | 0,30 | El paquete no existe en el registro público. Puede haber sido retirado (PyPI borra el malware entero, como con `ctx`) **o** ser privado, lo que abre la puerta a *dependency confusion*. Las dos lecturas son relevantes y ninguna es concluyente. |
| `depsdev-version-reciente` | 0,20 | Publicada hace menos de **14 días**. Casi todas las versiones maliciosas se detectan y retiran en días, y por eso la práctica de "cooldown" (p. ej. `minimumReleaseAge` de Renovate) espera entre 3 y 14 días. Ocurre muchísimo en paquetes sanos: sola es info. |
| `depsdev-reactivacion` | 0,25 | Nueva versión tras **más de 365 días** sin publicar. Es el patrón de toma de cuenta: un paquete dormido "revive" con otro autor (event-stream, ctx). También lo hacen proyectos legítimos que vuelven a la actividad. |
| `depsdev-obsoleto` | 0,10 | *Deprecated*. Es un riesgo de mantenimiento, no de compromiso. Contexto. |

**Decisión consciente:** deps.dev también lista avisos (`advisoryKeys`), pero los toma de la misma
base que OSV. Usarlos como "segunda fuente" contaría el mismo dato dos veces, así que no se usan.

### OpenSSF Scorecard (repositorio de origen, T1195.002)

Nunca se usa el **puntaje global**. Se correlaciona con el tamaño del proyecto, no con el riesgo de
compromiso: en la medición de Trail of Bits, `lodash` saca 7,2 con un solo publicador, y `p-limit`,
3,8. Solo marcan riesgo los checks que describen un mecanismo:

| Check | Marca si | p | Justificación |
|---|---|---|---|
| Dangerous-Workflow | < 10 | 0,30 | Un workflow de CI con inyección de scripts o checkout no confiable es una vía documentada de compromiso antes de publicar (p. ej. `pull_request_target`). |
| Binary-Artifacts | < 10 | 0,20 | Hay binarios versionados que nadie puede revisar. |
| Maintained | = 0 | 0,10 | Sin actividad en los últimos 90 días. Solo contexto: muchas librerías "terminadas" están sanas. |
| Code-Review, Token-Permissions y el resto | — | — | No marcan: miden la madurez del CI, que depende del tamaño del proyecto (metodología ToB). |

Origen de los datos: el CLI `scorecard` si hay `GITHUB_TOKEN` en el entorno; si no, el análisis
semanal publicado en deps.dev (se indica en `datos.origen` de la evidencia).

### GuardDog (código y metadatos del paquete)

| Señal | p | Justificación |
|---|---|---|
| Veredicto `high_risk` / `suspicious` / `low` | 0,70 / 0,50 / 0,20 | Son las bandas del propio `risk_score` de GuardDog (≥7, ≥5, <5 sobre 10), llevadas a probabilidad. Como es la misma fuente que sus reglas, se aplica la regla 2 y cuenta el máximo, no la suma. |
| Regla de amenaza (`threat-*`) de severidad alta / media / baja | 0,60 / 0,40 / 0,20 | La severidad la declara cada regla YARA de GuardDog. Por ejemplo, `threat-setup-network-in-install` (red durante la instalación) es alta. |
| Regla de capacidad (`capability-*`) | 0,05 | "Puede hacer conexiones de red" describe a muchísimos paquetes sanos (cualquier cliente HTTP). Solo contexto. |
| `potentially_compromised_email_domain`, `unclaimed_maintainer_email_domain` | 0,40 | Un dominio de correo vencido permite re-registrarlo y recuperar la cuenta del mantenedor. Es un mecanismo real de toma de cuenta. |
| `provenance_regression` | 0,40 | La versión perdió la atestación de procedencia que tenían las anteriores: es típico de una publicación hecha fuera del CI legítimo. |
| `typosquatting` | 0,35 | Nombre casi igual al de un paquete popular. Hay muchos homónimos legítimos. |
| `metadata_mismatch`, `repository_integrity_mismatch`, `risky_new_dependency` | 0,30 | Discrepancias entre lo publicado y el origen declarado. |
| `deceptive_author` | 0,25 | Correo desechable. Débil. |
| `bundled_binary`, `direct_url_dependency` | 0,20 | Prácticas poco auditables, frecuentes en paquetes sanos. |

Las capacidades solas **no generan hallazgo**: en las grabaciones reales de GuardDog sobre `requests`
y `lodash` (paquetes sanos) aparecían varias. Solo acompañan a una señal de verdad.

### Registro de npm (quién publicó y qué se ejecuta al instalar)

| Señal | p | Justificación |
|---|---|---|
| `npm-publicador-nuevo` | 0,35 | La versión la publicó una **cuenta** distinta de la que publicó la anterior. Es el mecanismo de las tomas de control por cesión o robo de cuenta (event-stream 3.3.5: `dominictarr` → `right9ctrl`). No es más alta porque los equipos rotan quién publica. Se compara la cuenta, no el correo: cambiar de correo no es cambiar de dueño (lodash cambió de correo con la misma cuenta). |
| `npm-script-instalacion-red` | 0,35 | Un `preinstall`/`install`/`postinstall` que descarga o ejecuta código (`curl`, `wget`, una URL, `node -e`, `eval`, base64…). Ese script corre con los permisos de quien instala, antes de que nadie revise nada. |
| `npm-script-instalacion` | 0,05 | Un script de instalación "normal" (p. ej. `node-gyp rebuild` para compilar código nativo). Solo contexto: **no genera hallazgo** por sí solo. |

La "versión anterior" se calcula con las fechas de publicación de deps.dev, sin contar los tapones
`-security`.

## 5. Ejemplos calculados

**A. Paquete malicioso conocido (caso real, test de la condición de salida de F2)**
`flatmap-stream@0.1.1`: osv aporta 0,95 (MAL-) y deps.dev 0,90 (tapón de npm).
`1 − (1 − 0,95)·(1 − 0,90) = 0,995` → malicioso, crítica. Es **un** hallazgo con 2 fuentes y 3 IDs.

**B. El patrón de "cuenta secuestrada" (test `test_senales_debiles_de_fuentes_distintas_se_refuerzan`)**

| Señal | Fuente | p | Sola daría |
|---|---|---|---|
| Versión de hace 5 días | deps.dev | 0,20 | info |
| Red durante la instalación | GuardDog | 0,60 | media |
| Workflow peligroso en el repo | Scorecard | 0,30 | baja |

Juntas: `1 − 0,8 · 0,4 · 0,7 = 0,776` → **media**, con T1195.001 y T1195.002. Si además el
registro de npm mostrara un publicador nuevo (p = 0,35, una cuarta fuente), subiría a
`1 − 0,8 · 0,4 · 0,7 · 0,65 = 0,85` → **alta**.

**C. Caso real sin ningún aviso: `event-stream@3.3.5`** (test
`test_event_stream_335_sin_avisos_lo_delata_la_correlacion`, y verificado en vivo)

Es la primera versión que publicó el atacante, antes de añadir `flatmap-stream` en 3.3.6. **No tiene
CVE, GHSA ni MAL-**: ningún escáner de avisos la marca.

| Señal | Fuente | p | Dato real |
|---|---|---|---|
| Reactivación tras más de un año | deps.dev | 0,25 | 3.3.4 salió el 2016-07-17; 3.3.5, 779 días después |
| Publicador nuevo | npm | 0,35 | 3.3.4: `dominictarr`; 3.3.5: `right9ctrl` |
| Repositorio sin mantenimiento | Scorecard | 0,10 | `Maintained = 0/10` (repositorio archivado) |

`1 − 0,75 · 0,65 · 0,90 = 0,561` → **sospechoso, media**, con T1195.001 y T1195.002. Cada señal sola
daría baja o info. Esta es la tesis de eslabon en un caso real.

**D. El patrón exacto del encargo** (versión reciente + script de instalación con red + mantenedor
nuevo): las dos señales de npm salen de la **misma** fuente, así que cuenta solo la más fuerte (0,35).
Con deps.dev (0,20) y GuardDog (0,60): `1 − 0,65 · 0,8 · 0,4 = 0,792` → **media**, justo por debajo de
alta. Es la regla 2 siendo conservadora a propósito: si se quisiera que ese patrón fuese "alta",
lo honesto es calibrar los pesos con datos (ver §6), no subirlos a mano.

## 6. Límites (dichos sin maquillar)

- **Los pesos son estimaciones ordinales, no probabilidades medidas.** Ordenan bien (MAL- > CWE-506 >
  texto > heurística fuerte > heurística débil > higiene), pero los valores exactos no se calibraron
  contra un corpus. La forma de calibrarlos: correr eslabon sobre (a) los paquetes de OpenSSF Malicious
  Packages y (b) los top-N de cada registro, y ajustar cada `p` a la tasa de acierto observada de su
  señal.
- **El supuesto de independencia entre fuentes es aproximado.** Por ejemplo, GuardDog y Scorecard
  pueden estar correlacionados en paquetes abandonados. La regla 2 mitiga la dependencia dentro de una
  misma fuente, no entre fuentes.
- **Solapamiento entre npm y GuardDog.** El script de instalación lo ven las dos fuentes: el registro
  de npm (el texto del script) y GuardDog (sus reglas `threat-npm-preinstall-script` y
  `threat-process-hooks`, que leen el mismo `package.json`). Ahí la independencia de la regla 3 es
  optimista. Mitigación: pesos moderados en las dos (0,35 y la severidad de la regla).
- **"Publicador nuevo" solo existe para npm.** PyPI no publica quién subió cada versión en su API
  pública, así que para PyPI esta señal no es evaluable (y eso no es evidencia de riesgo).
- **GuardDog es caro:** descarga y analiza cada paquete. Por defecto analiza los primeros 20 del
  inventario (`--guarddog-max`), y si omite paquetes lo dice en `fuentes_omitidas`.
