# Instalación de las herramientas (F0)

Estado al cierre de F0 (2026-09-26), en Windows 11 x64 con PowerShell 5.1.

| Herramienta | Versión | Estado | Ubicación |
|---|---|---|---|
| Python | 3.12.10 | ✅ ya estaba | `C:\Users\user1\AppData\Local\Programs\Python\Python312` |
| git | 2.53.0 | ✅ ya estaba | Git for Windows |
| gh (GitHub CLI) | — | ✅ ya estaba | `C:\Program Files\GitHub CLI` |
| Go / Docker / WSL | — | ❌ no instalados | — |
| **Syft** | 1.52.0 | ✅ instalado, SHA256 verificado | `%LOCALAPPDATA%\Programs\syft\syft.exe` |
| **OSV-Scanner** | 2.6.0 | ✅ instalado, SHA256 verificado | `%LOCALAPPDATA%\Programs\osv-scanner\osv-scanner.exe` |
| venv del proyecto | Python 3.12.10, pip 26.2.1 | ✅ creado | `eslabon\.venv` |
| **GuardDog** | 3.2.0 | ❌ **no instalable en Windows nativo** (ver abajo) | — |

Las dos rutas de instalación se agregaron solo al **PATH de usuario**, no al del sistema. Para que
`syft` y `osv-scanner` funcionen sin la ruta completa hay que **abrir una terminal nueva**.

---

## 1. Syft (genera el SBOM)

Origen: release oficial `v1.52.0` de <https://github.com/anchore/syft>.

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$work = "$env:TEMP\eslabon-f0"
New-Item -ItemType Directory -Force -Path $work | Out-Null

# 1) Descargar el binario y el fichero de checksums DE LA MISMA release
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_windows_amd64.zip' -OutFile "$work\syft.zip"
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_checksums.txt' -OutFile "$work\syft_checksums.txt"

# 2) Comparar el hash calculado con el publicado
$computed = (Get-FileHash -Algorithm SHA256 "$work\syft.zip").Hash.ToLower()
$line = Get-Content "$work\syft_checksums.txt" | Where-Object { $_ -match 'syft_1\.52\.0_windows_amd64\.zip$' }
$expected = ($line -split '\s+')[0]
if ($computed -ne $expected) { Write-Error 'SHA256 NO COINCIDE: no instalar' } else { 'SHA256 OK' }

# 3) Instalar (solo si dio OK)
$dest = "$env:LOCALAPPDATA\Programs\syft"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Expand-Archive -Path "$work\syft.zip" -DestinationPath $dest -Force

# 4) Agregar al PATH de usuario (si no estaba)
$p = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($p -split ';') -notcontains $dest) { [Environment]::SetEnvironmentVariable('Path', $p.TrimEnd(';') + ';' + $dest, 'User') }

# 5) Comprobar
& "$dest\syft.exe" version
```

- SHA256 esperado (publicado) y calculado:
  `de787a374cf961c56fd7b206b2e183295abba32d0af3cb44d9aef2357ca9eda2` ✅
- Resultado: `Version: 1.52.0`, `Platform: windows/amd64`.

## 2. OSV-Scanner (CVEs y paquetes maliciosos conocidos)

Origen: release oficial `v2.6.0` de <https://github.com/google/osv-scanner>. En este caso el
asset es directamente un `.exe`, no un zip.

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$work = "$env:TEMP\eslabon-f0"
New-Item -ItemType Directory -Force -Path $work | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_windows_amd64.exe' -OutFile "$work\osv-scanner_windows_amd64.exe"
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_SHA256SUMS' -OutFile "$work\osv-scanner_SHA256SUMS"

$expected = ((Get-Content "$work\osv-scanner_SHA256SUMS" | Where-Object { $_ -match 'osv-scanner_windows_amd64\.exe$' }) -split '\s+')[0]
$computed = (Get-FileHash -Algorithm SHA256 "$work\osv-scanner_windows_amd64.exe").Hash.ToLower()
if ($computed -ne $expected) { Write-Error 'SHA256 NO COINCIDE: no instalar' } else { 'SHA256 OK' }

$dest = "$env:LOCALAPPDATA\Programs\osv-scanner"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Force "$work\osv-scanner_windows_amd64.exe" "$dest\osv-scanner.exe"

$p = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($p -split ';') -notcontains $dest) { [Environment]::SetEnvironmentVariable('Path', $p.TrimEnd(';') + ';' + $dest, 'User') }

& "$dest\osv-scanner.exe" --version
```

- SHA256 esperado y calculado:
  `e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6` ✅
- Resultado: `osv-scanner version: 2.6.0`.

### Verificación independiente

Un segundo agente volvió a hacer todo el control sin fiarse del primero:
- descargó de nuevo los ficheros de checksums;
- recalculó los hashes;
- comprobó que las URLs de descarga pertenecen a los repos `anchore/syft` y `google/osv-scanner`;
- comparó byte a byte el `syft.exe` instalado con el del zip verificado;
- ejecutó ambas herramientas.

No encontró ninguna discrepancia.

### ⚠️ Límite de lo que verificamos: integridad, no autenticidad

Comparar contra el `checksums.txt` de **la misma release** demuestra que el fichero llegó entero y
sin alteraciones en el camino (**integridad**). **No** demuestra que lo haya publicado el autor
legítimo (**autenticidad**): quien pudiera modificar la release podría cambiar el binario y el
checksum a la vez. Para cubrir eso, cada proyecto publica además una firma:

| Herramienta | Qué publica | Cómo se verificaría (pendiente, requiere otra herramienta) |
|---|---|---|
| Syft | `checksums.txt.sig` + `.pem` (firma *keyless* de Sigstore/cosign) | `cosign verify-blob --certificate syft_1.52.0_checksums.txt.pem --signature syft_1.52.0_checksums.txt.sig --certificate-identity-regexp "https://github.com/anchore/syft/.*" --certificate-oidc-issuer https://token.actions.githubusercontent.com syft_1.52.0_checksums.txt` |
| OSV-Scanner | `multiple.intoto.jsonl` (procedencia SLSA) | `slsa-verifier verify-artifact osv-scanner_windows_amd64.exe --provenance-path multiple.intoto.jsonl --source-uri github.com/google/osv-scanner --source-tag v2.6.0` |

Queda anotado como mejora. Justamente este es el tipo de control que `eslabon` debería promover.

## 3. venv del proyecto

```powershell
Set-Location C:\Users\user1\Desktop\eslabon
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
```

Un *venv* es una copia aislada de Python solo para este proyecto. Lo que se instala ahí no toca el
Python del sistema ni otros proyectos. `.venv` no se sube a git (irá en `.gitignore`).

## 4. GuardDog: ❌ no se puede instalar en Windows nativo

```powershell
.venv\Scripts\python.exe -m pip install guarddog
# → exit code 1: "Failed building wheel for nono-py"
```

**Diagnóstico.** No falló por Semgrep, como se esperaba. El motivo es otro:

1. **GuardDog 3.x ya no usa Semgrep.** Desde la versión 3.0.0 usa **YARA** y una sandbox
   llamada **nono** (`nono-py`). La última versión con Semgrep es la 2.9.0. Se comprobó leyendo las
   dependencias declaradas en PyPI para cada versión.
2. **`nono-py` no publica ningún *wheel* (binario precompilado) para Windows**, solo para Linux y
   macOS. Entonces pip intenta compilarlo desde el código fuente en Rust.
3. La compilación falla porque no están las *Build Tools* de Microsoft (MSVC). El `link.exe` que
   encuentra es el `link` de GNU que trae Git Bash, un programa distinto que no sirve para esto:
   `link: extra operand ...`.
4. Aunque se lograra compilar, **no serviría**. `nono` aísla el análisis usando mecanismos del
   kernel de Linux (Landlock) y de macOS (Seatbelt), y no tiene equivalente en Windows. El README
   oficial de GuardDog lo dice: *"On Windows, the only supported installation method is Docker."*

pip deshizo la instalación, así que el venv quedó limpio (solo `pip`). No se forzó ni se parcheó
nada.

**Por qué importa la sandbox.** GuardDog descomprime paquetes potencialmente maliciosos. Hubo
vulnerabilidades reales de *path traversal* al extraer archivos (CVE-2022-23530/23531,
CVE-2026-22870/22871). Desactivarla con `--no-sandbox` sería exactamente lo contrario de lo que
predica esta herramienta.

### Alternativas (requieren tu autorización: instalan software fuera del proyecto)

| Opción | Qué implica | Recomendación |
|---|---|---|
| **A. Docker Desktop** (usa WSL2 por debajo) | `docker run --rm ghcr.io/datadog/guarddog pypi scan <paquete>` | ✅ Es el método oficial en Windows. Además, el paquete analizado queda dentro de un contenedor desechable |
| B. WSL2 + Ubuntu | `wsl --install` + reinicio; dentro: venv e `pip install guarddog` (existen wheels para Linux) | Válida, y más liviana que Docker |
| C. MSVC + compilar | La sandbox igual no funcionaría en Windows | ❌ No recomendada |
| D. `guarddog==2.9.0` (con Semgrep) | Versión vieja, sin sandbox, y Semgrep en Windows es inestable | ❌ No recomendada |

El colector de GuardDog de `eslabon` (F2) se va a diseñar para aceptar un **comando configurable**
(por ejemplo `guarddog` nativo o `docker run ... guarddog`). Así funciona igual con cualquiera de
las opciones A o B.

## 5. Comprobación final

```powershell
# (en una terminal NUEVA, para que tome el PATH)
syft version
osv-scanner --version
```

Ambos responden. `guarddog --help` queda **pendiente** hasta que se elija la opción A o B.
