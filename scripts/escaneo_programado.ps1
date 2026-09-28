<#
.SYNOPSIS
  Escaneo programado de eslabon: analiza una lista de proyectos y deja los eventos para Wazuh.

.DESCRIPTION
  Pensado para el Programador de tareas de Windows (PowerShell 5.1). Para cada objetivo de la
  lista ejecuta:
      eslabon scan <objetivo> -f siem -o resultados\eventos.jsonl --anexar --rotar-mb <N>
  El agente de Wazuh del grupo "eslabon" lee ese fichero (ver integrations/wazuh/README.md).

  - La lista de objetivos está en resultados\objetivos.txt (una ruta o paquete por línea; las
    líneas vacías y las que empiezan con # se ignoran). resultados\ no se sube a git.
  - GuardDog usa la variable de usuario ESLABON_GUARDDOG. Si Docker no está abierto, eslabon lo
    informa como "fuente omitida" (alerta 100150 en Wazuh): el escaneo sigue con lo demás.
  - Cada ejecución deja una línea por objetivo en resultados\escaneo_programado.log.

  Código de salida: el más grave de todos los escaneos (0 bien, 3 = algún análisis incompleto).
  Los hallazgos NO hacen fallar la tarea (--fallar-en nunca): su destino es el SIEM.
#>
param(
    [string]$Objetivos = "",
    [double]$RotarMb = 50
)

$ErrorActionPreference = "Stop"
$raiz = Split-Path -Parent $PSScriptRoot
# La tarea programada arranca en C:\Windows\System32: las rutas relativas de la lista se
# resuelven desde la raíz del proyecto.
Set-Location $raiz
if (-not $Objetivos) { $Objetivos = Join-Path $raiz "resultados\objetivos.txt" }
$eslabon = Join-Path $raiz ".venv\Scripts\eslabon.exe"
$eventos = Join-Path $raiz "resultados\eventos.jsonl"
$registro = Join-Path $raiz "resultados\escaneo_programado.log"

function Registrar([string]$texto) {
    $linea = "{0} {1}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"), $texto
    # UTF-8 SIN BOM (en PowerShell 5.1, Add-Content -Encoding UTF8 escribe un BOM al crear el fichero).
    [IO.File]::AppendAllText($registro, $linea + "`n", (New-Object Text.UTF8Encoding($false)))
    Write-Output $linea
}

if (-not (Test-Path $eslabon)) { Registrar "ERROR: no existe $eslabon"; exit 2 }
if (-not (Test-Path $Objetivos)) { Registrar "ERROR: no existe la lista $Objetivos"; exit 2 }

# Herramientas en el PATH de esta ejecución (la tarea programada no abre una terminal "normal").
$extra = @(
    (Join-Path $env:LOCALAPPDATA "Programs\syft"),
    (Join-Path $env:LOCALAPPDATA "Programs\osv-scanner"),
    "C:\Program Files\Docker\Docker\resources\bin"
)
$env:Path = ($extra + @($env:Path)) -join ";"
if (-not $env:ESLABON_GUARDDOG) {
    $env:ESLABON_GUARDDOG = [Environment]::GetEnvironmentVariable("ESLABON_GUARDDOG", "User")
}

$peor = 0
$lista = Get-Content -Path $Objetivos -Encoding UTF8 |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith("#") }

foreach ($objetivo in $lista) {
    & $eslabon scan $objetivo -f siem -o $eventos --anexar --rotar-mb $RotarMb --fallar-en nunca
    $codigo = $LASTEXITCODE
    Registrar ("objetivo={0} codigo={1}" -f $objetivo, $codigo)
    if ($codigo -gt $peor) { $peor = $codigo }
}
Registrar ("fin: {0} objetivos, peor codigo={1}" -f @($lista).Count, $peor)
exit $peor
