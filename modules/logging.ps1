#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Logging Module
.DESCRIPTION
    Sistema de logging profesional con niveles INFO, WARNING, ERROR.
    Escribe en consola con colores y en archivo de log rotativo.
.NOTES
    Standard: NIST 800-53 AU (Audit and Accountability)
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── CONSTANTES DE LOGGING ────────────────────────────────────────────────────

$Script:LogBasePath = 'C:\ProgramData\WinHardening\logs'
$Script:LogFile     = $null   # Se inicializa en Initialize-Logger
$Script:LogSession  = $null   # ID de sesión único por ejecución

# Niveles y colores de consola
$Script:LogLevels = @{
    INFO    = @{ Color = 'Cyan';    Prefix = 'INFO   ' }
    WARNING = @{ Color = 'Yellow';  Prefix = 'WARNING' }
    ERROR   = @{ Color = 'Red';     Prefix = 'ERROR  ' }
    SUCCESS = @{ Color = 'Green';   Prefix = 'SUCCESS' }
    DEBUG   = @{ Color = 'Gray';    Prefix = 'DEBUG  ' }
    SECTION = @{ Color = 'Magenta'; Prefix = '───────' }
}

# ─── FUNCIÓN DE INICIALIZACIÓN ────────────────────────────────────────────────

function Initialize-Logger {
    <#
    .SYNOPSIS
        Inicializa el sistema de logging creando el directorio y archivo de log.
    .PARAMETER SessionId
        Identificador único de sesión. Si no se provee, se genera automáticamente.
    #>
    [CmdletBinding()]
    param(
        [string]$SessionId
    )

    # Crear directorio de logs si no existe
    if (-not (Test-Path -Path $Script:LogBasePath)) {
        try {
            New-Item -ItemType Directory -Path $Script:LogBasePath -Force | Out-Null
        }
        catch {
            Write-Warning "No se pudo crear el directorio de logs: $Script:LogBasePath. Usando temp."
            $Script:LogBasePath = $env:TEMP
        }
    }

    # Generar sesión ID y nombre de archivo
    $Script:LogSession = if ($SessionId) { $SessionId } else { (Get-Date -Format 'yyyyMMdd_HHmmss') }
    $Script:LogFile    = Join-Path $Script:LogBasePath "hardening_$($Script:LogSession).log"

    # Encabezado del log
    $header = @"
================================================================================
  Windows Hardening Toolkit - Session Log
  Session ID : $Script:LogSession
  Started    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Host       : $($env:COMPUTERNAME)
  User       : $($env:USERNAME)
  OS         : $((Get-CimInstance -ClassName Win32_OperatingSystem).Caption)
  PS Version : $($PSVersionTable.PSVersion)
================================================================================
"@
    try {
        Add-Content -Path $Script:LogFile -Value $header -Encoding UTF8
    }
    catch {
        Write-Warning "No se pudo escribir en el archivo de log: $Script:LogFile"
    }

    Write-Log -Level INFO -Message "Logger inicializado. Archivo: $Script:LogFile"
}

# ─── FUNCIÓN PRINCIPAL DE LOGGING ─────────────────────────────────────────────

function Write-Log {
    <#
    .SYNOPSIS
        Escribe una entrada de log en consola y en archivo.
    .PARAMETER Level
        Nivel del mensaje: INFO, WARNING, ERROR, SUCCESS, DEBUG, SECTION
    .PARAMETER Message
        Mensaje a registrar.
    .PARAMETER Component
        Componente o módulo que genera el log (opcional).
    .PARAMETER NoConsole
        Si se especifica, no imprime en consola (solo escribe en archivo).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG', 'SECTION')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Component = '',

        [switch]$NoConsole
    )

    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelInfo  = $Script:LogLevels[$Level]
    $prefix     = $levelInfo.Prefix
    $color      = $levelInfo.Color
    $compPart   = if ($Component) { "[$Component] " } else { '' }

    # Formato de línea para archivo
    $logLine = "[$timestamp] [$prefix] $compPart$Message"

    # Escribir en archivo si está inicializado
    if ($Script:LogFile) {
        try {
            Add-Content -Path $Script:LogFile -Value $logLine -Encoding UTF8
        }
        catch {
            # Silencioso: no interrumpir la ejecución por fallo de log
        }
    }

    # Escribir en consola con color
    if (-not $NoConsole) {
        if ($Level -eq 'SECTION') {
            Write-Host ""
            Write-Host ("─" * 72) -ForegroundColor $color
            Write-Host "  $Message" -ForegroundColor $color
            Write-Host ("─" * 72) -ForegroundColor $color
        }
        else {
            $timeStr = "[$timestamp]"
            Write-Host -NoNewline "$timeStr " -ForegroundColor DarkGray
            Write-Host -NoNewline "[$prefix] " -ForegroundColor $color
            if ($Component) {
                Write-Host -NoNewline "[$Component] " -ForegroundColor DarkCyan
            }
            Write-Host $Message
        }
    }
}

# ─── FUNCIONES AUXILIARES ─────────────────────────────────────────────────────

function Write-LogInfo    { param([string]$Message, [string]$Component = '') Write-Log -Level INFO    -Message $Message -Component $Component }
function Write-LogWarning { param([string]$Message, [string]$Component = '') Write-Log -Level WARNING -Message $Message -Component $Component }
function Write-LogError   { param([string]$Message, [string]$Component = '') Write-Log -Level ERROR   -Message $Message -Component $Component }
function Write-LogSuccess { param([string]$Message, [string]$Component = '') Write-Log -Level SUCCESS -Message $Message -Component $Component }
function Write-LogDebug   { param([string]$Message, [string]$Component = '') Write-Log -Level DEBUG   -Message $Message -Component $Component }
function Write-LogSection { param([string]$Message)                          Write-Log -Level SECTION -Message $Message }

# ─── ROTACIÓN DE LOGS ─────────────────────────────────────────────────────────

function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Elimina logs más antiguos que N días para evitar acumulación.
    .PARAMETER DaysToKeep
        Número de días a conservar. Por defecto 30.
    #>
    [CmdletBinding()]
    param(
        [int]$DaysToKeep = 30
    )

    if (-not (Test-Path -Path $Script:LogBasePath)) { return }

    $cutoff  = (Get-Date).AddDays(-$DaysToKeep)
    $oldLogs = Get-ChildItem -Path $Script:LogBasePath -Filter '*.log' |
               Where-Object { $_.LastWriteTime -lt $cutoff }

    foreach ($log in $oldLogs) {
        try {
            Remove-Item -Path $log.FullName -Force
            Write-LogInfo "Log antiguo eliminado: $($log.Name)" -Component 'LogRotation'
        }
        catch {
            Write-LogWarning "No se pudo eliminar log: $($log.Name)" -Component 'LogRotation'
        }
    }

    if ($oldLogs.Count -gt 0) {
        Write-LogInfo "Rotación completada: $($oldLogs.Count) archivos eliminados." -Component 'LogRotation'
    }
}

# ─── OBTENER RUTA DEL LOG ACTUAL ──────────────────────────────────────────────

function Get-CurrentLogFile {
    <#
    .SYNOPSIS
        Devuelve la ruta del archivo de log de la sesión actual.
    #>
    return $Script:LogFile
}
