#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Hardening Toolkit - Main Entry Point
.DESCRIPTION
    Herramienta profesional de hardening para Windows 10, Windows 11 y Windows Server.
    Sigue estándares: CIS Benchmarks, Microsoft Security Baselines, NIST 800-53, MITRE ATT&CK.

    Funcionalidades:
      - Auditoría completa del estado de seguridad
      - Hardening automático (básico y empresarial)
      - Sistema de backup y rollback
      - Generación de reportes (TXT, HTML, JSON)
      - Logging profesional de todas las acciones

.NOTES
    Autor        : Windows Hardening Toolkit
    Versión      : 1.0.0
    Requiere     : PowerShell 5.1+ | Ejecutar como Administrador
    Plataformas  : Windows 10, Windows 11, Windows Server 2016/2019/2022
    Compatible   : PowerShell 5.1 y PowerShell 7+

.EXAMPLE
    # Ejecutar con menú interactivo:
    .\main.ps1

    # Ejecutar auditoría directamente:
    .\main.ps1 -Action Audit

    # Aplicar hardening empresarial con backup automático:
    .\main.ps1 -Action Harden -HardeningProfile Enterprise

    # Generar reporte:
    .\main.ps1 -Action Report

    # Restaurar configuración:
    .\main.ps1 -Action Rollback -SessionId "20241015_142300"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Menu', 'Audit', 'Harden', 'Report', 'Rollback')]
    [string]$Action  = 'Menu',

    [ValidateSet('Basic', 'Enterprise', 'Server')]
    [string]$HardeningProfile = 'Enterprise',

    [string]$SessionId = '',

    [switch]$SkipBackup,
    [switch]$SkipRDP,
    [switch]$SkipWinRM,
    [switch]$AuditModeASR,
    [switch]$NoHTML
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # No detener en errores no fatales

# ─── CONSTANTES GLOBALES ──────────────────────────────────────────────────────

$Script:ToolkitVersion  = '1.0.0'
$Script:ToolkitName     = 'Windows Hardening Toolkit'
$Script:ToolkitRoot     = $PSScriptRoot
$Script:ConfigPath      = Join-Path $PSScriptRoot 'config'
$Script:ModulesPath     = Join-Path $PSScriptRoot 'modules'
$Script:ReportsPath     = Join-Path $PSScriptRoot 'reports'
$Script:LogsPath        = 'C:\ProgramData\WinHardening\logs'
$Script:BackupPath      = 'C:\ProgramData\WinHardening\backup'
$Script:PoliciesFile    = Join-Path $Script:ConfigPath 'policies.json'
$Script:AsrRulesFile    = Join-Path $Script:ConfigPath 'asr_rules.json'
$Script:SessionId       = if ($SessionId) { $SessionId } else { (Get-Date -Format 'yyyyMMdd_HHmmss') }

# ─── VERIFICAR PRERREQUISITOS ─────────────────────────────────────────────────

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Verifica que el entorno cumpla los requisitos para ejecutar el toolkit.
    #>
    [CmdletBinding()]
    param()

    $issues = @()

    # Verificar elevación de privilegios (Administrador)
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        $issues += "CRITICO: El toolkit requiere ejecutarse como Administrador."
    }

    # Verificar versión de PowerShell
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $issues += "CRITICO: Se requiere PowerShell 5.1 o superior. Versión actual: $($PSVersionTable.PSVersion)"
    }

    # Verificar Windows
    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
        $issues += "CRITICO: Este toolkit es exclusivo para sistemas Windows."
    }

    # Verificar que los módulos existen
    $requiredModules = @(
        'logging.ps1', 'audit.ps1', 'firewall.ps1', 'network.ps1',
        'defender.ps1', 'tls.ps1', 'credentials.ps1', 'registry.ps1',
        'logging_audit.ps1', 'rollback.ps1', 'reporting.ps1'
    )

    foreach ($mod in $requiredModules) {
        $modPath = Join-Path $Script:ModulesPath $mod
        if (-not (Test-Path $modPath)) {
            $issues += "WARNING: Módulo no encontrado: $modPath"
        }
    }

    return @{
        IsAdmin  = $isAdmin
        Issues   = $issues
        CanRun   = ($issues | Where-Object { $_ -like 'CRITICO*' }).Count -eq 0
    }
}

# ─── CARGAR MÓDULOS ───────────────────────────────────────────────────────────

function Import-ToolkitModules {
    <#
    .SYNOPSIS
        Importa todos los módulos del toolkit en el orden correcto.
    #>
    # logging.ps1 SIEMPRE primero (otros módulos dependen de Write-Log*)
    $loadOrder = @(
        'logging.ps1',
        'audit.ps1',
        'firewall.ps1',
        'network.ps1',
        'defender.ps1',
        'tls.ps1',
        'credentials.ps1',
        'registry.ps1',
        'logging_audit.ps1',
        'rollback.ps1',
        'reporting.ps1'
    )

    foreach ($module in $loadOrder) {
        $modPath = Join-Path $Script:ModulesPath $module
        if (Test-Path $modPath) {
            try {
                . $modPath
            }
            catch {
                Write-Warning "Error al cargar módulo '$module': $_"
            }
        }
        else {
            Write-Warning "Módulo no encontrado: $modPath"
        }
    }
}

# ─── CARGAR CONFIGURACIÓN ─────────────────────────────────────────────────────

function Import-ToolkitConfig {
    <#
    .SYNOPSIS
        Carga la configuración desde policies.json.
    #>
    [CmdletBinding()]
    param()

    if (Test-Path $Script:PoliciesFile) {
        try {
            $Script:Config = Get-Content -Path $Script:PoliciesFile -Raw | ConvertFrom-Json
            Write-LogInfo "Configuración cargada: $Script:PoliciesFile" -Component 'Main'
        }
        catch {
            Write-LogWarning "No se pudo cargar policies.json: $_. Usando defaults." -Component 'Main'
            $Script:Config = $null
        }
    }
    else {
        Write-LogWarning "policies.json no encontrado en: $Script:PoliciesFile" -Component 'Main'
        $Script:Config = $null
    }
}

# ─── BANNER / CABECERA ────────────────────────────────────────────────────────

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ██╗    ██╗██╗  ██╗████████╗" -ForegroundColor Cyan
    Write-Host "  ██║    ██║██║  ██║╚══██╔══╝" -ForegroundColor Cyan
    Write-Host "  ██║ █╗ ██║███████║   ██║   " -ForegroundColor Cyan
    Write-Host "  ██║███╗██║██╔══██║   ██║   " -ForegroundColor Cyan
    Write-Host "  ╚███╔███╔╝██║  ██║   ██║   " -ForegroundColor Cyan
    Write-Host "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Windows Hardening Toolkit v$Script:ToolkitVersion" -ForegroundColor White
    Write-Host "  CIS Benchmarks | MS Security Baseline | NIST 800-53 | MITRE ATT&CK" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("  " + ("─" * 68)) -ForegroundColor DarkGray
    Write-Host "  Host    : $($env:COMPUTERNAME)" -ForegroundColor Gray
    Write-Host "  Usuario : $($env:USERNAME)" -ForegroundColor Gray
    Write-Host "  OS      : $((Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)" -ForegroundColor Gray
    Write-Host "  Fecha   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ("  " + ("─" * 68)) -ForegroundColor DarkGray
    Write-Host ""
}

# ─── MENÚ PRINCIPAL ───────────────────────────────────────────────────────────

function Show-MainMenu {
    <#
    .SYNOPSIS
        Muestra el menú interactivo principal del toolkit.
    #>
    [CmdletBinding()]
    param()

    while ($true) {
        Show-Banner

        Write-Host "  MENÚ PRINCIPAL" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] Ejecutar auditoría de seguridad" -ForegroundColor White
        Write-Host "  [2] Aplicar hardening básico" -ForegroundColor Green
        Write-Host "  [3] Aplicar hardening empresarial (completo)" -ForegroundColor Green
        Write-Host "  [4] Restaurar configuración (rollback)" -ForegroundColor Yellow
        Write-Host "  [5] Generar reporte de seguridad" -ForegroundColor Cyan
        Write-Host "  [6] Ver backups disponibles" -ForegroundColor Cyan
        Write-Host "  [7] Configuración avanzada" -ForegroundColor DarkCyan
        Write-Host "  [0] Salir" -ForegroundColor DarkGray
        Write-Host ""

        $choice = Read-Host "  Seleccione una opción"

        switch ($choice.Trim()) {
            '1' {
                Write-Host ""
                $results = Invoke-FullAudit
                $Script:LastAuditResults = $results.Results
                $Script:LastAuditScore   = $results.Score
                Write-Host ""
                Read-Host "  Presione Enter para continuar"
            }
            '2' {
                Invoke-BasicHardening
                Write-Host ""
                Read-Host "  Presione Enter para continuar"
            }
            '3' {
                Invoke-EnterpriseHardening
                Write-Host ""
                Read-Host "  Presione Enter para continuar"
            }
            '4' {
                Write-Host ""
                Get-AvailableBackups
                Invoke-Rollback
                Write-Host ""
                Read-Host "  Presione Enter para continuar"
            }
            '5' {
                Write-Host ""
                if (-not $Script:LastAuditResults) {
                    Write-Host "  [INFO] No hay resultados de auditoría previos. Ejecutando auditoría..." -ForegroundColor Yellow
                    $results = Invoke-FullAudit
                    $Script:LastAuditResults = $results.Results
                    $Script:LastAuditScore   = $results.Score
                }
                $reportFiles = Invoke-GenerateReport `
                    -AuditResults $Script:LastAuditResults `
                    -Score        $Script:LastAuditScore `
                    -Formats      @('TXT', 'HTML', 'JSON')

                Write-Host ""
                Write-Host "  Reportes generados:" -ForegroundColor Cyan
                foreach ($f in $reportFiles) { Write-Host "    -> $f" -ForegroundColor Green }
                Write-Host ""
                Read-Host "  Presione Enter para continuar"
            }
            '6' {
                Write-Host ""
                Get-AvailableBackups
                Read-Host "  Presione Enter para continuar"
            }
            '7' {
                Show-AdvancedMenu
            }
            '0' {
                Write-Host ""
                Write-Host "  Saliendo de $Script:ToolkitName..." -ForegroundColor DarkGray
                Write-LogInfo "Toolkit finalizado." -Component 'Main'
                Write-Host ""
                return
            }
            default {
                Write-Host "  Opción no válida. Intente de nuevo." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ─── MENÚ AVANZADO ────────────────────────────────────────────────────────────

function Show-AdvancedMenu {
    while ($true) {
        Show-Banner
        Write-Host "  CONFIGURACIÓN AVANZADA" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] Solo hardening de Firewall" -ForegroundColor White
        Write-Host "  [2] Solo hardening de Red (SMB, LLMNR, NTLM)" -ForegroundColor White
        Write-Host "  [3] Solo hardening de Defender + ASR" -ForegroundColor White
        Write-Host "  [4] Solo hardening de TLS/SSL" -ForegroundColor White
        Write-Host "  [5] Solo hardening de Credenciales (LSASS, WDigest)" -ForegroundColor White
        Write-Host "  [6] Solo hardening de Registro (PS, UAC, AutoRun)" -ForegroundColor White
        Write-Host "  [7] Solo políticas de auditoría de Windows" -ForegroundColor White
        Write-Host "  [8] Auditoría con reporte inmediato (TXT + HTML)" -ForegroundColor Cyan
        Write-Host "  [0] Volver al menú principal" -ForegroundColor DarkGray
        Write-Host ""

        $choice = Read-Host "  Seleccione una opción"

        switch ($choice.Trim()) {
            '1' { Invoke-FirewallHardening -SkipRDP:$SkipRDP -SkipWinRM:$SkipWinRM; Read-Host "`n  Enter para continuar" }
            '2' { Invoke-NetworkHardening;    Read-Host "`n  Enter para continuar" }
            '3' { Invoke-DefenderHardening -RulesConfigPath $Script:AsrRulesFile -AuditMode:$AuditModeASR; Read-Host "`n  Enter para continuar" }
            '4' { Invoke-TlsHardening;        Read-Host "`n  Enter para continuar" }
            '5' { Invoke-CredentialsHardening; Read-Host "`n  Enter para continuar" }
            '6' { Invoke-RegistryHardening;   Read-Host "`n  Enter para continuar" }
            '7' { Invoke-AuditPolicyHardening; Read-Host "`n  Enter para continuar" }
            '8' {
                $results = Invoke-FullAudit
                $Script:LastAuditResults = $results.Results
                $Script:LastAuditScore   = $results.Score
                Invoke-GenerateReport -AuditResults $results.Results -Score $results.Score -Formats @('TXT','HTML')
                Read-Host "`n  Enter para continuar"
            }
            '0' { return }
            default { Write-Host "  Opción no válida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    }
}

# ─── HARDENING BÁSICO ─────────────────────────────────────────────────────────

function Invoke-BasicHardening {
    <#
    .SYNOPSIS
        Aplica el perfil de hardening básico: controles de alto impacto, bajo riesgo.
    #>
    Show-Banner
    Write-Host "  HARDENING BÁSICO" -ForegroundColor Yellow
    Write-Host "  Controles de alto impacto y bajo riesgo de interrupción de servicios." -ForegroundColor Gray
    Write-Host ""

    $confirm = Read-Host "  ¿Confirma que desea aplicar hardening básico? (s/N)"
    if ($confirm.ToLower() -ne 's') {
        Write-LogInfo "Hardening básico cancelado por el usuario." -Component 'Main'
        return
    }

    # Backup previo
    if (-not $SkipBackup) {
        Write-LogInfo "Creando backup pre-hardening..." -Component 'Main'
        Invoke-FullBackup -SessionId $Script:SessionId
    }

    Write-LogSection "APLICANDO HARDENING BÁSICO"

    # Firewall (sin bloquear RDP/WinRM)
    Invoke-FirewallHardening -BasicOnly -SkipRDP -SkipWinRM

    # Red: solo controles críticos (SMBv1, LLMNR, NetBIOS)
    Disable-SmbV1
    Enable-SmbSigning
    Disable-NetBiosOverTcpIp
    Disable-Llmnr

    # Defender: protecciones básicas (sin ASR avanzado)
    Invoke-DefenderHardening -BasicOnly -AuditMode

    # TLS: deshabilitar versiones antiguas
    Disable-InsecureProtocols
    Enable-SecureProtocols
    Set-DotNetTlsSettings

    # Credenciales: WDigest y LSASS (sin Credential Guard)
    Disable-WDigest
    Enable-LsassProtection

    # Registro: UAC, AutoRun, PS Security
    Invoke-PowerShellSecurityHardening
    Invoke-UacHardening
    Invoke-AutoRunHardening

    Write-LogSuccess "Hardening básico completado exitosamente." -Component 'Main'

    # Generar reporte básico
    $results = Invoke-FullAudit
    $Script:LastAuditResults = $results.Results
    $Script:LastAuditScore   = $results.Score
    Invoke-GenerateReport -AuditResults $results.Results -Score $results.Score -Formats @('TXT')

    Write-Host ""
    Write-Host "  Hardening básico completado. Score: $($results.Score)%" -ForegroundColor Green
    Write-Host "  NOTA: Se recomienda reiniciar el sistema para que todos los cambios surtan efecto." -ForegroundColor Yellow
}

# ─── HARDENING EMPRESARIAL ────────────────────────────────────────────────────

function Invoke-EnterpriseHardening {
    <#
    .SYNOPSIS
        Aplica el perfil de hardening empresarial completo.
    #>
    Show-Banner
    Write-Host "  HARDENING EMPRESARIAL (COMPLETO)" -ForegroundColor Red
    Write-Host "  ADVERTENCIA: Este perfil aplica todos los controles de seguridad." -ForegroundColor Yellow
    Write-Host "  Puede interrumpir servicios si no se evalúan las exclusiones necesarias." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Configuración actual:" -ForegroundColor Gray
    Write-Host "  - Bloquear RDP (3389)    : $(if ($SkipRDP) { 'NO (excluido)' } else { 'SÍ' })" -ForegroundColor Gray
    Write-Host "  - Bloquear WinRM         : $(if ($SkipWinRM) { 'NO (excluido)' } else { 'SÍ' })" -ForegroundColor Gray
    Write-Host "  - ASR Rules modo Block   : $(if ($AuditModeASR) { 'NO (Audit Mode)' } else { 'SÍ' })" -ForegroundColor Gray
    Write-Host ""

    $confirm = Read-Host "  ¿Confirma que desea aplicar hardening empresarial? (s/N)"
    if ($confirm.ToLower() -ne 's') {
        Write-LogInfo "Hardening empresarial cancelado por el usuario." -Component 'Main'
        return
    }

    # Backup previo
    if (-not $SkipBackup) {
        Write-LogInfo "Creando backup pre-hardening..." -Component 'Main'
        Invoke-FullBackup -SessionId $Script:SessionId
    }

    Write-LogSection "APLICANDO HARDENING EMPRESARIAL"

    # Módulos en orden de dependencia
    Invoke-FirewallHardening -SkipRDP:$SkipRDP -SkipWinRM:$SkipWinRM
    Invoke-NetworkHardening
    Invoke-DefenderHardening -RulesConfigPath $Script:AsrRulesFile -AuditMode:$AuditModeASR
    Invoke-TlsHardening
    Invoke-CredentialsHardening
    Invoke-RegistryHardening
    Invoke-AuditPolicyHardening

    Write-LogSuccess "Hardening empresarial completado exitosamente." -Component 'Main'

    # Generar reportes completos
    $results = Invoke-FullAudit
    $Script:LastAuditResults = $results.Results
    $Script:LastAuditScore   = $results.Score

    $formats = if ($NoHTML) { @('TXT', 'JSON') } else { @('TXT', 'HTML', 'JSON') }
    $reportFiles = Invoke-GenerateReport -AuditResults $results.Results -Score $results.Score -Formats $formats

    Write-Host ""
    Write-Host "  Hardening empresarial completado." -ForegroundColor Green
    Write-Host "  Security Score: $($results.Score)%" -ForegroundColor $(if ($results.Score -ge 80) { 'Green' } elseif ($results.Score -ge 60) { 'Yellow' } else { 'Red' })
    Write-Host ""
    Write-Host "  Reportes disponibles:" -ForegroundColor Cyan
    foreach ($f in $reportFiles) { Write-Host "  -> $f" -ForegroundColor White }
    Write-Host ""
    Write-Host "  IMPORTANTE: Reinicie el sistema para aplicar todos los cambios." -ForegroundColor Yellow
}

# ─── PUNTO DE ENTRADA PRINCIPAL ───────────────────────────────────────────────

function Main {
    # Verificar prerrequisitos (sin logger aún)
    $prereqs = Test-Prerequisites

    if (-not $prereqs.CanRun) {
        Write-Host ""
        Write-Host "  ERROR: El toolkit no puede ejecutarse:" -ForegroundColor Red
        foreach ($issue in $prereqs.Issues) {
            Write-Host "  - $issue" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  Solución: Ejecute PowerShell como Administrador." -ForegroundColor Yellow
        Write-Host "    Clic derecho > 'Ejecutar como administrador'" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }

    # Crear directorios necesarios
    foreach ($dir in @($Script:LogsPath, $Script:BackupPath, $Script:ReportsPath)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # Inicializar logger
    Initialize-Logger -SessionId $Script:SessionId
    Invoke-LogRotation -DaysToKeep 30

    # Cargar configuración
    Import-ToolkitConfig

    # Mostrar banner y verificar estado
    if ($prereqs.Issues.Count -gt 0) {
        foreach ($issue in $prereqs.Issues) {
            Write-LogWarning $issue -Component 'Main'
        }
    }

    Write-LogInfo "$Script:ToolkitName v$Script:ToolkitVersion iniciado." -Component 'Main'
    Write-LogInfo "Session ID: $Script:SessionId" -Component 'Main'
    Write-LogInfo "Modo: $Action$(if ($Action -eq 'Harden') { " / Perfil: $HardeningProfile" })" -Component 'Main'

    # Variables de estado global
    $Script:LastAuditResults = $null
    $Script:LastAuditScore   = 0

    # Ejecutar acción solicitada
    switch ($Action) {
        'Menu' {
            Show-MainMenu
        }
        'Audit' {
            Show-Banner
            $results = Invoke-FullAudit
            $Script:LastAuditResults = $results.Results
            $Script:LastAuditScore   = $results.Score
        }
        'Harden' {
            switch ($HardeningProfile) {
                'Basic'      { Invoke-BasicHardening      }
                'Enterprise' { Invoke-EnterpriseHardening }
                'Server'     {
                    # Perfil Server: igual que Enterprise pero con RDP/WinRM excluidos
                    $script:SkipRDP   = $true
                    $script:SkipWinRM = $true
                    $script:AuditModeASR = $true
                    Invoke-EnterpriseHardening
                }
            }
        }
        'Report' {
            Show-Banner
            Write-LogInfo "Generando reporte (ejecutando auditoría primero)..." -Component 'Main'
            $results = Invoke-FullAudit
            $Script:LastAuditResults = $results.Results
            $Script:LastAuditScore   = $results.Score

            $formats = if ($NoHTML) { @('TXT', 'JSON') } else { @('TXT', 'HTML', 'JSON') }
            Invoke-GenerateReport -AuditResults $results.Results -Score $results.Score -Formats $formats
        }
        'Rollback' {
            Show-Banner
            if ($SessionId) {
                Invoke-Rollback -SessionId $SessionId
            }
            else {
                Get-AvailableBackups
                Invoke-Rollback
            }
        }
    }

    Write-LogInfo "$Script:ToolkitName finalizado. Log: $(Get-CurrentLogFile)" -Component 'Main'
}

# ─── INICIO ───────────────────────────────────────────────────────────────────
# Los módulos se cargan aquí, en el scope del SCRIPT (no dentro de una función).
# Esto es crítico: dot-sourcing dentro de una función crea las funciones en el
# scope local de esa función, que se destruye al retornar. Cargando aquí, las
# funciones quedan disponibles en el scope del script y son visibles desde Main
# y todas las funciones que Main invoca (Show-MainMenu, Show-Banner, etc.).

# Limpiar errores previos para capturar únicamente los de esta sesión
$Error.Clear()

$Script:_ModuleLoadOrder = @(
    'logging.ps1', 'audit.ps1', 'firewall.ps1', 'network.ps1',
    'defender.ps1', 'tls.ps1', 'credentials.ps1', 'registry.ps1',
    'logging_audit.ps1', 'rollback.ps1', 'reporting.ps1'
)

foreach ($Script:_mod in $Script:_ModuleLoadOrder) {
    $Script:_modPath = Join-Path $Script:ModulesPath $Script:_mod
    if (Test-Path $Script:_modPath) {
        try   { . $Script:_modPath }
        catch { Write-Warning "Error al cargar módulo '$Script:_mod': $_" }
    }
    else {
        Write-Warning "Módulo no encontrado: $Script:_modPath"
    }
}

# ─── DIAGNÓSTICO DE ARRANQUE ──────────────────────────────────────────────────
# Si hubo errores (no-terminantes) durante la carga de módulos, los captura en
# un archivo para que persistan aunque Clear-Host limpie la consola después.
if ($Error.Count -gt 0) {
    $Script:_diagFile = Join-Path $env:TEMP "WinHardening_Startup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    try {
        $Script:_diagLines = @("=== Windows Hardening Toolkit — Errores de Arranque ===")
        $Script:_diagLines += "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $Script:_diagLines += "PS Version: $($PSVersionTable.PSVersion)"
        $Script:_diagLines += ""
        $Script:_i = 0
        foreach ($Script:_err in $Error) {
            $Script:_i++
            $Script:_diagLines += "[$Script:_i] $($Script:_err.Exception.Message)"
            if ($Script:_err.InvocationInfo -and $Script:_err.InvocationInfo.ScriptName) {
                $Script:_diagLines += "    Archivo : $($Script:_err.InvocationInfo.ScriptName)"
                $Script:_diagLines += "    Línea   : $($Script:_err.InvocationInfo.ScriptLineNumber)"
                $Script:_diagLines += "    Código  : $($Script:_err.InvocationInfo.Line.Trim())"
            }
            $Script:_diagLines += ""
        }
        [System.IO.File]::WriteAllText(
            $Script:_diagFile,
            ($Script:_diagLines -join "`r`n"),
            [System.Text.UTF8Encoding]::new($false)
        )
        Write-Host ""
        Write-Host "  [DIAGNOSTICO] $($Error.Count) error(es) detectados al iniciar." -ForegroundColor Red
        Write-Host "  Log guardado en: $Script:_diagFile" -ForegroundColor Yellow
        Write-Host "  (El archivo persiste aunque se limpie la consola)" -ForegroundColor DarkGray
        Write-Host ""
        Start-Sleep -Seconds 4
    }
    catch { }
}
$Error.Clear()

Main
