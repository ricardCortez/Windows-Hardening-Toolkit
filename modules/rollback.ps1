#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Rollback / Backup Module
.DESCRIPTION
    Sistema de backup y restauración de configuraciones de seguridad.
    Antes de aplicar hardening, exporta:
    - Claves de registro críticas
    - Configuración de firewall
    - Configuración de Microsoft Defender
    - Estado de SMB
    Permite restauración completa con un solo comando.
.NOTES
    Standard: Change Management, NIST 800-53 CM-9
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── CONSTANTES DE BACKUP ─────────────────────────────────────────────────────

$Script:BackupBasePath = 'C:\ProgramData\WinHardening\backup'
$Script:BackupSession  = $null

# ─── INICIALIZAR SESIÓN DE BACKUP ─────────────────────────────────────────────

function Initialize-BackupSession {
    <#
    .SYNOPSIS
        Crea el directorio de backup para la sesión actual.
    .PARAMETER SessionId
        ID de sesión (normalmente la misma que el log).
    .OUTPUTS
        Ruta del directorio de backup de la sesión.
    #>
    [CmdletBinding()]
    param(
        [string]$SessionId
    )

    $Script:BackupSession = if ($SessionId) { $SessionId } else { (Get-Date -Format 'yyyyMMdd_HHmmss') }
    $sessionPath = Join-Path $Script:BackupBasePath $Script:BackupSession

    try {
        if (-not (Test-Path $sessionPath)) {
            New-Item -ItemType Directory -Path $sessionPath -Force | Out-Null
        }
        Write-LogInfo "Directorio de backup: $sessionPath" -Component 'Rollback'
        return $sessionPath
    }
    catch {
        Write-LogError "No se pudo crear directorio de backup: $sessionPath" -Component 'Rollback'
        return $null
    }
}

# ─── EXPORTAR CLAVE DE REGISTRO ───────────────────────────────────────────────

function Export-RegistryKey {
    <#
    .SYNOPSIS
        Exporta una clave de registro a un archivo .reg en el directorio de backup.
    .PARAMETER KeyPath
        Ruta completa de la clave de registro (ej: HKLM:\SYSTEM\CurrentControlSet\...)
    .PARAMETER FileName
        Nombre del archivo de backup (sin extensión).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$FileName
    )

    $sessionPath = Join-Path $Script:BackupBasePath $Script:BackupSession
    if (-not (Test-Path $sessionPath)) {
        New-Item -ItemType Directory -Path $sessionPath -Force | Out-Null
    }

    $outFile = Join-Path $sessionPath "$FileName.reg"

    # Convertir ruta PS a ruta reg.exe
    $regPath = $KeyPath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' `
                        -replace '^HKCU:\\', 'HKEY_CURRENT_USER\' `
                        -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\' `
                        -replace '/',        '\'

    try {
        $result = reg export "$regPath" "$outFile" /y 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-LogSuccess "Backup registro: $FileName.reg" -Component 'Rollback'
            return $true
        }
        else {
            Write-LogWarning "No se pudo exportar '$KeyPath': $result" -Component 'Rollback'
            return $false
        }
    }
    catch {
        Write-LogWarning "Error exportando '$KeyPath': $_" -Component 'Rollback'
        return $false
    }
}

# ─── BACKUP: REGISTRO DE SEGURIDAD ────────────────────────────────────────────

function Backup-SecurityRegistry {
    <#
    .SYNOPSIS
        Exporta todas las claves de registro que serán modificadas por el toolkit.
    #>
    [CmdletBinding()]
    param()

    Write-LogSection "Backup: Claves de Registro"

    $keysToBackup = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                           Name = 'LSA_Settings' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0';                    Name = 'NTLM_Settings' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest';      Name = 'WDigest_Settings' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL';     Name = 'SCHANNEL_Settings' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';       Name = 'SMB_Server_Settings' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters';  Name = 'SMB_Client_Settings' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell';                  Name = 'PS_Security_Policies' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';       Name = 'UAC_Policies' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient';                Name = 'DNS_Client_Policies' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard';                    Name = 'DeviceGuard_Settings' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework';                                Name = 'DotNET_Settings' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server';                Name = 'RDP_Settings' }
    )

    $exported = 0
    foreach ($key in $keysToBackup) {
        if (Test-Path $key.Path) {
            if (Export-RegistryKey -KeyPath $key.Path -FileName $key.Name) {
                $exported++
            }
        }
        else {
            Write-LogDebug "Clave no existe (backup omitido): $($key.Path)" -Component 'Rollback'
        }
    }

    Write-LogInfo "Backup de registro: $exported claves exportadas." -Component 'Rollback'
}

# ─── BACKUP: CONFIGURACIÓN DE FIREWALL ────────────────────────────────────────

function Backup-FirewallConfiguration {
    <#
    .SYNOPSIS
        Exporta la configuración completa del firewall en formato .wfw y .json.
    #>
    [CmdletBinding()]
    param()

    Write-LogSection "Backup: Windows Firewall"

    $sessionPath = Join-Path $Script:BackupBasePath $Script:BackupSession
    if (-not (Test-Path $sessionPath)) {
        New-Item -ItemType Directory -Path $sessionPath -Force | Out-Null
    }

    # Exportar configuración completa del firewall (netsh)
    $wfwFile = Join-Path $sessionPath 'firewall_config.wfw'
    try {
        $result = netsh advfirewall export "$wfwFile" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-LogSuccess "Backup de firewall exportado: firewall_config.wfw" -Component 'Rollback'
        }
        else {
            Write-LogWarning "netsh advfirewall export falló: $result" -Component 'Rollback'
        }
    }
    catch {
        Write-LogWarning "Error exportando configuración de firewall: $_" -Component 'Rollback'
    }

    # Exportar estado de perfiles como JSON
    try {
        $profilesJson = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogAllowed |
                        ConvertTo-Json -Depth 3

        $profilesFile = Join-Path $sessionPath 'firewall_profiles.json'
        $profilesJson | Out-File -FilePath $profilesFile -Encoding UTF8 -Force
        Write-LogSuccess "Estado de perfiles de firewall guardado: firewall_profiles.json" -Component 'Rollback'
    }
    catch {
        Write-LogWarning "No se pudo exportar perfiles de firewall a JSON: $_" -Component 'Rollback'
    }

    # Listar y exportar reglas personalizadas
    try {
        $rulesJson = Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled, Profile |
                     ConvertTo-Json -Depth 3
        $rulesFile = Join-Path $sessionPath 'firewall_rules.json'
        $rulesJson | Out-File -FilePath $rulesFile -Encoding UTF8 -Force
        Write-LogSuccess "Lista de reglas de firewall guardada: firewall_rules.json" -Component 'Rollback'
    }
    catch {
        Write-LogWarning "No se pudo exportar reglas de firewall: $_" -Component 'Rollback'
    }
}

# ─── BACKUP: ESTADO DE MICROSOFT DEFENDER ─────────────────────────────────────

function Backup-DefenderConfiguration {
    <#
    .SYNOPSIS
        Exporta el estado actual de Microsoft Defender.
    #>
    [CmdletBinding()]
    param()

    Write-LogSection "Backup: Microsoft Defender"

    $sessionPath = Join-Path $Script:BackupBasePath $Script:BackupSession

    try {
        $defStatus  = Get-MpComputerStatus -ErrorAction Stop
        $defPrefs   = Get-MpPreference     -ErrorAction Stop

        $defData = @{
            Timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Status     = $defStatus | Select-Object RealTimeProtectionEnabled, EnableNetworkProtection,
                                                    EnableControlledFolderAccess, AntivirusEnabled,
                                                    AntispywareEnabled, BehaviorMonitorEnabled
            Preferences = $defPrefs | Select-Object DisableRealtimeMonitoring, EnableNetworkProtection,
                                                    EnableControlledFolderAccess, MAPSReporting,
                                                    AttackSurfaceReductionRules_Ids,
                                                    AttackSurfaceReductionRules_Actions,
                                                    PUAProtection, CloudBlockLevel
        }

        $defFile = Join-Path $sessionPath 'defender_config.json'
        $defData | ConvertTo-Json -Depth 5 | Out-File -FilePath $defFile -Encoding UTF8 -Force
        Write-LogSuccess "Configuración de Defender guardada: defender_config.json" -Component 'Rollback'
    }
    catch {
        Write-LogWarning "No se pudo exportar configuración de Defender: $_" -Component 'Rollback'
    }
}

# ─── BACKUP: ESTADO DE SMB ────────────────────────────────────────────────────

function Backup-SmbConfiguration {
    <#
    .SYNOPSIS
        Exporta la configuración actual de SMB Server y Client.
    #>
    [CmdletBinding()]
    param()

    Write-LogSection "Backup: SMB Configuration"

    $sessionPath = Join-Path $Script:BackupBasePath $Script:BackupSession

    try {
        $smbConfig = @{
            Server = Get-SmbServerConfiguration -ErrorAction Stop |
                     Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature,
                                   EnableSecuritySignature, EncryptData, DisableCompression
        }

        $smbFile = Join-Path $sessionPath 'smb_config.json'
        $smbConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $smbFile -Encoding UTF8 -Force
        Write-LogSuccess "Configuración de SMB guardada: smb_config.json" -Component 'Rollback'
    }
    catch {
        Write-LogWarning "No se pudo exportar configuración SMB: $_" -Component 'Rollback'
    }
}

# ─── BACKUP: GENERAR MANIFIESTO ───────────────────────────────────────────────

function New-BackupManifest {
    <#
    .SYNOPSIS
        Genera un archivo de manifiesto con metadata del backup.
    #>
    [CmdletBinding()]
    param()

    $sessionPath = Join-Path $Script:BackupBasePath $Script:BackupSession

    try {
        $osInfo     = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $files      = Get-ChildItem -Path $sessionPath -File -ErrorAction SilentlyContinue

        $manifest = @{
            SessionId     = $Script:BackupSession
            Timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Hostname      = $env:COMPUTERNAME
            OS            = $osInfo.Caption
            OSVersion     = $osInfo.Version
            User          = $env:USERNAME
            BackupPath    = $sessionPath
            Files         = $files | ForEach-Object { @{ Name = $_.Name; Size = $_.Length; Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash } }
            ToolkitVersion = '1.0.0'
        }

        $manifestFile = Join-Path $sessionPath 'MANIFEST.json'
        $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestFile -Encoding UTF8 -Force
        Write-LogSuccess "Manifiesto de backup generado: MANIFEST.json" -Component 'Rollback'
    }
    catch {
        Write-LogWarning "No se pudo generar manifiesto: $_" -Component 'Rollback'
    }
}

# ─── FUNCIÓN MAESTRA DE BACKUP ────────────────────────────────────────────────

function Invoke-FullBackup {
    <#
    .SYNOPSIS
        Ejecuta un backup completo antes de aplicar hardening.
    .PARAMETER SessionId
        ID de sesión para nombrar el directorio de backup.
    .OUTPUTS
        Ruta del directorio de backup creado.
    #>
    [CmdletBinding()]
    param(
        [string]$SessionId
    )

    Write-LogSection "INICIANDO BACKUP PRE-HARDENING"

    $sessionPath = Initialize-BackupSession -SessionId $SessionId

    if (-not $sessionPath) {
        Write-LogError "No se pudo inicializar el directorio de backup. Hardening abortado." -Component 'Rollback'
        return $null
    }

    Backup-SecurityRegistry
    Backup-FirewallConfiguration
    Backup-DefenderConfiguration
    Backup-SmbConfiguration
    New-BackupManifest

    Write-LogSuccess "Backup completado en: $sessionPath" -Component 'Rollback'
    Write-LogInfo "Para restaurar, ejecute: Invoke-Rollback -SessionId '$Script:BackupSession'" -Component 'Rollback'

    return $sessionPath
}

# ─── RESTAURAR DESDE BACKUP ───────────────────────────────────────────────────

function Invoke-Rollback {
    <#
    .SYNOPSIS
        Restaura la configuración del sistema desde un backup previo.
    .PARAMETER SessionId
        ID de la sesión de backup a restaurar. Si no se provee, lista las disponibles.
    .PARAMETER WhatIf
        Muestra qué se restauraría sin aplicar cambios.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$SessionId
    )

    Write-LogSection "INICIANDO ROLLBACK DE CONFIGURACIÓN"

    # Listar backups disponibles si no se especifica sesión
    if (-not $SessionId) {
        $sessions = Get-ChildItem -Path $Script:BackupBasePath -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending

        if (-not $sessions) {
            Write-LogWarning "No se encontraron backups en: $Script:BackupBasePath" -Component 'Rollback'
            return
        }

        Write-Host ""
        Write-Host "  Backups disponibles:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $sessions.Count; $i++) {
            $manifestPath = Join-Path $sessions[$i].FullName 'MANIFEST.json'
            $timestamp    = $sessions[$i].Name
            if (Test-Path $manifestPath) {
                $manifest  = Get-Content $manifestPath | ConvertFrom-Json
                $timestamp = "$($manifest.Timestamp) (Host: $($manifest.Hostname))"
            }
            Write-Host "  [$($i+1)] $($sessions[$i].Name) - $timestamp"
        }

        Write-Host ""
        $choice = Read-Host "  Seleccione número de backup (Enter para cancelar)"
        if (-not $choice -or $choice -notmatch '^\d+$') { return }

        $idx = [int]$choice - 1
        if ($idx -lt 0 -or $idx -ge $sessions.Count) {
            Write-LogWarning "Selección inválida." -Component 'Rollback'
            return
        }

        $SessionId = $sessions[$idx].Name
    }

    $sessionPath = Join-Path $Script:BackupBasePath $SessionId

    if (-not (Test-Path $sessionPath)) {
        Write-LogError "Directorio de backup no encontrado: $sessionPath" -Component 'Rollback'
        return
    }

    Write-LogInfo "Restaurando desde: $sessionPath" -Component 'Rollback'

    # ── Restaurar claves de registro ──
    $regFiles = Get-ChildItem -Path $sessionPath -Filter '*.reg' -ErrorAction SilentlyContinue
    foreach ($regFile in $regFiles) {
        try {
            if ($PSCmdlet.ShouldProcess($regFile.Name, 'Importar clave de registro')) {
                $result = reg import "$($regFile.FullName)" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-LogSuccess "Registro restaurado: $($regFile.Name)" -Component 'Rollback'
                }
                else {
                    Write-LogWarning "No se pudo importar $($regFile.Name): $result" -Component 'Rollback'
                }
            }
        }
        catch {
            Write-LogError "Error restaurando $($regFile.Name): $_" -Component 'Rollback'
        }
    }

    # ── Restaurar configuración de firewall ──
    $wfwFile = Join-Path $sessionPath 'firewall_config.wfw'
    if (Test-Path $wfwFile) {
        try {
            if ($PSCmdlet.ShouldProcess('firewall_config.wfw', 'Restaurar firewall')) {
                $result = netsh advfirewall import "$wfwFile" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-LogSuccess "Configuración de firewall restaurada." -Component 'Rollback'
                }
                else {
                    Write-LogWarning "netsh advfirewall import falló: $result" -Component 'Rollback'
                }
            }
        }
        catch {
            Write-LogError "Error restaurando firewall: $_" -Component 'Rollback'
        }
    }

    # ── Eliminar reglas WHT del firewall ──
    try {
        if ($PSCmdlet.ShouldProcess('Reglas WHT', 'Eliminar')) {
            $whtRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'WHT -*' }
            $whtRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-LogSuccess "Reglas WHT de firewall eliminadas." -Component 'Rollback'
        }
    }
    catch {
        Write-LogWarning "No se pudo eliminar reglas WHT: $_" -Component 'Rollback'
    }

    # ── Restaurar SMBv1 si estaba habilitado (ATENCIÓN: solo si era necesario) ──
    $smbFile = Join-Path $sessionPath 'smb_config.json'
    if (Test-Path $smbFile) {
        try {
            $smbBackup = Get-Content $smbFile | ConvertFrom-Json
            if ($smbBackup.Server.EnableSMB1Protocol -eq $true) {
                Write-LogWarning "El backup indica que SMBv1 estaba habilitado. NO SE RESTAURA por seguridad." -Component 'Rollback'
                Write-LogWarning "Si necesita SMBv1, habilítelo manualmente con: Set-SmbServerConfiguration -EnableSMB1Protocol `$true" -Component 'Rollback'
            }
        }
        catch {
            Write-LogDebug "No se pudo leer backup de SMB." -Component 'Rollback'
        }
    }

    Write-LogSuccess "Rollback completado desde sesión: $SessionId" -Component 'Rollback'
    Write-LogWarning "NOTA: Algunos cambios (RunAsPPL, Credential Guard) requieren REINICIO para revertirse." -Component 'Rollback'
}

# ─── LISTAR BACKUPS DISPONIBLES ───────────────────────────────────────────────

function Get-AvailableBackups {
    <#
    .SYNOPSIS
        Lista todos los backups disponibles con metadata.
    #>
    [CmdletBinding()]
    param()

    $sessions = Get-ChildItem -Path $Script:BackupBasePath -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending

    if (-not $sessions) {
        Write-LogInfo "No hay backups disponibles en: $Script:BackupBasePath" -Component 'Rollback'
        return
    }

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │ BACKUPS DISPONIBLES                                                  │" -ForegroundColor Cyan
    Write-Host "  ├──────────────────────┬──────────────────────┬──────────────────────┤" -ForegroundColor Cyan
    Write-Host "  │ Session ID           │ Fecha/Hora           │ Host                 │" -ForegroundColor Cyan
    Write-Host "  ├──────────────────────┼──────────────────────┼──────────────────────┤" -ForegroundColor Cyan

    foreach ($session in $sessions) {
        $manifestPath = Join-Path $session.FullName 'MANIFEST.json'
        $timestamp    = 'N/A'
        $hostname     = 'N/A'

        if (Test-Path $manifestPath) {
            try {
                $manifest  = Get-Content $manifestPath | ConvertFrom-Json
                $timestamp = $manifest.Timestamp
                $hostname  = $manifest.Hostname
            }
            catch {}
        }

        $sessionStr   = $session.Name.PadRight(20)
        $timestampStr = $timestamp.PadRight(20)
        $hostnameStr  = $hostname.PadRight(20)
        Write-Host "  │ $sessionStr │ $timestampStr │ $hostnameStr │" -ForegroundColor White
    }

    Write-Host "  └──────────────────────┴──────────────────────┴──────────────────────┘" -ForegroundColor Cyan
    Write-Host ""

    return $sessions
}
