#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Registry Hardening Module
.DESCRIPTION
    Aplica hardening de seguridad via registro de Windows:
    - PowerShell Security (Script Block Logging, Module Logging, PS v2)
    - Políticas de contraseña y cuentas
    - Configuraciones de seguridad del sistema (UAC, AutoPlay, etc.)
    - Protección contra exploits comunes
.NOTES
    Standard: CIS Benchmark, Microsoft Security Baseline
    MITRE: T1059.001 (PowerShell), T1547 (Boot Autostart)
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── HELPER: APLICAR CONFIGURACIÓN DE REGISTRO ────────────────────────────────

function Set-RegistrySetting {
    <#
    .SYNOPSIS
        Aplica una configuración de registro de forma segura con logging.
    .PARAMETER Path
        Ruta de la clave de registro.
    .PARAMETER Name
        Nombre del valor.
    .PARAMETER Value
        Valor a establecer.
    .PARAMETER Type
        Tipo de dato: DWord, String, Binary, QWord, MultiString, ExpandString.
    .PARAMETER Description
        Descripción para el log (control de seguridad que se aplica).
    .PARAMETER Reference
        Referencia al estándar (CIS, NIST, etc.).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord','String','Binary','QWord','MultiString','ExpandString')]
        [string]$Type        = 'DWord',
        [string]$Description = '',
        [string]$Reference   = ''
    )

    try {
        # Crear ruta si no existe
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        # Verificar valor actual
        $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue

        if ($null -ne $current -and $current.$Name -eq $Value) {
            Write-LogInfo "Ya configurado: $Description ($Name = $Value)" -Component 'Registry'
            return $true
        }

        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Establecer $Value")) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
            $logMsg = if ($Description) { $Description } else { "$Path\$Name = $Value" }
            $refStr = if ($Reference)   { " [$Reference]" } else { '' }
            Write-LogSuccess "Aplicado: $logMsg$refStr" -Component 'Registry'
            return $true
        }
    }
    catch {
        Write-LogError "Error aplicando $Path\$Name : $_" -Component 'Registry'
        return $false
    }

    return $false
}

# ─── HARDENING POWERSHELL ─────────────────────────────────────────────────────

function Invoke-PowerShellSecurityHardening {
    <#
    .SYNOPSIS
        Aplica configuraciones de seguridad para PowerShell.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: PowerShell Security"

    # Script Block Logging
    Set-RegistrySetting `
        -Path        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name        'EnableScriptBlockLogging' `
        -Value       1 `
        -Description 'PowerShell Script Block Logging habilitado' `
        -Reference   'CIS 18.9.95.1'

    Set-RegistrySetting `
        -Path        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name        'EnableScriptBlockInvocationLogging' `
        -Value       1 `
        -Description 'PowerShell Script Block Invocation Logging habilitado' `
        -Reference   'CIS 18.9.95.1'

    # Module Logging
    Set-RegistrySetting `
        -Path        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        -Name        'EnableModuleLogging' `
        -Value       1 `
        -Description 'PowerShell Module Logging habilitado' `
        -Reference   'CIS 18.9.95.2'

    Set-RegistrySetting `
        -Path        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
        -Name        '*' `
        -Type        'String' `
        -Value       '*' `
        -Description 'Logging de todos los módulos de PowerShell' `
        -Reference   'CIS 18.9.95.2'

    # Transcription Logging
    Set-RegistrySetting `
        -Path        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        -Name        'EnableTranscripting' `
        -Value       1 `
        -Description 'PowerShell Transcription habilitado' `
        -Reference   'CIS 18.9.95.3'

    # Protected Event Logging (cifrar logs de PS)
    Set-RegistrySetting `
        -Path        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' `
        -Name        'EnableProtectedEventLogging' `
        -Value       1 `
        -Description 'Protected Event Logging habilitado' `
        -Reference   'MS Security Baseline'

    # Deshabilitar PowerShell v2
    try {
        $ps2Feature = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue
        if ($null -ne $ps2Feature -and $ps2Feature.State -eq 'Enabled') {
            if ($PSCmdlet.ShouldProcess('PowerShell v2', 'Deshabilitar característica')) {
                Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -ErrorAction Stop | Out-Null
                Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2'     -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Write-LogSuccess "PowerShell v2 deshabilitado." -Component 'Registry'
            }
        }
        else {
            Write-LogInfo "PowerShell v2 ya está deshabilitado o no está instalado." -Component 'Registry'
        }
    }
    catch {
        Write-LogWarning "No se pudo deshabilitar PowerShell v2: $_" -Component 'Registry'
    }

    # Execution Policy (LocalMachine)
    try {
        $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine
        if ($currentPolicy -in @('Unrestricted', 'Bypass')) {
            if ($PSCmdlet.ShouldProcess('Execution Policy', 'Establecer RemoteSigned')) {
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
                Write-LogSuccess "Execution Policy establecida en RemoteSigned (LocalMachine)." -Component 'Registry'
            }
        }
        else {
            Write-LogInfo "Execution Policy: $currentPolicy (aceptable)." -Component 'Registry'
        }
    }
    catch {
        Write-LogWarning "No se pudo configurar Execution Policy: $_" -Component 'Registry'
    }
}

# ─── HARDENING: UAC ───────────────────────────────────────────────────────────

function Invoke-UacHardening {
    <#
    .SYNOPSIS
        Configura UAC (User Account Control) en modo más restrictivo.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: UAC (User Account Control)"

    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    # Habilitar UAC
    Set-RegistrySetting -Path $uacPath -Name 'EnableLUA' -Value 1 `
        -Description 'UAC habilitado' -Reference 'CIS 2.3.17.1'

    # Comportamiento para administradores: 2 = solicitar credenciales
    Set-RegistrySetting -Path $uacPath -Name 'ConsentPromptBehaviorAdmin' -Value 2 `
        -Description 'UAC: Solicitar credenciales para elevación de administradores' -Reference 'CIS 2.3.17.2'

    # Comportamiento para usuarios estándar: 1 = solicitar credenciales
    Set-RegistrySetting -Path $uacPath -Name 'ConsentPromptBehaviorUser' -Value 1 `
        -Description 'UAC: Solicitar credenciales para usuarios estándar' -Reference 'CIS 2.3.17.3'

    # Solo elevar ejecutables firmados y validados
    Set-RegistrySetting -Path $uacPath -Name 'ValidateAdminCodeSignatures' -Value 1 `
        -Description 'UAC: Solo elevar ejecutables firmados' -Reference 'CIS 2.3.17.7'

    # Deshabilitar virtualización de archivos/registro UAC para apps legacy
    Set-RegistrySetting -Path $uacPath -Name 'EnableVirtualization' -Value 1 `
        -Description 'UAC: Virtualización habilitada para apps legacy' -Reference 'CIS 2.3.17.8'

    # Secure Desktop para prompt de elevación
    Set-RegistrySetting -Path $uacPath -Name 'PromptOnSecureDesktop' -Value 1 `
        -Description 'UAC: Usar Secure Desktop para prompts' -Reference 'CIS 2.3.17.6'
}

# ─── HARDENING: AUTORUN / AUTOPLAY ────────────────────────────────────────────

function Invoke-AutoRunHardening {
    <#
    .SYNOPSIS
        Deshabilita AutoRun y AutoPlay para todos los tipos de medios.
        Previene ejecución automática de malware desde USB/CD.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: AutoRun y AutoPlay"

    # Deshabilitar AutoRun via registro (NoDriveTypeAutoRun = 0xFF = todos los drives)
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name  'NoDriveTypeAutoRun' -Value 0xFF `
        -Description 'AutoRun deshabilitado para todos los tipos de unidades' `
        -Reference 'CIS 18.8.45.1'

    Set-RegistrySetting `
        -Path  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name  'NoDriveTypeAutoRun' -Value 0xFF `
        -Description 'AutoRun deshabilitado (usuario actual)' -Reference 'CIS 18.8.45.1'

    # Deshabilitar AutoPlay via GPO
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        -Name  'NoAutoplayfornonVolume' -Value 1 `
        -Description 'AutoPlay deshabilitado para dispositivos no de volumen' `
        -Reference 'CIS 18.8.45.2'

    # Comportamiento por defecto de AutoPlay = No hacer nada
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        -Name  'NoAutorun' -Value 1 `
        -Description 'AutoRun deshabilitado via GPO' -Reference 'CIS 18.8.45.3'
}

# ─── HARDENING: WINDOWS REMOTE MANAGEMENT ─────────────────────────────────────

function Invoke-WinRMHardening {
    <#
    .SYNOPSIS
        Aplica hardening básico a WinRM si está habilitado.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: WinRM Security"

    # Verificar si WinRM está corriendo
    $winrmService = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
    if ($null -eq $winrmService -or $winrmService.Status -ne 'Running') {
        Write-LogInfo "WinRM no está en ejecución. Omitiendo hardening de WinRM." -Component 'Registry'
        return
    }

    # Requerir HTTPS para WinRM
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
        -Name  'AllowUnencrypted' -Value 0 `
        -Description 'WinRM: Bloquear tráfico no cifrado' -Reference 'CIS 18.9.100.1'

    # Deshabilitar autenticación básica en cliente WinRM
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
        -Name  'AllowBasic' -Value 0 `
        -Description 'WinRM Cliente: Deshabilitar autenticación Basic' -Reference 'CIS 18.9.100.2'

    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
        -Name  'AllowUnencrypted' -Value 0 `
        -Description 'WinRM Cliente: Bloquear tráfico no cifrado' -Reference 'CIS 18.9.100.3'

    # Deshabilitar autenticación Digest
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
        -Name  'AllowDigest' -Value 0 `
        -Description 'WinRM Cliente: Deshabilitar autenticación Digest' -Reference 'CIS 18.9.100.4'
}

# ─── HARDENING: CONFIGURACIONES MISCELÁNEAS ───────────────────────────────────

function Invoke-MiscSecurityHardening {
    <#
    .SYNOPSIS
        Aplica configuraciones de seguridad misceláneas importantes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Configuraciones de seguridad adicionales"

    # Deshabilitar Remote Registry
    try {
        $remoteReg = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
        if ($remoteReg -and $remoteReg.StartType -ne 'Disabled') {
            if ($PSCmdlet.ShouldProcess('RemoteRegistry', 'Deshabilitar servicio')) {
                Stop-Service  -Name 'RemoteRegistry' -Force -ErrorAction SilentlyContinue
                Set-Service   -Name 'RemoteRegistry' -StartupType Disabled
                Write-LogSuccess "Servicio RemoteRegistry deshabilitado." -Component 'Registry'
            }
        }
    }
    catch {
        Write-LogDebug "Error configurando RemoteRegistry: $_" -Component 'Registry'
    }

    # Deshabilitar Telemetría de Windows (nivel 0 = Security, solo para Enterprise/LTSC)
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -Name  'AllowTelemetry' -Value 0 `
        -Description 'Telemetría reducida al mínimo (nivel Security)' `
        -Reference 'CIS 18.9.16.1'

    # Deshabilitar Cortana
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        -Name  'AllowCortana' -Value 0 `
        -Description 'Cortana deshabilitado' -Reference 'CIS 18.9.14.1'

    # Deshabilitar indexación de red en Windows Search
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        -Name  'AllowIndexingEncryptedStoresOrItems' -Value 0 `
        -Description 'Indexación de contenido cifrado deshabilitada' `
        -Reference 'CIS 18.9.59.3'

    # Protección contra ataques de Spectre/Meltdown (Indirect Branch Prediction)
    Set-RegistrySetting `
        -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        -Name  'FeatureSettingsOverride' -Value 72 `
        -Description 'Mitigación Spectre/Meltdown (FeatureSettingsOverride)' `
        -Reference 'CVE-2017-5715 / CVE-2017-5754'

    Set-RegistrySetting `
        -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        -Name  'FeatureSettingsOverrideMask' -Value 3 `
        -Description 'Mitigación Spectre/Meltdown (FeatureSettingsOverrideMask)' `
        -Reference 'CVE-2017-5715 / CVE-2017-5754'

    # Deshabilitar Named Pipe impersonation nivel bajo
    Set-RegistrySetting `
        -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name  'RestrictAnonymous' -Value 1 `
        -Description 'Acceso anónimo a shares/named pipes restringido' `
        -Reference 'CIS 2.3.10.3'

    Set-RegistrySetting `
        -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name  'RestrictAnonymousSAM' -Value 1 `
        -Description 'Enumeración anónima del SAM restringida' `
        -Reference 'CIS 2.3.10.1'

    # EMET-like: Enable DEP (Data Execution Prevention)
    Set-RegistrySetting `
        -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' `
        -Name  'MitigationOptions' -Value 0x100 -Type QWord `
        -Description 'Kernel MitigationOptions (DEP/SEHOP)' `
        -Reference 'MS Security Baseline'

    # Deshabilitar Link-local Multicast (mDNS ya se hace en network.ps1)
    Set-RegistrySetting `
        -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        -Name  'EnableMulticast' -Value 0 `
        -Description 'LLMNR/Multicast deshabilitado (redundante con network.ps1)' `
        -Reference 'CIS 18.5.4.2'

    # Proteger claves SAM/SYSTEM contra acceso directo
    Set-RegistrySetting `
        -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name  'NoLMHash' -Value 1 `
        -Description 'Almacenamiento de hashes LAN Manager deshabilitado' `
        -Reference 'CIS 2.3.11.6 / MITRE T1003'
}

# ─── HARDENING: POLÍTICAS DE CONTRASEÑA ───────────────────────────────────────

function Invoke-PasswordPolicyHardening {
    <#
    .SYNOPSIS
        Aplica políticas de contraseña mínimas recomendadas via net accounts.
    .NOTES
        CIS 1.1.x / NIST IA-5
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Políticas de Contraseña"

    if ($PSCmdlet.ShouldProcess('Password Policy', 'Aplicar net accounts')) {
        try {
            net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-LogWarning "net accounts retornó código $LASTEXITCODE al aplicar políticas de contraseña." -Component 'Registry'
            }
            else {
                Write-LogSuccess "Políticas de contraseña aplicadas: minlen=12, maxage=90, minage=1, history=5." -Component 'Registry'
            }
        }
        catch {
            Write-LogWarning "Error al aplicar políticas de contraseña: $_" -Component 'Registry'
        }
    }
}

# ─── FUNCIÓN MAESTRA ──────────────────────────────────────────────────────────

function Invoke-RegistryHardening {
    <#
    .SYNOPSIS
        Ejecuta hardening completo via registro de Windows.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogInfo "Iniciando hardening de Registro..." -Component 'Registry'

    Invoke-PowerShellSecurityHardening
    Invoke-UacHardening
    Invoke-AutoRunHardening
    Invoke-WinRMHardening
    Invoke-MiscSecurityHardening
    Invoke-PasswordPolicyHardening

    Write-LogSuccess "Hardening de Registro completado." -Component 'Registry'
}
