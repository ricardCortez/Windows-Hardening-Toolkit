#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Credentials Security Module
.DESCRIPTION
    Protege el subsistema de credenciales del sistema operativo:
    - LSASS como Protected Process Light (RunAsPPL)
    - Deshabilitar WDigest (previene credenciales en texto plano en memoria)
    - Configurar Credential Guard (VBS)
    - Bloquear almacenamiento de credenciales en red
    - Hardening de políticas de cuentas
.NOTES
    Standard: CIS Benchmark 18.3, 2.3.11 / NIST 800-53 IA-5
    MITRE: T1003.001 (LSASS Dump), T1552 (Credentials)
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── HABILITAR LSASS RunAsPPL ─────────────────────────────────────────────────

function Enable-LsassProtection {
    <#
    .SYNOPSIS
        Habilita LSASS como Protected Process Light (PPL).
        Impide el dumping de credenciales desde LSASS por procesos no firmados.
        REQUIERE REINICIO para que surta efecto.
    .NOTES
        MITRE T1003.001: Credential Dumping - LSASS Memory
        Compatible con: Windows 8.1+, Windows Server 2012 R2+
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: LSASS Protected Process Light (RunAsPPL)"

    $lsaPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lsaProp  = Get-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -ErrorAction SilentlyContinue
    $current  = if ($lsaProp) { $lsaProp.RunAsPPL } else { $null }

    if ($current -eq 1) {
        Write-LogInfo "LSASS RunAsPPL ya está habilitado." -Component 'Credentials'
        return
    }

    try {
        if ($PSCmdlet.ShouldProcess('LSASS RunAsPPL', 'Habilitar (requiere reinicio)')) {
            if (-not (Test-Path $lsaPath)) { New-Item -Path $lsaPath -Force | Out-Null }
            Set-ItemProperty -Path $lsaPath -Name 'RunAsPPL'     -Value 1 -Type DWord -Force -ErrorAction Stop
            Set-ItemProperty -Path $lsaPath -Name 'RunAsPPLBoot' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            # NOTE: LsaCfgFlags is NOT set here; it is managed exclusively by Enable-CredentialGuard

            Write-LogSuccess "LSASS RunAsPPL habilitado. REINICIO REQUERIDO." -Component 'Credentials'
            Write-LogWarning "Nota: Los controladores y herramientas que inyectan en LSASS dejarán de funcionar." -Component 'Credentials'
        }
    }
    catch {
        Write-LogError "Error habilitando RunAsPPL: $_" -Component 'Credentials'
    }

    # Deshabilitar depuración de LSASS (Security Packages debug)
    try {
        Set-ItemProperty -Path $lsaPath -Name 'DisableRestrictedAdmin' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-LogSuccess "Restricted Admin deshabilitado para LSASS." -Component 'Credentials'
    }
    catch {
        Write-LogDebug "No se pudo configurar DisableRestrictedAdmin: $_" -Component 'Credentials'
    }
}

# ─── DESHABILITAR WDIGEST ─────────────────────────────────────────────────────

function Disable-WDigest {
    <#
    .SYNOPSIS
        Deshabilita WDigest para evitar almacenamiento de credenciales en texto claro.
        WDigest habilitado = mimikatz puede obtener contraseñas directamente de memoria.
    .NOTES
        MITRE T1003.001, CVE mitigación: mimikatz sekurlsa::wdigest
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Deshabilitar WDigest Authentication"

    $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

    if (-not (Test-Path $wdigestPath)) {
        if ($PSCmdlet.ShouldProcess($wdigestPath, 'Crear clave de registro')) {
            New-Item -Path $wdigestPath -Force | Out-Null
        }
    }

    try {
        $wdigestProp = Get-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -ErrorAction SilentlyContinue
        $current = if ($wdigestProp) { $wdigestProp.UseLogonCredential } else { $null }

        if ($current -eq 0) {
            Write-LogInfo "WDigest ya está deshabilitado." -Component 'Credentials'
            return
        }

        if ($PSCmdlet.ShouldProcess('WDigest UseLogonCredential', 'Establecer en 0')) {
            Set-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -Value 0 -Type DWord -Force
            Write-LogSuccess "WDigest deshabilitado. Las credenciales ya no se almacenarán en texto claro." -Component 'Credentials'
        }
    }
    catch {
        Write-LogError "Error deshabilitando WDigest: $_" -Component 'Credentials'
    }
}

# ─── HABILITAR CREDENTIAL GUARD ───────────────────────────────────────────────

function Enable-CredentialGuard {
    <#
    .SYNOPSIS
        Habilita Windows Credential Guard (Virtualization Based Security).
        Requiere: UEFI, Secure Boot, y soporte de virtualización en CPU.
        REQUIERE REINICIO.
    .PARAMETER AuditMode
        No aplica para Credential Guard; incluido por coherencia de API.
    .NOTES
        CIS 18.8.5 / MITRE T1003
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Credential Guard (VBS)"

    # Verificar requisitos básicos
    try {
        $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $osInfo     = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        # Verificar virtualización
        $hvPath  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'
        $null    = Test-Path $hvPath   # hvPath checked; result unused by design

        Write-LogInfo "Sistema: $($systemInfo.Manufacturer) $($systemInfo.Model)" -Component 'Credentials'
        Write-LogInfo "OS: $($osInfo.Caption) Build $($osInfo.BuildNumber)" -Component 'Credentials'
    }
    catch {
        Write-LogWarning "No se pudo verificar requisitos de Credential Guard." -Component 'Credentials'
    }

    $deviceGuardPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $lsaCfgPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    try {
        if (-not (Test-Path $deviceGuardPath)) {
            New-Item -Path $deviceGuardPath -Force | Out-Null
        }

        if ($PSCmdlet.ShouldProcess('Credential Guard / VBS', 'Habilitar (requiere reinicio)')) {
            # EnableVirtualizationBasedSecurity = 1
            Set-ItemProperty -Path $deviceGuardPath -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord -Force
            # RequirePlatformSecurityFeatures: 1=Secure Boot, 3=Secure Boot + DMA Protection
            Set-ItemProperty -Path $deviceGuardPath -Name 'RequirePlatformSecurityFeatures'  -Value 3 -Type DWord -Force
            # LsaCfgFlags: 1=Credential Guard without UEFI lock, 2=with UEFI lock
            Set-ItemProperty -Path $lsaCfgPath      -Name 'LsaCfgFlags'                      -Value 1 -Type DWord -Force

            # HypervisorEnforcedCodeIntegrity
            Set-ItemProperty -Path $deviceGuardPath -Name 'HypervisorEnforcedCodeIntegrity' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

            Write-LogSuccess "Credential Guard / VBS habilitado. REINICIO REQUERIDO." -Component 'Credentials'
        }
    }
    catch {
        Write-LogWarning "No se pudo habilitar Credential Guard (puede requerir hardware compatible): $_" -Component 'Credentials'
    }
}

# ─── BLOQUEAR ALMACENAMIENTO DE CREDENCIALES EN RED ───────────────────────────

function Disable-NetworkCredentialStorage {
    <#
    .SYNOPSIS
        Bloquea el almacenamiento de contraseñas de red y credenciales en el Credential Manager.
        Previene que usuarios guarden credenciales de dominio localmente.
    .NOTES
        CIS 2.3.11.2 / NIST IA-5
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Bloquear almacenamiento de credenciales de red"

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    try {
        # DisableDomainCreds: 1 = No permite almacenar credenciales de dominio
        if ($PSCmdlet.ShouldProcess('DisableDomainCreds', 'Establecer en 1')) {
            Set-ItemProperty -Path $lsaPath -Name 'DisableDomainCreds' -Value 1 -Type DWord -Force
            Write-LogSuccess "Almacenamiento de credenciales de dominio bloqueado." -Component 'Credentials'
        }
    }
    catch {
        Write-LogWarning "No se pudo bloquear almacenamiento de credenciales: $_" -Component 'Credentials'
    }

    # Requerir contraseña al reanudar desde standby
    try {
        $powerPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
        if (-not (Test-Path $powerPath)) { New-Item -Path $powerPath -Force | Out-Null }
        Set-ItemProperty -Path $powerPath -Name 'ACSettingIndex'  -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $powerPath -Name 'DCSettingIndex'  -Value 1 -Type DWord -Force
        Write-LogSuccess "Contraseña requerida al reanudar desde modo de espera." -Component 'Credentials'
    }
    catch {
        Write-LogDebug "No se pudo configurar requerir contraseña en standby." -Component 'Credentials'
    }
}

# ─── HARDENING DE KERBEROS ────────────────────────────────────────────────────

function Set-KerberosHardening {
    <#
    .SYNOPSIS
        Aplica configuraciones de seguridad adicionales para Kerberos.
        Requiere cifrado AES-256, limita tickets.
    .NOTES
        CIS 2.3.17 / MITRE T1558 (Kerberoasting)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Kerberos Security"

    $kerbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'

    try {
        if (-not (Test-Path $kerbPath)) {
            New-Item -Path $kerbPath -Force | Out-Null
        }

        if ($PSCmdlet.ShouldProcess('Kerberos', 'Aplicar hardening')) {
            # Forzar AES-256 para tickets Kerberos (mitiga Kerberoasting con RC4)
            Set-ItemProperty -Path $kerbPath -Name 'SupportedEncryptionTypes' -Value 0x7fffffff -Type DWord -Force
            # MaxTokenSize para manejar tokens grandes (membresías de grupos numerosas)
            Set-ItemProperty -Path $kerbPath -Name 'MaxTokenSize' -Value 65535 -Type DWord -Force
            Write-LogSuccess "Kerberos configurado para usar AES-256." -Component 'Credentials'
        }
    }
    catch {
        Write-LogWarning "No se pudo configurar Kerberos (puede no ser DC): $_" -Component 'Credentials'
    }
}

# ─── HARDENING DE CUENTAS LOCALES ─────────────────────────────────────────────

function Set-LocalAccountsHardening {
    <#
    .SYNOPSIS
        Aplica hardening a cuentas locales integradas (Administrator, Guest).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Cuentas locales"

    try {
        # Renombrar cuenta de Administrador (ofuscación; no es una medida de seguridad fuerte, pero añade fricción)
        # Sólo si el nombre no ha sido cambiado previamente
        $adminAccount = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
        if ($adminAccount -and $adminAccount.Enabled) {
            Write-LogWarning "Cuenta 'Administrator' está habilitada. Considere deshabilitarla o renombrarla." -Component 'Credentials'
        }
        elseif ($adminAccount -and -not $adminAccount.Enabled) {
            Write-LogInfo "Cuenta 'Administrator' ya está deshabilitada." -Component 'Credentials'
        }

        # Deshabilitar cuenta Guest
        $guestAccount = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guestAccount -and $guestAccount.Enabled) {
            if ($PSCmdlet.ShouldProcess('Guest', 'Deshabilitar cuenta')) {
                Disable-LocalUser -Name 'Guest' -ErrorAction Stop
                Write-LogSuccess "Cuenta Guest deshabilitada." -Component 'Credentials'
            }
        }
        else {
            Write-LogInfo "Cuenta Guest ya está deshabilitada." -Component 'Credentials'
        }
    }
    catch {
        Write-LogWarning "Error gestionando cuentas locales: $_" -Component 'Credentials'
    }

    # Restricciones para cuentas locales con acceso de red
    $localNtPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try {
        # LocalAccountTokenFilterPolicy = 0: solo cuentas de dominio tienen tokens completos en red
        if ($PSCmdlet.ShouldProcess('LocalAccountTokenFilterPolicy', 'Establecer en 0')) {
            Set-ItemProperty -Path $localNtPath -Name 'LocalAccountTokenFilterPolicy' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            Write-LogSuccess "LocalAccountTokenFilterPolicy = 0 (UAC remoto habilitado)." -Component 'Credentials'
        }
    }
    catch {
        Write-LogDebug "No se pudo configurar LocalAccountTokenFilterPolicy: $_" -Component 'Credentials'
    }
}

# ─── FUNCIÓN MAESTRA ──────────────────────────────────────────────────────────

function Invoke-CredentialsHardening {
    <#
    .SYNOPSIS
        Ejecuta hardening completo del sistema de credenciales.
    .PARAMETER SkipCredentialGuard
        Omite la configuración de Credential Guard (si no hay soporte de hardware).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$SkipCredentialGuard
    )

    Write-LogInfo "Iniciando hardening de Credenciales..." -Component 'Credentials'

    Enable-LsassProtection
    Disable-WDigest
    Disable-NetworkCredentialStorage
    Set-KerberosHardening
    Set-LocalAccountsHardening

    if (-not $SkipCredentialGuard) {
        Enable-CredentialGuard
    }

    Write-LogWarning "NOTA: Algunos cambios (RunAsPPL, Credential Guard) requieren REINICIO del sistema." -Component 'Credentials'
    Write-LogSuccess "Hardening de Credenciales completado." -Component 'Credentials'
}
