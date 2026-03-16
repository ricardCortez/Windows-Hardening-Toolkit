#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Network Security Module
.DESCRIPTION
    Deshabilita protocolos de red inseguros: SMBv1, NetBIOS, LLMNR, NTLMv1.
    Fuerza SMB Signing y deshabilita SMB Compression.
.NOTES
    Standard: CIS Benchmark 18.3, 18.5 / NIST 800-53 SC-8
    MITRE: T1557 (LLMNR/NBT-NS Poisoning), T1021.002 (SMB), T1550 (Pass-the-Hash)
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── DESHABILITAR SMBv1 ───────────────────────────────────────────────────────

function Disable-SmbV1 {
    <#
    .SYNOPSIS
        Deshabilita SMBv1 en servidor y cliente.
        Mitiga EternalBlue (MS17-010) y variantes de ransomware (WannaCry, NotPetya).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Deshabilitando SMBv1"

    # ── Servidor SMBv1 ──
    try {
        $current = Get-SmbServerConfiguration -ErrorAction Stop

        if (-not $current.EnableSMB1Protocol) {
            Write-LogInfo "SMBv1 Server ya está deshabilitado." -Component 'Network'
        }
        elseif ($PSCmdlet.ShouldProcess('SMBv1 Server', 'Deshabilitar')) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -ErrorAction Stop
            Write-LogSuccess "SMBv1 Server deshabilitado via cmdlet." -Component 'Network'
        }
    }
    catch {
        Write-LogWarning "No se pudo deshabilitar SMBv1 via cmdlet. Usando registro..." -Component 'Network'

        # Fallback: registro
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        try {
            if ($PSCmdlet.ShouldProcess('Registro SMBv1', 'Establecer valor 0')) {
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                Set-ItemProperty -Path $regPath -Name 'SMB1' -Value 0 -Type DWord -Force -ErrorAction Stop
                Write-LogSuccess "SMBv1 deshabilitado via registro." -Component 'Network'
            }
        }
        catch {
            Write-LogError "No se pudo deshabilitar SMBv1 via registro: $_" -Component 'Network'
        }
    }

    # ── Registro SMBv1 (siempre aplicar como respaldo adicional) ──
    try {
        $smb1RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        if ($PSCmdlet.ShouldProcess('Registro SMBv1 (refuerzo)', 'Establecer SMB1=0')) {
            if (-not (Test-Path $smb1RegPath)) { New-Item -Path $smb1RegPath -Force | Out-Null }
            Set-ItemProperty -Path $smb1RegPath -Name 'SMB1' -Value 0 -Type DWord -Force -ErrorAction Stop
            Write-LogSuccess "SMBv1 confirmado deshabilitado via registro." -Component 'Network'
        }
    }
    catch {
        Write-LogWarning "No se pudo confirmar SMBv1 via registro: $_" -Component 'Network'
    }

    # ── Cliente SMBv1 (servicio MrxSmb10) ──
    try {
        $mrxSmb10 = Get-Service -Name 'MrxSmb10' -ErrorAction SilentlyContinue
        if ($mrxSmb10 -and $mrxSmb10.StartType -ne 'Disabled') {
            if ($PSCmdlet.ShouldProcess('MrxSmb10', 'Deshabilitar servicio cliente SMBv1')) {
                Set-Service -Name 'MrxSmb10' -StartupType Disabled -ErrorAction Stop
                Write-LogSuccess "Servicio MrxSmb10 (cliente SMBv1) deshabilitado." -Component 'Network'
            }
        }
        elseif ($null -eq $mrxSmb10) {
            Write-LogInfo "Servicio MrxSmb10 no encontrado (SMBv1 cliente no instalado)." -Component 'Network'
        }
    }
    catch {
        Write-LogWarning "No se pudo deshabilitar MrxSmb10: $_" -Component 'Network'
    }

    # ── Característica opcional de Windows ──
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
        if ($null -ne $feature -and $feature.State -eq 'Enabled') {
            if ($PSCmdlet.ShouldProcess('SMB1Protocol Feature', 'Deshabilitar característica de Windows')) {
                Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -ErrorAction Stop | Out-Null
                Write-LogSuccess "Característica SMB1Protocol deshabilitada (requiere reinicio)." -Component 'Network'
            }
        }
    }
    catch {
        Write-LogDebug "No se pudo verificar característica SMB1Protocol: $_" -Component 'Network'
    }
}

# ─── FORZAR SMB SIGNING ───────────────────────────────────────────────────────

function Enable-SmbSigning {
    <#
    .SYNOPSIS
        Fuerza la firma digital en comunicaciones SMB (servidor y cliente).
        Previene ataques MITM sobre SMB (relay attacks).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Forzando SMB Signing"

    try {
        $smbConf = Get-SmbServerConfiguration -ErrorAction Stop

        # Servidor: RequireSecuritySignature
        if (-not $smbConf.RequireSecuritySignature) {
            if ($PSCmdlet.ShouldProcess('SMB Server Signing', 'Habilitar firma requerida')) {
                Set-SmbServerConfiguration `
                    -RequireSecuritySignature $true `
                    -EnableSecuritySignature  $true `
                    -Confirm:$false `
                    -ErrorAction Stop
                Write-LogSuccess "SMB Signing requerido en servidor." -Component 'Network'
            }
        }
        else {
            Write-LogInfo "SMB Server Signing ya está habilitado." -Component 'Network'
        }
    }
    catch {
        Write-LogError "Error configurando SMB Signing en servidor: $_" -Component 'Network'
    }

    # Cliente SMB Signing via registro
    try {
        $clientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        $clientProp = Get-ItemProperty -Path $clientPath -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue
        $currentReq = if ($clientProp) { $clientProp.RequireSecuritySignature } else { $null }

        if ($currentReq -ne 1) {
            if ($PSCmdlet.ShouldProcess('SMB Client Signing', 'Habilitar firma requerida')) {
                Set-ItemProperty -Path $clientPath -Name 'RequireSecuritySignature' -Value 1 -Type DWord -Force
                Set-ItemProperty -Path $clientPath -Name 'EnableSecuritySignature'  -Value 1 -Type DWord -Force
                Write-LogSuccess "SMB Signing requerido en cliente." -Component 'Network'
            }
        }
        else {
            Write-LogInfo "SMB Client Signing ya está habilitado." -Component 'Network'
        }
    }
    catch {
        Write-LogError "Error configurando SMB Signing en cliente: $_" -Component 'Network'
    }
}

# ─── DESHABILITAR SMB COMPRESSION ─────────────────────────────────────────────

function Disable-SmbCompression {
    <#
    .SYNOPSIS
        Deshabilita la compresión SMB para mitigar CVE-2020-0796 (SMBGhost).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Deshabilitando SMB Compression"

    try {
        $smbConf = Get-SmbServerConfiguration -ErrorAction Stop

        if ($smbConf.DisableCompression) {
            Write-LogInfo "SMB Compression ya está deshabilitada." -Component 'Network'
            return
        }

        if ($PSCmdlet.ShouldProcess('SMB Compression', 'Deshabilitar')) {
            Set-SmbServerConfiguration -DisableCompression $true -Confirm:$false -ErrorAction Stop
            Write-LogSuccess "SMB Compression deshabilitada (mitiga CVE-2020-0796)." -Component 'Network'
        }
    }
    catch {
        # Propiedad no disponible en versiones antiguas de Windows, usar registro
        Write-LogDebug "DisableCompression no disponible via cmdlet. Usando registro..." -Component 'Network'
        try {
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            if ($PSCmdlet.ShouldProcess('Registro SMB Compression', 'Deshabilitar')) {
                Set-ItemProperty -Path $regPath -Name 'DisableCompression' -Value 1 -Type DWord -Force
                Write-LogSuccess "SMB Compression deshabilitada via registro." -Component 'Network'
            }
        }
        catch {
            Write-LogWarning "No se pudo deshabilitar SMB Compression: $_" -Component 'Network'
        }
    }
}

# ─── DESHABILITAR NETBIOS SOBRE TCP/IP ────────────────────────────────────────

function Disable-NetBiosOverTcpIp {
    <#
    .SYNOPSIS
        Deshabilita NetBIOS sobre TCP/IP en todos los adaptadores de red activos.
        NetBIOS = TcpipNetbiosOptions 2 (deshabilitado), 0 o 1 (habilitado).
        Previene NBT-NS poisoning y ataques de reconocimiento de red.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Deshabilitando NetBIOS sobre TCP/IP"

    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop

        $changed = 0

        foreach ($adapter in $adapters) {
            if ($adapter.TcpipNetbiosOptions -eq 2) {
                Write-LogInfo "Adaptador '$($adapter.Description)': NetBIOS ya deshabilitado." -Component 'Network'
                continue
            }

            if ($PSCmdlet.ShouldProcess($adapter.Description, "Deshabilitar NetBIOS")) {
                # SetTcpipNetbios: 0=Default(via DHCP), 1=Enabled, 2=Disabled
                $result = $adapter.SetTcpipNetbios(2)

                if ($result.ReturnValue -eq 0) {
                    Write-LogSuccess "NetBIOS deshabilitado en: $($adapter.Description)" -Component 'Network'
                    $changed++
                }
                else {
                    Write-LogWarning "No se pudo deshabilitar NetBIOS en $($adapter.Description). Código: $($result.ReturnValue)" -Component 'Network'
                }
            }
        }

        # También deshabilitar via clave de registro global como respaldo
        $netbiosRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        if (Test-Path $netbiosRegPath) {
            $interfaces = Get-ChildItem -Path $netbiosRegPath -ErrorAction SilentlyContinue
            foreach ($iface in $interfaces) {
                Set-ItemProperty -Path $iface.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }

        Write-LogInfo "NetBIOS deshabilitado en $changed adaptador(es)." -Component 'Network'
    }
    catch {
        Write-LogError "Error deshabilitando NetBIOS: $_" -Component 'Network'
    }
}

# ─── DESHABILITAR LLMNR ────────────────────────────────────────────────────────

function Disable-Llmnr {
    <#
    .SYNOPSIS
        Deshabilita LLMNR (Link-Local Multicast Name Resolution) via registro.
        Previene ataques de responder/poisoning (MITRE T1557).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Deshabilitando LLMNR"

    $llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'

    try {
        # Crear clave si no existe
        if (-not (Test-Path $llmnrPath)) {
            if ($PSCmdlet.ShouldProcess($llmnrPath, 'Crear clave de registro')) {
                New-Item -Path $llmnrPath -Force | Out-Null
            }
        }

        $current = Get-ItemProperty -Path $llmnrPath -Name 'EnableMulticast' -ErrorAction SilentlyContinue

        if ($null -ne $current -and $current.EnableMulticast -eq 0) {
            Write-LogInfo "LLMNR ya está deshabilitado." -Component 'Network'
            return
        }

        if ($PSCmdlet.ShouldProcess('LLMNR EnableMulticast', 'Establecer en 0 (deshabilitado)')) {
            Set-ItemProperty -Path $llmnrPath -Name 'EnableMulticast' -Value 0 -Type DWord -Force
            Write-LogSuccess "LLMNR deshabilitado (previene responder/poisoning)." -Component 'Network'
        }
    }
    catch {
        Write-LogError "Error deshabilitando LLMNR: $_" -Component 'Network'
    }
}

# ─── FORZAR NTLM v2 (DESHABILITAR NTLMv1) ────────────────────────────────────

function Disable-NtlmV1 {
    <#
    .SYNOPSIS
        Configura LmCompatibilityLevel = 5 para aceptar solo NTLMv2.
        Previene ataques pass-the-hash con hashes LM/NTLMv1 (MITRE T1550).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Forzando NTLMv2 (deshabilitando NTLMv1/LM)"

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    try {
        $current = Get-ItemProperty -Path $lsaPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
        $level   = if ($null -ne $current) { $current.LmCompatibilityLevel } else { 3 }

        if ($level -ge 5) {
            Write-LogInfo "NTLMv2 ya está forzado (nivel $level)." -Component 'Network'
        }
        elseif ($PSCmdlet.ShouldProcess('LmCompatibilityLevel', 'Establecer en 5')) {
            Set-ItemProperty -Path $lsaPath -Name 'LmCompatibilityLevel' -Value 5 -Type DWord -Force
            Write-LogSuccess "LmCompatibilityLevel = 5: Solo NTLMv2 aceptado." -Component 'Network'
        }

        # También configurar NTLMMinClientSec y NTLMMinServerSec para requerir NTLMv2 con 128-bit encryption
        $ntlmPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        if (-not (Test-Path $ntlmPath)) { New-Item -Path $ntlmPath -Force | Out-Null }

        if ($PSCmdlet.ShouldProcess('NTLM Security', 'Forzar 128-bit encryption')) {
            # 0x20080000 = Require NTLMv2 + 128-bit encryption
            Set-ItemProperty -Path $ntlmPath -Name 'NtlmMinClientSec' -Value 0x20080000 -Type DWord -Force
            Set-ItemProperty -Path $ntlmPath -Name 'NtlmMinServerSec' -Value 0x20080000 -Type DWord -Force
            Write-LogSuccess "NTLM configurado para requerir NTLMv2 + 128-bit session security." -Component 'Network'
        }
    }
    catch {
        Write-LogError "Error configurando NTLMv2: $_" -Component 'Network'
    }
}

# ─── DESHABILITAR mDNS ────────────────────────────────────────────────────────

function Disable-mDns {
    <#
    .SYNOPSIS
        Deshabilita mDNS en el servicio DNS de Windows para reducir superficie de ataque.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $mdnsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'

    try {
        if ($PSCmdlet.ShouldProcess('mDNS', 'Deshabilitar')) {
            if (-not (Test-Path $mdnsPath)) { New-Item -Path $mdnsPath -Force | Out-Null }
            Set-ItemProperty -Path $mdnsPath -Name 'EnableMDNS' -Value 0 -Type DWord -Force
            Write-LogSuccess "mDNS deshabilitado." -Component 'Network'
        }
    }
    catch {
        Write-LogWarning "No se pudo deshabilitar mDNS: $_" -Component 'Network'
    }
}

# ─── FUNCIÓN MAESTRA DE HARDENING DE RED ──────────────────────────────────────

function Invoke-NetworkHardening {
    <#
    .SYNOPSIS
        Ejecuta hardening completo de protocolos de red.
    .PARAMETER BasicOnly
        Solo aplica las configuraciones más críticas (SMBv1, LLMNR, NetBIOS).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$BasicOnly
    )

    Write-LogInfo "Iniciando hardening de Red..." -Component 'Network'

    Disable-SmbV1
    Enable-SmbSigning
    Disable-SmbCompression
    Disable-NetBiosOverTcpIp
    Disable-Llmnr
    Disable-NtlmV1

    if (-not $BasicOnly) {
        Disable-mDns
    }

    Write-LogSuccess "Hardening de Red completado." -Component 'Network'
}
