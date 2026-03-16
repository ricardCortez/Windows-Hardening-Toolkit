#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Audit Module
.DESCRIPTION
    Audita el estado actual de seguridad del sistema clasificando cada control
    como SECURE, WARNING o VULNERABLE según CIS Benchmarks y Microsoft Baselines.
.NOTES
    Standard: CIS Benchmark for Windows, NIST 800-53 CA-7, MITRE ATT&CK
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── ESTADO GLOBAL DE AUDITORÍA ───────────────────────────────────────────────

$Script:AuditResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# ─── HELPERS DE RESULTADO ─────────────────────────────────────────────────────

function New-AuditResult {
    param(
        [string]$Category,
        [string]$Control,
        [string]$Status,        # SECURE | WARNING | VULNERABLE
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [string]$Remediation,
        [string]$Reference = ''
    )

    $result = [PSCustomObject]@{
        Timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Category     = $Category
        Control      = $Control
        Status       = $Status
        CurrentValue = $CurrentValue
        ExpectedValue= $ExpectedValue
        Remediation  = $Remediation
        Reference    = $Reference
    }

    $Script:AuditResults.Add($result)

    # Color en consola según estado
    $statusColor = switch ($Status) {
        'SECURE'     { 'Green'  }
        'WARNING'    { 'Yellow' }
        'VULNERABLE' { 'Red'    }
        default      { 'Gray'   }
    }

    $icon = switch ($Status) {
        'SECURE'     { '[OK]  ' }
        'WARNING'    { '[WARN]' }
        'VULNERABLE' { '[VULN]' }
        default      { '[----]' }
    }

    Write-Host "  " -NoNewline
    Write-Host "$icon" -NoNewline -ForegroundColor $statusColor
    Write-Host " $Category" -NoNewline -ForegroundColor Cyan
    Write-Host " | $Control" -NoNewline
    Write-Host " => $CurrentValue" -ForegroundColor DarkGray
}

function Get-AuditResults {
    return $Script:AuditResults
}

function Clear-AuditResults {
    $Script:AuditResults.Clear()
}

# ─── AUDITORÍA: FIREWALL ──────────────────────────────────────────────────────

function Invoke-FirewallAudit {
    Write-LogSection "Auditoría: Windows Firewall"

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop

        foreach ($fwProfile in $profiles) {
            $status = if ($fwProfile.Enabled) { 'SECURE' } else { 'VULNERABLE' }
            New-AuditResult `
                -Category   'Firewall' `
                -Control    "Perfil $($fwProfile.Name)" `
                -Status     $status `
                -CurrentValue $(if ($fwProfile.Enabled) { 'Habilitado' } else { 'Deshabilitado' }) `
                -ExpectedValue 'Habilitado' `
                -Remediation "Set-NetFirewallProfile -Name $($fwProfile.Name) -Enabled True" `
                -Reference  'CIS 9.1 / NIST SC-7'
        }

        # Verificar política de bloqueo por defecto (tráfico entrante)
        foreach ($fwProfile in $profiles) {
            $status = if ($fwProfile.DefaultInboundAction -eq 'Block') { 'SECURE' } else { 'WARNING' }
            New-AuditResult `
                -Category   'Firewall' `
                -Control    "DefaultInbound $($fwProfile.Name)" `
                -Status     $status `
                -CurrentValue $fwProfile.DefaultInboundAction `
                -ExpectedValue 'Block' `
                -Remediation 'Set-NetFirewallProfile -DefaultInboundAction Block' `
                -Reference  'CIS 9.2'
        }
    }
    catch {
        Write-LogError "Error auditando firewall: $_" -Component 'Audit'
        New-AuditResult -Category 'Firewall' -Control 'Estado general' -Status 'VULNERABLE' `
            -CurrentValue 'Error al consultar' -ExpectedValue 'Habilitado' `
            -Remediation 'Verificar servicio MpsSvc' -Reference 'CIS 9.1'
    }
}

# ─── AUDITORÍA: SMB ───────────────────────────────────────────────────────────

function Invoke-SmbAudit {
    Write-LogSection "Auditoría: SMB"

    # SMBv1
    try {
        $smb1 = Get-SmbServerConfiguration -ErrorAction Stop
        $smb1Status = if (-not $smb1.EnableSMB1Protocol) { 'SECURE' } else { 'VULNERABLE' }
        New-AuditResult `
            -Category   'Network' `
            -Control    'SMBv1 Protocol' `
            -Status     $smb1Status `
            -CurrentValue $(if ($smb1.EnableSMB1Protocol) { 'Habilitado (PELIGROSO)' } else { 'Deshabilitado' }) `
            -ExpectedValue 'Deshabilitado' `
            -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false' `
            -Reference  'CIS 18.3.3 / MS-LAPS / EternalBlue mitigation'
    }
    catch {
        Write-LogWarning "No se pudo consultar SMBv1 via Get-SmbServerConfiguration" -Component 'Audit'
        # Fallback vía registro
        $regVal = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                                   -Name 'SMB1' -ErrorAction SilentlyContinue
        $smb1Enabled = if ($null -eq $regVal -or $regVal.SMB1 -ne 0) { $true } else { $false }
        $status = if (-not $smb1Enabled) { 'SECURE' } else { 'VULNERABLE' }
        New-AuditResult -Category 'Network' -Control 'SMBv1 (registry)' -Status $status `
            -CurrentValue $(if ($smb1Enabled) { 'Habilitado' } else { 'Deshabilitado' }) `
            -ExpectedValue 'Deshabilitado' `
            -Remediation 'Set-ItemProperty HKLM:\...LanmanServer\Parameters SMB1 0' `
            -Reference 'CIS 18.3.3'
    }

    # SMB Signing
    try {
        $smbConf = Get-SmbServerConfiguration -ErrorAction Stop
        $signingStatus = if ($smbConf.RequireSecuritySignature) { 'SECURE' } else { 'WARNING' }
        New-AuditResult `
            -Category   'Network' `
            -Control    'SMB Signing requerido' `
            -Status     $signingStatus `
            -CurrentValue $(if ($smbConf.RequireSecuritySignature) { 'Habilitado' } else { 'Deshabilitado' }) `
            -ExpectedValue 'Habilitado' `
            -Remediation 'Set-SmbServerConfiguration -RequireSecuritySignature $true' `
            -Reference  'CIS 18.3.6'
    }
    catch {
        Write-LogWarning "No se pudo consultar SMB Signing" -Component 'Audit'
    }

    # SMB Compression
    try {
        $smbConf = Get-SmbServerConfiguration -ErrorAction Stop
        $compressStatus = if (-not $smbConf.DisableCompression) { 'WARNING' } else { 'SECURE' }
        New-AuditResult `
            -Category   'Network' `
            -Control    'SMB Compression' `
            -Status     $compressStatus `
            -CurrentValue $(if ($smbConf.DisableCompression) { 'Deshabilitada' } else { 'Habilitada' }) `
            -ExpectedValue 'Deshabilitada' `
            -Remediation 'Set-SmbServerConfiguration -DisableCompression $true' `
            -Reference  'CVE-2020-0796 mitigation'
    }
    catch {
        Write-LogDebug "SMB Compression no disponible en esta versión de Windows" -Component 'Audit'
    }
}

# ─── AUDITORÍA: NETBIOS / LLMNR ───────────────────────────────────────────────

function Invoke-NetBiosLlmnrAudit {
    Write-LogSection "Auditoría: NetBIOS y LLMNR"

    # NetBIOS sobre TCP/IP
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
                                    -Filter 'IPEnabled = True' -ErrorAction Stop
        $netbiosEnabled = $adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 }

        $status = if ($netbiosEnabled) { 'VULNERABLE' } else { 'SECURE' }
        New-AuditResult `
            -Category   'Network' `
            -Control    'NetBIOS sobre TCP/IP' `
            -Status     $status `
            -CurrentValue $(if ($netbiosEnabled) { "Habilitado en $($netbiosEnabled.Count) adaptador(es)" } else { 'Deshabilitado' }) `
            -ExpectedValue 'Deshabilitado en todos los adaptadores' `
            -Remediation 'Iterar adaptadores y establecer TcpipNetbiosOptions = 2' `
            -Reference  'CIS 18.5.4 / MITRE T1171'
    }
    catch {
        Write-LogWarning "Error auditando NetBIOS: $_" -Component 'Audit'
    }

    # LLMNR
    $llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $llmnrVal  = Get-ItemProperty -Path $llmnrPath -Name 'EnableMulticast' -ErrorAction SilentlyContinue

    $llmnrEnabled = ($null -eq $llmnrVal -or $llmnrVal.EnableMulticast -ne 0)
    $status = if (-not $llmnrEnabled) { 'SECURE' } else { 'VULNERABLE' }

    New-AuditResult `
        -Category   'Network' `
        -Control    'LLMNR (Link-Local Multicast)' `
        -Status     $status `
        -CurrentValue $(if ($llmnrEnabled) { 'Habilitado (responder vulnerable)' } else { 'Deshabilitado' }) `
        -ExpectedValue 'Deshabilitado' `
        -Remediation 'GPO: Computer Config > Admin Templates > DNS Client > Turn off Multicast' `
        -Reference  'CIS 18.5.4.2 / MITRE T1557'
}

# ─── AUDITORÍA: NTLM ──────────────────────────────────────────────────────────

function Invoke-NtlmAudit {
    Write-LogSection "Auditoría: NTLM"

    $ntlmPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $ntlmVal  = Get-ItemProperty -Path $ntlmPath -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue

    $level  = if ($null -eq $ntlmVal) { 3 } else { $ntlmVal.LmCompatibilityLevel }  # Default es 3 en W10
    $status = switch ($level) {
        { $_ -ge 5 } { 'SECURE'     }
        { $_ -eq 4 } { 'WARNING'    }
        default      { 'VULNERABLE' }
    }

    $levelDesc = switch ($level) {
        0 { 'LM y NTLMv1 permitidos' }
        1 { 'LM y NTLMv1 con session security' }
        2 { 'Solo NTLMv1' }
        3 { 'Solo NTLMv2 (cliente)' }
        4 { 'NTLMv1 rechazado (servidor)' }
        5 { 'Solo NTLMv2 aceptado' }
        default { "Nivel desconocido: $level" }
    }

    New-AuditResult `
        -Category   'Authentication' `
        -Control    'NTLM LM Compatibility Level' `
        -Status     $status `
        -CurrentValue "Nivel $level - $levelDesc" `
        -ExpectedValue 'Nivel 5 (solo NTLMv2)' `
        -Remediation 'Set-ItemProperty HKLM:\SYSTEM\...\Lsa LmCompatibilityLevel 5' `
        -Reference  'CIS 2.3.11.7 / MITRE T1550'
}

# ─── AUDITORÍA: TLS ───────────────────────────────────────────────────────────

function Invoke-TlsAudit {
    Write-LogSection "Auditoría: TLS/SSL"

    $tlsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

    $protocols = @{
        'SSL 2.0'   = @{ Path = "$tlsBase\SSL 2.0\Server";  ExpectedEnabled = $false }
        'SSL 3.0'   = @{ Path = "$tlsBase\SSL 3.0\Server";  ExpectedEnabled = $false }
        'TLS 1.0'   = @{ Path = "$tlsBase\TLS 1.0\Server";  ExpectedEnabled = $false }
        'TLS 1.1'   = @{ Path = "$tlsBase\TLS 1.1\Server";  ExpectedEnabled = $false }
        'TLS 1.2'   = @{ Path = "$tlsBase\TLS 1.2\Server";  ExpectedEnabled = $true  }
        'TLS 1.3'   = @{ Path = "$tlsBase\TLS 1.3\Server";  ExpectedEnabled = $true  }
    }

    foreach ($proto in $protocols.GetEnumerator()) {
        $regVal  = Get-ItemProperty -Path $proto.Value.Path -Name 'Enabled'           -ErrorAction SilentlyContinue
        $null    = Get-ItemProperty -Path $proto.Value.Path -Name 'DisabledByDefault' -ErrorAction SilentlyContinue

        # Si la clave no existe, asumimos estado por defecto del SO
        $isEnabled = if ($null -eq $regVal) {
            switch ($proto.Key) {
                'TLS 1.2' { $true }
                'TLS 1.3' { $true }   # W11 / Server 2022
                default   { $false }  # W10+ desactiva SSL/TLS 1.0/1.1 por GPO
            }
        } else {
            $regVal.Enabled -ne 0
        }

        $shouldBeEnabled = $proto.Value.ExpectedEnabled
        $status = if ($isEnabled -eq $shouldBeEnabled) { 'SECURE' } elseif ($shouldBeEnabled -and -not $isEnabled) { 'WARNING' } else { 'VULNERABLE' }
        $currentDesc = if ($isEnabled) { 'Habilitado' } else { 'Deshabilitado' }
        $expectedDesc = if ($shouldBeEnabled) { 'Habilitado' } else { 'Deshabilitado' }

        New-AuditResult `
            -Category   'TLS' `
            -Control    $proto.Key `
            -Status     $status `
            -CurrentValue $currentDesc `
            -ExpectedValue $expectedDesc `
            -Remediation "Configurar registro SCHANNEL para $($proto.Key)" `
            -Reference  'CIS 18.10 / NIST SP 800-52 Rev.2'
    }
}

# ─── AUDITORÍA: MICROSOFT DEFENDER ────────────────────────────────────────────

function Invoke-DefenderAudit {
    Write-LogSection "Auditoría: Microsoft Defender"

    try {
        $defStatus = Get-MpComputerStatus -ErrorAction Stop

        # Protección en tiempo real
        $status = if ($defStatus.RealTimeProtectionEnabled) { 'SECURE' } else { 'VULNERABLE' }
        New-AuditResult -Category 'Defender' -Control 'Real-Time Protection' -Status $status `
            -CurrentValue $(if ($defStatus.RealTimeProtectionEnabled) { 'Activa' } else { 'Inactiva' }) `
            -ExpectedValue 'Activa' `
            -Remediation 'Set-MpPreference -DisableRealtimeMonitoring $false' `
            -Reference 'CIS 18.9.45 / MITRE T1562.001'

        # Network Protection
        $netProt = switch ($defStatus.EnableNetworkProtection) {
            1       { 'Habilitada (Block)' }
            2       { 'Modo Audit' }
            default { 'Deshabilitada' }
        }
        $npStatus = if ($defStatus.EnableNetworkProtection -eq 1) { 'SECURE' } `
                    elseif ($defStatus.EnableNetworkProtection -eq 2) { 'WARNING' } `
                    else { 'VULNERABLE' }
        New-AuditResult -Category 'Defender' -Control 'Network Protection' -Status $npStatus `
            -CurrentValue $netProt -ExpectedValue 'Habilitada (Block)' `
            -Remediation 'Set-MpPreference -EnableNetworkProtection Enabled' `
            -Reference 'CIS 18.9.45.4.2 / MITRE T1566'

        # Controlled Folder Access
        $cfaDesc = switch ($defStatus.EnableControlledFolderAccess) {
            1       { 'Habilitado' }
            2       { 'Modo Audit' }
            default { 'Deshabilitado' }
        }
        $cfaStatus = if ($defStatus.EnableControlledFolderAccess -eq 1) { 'SECURE' } `
                     elseif ($defStatus.EnableControlledFolderAccess -eq 2) { 'WARNING' } `
                     else { 'VULNERABLE' }
        New-AuditResult -Category 'Defender' -Control 'Controlled Folder Access' -Status $cfaStatus `
            -CurrentValue $cfaDesc -ExpectedValue 'Habilitado' `
            -Remediation 'Set-MpPreference -EnableControlledFolderAccess Enabled' `
            -Reference 'CIS 18.9.45.5 / MITRE T1486'

        # Antivirus Signature Age
        $sigAge = (Get-Date) - $defStatus.AntivirusSignatureLastUpdated
        $sigStatus = if ($sigAge.TotalDays -le 1) { 'SECURE' } `
                     elseif ($sigAge.TotalDays -le 3) { 'WARNING' } `
                     else { 'VULNERABLE' }
        New-AuditResult -Category 'Defender' -Control 'Firmas de antivirus' -Status $sigStatus `
            -CurrentValue "Última actualización: $($defStatus.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm'))" `
            -ExpectedValue 'Menos de 24 horas' `
            -Remediation 'Update-MpSignature' -Reference 'CIS 18.9.45.2'
    }
    catch {
        Write-LogWarning "No se pudo consultar estado de Defender (puede requerir elevación): $_" -Component 'Audit'
        New-AuditResult -Category 'Defender' -Control 'Estado general' -Status 'WARNING' `
            -CurrentValue 'No se pudo consultar' -ExpectedValue 'Activo y actualizado' `
            -Remediation 'Verificar que el proceso MsMpEng está corriendo' -Reference 'CIS 18.9.45'
    }
}

# ─── AUDITORÍA: ASR RULES ─────────────────────────────────────────────────────

function Invoke-AsrAudit {
    Write-LogSection "Auditoría: ASR Rules (Attack Surface Reduction)"

    # GUIDs de las reglas ASR recomendadas por Microsoft
    $recommendedRules = @{
        'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email/webmail'
        '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office apps from injecting into processes'
        '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office apps from creating executable content'
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block Office apps from child process creation'
        'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JS/VBS from downloaded executable content'
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block obfuscated script execution'
        '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
        '01443614-CD74-433A-B99E-2ECDC07BFC25' = 'Block executable files unless meet prevalence criteria'
        'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Use advanced ransomware protection'
        '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from LSASS'
        'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Block process creation from PSExec and WMI'
        'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted and unsigned USB processes'
        '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office comm app from child process creation'
        '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader from child process creation'
        'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'Block persistence through WMI event subscription'
    }

    try {
        $mpPrefs = Get-MpPreference -ErrorAction Stop
        $enabledRules = $mpPrefs.AttackSurfaceReductionRules_Ids
        $ruleActions  = $mpPrefs.AttackSurfaceReductionRules_Actions

        $totalRules   = $recommendedRules.Count
        $enabledCount = 0

        foreach ($rule in $recommendedRules.GetEnumerator()) {
            $idx = if ($enabledRules) { [Array]::IndexOf($enabledRules, $rule.Key) } else { -1 }
            $action = if ($idx -ge 0 -and $ruleActions) { $ruleActions[$idx] } else { -1 }

            $ruleStatus = switch ($action) {
                1       { $enabledCount++; 'SECURE'  }
                2       { 'WARNING'   }   # Audit mode
                default { 'VULNERABLE' }
            }

            $actionDesc = switch ($action) {
                1       { 'Block (activo)' }
                2       { 'Audit (solo registro)' }
                6       { 'Warn' }
                default { 'Deshabilitado' }
            }

            New-AuditResult -Category 'ASR' -Control $rule.Value -Status $ruleStatus `
                -CurrentValue $actionDesc -ExpectedValue 'Block (activo)' `
                -Remediation "Add-MpPreference -AttackSurfaceReductionRules_Ids '$($rule.Key)' -AttackSurfaceReductionRules_Actions Enabled" `
                -Reference 'MITRE ATT&CK Mitigation'
        }

        Write-LogInfo "ASR: $enabledCount/$totalRules reglas en modo Block." -Component 'Audit'
    }
    catch {
        Write-LogWarning "No se pudo auditar reglas ASR: $_" -Component 'Audit'
    }
}

# ─── AUDITORÍA: CREDENCIALES / LSASS ──────────────────────────────────────────

function Invoke-CredentialsAudit {
    Write-LogSection "Auditoría: Protección de Credenciales"

    # LSASS RunAsPPL
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $pplVal  = Get-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -ErrorAction SilentlyContinue
    $pplStatus = if ($pplVal -and $pplVal.RunAsPPL -eq 1) { 'SECURE' } else { 'VULNERABLE' }
    New-AuditResult -Category 'Credentials' -Control 'LSASS RunAsPPL' -Status $pplStatus `
        -CurrentValue $(if ($pplVal -and $pplVal.RunAsPPL -eq 1) { 'Habilitado' } else { 'Deshabilitado' }) `
        -ExpectedValue 'Habilitado' `
        -Remediation 'Set-ItemProperty HKLM:\SYSTEM\...\Lsa RunAsPPL 1 (requiere reinicio)' `
        -Reference 'CIS 18.3.1 / MITRE T1003.001'

    # WDigest
    $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    $wdigestVal  = Get-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -ErrorAction SilentlyContinue
    $wdigestEnabled = ($null -ne $wdigestVal -and $wdigestVal.UseLogonCredential -eq 1)
    $wdStatus = if (-not $wdigestEnabled) { 'SECURE' } else { 'VULNERABLE' }
    New-AuditResult -Category 'Credentials' -Control 'WDigest Authentication' -Status $wdStatus `
        -CurrentValue $(if ($wdigestEnabled) { 'Habilitado (credenciales en claro en memoria)' } else { 'Deshabilitado' }) `
        -ExpectedValue 'Deshabilitado' `
        -Remediation 'Set-ItemProperty HKLM:\...\WDigest UseLogonCredential 0' `
        -Reference 'CIS 18.3.7 / MITRE T1003.001'

    # Credential Guard
    $cgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $cgVal  = Get-ItemProperty -Path $cgPath -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue
    $cgEnabled = ($null -ne $cgVal -and $cgVal.EnableVirtualizationBasedSecurity -ge 1)
    $cgStatus = if ($cgEnabled) { 'SECURE' } else { 'WARNING' }
    New-AuditResult -Category 'Credentials' -Control 'Virtualization Based Security' -Status $cgStatus `
        -CurrentValue $(if ($cgEnabled) { 'Habilitado' } else { 'Deshabilitado' }) `
        -ExpectedValue 'Habilitado' `
        -Remediation 'Habilitar VBS/Credential Guard en Device Guard (requiere hardware compatible)' `
        -Reference 'CIS 18.8.5 / MITRE T1003'
}

# ─── AUDITORÍA: POWERSHELL SECURITY ───────────────────────────────────────────

function Invoke-PowerShellAudit {
    Write-LogSection "Auditoría: PowerShell Security"

    # Execution Policy
    $execPolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
    $epStatus = switch ($execPolicy) {
        'Restricted'     { 'SECURE'  }
        'AllSigned'      { 'SECURE'  }
        'RemoteSigned'   { 'WARNING' }
        'Unrestricted'   { 'VULNERABLE' }
        'Bypass'         { 'VULNERABLE' }
        default          { 'WARNING' }
    }
    New-AuditResult -Category 'PowerShell' -Control 'Execution Policy' -Status $epStatus `
        -CurrentValue $execPolicy -ExpectedValue 'AllSigned o RemoteSigned' `
        -Remediation 'Set-ExecutionPolicy AllSigned -Scope LocalMachine' `
        -Reference 'CIS 18.9.95 / MITRE T1059.001'

    # Script Block Logging
    $sblPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sblVal  = Get-ItemProperty -Path $sblPath -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue
    $sblEnabled = ($null -ne $sblVal -and $sblVal.EnableScriptBlockLogging -eq 1)
    $sblStatus = if ($sblEnabled) { 'SECURE' } else { 'WARNING' }
    New-AuditResult -Category 'PowerShell' -Control 'Script Block Logging' -Status $sblStatus `
        -CurrentValue $(if ($sblEnabled) { 'Habilitado' } else { 'Deshabilitado' }) `
        -ExpectedValue 'Habilitado' `
        -Remediation 'GPO: PowerShell > Turn on Script Block Logging' `
        -Reference 'CIS 18.9.95.1 / MITRE T1059.001'

    # Module Logging
    $mlPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    $mlVal   = Get-ItemProperty -Path $mlPath -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue
    $mlEnabled = ($null -ne $mlVal -and $mlVal.EnableModuleLogging -eq 1)
    $mlStatus = if ($mlEnabled) { 'SECURE' } else { 'WARNING' }
    New-AuditResult -Category 'PowerShell' -Control 'Module Logging' -Status $mlStatus `
        -CurrentValue $(if ($mlEnabled) { 'Habilitado' } else { 'Deshabilitado' }) `
        -ExpectedValue 'Habilitado' `
        -Remediation 'GPO: PowerShell > Turn on Module Logging' `
        -Reference 'CIS 18.9.95.2'

    # PowerShell v2
    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' `
           -ErrorAction SilentlyContinue
    if ($null -ne $ps2) {
        $ps2Status = if ($ps2.State -eq 'Disabled') { 'SECURE' } else { 'VULNERABLE' }
        New-AuditResult -Category 'PowerShell' -Control 'PowerShell v2 (legacy)' -Status $ps2Status `
            -CurrentValue $ps2.State -ExpectedValue 'Disabled' `
            -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' `
            -Reference 'CIS / MITRE T1059.001 downgrade'
    }
}

# ─── AUDITORÍA: POLÍTICAS DE CONTRASEÑA ───────────────────────────────────────

function Invoke-PasswordPolicyAudit {
    Write-LogSection "Auditoría: Políticas de Contraseña"

    try {
        $netAccountsOutput = net accounts 2>&1
        if ($LASTEXITCODE -ne 0) { throw "net accounts falló" }

        # Parsear salida de net accounts
        $minLen    = ($netAccountsOutput | Select-String 'Minimum password length').ToString() -replace '\D+', ''
        $null = ($netAccountsOutput | Select-String 'Maximum password age')   # auditado via lockout threshold
        $null = ($netAccountsOutput | Select-String 'Minimum password age')
        $history   = ($netAccountsOutput | Select-String 'Length of password history').ToString() -replace '[^0-9]', ''
        $lockCount = ($netAccountsOutput | Select-String 'Lockout threshold').ToString() -replace '[^0-9]', ''

        # Longitud mínima (CIS: mínimo 14)
        $lenInt    = [int]$minLen
        $lenStatus = if ($lenInt -ge 14) { 'SECURE' } elseif ($lenInt -ge 8) { 'WARNING' } else { 'VULNERABLE' }
        New-AuditResult -Category 'Password' -Control 'Longitud mínima' -Status $lenStatus `
            -CurrentValue "$lenInt caracteres" -ExpectedValue '14 o más caracteres' `
            -Remediation 'net accounts /minpwlen:14' -Reference 'CIS 1.1.4'

        # Historial (CIS: 24)
        $histInt   = [int]$history
        $histStatus = if ($histInt -ge 24) { 'SECURE' } elseif ($histInt -ge 5) { 'WARNING' } else { 'VULNERABLE' }
        New-AuditResult -Category 'Password' -Control 'Historial de contraseñas' -Status $histStatus `
            -CurrentValue "$histInt contraseñas recordadas" -ExpectedValue '24 o más' `
            -Remediation 'net accounts /uniquepw:24' -Reference 'CIS 1.1.1'

        # Umbral de bloqueo (CIS: 5 o menos)
        $lockInt   = [int]$lockCount
        $lockStatus = if ($lockInt -gt 0 -and $lockInt -le 5) { 'SECURE' } `
                      elseif ($lockInt -le 10) { 'WARNING' } `
                      else { 'VULNERABLE' }
        New-AuditResult -Category 'Password' -Control 'Umbral de bloqueo' -Status $lockStatus `
            -CurrentValue "$lockInt intentos" -ExpectedValue '5 o menos intentos' `
            -Remediation 'net accounts /lockoutthreshold:5' -Reference 'CIS 1.2.1'
    }
    catch {
        Write-LogWarning "No se pudo auditar políticas de contraseña: $_" -Component 'Audit'
    }
}

# ─── FUNCIÓN MAESTRA DE AUDITORÍA ─────────────────────────────────────────────

function Invoke-FullAudit {
    <#
    .SYNOPSIS
        Ejecuta todos los controles de auditoría y devuelve el resumen.
    .OUTPUTS
        Hashtable con totales por estado (SECURE, WARNING, VULNERABLE)
    #>
    [CmdletBinding()]
    param()

    Clear-AuditResults

    Write-LogSection "INICIANDO AUDITORÍA COMPLETA DE SEGURIDAD"
    Write-LogInfo "Host: $env:COMPUTERNAME | Usuario: $env:USERNAME" -Component 'Audit'

    Invoke-FirewallAudit
    Invoke-SmbAudit
    Invoke-NetBiosLlmnrAudit
    Invoke-NtlmAudit
    Invoke-TlsAudit
    Invoke-DefenderAudit
    Invoke-AsrAudit
    Invoke-CredentialsAudit
    Invoke-PowerShellAudit
    Invoke-PasswordPolicyAudit

    # Resumen
    $results  = $Script:AuditResults
    $secure   = @($results | Where-Object Status -eq 'SECURE').Count
    $warning  = @($results | Where-Object Status -eq 'WARNING').Count
    $vuln     = @($results | Where-Object Status -eq 'VULNERABLE').Count
    $total    = $results.Count

    Write-LogSection "RESUMEN DE AUDITORÍA"
    Write-Host ""
    Write-Host "  Total de controles : " -NoNewline; Write-Host $total -ForegroundColor White
    Write-Host "  SECURE             : " -NoNewline; Write-Host $secure  -ForegroundColor Green
    Write-Host "  WARNING            : " -NoNewline; Write-Host $warning -ForegroundColor Yellow
    Write-Host "  VULNERABLE         : " -NoNewline; Write-Host $vuln   -ForegroundColor Red
    Write-Host ""

    $score = if ($total -gt 0) { [math]::Round(($secure / $total) * 100, 1) } else { 0 }
    $scoreColor = if ($score -ge 80) { 'Green' } elseif ($score -ge 60) { 'Yellow' } else { 'Red' }
    Write-Host "  Security Score: " -NoNewline
    Write-Host "$score%" -ForegroundColor $scoreColor
    Write-Host ""

    Write-LogInfo "Auditoría completada: $secure SECURE / $warning WARNING / $vuln VULNERABLE (Score: $score%)" -Component 'Audit'

    return @{
        Secure     = $secure
        Warning    = $warning
        Vulnerable = $vuln
        Total      = $total
        Score      = $score
        Results    = $results
    }
}
