#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Firewall Module
.DESCRIPTION
    Configura y aplica hardening de Windows Defender Firewall.
    Activa todos los perfiles y bloquea puertos críticos según CIS Benchmark.
.NOTES
    Standard: CIS Benchmark Section 9, NIST 800-53 SC-7
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── PUERTOS CRÍTICOS A BLOQUEAR ──────────────────────────────────────────────
# Referencia: MITRE ATT&CK, CIS Benchmark, NSA Hardening Guide

$Script:BlockedPorts = @(
    @{ Port = 21;   Protocol = 'TCP'; Description = 'FTP (cleartext)' }
    @{ Port = 23;   Protocol = 'TCP'; Description = 'Telnet (cleartext)' }
    @{ Port = 69;   Protocol = 'UDP'; Description = 'TFTP (unauthenticated)' }
    @{ Port = 135;  Protocol = 'TCP'; Description = 'RPC Endpoint Mapper' }
    @{ Port = 137;  Protocol = 'UDP'; Description = 'NetBIOS Name Service' }
    @{ Port = 138;  Protocol = 'UDP'; Description = 'NetBIOS Datagram' }
    @{ Port = 139;  Protocol = 'TCP'; Description = 'NetBIOS Session' }
    @{ Port = 445;  Protocol = 'TCP'; Description = 'SMB (EternalBlue)' }
    @{ Port = 593;  Protocol = 'TCP'; Description = 'RPC over HTTP' }
    @{ Port = 1900; Protocol = 'UDP'; Description = 'UPnP SSDP' }
    @{ Port = 3389; Protocol = 'TCP'; Description = 'RDP (restrict; no bloquear si se usa)' }
    @{ Port = 5985; Protocol = 'TCP'; Description = 'WinRM HTTP' }
    @{ Port = 5986; Protocol = 'TCP'; Description = 'WinRM HTTPS (solo permitir si es necesario)' }
)

# ─── HABILITAR PERFILES DE FIREWALL ───────────────────────────────────────────

function Enable-FirewallProfiles {
    <#
    .SYNOPSIS
        Habilita los tres perfiles de Windows Firewall (Domain, Private, Public).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$Force
    )

    Write-LogSection "Hardening: Habilitando perfiles de Firewall"

    $profiles = @('Domain', 'Private', 'Public')

    foreach ($profileName in $profiles) {
        try {
            $current = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop

            if ($current.Enabled -and -not $Force) {
                Write-LogInfo "Perfil $profileName ya está habilitado. Omitiendo." -Component 'Firewall'
                continue
            }

            if ($PSCmdlet.ShouldProcess("Firewall perfil $profileName", "Habilitar")) {
                Set-NetFirewallProfile -Name $profileName `
                    -Enabled             True `
                    -DefaultInboundAction  Block `
                    -DefaultOutboundAction Allow `
                    -LogAllowed          True `
                    -LogBlocked          True `
                    -LogMaxSizeKilobytes 32767 `
                    -ErrorAction Stop

                Write-LogSuccess "Perfil $profileName habilitado con política Block inbound." -Component 'Firewall'
            }
        }
        catch {
            Write-LogError "Error habilitando perfil $profileName : $_" -Component 'Firewall'
        }
    }
}

# ─── BLOQUEAR PUERTOS CRÍTICOS ────────────────────────────────────────────────

function Block-CriticalPorts {
    <#
    .SYNOPSIS
        Crea reglas de firewall para bloquear puertos críticos (inbound).
    .PARAMETER SkipRDP
        Si se especifica, omite la regla para RDP (puerto 3389).
    .PARAMETER SkipWinRM
        Si se especifica, omite las reglas para WinRM (5985/5986).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$SkipRDP,
        [switch]$SkipWinRM
    )

    Write-LogSection "Hardening: Bloqueando puertos críticos"

    foreach ($portDef in $Script:BlockedPorts) {
        $port     = $portDef.Port
        $proto    = $portDef.Protocol
        $desc     = $portDef.Description
        $ruleName = "WHT - Block Inbound $($proto)/$port ($desc)"

        # Omitir RDP si se solicita
        if ($SkipRDP -and $port -eq 3389) {
            Write-LogInfo "Omitiendo bloqueo de RDP (3389) por solicitud explícita." -Component 'Firewall'
            continue
        }

        # Omitir WinRM si se solicita
        if ($SkipWinRM -and $port -in @(5985, 5986)) {
            Write-LogInfo "Omitiendo bloqueo de WinRM ($port) por solicitud explícita." -Component 'Firewall'
            continue
        }

        try {
            # Verificar si la regla ya existe
            $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

            if ($existing) {
                Write-LogInfo "Regla ya existe: $ruleName" -Component 'Firewall'
                continue
            }

            if ($PSCmdlet.ShouldProcess($ruleName, "Crear regla de bloqueo")) {
                New-NetFirewallRule `
                    -DisplayName $ruleName `
                    -Direction   Inbound `
                    -Protocol    $proto `
                    -LocalPort   $port `
                    -Action      Block `
                    -Profile     Any `
                    -Description "WHT: $desc - CIS/NIST SC-7" `
                    -Enabled     True `
                    -ErrorAction Stop | Out-Null

                Write-LogSuccess "Regla creada: Block $proto/$port ($desc)" -Component 'Firewall'
            }
        }
        catch {
            Write-LogError "Error creando regla para $proto/$port : $_" -Component 'Firewall'
        }
    }
}

# ─── BLOQUEAR TRÁFICO SALIENTE A PUERTOS INSEGUROS ────────────────────────────

function Block-OutboundInsecureProtocols {
    <#
    .SYNOPSIS
        Bloquea tráfico saliente hacia protocolos inseguros (Telnet, FTP cleartext).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Bloqueando protocolos salientes inseguros"

    $outboundRules = @(
        @{ Port = 21;  Protocol = 'TCP'; Description = 'FTP cleartext outbound' }
        @{ Port = 23;  Protocol = 'TCP'; Description = 'Telnet cleartext outbound' }
        @{ Port = 69;  Protocol = 'UDP'; Description = 'TFTP unauthenticated outbound' }
        @{ Port = 119; Protocol = 'TCP'; Description = 'NNTP outbound' }
    )

    foreach ($rule in $outboundRules) {
        $ruleName = "WHT - Block Outbound $($rule.Protocol)/$($rule.Port) ($($rule.Description))"

        try {
            $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if ($existing) {
                Write-LogInfo "Regla ya existe: $ruleName" -Component 'Firewall'
                continue
            }

            if ($PSCmdlet.ShouldProcess($ruleName, "Crear regla outbound")) {
                New-NetFirewallRule `
                    -DisplayName $ruleName `
                    -Direction   Outbound `
                    -Protocol    $rule.Protocol `
                    -RemotePort  $rule.Port `
                    -Action      Block `
                    -Profile     Any `
                    -Description "WHT: $($rule.Description) - CIS/NIST" `
                    -Enabled     True `
                    -ErrorAction Stop | Out-Null

                Write-LogSuccess "Regla outbound creada: Block $($rule.Protocol)/$($rule.Port)" -Component 'Firewall'
            }
        }
        catch {
            Write-LogError "Error creando regla outbound $($rule.Port): $_" -Component 'Firewall'
        }
    }
}

# ─── HARDENING ADICIONAL DE FIREWALL ──────────────────────────────────────────

function Set-FirewallAdvancedSettings {
    <#
    .SYNOPSIS
        Aplica configuraciones avanzadas de firewall (unicast, notificaciones, logs).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Configuraciones avanzadas de Firewall"

    $profiles = @('Domain', 'Private', 'Public')

    foreach ($profileName in $profiles) {
        try {
            if ($PSCmdlet.ShouldProcess("Firewall $profileName", "Configuración avanzada")) {
                Set-NetFirewallProfile -Name $profileName `
                    -AllowUnicastResponseToMulticast False `
                    -NotifyOnListen                 False `
                    -LogAllowed                     True `
                    -LogBlocked                     True `
                    -LogIgnored                     True `
                    -LogMaxSizeKilobytes             32767 `
                    -ErrorAction Stop

                Write-LogSuccess "Configuración avanzada aplicada al perfil $profileName." -Component 'Firewall'
            }
        }
        catch {
            Write-LogWarning "No se pudo aplicar configuración avanzada a $profileName : $_" -Component 'Firewall'
        }
    }
}

# ─── FUNCIÓN MAESTRA DE HARDENING DE FIREWALL ─────────────────────────────────

function Invoke-FirewallHardening {
    <#
    .SYNOPSIS
        Ejecuta hardening completo del firewall.
    .PARAMETER SkipRDP
        Omite el bloqueo del puerto RDP (3389).
    .PARAMETER SkipWinRM
        Omite el bloqueo de WinRM (5985/5986).
    .PARAMETER BasicOnly
        Solo habilita perfiles, sin crear reglas adicionales.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$SkipRDP,
        [switch]$SkipWinRM,
        [switch]$BasicOnly
    )

    Write-LogInfo "Iniciando hardening de Firewall..." -Component 'Firewall'

    Enable-FirewallProfiles
    Set-FirewallAdvancedSettings

    if (-not $BasicOnly) {
        Block-CriticalPorts -SkipRDP:$SkipRDP -SkipWinRM:$SkipWinRM
        Block-OutboundInsecureProtocols
    }

    Write-LogSuccess "Hardening de Firewall completado." -Component 'Firewall'
}

# ─── ELIMINAR REGLAS WHT (ROLLBACK PARCIAL) ───────────────────────────────────

function Remove-WhtFirewallRules {
    <#
    .SYNOPSIS
        Elimina todas las reglas de firewall creadas por este toolkit (prefijo WHT).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Rollback: Eliminando reglas WHT de Firewall"

    $whtRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'WHT -*' }

    if (-not $whtRules) {
        Write-LogInfo "No se encontraron reglas WHT para eliminar." -Component 'Firewall'
        return
    }

    foreach ($rule in $whtRules) {
        try {
            if ($PSCmdlet.ShouldProcess($rule.DisplayName, "Eliminar regla WHT")) {
                Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                Write-LogSuccess "Regla eliminada: $($rule.DisplayName)" -Component 'Firewall'
            }
        }
        catch {
            Write-LogError "Error eliminando regla $($rule.DisplayName): $_" -Component 'Firewall'
        }
    }

    Write-LogInfo "Eliminación de reglas WHT completada." -Component 'Firewall'
}
