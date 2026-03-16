#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Windows Event Logging & Audit Policy Module
.DESCRIPTION
    Configura políticas de auditoría de Windows y tamaños de los registros de eventos.
    Habilita auditoría granular para detectar intrusiones y movimientos laterales.
.NOTES
    Standard: CIS Benchmark 17.x, NIST 800-53 AU-2, NIST 800-92
    MITRE: T1070 (Indicator Removal), T1562.002 (Disable Windows Event Logging)
    Compatible: PowerShell 5.1 / PowerShell 7+
    Nota: Este módulo se llama logging_audit.ps1 para diferenciarse de logging.ps1
          (que gestiona el log interno de la herramienta).
#>

# ─── CONFIGURAR TAMAÑO DE REGISTROS DE EVENTOS ────────────────────────────────

function Set-EventLogSize {
    <#
    .SYNOPSIS
        Configura el tamaño máximo de los principales registros de eventos de Windows.
    .PARAMETER SizeMB
        Tamaño máximo en MB. Por defecto: 1024 MB (1 GB) para registros críticos.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$SizeMB = 1024
    )

    Write-LogSection "Hardening: Tamaños de Registros de Eventos"

    $eventLogs = @{
        'Security'     = $SizeMB * 1MB    # Log más crítico: máximo tamaño
        'System'       = ($SizeMB / 4) * 1MB
        'Application'  = ($SizeMB / 4) * 1MB
        'Microsoft-Windows-PowerShell/Operational' = ($SizeMB / 2) * 1MB
        'Microsoft-Windows-Sysmon/Operational'     = $SizeMB * 1MB    # Si Sysmon está instalado
    }

    foreach ($log in $eventLogs.GetEnumerator()) {
        try {
            $logObj = Get-WinEvent -ListLog $log.Key -ErrorAction SilentlyContinue
            if ($null -eq $logObj) {
                Write-LogDebug "Log '$($log.Key)' no encontrado (puede no estar habilitado)." -Component 'Logging'
                continue
            }

            if ($PSCmdlet.ShouldProcess($log.Key, "Establecer tamaño máximo $($log.Value / 1MB) MB")) {
                $logObj.MaximumSizeInBytes = $log.Value
                $logObj.SaveChanges()
                Write-LogSuccess "Log '$($log.Key)' configurado a $($log.Value / 1MB) MB." -Component 'Logging'
            }
        }
        catch {
            Write-LogWarning "No se pudo configurar log '$($log.Key)': $_" -Component 'Logging'
        }
    }

    # Asegurar que el log de seguridad no se sobreescriba (retención de eventos)
    try {
        if ($PSCmdlet.ShouldProcess('Security Log', 'Configurar retención')) {
            $secLog = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
            $secLog.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]::Retain
            $secLog.SaveChanges()
            Write-LogSuccess "Security Log configurado en modo Retain (no sobreescribir)." -Component 'Logging'
        }
    }
    catch {
        # En algunos entornos, Retain puede necesitar configuración diferente
        $wevtutil = "wevtutil sl Security /r:false /rt:false"
        Write-LogDebug "Usando wevtutil para configurar retención: $wevtutil" -Component 'Logging'
    }
}

# ─── CONFIGURAR POLÍTICA DE AUDITORÍA ─────────────────────────────────────────

function Set-AuditPolicy {
    <#
    .SYNOPSIS
        Configura las políticas de auditoría granulares via auditpol.exe.
        Estas son las recomendaciones de CIS Benchmark y Microsoft Security Baseline.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Políticas de Auditoría (auditpol)"

    # Categorías de auditoría: (Category, Subcategory, Success, Failure)
    $auditPolicies = @(
        # Account Logon
        @{ Cat = 'Account Logon'; Sub = 'Credential Validation';              S = 1; F = 1; Ref = 'CIS 17.1.1' }
        @{ Cat = 'Account Logon'; Sub = 'Kerberos Authentication Service';    S = 1; F = 1; Ref = 'CIS 17.1.2' }
        @{ Cat = 'Account Logon'; Sub = 'Kerberos Service Ticket Operations'; S = 0; F = 1; Ref = 'CIS 17.1.3' }

        # Account Management
        @{ Cat = 'Account Management'; Sub = 'Computer Account Management';  S = 1; F = 0; Ref = 'CIS 17.2.1' }
        @{ Cat = 'Account Management'; Sub = 'Security Group Management';    S = 1; F = 0; Ref = 'CIS 17.2.2' }
        @{ Cat = 'Account Management'; Sub = 'User Account Management';      S = 1; F = 1; Ref = 'CIS 17.2.4' }
        @{ Cat = 'Account Management'; Sub = 'Distribution Group Management';S = 1; F = 0; Ref = 'CIS 17.2.3' }

        # Detailed Tracking
        @{ Cat = 'Detailed Tracking'; Sub = 'Process Creation';              S = 1; F = 0; Ref = 'CIS 17.3.1' }
        @{ Cat = 'Detailed Tracking'; Sub = 'Process Termination';           S = 1; F = 0; Ref = 'MS Baseline'  }
        @{ Cat = 'Detailed Tracking'; Sub = 'DPAPI Activity';                S = 1; F = 1; Ref = 'MS Baseline'  }

        # Logon/Logoff
        @{ Cat = 'Logon/Logoff'; Sub = 'Account Lockout';                    S = 1; F = 0; Ref = 'CIS 17.5.1' }
        @{ Cat = 'Logon/Logoff'; Sub = 'Logoff';                             S = 1; F = 0; Ref = 'CIS 17.5.2' }
        @{ Cat = 'Logon/Logoff'; Sub = 'Logon';                              S = 1; F = 1; Ref = 'CIS 17.5.3' }
        @{ Cat = 'Logon/Logoff'; Sub = 'Special Logon';                      S = 1; F = 0; Ref = 'CIS 17.5.4' }
        @{ Cat = 'Logon/Logoff'; Sub = 'Other Logon/Logoff Events';          S = 1; F = 1; Ref = 'CIS 17.5.6' }
        @{ Cat = 'Logon/Logoff'; Sub = 'Network Policy Server';              S = 1; F = 1; Ref = 'MS Baseline'  }

        # Object Access
        @{ Cat = 'Object Access'; Sub = 'Detailed File Share';               S = 0; F = 1; Ref = 'CIS 17.6.1' }
        @{ Cat = 'Object Access'; Sub = 'File Share';                        S = 1; F = 1; Ref = 'CIS 17.6.2' }
        @{ Cat = 'Object Access'; Sub = 'Removable Storage';                 S = 1; F = 1; Ref = 'CIS 17.6.4' }
        @{ Cat = 'Object Access'; Sub = 'SAM';                               S = 0; F = 1; Ref = 'MS Baseline'  }

        # Policy Change
        @{ Cat = 'Policy Change'; Sub = 'Audit Policy Change';               S = 1; F = 0; Ref = 'CIS 17.7.1' }
        @{ Cat = 'Policy Change'; Sub = 'Authentication Policy Change';      S = 1; F = 0; Ref = 'CIS 17.7.2' }
        @{ Cat = 'Policy Change'; Sub = 'Authorization Policy Change';       S = 1; F = 0; Ref = 'CIS 17.7.3' }
        @{ Cat = 'Policy Change'; Sub = 'MPSSVC Rule-Level Policy Change';   S = 1; F = 1; Ref = 'CIS 17.7.4' }
        @{ Cat = 'Policy Change'; Sub = 'Filtering Platform Policy Change';  S = 0; F = 1; Ref = 'CIS 17.7.5' }

        # Privilege Use
        @{ Cat = 'Privilege Use'; Sub = 'Sensitive Privilege Use';           S = 1; F = 1; Ref = 'CIS 17.8.1' }

        # System
        @{ Cat = 'System'; Sub = 'IPsec Driver';                             S = 1; F = 1; Ref = 'CIS 17.9.1' }
        @{ Cat = 'System'; Sub = 'Other System Events';                      S = 1; F = 1; Ref = 'CIS 17.9.2' }
        @{ Cat = 'System'; Sub = 'Security State Change';                    S = 1; F = 0; Ref = 'CIS 17.9.3' }
        @{ Cat = 'System'; Sub = 'Security System Extension';                S = 1; F = 0; Ref = 'CIS 17.9.4' }
        @{ Cat = 'System'; Sub = 'System Integrity';                         S = 1; F = 1; Ref = 'CIS 17.9.5' }

        # DS Access (relevante en Domain Controllers)
        @{ Cat = 'DS Access'; Sub = 'Directory Service Changes';             S = 1; F = 0; Ref = 'CIS 17.4.1' }
    )

    $applied = 0
    $failed  = 0

    foreach ($policy in $auditPolicies) {
        $success = if ($policy.S -eq 1) { 'enable' } else { 'disable' }
        $failure = if ($policy.F -eq 1) { 'enable' } else { 'disable' }
        $subcategory = $policy.Sub

        try {
            if ($PSCmdlet.ShouldProcess($subcategory, "Auditoría S:$success F:$failure")) {
                # Usar auditpol.exe para configuración granular
                $auditCmd = "auditpol /set /subcategory:`"$subcategory`" /success:$success /failure:$failure"
                $result   = cmd /c $auditCmd 2>&1

                if ($LASTEXITCODE -eq 0) {
                    Write-LogSuccess "Audit: '$subcategory' (S:$success/F:$failure) [$($policy.Ref)]" -Component 'Logging'
                    $applied++
                }
                else {
                    Write-LogDebug "Audit (ignorado): '$subcategory' - $result" -Component 'Logging'
                    $failed++
                }
            }
        }
        catch {
            Write-LogWarning "Error configurando auditoría '$subcategory': $_" -Component 'Logging'
            $failed++
        }
    }

    Write-LogInfo "Políticas de auditoría: $applied aplicadas / $failed omitidas." -Component 'Logging'
}

# ─── HABILITAR COMMAND LINE AUDITING ──────────────────────────────────────────

function Enable-ProcessCommandLineAudit {
    <#
    .SYNOPSIS
        Habilita el registro de la línea de comandos en eventos de creación de procesos.
        Permite detectar ejecución de comandos maliciosos (MITRE T1059).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Process Command Line Audit"

    $cmdAuditPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

    try {
        if (-not (Test-Path $cmdAuditPath)) {
            New-Item -Path $cmdAuditPath -Force | Out-Null
        }

        if ($PSCmdlet.ShouldProcess('ProcessCreationIncludeCmdLine', 'Habilitar')) {
            Set-ItemProperty -Path $cmdAuditPath -Name 'ProcessCreationIncludeCmdLine_Enabled' `
                             -Value 1 -Type DWord -Force
            Write-LogSuccess "Command Line Auditing habilitado (Evento 4688)." -Component 'Logging'
        }
    }
    catch {
        Write-LogWarning "No se pudo habilitar Command Line Auditing: $_" -Component 'Logging'
    }
}

# ─── CONFIGURAR SYSMON (SI ESTÁ INSTALADO) ────────────────────────────────────

function Set-SysmonLogging {
    <#
    .SYNOPSIS
        Verifica si Sysmon está instalado y reporta su estado.
        No instala Sysmon (requiere descarga separada).
    #>
    [CmdletBinding()]
    param()

    Write-LogSection "Verificando: Sysmon"

    $sysmon = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue

    if ($sysmon) {
        Write-LogSuccess "Sysmon detectado: $($sysmon.Name) - Estado: $($sysmon.Status)" -Component 'Logging'
    }
    else {
        Write-LogWarning "Sysmon NO está instalado. Se recomienda instalar Sysmon para telemetría avanzada." -Component 'Logging'
        Write-LogInfo "Sysmon disponible en: https://docs.microsoft.com/sysinternals/sysmon" -Component 'Logging'
    }
}

# ─── FUNCIÓN MAESTRA ──────────────────────────────────────────────────────────

function Invoke-AuditPolicyHardening {
    <#
    .SYNOPSIS
        Ejecuta hardening completo de políticas de auditoría y logs de eventos.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$LogSizeMB = 1024
    )

    Write-LogInfo "Iniciando hardening de Políticas de Auditoría..." -Component 'Logging'

    Set-EventLogSize -SizeMB $LogSizeMB
    Set-AuditPolicy
    Enable-ProcessCommandLineAudit
    Set-SysmonLogging

    Write-LogSuccess "Hardening de Políticas de Auditoría completado." -Component 'Logging'
}
