#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Microsoft Defender Module
.DESCRIPTION
    Configura Microsoft Defender con protecciones avanzadas: protección en tiempo
    real, network protection, controlled folder access y reglas ASR completas.
.NOTES
    Standard: CIS Benchmark 18.9.45, Microsoft Security Baseline
    MITRE: T1562.001, T1486, T1566, T1059, T1203
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── HABILITAR PROTECCIÓN EN TIEMPO REAL ──────────────────────────────────────

function Enable-DefenderRealTimeProtection {
    <#
    .SYNOPSIS
        Activa la protección en tiempo real de Microsoft Defender.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Defender Real-Time Protection"

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop

        if ($status.RealTimeProtectionEnabled) {
            Write-LogInfo "Real-Time Protection ya está habilitada." -Component 'Defender'
        }
        elseif ($PSCmdlet.ShouldProcess('Defender', 'Habilitar Real-Time Protection')) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Write-LogSuccess "Real-Time Protection habilitada." -Component 'Defender'
        }

        # Habilitar monitoreo de comportamiento
        if ($PSCmdlet.ShouldProcess('Defender', 'Habilitar Behavior Monitoring')) {
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            Write-LogSuccess "Behavior Monitoring habilitado." -Component 'Defender'
        }

        # Habilitar IOAV (escaneo de descargas)
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
        Write-LogSuccess "IOAV Protection (escaneo de descargas) habilitada." -Component 'Defender'

        # Habilitar escaneo de scripts
        Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
        Write-LogSuccess "Script Scanning habilitado." -Component 'Defender'
    }
    catch {
        Write-LogError "Error configurando Real-Time Protection: $_" -Component 'Defender'
    }
}

# ─── HABILITAR NETWORK PROTECTION ─────────────────────────────────────────────

function Enable-DefenderNetworkProtection {
    <#
    .SYNOPSIS
        Habilita Network Protection para bloquear conexiones maliciosas.
        Modo: Enabled (Block) o AuditMode.
    .PARAMETER AuditMode
        Si se especifica, activa en modo auditoría en lugar de bloqueo.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$AuditMode
    )

    Write-LogSection "Hardening: Defender Network Protection"

    $mode = if ($AuditMode) { 'AuditMode' } else { 'Enabled' }

    try {
        $current = (Get-MpPreference -ErrorAction Stop).EnableNetworkProtection
        $currentMode = switch ($current) { 1 { 'Enabled' }; 2 { 'AuditMode' }; default { 'Disabled' } }

        if ($currentMode -eq $mode) {
            Write-LogInfo "Network Protection ya está en modo $mode." -Component 'Defender'
            return
        }

        if ($PSCmdlet.ShouldProcess('Network Protection', "Configurar en modo $mode")) {
            Set-MpPreference -EnableNetworkProtection $mode -ErrorAction Stop
            Write-LogSuccess "Network Protection configurada en modo $mode." -Component 'Defender'
        }
    }
    catch {
        Write-LogError "Error configurando Network Protection: $_" -Component 'Defender'
    }
}

# ─── HABILITAR CONTROLLED FOLDER ACCESS ───────────────────────────────────────

function Enable-ControlledFolderAccess {
    <#
    .SYNOPSIS
        Habilita Controlled Folder Access (protección anti-ransomware).
    .PARAMETER AuditMode
        Si se especifica, activa en modo auditoría.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$AuditMode
    )

    Write-LogSection "Hardening: Defender Controlled Folder Access"

    $mode = if ($AuditMode) { 'AuditMode' } else { 'Enabled' }

    try {
        $current = (Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess
        $currentMode = switch ($current) { 1 { 'Enabled' }; 2 { 'AuditMode' }; default { 'Disabled' } }

        if ($currentMode -eq $mode) {
            Write-LogInfo "Controlled Folder Access ya está en modo $mode." -Component 'Defender'
            return
        }

        if ($PSCmdlet.ShouldProcess('Controlled Folder Access', "Configurar en modo $mode")) {
            Set-MpPreference -EnableControlledFolderAccess $mode -ErrorAction Stop
            Write-LogSuccess "Controlled Folder Access configurada en modo $mode." -Component 'Defender'
        }
    }
    catch {
        Write-LogError "Error configurando Controlled Folder Access: $_" -Component 'Defender'
    }
}

# ─── HABILITAR REGLAS ASR ─────────────────────────────────────────────────────

function Enable-AsrRules {
    <#
    .SYNOPSIS
        Habilita las reglas de Attack Surface Reduction recomendadas por Microsoft.
    .PARAMETER RulesConfigPath
        Ruta al archivo JSON con configuración de reglas ASR.
    .PARAMETER AuditMode
        Si se especifica, activa reglas en modo auditoría.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$RulesConfigPath,
        [switch]$AuditMode
    )

    Write-LogSection "Hardening: ASR Rules (Attack Surface Reduction)"

    $action = if ($AuditMode) { 'AuditMode' } else { 'Enabled' }

    # Cargar reglas desde JSON si se provee, si no usar conjunto por defecto
    if ($RulesConfigPath -and (Test-Path $RulesConfigPath)) {
        try {
            $asrConfig = Get-Content -Path $RulesConfigPath -Raw | ConvertFrom-Json
            $asrRules  = $asrConfig.rules
            Write-LogInfo "Reglas ASR cargadas desde: $RulesConfigPath" -Component 'Defender'
        }
        catch {
            Write-LogWarning "No se pudo cargar $RulesConfigPath. Usando reglas por defecto." -Component 'Defender'
            $asrRules = $null
        }
    }

    # Reglas ASR recomendadas por Microsoft (habilitadas en modo Block para producción)
    if (-not $asrRules) {
        $asrRules = @(
            @{ Id = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Name = 'Block executable content from email/webmail' }
            @{ Id = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Name = 'Block Office apps from injecting into processes' }
            @{ Id = '3B576869-A4EC-4529-8536-B80A7769E899'; Name = 'Block Office apps from creating executable content' }
            @{ Id = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Name = 'Block Office apps from creating child processes' }
            @{ Id = 'D3E037E1-3EB8-44C8-A917-57927947596D'; Name = 'Block JS/VBS from launching downloaded executables' }
            @{ Id = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Name = 'Block execution of obfuscated scripts' }
            @{ Id = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Name = 'Block Win32 API calls from Office macros' }
            @{ Id = '01443614-CD74-433A-B99E-2ECDC07BFC25'; Name = 'Block executable files unless prevalence criteria met' }
            @{ Id = 'C1DB55AB-C21A-4637-BB3F-A12568109D35'; Name = 'Use advanced protection against ransomware' }
            @{ Id = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Name = 'Block credential stealing from LSASS' }
            @{ Id = 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'; Name = 'Block process creation from PSExec and WMI commands' }
            @{ Id = 'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'; Name = 'Block untrusted/unsigned processes from USB' }
            @{ Id = '26190899-1602-49E8-8B27-EB1D0A1CE869'; Name = 'Block Office communication app from creating child processes' }
            @{ Id = '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'; Name = 'Block Adobe Reader from creating child processes' }
            @{ Id = 'E6DB77E5-3DF2-4CF1-B95A-636979351E5B'; Name = 'Block persistence through WMI event subscription' }
        )
    }

    # Verificar que Defender Antivirus está activo antes de aplicar reglas ASR
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mpStatus.AntivirusEnabled) {
            Write-LogWarning "Antivirus no está habilitado. Las reglas ASR pueden no aplicarse correctamente." -Component 'Defender'
        }
    }
    catch {
        Write-LogWarning "No se pudo verificar estado de Antivirus antes de aplicar ASR: $_" -Component 'Defender'
    }

    $enabled = 0
    $failed  = 0

    foreach ($rule in $asrRules) {
        $ruleId   = if ($rule -is [PSCustomObject]) { $rule.Id }   else { $rule.Id }
        $ruleName = if ($rule -is [PSCustomObject]) { $rule.Name } else { $rule.Name }

        try {
            if ($PSCmdlet.ShouldProcess($ruleName, "Habilitar regla ASR en modo $action")) {
                Add-MpPreference `
                    -AttackSurfaceReductionRules_Ids     $ruleId `
                    -AttackSurfaceReductionRules_Actions $action `
                    -ErrorAction SilentlyContinue

                Write-LogSuccess "ASR [$action]: $ruleName" -Component 'Defender'
                $enabled++
            }
        }
        catch {
            Write-LogWarning "No se pudo habilitar regla ASR '$ruleName': $_" -Component 'Defender'
            $failed++
        }
    }

    Write-LogInfo "ASR Rules: $enabled habilitadas / $failed fallidas (modo $action)." -Component 'Defender'
}

# ─── CONFIGURACIÓN AVANZADA DE DEFENDER ───────────────────────────────────────

function Set-DefenderAdvancedSettings {
    <#
    .SYNOPSIS
        Aplica configuraciones avanzadas de Defender para máxima protección.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Defender Advanced Settings"

    try {
        if ($PSCmdlet.ShouldProcess('Defender Advanced Settings', 'Aplicar')) {
            $settings = @{
                # Protección en la nube
                MAPSReporting                      = 'Advanced'   # Basic | Advanced
                SubmitSamplesConsent               = 'SendAllSamples'

                # Protección PUA (Potentially Unwanted Apps)
                PUAProtection                      = 'Enabled'

                # Escaneo
                DisableArchiveScanning             = $false
                DisableEmailScanning               = $false
                DisableRemovableDriveScanning      = $false
                DisableScanningNetworkFiles        = $false

                # Niveles de detección
                CloudBlockLevel                    = 'High'
                CloudExtendedTimeout               = 50   # segundos adicionales para análisis en nube

                # Actualizaciones de firmas
                SignatureUpdateInterval            = 4    # horas entre actualizaciones
            }

            foreach ($setting in $settings.GetEnumerator()) {
                try {
                    $params = @{ $setting.Key = $setting.Value; ErrorAction = 'Stop' }
                    Set-MpPreference @params
                    Write-LogSuccess "Defender: $($setting.Key) = $($setting.Value)" -Component 'Defender'
                }
                catch {
                    Write-LogDebug "No se pudo aplicar $($setting.Key): $_" -Component 'Defender'
                }
            }
        }
    }
    catch {
        Write-LogError "Error en configuración avanzada de Defender: $_" -Component 'Defender'
    }
}

# ─── ACTUALIZAR FIRMAS ────────────────────────────────────────────────────────

function Update-DefenderSignatures {
    <#
    .SYNOPSIS
        Fuerza la actualización de firmas de antivirus.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogInfo "Actualizando firmas de Microsoft Defender..." -Component 'Defender'

    try {
        if ($PSCmdlet.ShouldProcess('Defender Signatures', 'Actualizar')) {
            Update-MpSignature -ErrorAction Stop
            Write-LogSuccess "Firmas de Defender actualizadas correctamente." -Component 'Defender'
        }
    }
    catch {
        Write-LogWarning "No se pudo actualizar firmas automáticamente: $_" -Component 'Defender'
    }
}

# ─── FUNCIÓN MAESTRA DE HARDENING DE DEFENDER ─────────────────────────────────

function Invoke-DefenderHardening {
    <#
    .SYNOPSIS
        Ejecuta hardening completo de Microsoft Defender.
    .PARAMETER RulesConfigPath
        Ruta al JSON de configuración de reglas ASR.
    .PARAMETER AuditMode
        Activa reglas ASR en modo auditoría (no bloqueo).
    .PARAMETER BasicOnly
        Solo activa protección básica sin reglas ASR avanzadas.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$RulesConfigPath,
        [switch]$AuditMode,
        [switch]$BasicOnly
    )

    Write-LogInfo "Iniciando hardening de Microsoft Defender..." -Component 'Defender'

    # Verificar si Defender está disponible
    try {
        $null = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        Write-LogError "Microsoft Defender no está disponible en este sistema. ¿Hay un AV de terceros?" -Component 'Defender'
        return
    }

    Enable-DefenderRealTimeProtection
    Enable-DefenderNetworkProtection -AuditMode:$AuditMode
    Enable-ControlledFolderAccess -AuditMode:$AuditMode

    if (-not $BasicOnly) {
        Enable-AsrRules -RulesConfigPath $RulesConfigPath -AuditMode:$AuditMode
        Set-DefenderAdvancedSettings
        Update-DefenderSignatures
    }

    Write-LogSuccess "Hardening de Microsoft Defender completado." -Component 'Defender'
}
