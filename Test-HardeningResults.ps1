#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Hardening Toolkit - Hardening Verification Script
.DESCRIPTION
    Verifica los 15 controles de seguridad aplicados por el toolkit.
    Genera un reporte en $env:TEMP con los resultados PASS/FAIL/WARN.
.NOTES
    Standard: CIS Benchmarks, NIST 800-53, Microsoft Security Baseline
    Compatible: PowerShell 5.1+
    Requiere: Administrador local

.EXAMPLE
    .\Test-HardeningResults.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─── COLORES Y RESULTADOS ─────────────────────────────────────────────────────

$Script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# ─── HELPER: WRITE-TESTRESULT ─────────────────────────────────────────────────

function Write-TestResult {
    <#
    .SYNOPSIS
        Imprime un resultado de test con color y lo agrega al array global.
    .PARAMETER Name
        Nombre descriptivo del test.
    .PARAMETER Status
        PASS, FAIL o WARN.
    .PARAMETER Detail
        Detalle adicional del resultado.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','WARN')][string]$Status,
        [string]$Detail = ''
    )

    $color = switch ($Status) {
        'PASS' { 'Green'  }
        'FAIL' { 'Red'    }
        'WARN' { 'Yellow' }
    }

    $label = switch ($Status) {
        'PASS' { '[PASS]' }
        'FAIL' { '[FAIL]' }
        'WARN' { '[WARN]' }
    }

    Write-Host -NoNewline "  $label " -ForegroundColor $color
    Write-Host -NoNewline $Name
    if ($Detail) {
        Write-Host " — $Detail" -ForegroundColor DarkGray
    }
    else {
        Write-Host ''
    }

    $Script:Results.Add([PSCustomObject]@{
        Name   = $Name
        Status = $Status
        Detail = $Detail
    })
}

# ─── HELPER: INVOKE-REGISTRYCHECK ─────────────────────────────────────────────

function Invoke-RegistryCheck {
    <#
    .SYNOPSIS
        Comprueba un valor de registro y devuelve PASS, FAIL o WARN.
    .PARAMETER Path
        Ruta de la clave de registro (formato HKLM:\...).
    .PARAMETER Name
        Nombre del valor a verificar.
    .PARAMETER ExpectedValue
        Valor esperado. Se compara con -eq.
    .OUTPUTS
        Hashtable con Status (PASS/FAIL/WARN) y Detail.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$ExpectedValue
    )

    try {
        if (-not (Test-Path $Path)) {
            return @{ Status = 'WARN'; Detail = "Clave no encontrada: $Path" }
        }

        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue

        if ($null -eq $prop) {
            return @{ Status = 'WARN'; Detail = "Valor '$Name' no existe en $Path" }
        }

        $actual = $prop.$Name

        if ($actual -eq $ExpectedValue) {
            return @{ Status = 'PASS'; Detail = "$Name = $actual" }
        }
        else {
            return @{ Status = 'FAIL'; Detail = "$Name = $actual (esperado: $ExpectedValue)" }
        }
    }
    catch {
        return @{ Status = 'WARN'; Detail = "Error al leer registro: $_" }
    }
}

# ─── BANNER ───────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  ================================================================' -ForegroundColor Cyan
Write-Host '   Windows Hardening Toolkit — Verificación de Resultados' -ForegroundColor Cyan
Write-Host '  ================================================================' -ForegroundColor Cyan
Write-Host "  Host   : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Fecha  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host '  ----------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host ''

# ─── TEST 1: FIREWALL HABILITADO EN LOS 3 PERFILES ────────────────────────────

Write-Host '  TEST 1: Firewall habilitado (Domain, Private, Public)' -ForegroundColor White
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $allEnabled = ($fwProfiles | Where-Object { -not $_.Enabled }).Count -eq 0

    if ($allEnabled) {
        Write-TestResult -Name 'Firewall — todos los perfiles habilitados' -Status 'PASS' `
            -Detail ($fwProfiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', '
    }
    else {
        $disabled = ($fwProfiles | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name }) -join ', '
        Write-TestResult -Name 'Firewall — todos los perfiles habilitados' -Status 'FAIL' `
            -Detail "Perfiles deshabilitados: $disabled"
    }
}
catch {
    Write-TestResult -Name 'Firewall — todos los perfiles habilitados' -Status 'WARN' `
        -Detail "No se pudo consultar: $_"
}

# ─── TEST 2: SMBv1 DESHABILITADO ──────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 2: SMBv1 deshabilitado' -ForegroundColor White
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    if ($smb.EnableSMB1Protocol -eq $false) {
        Write-TestResult -Name 'SMBv1 deshabilitado' -Status 'PASS' -Detail 'EnableSMB1Protocol = False'
    }
    else {
        Write-TestResult -Name 'SMBv1 deshabilitado' -Status 'FAIL' -Detail 'EnableSMB1Protocol = True (PELIGROSO)'
    }
}
catch {
    Write-TestResult -Name 'SMBv1 deshabilitado' -Status 'WARN' -Detail "No se pudo consultar SMB: $_"
}

# ─── TEST 3: NETBIOS DESHABILITADO ────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 3: NetBIOS deshabilitado (TcpipNetbiosOptions = 2)' -ForegroundColor White
try {
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop
    $notDisabled = @($adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })

    if ($notDisabled.Count -eq 0) {
        Write-TestResult -Name 'NetBIOS deshabilitado en todos los adaptadores' -Status 'PASS' `
            -Detail "$($adapters.Count) adaptador(es) verificado(s)"
    }
    else {
        $names = ($notDisabled | ForEach-Object { $_.Description }) -join '; '
        Write-TestResult -Name 'NetBIOS deshabilitado en todos los adaptadores' -Status 'FAIL' `
            -Detail "NetBIOS activo en: $names"
    }
}
catch {
    Write-TestResult -Name 'NetBIOS deshabilitado en todos los adaptadores' -Status 'WARN' `
        -Detail "No se pudo consultar adaptadores: $_"
}

# ─── TEST 4: LLMNR DESHABILITADO ──────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 4: LLMNR deshabilitado' -ForegroundColor White
$llmnrCheck = Invoke-RegistryCheck `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
    -Name 'EnableMulticast' `
    -ExpectedValue 0
Write-TestResult -Name 'LLMNR deshabilitado (EnableMulticast=0)' `
    -Status $llmnrCheck.Status -Detail $llmnrCheck.Detail

# ─── TEST 5: LSASS RunAsPPL ───────────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 5: LSASS RunAsPPL habilitado' -ForegroundColor White
$pplCheck = Invoke-RegistryCheck `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RunAsPPL' `
    -ExpectedValue 1
Write-TestResult -Name 'LSASS RunAsPPL = 1' -Status $pplCheck.Status -Detail $pplCheck.Detail

# ─── TEST 6: WDIGEST DESHABILITADO ────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 6: WDigest deshabilitado' -ForegroundColor White
$wdigestCheck = Invoke-RegistryCheck `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
    -Name 'UseLogonCredential' `
    -ExpectedValue 0
Write-TestResult -Name 'WDigest UseLogonCredential = 0' `
    -Status $wdigestCheck.Status -Detail $wdigestCheck.Detail

# ─── TEST 7: SMARTSCREEN ACTIVO ───────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 7: SmartScreen activo' -ForegroundColor White
try {
    $ssPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
    $ssProp = Get-ItemProperty -Path $ssPath -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue

    if ($null -eq $ssProp) {
        Write-TestResult -Name 'SmartScreen habilitado' -Status 'WARN' `
            -Detail 'Valor SmartScreenEnabled no encontrado (puede estar gestionado por GPO)'
    }
    elseif ($ssProp.SmartScreenEnabled -in @('On', 'Warn')) {
        Write-TestResult -Name 'SmartScreen habilitado' -Status 'PASS' `
            -Detail "SmartScreenEnabled = $($ssProp.SmartScreenEnabled)"
    }
    else {
        Write-TestResult -Name 'SmartScreen habilitado' -Status 'FAIL' `
            -Detail "SmartScreenEnabled = $($ssProp.SmartScreenEnabled) (esperado: On o Warn)"
    }
}
catch {
    Write-TestResult -Name 'SmartScreen habilitado' -Status 'WARN' -Detail "Error: $_"
}

# ─── TEST 8: UAC HABILITADO ───────────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 8: UAC habilitado (EnableLUA = 1)' -ForegroundColor White
$uacCheck = Invoke-RegistryCheck `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'EnableLUA' `
    -ExpectedValue 1
Write-TestResult -Name 'UAC habilitado (EnableLUA = 1)' -Status $uacCheck.Status -Detail $uacCheck.Detail

# ─── TEST 9: DEP HABILITADO ───────────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 9: DEP habilitado (DataExecutionPrevention_SupportPolicy >= 2)' -ForegroundColor White
try {
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
    $depPolicy = $os.DataExecutionPrevention_SupportPolicy

    if ($depPolicy -ge 2) {
        Write-TestResult -Name 'DEP habilitado' -Status 'PASS' `
            -Detail "DataExecutionPrevention_SupportPolicy = $depPolicy"
    }
    else {
        Write-TestResult -Name 'DEP habilitado' -Status 'FAIL' `
            -Detail "DataExecutionPrevention_SupportPolicy = $depPolicy (esperado >= 2)"
    }
}
catch {
    Write-TestResult -Name 'DEP habilitado' -Status 'WARN' -Detail "No se pudo consultar: $_"
}

# ─── TEST 10: SCRIPT BLOCK LOGGING ────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 10: Script Block Logging habilitado' -ForegroundColor White
$sblCheck = Invoke-RegistryCheck `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name 'EnableScriptBlockLogging' `
    -ExpectedValue 1
Write-TestResult -Name 'Script Block Logging habilitado' -Status $sblCheck.Status -Detail $sblCheck.Detail

# ─── TEST 11: POWERSHELL V2 DESHABILITADO ─────────────────────────────────────

Write-Host ''
Write-Host '  TEST 11: PowerShell v2 deshabilitado' -ForegroundColor White
try {
    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -ErrorAction Stop
    if ($ps2.State -eq 'Disabled') {
        Write-TestResult -Name 'PowerShell v2 deshabilitado' -Status 'PASS' `
            -Detail "MicrosoftWindowsPowerShellV2 State = $($ps2.State)"
    }
    else {
        Write-TestResult -Name 'PowerShell v2 deshabilitado' -Status 'FAIL' `
            -Detail "MicrosoftWindowsPowerShellV2 State = $($ps2.State)"
    }
}
catch {
    Write-TestResult -Name 'PowerShell v2 deshabilitado' -Status 'WARN' `
        -Detail "Característica no disponible o no consultable en este sistema: $_"
}

# ─── TEST 12: CONFIGURACIÓN TLS ───────────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 12: Configuración TLS (1.0 deshabilitado, 1.2 habilitado)' -ForegroundColor White

$tlsBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

# TLS 1.0 Server — Enabled debe ser 0
$tls10Check = Invoke-RegistryCheck -Path "$tlsBase\TLS 1.0\Server" -Name 'Enabled' -ExpectedValue 0
$tls10Status = if ($tls10Check.Status -eq 'WARN') { 'WARN' } else { $tls10Check.Status }
Write-TestResult -Name 'TLS 1.0 Server deshabilitado (Enabled=0)' `
    -Status $tls10Status -Detail $tls10Check.Detail

# TLS 1.1 Server — Enabled debe ser 0
$tls11Check = Invoke-RegistryCheck -Path "$tlsBase\TLS 1.1\Server" -Name 'Enabled' -ExpectedValue 0
$tls11Status = if ($tls11Check.Status -eq 'WARN') { 'WARN' } else { $tls11Check.Status }
Write-TestResult -Name 'TLS 1.1 Server deshabilitado (Enabled=0)' `
    -Status $tls11Status -Detail $tls11Check.Detail

# TLS 1.2 Server — Enabled debe ser 1
$tls12Check = Invoke-RegistryCheck -Path "$tlsBase\TLS 1.2\Server" -Name 'Enabled' -ExpectedValue 1
$tls12Status = if ($tls12Check.Status -eq 'WARN') { 'WARN' } else { $tls12Check.Status }
Write-TestResult -Name 'TLS 1.2 Server habilitado (Enabled=1)' `
    -Status $tls12Status -Detail $tls12Check.Detail

# ─── TEST 13: DEFENDER ACTIVO Y FIRMAS FRESCAS ────────────────────────────────

Write-Host ''
Write-Host '  TEST 13: Defender activo y firmas actualizadas (<= 7 dias)' -ForegroundColor White
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop

    if (-not $mpStatus.AntivirusEnabled) {
        Write-TestResult -Name 'Defender Antivirus habilitado' -Status 'FAIL' `
            -Detail 'AntivirusEnabled = False'
    }
    else {
        Write-TestResult -Name 'Defender Antivirus habilitado' -Status 'PASS' `
            -Detail 'AntivirusEnabled = True'
    }

    $sigAge = $mpStatus.AntivirusSignatureAge
    if ($sigAge -le 7) {
        Write-TestResult -Name 'Firmas Defender frescas (<= 7 dias)' -Status 'PASS' `
            -Detail "AntivirusSignatureAge = $sigAge dia(s)"
    }
    else {
        Write-TestResult -Name 'Firmas Defender frescas (<= 7 dias)' -Status 'FAIL' `
            -Detail "AntivirusSignatureAge = $sigAge dia(s) (requiere actualizacion)"
    }
}
catch {
    Write-TestResult -Name 'Defender Antivirus habilitado' -Status 'WARN' `
        -Detail "No se pudo consultar estado de Defender: $_"
}

# ─── TEST 14: REGLAS ASR CONFIGURADAS ─────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 14: Reglas ASR configuradas' -ForegroundColor White
try {
    $mpPref = Get-MpPreference -ErrorAction Stop
    $asrActions = $mpPref.AttackSurfaceReductionRules_Actions

    if ($null -ne $asrActions -and $asrActions.Count -gt 0) {
        Write-TestResult -Name 'Reglas ASR configuradas' -Status 'PASS' `
            -Detail "$($asrActions.Count) regla(s) con accion definida"
    }
    else {
        Write-TestResult -Name 'Reglas ASR configuradas' -Status 'FAIL' `
            -Detail 'AttackSurfaceReductionRules_Actions esta vacio (sin reglas configuradas)'
    }
}
catch {
    Write-TestResult -Name 'Reglas ASR configuradas' -Status 'WARN' `
        -Detail "No se pudo consultar MpPreference: $_"
}

# ─── TEST 15: POLÍTICAS DE CONTRASEÑA ─────────────────────────────────────────

Write-Host ''
Write-Host '  TEST 15: Politicas de contrasena (minlen >= 12, maxage <= 90)' -ForegroundColor White
try {
    $netOutput = net accounts 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-TestResult -Name 'Politicas de contrasena' -Status 'WARN' `
            -Detail "net accounts retorno codigo $LASTEXITCODE"
    }
    else {
        # Parsear longitud minima
        $minLenLine = $netOutput | Where-Object { $_ -match 'Minimum password length' } | Select-Object -First 1
        $minLenStr  = if ($minLenLine) { ($minLenLine -replace '[^\d]', '').Trim() } else { '0' }
        $minLen     = if ($minLenStr -match '^\d+$') { [int]$minLenStr } else { 0 }

        # Parsear edad maxima (puede ser "Unlimited")
        $maxAgeLine = $netOutput | Where-Object { $_ -match 'Maximum password age' } | Select-Object -First 1
        $maxAgeStr  = if ($maxAgeLine) { ($maxAgeLine -replace 'Maximum password age.*?(\d+|Unlimited).*','$1').Trim() } else { '0' }

        if ($minLen -ge 12) {
            Write-TestResult -Name 'Longitud minima de contrasena >= 12' -Status 'PASS' `
                -Detail "Minimum password length = $minLen"
        }
        else {
            Write-TestResult -Name 'Longitud minima de contrasena >= 12' -Status 'FAIL' `
                -Detail "Minimum password length = $minLen (esperado >= 12)"
        }

        if ($maxAgeStr -eq 'Unlimited') {
            Write-TestResult -Name 'Edad maxima de contrasena <= 90 dias' -Status 'WARN' `
                -Detail 'Maximum password age = Unlimited (sin expiracion configurada)'
        }
        else {
            $maxAge = if ($maxAgeStr -match '^\d+$') { [int]$maxAgeStr } else { 999 }
            if ($maxAge -le 90) {
                Write-TestResult -Name 'Edad maxima de contrasena <= 90 dias' -Status 'PASS' `
                    -Detail "Maximum password age = $maxAge dias"
            }
            else {
                Write-TestResult -Name 'Edad maxima de contrasena <= 90 dias' -Status 'FAIL' `
                    -Detail "Maximum password age = $maxAge dias (esperado <= 90)"
            }
        }
    }
}
catch {
    Write-TestResult -Name 'Politicas de contrasena' -Status 'WARN' `
        -Detail "Error al ejecutar net accounts: $_"
}

# ─── RESUMEN ──────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  ================================================================' -ForegroundColor Cyan
Write-Host '   RESUMEN DE VERIFICACION' -ForegroundColor Cyan
Write-Host '  ================================================================' -ForegroundColor Cyan

$totalPass = ($Script:Results | Where-Object Status -eq 'PASS').Count
$totalFail = ($Script:Results | Where-Object Status -eq 'FAIL').Count
$totalWarn = ($Script:Results | Where-Object Status -eq 'WARN').Count
$totalAll  = $Script:Results.Count

Write-Host "  Total verificaciones : $totalAll" -ForegroundColor White
Write-Host "  PASS                 : $totalPass" -ForegroundColor Green
Write-Host "  FAIL                 : $totalFail" -ForegroundColor Red
Write-Host "  WARN                 : $totalWarn" -ForegroundColor Yellow
Write-Host ''

$scoreColor = if ($totalFail -eq 0) { 'Green' } elseif ($totalFail -le 3) { 'Yellow' } else { 'Red' }
Write-Host "  Estado general       : $(if ($totalFail -eq 0) { 'CORRECTO' } elseif ($totalFail -le 3) { 'REVISION RECOMENDADA' } else { 'REQUIERE ATENCION' })" -ForegroundColor $scoreColor
Write-Host ''

# ─── ESCRIBIR REPORTE EN ARCHIVO ──────────────────────────────────────────────

try {
    $reportFile = Join-Path $env:TEMP "HardeningReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('================================================================================')
    $null = $sb.AppendLine('  Windows Hardening Toolkit — Reporte de Verificacion')
    $null = $sb.AppendLine('================================================================================')
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("  Fecha    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("  Hostname : $env:COMPUTERNAME")
    $null = $sb.AppendLine("  Usuario  : $env:USERNAME")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('  RESULTADOS:')
    $null = $sb.AppendLine('  ----------')

    foreach ($r in $Script:Results) {
        $line = "  [$($r.Status.PadRight(4))] $($r.Name)"
        if ($r.Detail) { $line += " — $($r.Detail)" }
        $null = $sb.AppendLine($line)
    }

    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('  RESUMEN:')
    $null = $sb.AppendLine("  Total : $totalAll  |  PASS: $totalPass  |  FAIL: $totalFail  |  WARN: $totalWarn")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('================================================================================')
    $null = $sb.AppendLine('  Windows Hardening Toolkit v1.0.0')
    $null = $sb.AppendLine('================================================================================')

    $utf8bom = [System.Text.UTF8Encoding]::new($true)
    [System.IO.File]::WriteAllText($reportFile, $sb.ToString(), $utf8bom)

    Write-Host "  Reporte guardado en: $reportFile" -ForegroundColor Cyan
}
catch {
    Write-Host "  No se pudo guardar el reporte: $_" -ForegroundColor Red
}

Write-Host ''
