#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - Reporting Module
.DESCRIPTION
    Genera reportes de seguridad en múltiples formatos (TXT, HTML, JSON, CSV).
    Los reportes incluyen resultados de auditoría, acciones aplicadas y puntuación.
.NOTES
    Standard: NIST 800-53 AU-6 (Audit Review, Analysis, and Reporting)
    Compatible: PowerShell 5.1 / PowerShell 7+
#>

# ─── RUTA BASE DE REPORTES ────────────────────────────────────────────────────

$Script:ReportBasePath = 'reports'   # Relativo al directorio del toolkit

function Get-ReportPath {
    <#
    .SYNOPSIS
        Devuelve la ruta absoluta del directorio de reportes.
    #>
    $scriptRoot = if ($PSScriptRoot) { Split-Path $PSScriptRoot } else { $PSScriptRoot }
    return Join-Path $scriptRoot $Script:ReportBasePath
}

# ─── GENERAR REPORTE TXT ──────────────────────────────────────────────────────

function New-TextReport {
    <#
    .SYNOPSIS
        Genera un reporte de seguridad en formato de texto plano.
    .PARAMETER AuditResults
        Array de resultados de auditoría (PSCustomObject[]).
    .PARAMETER HardeningActions
        Array de acciones de hardening aplicadas.
    .PARAMETER Score
        Puntuación de seguridad (0-100).
    .PARAMETER OutputPath
        Ruta del archivo de salida. Si no se provee, se genera automáticamente.
    #>
    [CmdletBinding()]
    param(
        [array]$AuditResults     = @(),
        [array]$HardeningActions = @(),
        [float]$Score            = 0,
        [string]$OutputPath      = ''
    )

    $reportPath = if ($OutputPath) { $OutputPath } else {
        $dir      = Get-ReportPath
        $filename = "security_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Join-Path $dir $filename
    }

    $osInfo      = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $secure      = ($AuditResults | Where-Object Status -eq 'SECURE').Count
    $warning     = ($AuditResults | Where-Object Status -eq 'WARNING').Count
    $vulnerable  = ($AuditResults | Where-Object Status -eq 'VULNERABLE').Count
    $scoreRating = if ($Score -ge 80) { 'BUENO' } elseif ($Score -ge 60) { 'ACEPTABLE' } else { 'CRITICO' }

    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("================================================================================")
    $null = $sb.AppendLine("  WINDOWS HARDENING TOOLKIT - REPORTE DE SEGURIDAD")
    $null = $sb.AppendLine("================================================================================")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("  Fecha             : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("  Hostname          : $($env:COMPUTERNAME)")
    $null = $sb.AppendLine("  Usuario           : $($env:USERNAME)")
    $null = $sb.AppendLine("  Sistema Operativo : $($osInfo?.Caption)")
    $null = $sb.AppendLine("  Versión OS        : $($osInfo?.Version)")
    $null = $sb.AppendLine("  PS Version        : $($PSVersionTable.PSVersion)")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    $null = $sb.AppendLine("  PUNTUACIÓN DE SEGURIDAD")
    $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("  Security Score    : $Score% [$scoreRating]")
    $null = $sb.AppendLine("  Total controles   : $($AuditResults.Count)")
    $null = $sb.AppendLine("  SECURE            : $secure")
    $null = $sb.AppendLine("  WARNING           : $warning")
    $null = $sb.AppendLine("  VULNERABLE        : $vulnerable")
    $null = $sb.AppendLine("")

    # Resumen por categoría
    $categories = $AuditResults | Select-Object -ExpandProperty Category -Unique
    $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    $null = $sb.AppendLine("  RESUMEN POR CATEGORÍA")
    $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    $null = $sb.AppendLine("")

    foreach ($cat in ($categories | Sort-Object)) {
        $catResults = $AuditResults | Where-Object Category -eq $cat
        $catSecure  = ($catResults | Where-Object Status -eq 'SECURE').Count
        $catWarning = ($catResults | Where-Object Status -eq 'WARNING').Count
        $catVuln    = ($catResults | Where-Object Status -eq 'VULNERABLE').Count
        $catTotal   = $catResults.Count
        $catScore   = if ($catTotal -gt 0) { [math]::Round(($catSecure / $catTotal) * 100) } else { 0 }

        $statusIcon = if ($catVuln -gt 0) { '[VULN]' } elseif ($catWarning -gt 0) { '[WARN]' } else { '[OK]  ' }
        $null = $sb.AppendLine("  $statusIcon $($cat.PadRight(20)) Score: $($catScore.ToString().PadLeft(3))%  | OK:$catSecure  WARN:$catWarning  VULN:$catVuln")
    }

    # Controles VULNERABLE
    if ($vulnerable -gt 0) {
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        $null = $sb.AppendLine("  CONTROLES VULNERABLES (ACCIÓN INMEDIATA REQUERIDA)")
        $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        $null = $sb.AppendLine("")

        foreach ($item in ($AuditResults | Where-Object Status -eq 'VULNERABLE')) {
            $null = $sb.AppendLine("  [VULNERABLE] $($item.Category) | $($item.Control)")
            $null = $sb.AppendLine("    Estado actual  : $($item.CurrentValue)")
            $null = $sb.AppendLine("    Estado esperado: $($item.ExpectedValue)")
            $null = $sb.AppendLine("    Remediación    : $($item.Remediation)")
            if ($item.Reference) {
            $null = $sb.AppendLine("    Referencia     : $($item.Reference)")
            }
            $null = $sb.AppendLine("")
        }
    }

    # Controles WARNING
    if ($warning -gt 0) {
        $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        $null = $sb.AppendLine("  CONTROLES EN ADVERTENCIA")
        $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        $null = $sb.AppendLine("")

        foreach ($item in ($AuditResults | Where-Object Status -eq 'WARNING')) {
            $null = $sb.AppendLine("  [WARNING] $($item.Category) | $($item.Control)")
            $null = $sb.AppendLine("    Estado actual  : $($item.CurrentValue)")
            $null = $sb.AppendLine("    Remediación    : $($item.Remediation)")
            $null = $sb.AppendLine("")
        }
    }

    # Referencia estándar rápida
    $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    $null = $sb.AppendLine("  ESTADO CONSOLIDADO (FORMATO EJECUTIVO)")
    $null = $sb.AppendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    $null = $sb.AppendLine("")

    # Estado de controles clave
    $keyControls = @(
        @{ Label = 'Firewall (Domain/Private/Public)'; Cat = 'Firewall'; Search = 'Perfil' }
        @{ Label = 'SMBv1 Protocol';                   Cat = 'Network';  Search = 'SMBv1' }
        @{ Label = 'LLMNR';                             Cat = 'Network';  Search = 'LLMNR' }
        @{ Label = 'NetBIOS';                           Cat = 'Network';  Search = 'NetBIOS' }
        @{ Label = 'NTLMv1';                            Cat = 'Authentication'; Search = 'NTLM' }
        @{ Label = 'TLS 1.0';                           Cat = 'TLS';      Search = 'TLS 1.0' }
        @{ Label = 'TLS 1.1';                           Cat = 'TLS';      Search = 'TLS 1.1' }
        @{ Label = 'TLS 1.2';                           Cat = 'TLS';      Search = 'TLS 1.2' }
        @{ Label = 'ASR Rules';                         Cat = 'ASR';      Search = 'ransomware' }
        @{ Label = 'Defender Real-Time';                Cat = 'Defender'; Search = 'Real-Time' }
        @{ Label = 'WDigest';                           Cat = 'Credentials'; Search = 'WDigest' }
        @{ Label = 'LSASS PPL';                         Cat = 'Credentials'; Search = 'RunAsPPL' }
    )

    foreach ($ctrl in $keyControls) {
        $found = $AuditResults | Where-Object {
            $_.Category -eq $ctrl.Cat -and $_.Control -like "*$($ctrl.Search)*"
        } | Select-Object -First 1

        $status = if ($found) { $found.Status } else { 'N/A' }
        $value  = if ($found) { $found.CurrentValue } else { 'No auditado' }
        $statusPad = $status.PadRight(12)
        $labelPad  = $ctrl.Label.PadRight(35)
        $null = $sb.AppendLine("  $labelPad : $statusPad | $value")
    }

    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("================================================================================")
    $null = $sb.AppendLine("  Reporte generado por Windows Hardening Toolkit v1.0.0")
    $null = $sb.AppendLine("  Estándares: CIS Benchmarks | Microsoft Security Baseline | NIST 800-53 | MITRE ATT&CK")
    $null = $sb.AppendLine("================================================================================")

    try {
        $sb.ToString() | Out-File -FilePath $reportPath -Encoding UTF8 -Force
        Write-LogSuccess "Reporte TXT generado: $reportPath" -Component 'Reporting'
        return $reportPath
    }
    catch {
        Write-LogError "No se pudo guardar el reporte: $_" -Component 'Reporting'
        return $null
    }
}

# ─── GENERAR REPORTE HTML ─────────────────────────────────────────────────────

function New-HtmlReport {
    <#
    .SYNOPSIS
        Genera un reporte de seguridad en formato HTML interactivo.
    .PARAMETER AuditResults
        Array de resultados de auditoría.
    .PARAMETER Score
        Puntuación de seguridad.
    .PARAMETER OutputPath
        Ruta de salida del HTML. Si no se provee, se genera automáticamente.
    #>
    [CmdletBinding()]
    param(
        [array]$AuditResults = @(),
        [float]$Score        = 0,
        [string]$OutputPath  = ''
    )

    $reportPath = if ($OutputPath) { $OutputPath } else {
        $dir      = Get-ReportPath
        $filename = "security_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Join-Path $dir $filename
    }

    $osInfo     = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $secure     = ($AuditResults | Where-Object Status -eq 'SECURE').Count
    $warning    = ($AuditResults | Where-Object Status -eq 'WARNING').Count
    $vulnerable = ($AuditResults | Where-Object Status -eq 'VULNERABLE').Count
    $scoreColor = if ($Score -ge 80) { '#28a745' } elseif ($Score -ge 60) { '#ffc107' } else { '#dc3545' }
    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Construir filas de tabla
    $tableRows = foreach ($item in ($AuditResults | Sort-Object Category, Status)) {
        $rowClass = switch ($item.Status) {
            'SECURE'     { 'table-success' }
            'WARNING'    { 'table-warning' }
            'VULNERABLE' { 'table-danger'  }
            default      { '' }
        }
        $badge = switch ($item.Status) {
            'SECURE'     { '<span class="badge bg-success">SECURE</span>'     }
            'WARNING'    { '<span class="badge bg-warning text-dark">WARNING</span>' }
            'VULNERABLE' { '<span class="badge bg-danger">VULNERABLE</span>'  }
            default      { '<span class="badge bg-secondary">N/A</span>'      }
        }
        "<tr class='$rowClass'><td>$($item.Category)</td><td>$($item.Control)</td><td>$badge</td><td>$([System.Web.HttpUtility]::HtmlEncode($item.CurrentValue))</td><td>$([System.Web.HttpUtility]::HtmlEncode($item.ExpectedValue))</td><td><small>$($item.Reference)</small></td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Hardening Toolkit - Security Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', monospace; }
        .card { background: #161b22; border: 1px solid #30363d; }
        .card-header { background: #21262d; }
        .score-circle { width: 150px; height: 150px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; font-weight: bold; border: 8px solid $scoreColor; color: $scoreColor; }
        table { color: #c9d1d9; }
        .table-success { background-color: rgba(40,167,69,0.15) !important; }
        .table-warning { background-color: rgba(255,193,7,0.15) !important; }
        .table-danger  { background-color: rgba(220,53,69,0.15) !important; }
        th { background: #21262d; color: #58a6ff; }
        .stat-card { text-align: center; padding: 20px; }
        .stat-number { font-size: 2rem; font-weight: bold; }
        header { background: #161b22; border-bottom: 2px solid #30363d; padding: 20px; margin-bottom: 30px; }
    </style>
</head>
<body>
<header>
    <div class="container">
        <h1 class="text-info">🔒 Windows Hardening Toolkit</h1>
        <p class="text-muted mb-0">Security Report | $timestamp | $($env:COMPUTERNAME)</p>
    </div>
</header>

<div class="container pb-5">
    <!-- System Info -->
    <div class="card mb-4">
        <div class="card-header"><h5 class="mb-0 text-info">Información del Sistema</h5></div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <table class="table table-sm table-borderless">
                        <tr><td class="text-muted">Hostname</td><td>$($env:COMPUTERNAME)</td></tr>
                        <tr><td class="text-muted">Usuario</td><td>$($env:USERNAME)</td></tr>
                        <tr><td class="text-muted">Sistema Operativo</td><td>$($osInfo?.Caption)</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <table class="table table-sm table-borderless">
                        <tr><td class="text-muted">Versión OS</td><td>$($osInfo?.Version)</td></tr>
                        <tr><td class="text-muted">PowerShell</td><td>$($PSVersionTable.PSVersion)</td></tr>
                        <tr><td class="text-muted">Fecha del reporte</td><td>$timestamp</td></tr>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Score Dashboard -->
    <div class="card mb-4">
        <div class="card-header"><h5 class="mb-0 text-info">Security Score</h5></div>
        <div class="card-body">
            <div class="row align-items-center">
                <div class="col-md-3 text-center">
                    <div class="score-circle mx-auto">$Score%</div>
                    <p class="mt-2 text-muted">Security Score</p>
                </div>
                <div class="col-md-9">
                    <div class="row text-center">
                        <div class="col-md-3 stat-card">
                            <div class="stat-number text-secondary">$($AuditResults.Count)</div>
                            <div class="text-muted">Total Controles</div>
                        </div>
                        <div class="col-md-3 stat-card">
                            <div class="stat-number text-success">$secure</div>
                            <div class="text-muted">SECURE</div>
                        </div>
                        <div class="col-md-3 stat-card">
                            <div class="stat-number text-warning">$warning</div>
                            <div class="text-muted">WARNING</div>
                        </div>
                        <div class="col-md-3 stat-card">
                            <div class="stat-number text-danger">$vulnerable</div>
                            <div class="text-muted">VULNERABLE</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Audit Results Table -->
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0 text-info">Resultados de Auditoría</h5>
            <input class="form-control w-25 bg-dark text-light border-secondary" type="text" id="searchInput" placeholder="Filtrar..." onkeyup="filterTable()">
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover mb-0" id="auditTable">
                    <thead><tr><th>Categoría</th><th>Control</th><th>Estado</th><th>Valor Actual</th><th>Valor Esperado</th><th>Referencia</th></tr></thead>
                    <tbody>
                        $($tableRows -join "`n")
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="text-center text-muted mt-4">
        <small>Windows Hardening Toolkit v1.0.0 | CIS Benchmarks | Microsoft Security Baseline | NIST 800-53 | MITRE ATT&CK</small>
    </div>
</div>

<script>
function filterTable() {
    var input = document.getElementById("searchInput").value.toLowerCase();
    var rows  = document.querySelectorAll("#auditTable tbody tr");
    rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(input) ? "" : "none";
    });
}
</script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $reportPath -Encoding UTF8 -Force
        Write-LogSuccess "Reporte HTML generado: $reportPath" -Component 'Reporting'
        return $reportPath
    }
    catch {
        Write-LogError "No se pudo guardar el reporte HTML: $_" -Component 'Reporting'
        return $null
    }
}

# ─── GENERAR REPORTE JSON ─────────────────────────────────────────────────────

function New-JsonReport {
    <#
    .SYNOPSIS
        Genera un reporte de seguridad en formato JSON (para integración con SIEM/tools).
    #>
    [CmdletBinding()]
    param(
        [array]$AuditResults = @(),
        [float]$Score        = 0,
        [string]$OutputPath  = ''
    )

    $reportPath = if ($OutputPath) { $OutputPath } else {
        $dir      = Get-ReportPath
        $filename = "security_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Join-Path $dir $filename
    }

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

    $report = @{
        Metadata = @{
            Timestamp       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Hostname        = $env:COMPUTERNAME
            Username        = $env:USERNAME
            OS              = $osInfo?.Caption
            OSVersion       = $osInfo?.Version
            PSVersion       = $PSVersionTable.PSVersion.ToString()
            ToolkitVersion  = '1.0.0'
        }
        Summary = @{
            Score      = $Score
            Total      = $AuditResults.Count
            Secure     = ($AuditResults | Where-Object Status -eq 'SECURE').Count
            Warning    = ($AuditResults | Where-Object Status -eq 'WARNING').Count
            Vulnerable = ($AuditResults | Where-Object Status -eq 'VULNERABLE').Count
        }
        Results = $AuditResults
    }

    try {
        $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8 -Force
        Write-LogSuccess "Reporte JSON generado: $reportPath" -Component 'Reporting'
        return $reportPath
    }
    catch {
        Write-LogError "No se pudo guardar el reporte JSON: $_" -Component 'Reporting'
        return $null
    }
}

# ─── FUNCIÓN MAESTRA DE REPORTE ───────────────────────────────────────────────

function Invoke-GenerateReport {
    <#
    .SYNOPSIS
        Genera todos los formatos de reporte disponibles.
    .PARAMETER AuditResults
        Resultados de la auditoría. Si no se provee, ejecuta una auditoría nueva.
    .PARAMETER Score
        Puntuación de seguridad. Si no se provee, se calcula de AuditResults.
    .PARAMETER Formats
        Formatos a generar: TXT, HTML, JSON. Por defecto: todos.
    #>
    [CmdletBinding()]
    param(
        [array]$AuditResults = @(),
        [float]$Score        = 0,
        [ValidateSet('TXT', 'HTML', 'JSON')]
        [string[]]$Formats   = @('TXT', 'HTML', 'JSON')
    )

    Write-LogSection "Generando Reportes de Seguridad"

    # Calcular score si no se provee
    if ($Score -eq 0 -and $AuditResults.Count -gt 0) {
        $secure = ($AuditResults | Where-Object Status -eq 'SECURE').Count
        $Score  = [math]::Round(($secure / $AuditResults.Count) * 100, 1)
    }

    $generatedFiles = @()

    foreach ($format in $Formats) {
        switch ($format) {
            'TXT'  { $path = New-TextReport -AuditResults $AuditResults -Score $Score }
            'HTML' { $path = New-HtmlReport -AuditResults $AuditResults -Score $Score }
            'JSON' { $path = New-JsonReport -AuditResults $AuditResults -Score $Score }
        }
        if ($path) { $generatedFiles += $path }
    }

    Write-LogSuccess "$($generatedFiles.Count) reporte(s) generados." -Component 'Reporting'

    # Guardar también la ruta estándar security_report.txt
    $standardPath = Join-Path (Get-ReportPath) 'security_report.txt'
    if ($generatedFiles | Where-Object { $_ -like '*.txt' }) {
        $txtFile = $generatedFiles | Where-Object { $_ -like '*.txt' } | Select-Object -First 1
        try {
            Copy-Item -Path $txtFile -Destination $standardPath -Force
        }
        catch {}
    }

    return $generatedFiles
}
