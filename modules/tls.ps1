#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Toolkit - TLS/SSL Protocol Module
.DESCRIPTION
    Configura protocolos TLS/SSL en el sistema operativo via SCHANNEL.
    Deshabilita SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1.
    Habilita TLS 1.2 y TLS 1.3.
    Configura cipher suites y key exchange algorithms seguros.
.NOTES
    Standard: NIST SP 800-52 Rev.2, CIS Benchmark 18.10, PCI-DSS 4.0
    Compatible: PowerShell 5.1 / PowerShell 7+
    IMPORTANTE: Algunos cambios requieren reinicio del servidor web/IIS o del sistema.
#>

# ─── BASE DE REGISTRO SCHANNEL ────────────────────────────────────────────────

$Script:SchannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

# ─── CONFIGURAR PROTOCOLO ─────────────────────────────────────────────────────

function Set-TlsProtocol {
    <#
    .SYNOPSIS
        Habilita o deshabilita un protocolo TLS/SSL en SCHANNEL para Server y/o Client.
    .PARAMETER Protocol
        Nombre del protocolo (ej: 'TLS 1.0', 'SSL 2.0')
    .PARAMETER Enabled
        True para habilitar, False para deshabilitar.
    .PARAMETER Role
        'Server', 'Client' o 'Both' (por defecto).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Protocol,

        [Parameter(Mandatory)]
        [bool]$Enabled,

        [ValidateSet('Server', 'Client', 'Both')]
        [string]$Role = 'Both'
    )

    $enabledVal  = if ($Enabled) { 1 } else { 0 }
    $disabledVal = if ($Enabled) { 0 } else { 1 }

    $roles = switch ($Role) {
        'Server' { @('Server') }
        'Client' { @('Client') }
        'Both'   { @('Server', 'Client') }
    }

    foreach ($r in $roles) {
        $regPath = "$Script:SchannelBase\Protocols\$Protocol\$r"

        try {
            if (-not (Test-Path $regPath)) {
                if ($PSCmdlet.ShouldProcess($regPath, 'Crear clave de registro')) {
                    New-Item -Path $regPath -Force | Out-Null
                }
            }

            $actionLabel = if ($Enabled) { 'Habilitar' } else { 'Deshabilitar' }
            if ($PSCmdlet.ShouldProcess("$Protocol/$r", $actionLabel)) {
                Set-ItemProperty -Path $regPath -Name 'Enabled'           -Value $enabledVal  -Type DWord -Force
                Set-ItemProperty -Path $regPath -Name 'DisabledByDefault' -Value $disabledVal -Type DWord -Force

                $action = if ($Enabled) { 'habilitado' } else { 'deshabilitado' }
                Write-LogSuccess "SCHANNEL: $Protocol ($r) $action." -Component 'TLS'
            }
        }
        catch {
            Write-LogError "Error configurando $Protocol/$r : $_" -Component 'TLS'
        }
    }
}

# ─── DESHABILITAR PROTOCOLOS INSEGUROS ────────────────────────────────────────

function Disable-InsecureProtocols {
    <#
    .SYNOPSIS
        Deshabilita todos los protocolos SSL/TLS considerados inseguros.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Deshabilitando protocolos inseguros (SSL/TLS legacy)"

    $insecureProtocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')

    foreach ($proto in $insecureProtocols) {
        Set-TlsProtocol -Protocol $proto -Enabled $false -Role 'Both'
    }
}

# ─── HABILITAR PROTOCOLOS SEGUROS ─────────────────────────────────────────────

function Enable-SecureProtocols {
    <#
    .SYNOPSIS
        Habilita TLS 1.2 y TLS 1.3.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Habilitando TLS 1.2 y TLS 1.3"

    $secureProtocols = @('TLS 1.2', 'TLS 1.3')

    foreach ($proto in $secureProtocols) {
        Set-TlsProtocol -Protocol $proto -Enabled $true -Role 'Both'
    }
}

# ─── CONFIGURAR CIPHER SUITES SEGUROS ─────────────────────────────────────────

function Set-SecureCipherSuites {
    <#
    .SYNOPSIS
        Configura la lista de cipher suites permitidos vía GPO/registro.
        Prioriza AES-256-GCM, CHACHA20, y elimina RC4, DES, 3DES, NULL.
    .NOTES
        Usa el proveedor de políticas de Windows para cipher suites.
        En entornos con IIS, también aplicar via IIS Crypto o PowerShell.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Configurando Cipher Suites seguros"

    # Cipher suites recomendados (orden de preferencia)
    $secureCiphers = @(
        'TLS_AES_256_GCM_SHA384'                        # TLS 1.3
        'TLS_AES_128_GCM_SHA256'                        # TLS 1.3
        'TLS_CHACHA20_POLY1305_SHA256'                  # TLS 1.3
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
        'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
        'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
    )

    # Cipher suites a deshabilitar explícitamente
    $insecureCiphers = @(
        'RC4 128/128', 'RC4 64/128', 'RC4 56/128', 'RC4 40/128'
        'DES 56/56'
        'Triple DES 168'
        'NULL'
        'TLS_RSA_WITH_RC4_128_SHA'
        'TLS_RSA_WITH_RC4_128_MD5'
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        'TLS_RSA_WITH_NULL_SHA256'
        'TLS_RSA_WITH_NULL_SHA'
        'TLS_RSA_WITH_NULL_MD5'
    )

    # Deshabilitar ciphers inseguros via SCHANNEL
    $ciphersBase = "$Script:SchannelBase\Ciphers"

    foreach ($cipher in $insecureCiphers) {
        $cipherPath = "$ciphersBase\$cipher"
        try {
            if (-not (Test-Path $cipherPath)) {
                New-Item -Path $cipherPath -Force | Out-Null
            }
            Set-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 -Type DWord -Force
            Write-LogSuccess "Cipher deshabilitado: $cipher" -Component 'TLS'
        }
        catch {
            Write-LogDebug "No se pudo deshabilitar cipher '$cipher': $_" -Component 'TLS'
        }
    }

    # Configurar cipher suites permitidos via GPO (SSL Cipher Suite Order)
    $cipherPolicy = "$Script:SchannelBase\..\Cryptography\Configuration\SSL 0x00010000\Functions"
    $fullCipherPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'

    try {
        if (-not (Test-Path $fullCipherPath)) {
            New-Item -Path $fullCipherPath -Force | Out-Null
        }

        $cipherList = $secureCiphers -join ','
        if ($PSCmdlet.ShouldProcess('SSL Cipher Suite Order', 'Configurar lista segura')) {
            Set-ItemProperty -Path $fullCipherPath -Name 'Functions' -Value $cipherList -Type String -Force
            Write-LogSuccess "Cipher suite order configurado con $($secureCiphers.Count) suites seguros." -Component 'TLS'
        }
    }
    catch {
        Write-LogWarning "No se pudo configurar cipher suite order via GPO: $_" -Component 'TLS'
    }
}

# ─── CONFIGURAR ALGORITMOS DE HASH SEGUROS ────────────────────────────────────

function Set-SecureHashAlgorithms {
    <#
    .SYNOPSIS
        Deshabilita algoritmos de hash débiles (MD5, SHA1 para firma de código).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Configurando algoritmos de hash seguros"

    $hashBase = "$Script:SchannelBase\Hashes"

    # MD5 - deshabilitar para SCHANNEL
    $md5Path = "$hashBase\MD5"
    try {
        if (-not (Test-Path $md5Path)) { New-Item -Path $md5Path -Force | Out-Null }
        if ($PSCmdlet.ShouldProcess('Hash MD5', 'Deshabilitar en SCHANNEL')) {
            Set-ItemProperty -Path $md5Path -Name 'Enabled' -Value 0 -Type DWord -Force
            Write-LogSuccess "Hash MD5 deshabilitado en SCHANNEL." -Component 'TLS'
        }
    }
    catch {
        Write-LogDebug "No se pudo deshabilitar MD5: $_" -Component 'TLS'
    }

    # SHA1 - habilitar (aún necesario para compatibilidad) pero con advertencia
    $sha1Path = "$hashBase\SHA"
    try {
        if (-not (Test-Path $sha1Path)) { New-Item -Path $sha1Path -Force | Out-Null }
        Set-ItemProperty -Path $sha1Path -Name 'Enabled' -Value 0xffffffff -Type DWord -Force
        Write-LogInfo "SHA-1 mantenido habilitado por compatibilidad (SHA-256+ preferido)." -Component 'TLS'
    }
    catch {
        Write-LogDebug "No se pudo configurar SHA-1: $_" -Component 'TLS'
    }

    # SHA256, SHA384, SHA512 - habilitar explícitamente
    foreach ($sha in @('SHA256', 'SHA384', 'SHA512')) {
        $shaPath = "$hashBase\$sha"
        try {
            if (-not (Test-Path $shaPath)) { New-Item -Path $shaPath -Force | Out-Null }
            Set-ItemProperty -Path $shaPath -Name 'Enabled' -Value 0xffffffff -Type DWord -Force
            Write-LogSuccess "$sha habilitado explícitamente en SCHANNEL." -Component 'TLS'
        }
        catch {
            Write-LogDebug "No se pudo configurar $sha : $_" -Component 'TLS'
        }
    }
}

# ─── CONFIGURAR KEY EXCHANGE ALGORITHMS ───────────────────────────────────────

function Set-SecureKeyExchange {
    <#
    .SYNOPSIS
        Configura algoritmos de intercambio de claves seguros.
        Habilita ECDH, deshabilita Diffie-Hellman con parámetros débiles.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: Configurando Key Exchange Algorithms"

    $keBase = "$Script:SchannelBase\KeyExchangeAlgorithms"

    # Diffie-Hellman - habilitar con mínimo 2048 bits
    $dhPath = "$keBase\Diffie-Hellman"
    try {
        if (-not (Test-Path $dhPath)) { New-Item -Path $dhPath -Force | Out-Null }
        if ($PSCmdlet.ShouldProcess('Diffie-Hellman', 'Configurar mínimo 2048 bits')) {
            Set-ItemProperty -Path $dhPath -Name 'Enabled'            -Value 0xffffffff -Type DWord -Force
            Set-ItemProperty -Path $dhPath -Name 'ServerMinKeyBitLength' -Value 2048  -Type DWord -Force
            Write-LogSuccess "DH configurado con mínimo 2048-bit key length." -Component 'TLS'
        }
    }
    catch {
        Write-LogDebug "No se pudo configurar DH key size: $_" -Component 'TLS'
    }

    # ECDH - habilitar
    $ecdhPath = "$keBase\ECDH"
    try {
        if (-not (Test-Path $ecdhPath)) { New-Item -Path $ecdhPath -Force | Out-Null }
        Set-ItemProperty -Path $ecdhPath -Name 'Enabled' -Value 0xffffffff -Type DWord -Force
        Write-LogSuccess "ECDH habilitado." -Component 'TLS'
    }
    catch {
        Write-LogDebug "No se pudo configurar ECDH: $_" -Component 'TLS'
    }

    # PKCS - deshabilitar (vulnerable a padding oracle attacks)
    $pkcsPath = "$keBase\PKCS"
    try {
        if (-not (Test-Path $pkcsPath)) { New-Item -Path $pkcsPath -Force | Out-Null }
        Set-ItemProperty -Path $pkcsPath -Name 'Enabled' -Value 0 -Type DWord -Force
        Write-LogSuccess "PKCS Key Exchange deshabilitado." -Component 'TLS'
    }
    catch {
        Write-LogDebug "No se pudo deshabilitar PKCS: $_" -Component 'TLS'
    }
}

# ─── CONFIGURAR .NET FRAMEWORK PARA TLS 1.2+ ──────────────────────────────────

function Set-DotNetTlsSettings {
    <#
    .SYNOPSIS
        Configura .NET Framework para usar TLS 1.2+ por defecto.
        Crítico para aplicaciones .NET que no especifican versión TLS explícitamente.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Write-LogSection "Hardening: .NET Framework TLS Settings"

    $netPaths = @{
        'NET 4.0 (32-bit)' = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
        'NET 4.0 (64-bit)' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
        'NET 2.0 (32-bit)' = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'
        'NET 2.0 (64-bit)' = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727'
    }

    foreach ($net in $netPaths.GetEnumerator()) {
        $path = $net.Value
        if (-not (Test-Path $path)) { continue }

        try {
            if ($PSCmdlet.ShouldProcess($net.Key, 'Configurar SystemDefaultTlsVersions = 1')) {
                # SystemDefaultTlsVersions = 1: permite que el OS elija la mejor versión TLS
                Set-ItemProperty -Path $path -Name 'SystemDefaultTlsVersions' -Value 1 -Type DWord -Force
                # SchUseStrongCrypto = 1: deshabilita ciphers/protocolos débiles en .NET
                Set-ItemProperty -Path $path -Name 'SchUseStrongCrypto'        -Value 1 -Type DWord -Force
                Write-LogSuccess ".NET $($net.Key): TLS forzado a versiones seguras." -Component 'TLS'
            }
        }
        catch {
            Write-LogWarning "No se pudo configurar $($net.Key): $_" -Component 'TLS'
        }
    }
}

# ─── FUNCIÓN MAESTRA DE HARDENING TLS ─────────────────────────────────────────

function Invoke-TlsHardening {
    <#
    .SYNOPSIS
        Ejecuta hardening completo de TLS/SSL en SCHANNEL y .NET Framework.
    .PARAMETER SkipCipherSuites
        Omite la configuración de cipher suites (útil si hay restricciones empresariales).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$SkipCipherSuites
    )

    Write-LogInfo "Iniciando hardening de TLS/SSL..." -Component 'TLS'

    Disable-InsecureProtocols
    Enable-SecureProtocols

    if (-not $SkipCipherSuites) {
        Set-SecureCipherSuites
    }

    Set-SecureHashAlgorithms
    Set-SecureKeyExchange
    Set-DotNetTlsSettings

    Write-LogWarning "NOTA: Los cambios de TLS/SCHANNEL requieren reinicio del sistema o del servicio IIS para surtir efecto." -Component 'TLS'
    Write-LogSuccess "Hardening de TLS completado." -Component 'TLS'
}
