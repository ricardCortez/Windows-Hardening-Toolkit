# Windows Hardening Toolkit

**Herramienta profesional de hardening para Windows 10, Windows 11 y Windows Server.**

Sigue los estándares CIS Benchmarks, Microsoft Security Baselines, NIST 800-53 y MITRE ATT&CK.

---

## Estructura del proyecto

```
Windows-Hardening-Toolkit/
├── main.ps1                    # Punto de entrada principal + menú interactivo
├── config/
│   ├── policies.json           # Configuración de políticas de seguridad
│   └── asr_rules.json          # Configuración de reglas ASR (Attack Surface Reduction)
├── modules/
│   ├── logging.ps1             # Sistema de logging interno del toolkit
│   ├── audit.ps1               # Auditoría del estado de seguridad
│   ├── firewall.ps1            # Hardening de Windows Firewall
│   ├── network.ps1             # Hardening de protocolos de red (SMB, LLMNR, NTLM)
│   ├── defender.ps1            # Hardening de Microsoft Defender + ASR
│   ├── tls.ps1                 # Hardening de TLS/SSL (SCHANNEL + .NET)
│   ├── credentials.ps1         # Hardening de credenciales (LSASS, WDigest, Kerberos)
│   ├── registry.ps1            # Hardening via registro (PS, UAC, AutoRun, misc)
│   ├── logging_audit.ps1       # Políticas de auditoría de Windows y tamaños de logs
│   ├── rollback.ps1            # Backup y restauración de configuraciones
│   └── reporting.ps1           # Generación de reportes (TXT, HTML, JSON)
├── reports/                    # Reportes generados
├── logs/                       # Logs del toolkit (también en C:\ProgramData\WinHardening\)
└── backup/                     # Referencia a backups (almacenados en C:\ProgramData\)
```

---

## Requisitos

| Requisito | Detalle |
|-----------|---------|
| **Sistema operativo** | Windows 10, Windows 11, Windows Server 2016/2019/2022 |
| **PowerShell** | 5.1 o superior (compatible con PS 7+) |
| **Privilegios** | Administrador local o de dominio |
| **Módulos PS** | No requiere módulos externos |

---

## Uso rápido

### Menú interactivo

```powershell
# Ejecutar PowerShell como Administrador, luego:
cd "C:\ruta\Windows-Hardening-Toolkit"
.\main.ps1
```

### Modo línea de comandos

```powershell
# Solo auditoría
.\main.ps1 -Action Audit

# Hardening básico (bajo riesgo)
.\main.ps1 -Action Harden -Profile Basic

# Hardening empresarial completo
.\main.ps1 -Action Harden -Profile Enterprise

# Hardening para Windows Server (excluye RDP y WinRM del bloqueo)
.\main.ps1 -Action Harden -Profile Server

# Generar reporte (ejecuta auditoría automáticamente)
.\main.ps1 -Action Report

# Restaurar configuración desde backup específico
.\main.ps1 -Action Rollback -SessionId "20241015_142300"

# Hardening empresarial sin bloquear RDP, con ASR en modo auditoría
.\main.ps1 -Action Harden -Profile Enterprise -SkipRDP -AuditModeASR
```

### Parámetros disponibles

| Parámetro | Valores | Descripción |
|-----------|---------|-------------|
| `-Action` | `Menu`, `Audit`, `Harden`, `Report`, `Rollback` | Acción a ejecutar |
| `-Profile` | `Basic`, `Enterprise`, `Server` | Perfil de hardening |
| `-SessionId` | string | ID de sesión de backup para rollback |
| `-SkipBackup` | switch | Omite el backup pre-hardening |
| `-SkipRDP` | switch | No bloquea el puerto RDP (3389) |
| `-SkipWinRM` | switch | No bloquea WinRM (5985/5986) |
| `-AuditModeASR` | switch | Activa reglas ASR en modo auditoría |
| `-NoHTML` | switch | Genera reportes solo TXT y JSON |

---

## Controles de seguridad

### Firewall (CIS Section 9 / NIST SC-7)
- Activa perfiles Domain, Private y Public
- Política por defecto: bloquear inbound
- Bloquea puertos críticos: 21, 23, 69, 135, 137-139, 445, 593, 1900, 5985, 5986

### Network Security (CIS 18.3, 18.5 / MITRE T1557)
- Deshabilita SMBv1 (mitiga EternalBlue/WannaCry)
- Fuerza SMB Signing (previene MITM/relay attacks)
- Deshabilita SMB Compression (mitiga CVE-2020-0796)
- Deshabilita NetBIOS (previene NBT-NS poisoning)
- Deshabilita LLMNR (previene responder attacks)
- Configura NTLMv2 obligatorio, nivel 5 (mitiga pass-the-hash)

### Microsoft Defender (CIS 18.9.45 / MITRE T1562)
- Protección en tiempo real, comportamiento y descargas
- Network Protection en modo Block
- Controlled Folder Access (anti-ransomware)
- 15 reglas ASR activadas en modo Block

### TLS/SSL (NIST SP 800-52 Rev.2 / PCI-DSS 4.0)
- Deshabilita: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
- Habilita: TLS 1.2, TLS 1.3
- Configura cipher suites seguros (AES-256-GCM, ECDHE)
- Fuerza TLS 1.2+ en .NET Framework

### Credenciales (CIS 18.3 / MITRE T1003)
- LSASS como Protected Process Light (RunAsPPL)
- Deshabilita WDigest (previene credenciales en texto plano)
- Configura Credential Guard (VBS)
- Bloquea almacenamiento de credenciales de dominio

### PowerShell Security (CIS 18.9.95 / MITRE T1059.001)
- Deshabilita PowerShell v2 (sin downgrade attacks)
- Habilita Script Block Logging
- Habilita Module Logging
- Habilita Transcription Logging

### Auditoría de Windows (CIS 17.x / NIST AU-2)
- 30+ subcategorías de auditoría configuradas
- Tamaño del Security Log: 1 GB
- Command Line Auditing habilitado (Evento 4688)

---

## Sistema de clasificación de controles

| Estado | Descripción |
|--------|-------------|
| **SECURE** | El control cumple el estándar de seguridad |
| **WARNING** | El control está parcialmente configurado o en modo auditoría |
| **VULNERABLE** | El control no cumple el estándar, requiere acción |

---

## Reportes generados

Los reportes se guardan en `reports/` con timestamp:

| Formato | Descripción |
|---------|-------------|
| `security_report.txt` | Reporte texto plano (formato ejecutivo) |
| `security_report_YYYYMMDD_HHmmss.html` | Reporte HTML interactivo con Bootstrap |
| `security_report_YYYYMMDD_HHmmss.json` | Reporte JSON para integración con SIEM |

### Contenido del reporte
- Puntuación de seguridad (0-100%)
- Resumen por categoría
- Listado de controles VULNERABLE con remediación
- Estado consolidado de controles clave

---

## Sistema de backup y rollback

Antes de cualquier hardening, el toolkit exporta automáticamente:

- Claves de registro críticas (`.reg`)
- Configuración completa del firewall (`.wfw`)
- Estado de Microsoft Defender (`.json`)
- Configuración de SMB (`.json`)
- Manifiesto con hashes SHA-256 de los archivos

Los backups se almacenan en: `C:\ProgramData\WinHardening\backup\<SessionId>\`

**Para restaurar:**
```powershell
.\main.ps1 -Action Rollback
# (muestra menú de selección de backups disponibles)

# O directamente:
.\main.ps1 -Action Rollback -SessionId "20241015_142300"
```

---

## Logs

Los logs se almacenan en: `C:\ProgramData\WinHardening\logs\`

Formato: `[yyyy-MM-dd HH:mm:ss] [NIVEL  ] [Componente] Mensaje`

Niveles: `INFO`, `WARNING`, `ERROR`, `SUCCESS`, `DEBUG`

Rotación automática de logs (>30 días).

---

## Perfiles de hardening

### Basic (Básico)
Controles de alto impacto con mínimo riesgo de rotura de servicios.
- RDP y WinRM **no bloqueados**
- ASR en **modo auditoría**
- Sin Credential Guard
- Recomendado para: entornos de prueba, primera implementación

### Enterprise (Empresarial)
Hardening completo siguiendo CIS Level 2.
- Todos los puertos bloqueados (configurable con flags)
- ASR en **modo Block**
- Credential Guard activado
- Recomendado para: entornos corporativos con evaluación previa

### Server (Servidor)
Como Enterprise pero con RDP y WinRM excluidos del bloqueo.
- ASR en **modo auditoría** (menor riesgo en servidores)
- Recomendado para: Windows Server en producción

---

## Exclusiones recomendadas antes de aplicar hardening

Antes de aplicar hardening empresarial, evalúe:

1. **Si usa RDP**: usar flag `-SkipRDP` o restringir por IP con reglas de firewall
2. **Si gestiona via WinRM/Ansible/SCCM**: usar flag `-SkipWinRM`
3. **Si usa software legacy de Office**: usar `-AuditModeASR` primero para evaluar impacto
4. **Si tiene software sin firma**: revisar regla ASR `01443614` antes de activar en Block
5. **Si PSExec o herramientas RMM legítimas**: revisar regla `D1E49AAC` antes de activar

---

## Estándares de referencia

| Estándar | Cobertura |
|----------|-----------|
| **CIS Benchmark Windows 10/11/Server** | Secciones 1, 2, 9, 17, 18 |
| **Microsoft Security Baseline** | Windows 10/11, Windows Server |
| **NIST 800-53 Rev. 5** | AC, AU, CM, IA, SC, SI |
| **NIST SP 800-52 Rev. 2** | TLS/SSL |
| **MITRE ATT&CK** | Mitigaciones T1003, T1021, T1027, T1047, T1059, T1486, T1557, T1562 |

---

## Consideraciones de seguridad del código

- Usa `Get-CimInstance` en lugar del obsoleto `Get-WmiObject`
- Compatible con PowerShell 5.1 y 7+
- Verificación del estado actual antes de aplicar cambios (idempotente)
- Soporte completo para `-WhatIf` en funciones de modificación
- No requiere módulos externos ni conexión a Internet
- No modifica el PATH ni variables de entorno del sistema

---

## Limitaciones conocidas

- **Credential Guard**: requiere hardware con soporte UEFI, Secure Boot y VT-x/AMD-V
- **TLS 1.3**: puede no estar disponible en Windows Server 2016 o versiones anteriores
- **ASR Rules**: requieren Windows 10 1709+ con Microsoft Defender activo (no compatible con AV de terceros)
- **RunAsPPL**: requiere reinicio del sistema para activarse

---

*Windows Hardening Toolkit v1.0.0*
*Estándares: CIS Benchmarks | Microsoft Security Baseline | NIST 800-53 | MITRE ATT&CK*
