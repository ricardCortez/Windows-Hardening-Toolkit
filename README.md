# Windows Hardening Toolkit

**Professional hardening tool for Windows 10, Windows 11, and Windows Server.**

Implements controls aligned with CIS Benchmarks, Microsoft Security Baselines, NIST 800-53, and MITRE ATT&CK.

> **WARNING:** Test all changes in a lab environment before applying to production systems. Some controls (RunAsPPL, Credential Guard, ASR Block mode) require a system restart and may interrupt services. Use `-SkipRDP`, `-SkipWinRM`, and `-AuditModeASR` flags when needed to prevent service disruptions.

---

## System Requirements

| Requirement | Detail |
|-------------|--------|
| **Operating System** | Windows 10 (1709+), Windows 11, Windows Server 2016 / 2019 / 2022 |
| **PowerShell** | 5.1 or later (fully compatible with PS 7+) |
| **Privileges** | Local Administrator or Domain Administrator |
| **External Modules** | None — no dependencies beyond what ships with Windows |
| **Disk Space** | ~10 MB for toolkit + backup storage in `C:\ProgramData\WinHardening\` |

---

## Quick Start

### Step 1 — Open PowerShell as Administrator

Right-click the PowerShell icon and select **Run as administrator**, or from an elevated terminal:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process -Force
cd "C:\path\to\Windows-Hardening-Toolkit"
```

### Step 2 — Run the interactive menu

```powershell
.\main.ps1
```

### Step 3 — Or use direct command-line mode

```powershell
# Security audit only (read-only, no changes)
.\main.ps1 -Action Audit

# Basic hardening (high-impact, low-disruption controls)
.\main.ps1 -Action Harden -Profile Basic

# Full enterprise hardening
.\main.ps1 -Action Harden -Profile Enterprise

# Enterprise hardening — preserve RDP and WinRM access
.\main.ps1 -Action Harden -Profile Enterprise -SkipRDP -SkipWinRM

# Enterprise hardening — ASR rules in audit mode (no blocking)
.\main.ps1 -Action Harden -Profile Enterprise -AuditModeASR

# Server profile (RDP + WinRM excluded, ASR in audit mode)
.\main.ps1 -Action Harden -Profile Server

# Generate security report (runs audit first)
.\main.ps1 -Action Report

# Restore configuration from a previous backup
.\main.ps1 -Action Rollback -SessionId "20241015_142300"

# Rollback with interactive backup selection
.\main.ps1 -Action Rollback

# Verify hardening results (separate verification script)
.\Test-HardeningResults.ps1
```

### Available Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `-Action` | `Menu`, `Audit`, `Harden`, `Report`, `Rollback` | Action to execute |
| `-HardeningProfile` | `Basic`, `Enterprise`, `Server` | Hardening profile |
| `-SessionId` | string | Backup session ID for rollback |
| `-SkipBackup` | switch | Skip pre-hardening backup |
| `-SkipRDP` | switch | Do not block RDP port (3389) |
| `-SkipWinRM` | switch | Do not block WinRM ports (5985/5986) |
| `-AuditModeASR` | switch | Enable ASR rules in audit mode instead of block |
| `-NoHTML` | switch | Generate TXT and JSON reports only (skip HTML) |

---

## Security Controls — All 15

| # | Control | Description | Standard Reference |
|---|---------|-------------|-------------------|
| 1 | **Firewall — All Profiles** | Enables Domain, Private, and Public profiles with Block inbound default policy | CIS 9.1–9.3 / NIST SC-7 |
| 2 | **SMBv1 Disabled** | Disables SMBv1 server and client; mitigates EternalBlue (MS17-010), WannaCry, NotPetya | CIS 18.3.3 / MITRE T1021.002 |
| 3 | **NetBIOS Disabled** | Disables NetBIOS over TCP/IP on all active adapters; prevents NBT-NS poisoning | CIS 18.5.4 / MITRE T1171 |
| 4 | **LLMNR Disabled** | Disables Link-Local Multicast Name Resolution; prevents Responder attacks | CIS 18.5.4.2 / MITRE T1557 |
| 5 | **LSASS RunAsPPL** | Enables LSASS as Protected Process Light; blocks credential dumping from memory | CIS 18.3.1 / MITRE T1003.001 |
| 6 | **WDigest Disabled** | Disables WDigest authentication; prevents plaintext credentials in memory (mimikatz) | CIS 18.3.7 / MITRE T1003.001 |
| 7 | **SmartScreen Active** | Verifies Windows SmartScreen is enabled (On or Warn mode) | CIS 18.9.80 / MITRE T1204 |
| 8 | **UAC Enabled** | Enforces User Account Control with secure desktop prompt for elevation | CIS 2.3.17 / NIST AC-6 |
| 9 | **DEP Enabled** | Verifies Data Execution Prevention policy is active (SupportPolicy >= 2) | MS Security Baseline / NIST SI-16 |
| 10 | **Script Block Logging** | Enables PowerShell Script Block Logging; records all PS code executed | CIS 18.9.95.1 / MITRE T1059.001 |
| 11 | **PowerShell v2 Disabled** | Disables the legacy PS v2 engine; prevents downgrade attacks | CIS / MITRE T1059.001 |
| 12 | **TLS Configuration** | Disables TLS 1.0 and 1.1; enforces TLS 1.2 (and 1.3 where available) | NIST SP 800-52 Rev.2 / PCI-DSS 4.0 |
| 13 | **Defender Active + Fresh Signatures** | Verifies Antivirus is enabled and signatures are no more than 7 days old | CIS 18.9.45 / MITRE T1562.001 |
| 14 | **ASR Rules Configured** | Verifies Attack Surface Reduction rules have at least one action defined | CIS 18.9.45.3 / MITRE ATT&CK |
| 15 | **Password Policies** | Enforces minimum length >= 12 and maximum age <= 90 days | CIS 1.1.x / NIST IA-5 |

---

## Module Descriptions

### `main.ps1`
Entry point. Handles parameter parsing, module loading, backup initialization, and routing to the selected action (Menu / Audit / Harden / Report / Rollback). Requires PowerShell 5.1+ and administrator privileges (`#Requires -RunAsAdministrator`).

### `modules/logging.ps1`
Internal logging system. Writes timestamped entries to console (with color) and to a rotating log file in `C:\ProgramData\WinHardening\logs\`. Log levels: INFO, WARNING, ERROR, SUCCESS, DEBUG, SECTION.

### `modules/audit.ps1`
Read-only security audit. Checks current system state against CIS/NIST baselines across 10 categories: Firewall, SMB, NetBIOS/LLMNR, NTLM, TLS, Defender, ASR, Credentials, PowerShell, and Password Policy. Returns a score (0–100%).

### `modules/firewall.ps1`
Windows Firewall hardening. Enables all three profiles with Block inbound default, creates blocking rules for critical ports (21, 23, 69, 135, 137–139, 445, 593, 1900, 3389, 5985, 5986), and blocks outbound insecure protocols (FTP, Telnet, TFTP).

### `modules/network.ps1`
Network protocol hardening. Disables SMBv1 (via cmdlet + registry key), forces SMB Signing, disables SMB Compression (CVE-2020-0796), disables NetBIOS over TCP/IP (via WMI `SetTcpipNetbios`), disables LLMNR and mDNS, and enforces NTLMv2 (LmCompatibilityLevel = 5).

### `modules/defender.ps1`
Microsoft Defender hardening. Enables real-time protection, behavior monitoring, IOAV, Network Protection (Block mode), Controlled Folder Access, PUA protection, cloud-delivered protection, and applies all 15 recommended ASR rules. Checks `AntivirusEnabled` before applying ASR.

### `modules/tls.ps1`
TLS/SCHANNEL hardening. Disables SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1. Enables TLS 1.2 and TLS 1.3. Configures secure cipher suites (AES-256-GCM, ECDHE), disables weak key exchange algorithms (PKCS), and configures .NET Framework 2.0 and 4.0 to use TLS 1.2+ by default.

### `modules/credentials.ps1`
Credential subsystem hardening. Enables LSASS RunAsPPL (without touching LsaCfgFlags), disables WDigest, blocks domain credential storage, configures Kerberos for AES-256, disables the Guest account, and optionally enables Credential Guard (VBS). Changes to RunAsPPL require a reboot.

### `modules/registry.ps1`
Registry-based hardening. Applies PowerShell security settings (Script Block Logging, Module Logging, Transcription, disables PS v2), UAC hardening (EnableLUA, ConsentPromptBehavior, Secure Desktop), AutoRun/AutoPlay disabling, WinRM security settings, miscellaneous protections (telemetry, Cortana, Spectre/Meltdown mitigations, LAN Manager hash), and password policy enforcement via `net accounts`.

### `modules/logging_audit.ps1`
Windows event log and audit policy hardening. Sets Security log size to 1 GB, configures 30+ audit subcategories via `auditpol.exe` (Logon, Account Management, Process Creation, Policy Change, etc.), enables command-line auditing (Event 4688), and reports Sysmon status.

### `modules/rollback.ps1`
Backup and restore system. Before hardening, exports registry keys (`.reg`), firewall configuration (`.wfw`), Defender state, and SMB configuration to `C:\ProgramData\WinHardening\backup\<SessionId>\` with a SHA-256 manifest. Provides interactive or scripted restore.

### `modules/reporting.ps1`
Report generation. Produces TXT (executive format), HTML (Bootstrap dark theme with filterable table), and JSON (for SIEM integration) reports in the `reports/` directory. Reports include security score, per-category breakdown, and remediation steps for all FAIL/WARN findings.

### `Test-HardeningResults.ps1`
Standalone verification script. Runs 15 independent checks against the system, prints PASS/FAIL/WARN results to console, and writes a timestamped report to `$env:TEMP\HardeningReport_<timestamp>.txt`. Does not modify any system settings.

---

## Hardening Profiles

### Basic
Applies high-impact, low-disruption controls only.
- RDP (3389) and WinRM (5985/5986) are **not** blocked
- ASR rules applied in **audit mode** (log only, no blocking)
- Credential Guard **not** configured
- Recommended for: first deployment, evaluation environments

### Enterprise
Full hardening following CIS Level 2 recommendations.
- All critical ports blocked (override with `-SkipRDP`, `-SkipWinRM`)
- ASR rules in **block mode** (override with `-AuditModeASR`)
- Credential Guard configured (requires hardware support)
- Recommended for: corporate workstations after evaluation

### Server
Same as Enterprise but with RDP and WinRM preserved, and ASR in audit mode.
- Recommended for: Windows Server 2016/2019/2022 in production

---

## Backup and Rollback

Before any hardening operation, the toolkit automatically exports:

- Registry keys (LSA, NTLM, WDigest, SCHANNEL, SMB, PowerShell, UAC, DNS, DeviceGuard, .NET, RDP) as `.reg` files
- Full firewall configuration as `.wfw` (restorable via `netsh advfirewall import`)
- Microsoft Defender state as `defender_config.json`
- SMB server configuration as `smb_config.json`
- SHA-256 manifest file (`MANIFEST.json`)

Backups are stored at: `C:\ProgramData\WinHardening\backup\<SessionId>\`

**To restore:**
```powershell
# Interactive selection from available backups
.\main.ps1 -Action Rollback

# Direct restore by session ID
.\main.ps1 -Action Rollback -SessionId "20241015_142300"
```

> Note: Changes to RunAsPPL and Credential Guard require a **system restart** to take effect or to revert.

---

## Pre-deployment Checklist

Before applying enterprise hardening, evaluate the following:

1. **Uses RDP for remote management?** — Add `-SkipRDP` or restrict by IP via firewall rules
2. **Managed via WinRM / Ansible / SCCM?** — Add `-SkipWinRM`
3. **Uses legacy Office macros?** — Run with `-AuditModeASR` first, review Event 1121/1122 in Event Viewer
4. **Has unsigned in-house software?** — Review ASR rule `01443614` (executable prevalence) before enabling in Block mode
5. **Uses PSExec or legitimate RMM tools?** — Review ASR rule `D1E49AAC` before enabling in Block mode
6. **Domain environment?** — Test NTLM level 5 against all authenticating services before enabling
7. **TLS changes affect IIS/web services?** — Restart IIS (`iisreset`) after applying TLS hardening

---

## Project Structure

```
Windows-Hardening-Toolkit/
├── main.ps1                     # Entry point + interactive menu
├── Test-HardeningResults.ps1    # Standalone verification (15 tests)
├── config/
│   ├── policies.json            # Security policy configuration
│   └── asr_rules.json           # ASR rules configuration (15 rules)
├── modules/
│   ├── logging.ps1              # Internal toolkit logging
│   ├── audit.ps1                # Read-only security audit
│   ├── firewall.ps1             # Windows Firewall hardening
│   ├── network.ps1              # Network protocol hardening (SMB, LLMNR, NTLM)
│   ├── defender.ps1             # Microsoft Defender + ASR hardening
│   ├── tls.ps1                  # TLS/SSL / SCHANNEL / .NET hardening
│   ├── credentials.ps1          # LSASS, WDigest, Credential Guard hardening
│   ├── registry.ps1             # Registry hardening (PS, UAC, AutoRun, misc)
│   ├── logging_audit.ps1        # Windows audit policy + event log sizing
│   ├── rollback.ps1             # Backup and restore
│   └── reporting.ps1            # Report generation (TXT, HTML, JSON)
├── reports/                     # Generated security reports
└── logs/                        # Symlink reference (actual logs: C:\ProgramData\WinHardening\logs\)
```

---

## Standards Coverage

| Standard | Sections Covered |
|----------|-----------------|
| **CIS Benchmark — Windows 10/11/Server 2022** | 1.1 (Password), 2.3 (Security Options), 9 (Firewall), 17 (Audit Policy), 18.3/18.5/18.9 (System Settings) |
| **Microsoft Security Baseline** | Windows 10, Windows 11, Windows Server 2019/2022 |
| **NIST 800-53 Rev. 5** | AC (Access Control), AU (Audit), CM (Config Mgmt), IA (Identification), SC (System/Comm Protection), SI (System Integrity) |
| **NIST SP 800-52 Rev. 2** | TLS/SSL Guidelines for Federal Systems |
| **MITRE ATT&CK** | T1003, T1021, T1027, T1047, T1059, T1171, T1486, T1547, T1557, T1558, T1562, T1566 |
| **PCI-DSS 4.0** | Requirements 2, 6, 8 (TLS, patching, passwords) |

---

## Logs

Log files are stored at: `C:\ProgramData\WinHardening\logs\`

Format: `[yyyy-MM-dd HH:mm:ss] [LEVEL  ] [Component] Message`

Levels: `INFO`, `WARNING`, `ERROR`, `SUCCESS`, `DEBUG`

Automatic rotation removes logs older than 30 days.

---

## License

This project is provided as-is for educational and operational use. Test thoroughly in a lab environment before deploying to production systems. The authors accept no liability for service disruptions caused by applying these hardening controls without prior evaluation.

---

*Windows Hardening Toolkit v1.0.0*
*Standards: CIS Benchmarks | Microsoft Security Baseline | NIST 800-53 | MITRE ATT&CK*
