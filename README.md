# NTFS ADS Execution Research Framework

## Purpose
This tool demonstrates the intersection of NTFS Alternate Data Streams (ADS) 
and Windows execution primitives for adversary emulation and detection research.

**Primary Use Cases:**
1. Red Team: CCDC-style persistence testing (authorized environments only)
2. Blue Team: Understanding ADS detection gaps and telemetry
3. Research: Novel NTFS hiding techniques and their forensic visibility

## Ethical Guidelines
✅ Authorized penetration testing with explicit permission
✅ CCDC competition (adversary emulation)
✅ Security research and detection development
❌ Unauthorized access to systems
❌ Malicious use

## Architecture
```
[Payload] → [Storage] → [Loader] → [Trigger]
```

**Storage Backends:**
| Type           | Visibility | Stability        | Use Case                     |
|----------------|------------|------------------|------------------------------|
| Classic ADS    | Medium     | High             | Production red team          |
| Volume Root    | Low        | High             | Enumeration evasion research |
| NTFS Internal* | Very Low   | **Experimental** | Research only                |

*NTFS Internal streams (e.g., $LOGGED_UTILITY_STREAM) are **unstable** 
and may cause filesystem corruption. Use only in disposable VMs.

## Detection & Defense
This tool intentionally creates artifacts to help blue teams understand detection:

**What Defender Will See:**
- Scheduled task creation (Event ID 4698)
- Wscript.exe spawning PowerShell (Sysmon Event ID 1)
- ADS access (if stream hash monitoring enabled)

**How to Detect:**
```powershell
# Find all ADS in ProgramData
Get-ChildItem C:\ProgramData -Recurse | Get-Item -Stream * | Where-Object Stream -ne ':$DATA'

# Check for suspicious tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -like "*Windows*" -and $_.Author -eq ""}
```

## MITRE ATT&CK Mapping
- T1564.004: Hide Artifacts - NTFS File Attributes
- T1053.005: Scheduled Task/Job
- T1059.001: PowerShell
