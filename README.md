#### README.md
# Apparition Delivery System
```
. : .  .  .. ... ...... ..................... ...... ... .. .  . : .
: .   .       .       .        .        .        .        .   . . :
.       _    ___   ___   _     ___    ___ _____  _   ___  _  _       .
       /_\   | _ \| _ \ /_\   | __ \ |_ _|_   _|| | / _ \| \| |
      / _ \  |  _/|  _// _ \  | |/ /  | |  | |  | || (_) | .` |
     /_/ \_\ |_|  |_| /_/ \_\ |_|\_| |___| |_|  |_| \___/|_|\_|
: .    . .   . . ..  . .. . . .. . .. .. . .. ... . .. .    . . :
.   .  .     . :     .    :  . : :   . : :    . :      .    .   .
   .   :      '  Apparition Delivery System (ADS) '      :    .
 .  .  .   . . ' " Execution without presence " ' .    .   .  .
    . .      . .. .. . ... .................. .. . .. .      . .
```

**ADS hides, persists, and executes arbitrary PowerShell payloads inside NTFS Alternate Data Streams — invisible to `dir`, immune to `Get-ChildItem`, and clean against Windows Defender.**

Current version: **v2.5** | [Quick-Start Guide](QUICK-START.md) | [Red Team Showcase](tests/RED-TEAM-SHOWCASE.md)

---

## What Do I Type?

Three canonical examples. Copy, modify the payload, run on Kali.

```bash
# 1. Fastest possible — firewall down, Advanced tier (auto-encrypted, Zone.Identifier stream)
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'cmd /c "netsh advfirewall set allprofiles state off"' \
  -OutputFile /tmp/fw-off.txt

# 2. Standard CCDC op — Advanced tier, registry persist, 3 redundant instances
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'cmd /c "netsh advfirewall set allprofiles state off"' \
  -Obfuscate Advanced \
  -Persist registry \
  -InstanceCount 3 \
  -OutputFile /tmp/fw-registry.txt

# 3. Max stealth — Paranoid tier ($Data+ZW stream, auto-encrypted, all triggers)
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/mypayload.ps1 \
  -Obfuscate Paranoid \
  -Trigger all \
  -OutputFile /tmp/paranoid.txt
```

Then on Windows: paste **OPTION 1** (the base64 one-liner) from the output file into PowerShell as Administrator.

---

## Quick-Reference: All Options

### ADS-OneLiner.ps1 (run on Kali — generates the one-liner)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| **Payload Input** | | | |
| `-Payload 'cmd'` | string | — | Inline PowerShell. Use single quotes in bash. |
| `-PayloadFile /path` | string | — | Read payload from file. Best for `$variables`. |
| `-PayloadAtDeployment` | switch | off | Prompt for payload on Windows target at paste time. |
| **Stealth Tier** | | | |
| `-Obfuscate None\|Basic\|Advanced\|Paranoid` | string | `Advanced` | See tier table below. Controls encryption, placement, stream naming. |
| **Persistence** | | | |
| `-Persist task\|registry\|none` | string | `task` | How the payload re-triggers. |
| `-Trigger AtLogOn,AtStartup,OnIdle,OnUnlock,all` | string[] | `AtLogOn,AtStartup` | When the task fires. Use `all` for all four triggers, or comma-separate: `'AtLogOn,OnIdle'`. |
| `-PeriodicMinutes N` | int 1–1440 | `5` | Periodic task interval in minutes. |
| `-JitterPercent N` | int 0–50 | `20` | Randomize timing by ±N% of interval. |
| `-InstanceCount N` | int 1–20 | `1` | Deploy N independent copies with unique names/paths. |
| **Evasion** | | | |
| `-Encrypt` | switch | tier-implied | DPAPI machine-bound encrypt payload. **Auto-on for Advanced/Paranoid.** |
| `-Encrypt:$false` | | — | Explicitly disable encryption even on Advanced/Paranoid. |
| `-UseCompression $true\|$false` | bool | `$true` | DeflateStream compression (~50% smaller). |
| `-Randomize $true\|$false` | bool | tier-implied | Randomize all artifact names. |
| `-UseDeepPlacement $true\|$false` | bool | tier-implied | Bury ADS in WER/Cache dirs. |
| `-AttachToExisting $true\|$false` | bool | tier-implied | Attach to existing system file. |
| `-NoAmsi` | switch | off | Disable AMSI bypass (almost never use). |
| **Stream & Artifact Naming** | | | |
| `-StreamName name` | string | tier-implied | ADS stream name. Used as-is (no ZW) or as visible prefix (ZW on). Tier defaults: Advanced=`Zone.Identifier`, Paranoid=`$Data`. |
| `-ZeroWidthStreams` | switch | tier-implied | ZW Unicode chars in stream names. Implied by Paranoid. |
| `-ZeroWidthMode single\|multi` | string | `single` | ZW character pattern. When `-StreamName` set, ZW chars append as suffix. |
| `-FileName name` | string | — | Custom host file name (e.g., `WindowsUpdate.dat`). Directory still auto-selected. |
| `-TaskName name` | string | — | Custom task name. Multi-instance: `_00`/`_01`/`_02` suffix appended. |
| `-CreateDecoys N` | int 0–10 | `0` | Create N benign decoy ADS streams. |
| `-ShowArtifacts` | switch | off | Show ADS path and decoy locations on deployment. Always shown for None tier. |
| **Output** | | | |
| `-OutputFile path` | string | `ads-payload.txt` | Where to save the generated deployment file. |
| `-ManifestDir path` | string | `./manifests` | Where to save the cleanup manifest. |

### ADS-Dropper.ps1 (run on Windows — direct deployment or -GenerateOnly)

All OneLiner parameters above, plus:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Targets host[]` | string[] | `localhost` | Remote target hosts (WinRM). |
| `-Credential cred` | PSCredential | — | Credentials for remote deployment. |
| `-NoExec` | switch | off | Stage artifacts without executing. |
| `-ManifestPath path` | string | — | Path to save cleanup manifest. |
| `-GenerateOnly` | switch | off | Print config object without creating artifacts (Linux). |
| `-PayloadAtRuntime` | switch | off | Prompt for payload on Windows at runtime. |
| `-Help` | switch | — | Show full inline help. |

---

## Stealth Tier Guide

The `-Obfuscate` parameter is the primary control. Most evasion parameters are implied by the tier.

| Tier | Task/File Names | ADS Placement | Stream Name | ZW Streams | Encrypt | When to Use |
|------|-----------------|---------------|-------------|------------|---------|-------------|
| `None` | Fixed: `SystemOptimization` | `C:\ProgramData\` | `payload` | No | No | **Testing only. Never in competition.** |
| `Basic` | Word-list random | `C:\ProgramData\` | Random 8 chars | No | No | Quick deployment, acceptable stealth. |
| `Advanced` | Word-list random | WER\Cache, Diagnosis | **`Zone.Identifier`** | No | **Yes** | **Default. Standard CCDC.** |
| `Paranoid` | Word-list random | WER\Cache + attach | **`$Data`+ZW** | **Yes** | **Yes** | Max stealth. Harder to clean up. |

**v2.5 tier-implied defaults:**
- `Advanced` or `Paranoid` → `Randomize=$true`, `UseDeepPlacement=$true`, `AttachToExisting=$true`, **`Encrypt=$true`**
- `Advanced` → stream name defaults to `Zone.Identifier` (blends into legitimate Windows ADS traffic)
- `Paranoid` → additionally `ZeroWidthStreams=$true`, stream name defaults to `$Data` with ZW suffix

**Override examples:**
```bash
# Advanced tier but disable encryption:
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -Obfuscate Advanced -Encrypt:$false

# Paranoid tier with custom stream name (ZW still appended):
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -Obfuscate Paranoid -StreamName 'Zone.Identifier'

# Custom task and file names:
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -TaskName 'WinDefSvc' -FileName 'AppData.dat'
```

---

## Architecture

```
[Kali]  ADS-OneLiner.ps1  →  deployment one-liner (base64)
          |
          | paste on Windows
          v
[Target] powershell instance  →  [ADS payload]  ←  NTFS stream (invisible to dir/ls)
                              →  [JScript wrapper]  (wscript.exe → no PS window)
                              →  [Task Scheduler] or [Registry Run key]
```

**Two-script architecture:**
- `src/ADS-OneLiner.ps1` — Runs on Linux/Kali. Generates minimal deployment commands. No file uploads needed.
- `src/ADS-Dropper.ps1` — Primary engine of the system (it might be able to run as a stand-alone if it were to be dropped on Windows). All business logic: ADS creation, encryption, persistence, cleanup.

---

## Persistence Methods

### Task Persistence (`-Persist task`)
- Requires admin
- Creates a JScript wrapper (`wscript.exe //B file.js`) — no visible PowerShell window
- Fires on: configured `-Trigger` events + periodic every `-PeriodicMinutes` minutes
- Task name randomized from plausible word lists (Advanced/Paranoid tier), or use `-TaskName`

### Registry Persistence (`-Persist registry`)
- Works as user or admin
- Sets `HKCU:\...\Run` (and `HKLM:\...\Run` if admin)
- Fires in the user's logon session — interactive payloads (memes, UI effects) work here
- Companion scheduled task handles periodic re-trigger

---

## Payload Library

The payload library (will be release after competitions) contains 89 curated payloads across 14 categories:

| Category | IDs | Description |
|----------|-----|-------------|
| Firewall | FW-001 to FW-008 | Disable profiles, open ports, allow-all rules, nuclear silent kill |
| RDP | RDP-001 to RDP-004 | Enable RDP, disable NLA, change port |
| User Creation | USR-001 to USR-006 | Local admin, hidden admin, password never expires |
| Service Control | SVC-001 to SVC-006 | Disable Defender, Sysmon, Event Log, EDR |
| C2 / Beaconing | C2-001 to C2-007 | Download cradles, reverse shell, BITS, DNS |
| Credentials | CRED-001 to CRED-008 | SAM/SYSTEM dump, Credential Manager, cred file hunt |
| Defense Evasion | DEF-001 to DEF-009 | Clear logs, disable logging, wipe Defender history |
| Reconnaissance | RECON-001 to RECON-006 | System enum, domain enum, privesc surface |
| Lateral Prep | LAT-001 to LAT-005 | WinRM, PSRemoting, WMI, SMB shares, relay prep |
| Exfil | EXFIL-001 to EXFIL-003 | Stage files, HTTP exfil, ICMP |
| Impact / Fun | FUN-001 to FUN-008 | Desktop effects (interactive session required) |
| Memes | MEME-001 to MEME-009 | Fake BSOD, clipboard hijack, LED disco, Matrix rain, OIIA |
| Combos | COMBO-001 to COMBO-003 | Multi-action packages (FW+RDP+admin+logging) |
| Novel / Experimental | NOVEL-001 to NOVEL-007 | COM hijack, WMI subscription, IFEO, AppInit DLLs |

```bash
# Use a library payload:
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile ops/payloads/ccdc-library.ps1 \
  -Payload 'FW-002' \
  -OutputFile /tmp/fw.txt
```

---

## Session Context: Interactive vs. SYSTEM

Tasks run as `NT AUTHORITY\SYSTEM` (Session 0). Payloads that open windows, play audio, or access the clipboard need a **user session**.

| Context | Use `-Persist task` | Use `-Persist registry` |
|---------|--------------------|-----------------------|
| SYSTEM (Session 0) | Firewall, registry, files, services, credential dump | — |
| User session | `-Trigger AtLogOn` or `OnUnlock` | Always user session |
| Interactive UI (memes, desktop effects) | Use `-Trigger AtLogOn` only | Preferred |

**Rule:** For anything that needs to be visible to a human (memes, popups, audio), use `-Persist registry`.

---

## Detection Surface

| Technique | Detection Vector |
|-----------|-----------------|
| ADS creation | Sysmon Event 15 (FileCreateStreamHash). `dir /r` in cmd shows stream sizes. |
| Scheduled task | Event ID 4698 (Task Created). `Get-ScheduledTask` shows obfuscated name. |
| Registry Run key | Event ID 4657 (Registry Modification). Standard auditing. |
| JScript execution | `wscript.exe` in process tree. No PowerShell window. |
| AMSI bypass | XOR byte array in deployment script — fragmented so no contiguous string. |
| Payload at runtime | Compressed + base64. No plaintext payload on disk. Encrypted with DPAPI if `-Encrypt` active. |
| Stream name | `Zone.Identifier` (Advanced) blends with legit Windows ADS. `$Data`+ZW (Paranoid) invisible in most tools. |

**MITRE ATT&CK:** T1564.004 (ADS) | T1053.005 (Scheduled Task) | T1547.001 (Registry Run Keys)

---

## References & Credits

- Oddvar Moe — ADS execution techniques: https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/
- Enigma0x3 — ADS persistence: https://enigma0x3.net/2015/03/05/using-alternate-data-streams-to-persist-on-a-compromised-machine/
- MITRE ATT&CK T1564.004: https://attack.mitre.org/techniques/T1564/004/
- NTFS streams: https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams

---

## See Also

- [QUICK-START.md](QUICK-START.md) — Full parameter reference, scenario cookbook, bash escaping guide
- [tests/COMPREHENSIVE-TEST-SUITE.md](tests/COMPREHENSIVE-TEST-SUITE.md) — Full VM validation test suite
- [defense/](defense/) — Blue team detection scripts

---

## License & Disclaimer

For authorized security testing, CCDC competition, and security research only.

Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical. The author assumes no liability for misuse.

By using this tool you agree to: obtain explicit permission before testing, follow responsible disclosure practices, and provide detection guidance to defenders when appropriate.

---

*"Execution without presence"*
© 2026 Qweary — Security Research With Purpose
Contact: qwearyblog@gmail.com | https://qweary.github.io | https://github.com/Qweary
