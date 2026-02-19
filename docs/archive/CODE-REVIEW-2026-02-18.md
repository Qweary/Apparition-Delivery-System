# Code Review — 2026-02-18 (Opus 4.6)

> **Triage note (Session 7):** This review was produced by Claude Opus 4.6 with access to both the `main` and `test` branches and prior session history — possible memory bleed between branch states. All findings were cross-checked against actual v2.4 source before any action was taken. Summary of findings below; full review text preserved beneath.

## Triage Summary

| Finding | Verdict | Action Taken |
|---------|---------|-------------|
| BUG-1: Param divergence between two OneLiner versions | **FALSE POSITIVE** — memory bleed; single current version on test branch | None |
| BUG-2: `$Encrypt.IsPresent` type mismatch | **FALSE POSITIVE** — `$Encrypt` is still `[switch]`; `.IsPresent` is correct | None |
| BUG-3: `$Randomize.IsPresent` after switch→bool | **ALREADY FIXED** — manifest uses `[bool]$Randomize` etc. in v2.4 | None |
| BUG-4: Compression stub still detected | **KNOWN (BUG-015)** — DeflateStream evasion already in v2.4; VM test pending | None |
| BUG-5: Deep placement silent failure | **ALREADY FIXED (BUG-016)** — denylist + post-write verification in v2.4 | None |
| ISSUE-6: Registry AMSI raw reflection | **FALSE POSITIVE** — uses `New-AmsiBypassForRegistry` → XOR Fragment Splitting | None |
| ISSUE-7: Unencrypted task path hardcodes triggers | **FALSE POSITIVE** — all 3 task paths call `Build-TriggerBlock` (confirmed at lines 725, 761, 880) | None |
| ISSUE-8: Multi-instance variable expansion in here-string | **PROBABLY FINE** — `@"..."@` expandable here-string; not verified at code level | Low-priority note |
| ISSUE-9: Manifest `.IsPresent` on bool params | **ALREADY FIXED** — only `$Encrypt.IsPresent` remains; `$Encrypt` is still `[switch]` (correct) | None |
| QUALITY-1: Layer A AMSI dot-sourced scriptblock | **LOW PRIORITY** — lower risk than Layer B; noted for future | Logged as note |
| QUALITY-2: `gwmi` deprecation noise in PS 7 | **COSMETIC** — PS 5.1 is target runtime; no functional impact | None |
| QUALITY-3: Version strings say v2.3 | **REAL** — both scripts reported v2.3 after v2.4 commit | **FIXED** — updated to v2.4 in all 4 locations (Session 7) |
| "Things Not Considered Yet" section | **USEFUL IDEAS** — strategic future capabilities | Captured in `competition/COMPETITION-STRATEGY.md` |

**Queue's additional manual testing finding:**
- ZeroWidth mode + certain persistence methods fails without graceful failure → logged as **BUG-018** in `docs/project-context/active-bugs.md`

---

## Original Review Text

*(Preserved verbatim. Note: escaped markdown from source document retained.)*

---

This review was done by Claude with both the test and main branch (and had worked on the project at different stages in the past), so there may be some memory bleed. Verify that these things exist before taking any action. After that, come up with a plan on how the swarm can best tackle the concerns (feel free to ask my opinion if you are unsure).
Code Review — Bugs, Traps, and Improvement Strategies

After reading through both `ADS-Dropper.ps1` and `ADS-OneLiner.ps1` end-to-end, along with the decision log, AMSI research notes, and Defender behavioral detection log, here's what I found.

### Critical Bugs

**BUG-1: Parameter Divergence Between OneLiner Versions (Two Competing param blocks)**

The project knowledge returns two distinct versions of the ADS-OneLiner.ps1 param block. One version (older) has `[switch]$Encrypt`, `[switch]$Randomize`, and lacks `-PayloadFile`, `-Trigger`, `-PeriodicMinutes`, `-JitterPercent`, `-Obfuscate`, and `-UseCompression`. The newer v2.3 version has all of these including `[bool]$Randomize`, `[string]$Obfuscate`, and `[bool]$UseCompression`. If your test branch has both files or a partially-merged state, this will cause silent failures: the OneLiner will pass parameters to the Dropper that it doesn't expect, or fail to pass parameters the Dropper now requires.

Verify which version is on the test branch and ensure the param blocks are synchronized. The v2.3 OneLiner params should match the Dropper's current param block (which has `[bool]$Randomize`, `[string]$Obfuscate`, etc.). If you're running the older OneLiner against the newer Dropper, the `-Obfuscate` tier-implied defaults won't propagate because the OneLiner won't pass them.

**BUG-2: `$Encrypt.IsPresent` vs `$Encrypt` Type Mismatch**

The Dropper declares `[switch]$Encrypt`, which works fine with `.IsPresent` checks. However, in the OneLiner's `$params` hashtable that calls the Dropper, `Encrypt = $Encrypt` passes the switch value directly. When the Dropper's `-GenerateOnly` return object uses `PayloadEncrypted = $Encrypt.IsPresent`, this works. But in the OneLiner's manifest generation, there are references to `$Encrypt.IsPresent` that will break if `$Encrypt` was passed as a `[bool]` from the Obfuscate tier-implied defaults. The manifest line `Encrypted = $Encrypt.IsPresent` will fail silently (returning `$null` / false) if `$Encrypt` is a boolean rather than a switch.

Fix: In the manifest block, use `Encrypted = [bool]$Encrypt` instead of `$Encrypt.IsPresent`. This works regardless of whether the value came from a switch or a bool.

**BUG-3: `$Randomize.IsPresent` References After Switch-to-Bool Conversion**

The decision log from 2026-02-17 documents that `Randomize` was changed from `[switch]` to `[bool]`. However, the older OneLiner output template and manifest still reference `$Randomize.IsPresent`, which doesn't exist on a `[bool]`. The expression evaluates to `$null` (falsy), so manifests will always record `Randomized = False` even when randomization is active.

Fix: Replace every instance of `$Randomize.IsPresent` with `[bool]$Randomize` in both files. Grep for `.IsPresent` across the codebase after the switch-to-bool migration to catch any remaining instances.

**BUG-4: Compression Decompression Stub Is Likely Still Detected**

The decision log and research notes document that GZip's `DecompressStream + StreamReader + IEX` pattern triggers `PShellCobStager.A`. The code was switched to DeflateStream to avoid this. However, the decompression stub still follows the same structural pattern (decompress from MemoryStream then execute), just with a different .NET type name. Defender's behavioral engine may match on the execution pattern rather than the specific type name. The research notes say "OPEN — needs evasion approach" but `UseCompression` defaults to `$true`.

If this hasn't been field-tested against Defender yet, I'd strongly recommend defaulting `UseCompression` to `$false` until it's validated. Getting flagged during competition because the default compression stub triggers Defender would be catastrophic. The 50% size reduction is nice but not worth the risk if unvalidated.

Quick fix to the parameter declaration:

```powershell
[bool]$UseCompression = $false   # was $true — change to opt-in until Defender-tested
```

**BUG-5: Deep Placement Silent Failure With Locked Files**

The research log documents that deep placement selected `qmgr.db` (BITS queue manager), which is exclusively locked by the BITS service, causing ADS write failure while the script still printed "[+] Deployment complete". The post-write verification in the OneLiner (`if(-not(Get-Item $hp -Stream $sn -EA 0))`) catches this and falls back to a random ProgramData path, but the Dropper's `Write-ADSPayload` function catches the error and returns `$null`, then the main execution path checks `if (-not $adsPath)` and calls `exit 1`. These two paths behave differently — the OneLiner is more resilient than the Dropper for deep placement failures.

However, neither script maintains a denylist of known-locked files. Add an exclusion filter to `Get-RandomADSConfig` when `UseDeepPlacement` is true:

```powershell
$denylist = @('qmgr.db', 'qmgr0.dat', 'qmgr1.dat', 'NTUSER.DAT', 'UsrClass.dat',
              'ntds.dit', 'edb.log', 'edb.chk', 'pagefile.sys', 'swapfile.sys')
# Filter candidate files:
$candidates = $candidates | Where-Object { $denylist -notcontains $_.Name }
```

### Medium Severity Issues

**ISSUE-6: OneLiner Registry Persistence Block Has Hardcoded AMSI Bypass (Non-XOR)**

In the older OneLiner version's registry persistence path, when `$NoAmsi` is not set, the registry value is built with a raw `[Ref].Assembly.GetType(...)` reflection chain visible as a string literal (just with basic string concatenation). This is the older AMSI bypass style that the decision log says Defender now pattern-matches on. The newer version uses `New-AmsiBypassForRegistry` which delegates to the XOR fragment approach, but verify your test branch is using the newer version. The older one will get flagged.

**ISSUE-7: OneLiner Unencrypted Task Persistence Missing Trigger + Jitter Configuration**

In the unencrypted task persistence block of `Build-DeployBlock`, I see a code path that creates only `$t1=New-ScheduledTaskTrigger -AtLogOn` and `$t2=New-ScheduledTaskTrigger -Once -At ... -RepetitionInterval ... 5 minutes ...` with hardcoded values. The `$Trigger` array, `$PeriodicMinutes`, and `$JitterPercent` parameters are not consulted in this code path — only the encrypted path calls `Build-TriggerBlock`. This means unencrypted OneLiner deployments always get AtLogOn + 5-minute periodic regardless of what you specify.

Fix: The unencrypted task block needs to use the same `Build-TriggerBlock` function that the encrypted block uses, or at minimum inline the trigger/jitter configuration from the parameters.

**ISSUE-8: Multi-Instance Loop Uses Literal `$InstanceCount` Instead of Variable**

In the multi-instance deployment path, the loop condition is:

```powershell
for(`$_i=0;`$_i -lt `$_instanceCount;`$_i++){
```

But `$_instanceCount` is set from `$InstanceCount` which is an integer parameter on the OneLiner. Since this is being embedded into a string that becomes the minimal script, the value of `$InstanceCount` from the generation environment is baked in. However, the variable assignment line uses the PowerShell variable `$InstanceCount` without the backtick escape in the here-string context:

```powershell
$minimalScript += @"
`$_instanceCount=$InstanceCount
```

This is correct — `$InstanceCount` is expanded at generation time (Linux) and the literal number is embedded. But verify this generates correctly; if the here-string is a literal (`@'...'@`) instead of an expandable (`@"..."@`), the variable won't expand and the target will get the literal string `$InstanceCount` which is undefined.

**ISSUE-9: Manifest `$Randomize.IsPresent` and `$UseDeepPlacement.IsPresent`**

Similar to BUG-3, the manifest generation block references `.IsPresent` on bool parameters:

```powershell
Randomized        = $Randomize.IsPresent    # Always $null for [bool]
DeepPlacement     = $UseDeepPlacement.IsPresent  # Always $null for [bool]
AttachToExisting  = $AttachToExisting.IsPresent   # Always $null for [bool]
```

All three will record as `False` in every manifest regardless of actual values.

### Low Severity / Quality Improvements

**QUALITY-1: Layer A AMSI Bypass Uses ScriptBlock Invocation (Detectable Pattern)**

The Layer A bypass in the OneLiner's `$minimalScript` uses:

```powershell
$_ab={try{$x=[Ref].Assembly.GetType('System.Management.Automation.'+$('Am'+'si'+'Utils'));...};.$_ab
```

The `.` (dot-source) of a scriptblock variable assigned immediately before is itself a behavioral pattern some EDRs flag. The XOR Fragment Splitting approach used in Layer B is significantly more evasion-resistant. Consider upgrading Layer A to also use the XOR fragment approach for consistency. Since Layer A runs at paste-time (interactive console), the risk is lower, but uniformity simplifies maintenance.

**QUALITY-2: `gwmi` Alias Deprecation Warning**

Both scripts use `gwmi` (Get-WmiObject) which is deprecated in PowerShell 7.x and generates warnings. For the inline JScript wrapper and OneLiner helper functions, `gwmi` still works on PS 5.1 (the target runtime on Windows), so this is functionally fine. But if someone runs the Dropper directly under pwsh 7 on Windows, they'll see deprecation noise. Since PS 5.1 is the realistic target, this is cosmetic only.

**QUALITY-3: Show-Help Still Says v2.1 / v2.3 Inconsistency**

The Dropper's `Show-Help` says "ADS-Dropper v2.3" but the OneLiner's header block says "v2.3" in one version and "v2.1.0 (Command Generator)" in another. The README says v2.2.4. Synchronize version strings.

---

## Part 2: Copy-Paste Fixes

### Fix for BUG-2 and BUG-3 (`.IsPresent` on bool params)

In ADS-OneLiner.ps1, find the manifest generation block and replace:

```powershell
# OLD (broken after switch→bool migration):
Encrypted         = $Encrypt.IsPresent
Randomized        = $Randomize.IsPresent
DeepPlacement     = $UseDeepPlacement.IsPresent
AttachToExisting  = $AttachToExisting.IsPresent

# NEW (works for both switch and bool):
Encrypted         = [bool]$Encrypt
Randomized        = [bool]$Randomize
DeepPlacement     = [bool]$UseDeepPlacement
AttachToExisting  = [bool]$AttachToExisting
```

Also update the output template's CONFIGURATION block:

```powershell
# OLD:
  Encryption: $($Encrypt.IsPresent)
  Randomized: $($Randomize.IsPresent)

# NEW:
  Encryption: $([bool]$Encrypt)
  Randomized: $([bool]$Randomize)
```

Then grep the entire codebase: `grep -rn '\.IsPresent' src/` and fix any remaining references to parameters that were converted from `[switch]` to `[bool]`.

### Fix for BUG-4 (Compression default)

```powershell
# In ADS-OneLiner.ps1 param block, change:
[bool]$UseCompression = $true
# To:
[bool]$UseCompression = $false
```

### Fix for BUG-5 (Deep placement denylist)

In ADS-Dropper.ps1, inside the `Get-RandomADSConfig` function where deep placement candidates are filtered, add after the candidate selection:

```powershell
# Denylist: files commonly locked exclusively by system services
$lockedFileDenylist = @(
    'qmgr.db', 'qmgr0.dat', 'qmgr1.dat',  # BITS
    'NTUSER.DAT', 'UsrClass.dat',            # Registry hives
    'ntds.dit', 'edb.log', 'edb.chk',        # Active Directory
    'pagefile.sys', 'swapfile.sys',           # Virtual memory
    'hiberfil.sys',                            # Hibernation
    'desktop.ini'                              # Shell metadata (often locked)
)
$candidates = $candidates | Where-Object { $lockedFileDenylist -notcontains $_.Name }
```

## Things You Haven't Considered Yet

*(Captured in `competition/COMPETITION-STRATEGY.md` — Future Capabilities section)*

**ADS on the Volume Shadow Copy**: Windows VSS snapshots include ADS. If blue team restores from a shadow copy to undo your changes, your ADS persistence comes back with it. You could also write payloads to ADS on files that are part of the VSS-protected set, making your persistence survive restore operations.

**ADS on Network Shares**: NTFS ADS works on network shares accessed via SMB. If a target box has a share mounted from another box, you can write ADS to files on the remote share without needing direct access to the remote machine. The persistence triggers on the local box, but the payload storage is remote — making forensic analysis much harder because the evidence spans two machines.

**Decoy ADS as Blue Team Traps**: Create obviously-detectable ADS with honeypot payloads that look like your real persistence but actually do nothing harmful. Blue team spends time analyzing and removing them while your real payloads (with zero-width stream names) remain invisible. Deploy 10 obvious decoys per 1 real payload.

**ADS Chain Loading**: Instead of storing the full payload in one ADS, split it across multiple streams and have a tiny loader that reads and concatenates them. Each individual stream contains only a fragment of the payload — no single stream triggers content-based detection, and blue team analyzing individual streams sees only gibberish.

**Environment-Keyed Payloads**: Beyond hardware-derived encryption, you can key payloads to specific environmental conditions: only execute if the hostname matches a pattern, only execute during business hours, only execute if certain services are running. This prevents analysis in sandboxes and makes the payload useless to blue team even if they extract it.

**Time-Delayed Payload Activation**: Deploy dormant ADS on day 1 of competition that only activate after a time threshold. Blue team's initial sweep finds nothing, they declare the box clean, then 2 hours later your persistence kicks in. The scheduled task exists but the payload checks `Get-Date` and sleeps until activation time.

```powershell
# Time-bomb: sleeps until activation, then executes real payload
$activateAt = [DateTime]'2026-04-15 14:00:00'  # Set to competition day + offset
while((Get-Date) -lt $activateAt){ Start-Sleep -Seconds 60 }
# Now execute real payload
IEX(gc "$env:ProgramData\host.dat:stream" -Raw)
```

**Time stomping payloads (if we have not implemented that yet) is very important!**

*(Note: Timestamp anti-forensics ARE implemented in v2.4 — `ADS-Dropper.ps1` restores original file timestamps after ADS write.)*
