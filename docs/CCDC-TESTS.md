
## `docs/CCDC-TESTS.md`
```markdown
# CCDC Validation & Scoring

## 🔍 Blue Team Detection (Your Score Triggers)

```powershell
# 1. Task Creation (Primary score)
schtasks /query /fo LIST | findstr /i "UX\|Maintenance\|UsbCeip"

# 2. ADS Discovery
dir /r C:\ /s 2>nul | findstr ":syc_payload\|:Sys\|:Kernel"
powershell "Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue | ? PSIsContainer -eq $false | Get-Item -Stream * | ? Name -match 'syc|app_log'"

# 3. Process Chains
Get-Process | ? {$_.ProcessName -match "script|powershell|wscript"} | select Name,Id,Parent

# 4. WMI Events
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | select Query,CommandLineTemplate

🧪 Red Team Validation
powershell

# Test payload (infinite notepad beacon)
$testPayload = '$proc=Get-Process notepad; if(-not $proc){Start-Process notepad -WindowStyle Hidden}; while(1){sleep 30}'

# Deploy + validate
.\src\ADS-Dropper.ps1 -Payload $testPayload -Persist task,volroot -Randomize -Encrypt -NoExec

# Verify deployment
dir /r C:\ProgramData\  # Should show ADS
schtasks /query | findstr app_log  # Task created
Get-Process notepad  # Beacon active

# Cleanup
schtasks /delete /f /tn "Microsoft\Windows\UX\*" 2>nul
del /a C:\ProgramData\app_log*.vbs 2>nul
powershell "Get-ChildItem C:\ -Stream * | ? Name -match 'syc' | Remove-Item"
