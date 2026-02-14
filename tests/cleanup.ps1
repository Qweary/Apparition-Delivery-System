# /tests/cleanup.ps1
   param([string[]]$Targets = @('localhost'))
   
   foreach($target in $Targets) {
       Invoke-Command -ComputerName $target -ScriptBlock {
           # Remove tasks
           schtasks /delete /f /tn "*UX*" 2>$null
           schtasks /delete /f /tn "*WinSAT*" 2>$null
           
           # Remove registry
           Remove-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update_*" -ErrorAction SilentlyContinue
           Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update_*" -ErrorAction SilentlyContinue
           
           # Remove ADS
           Get-ChildItem C:\ProgramData -Recurse | Get-Item -Stream * | Where-Object { $_.Stream -match 'syc|Zone|SmartScreen' } | Remove-Item -Force
           Get-ChildItem "C:\:ads_*" | Remove-Item -Force
           
           # Remove loaders
           Remove-Item C:\ProgramData\app_log*.vbs, C:\ProgramData\app_log*.ps1 -Force -ErrorAction SilentlyContinue

           # Remove Wscript and Jscript stuff
           Get-ScheduledTask | Where-Object { $_.Actions.Execute -eq 'wscript.exe' -and $_.Actions.Arguments -match '\.js' } | ForEach-Object {
               # Extract JScript path from Arguments
               if ($_.Actions.Arguments -match '"([^"]+\.js)"') {
                   $jsPath = $Matches[1]
                   if (Test-Path $jsPath) {
                       Remove-Item $jsPath -Force
                       Write-Host "Removed JScript: $jsPath" -ForegroundColor Yellow
                   }
               }
               # Remove task
               Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
               Write-Host "Removed task: $($_.TaskName)" -ForegroundColor Green
           }
           
           # Remove randomized host files
           Get-ChildItem C:\ProgramData -Filter "????????" -File | 
               Where-Object { $_.Name -match '^[A-Za-z]{8}$' } | 
               ForEach-Object {
                   $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue
                   if ($streams | Where-Object { $_.Stream -ne ':$DATA' }) {
                       Remove-Item $_.FullName -Force
                   }
               }
           
           # Remove randomized tasks
           Get-ScheduledTask | 
               Where-Object { $_.TaskName -match '^WinSAT_[A-Z]{6}$' } | 
               Unregister-ScheduledTask -Confirm:$false
           
       }
   }
