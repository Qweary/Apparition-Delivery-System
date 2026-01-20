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
       }
   }
