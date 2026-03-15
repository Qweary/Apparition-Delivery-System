<#
.SYNOPSIS
    ADS v2.5 Feature Validation + Regression Test Suite

.DESCRIPTION
    Runs on Linux/Kali (pwsh). Tests all new v2.5 features and confirms
    existing v2.4 behavior is unchanged.

    NEW FEATURE TESTS (N-series): Validate each of the 9 v2.5 changes.
    REGRESSION TESTS (R-series): Confirm v2.4 baseline behavior is intact.

    Each test runs ADS-OneLiner.ps1, captures the output file, and inspects
    the OPTION 2 (readable minimalScript) or CONFIGURATION section for
    expected/unexpected content.

.USAGE
    pwsh tests/validate-v2.5-features.ps1
    pwsh tests/validate-v2.5-features.ps1 -TestFilter 'N-'   # new features only
    pwsh tests/validate-v2.5-features.ps1 -TestFilter 'R-'   # regression only
    pwsh tests/validate-v2.5-features.ps1 -TestId N-01       # single test

.NOTES
    Author: Qweary / Claude Code
    Version: 2.5
    Platform: Linux/Kali (pwsh). Does NOT deploy — generation-only inspection.
#>

[CmdletBinding()]
param(
    [string]$TestFilter = '',
    [string]$TestId = '',
    [string]$OutputDir = '/tmp/ads-v25-tests'
)

$ErrorActionPreference = 'Continue'
$oneLiner = "$PSScriptRoot/../src/ADS-OneLiner.ps1"

if (-not (Test-Path $oneLiner)) {
    Write-Error "ADS-OneLiner.ps1 not found at: $oneLiner"
    exit 1
}

# ============================================================
# TEST INFRASTRUCTURE
# ============================================================

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$passCount = 0
$failCount = 0
$skipCount = 0

if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

function Invoke-Test {
    param(
        [string]$Id,
        [string]$Description,
        [scriptblock]$Body
    )

    # Filter logic
    if ($TestId -and $Id -ne $TestId) { return }
    if ($TestFilter -and $Id -notlike "$TestFilter*") { return }

    Write-Host "`n[$Id] $Description" -ForegroundColor Cyan

    try {
        $result = & $Body
        if ($result.Pass) {
            Write-Host "  PASS" -ForegroundColor Green
            if ($result.Detail) { Write-Host "  $($result.Detail)" -ForegroundColor DarkGray }
            $script:passCount++
            $script:results.Add([PSCustomObject]@{ Id=$Id; Status='PASS'; Description=$Description; Detail=$result.Detail })
        } else {
            Write-Host "  FAIL: $($result.Detail)" -ForegroundColor Red
            $script:failCount++
            $script:results.Add([PSCustomObject]@{ Id=$Id; Status='FAIL'; Description=$Description; Detail=$result.Detail })
        }
    } catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
        $script:failCount++
        $script:results.Add([PSCustomObject]@{ Id=$Id; Status='ERROR'; Description=$Description; Detail="$_" })
    }
}

# Helper: run OneLiner and return output file content
function Run-OneLiner {
    param([hashtable]$Params, [string]$TestId)

    $outFile = Join-Path $OutputDir "$TestId-output.txt"
    $manifestDir = Join-Path $OutputDir "$TestId-manifests"
    $Params['OutputFile'] = $outFile
    $Params['ManifestDir'] = $manifestDir

    # Redirect stderr to suppress noisy generation output
    $null = & $oneLiner @Params 2>&1

    if (Test-Path $outFile) {
        return Get-Content $outFile -Raw
    }
    return $null
}

# Helper: check string presence in output
function Assert-Contains { param([string]$Content, [string]$Pattern)
    [bool]($Content -match [regex]::Escape($Pattern)) -or [bool]($Content -match $Pattern)
}

# Minimal benign test payload (no $ variables — avoids expansion corruption detection)
$testPayload = "Write-Host 'ADS-Test-OK'"

Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  ADS v2.5 Feature Validation + Regression Test Suite    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# ============================================================
# NEW FEATURE TESTS
# ============================================================

Write-Host "━━━ NEW FEATURE TESTS (N-series) ━━━" -ForegroundColor Yellow

# N-01: Advanced tier auto-enables Encrypt
Invoke-Test -Id 'N-01' -Description '-Obfuscate Advanced auto-enables -Encrypt (no _Encrypt param passed)' -Body {
    $out = Run-OneLiner -TestId 'N-01' -Params @{
        Payload   = $testPayload
        Obfuscate = 'Advanced'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # _prot or _wrapEC appear in OPTION 2 when encryption is active
    $hasEnc = ($out -match '_prot|_wrapEC|ProtectedData|Compression forced')
    @{ Pass = $hasEnc; Detail = if ($hasEnc) { 'Encryption markers found in output' } else { '_prot/_wrapEC not found — encryption may not be active' } }
}

# N-02: Paranoid tier auto-enables Encrypt
Invoke-Test -Id 'N-02' -Description '-Obfuscate Paranoid auto-enables -Encrypt' -Body {
    $out = Run-OneLiner -TestId 'N-02' -Params @{
        Payload   = $testPayload
        Obfuscate = 'Paranoid'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasEnc = ($out -match '_prot|_wrapEC|ProtectedData|Compression forced')
    @{ Pass = $hasEnc; Detail = if ($hasEnc) { 'Encryption markers found' } else { 'Encryption not detected' } }
}

# N-03: None tier does NOT auto-enable Encrypt
Invoke-Test -Id 'N-03' -Description '-Obfuscate None does NOT auto-enable -Encrypt' -Body {
    $out = Run-OneLiner -TestId 'N-03' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Encryption: false should appear in CONFIGURATION section
    $noEnc = ($out -match 'Encryption: False')
    @{ Pass = $noEnc; Detail = if ($noEnc) { 'Encryption=False confirmed' } else { 'Expected Encryption: False in CONFIGURATION' } }
}

# N-04: -Encrypt:$false overrides Advanced tier default
Invoke-Test -Id 'N-04' -Description '-Encrypt:$false with -Obfuscate Advanced disables encryption' -Body {
    $out = Run-OneLiner -TestId 'N-04' -Params @{
        Payload      = $testPayload
        Obfuscate    = 'Advanced'
        Encrypt      = $false
        Persist      = 'none'
        UseCompression = $false
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $noEnc = ($out -match 'Encryption: False')
    @{ Pass = $noEnc; Detail = if ($noEnc) { 'Override confirmed — Encryption=False' } else { 'Encryption override did not work' } }
}

# N-05: Deployment complete absent for Advanced (no -ShowArtifacts)
Invoke-Test -Id 'N-05' -Description 'No "[+] Deployment complete" in generated script for Advanced (no -ShowArtifacts)' -Body {
    $out = Run-OneLiner -TestId 'N-05' -Params @{
        Payload   = $testPayload
        Obfuscate = 'Advanced'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasMsg = ($out -match 'Deployment complete')
    @{ Pass = (-not $hasMsg); Detail = if (-not $hasMsg) { 'Message correctly absent' } else { 'FAIL: Deployment complete message found (should be suppressed)' } }
}

# N-06: Deployment complete present for None (default)
Invoke-Test -Id 'N-06' -Description '"[+] Deployment complete" present for -Obfuscate None (default-on)' -Body {
    $out = Run-OneLiner -TestId 'N-06' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasMsg = ($out -match 'Deployment complete')
    @{ Pass = $hasMsg; Detail = if ($hasMsg) { 'Message correctly present' } else { 'FAIL: Deployment complete missing for None tier' } }
}

# N-07: -ShowArtifacts shows deployment message for Advanced
Invoke-Test -Id 'N-07' -Description '-ShowArtifacts reveals "[+] Deployment complete" for Advanced tier' -Body {
    $out = Run-OneLiner -TestId 'N-07' -Params @{
        Payload       = $testPayload
        Obfuscate     = 'Advanced'
        ShowArtifacts = $true
        Persist       = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasMsg = ($out -match 'Deployment complete')
    @{ Pass = $hasMsg; Detail = if ($hasMsg) { 'Message present with -ShowArtifacts' } else { 'FAIL: Deployment complete missing even with -ShowArtifacts' } }
}

# N-08: -StreamName 'custom' without ZW — used as-is in stream configuration
Invoke-Test -Id 'N-08' -Description '-StreamName custom_stream (no ZW) — appears in CONFIGURATION section' -Body {
    $out = Run-OneLiner -TestId 'N-08' -Params @{
        Payload    = $testPayload
        Obfuscate  = 'Basic'
        StreamName = 'custom_stream'
        Persist    = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $found = ($out -match 'custom_stream')
    @{ Pass = $found; Detail = if ($found) { 'custom_stream found in output' } else { 'custom_stream not found in output' } }
}

# N-09: -StreamName with -ZeroWidthStreams — prefix + ZW suffix
Invoke-Test -Id 'N-09' -Description '-StreamName + -ZeroWidthStreams — stream uses prefix (ZW chars appended)' -Body {
    $out = Run-OneLiner -TestId 'N-09' -Params @{
        Payload          = $testPayload
        Obfuscate        = 'Basic'
        StreamName       = 'MyPrefix'
        ZeroWidthStreams = $true
        Persist          = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # ZW active + StreamName: CONFIGURATION shows '<zero-width> (...)' with prefix codepoints + ZW codepoints
    # 'M' = U+004D, and at least one ZW char must also appear (U+200B/200C/200D/FEFF/2060/200E/200F)
    $hasZwTag   = ($out -match 'zero-width')
    $hasPfxChar = ($out -match 'U\+004D')  # 'M' from 'MyPrefix'
    $hasZwChar  = ($out -match 'U\+200[BCDEFbcdef]|U\+FEFF|U\+2060')  # at least one ZW codepoint
    $hasCfg = $hasZwTag -and $hasPfxChar -and $hasZwChar
    @{ Pass = $hasCfg; Detail = if ($hasCfg) { 'ZW prefix stream confirmed (zero-width tag + prefix codepoint + ZW codepoint)' } else { "ZW prefix stream not detected: zwTag=$hasZwTag, pfxChar=$hasPfxChar, zwChar=$hasZwChar" } }
}

# N-10: -ZeroWidthMode multi with -StreamName — multiple ZW chars appended
Invoke-Test -Id 'N-10' -Description '-ZeroWidthMode multi + -StreamName — prefix + multiple ZW chars' -Body {
    $out = Run-OneLiner -TestId 'N-10' -Params @{
        Payload          = $testPayload
        Obfuscate        = 'Basic'
        StreamName       = 'PfxTest'
        ZeroWidthStreams = $true
        ZeroWidthMode    = 'multi'
        Persist          = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Codepoints section should have multiple U+ entries for the ZW chars (at least 2 beyond prefix)
    $cpMatch = [regex]::Matches($out, 'U\+[0-9A-F]{4}')
    # PfxTest = 7 ASCII chars + at least 2 ZW chars = at least 9 codepoints
    $hasManyZW = $cpMatch.Count -ge 9
    @{ Pass = $hasManyZW; Detail = if ($hasManyZW) { "Found $($cpMatch.Count) codepoints (prefix + multiple ZW)" } else { "Only $($cpMatch.Count) codepoints found — expected >= 9" } }
}

# N-11: Paranoid default stream = '$Data' prefix + ZW
Invoke-Test -Id 'N-11' -Description '-Obfuscate Paranoid default stream name starts with $Data (0x0024 0x0044...)' -Body {
    $out = Run-OneLiner -TestId 'N-11' -Params @{
        Payload   = $testPayload
        Obfuscate = 'Paranoid'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # $Data: $ = U+0024, D = U+0044 — extract CONFIGURATION section and check Stream Name line
    # Checking U+XXXX format (not bare hex substring) to avoid false positives from base64 blob
    $cfgSection = ($out -split '={10,}')[0]  # CONFIGURATION is before the first long separator
    $has0024 = ($cfgSection -match 'U\+0024')  # $ char (not bare '0024' which matches base64)
    $has0044 = ($cfgSection -match 'U\+0044')  # D char
    $hasZwChar  = ($cfgSection -match 'U\+200[BCDEFbcdef]|U\+FEFF|U\+2060')  # ZW suffix appended
    @{ Pass = ($has0024 -and $has0044 -and $hasZwChar); Detail = if ($has0024 -and $has0044 -and $hasZwChar) { '$Data prefix (U+0024, U+0044) + ZW suffix confirmed in CONFIGURATION' } else { "Missing: 0024=$has0024, 0044=$has0044, zwChar=$hasZwChar" } }
}

# N-12: Advanced default stream = Zone.Identifier (in CONFIGURATION)
Invoke-Test -Id 'N-12' -Description '-Obfuscate Advanced default stream = Zone.Identifier (no ZW)' -Body {
    $out = Run-OneLiner -TestId 'N-12' -Params @{
        Payload   = $testPayload
        Obfuscate = 'Advanced'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # CONFIGURATION: "Stream Name: Zone.Identifier" (no ZW active for Advanced by default)
    $found = ($out -match 'Zone\.Identifier')
    @{ Pass = $found; Detail = if ($found) { 'Zone.Identifier confirmed as Advanced default stream' } else { 'Zone.Identifier not found in output' } }
}

# N-13: -Trigger all expands to all 4 triggers
Invoke-Test -Id 'N-13' -Description '-Trigger all expands to AtLogOn+AtStartup+OnIdle+OnUnlock' -Body {
    $out = Run-OneLiner -TestId 'N-13' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        Trigger   = @('all')
        Persist   = 'task'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasAll = ($out -match 'AtLogOn') -and ($out -match 'AtStartup') -and ($out -match 'OnIdle') -and ($out -match 'OnUnlock')
    @{ Pass = $hasAll; Detail = if ($hasAll) { 'All 4 triggers found in output' } else { "Missing triggers: AtLogOn=$($out -match 'AtLogOn'), AtStartup=$($out -match 'AtStartup'), OnIdle=$($out -match 'OnIdle'), OnUnlock=$($out -match 'OnUnlock')" } }
}

# N-14: -Trigger comma string 'AtLogOn,OnIdle' parses correctly
Invoke-Test -Id 'N-14' -Description "-Trigger 'AtLogOn,OnIdle' (comma string) parsed as two separate triggers" -Body {
    $out = Run-OneLiner -TestId 'N-14' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        Trigger   = @('AtLogOn,OnIdle')
        Persist   = 'task'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasLogon = ($out -match 'AtLogOn')
    $hasIdle  = ($out -match 'OnIdle')
    $noStartup = (-not ($out -match 'AtStartup'))  # AtStartup should NOT be present (not specified)
    @{ Pass = ($hasLogon -and $hasIdle -and $noStartup); Detail = if ($hasLogon -and $hasIdle -and $noStartup) { 'AtLogOn+OnIdle parsed; AtStartup correctly absent' } else { "AtLogOn=$hasLogon, OnIdle=$hasIdle, AtStartup-absent=$noStartup" } }
}

# N-15: Invalid trigger value fails validation
Invoke-Test -Id 'N-15' -Description "-Trigger 'BadTrigger' fails validation with error" -Body {
    $exitCode = 0
    try {
        $null = & $oneLiner -Payload $testPayload -Obfuscate None -Trigger @('BadTrigger') -OutputFile '/dev/null' -ManifestDir '/tmp/ads-null' 2>&1
        $exitCode = $LASTEXITCODE
    } catch { $exitCode = 1 }
    # Should fail: ValidateScript throws ParameterBindingValidationException — caught above, $exitCode=1
    # Also check that error output mentions the bad trigger
    $errOut = ''
    try {
        $errOut = & $oneLiner -Payload $testPayload -Obfuscate None -Trigger @('BadTrigger') -OutputFile '/dev/null' -ManifestDir '/tmp/ads-null' 2>&1 | Out-String
    } catch { $errOut = $_.ToString() }
    $failed = ($exitCode -ne 0) -or ($errOut -match 'BadTrigger|Invalid trigger|Cannot validate|ParameterBinding')
    @{ Pass = $failed; Detail = if ($failed) { 'Validation correctly rejected bad trigger value' } else { "FAIL: Bad trigger was accepted (exitCode=$exitCode)" } }
}

# N-16: -InstanceCount 3 + -StreamName + -ZeroWidthStreams — all instances use prefix
Invoke-Test -Id 'N-16' -Description '-InstanceCount 3 + -StreamName + ZW — all instances use StreamName prefix (bug fix)' -Body {
    $out = Run-OneLiner -TestId 'N-16' -Params @{
        Payload          = $testPayload
        Obfuscate        = 'Basic'
        InstanceCount    = 3
        StreamName       = 'PrefixCheck'
        ZeroWidthStreams = $true
        Persist          = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Generated script should contain '$sn=''PrefixCheck''+[char]...' NOT the old random generation
    $hasPrefixCode = ($out -match [regex]::Escape("sn='PrefixCheck'"))
    $hasRandomCode = ($out -match [regex]::Escape('65..90')+'.*'+[regex]::Escape('97..122'))  # old random code
    @{ Pass = ($hasPrefixCode -and -not $hasRandomCode); Detail = if ($hasPrefixCode -and -not $hasRandomCode) { 'StreamName prefix used; random generation absent' } elseif ($hasRandomCode) { 'FAIL: Old random stream generation still present' } else { "hasPrefixCode=$hasPrefixCode, hasRandomCode=$hasRandomCode" } }
}

# N-17: -InstanceCount 3 without -StreamName — random $sn per instance (unchanged)
Invoke-Test -Id 'N-17' -Description '-InstanceCount 3 without -StreamName — random sn generation preserved' -Body {
    $out = Run-OneLiner -TestId 'N-17' -Params @{
        Payload       = $testPayload
        Obfuscate     = 'Basic'
        InstanceCount = 3
        Persist       = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Should still use random generation
    $hasRandom = ($out -match '65\.\.90.*97\.\.122|Get-Random.*Count 8')
    @{ Pass = $hasRandom; Detail = if ($hasRandom) { 'Random stream generation present for instances' } else { 'Random stream generation not found' } }
}

# N-18: -CreateDecoys -Obfuscate None → decoy message in generated script
Invoke-Test -Id 'N-18' -Description '-CreateDecoys 2 with -Obfuscate None → decoy location message in generated script' -Body {
    $out = Run-OneLiner -TestId 'N-18' -Params @{
        Payload       = $testPayload
        Obfuscate     = 'None'
        CreateDecoys  = 2
        Persist       = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Check for the Write-Host runtime message (not just the CONFIGURATION 'Decoys: 2' field which always appears)
    $hasDecoyMsg = ($out -match 'Write-Host.*Decoys:')
    @{ Pass = $hasDecoyMsg; Detail = if ($hasDecoyMsg) { 'Decoy Write-Host message found in generated script' } else { 'Decoy Write-Host message missing (should show for None tier)' } }
}

# N-19: -CreateDecoys -Obfuscate Advanced (no -ShowArtifacts) → no decoy message
Invoke-Test -Id 'N-19' -Description '-CreateDecoys 2 with Advanced and no -ShowArtifacts → no decoy message in generated script' -Body {
    $out = Run-OneLiner -TestId 'N-19' -Params @{
        Payload      = $testPayload
        Obfuscate    = 'Advanced'
        CreateDecoys = 2
        Persist      = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasDecoyMsg = ($out -match 'Write-Host.*Decoys:')
    @{ Pass = (-not $hasDecoyMsg); Detail = if (-not $hasDecoyMsg) { 'Decoy message correctly absent for Advanced without -ShowArtifacts' } else { 'FAIL: Decoy message present (should be suppressed)' } }
}

# N-20: -CreateDecoys + -ShowArtifacts → decoy message present for Advanced
Invoke-Test -Id 'N-20' -Description '-CreateDecoys 2 + -ShowArtifacts → decoy location message present for Advanced' -Body {
    $out = Run-OneLiner -TestId 'N-20' -Params @{
        Payload       = $testPayload
        Obfuscate     = 'Advanced'
        CreateDecoys  = 2
        ShowArtifacts = $true
        Persist       = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasDecoyMsg = ($out -match 'Write-Host.*Decoys:')
    @{ Pass = $hasDecoyMsg; Detail = if ($hasDecoyMsg) { 'Decoy message present with -ShowArtifacts' } else { 'Decoy message missing even with -ShowArtifacts' } }
}

# N-21: -TaskName single instance → custom task name in output
Invoke-Test -Id 'N-21' -Description '-TaskName MyCustomTask (single instance) → task name in generated script' -Body {
    $out = Run-OneLiner -TestId 'N-21' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        TaskName  = 'MyCustomTask'
        Persist   = 'task'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Single instance: task name appears in CONFIGURATION and as $_tn0='MyCustomTask'
    $found = ($out -match 'MyCustomTask')
    @{ Pass = $found; Detail = if ($found) { 'MyCustomTask found in output' } else { 'Custom task name not found in output' } }
}

# N-22: -TaskName + -InstanceCount 3 → indexed names (MyTask_00, MyTask_01, MyTask_02)
Invoke-Test -Id 'N-22' -Description '-TaskName MyTask + -InstanceCount 3 → indexed task names MyTask_00/01/02' -Body {
    $out = Run-OneLiner -TestId 'N-22' -Params @{
        Payload       = $testPayload
        Obfuscate     = 'Basic'
        TaskName      = 'MyTask'
        InstanceCount = 3
        Persist       = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Generated loop should use 'MyTask'+'_'+$_i.ToString('00')
    $hasIndexed = ($out -match [regex]::Escape("'MyTask'+'_'"))
    @{ Pass = $hasIndexed; Detail = if ($hasIndexed) { 'Indexed task name code found in multi-instance loop' } else { 'Indexed task name code not found' } }
}

# N-23: -FileName 'WindowsUpdate.dat' → host file name in output
Invoke-Test -Id 'N-23' -Description "-FileName 'WindowsUpdate.dat' → host path uses custom file name" -Body {
    $out = Run-OneLiner -TestId 'N-23' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        FileName  = 'WindowsUpdate.dat'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $found = ($out -match 'WindowsUpdate\.dat')
    @{ Pass = $found; Detail = if ($found) { 'WindowsUpdate.dat found in output CONFIGURATION' } else { 'Custom file name not found in output' } }
}

# N-24: -HybridPrefix no longer accepted (param removed)
Invoke-Test -Id 'N-24' -Description '-HybridPrefix is removed — script rejects unknown parameter' -Body {
    $errOut = $null
    try {
        $errOut = & $oneLiner -Payload $testPayload -Obfuscate Basic -HybridPrefix 'Zone.Identifier' -OutputFile '/dev/null' -ManifestDir '/tmp/ads-null' 2>&1
    } catch { $errOut = "$_" }
    # Should produce an error about unknown parameter
    $rejected = ($errOut -match 'HybridPrefix|not recogniz|unknown|parameter')
    @{ Pass = $rejected; Detail = if ($rejected) { 'HybridPrefix correctly rejected as unknown parameter' } else { "Unexpected: HybridPrefix was accepted. Output: $($errOut | Select-Object -First 3 | Out-String)" } }
}

# ============================================================
# REGRESSION TESTS
# ============================================================

Write-Host "`n━━━ REGRESSION TESTS (R-series) ━━━" -ForegroundColor Yellow

# R-01: Basic plaintext payload, -Obfuscate None
Invoke-Test -Id 'R-01' -Description '-Obfuscate None generates valid output file' -Body {
    $out = Run-OneLiner -TestId 'R-01' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        Persist   = 'none'
    }
    $valid = ($out -match 'EncodedCommand') -and ($out -match 'OPTION 1') -and ($out -match 'OPTION 2')
    @{ Pass = $valid; Detail = if ($valid) { 'Valid output format (OPTION 1 + OPTION 2 present)' } else { 'Output missing expected sections' } }
}

# R-02: -Obfuscate Basic still works
Invoke-Test -Id 'R-02' -Description '-Obfuscate Basic generates without error; no ZW chars by default' -Body {
    $out = Run-OneLiner -TestId 'R-02' -Params @{
        Payload   = $testPayload
        Obfuscate = 'Basic'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Basic should NOT have zero-width active — CONFIGURATION 'Stream Name:' should NOT show '<zero-width> (...)'
    # 'Zero-Width Mode: single' always appears (it is the default param value) so that check is a tautology
    $noZW = ($out -notmatch 'Stream Name: <zero-width>')
    @{ Pass = $noZW; Detail = if ($noZW) { 'Basic tier generates correctly without ZW active' } else { 'Unexpected ZW stream in Basic tier (Stream Name showed <zero-width>)' } }
}

# R-03: -ZeroWidthStreams without -StreamName → pure ZW stream (existing behavior)
Invoke-Test -Id 'R-03' -Description '-ZeroWidthStreams without -StreamName → pure ZW stream name' -Body {
    $out = Run-OneLiner -TestId 'R-03' -Params @{
        Payload          = $testPayload
        Obfuscate        = 'Basic'
        ZeroWidthStreams = $true
        Persist          = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasZW = ($out -match 'zero-width \(U\+')
    @{ Pass = $hasZW; Detail = if ($hasZW) { 'Pure ZW stream confirmed (zero-width codepoint in CONFIGURATION)' } else { 'ZW stream not detected' } }
}

# R-04: -ZeroWidthMode single (pure ZW, no prefix)
Invoke-Test -Id 'R-04' -Description '-ZeroWidthMode single without -StreamName → single ZW char only' -Body {
    $out = Run-OneLiner -TestId 'R-04' -Params @{
        Payload          = $testPayload
        Obfuscate        = 'Basic'
        ZeroWidthStreams = $true
        ZeroWidthMode    = 'single'
        Persist          = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Single mode: only 1 codepoint in the ZW section
    $cpMatches = [regex]::Matches($out, 'zero-width \((U\+[0-9A-F]{4})\)')
    $isSingle = ($cpMatches.Count -eq 1)
    @{ Pass = $isSingle; Detail = if ($isSingle) { "Single ZW char confirmed: $($cpMatches[0].Groups[1].Value)" } else { "Expected 1 codepoint, found $($cpMatches.Count)" } }
}

# R-05: -ZeroWidthMode multi (pure ZW, no prefix) → multiple chars
Invoke-Test -Id 'R-05' -Description '-ZeroWidthMode multi without -StreamName → multiple ZW chars' -Body {
    $out = Run-OneLiner -TestId 'R-05' -Params @{
        Payload          = $testPayload
        Obfuscate        = 'Basic'
        ZeroWidthStreams = $true
        ZeroWidthMode    = 'multi'
        Persist          = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Multi mode: should have multiple U+ codepoints in a single stream name
    $cpMatches = [regex]::Matches($out, 'U\+[0-9A-F]{4}')
    $isMulti = ($cpMatches.Count -ge 2)
    @{ Pass = $isMulti; Detail = if ($isMulti) { "Multiple ZW chars confirmed: $($cpMatches.Count) codepoints" } else { "Only $($cpMatches.Count) codepoint(s) — expected >= 2 for multi mode" } }
}

# R-06: -Persist registry still generates registry block
Invoke-Test -Id 'R-06' -Description '-Persist registry generates registry persistence code' -Body {
    $out = Run-OneLiner -TestId 'R-06' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        Persist   = 'registry'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasReg = ($out -match 'Set-ItemProperty')
    @{ Pass = $hasReg; Detail = if ($hasReg) { 'Set-ItemProperty found — registry persistence present' } else { 'Registry persistence code not found' } }
}

# R-07: -Trigger AtLogOn generates correct trigger block
Invoke-Test -Id 'R-07' -Description '-Trigger AtLogOn generates New-ScheduledTaskTrigger -AtLogOn' -Body {
    $out = Run-OneLiner -TestId 'R-07' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        Trigger   = @('AtLogOn')
        Persist   = 'task'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasTrigger = ($out -match 'AtLogOn')
    @{ Pass = $hasTrigger; Detail = if ($hasTrigger) { 'AtLogOn trigger confirmed in generated code' } else { 'AtLogOn trigger not found' } }
}

# R-08: -InstanceCount 3 without new params — loop structure present
Invoke-Test -Id 'R-08' -Description '-InstanceCount 3 (no new params) — multi-instance loop generated' -Body {
    $out = Run-OneLiner -TestId 'R-08' -Params @{
        Payload       = $testPayload
        Obfuscate     = 'Basic'
        InstanceCount = 3
        Persist       = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasLoop = ($out -match '_instanceCount=3') -and ($out -match 'for\(.*_i=0')
    @{ Pass = $hasLoop; Detail = if ($hasLoop) { 'Multi-instance loop (count=3) confirmed' } else { 'Loop structure not found' } }
}

# R-09: -UseDeepPlacement $true → deep placement code present
Invoke-Test -Id 'R-09' -Description '-UseDeepPlacement $true — deep placement runtime code in generated script' -Body {
    $out = Run-OneLiner -TestId 'R-09' -Params @{
        Payload          = $testPayload
        Obfuscate        = 'None'
        UseDeepPlacement = $true
        Persist          = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasDeep = ($out -match 'WER|validDirs|deepDir')
    @{ Pass = $hasDeep; Detail = if ($hasDeep) { 'Deep placement runtime code present' } else { 'Deep placement code not found' } }
}

# R-10: -CreateDecoys 3 -Obfuscate None → decoy sc commands in generated script
Invoke-Test -Id 'R-10' -Description '-CreateDecoys 3 -Obfuscate None → sc commands for decoys in generated script' -Body {
    $out = Run-OneLiner -TestId 'R-10' -Params @{
        Payload      = $testPayload
        Obfuscate    = 'None'
        CreateDecoys = 3
        Persist      = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasDecoys = ($out -match 'sc.*Zone\.Identifier') -or ($out -match "sc.*Summary")
    @{ Pass = $hasDecoys; Detail = if ($hasDecoys) { 'Decoy sc commands found in generated script' } else { 'Decoy sc commands not found' } }
}

# R-11: -Obfuscate Paranoid still generates ZW stream (with $Data prefix by default)
Invoke-Test -Id 'R-11' -Description '-Obfuscate Paranoid still generates ZW stream name' -Body {
    $out = Run-OneLiner -TestId 'R-11' -Params @{
        Payload   = $testPayload
        Obfuscate = 'Paranoid'
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    $hasZW = ($out -match 'zero-width \(U\+')
    @{ Pass = $hasZW; Detail = if ($hasZW) { 'ZW stream confirmed for Paranoid tier' } else { 'ZW stream not found — Paranoid tier broken' } }
}

# R-12: Output file created at -OutputFile path
Invoke-Test -Id 'R-12' -Description 'Output file created at -OutputFile path' -Body {
    $outFile = Join-Path $OutputDir 'R-12-specific-output.txt'
    $null = & $oneLiner -Payload $testPayload -Obfuscate None -Persist none `
        -OutputFile $outFile -ManifestDir (Join-Path $OutputDir 'R-12-manifests') 2>&1
    $exists = Test-Path $outFile
    @{ Pass = $exists; Detail = if ($exists) { "File exists: $outFile" } else { "File NOT created: $outFile" } }
}

# R-13: Manifest written to -ManifestDir
Invoke-Test -Id 'R-13' -Description 'Manifest JSON written to -ManifestDir' -Body {
    $manifestDir = Join-Path $OutputDir 'R-13-manifests'
    $null = & $oneLiner -Payload $testPayload -Obfuscate None -Persist none `
        -OutputFile (Join-Path $OutputDir 'R-13-out.txt') -ManifestDir $manifestDir 2>&1
    $manifests = Get-ChildItem $manifestDir -Filter '*.json' -ErrorAction SilentlyContinue
    $exists = $manifests.Count -gt 0
    @{ Pass = $exists; Detail = if ($exists) { "Manifest found: $($manifests[0].Name)" } else { 'No manifest JSON files found' } }
}

# R-14: -NoAmsi skips Layer A bypass
Invoke-Test -Id 'R-14' -Description '-NoAmsi skips Layer A XOR bypass code' -Body {
    $out = Run-OneLiner -TestId 'R-14' -Params @{
        Payload   = $testPayload
        Obfuscate = 'None'
        NoAmsi    = $true
        Persist   = 'none'
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # Without AMSI bypass, the XOR byte array code should not appear
    $hasAmsi = ($out -match 'AMSI Bypass: False')
    @{ Pass = $hasAmsi; Detail = if ($hasAmsi) { 'AMSI Bypass: False confirmed in CONFIGURATION' } else { 'AMSI status not confirmed' } }
}

# R-15: Jitter ISO 8601 format correct (PT<n>M)
Invoke-Test -Id 'R-15' -Description 'Jitter uses ISO 8601 PT<n>M format in trigger code' -Body {
    $out = Run-OneLiner -TestId 'R-15' -Params @{
        Payload        = $testPayload
        Obfuscate      = 'None'
        JitterPercent  = 20
        PeriodicMinutes = 10
        Persist        = 'task'
        Trigger        = @('AtLogOn')
    }
    if (-not $out) { return @{Pass=$false; Detail='No output generated'} }
    # ISO 8601 duration: PT2M (20% of 10 = 2 minutes)
    $hasISO = ($out -match "PT\d+M")
    @{ Pass = $hasISO; Detail = if ($hasISO) { 'ISO 8601 PT<n>M jitter format confirmed' } else { 'ISO 8601 jitter format not found' } }
}

# ============================================================
# SUMMARY
# ============================================================

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
Write-Host "RESULTS SUMMARY" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White

$results | ForEach-Object {
    $color = switch ($_.Status) {
        'PASS'  { 'Green' }
        'FAIL'  { 'Red' }
        'ERROR' { 'Yellow' }
    }
    Write-Host "  [$($_.Id)] $($_.Status.PadRight(5)) — $($_.Description)" -ForegroundColor $color
}

Write-Host "`n  Total: $($results.Count)  |  PASS: $passCount  |  FAIL: $failCount" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Red' })

if ($failCount -eq 0 -and $results.Count -gt 0) {
    Write-Host "`n  ALL TESTS PASSED — v2.5 features confirmed, v2.4 regression baseline intact" -ForegroundColor Green
} elseif ($failCount -gt 0) {
    Write-Host "`n  FAILURES DETECTED — review output above before committing" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n  No tests ran (check -TestFilter or -TestId params)" -ForegroundColor Yellow
}
