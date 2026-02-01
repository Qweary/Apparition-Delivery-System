<#
.SYNOPSIS
    Detect-ZeroWidthADS.ps1 - Blue team tool for enumerating zero-width Unicode ADS.

.DESCRIPTION
    Forensic and IR tool that enumerates Alternate Data Streams and reveals
    zero-width Unicode characters through byte-level analysis. Does NOT create
    or modify any ADS - strictly read-only enumeration.

.PARAMETER Path
    Root path to scan for ADS. Supports both files and directories.

.PARAMETER Recurse
    Recursively scan all subdirectories.

.PARAMETER ShowOnlyNonPrintable
    Filter results to show only streams containing non-printable characters.

.PARAMETER ExportCSV
    Export results to CSV file for analysis.

.PARAMETER CheckScheduledTasks
    Also scan scheduled task names for zero-width characters.

.PARAMETER CheckRegistry
    Also scan common registry persistence locations for zero-width characters.

.EXAMPLE
    .\Detect-ZeroWidthADS.ps1 -Path C:\ProgramData -Recurse -ShowOnlyNonPrintable

.EXAMPLE
    .\Detect-ZeroWidthADS.ps1 -Path C:\ -Recurse -ExportCSV C:\IR\ads_scan.csv

.EXAMPLE
    .\Detect-ZeroWidthADS.ps1 -Path C:\Windows\System32 -CheckScheduledTasks -CheckRegistry

.NOTES
    Author: Blue Team / ChatGPT Contribution
    Version: 1.0.0
    Purpose: Detection and forensic analysis only
    
    Requires: PowerShell 5.1+ and local admin for full visibility
    
    SAFE FOR PRODUCTION: Read-only operations, no system modifications
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Path,

    [switch]$Recurse,

    [switch]$ShowOnlyNonPrintable,

    [string]$ExportCSV,

    [switch]$CheckScheduledTasks,

    [switch]$CheckRegistry
)

# Known zero-width Unicode codepoints from research
$script:ZeroWidthCodepoints = @(
    0x061C,  # Arabic Letter Mark
    0x180E,  # Mongolian Vowel Separator
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0x200E,  # Left-to-Right Mark
    0x200F,  # Right-to-Left Mark
    0x202A,  # LTR Embedding
    0x202B,  # RTL Embedding
    0x202C,  # Pop Directional
    0x202D,  # LTR Override
    0x202E,  # RTL Override
    0x2060,  # Word Joiner
    0xFEFF   # Zero Width No-Break Space
)

function Get-StreamNameInfo {
    <#
    .SYNOPSIS
        Analyzes a stream name and returns detailed Unicode information.
    #>
    param([string]$streamName)

    # Convert stream name to Unicode codepoints and bytes
    $chars = $streamName.ToCharArray()
    $codepoints = $chars | ForEach-Object { "U+{0:X4}" -f [int]$_ }
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($streamName) |
             ForEach-Object { "0x{0:X2}" -f $_ }

    # Check if printable ASCII
    $isPrintable = ($streamName -cmatch '^[\x20-\x7E]+$')
    
    # Check for zero-width characters
    $containsZeroWidth = ($chars | Where-Object {
        $code = [int]$_
        $script:ZeroWidthCodepoints -contains $code
    }).Count -gt 0

    # Check for bidirectional control characters
    $containsBidi = ($chars | Where-Object {
        $code = [int]$_
        ($code -ge 0x202A -and $code -le 0x202E)
    }).Count -gt 0

    return [PSCustomObject]@{
        StreamRaw = $streamName
        StreamEscaped = ($codepoints -join ' ')
        Codepoints = $codepoints
        Bytes = ($bytes -join ' ')
        IsPrintable = $isPrintable
        ContainsZeroWidth = $containsZeroWidth
        ContainsBidi = $containsBidi
        Length = $chars.Length
    }
}

function Get-FileADS {
    <#
    .SYNOPSIS
        Scans files for alternate data streams.
    #>
    param([string]$scanPath, [bool]$recursive)

    Write-Host "[*] Scanning for ADS in: $scanPath" -ForegroundColor Cyan
    
    $results = @()

    try {
        $files = if ($recursive) { 
            Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue 
        } else { 
            Get-ChildItem -Path $scanPath -File -ErrorAction SilentlyContinue 
        }

        $fileCount = 0
        $streamCount = 0

        foreach ($f in $files) {
            $fileCount++
            
            if ($fileCount % 100 -eq 0) {
                Write-Progress -Activity "Scanning files" -Status "$fileCount files processed" `
                              -PercentComplete (($fileCount / $files.Count) * 100)
            }

            try {
                $streams = Get-Item -Path $f.FullName -Stream * -ErrorAction Stop
            } catch {
                continue
            }

            foreach ($s in $streams) {
                # Skip primary data stream
                if ($s.Stream -eq ':$DATA') { continue }
                
                $streamCount++
                $info = Get-StreamNameInfo -streamName $s.Stream

                # Apply filter if requested
                if ($ShowOnlyNonPrintable -and $info.IsPrintable) {
                    continue
                }

                $result = [PSCustomObject]@{
                    File = $f.FullName
                    StreamName = $info.StreamRaw
                    StreamSize = $s.Length
                    Codepoints = $info.StreamEscaped
                    Bytes = $info.Bytes
                    IsPrintable = $info.IsPrintable
                    ContainsZeroWidth = $info.ContainsZeroWidth
                    ContainsBidi = $info.ContainsBidi
                    StreamLength = $info.Length
                    FirstBytes = if ($s.Length -gt 0) {
                        try {
                            $content = Get-Content -Path "$($f.FullName):$($s.Stream)" -Raw -ErrorAction Stop
                            $content.Substring(0, [Math]::Min(100, $content.Length))
                        } catch {
                            "[Error reading stream]"
                        }
                    } else {
                        "[Empty stream]"
                    }
                }

                $results += $result

                # Highlight suspicious streams
                if ($info.ContainsZeroWidth) {
                    Write-Host "[!] ZERO-WIDTH DETECTED: $($f.FullName)" -ForegroundColor Red
                    Write-Host "    Stream: '$($s.Stream)' (appears blank)" -ForegroundColor Yellow
                    Write-Host "    Codepoints: $($info.StreamEscaped)" -ForegroundColor Yellow
                    Write-Host "    Size: $($s.Length) bytes" -ForegroundColor Yellow
                }
            }
        }

        Write-Progress -Activity "Scanning files" -Completed
        Write-Host "[+] Scan complete: $fileCount files, $streamCount ADS found" -ForegroundColor Green

    } catch {
        Write-Error "Scan failed: $_"
    }

    return $results
}

function Get-ScheduledTaskUnicode {
    <#
    .SYNOPSIS
        Scans scheduled task names for zero-width Unicode characters.
    #>
    
    Write-Host "[*] Scanning scheduled tasks for Unicode anomalies..." -ForegroundColor Cyan
    
    $results = @()

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop

        foreach ($task in $tasks) {
            $taskName = $task.TaskName
            $info = Get-StreamNameInfo -streamName $taskName

            if ($info.ContainsZeroWidth -or $info.ContainsBidi) {
                $result = [PSCustomObject]@{
                    TaskName = $taskName
                    TaskPath = $task.TaskPath
                    State = $task.State
                    Codepoints = $info.StreamEscaped
                    ContainsZeroWidth = $info.ContainsZeroWidth
                    ContainsBidi = $info.ContainsBidi
                    Actions = ($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
                }

                $results += $result

                Write-Host "[!] SUSPICIOUS TASK: $taskName" -ForegroundColor Red
                Write-Host "    Path: $($task.TaskPath)" -ForegroundColor Yellow
                Write-Host "    Codepoints: $($info.StreamEscaped)" -ForegroundColor Yellow
            }
        }

        if ($results.Count -eq 0) {
            Write-Host "[+] No suspicious scheduled tasks found" -ForegroundColor Green
        }

    } catch {
        Write-Error "Failed to scan scheduled tasks: $_"
    }

    return $results
}

function Get-RegistryUnicode {
    <#
    .SYNOPSIS
        Scans common registry persistence locations for zero-width characters.
    #>
    
    Write-Host "[*] Scanning registry for Unicode anomalies..." -ForegroundColor Cyan
    
    $results = @()

    # Common persistence locations
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    )

    foreach ($regPath in $regPaths) {
        try {
            if (-not (Test-Path $regPath)) { continue }

            $keys = Get-Item -Path $regPath -ErrorAction Stop
            
            foreach ($property in $keys.Property) {
                $info = Get-StreamNameInfo -streamName $property

                if ($info.ContainsZeroWidth -or $info.ContainsBidi) {
                    $value = Get-ItemProperty -Path $regPath -Name $property

                    $result = [PSCustomObject]@{
                        RegistryPath = $regPath
                        ValueName = $property
                        Codepoints = $info.StreamEscaped
                        ContainsZeroWidth = $info.ContainsZeroWidth
                        ContainsBidi = $info.ContainsBidi
                        Value = $value.$property
                    }

                    $results += $result

                    Write-Host "[!] SUSPICIOUS REGISTRY VALUE: $property" -ForegroundColor Red
                    Write-Host "    Path: $regPath" -ForegroundColor Yellow
                    Write-Host "    Codepoints: $($info.StreamEscaped)" -ForegroundColor Yellow
                }
            }

        } catch {
            # Silent continue for access denied
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "[+] No suspicious registry entries found" -ForegroundColor Green
    }

    return $results
}

# Main execution
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Zero-Width ADS Detection Tool - Blue Team Edition" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$allResults = @()

# Scan filesystem ADS
$adsResults = Get-FileADS -scanPath $Path -recursive $Recurse
$allResults += $adsResults

# Scan scheduled tasks if requested
if ($CheckScheduledTasks) {
    $taskResults = Get-ScheduledTaskUnicode
    if ($taskResults) {
        $allResults += $taskResults
    }
}

# Scan registry if requested
if ($CheckRegistry) {
    $regResults = Get-RegistryUnicode
    if ($regResults) {
        $allResults += $regResults
    }
}

# Display summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Scan Summary" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

$zwCount = ($allResults | Where-Object { $_.ContainsZeroWidth }).Count
$bidiCount = ($allResults | Where-Object { $_.ContainsBidi }).Count

Write-Host "Total items scanned: $($allResults.Count)" -ForegroundColor White
Write-Host "Items with zero-width chars: $zwCount" -ForegroundColor $(if ($zwCount -gt 0) { "Red" } else { "Green" })
Write-Host "Items with bidi controls: $bidiCount" -ForegroundColor $(if ($bidiCount -gt 0) { "Red" } else { "Green" })

# Export to CSV if requested
if ($ExportCSV) {
    try {
        $allResults | Export-Csv -Path $ExportCSV -NoTypeInformation -Force
        Write-Host ""
        Write-Host "[+] Results exported to: $ExportCSV" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
}

# Display detailed results
if ($allResults.Count -gt 0 -and -not $ExportCSV) {
    Write-Host ""
    Write-Host "Detailed Results:" -ForegroundColor Cyan
    $allResults | Format-Table -AutoSize
}

Write-Host ""
