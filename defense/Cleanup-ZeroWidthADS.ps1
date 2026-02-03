<#
.SYNOPSIS
    Cleanup-ZeroWidthADS.ps1 - Safe removal tool for zero-width ADS.

.DESCRIPTION
    Authorized cleanup tool for removing Alternate Data Streams identified
    by exact byte sequences. Requires explicit confirmation and supports
    -WhatIf for dry-run testing.

    SAFETY FEATURES:
    - Requires exact byte sequence (no wildcards)
    - Supports -WhatIf for testing
    - Requires confirmation before deletion
    - Logs all operations
    - Creates backup option

.PARAMETER File
    Full path to the file containing the ADS to remove.

.PARAMETER StreamBytes
    Space-separated byte sequence identifying the stream name.
    Format: "0xFF 0xFE 0x20 0x00" or "0x200B 0x00"

.PARAMETER WhatIf
    Shows what would be deleted without actually performing deletion.

.PARAMETER Force
    Skip confirmation prompt (use with extreme caution).

.PARAMETER CreateBackup
    Create a copy of the file before removing streams.

.PARAMETER LogPath
    Path to log file for cleanup operations.

.EXAMPLE
    .\Cleanup-ZeroWidthADS.ps1 -File "C:\ProgramData\system.dll" `
        -StreamBytes "0x0B 0x20 0x00 0x00" -WhatIf

.EXAMPLE
    .\Cleanup-ZeroWidthADS.ps1 -File "C:\Temp\suspicious.txt" `
        -StreamBytes "0xFE 0xFF" -CreateBackup -LogPath "C:\IR\cleanup.log"

.NOTES
    Author: Blue Team / ChatGPT Contribution
    Version: 1.0.0
    Purpose: Authorized remediation only
    
    CRITICAL: Only use with proper authorization and incident response procedures
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$File,

    [Parameter(Mandatory=$true)]
    [string]$StreamBytes,

    [switch]$Force,

    [switch]$CreateBackup,

    [string]$LogPath = "$env:TEMP\ADS-Cleanup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

function Write-CleanupLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARN" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
    
    $logEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function ConvertFrom-ByteString {
    <#
    .SYNOPSIS
        Converts a byte string to actual stream name.
    #>
    param([string]$bytes)
    
    try {
        # Parse bytes: "0xFF 0xFE" or "FF FE" or "0xFF,0xFE"
        $byteArray = $bytes -split '[\s,]+' | ForEach-Object { 
            $cleaned = $_ -replace '^0x', ''
            [Convert]::ToByte($cleaned, 16) 
        }
        
        $streamName = [System.Text.Encoding]::Unicode.GetString($byteArray)
        return $streamName
        
    } catch {
        throw "Invalid byte sequence: $_"
    }
}

function Get-StreamInfo {
    param([string]$filePath, [string]$streamName)
    
    try {
        $fullPath = "$filePath`:$streamName"
        $stream = Get-Item -LiteralPath $fullPath -Stream $streamName -ErrorAction Stop
        
        # Get codepoints for display
        $chars = $streamName.ToCharArray()
        $codepoints = ($chars | ForEach-Object { "U+{0:X4}" -f [int]$_ }) -join ' '
        
        return [PSCustomObject]@{
            FilePath = $filePath
            StreamName = $streamName
            Codepoints = $codepoints
            Size = $stream.Length
            FullPath = $fullPath
        }
        
    } catch {
        return $null
    }
}

function Backup-FileWithStreams {
    param([string]$filePath)
    
    try {
        $backupPath = "$filePath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        
        # Use robocopy to preserve ADS
        $result = & robocopy $(Split-Path $filePath) $(Split-Path $backupPath) `
                    $(Split-Path $filePath -Leaf) /COPY:DATSOU /R:1 /W:1 2>&1
        
        if (Test-Path $backupPath) {
            Write-CleanupLog "Backup created: $backupPath" "SUCCESS"
            return $backupPath
        } else {
            Write-CleanupLog "Backup failed" "ERROR"
            return $null
        }
        
    } catch {
        Write-CleanupLog "Backup error: $_" "ERROR"
        return $null
    }
}

# Main execution
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Zero-Width ADS Cleanup Tool - Authorized Use Only" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-CleanupLog "Cleanup operation initiated"
Write-CleanupLog "Target file: $File"
Write-CleanupLog "Operator: $env:USERNAME @ $env:COMPUTERNAME"

# Convert byte sequence to stream name
try {
    $streamName = ConvertFrom-ByteString -bytes $StreamBytes
    Write-CleanupLog "Resolved stream from bytes: $StreamBytes"
} catch {
    Write-CleanupLog "Invalid byte sequence: $_" "ERROR"
    Write-Error "Failed to parse byte sequence. Use format: '0xFF 0xFE 0x20 0x00'"
    exit 1
}

# Get stream information
$streamInfo = Get-StreamInfo -filePath $File -streamName $streamName

if (-not $streamInfo) {
    Write-CleanupLog "Stream not found on target file" "WARN"
    Write-Warning "No stream matching the byte sequence was found on $File"
    Write-Host ""
    Write-Host "Existing streams on file:" -ForegroundColor Yellow
    Get-Item -Path $File -Stream * | ForEach-Object {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($_.Stream)
        $byteStr = ($bytes | ForEach-Object { "0x{0:X2}" -f $_ }) -join ' '
        Write-Host "  Stream: '$($_.Stream)' | Bytes: $byteStr"
    }
    exit 1
}

# Display what will be deleted
Write-Host ""
Write-Host "Stream Details:" -ForegroundColor Cyan
Write-Host "  File: $($streamInfo.FilePath)" -ForegroundColor White
Write-Host "  Stream (visual): '$($streamInfo.StreamName)'" -ForegroundColor White
Write-Host "  Codepoints: $($streamInfo.Codepoints)" -ForegroundColor Yellow
Write-Host "  Bytes: $StreamBytes" -ForegroundColor Yellow
Write-Host "  Size: $($streamInfo.Size) bytes" -ForegroundColor White
Write-Host "  Full path: $($streamInfo.FullPath)" -ForegroundColor Gray
Write-Host ""

# Create backup if requested
if ($CreateBackup) {
    Write-Host "Creating backup..." -ForegroundColor Cyan
    $backupPath = Backup-FileWithStreams -filePath $File
    
    if (-not $backupPath) {
        Write-Error "Backup failed. Aborting cleanup for safety."
        exit 1
    }
}

# Confirmation
if (-not $Force -and -not $WhatIfPreference) {
    Write-Host "WARNING: This will permanently delete the ADS." -ForegroundColor Red
    Write-Host "Type 'DELETE' to confirm, or anything else to abort:" -ForegroundColor Yellow
    $confirmation = Read-Host
    
    if ($confirmation -ne 'DELETE') {
        Write-CleanupLog "Operation aborted by user" "WARN"
        Write-Host "Aborted by operator." -ForegroundColor Yellow
        exit 0
    }
}

# Perform deletion
if ($PSCmdlet.ShouldProcess($streamInfo.FullPath, "Remove ADS")) {
    try {
        Remove-Item -LiteralPath $streamInfo.FullPath -Force -ErrorAction Stop
        
        Write-CleanupLog "Successfully removed stream: $($streamInfo.Codepoints)" "SUCCESS"
        Write-Host ""
        Write-Host "[+] Stream removed successfully" -ForegroundColor Green
        
        # Verify deletion
        $verify = Get-StreamInfo -filePath $File -streamName $streamName
        if ($verify) {
            Write-CleanupLog "Verification failed - stream still exists" "ERROR"
            Write-Warning "Stream still detected after deletion. Manual investigation required."
        } else {
            Write-CleanupLog "Deletion verified - stream no longer exists" "SUCCESS"
        }
        
    } catch {
        Write-CleanupLog "Deletion failed: $_" "ERROR"
        Write-Error "Failed to remove stream: $_"
        exit 1
    }
} else {
    Write-CleanupLog "WhatIf mode - no changes made" "INFO"
    Write-Host "[WhatIf] Would delete: $($streamInfo.FullPath)" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Log saved to: $LogPath" -ForegroundColor Cyan
Write-Host ""
