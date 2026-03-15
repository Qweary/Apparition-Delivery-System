<#
.SYNOPSIS
    MEME-021: The Turing Test — generates a continuous stream of activity that is
    indistinguishable from legitimate system administration, forcing the AI blue team
    to either alert on everything (alert fatigue) or ignore it (missed detections)
.NOTES
    Session: SYSTEM OK — all operations use legitimate admin tools and APIs
    Time-limited: runs for 5 minutes then exits cleanly
    Anti-AI strategy: exploits the documented weakness that the AI blue team
    "cannot distinguish legitimate administrative activity from red team activity
    when the same tools and patterns are used." Every action here is something
    a real admin would do. None of it is malicious. But the AI can't be sure.
#>

$duration = 5 # minutes
$end = (Get-Date).AddMinutes($duration)
$actions = 0

Write-Output "Starting admin-lookalike activity for $duration minutes..."

while ((Get-Date) -lt $end) {
    $action = Get-Random -Max 15

    switch ($action) {
        # Legitimate service queries
        0 {
            Get-Service | Where-Object { $_.Status -eq 'Running' } | Out-Null
            $actions++
        }
        # Check scheduled tasks (exactly what an admin would do)
        1 {
            schtasks /query /fo LIST 2>$null | Out-Null
            $actions++
        }
        # Query firewall status (routine admin check)
        2 {
            netsh advfirewall show allprofiles state 2>$null | Out-Null
            $actions++
        }
        # List local administrators (security audit)
        3 {
            net localgroup Administrators 2>$null | Out-Null
            $actions++
        }
        # Check network connections (exactly what a defender would run)
        4 {
            netstat -ano 2>$null | Out-Null
            $actions++
        }
        # Query DNS (routine troubleshooting)
        5 {
            nslookup localhost 2>$null | Out-Null
            $actions++
        }
        # Check event logs (this is literally what the AI blue team does)
        6 {
            wevtutil qe Security /c:5 /rd:true /f:text 2>$null | Out-Null
            $actions++
        }
        # Query registry (configuration verification)
        7 {
            reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>$null | Out-Null
            $actions++
        }
        # WMI query (system inventory)
        8 {
            Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue | Out-Null
            $actions++
        }
        # Test network connectivity (routine health check)
        9 {
            Test-NetConnection -ComputerName localhost -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
            $actions++
        }
        # PowerShell remoting test (admin would verify this works)
        10 {
            Test-WSMan -ComputerName localhost -ErrorAction SilentlyContinue | Out-Null
            $actions++
        }
        # Disk space check (capacity planning)
        11 {
            Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | Out-Null
            $actions++
        }
        # Process listing (routine monitoring)
        12 {
            tasklist /v 2>$null | Out-Null
            $actions++
        }
        # Windows Update check (maintenance)
        13 {
            Get-HotFix -ErrorAction SilentlyContinue | Select-Object -First 5 | Out-Null
            $actions++
        }
        # System info (inventory/documentation)
        14 {
            hostname; whoami 2>$null | Out-Null
            $actions++
        }
    }

    # Randomized sleep between 3-15 seconds — realistic admin pacing
    Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 16)
}

Write-Output "Completed $actions admin-lookalike actions over $duration minutes."
Write-Output "Every single action was something a legitimate admin would do."
Write-Output "The AI blue team now has to decide: was this us, or was this IT?"
Write-Output "Spoiler: it was us. But the logs look identical either way."
