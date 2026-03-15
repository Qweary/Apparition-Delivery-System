<#
.SYNOPSIS
    MEME-020: Token Burn Garden — generates large, plausible-looking files across the
    filesystem that the AI blue team will spend tokens reading and analyzing
.NOTES
    Session: SYSTEM OK — file writes work from any session context
    No kill switch needed — fire-and-forget, files persist until deleted
    Anti-AI strategy: the AI will try to read and analyze these files for IoCs.
    Each file is large enough to consume significant tokens but contains no
    actionable intelligence. Quantity over quality — plant many, waste much.
    Generates ~2MB of decoy content across ~20 files
#>

function New-FakeLog {
    param([int]$Lines = 500)
    $users = @("SYSTEM","NT AUTHORITY\LOCAL SERVICE","Administrator","svchost","lsass","services","wininit","csrss","smss","dwm")
    $actions = @("Process started","Service control manager","Security policy applied","Group policy refresh","Certificate validation","DNS resolution","LDAP bind","Kerberos authentication","Registry key accessed","File system audit")
    $sources = @("Microsoft-Windows-Security-Auditing","Microsoft-Windows-Sysmon","Microsoft-Windows-PowerShell","Service Control Manager","Microsoft-Windows-TaskScheduler","Microsoft-Windows-DNS-Client","Microsoft-Windows-GroupPolicy")
    $pids = 400..8000
    $output = New-Object System.Text.StringBuilder
    $base = Get-Date -Format "yyyy-MM-dd"
    for ($i = 0; $i -lt $Lines; $i++) {
        $h = Get-Random -Min 8 -Max 18
        $m = Get-Random -Max 60
        $s = Get-Random -Max 60
        $ms = Get-Random -Max 999
        $ts = "$base $($h.ToString('D2')):$($m.ToString('D2')):$($s.ToString('D2')).$($ms.ToString('D3'))"
        $user = $users[(Get-Random -Max $users.Count)]
        $action = $actions[(Get-Random -Max $actions.Count)]
        $source = $sources[(Get-Random -Max $sources.Count)]
        $pid = $pids[(Get-Random -Max $pids.Count)]
        [void]$output.AppendLine("$ts | $source | PID:$pid | $user | $action | Status:Success | Details:Normal operation - no anomalies detected in security audit subsystem event correlation pipeline stage $i")
    }
    return $output.ToString()
}

function New-FakeConfig {
    param([int]$Entries = 200)
    $output = New-Object System.Text.StringBuilder
    [void]$output.AppendLine("# System Configuration Export")
    [void]$output.AppendLine("# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$output.AppendLine("# Classification: INTERNAL")
    [void]$output.AppendLine("")

    $sections = @("NetworkPolicy","FirewallRules","ServiceConfiguration","RegistryBaseline","UserAccountPolicy","AuditPolicy","CertificateStore","GroupPolicyObjects","ScheduledTaskBaseline","DefenderConfiguration")
    foreach ($section in $sections) {
        [void]$output.AppendLine("[$section]")
        for ($i = 0; $i -lt ($Entries / $sections.Count); $i++) {
            $key = "Setting_$($section)_$i"
            $val = [System.Guid]::NewGuid().ToString()
            [void]$output.AppendLine("$key = $val")
        }
        [void]$output.AppendLine("")
    }
    return $output.ToString()
}

function New-FakeNetworkCapture {
    param([int]$Lines = 300)
    $output = New-Object System.Text.StringBuilder
    [void]$output.AppendLine("# Network Connection Log - Baseline Capture")
    [void]$output.AppendLine("# All connections below are LEGITIMATE pre-competition traffic")
    [void]$output.AppendLine("Timestamp,SrcIP,SrcPort,DstIP,DstPort,Protocol,Status,Bytes")

    $srcIPs = @("10.0.1.10","10.0.1.11","10.0.2.20","10.0.2.21","10.0.3.30")
    $dstIPs = @("10.0.1.1","10.0.2.1","8.8.8.8","10.0.5.5","172.16.0.1","10.0.1.50","10.0.1.51")
    $ports = @(80,443,445,389,636,88,135,139,3389,5985,5986,8080,53,25,110)

    for ($i = 0; $i -lt $Lines; $i++) {
        $ts = "$(Get-Date -Format 'yyyy-MM-dd') $(Get-Random -Min 8 -Max 18):$(Get-Random -Max 60):$(Get-Random -Max 60)"
        $src = $srcIPs[(Get-Random -Max $srcIPs.Count)]
        $sp = Get-Random -Min 49152 -Max 65535
        $dst = $dstIPs[(Get-Random -Max $dstIPs.Count)]
        $dp = $ports[(Get-Random -Max $ports.Count)]
        $bytes = Get-Random -Min 64 -Max 65535
        [void]$output.AppendLine("$ts,$src,$sp,$dst,$dp,TCP,ESTABLISHED,$bytes")
    }
    return $output.ToString()
}

# Plant the garden
$gardenPaths = @(
    "$env:ProgramData\SystemAudit",
    "$env:ProgramData\DiagnosticLogs",
    "$env:ProgramData\NetworkBaseline",
    "C:\Windows\Temp\AuditExport"
)

$count = 0
foreach ($gp in $gardenPaths) {
    try {
        if (!(Test-Path $gp)) { New-Item -Path $gp -ItemType Directory -Force | Out-Null }
    } catch { continue }

    # Fake security logs (large)
    try {
        $log = New-FakeLog -Lines (Get-Random -Min 400 -Max 800)
        $log | Out-File (Join-Path $gp "security-audit-export.log") -Force -Encoding UTF8
        $count++
    } catch { }

    # Fake config exports
    try {
        $cfg = New-FakeConfig -Entries (Get-Random -Min 150 -Max 300)
        $cfg | Out-File (Join-Path $gp "system-config-baseline.ini") -Force -Encoding UTF8
        $count++
    } catch { }

    # Fake network captures
    try {
        $net = New-FakeNetworkCapture -Lines (Get-Random -Min 200 -Max 500)
        $net | Out-File (Join-Path $gp "network-connections-baseline.csv") -Force -Encoding UTF8
        $count++
    } catch { }

    # Fake PowerShell transcript (the AI will definitely read these)
    try {
        $transcript = @"
**********************
Windows PowerShell transcript start
Start time: $(Get-Date -Format 'yyyyMMddHHmmss')
Username: $(hostname)\Administrator
RunAs User: $(hostname)\Administrator
Configuration Name:
Machine: $(hostname)
Host Application: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process ID: $(Get-Random -Min 1000 -Max 9999)
PSVersion: 5.1.19041.1
**********************
PS C:\Users\Administrator> Get-Service | Where-Object Status -eq Running | Format-Table -Auto
PS C:\Users\Administrator> Get-NetFirewallProfile | Select Name, Enabled
PS C:\Users\Administrator> Get-ScheduledTask | Where-Object State -eq Ready | Format-Table TaskName, State -Auto
PS C:\Users\Administrator> Get-LocalGroupMember Administrators | Format-Table Name, ObjectClass -Auto
PS C:\Users\Administrator> Test-NetConnection -ComputerName DC01 -Port 445
PS C:\Users\Administrator> # Routine maintenance complete. All systems nominal.
PS C:\Users\Administrator> # No anomalies detected. Baseline verified.
**********************
Windows PowerShell transcript end
End time: $(Get-Date -Format 'yyyyMMddHHmmss')
**********************
"@
        $transcript | Out-File (Join-Path $gp "PowerShell_transcript.$(hostname).log") -Force -Encoding UTF8
        $count++
    } catch { }
}

Write-Output "Planted $count decoy analysis files across $($gardenPaths.Count) directories."
Write-Output "Estimated token cost to the AI blue team: several thousand per file."
