Blue Team Guide: Detecting and Responding to Zero-Width ADS
===========================================================

Target Audience: SOC Analysts, Incident Responders, Threat Hunters, Security Engineers\
Difficulty: Intermediate to Advanced\
Tools Required: PowerShell, Sysmon, SIEM (Splunk/Sentinel/ELK)

* * * * *

Executive Summary
-----------------

Zero-width Unicode characters in NTFS Alternate Data Stream (ADS) names create visually invisible persistence mechanisms that evade traditional detection methods. This guide provides comprehensive detection, analysis, and remediation procedures.

Key Takeaways:

-   👁️ Zero-width streams appear blank in standard tools

-   🔍 Requires byte-level enumeration to detect

-   ⚡ Sysmon Event ID 15 is your primary detection signal

-   🛠️ Specialized scripts needed for cleanup

* * * * *

Table of Contents
-----------------

1.  Threat Overview

2.  Detection Methods

3.  Analysis Procedures

4.  Incident Response Playbook

5.  SIEM Rules & Queries

6.  Forensic Artifacts

7.  Hardening Recommendations

* * * * *

Threat Overview
---------------

### What Are Zero-Width ADS?

Normal ADS:

C:\ProgramData\file.dll:visible_stream

Zero-Width ADS:

C:\ProgramData\file.dll:[blank - U+200B]

### Known Zero-Width Characters

```
Codepoint            Name                Hex Bytes(UTF-16LE)          Detection Pattern
U+061C        Arabic Letter Mark            1C 06 00 00                   \x1C\x06
U+200B        Zero Width Space              0B 20 00 00                   \x0B\x20
U+200D        Zero Width Joiner             0D 20 00 00                   \x0D\x20
U+202E        RTL Override                  2E 20 00 00                   \x2E\x20
U+FEFF        Zero Width No-Break           FF FE 00 00                   \xFF\xFE
```

Full List: 14 verified characters (see Integration Notes)

### Attack Chain

[Initial Access] → [Payload Download] → [Zero-Width ADS Creation] → [Scheduled Task Persistence] → [Execution]

       ↓                    ↓                       ↓                           ↓                    ↓

   Phishing           PowerShell             Invisible Stream           Hidden Task Name      C2 Beacon

### MITRE ATT&CK Mapping

-   T1564.004: Hide Artifacts - NTFS File Attributes

-   T1053.005: Scheduled Task/Job - Scheduled Task

-   T1059.001: Command and Scripting Interpreter - PowerShell

* * * * *

Detection Methods
-----------------

### Method 1: Sysmon Event ID 15 (Primary Detection)

Why This Works: Sysmon Event ID 15 (FileCreateStreamHash) logs all ADS creation, including zero-width.

#### Configuration

Sysmon Config (sysmonconfig.xml):

<Sysmon schemaversion="4.82">

  <EventFiltering>

    <FileCreateStreamHash onmatch="include">

      <!-- Monitor high-risk directories -->

      <TargetFilename condition="contains">C:\ProgramData</TargetFilename>

      <TargetFilename condition="contains">C:\Windows\Temp</TargetFilename>

      <TargetFilename condition="contains">C:\Users</TargetFilename>

      <TargetFilename condition="contains">C:\Windows\System32</TargetFilename>

    </FileCreateStreamHash>

  </EventFiltering>

</Sysmon>

#### Example Event

<Event>

  <System>

    <EventID>15</EventID>

    <Computer>WORKSTATION01</Computer>

  </System>

  <EventData>

    <Data Name="UtcTime">2025-01-29 14:30:45.123</Data>

    <Data Name="ProcessGuid">{12345678-ABCD-...}</Data>

    <Data Name="ProcessId">4567</Data>

    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>

    <Data Name="TargetFilename">C:\ProgramData\SystemCache.dat:[blank appears here]</Data>

    <Data Name="CreationUtcTime">2025-01-29 14:30:45.120</Data>

    <Data Name="Hash">SHA256=A3F5B2C1D4E6F7...</Data>

  </EventData>

</Event>

Indicators of Compromise:

-   ✅ TargetFilename ends with : followed by blank or unusual chars

-   ✅ Image is PowerShell or suspicious process

-   ✅ Hash shows suspicious payload signature

-   ✅ Directory is ProgramData, Temp, or unusual location

#### Detection Query (Windows Event Viewer)

<QueryList>

  <Query Id="0">

    <Select Path="Microsoft-Windows-Sysmon/Operational">

      *[System[(EventID=15)]]

      and

      *[EventData[Data[@Name='TargetFilename'] and (contains(., 'ProgramData') or contains(., 'Temp'))]]

    </Select>

  </Query>

</QueryList>

* * * * *

### Method 2: PowerShell Byte-Level Enumeration

Script: Detect-ZeroWidthADS.ps1

Located in /defense directory. See tool documentation below.

Manual One-Liner:

Get-ChildItem C:\ProgramData -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {

    $file = $_.FullName

    Get-Item $file -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' } | ForEach-Object {

        $bytes = [System.Text.Encoding]::Unicode.GetBytes($_.Stream)

        $hex = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '

        if ($hex -match '(0B 20|0D 20|FF FE|1C 06|2E 20)') {

            [PSCustomObject]@{

                File = $file

                Stream = $_.Stream

                Bytes = $hex

                Size = $_.Length

            }

        }

    }

}

Output:

File                              Stream  Bytes               Size

----                              ------  -----               ----

C:\ProgramData\SystemCache.dat    [blank] 0B 20 00 00         1024

C:\ProgramData\CacheSvc.log       [blank] 2E 20 00 00          512

* * * * *

### Method 3: Scheduled Task Monitoring

Zero-width characters can also appear in task names.

#### Event ID 4698 (Task Created)

Query:

Get-WinEvent -LogName Security | Where-Object {

    $_.Id -eq 4698 -and

    $_.TimeCreated -gt (Get-Date).AddDays(-7)

} | ForEach-Object {

    $xml = [xml]$_.ToXml()

    $taskName = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TaskName' } | Select-Object -ExpandProperty '#text'

    $taskContent = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TaskContent' } | Select-Object -ExpandProperty '#text'

    # Check task name for non-printable characters

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($taskName)

    $hasZeroWidth = $false

    foreach ($b in $bytes) {

        if ($b -eq 0x0B -or $b -eq 0x0D -or $b -eq 0xFF -or $b -eq 0x1C -or $b -eq 0x2E) {

            $hasZeroWidth = $true

            break

        }

    }

    if ($hasZeroWidth -or $taskContent -match 'wscript.*//B|powershell.*Hidden') {

        [PSCustomObject]@{

            Time = $_.TimeCreated

            TaskName = $taskName

            TaskNameBytes = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '

            Suspicious = $true

        }

    }

}

Suspicious Patterns:

-   Task names with zero-width bytes

-   Task actions: wscript.exe //B, powershell.exe -WindowStyle Hidden

-   Run levels: SYSTEM or Highest

-   Triggers: Logon, system startup

* * * * *

### Method 4: Registry Persistence Locations

Check common Run keys for zero-width value names:

$regPaths = @(

    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',

    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',

    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',

    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'

)

foreach ($path in $regPaths) {

    if (Test-Path $path) {

        $keys = Get-Item $path

        foreach ($prop in $keys.Property) {

            $bytes = [System.Text.Encoding]::Unicode.GetBytes($prop)

            $hex = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '

            if ($hex -match '(0B 20|0D 20|FF FE)') {

                Write-Warning "Suspicious registry value: $path\$prop"

                Write-Host "Bytes: $hex"

            }

        }

    }

}

* * * * *

Analysis Procedures
-------------------

### Triage Checklist

When zero-width ADS detected:

1.  Isolation

-   [ ] Isolate affected system from network (if active threat)

-   [ ] Prevent scheduled task execution (Disable-ScheduledTask)

-   [ ] Document current state (screenshots, logs)

3.  Evidence Collection

-   [ ] Export Sysmon logs (Event ID 15, 1, 3)

-   [ ] Export Security logs (Event ID 4698, 4688)

-   [ ] Capture ADS byte dump (see script below)

-   [ ] Memory dump (if C2 activity suspected)

5.  Initial Analysis

-   [ ] Identify all files with zero-width ADS

-   [ ] Check for manifest files (see locations below)

-   [ ] Enumerate scheduled tasks and registry entries

-   [ ] Timeline correlation (when was ADS created vs. initial access?)

### Evidence Collection Script

# Create evidence directory

$evidenceDir = "C:\IR\Evidence-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

New-Item -Path $evidenceDir -ItemType Directory -Force

# 1. Export ADS enumeration

.\defense\Detect-ZeroWidthADS.ps1 -Path C:\ -Recurse -ExportCSV "$evidenceDir\ads-scan.csv"

# 2. Export Sysmon logs

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 | 

    Where-Object { $_.Id -in @(1, 3, 15) } | 

    Export-Clixml -Path "$evidenceDir\sysmon-events.xml"

# 3. Export scheduled tasks

Get-ScheduledTask | Export-Clixml -Path "$evidenceDir\scheduled-tasks.xml"

# 4. Capture specific ADS content (requires manual input of file path)

$suspiciousFile = Read-Host "Enter path to suspicious file"

$streams = Get-Item $suspiciousFile -Stream *

foreach ($stream in $streams) {

    if ($stream.Stream -ne ':$DATA') {

        $bytes = [System.Text.Encoding]::Unicode.GetBytes($stream.Stream)

        $hex = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '

        $content = Get-Content "$suspiciousFile`:$($stream.Stream)" -Raw -ErrorAction SilentlyContinue

        [PSCustomObject]@{

            File = $suspiciousFile

            Stream = $stream.Stream

            StreamBytes = $hex

            Size = $stream.Length

            Content = $content

        } | Export-Clixml -Path "$evidenceDir\stream-$($stream.Stream -replace '[^\w]','_').xml"

    }

}

Write-Host "Evidence collected in: $evidenceDir"

### Manifest File Locations

If using Apparition Delivery System, attacker may have left manifest:

File-Based:

-   %APPDATA%\Microsoft\Windows\Themes\slideshow.dat

-   Attributes: Hidden, System

-   Format: AES-256 encrypted JSON

Registry-Based:

-   HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced

-   Value: TaskbarAnimations

-   Format: Base64(AES-256(JSON))

Check for Manifest:

# File

$manifestFile = "$env:APPDATA\Microsoft\Windows\Themes\slideshow.dat"

if (Test-Path $manifestFile) {

    Write-Warning "Manifest file found: $manifestFile"

    Get-Content $manifestFile | Out-File "$evidenceDir\manifest-encrypted.txt"

}

# Registry

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

$value = Get-ItemProperty -Path $regPath -Name "TaskbarAnimations" -ErrorAction SilentlyContinue

if ($value) {

    Write-Warning "Potential manifest in registry"

    $value.TaskbarAnimations | Out-File "$evidenceDir\manifest-registry.txt"

}

Note: Manifests are encrypted with host-specific key. Decryption requires attacker's key derivation logic.

* * * * *

Incident Response Playbook
--------------------------

### Phase 1: Detection & Validation

Objective: Confirm zero-width ADS presence and scope

Actions:

1.  Run Detect-ZeroWidthADS.ps1 on suspected systems

2.  Correlate with Sysmon Event ID 15

3.  Identify all affected files and hosts

Decision Point: Is this active C2 or dormant persistence?

-   Active: Proceed to Phase 2 (Containment)

-   Dormant: Proceed to Phase 3 (Eradication) with monitoring

* * * * *

### Phase 2: Containment

Objective: Prevent spread and C2 communication

Actions:

Network Isolation (if C2 detected)

Disable-NetAdapter -Name "Ethernet" -Confirm:$false

1.

Disable Scheduled Tasks

Get-ScheduledTask | Where-Object { $_.TaskName -match 'Suspicious|Pattern' } | Disable-ScheduledTask

1.

2.  Block Outbound C2

-   Add firewall rules for known C2 domains/IPs

-   Monitor DNS logs for suspicious queries

4.  Preserve Evidence

-   Memory dump (DumpIt, FTK Imager)

-   Disk snapshot (if VM)

* * * * *

### Phase 3: Eradication

Objective: Remove all artifacts safely

Procedure:

Backup Before Removal

.\defense\Cleanup-ZeroWidthADS.ps1 -File "C:\ProgramData\file.dll" -StreamBytes "0x0B 0x20" -CreateBackup -WhatIf

1.

Remove ADS (after backup)

.\defense\Cleanup-ZeroWidthADS.ps1 -File "C:\ProgramData\file.dll" -StreamBytes "0x0B 0x20" -Force

1.

Remove Scheduled Tasks

Unregister-ScheduledTask -TaskName "SuspiciousTask" -Confirm:$false

1.

Clean Registry

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SuspiciousValue"

1.

Remove Manifest Files

Remove-Item "$env:APPDATA\Microsoft\Windows\Themes\slideshow.dat" -Force

Remove-ItemProperty -Path "HKCU:\...\Explorer\Advanced" -Name "TaskbarAnimations"

1.

* * * * *

### Phase 4: Recovery & Verification

Objective: Restore normal operations and verify cleanup

Actions:

Verify Removal

.\defense\Detect-ZeroWidthADS.ps1 -Path C:\ -Recurse -ShowOnlyNonPrintable

# Should return no results

1.

Restore Network

Enable-NetAdapter -Name "Ethernet"

1.

2.  Monitor for Re-Infection

-   Watch Sysmon Event ID 15 for 48 hours

-   Check for new scheduled tasks

-   Review outbound connections

4.  Root Cause Analysis

-   How did initial access occur?

-   What vulnerability was exploited?

-   Was multi-factor authentication bypassed?

* * * * *

SIEM Rules & Queries
--------------------

### Splunk

Rule 1: Zero-Width ADS Creation

index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=15

| regex TargetFilename=".*:([\x00-\x1F]|\x7F|\u200B|\u200D|\uFEFF)"

| eval stream_name=mvindex(split(TargetFilename, ":"), -1)

| eval stream_bytes=tostring(stream_name, "hex")

| where match(stream_bytes, "0b20|0d20|fffe|1c06|2e20")

| stats count by Computer, TargetFilename, Image, Hash

| where count > 0

Rule 2: Suspicious Scheduled Task

index=windows sourcetype="WinEventLog:Security" EventCode=4698

| rex field=TaskContent "<Exec>.*<Command>(?<cmd>.*)</Command>"

| where match(cmd, "wscript.*//B") OR match(cmd, "powershell.*Hidden")

| table _time, Computer, TaskName, cmd

* * * * *

### Microsoft Sentinel (KQL)

Rule 1: Zero-Width ADS Detection

Sysmon

| where EventID == 15

| extend StreamName = split(TargetFilename, ":")[-1]

| extend StreamBytes = bin2hex(tobinary(StreamName))

| where StreamBytes matches regex "0b20|0d20|fffe"

| project TimeGenerated, Computer, Image, TargetFilename, StreamBytes, Hash

Rule 2: PowerShell ADS Access

Sysmon

| where EventID == 1 and Image endswith "powershell.exe"

| where CommandLine contains "Get-Content" and CommandLine contains ":"

| extend FilePath = extract(@"Get-Content\s+([^\s:]+):([^\s]+)", 1, CommandLine)

| extend StreamName = extract(@"Get-Content\s+([^\s:]+):([^\s]+)", 2, CommandLine)

| where isnotempty(StreamName)

| project TimeGenerated, Computer, CommandLine, FilePath, StreamName

* * * * *

### ELK Stack (Elasticsearch)

Query:

{

  "query": {

    "bool": {

      "must": [

        { "match": { "event.code": "15" }},

        { "match": { "event.provider": "Microsoft-Windows-Sysmon" }}

      ],

      "filter": [

        {

          "regexp": {

            "file.path": ".*:[\x00-\x1F\x7F\u200B\u200D\uFEFF].*"

          }

        }

      ]

    }

  }

}

* * * * *

Forensic Artifacts
------------------

### Timeline of Artifacts

```
Time Offset                    Artifact                    Location                    Description
T-0 (Initial Access)           Phishing email              Exchange logs               User opens malicious attachment
T+5min                         PowerShell execution        Sysmon Event ID 1           Downloads payload
T+6min                         ADS creation                Sysmon Event ID 15          Zero-width stream created
T+7min                         Task creation               Security Event 4698         Persistence via task
T+10min                        Manifest storage            File/Registry               Encrypted manifest saved
T+Reboot                       Task execution              Sysmon Event ID 1           Payload runs from ADS
```

### Disk Forensics

MFT Analysis:

-   ADS stored in $DATA attribute of MFT record

-   Stream name in Unicode (UTF-16LE)

-   Look for multiple $DATA attributes on single file

Tools:

-   MFTExplorer (Eric Zimmerman)

-   Autopsy with NTFS parser

-   FTK Imager

Sample MFT Record:

File: C:\ProgramData\SystemCache.dat

$DATA (primary): 0 bytes

$DATA :0x200B: 1024 bytes  <-- Zero-width stream

$DATA :Zone.Identifier: 512 bytes

* * * * *

Hardening Recommendations
-------------------------

### Preventative Controls

1.  Application Whitelisting (AppLocker/WDAC)

-   Block unsigned PowerShell scripts in user directories

-   Require code signing for scheduled tasks

3.  Sysmon Deployment

-   Deploy to all endpoints

-   Monitor Event ID 15 with alerting

5.  Scheduled Task Hardening

-   GPO: Require admin approval for task creation

-   Monitor: Alert on all task creations

7.  PowerShell Logging

-   Enable ScriptBlock Logging

-   Enable Module Logging

-   Enable Transcription

### Detective Controls

1.  Continuous Monitoring

-   SIEM rules for Sysmon Event ID 15

-   Scheduled task creation alerts

-   Anomalous PowerShell usage

3.  Threat Hunting

-   Weekly ADS scans on critical systems

-   Scheduled task reviews

-   Registry persistence checks

5.  User Awareness

-   Training on phishing

-   Reporting suspicious emails

* * * * *

Quick Reference Card
--------------------

### Detection Commands

# Quick scan for zero-width ADS

Get-ChildItem C:\ProgramData -Recurse | Get-Item -Stream * | Where {

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($_.Stream)

    ($bytes | Where { $_ -in @(0x0B, 0x0D, 0xFF, 0x1C, 0x2E) }).Count -gt 0

}

# Check scheduled tasks

Get-ScheduledTask | Where { $_.Actions.Execute -match 'wscript|powershell' }

# Check Sysmon

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=15]]" -MaxEvents 100

### Cleanup Commands

# List all ADS

.\defense\Detect-ZeroWidthADS.ps1 -Path C:\ -Recurse -ShowOnlyNonPrintable

# Remove specific ADS

.\defense\Cleanup-ZeroWidthADS.ps1 -File "C:\Path\file.txt" -StreamBytes "0x0B 0x20" -CreateBackup -Force

* * * * *

Resources
---------

### Tools

-   Detect-ZeroWidthADS.ps1 - /defense directory

-   Cleanup-ZeroWidthADS.ps1 - /defense directory

-   Sysmon - https://docs.microsoft.com/sysinternals/sysmon

-   MFTExplorer - https://ericzimmerman.github.io/

### Documentation

-   MITRE ATT&CK T1564.004 - https://attack.mitre.org/techniques/T1564/004/

-   Microsoft NTFS Streams - https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams

-   Apparition Research - https://qweary.github.io/
