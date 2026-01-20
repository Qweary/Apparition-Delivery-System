#### /docs/DETECTION.md
# Detection Research Findings

## Test Environment
- Windows 11 22H2
- Defender Real-Time Protection: Enabled
- Sysmon 15.0 with SwiftOnSecurity config

## Technique Visibility Matrix

| Storage Method | Dir /r | Streams.exe           | Defender | Sysmon  | Forensics |
|----------------|--------|-----------------------|----------|---------|-----------|
| Classic ADS    | ✅ Yes | ✅ Yes               | ⚠️ Maybe | ✅ Yes | ✅ Easy   |
| Volume Root    | ❌ No  | ⚠️ Requires /vol:C:\ | ❌ No    | ✅ Yes | ⚠️ Medium |
| NTFS Internal* | ❌ No  | ❌ No                | ❌ No    | ❌ No  | ⚠️ Hard   |

*Requires raw disk analysis tools

## Blue Team Recommendations
1. Enable Sysmon FileCreateStreamHash (Event ID 15)
2. Monitor task creation from non-admin users
3. Baseline legitimate ADS usage (Zone.Identifier, etc.)
4. Use PowerShell: `Get-Item -Stream *` in security scans

## CCDC Blue Team Detection Matrix (Sysmon/Defender/EDR)
```
1. SCHTASKS (T1053.005)
   Event ID 4698: TaskCreation
   Cmdline: schtasks /create /tn "Microsoft\Windows\UX\..." /tr "wscript.exe //B C:\...\app_log_*.vbs"
   MITRE: T1053.005"
   
2. WMI EVENT SUBSCRIPTION (T1546.003)
   Event ID 5861: WMICreatedEventConsumer
   Query: SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession'
   
3. ADS CREATION (T1564.004)
   Sysmon 11: FileCreate (stream names: :syc_payload, :$EA, :$OBJECT_ID)
   PowerShell: dir /r C:\ | findstr :syc  ← Blue team hunting
   
4. VBS Execution (T1059.005)
   Sysmon 1: ProcessCreate parent=wscript.exe child=powershell.exe
   Cmdline: powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass
   
5. PS1 Execution (fallback for AES)
   Sysmon 1: powershell.exe -File C:\...\app_log_*.ps1
   
6. Registry Run Key (T1547.001)
   RegEvent: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<GUID>
```
## Defender AMS Queries:
```
DeviceProcessEvents | where ProcessCommandLine contains "app_log_" or FolderPath contains "ProgramData\\Sys"
DeviceRegistryEvents | where RegistryKey contains "CurrentVersion\\Run" and ProcessCommandLine contains "wscript"
```
