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
