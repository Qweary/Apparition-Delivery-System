📜 README.md
ADS-Drop-System: Stealthy Multi-Stage Persistence Framework

The ADS-Drop-System is a modular post-exploitation toolkit focusing on extreme evasiveness and redundancy. By utilizing NTFS Alternate Data Streams (ADS) for payload hiding and a custom VBScript/PowerShell loader chain, it ensures that C2 beacons are loaded directly into memory (svchost.exe/dllhost.exe) and are resilient against common defensive practices (e.g., clearing the %TEMP% directory or killing a single process).

Key Features:
    Payload Concealment: The true encrypted C2 beacon (Stage 1) is hidden within a benign system file's ADS stream (SystemCache.dat:syc_core).
    LOLBAS Execution Chain: Uses a VBScript loader (app_log_a.vbs) to invisibly launch an encoded PowerShell command, minimizing forensic artifacts.
    Dual-Beacon Redundancy: Injects the payload into two separate processes (svchost.exe and dllhost.exe) simultaneously for immediate failover.
    Self-Healing Persistence: Creates redundant persistence mechanisms via both HKCU\Run and a stealthy, SYSTEM-level Scheduled Task designed to run on user login and on a short interval (e.g., 5 minutes) to monitor and restart the beacon if terminated.
    Lateral Movement: Includes an Invoke-LateralDeploySyc PowerShell function for rapid, WMI/WinRM-based deployment across remote systems.
