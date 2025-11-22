🧭 ATTACK_FLOW.md
ADS-Drop-System: Stage-by-Stage Attack Blueprint

This document outlines the ADS-Drop-System workflow for both Standard User and Administrator access levels. The overall objective is to execute the encrypted Stage 1 beacon (loaded from ADS) directly into memory and establish multi-layered persistence.


Stage 0: Initial Deployment & File Setup

Step	Action	              Access Level	Description	                                                                                                  Key Artifacts
0.1	  Initial Access	      CLI	          Gain an initial command-line shell (via SSH, WinRM, or exploit) on the target machine.	                      N/A
0.2  	Deploy Host & Loader	Both	        Create the target path (%APPDATA%\Local\Microsoft\CLR) and write the Stage 0 VBScript Loader                  (app_log_a.vbs).	app_log_a.vbs
0.3	  Create ADS Payload	  Both	        Write the raw, encrypted Stage 1 beacon (Base64-encoded) into the Alternate Data Stream of the host file.	    SystemCache.dat:syc_core
0.4	  Initial Execution	    Both	        Run the VBScript loader via the command line: wscript.exe //B %PATH%\app_log_a.vbs	                          N/A


Stage 1: Local Execution and Redundancy
This stage is handled by the VBScript's delegated, encoded PowerShell command.

Step	Action	              Description	                                                                                        Process/Target
1.1	  Persistence Set	      VBScript writes to HKCU\Software\Microsoft\Windows\CurrentVersion\Run.	                            Registry Key
1.2	  ADS Read & Decrypt	  PowerShell reads, decrypts, and prepares the Stage 1 shellcode in memory.	                          PowerShell
1.3	  Primary Injection	    Reflective DLL Injection of the beacon into a victim process.	                                      svchost.exe (as sycsc.exe)
1.4	  Secondary Injection	  Immediate, simultaneous reflective injection into a second victim process for instant redundancy.	  dllhost.exe (as svs.dll)


Stage 2 (Admin Only): Resilient Persistence
If the initial shell has Administrator or SYSTEM privileges, additional resilience is established.

Step	      Artifact Name	        Trigger/Mechanism	                                  Persistence Type
2.1	        KernelConsolidator	  Task Scheduler, runs On Logon of Any User.	        High-Efficacy Persistence
2.2	        ProcessMonitor	      Task Scheduler, runs every 5 minutes (as SYSTEM).	  Watchdog/Self-Healing
2.3	(Opt.)	WMI Permanent Event   Consumer watching for process stop events.	        Advanced Resilience


Stage 3 (Admin Only): Lateral Propagation
The primary beacon executes the Invoke-LateralDeploySyc function to spread the infection to remote hosts.

Step	Method	          Action	                                                                                                                Target   Hosts
3.1	  Invoke-Command	  Stage 0 files and ADS are written to C:\ProgramData\.	                                                                  Remote   Hosts
3.2	  schtasks.exe	    KernelConsolidator and ProcessMonitor tasks are created remotely using SYSTEM credentials.	                            Remote   Hosts
3.3	  WMI/CIM	          Initial execution of the VBScript loader using Start-Process to kick off the beacon deployment on the remote machine.	  Remote   Hosts
