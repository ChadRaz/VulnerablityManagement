<#
.SYNOPSIS
    This PowerShell script checks whether Windows apps are prevented from being activated by voice
    (HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoice = 2, Force Deny).
    Exit codes: 0 = Not a Finding, 1 = Open, 2 = Error.

.NOTES
    Author          : <Your Name>
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2026-11-14
    Last Modified   : 2026-11-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000366
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-CC-000366/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11 Pro 26H2 x64 (Gen2)
    PowerShell Ver. : 

.USAGE
    Run from an elevated PowerShell prompt.
    Example syntax:
    PS C:\> .\WN11-CC-000366_Check.ps1
#>

[CmdletBinding()]
param()

$StigId        = 'WN11-CC-000366'
$RegPath       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
$ValueName     = 'LetAppsActivateWithVoice'
$ExpectedValue = 2
$ExpectedKind  = 'DWord'

try {
    if (-not (Test-Path -Path $RegPath)) {
        Write-Output "[$StigId] OPEN - Registry key not found: $RegPath"
        exit 1
    }

    $key = Get-Item -Path $RegPath
    if ($key.GetValueNames() -notcontains $ValueName) {
        Write-Output "[$StigId] OPEN - Value '$ValueName' does not exist (expected $ExpectedValue)."
        exit 1
    }

    $actual = $key.GetValue($ValueName)
    $kind   = $key.GetValueKind($ValueName)

    if ($kind -ne $ExpectedKind) {
        Write-Output "[$StigId] OPEN - '$ValueName' is type $kind (expected REG_DWORD). Current value: $actual"
        exit 1
    }

    if ($actual -ne $ExpectedValue) {
        Write-Output "[$StigId] OPEN - '$ValueName' = $actual (expected $ExpectedValue = Force Deny)."
        exit 1
    }

    Write-Output "[$StigId] NOT A FINDING - '$ValueName' = $actual (REG_DWORD)."
    exit 0
}
catch {
    Write-Output "[$StigId] ERROR - $($_.Exception.Message)"
    exit 2
}
