<#
.SYNOPSIS
    This PowerShell script checks that the System event log maximum size is 32768 KB (32 MB) or greater
    (HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize >= 32768).
    N/A if the system sends audit records directly to an audit server (must be documented with the ISSO);
    this cannot be detected automatically, so the script always evaluates the registry value.
    Exit codes: 0 = Not a Finding, 1 = Open, 2 = Error.

.NOTES
    Author          : Razin Abbas
    LinkedIn        : https://www.linkedin.com/in/razin-abbas-9b582728a/
    GitHub          : https://github.com/ChadRaz
    Date Created    : 2026-11-14
    Last Modified   : 2026-11-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000510
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-AU-000510/

.TESTED ON
    Date(s) Tested  : 2026-11-14
    Tested By       : Razin Abbas
    Systems Tested  : Windows 11 Pro 26H2 x64 (Gen2)
    PowerShell Ver. : 5.1

.USAGE
    Run from an elevated PowerShell prompt.
    Example syntax:
    PS C:\> .\WN11-AU-000510_Check.ps1
#>

[CmdletBinding()]
param()

$StigId        = 'WN11-AU-000510'
$RegPath       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
$ValueName     = 'MaxSize'
$ExpectedValue = 32768
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

    if ($actual -lt $ExpectedValue) {
        Write-Output "[$StigId] OPEN - '$ValueName' = $actual (expected $ExpectedValue KB or greater)."
        exit 1
    }

    Write-Output "[$StigId] NOT A FINDING - '$ValueName' = $actual KB (REG_DWORD, minimum $ExpectedValue)."
    exit 0
}
catch {
    Write-Output "[$StigId] ERROR - $($_.Exception.Message)"
    exit 2
}
