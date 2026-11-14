<#
.SYNOPSIS
    This PowerShell script prevents printing over HTTP by setting
    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting to REG_DWORD 1
    (GPO equivalent: Internet Communication settings >> "Turn off printing over HTTP" = Enabled).
    It backs up the current state to C:\ProgramData\STIG\Backups before changing anything, then verifies the fix.
    Exit codes: 0 = Remediated/already compliant, 1 = Still open, 2 = Error.

.NOTES
    Author          : <Your Name>
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2026-11-14
    Last Modified   : 2026-11-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000110
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-CC-000110/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11 Pro 26H2 x64 (Gen2)
    PowerShell Ver. : 

.USAGE
    Run from an elevated PowerShell prompt. No reboot required.
    If the device is domain-joined, a conflicting domain GPO will overwrite this value at the next refresh.
    Rollback: reg import "<backup .reg file>", or if the value did not exist before:
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name DisableHTTPPrinting
    Example syntax:
    PS C:\> .\WN11-CC-000110_Remediate.ps1
#>

[CmdletBinding()]
param(
    [string]$BackupDir = "$env:ProgramData\STIG\Backups"
)

$StigId        = 'WN11-CC-000110'
$RegPath       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
$RegPathNative = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
$ValueName     = 'DisableHTTPPrinting'
$DesiredValue  = 1

# --- Admin check -------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "[$StigId] ERROR - This script must be run as Administrator."
    exit 2
}

try {
    # --- Current state ------------------------------------------------------
    $current = $null
    $currentKind = $null
    if (Test-Path -Path $RegPath) {
        $key = Get-Item -Path $RegPath
        if ($key.GetValueNames() -contains $ValueName) {
            $current     = $key.GetValue($ValueName)
            $currentKind = $key.GetValueKind($ValueName)
        }
    }

    if ($currentKind -eq 'DWord' -and $current -eq $DesiredValue) {
        Write-Output "[$StigId] Already compliant - '$ValueName' = $current. No changes made."
        exit 0
    }

    $stateText = if ($null -eq $current) { "'$ValueName' not set" } else { "'$ValueName' = $current ($currentKind)" }
    Write-Output "[$StigId] Current state: $stateText"

    # --- Backup -------------------------------------------------------------
    if (-not (Test-Path -Path $BackupDir)) {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (Test-Path -Path $RegPath) {
        $backupFile = Join-Path $BackupDir "${StigId}_$stamp.reg"
        & reg.exe export $RegPathNative $backupFile /y | Out-Null
        Write-Output "[$StigId] Backup saved: $backupFile"
    }
    else {
        $backupFile = Join-Path $BackupDir "${StigId}_$stamp.txt"
        "Key '$RegPathNative' did not exist before remediation on $(Get-Date). Rollback = delete the value/key." |
            Set-Content -Path $backupFile
        Write-Output "[$StigId] Key did not exist; rollback note saved: $backupFile"
    }

    # --- Remediate ----------------------------------------------------------
    if (-not (Test-Path -Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    # Remove first in case it exists with the wrong type (e.g. REG_SZ)
    if ($null -ne $currentKind -and $currentKind -ne 'DWord') {
        Remove-ItemProperty -Path $RegPath -Name $ValueName -Force
    }
    New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $DesiredValue -Force | Out-Null

    # --- Verify -------------------------------------------------------------
    $key    = Get-Item -Path $RegPath
    $after  = $key.GetValue($ValueName)
    $kind   = $key.GetValueKind($ValueName)

    if ($kind -eq 'DWord' -and $after -eq $DesiredValue) {
        Write-Output "[$StigId] REMEDIATED - '$ValueName' = $after (REG_DWORD, printing over HTTP disabled)."
        exit 0
    }
    else {
        Write-Output "[$StigId] STILL OPEN - '$ValueName' = $after ($kind) after remediation."
        exit 1
    }
}
catch {
    Write-Output "[$StigId] ERROR - $($_.Exception.Message)"
    exit 2
}
