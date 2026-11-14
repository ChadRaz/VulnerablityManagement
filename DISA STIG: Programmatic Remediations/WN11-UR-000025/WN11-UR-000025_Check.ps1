<#
.SYNOPSIS
    This PowerShell script checks that the "Allow log on locally" user right (SeInteractiveLogonRight)
    is assigned only to the Administrators (S-1-5-32-544) and Users (S-1-5-32-545) groups.
    Any other account or group holding the right is a finding.
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
    STIG-ID         : WN11-UR-000025
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-UR-000025/

.TESTED ON
    Date(s) Tested  : 2026-11-14
    Tested By       : Razin Abbas
    Systems Tested  : Windows 11 Pro 26H2 x64 (Gen2)
    PowerShell Ver. : 5.1

.USAGE
    Run from an elevated PowerShell prompt (secedit requires Administrator).
    Reads the effective local policy via "secedit /export /areas USER_RIGHTS".
    Example syntax:
    PS C:\> .\WN11-UR-000025_Check.ps1
#>

[CmdletBinding()]
param()

$StigId     = 'WN11-UR-000025'
$RightName  = 'SeInteractiveLogonRight'
$AllowedSids = @('S-1-5-32-544', 'S-1-5-32-545')   # Administrators, Users

function Resolve-ToSid([string]$Entry) {
    $e = $Entry.Trim()
    if ($e.StartsWith('*')) { return $e.Substring(1) }
    try   { return (New-Object System.Security.Principal.NTAccount($e)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $e }   # unresolvable name; return as-is so it is flagged
}

function Resolve-ToName([string]$Sid) {
    try   { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

# --- Admin check -------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "[$StigId] ERROR - This script must be run as Administrator."
    exit 2
}

$exportFile = Join-Path $env:TEMP "${StigId}_export_$([guid]::NewGuid().Guid).inf"

try {
    & secedit.exe /export /cfg $exportFile /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exportFile)) {
        throw "secedit /export failed (exit code $LASTEXITCODE)."
    }

    $line = Get-Content -Path $exportFile | Where-Object { $_ -match "^\s*$RightName\s*=" } | Select-Object -First 1

    if (-not $line) {
        Write-Output "[$StigId] NOT A FINDING - '$RightName' is not assigned to any account or group."
        exit 0
    }

    $assignedSids = ($line -split '=', 2)[1].Split(',') |
                    Where-Object { $_.Trim() } |
                    ForEach-Object { Resolve-ToSid $_ }

    $assignedNames = $assignedSids | ForEach-Object { Resolve-ToName $_ }
    Write-Output "[$StigId] Currently assigned: $($assignedNames -join ', ')"

    $unauthorized = $assignedSids | Where-Object { $AllowedSids -notcontains $_ }

    if ($unauthorized) {
        $names = $unauthorized | ForEach-Object { "$(Resolve-ToName $_) ($_)" }
        Write-Output "[$StigId] OPEN - Unauthorized account(s)/group(s) hold 'Allow log on locally': $($names -join ', ')"
        exit 1
    }

    Write-Output "[$StigId] NOT A FINDING - 'Allow log on locally' is limited to Administrators and/or Users."
    exit 0
}
catch {
    Write-Output "[$StigId] ERROR - $($_.Exception.Message)"
    exit 2
}
finally {
    Remove-Item -Path $exportFile -Force -ErrorAction SilentlyContinue
}
