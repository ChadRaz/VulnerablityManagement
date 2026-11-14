<#
.SYNOPSIS
    This PowerShell script sets the "Allow log on locally" user right (SeInteractiveLogonRight)
    to only the Administrators (S-1-5-32-544) and Users (S-1-5-32-545) groups.
    (GPO equivalent: Security Settings >> Local Policies >> User Rights Assignment >>
    "Allow log on locally" = Administrators, Users).
    It backs up the current user rights to C:\ProgramData\STIG\Backups before changing anything,
    then verifies the fix.
    Exit codes: 0 = Remediated/already compliant, 1 = Still open, 2 = Error.

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
    Run from an elevated PowerShell prompt. No reboot required; takes effect at the next logon.
    This does NOT affect RDP, which uses the separate "Allow log on through Remote Desktop Services" right.
    If the device is domain-joined, a domain GPO that sets this right will override the local policy.
    Rollback (restores the user rights saved in the backup file):
    secedit /configure /db "$env:TEMP\rollback.sdb" /cfg "<backup .inf file>" /areas USER_RIGHTS
    Example syntax:
    PS C:\> .\WN11-UR-000025_Remediate.ps1
#>

[CmdletBinding()]
param(
    [string]$BackupDir = "$env:ProgramData\STIG\Backups"
)

$StigId      = 'WN11-UR-000025'
$RightName   = 'SeInteractiveLogonRight'
$AllowedSids = @('S-1-5-32-544', 'S-1-5-32-545')   # Administrators, Users

function Resolve-ToSid([string]$Entry) {
    $e = $Entry.Trim()
    if ($e.StartsWith('*')) { return $e.Substring(1) }
    try   { return (New-Object System.Security.Principal.NTAccount($e)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $e }
}

function Resolve-ToName([string]$Sid) {
    try   { return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

function Get-AssignedSids([string]$InfPath) {
    $line = Get-Content -Path $InfPath | Where-Object { $_ -match "^\s*$RightName\s*=" } | Select-Object -First 1
    if (-not $line) { return @() }
    return @(($line -split '=', 2)[1].Split(',') | Where-Object { $_.Trim() } | ForEach-Object { Resolve-ToSid $_ })
}

# --- Admin check -------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "[$StigId] ERROR - This script must be run as Administrator."
    exit 2
}

$tag        = [guid]::NewGuid().Guid
$exportFile = Join-Path $env:TEMP "${StigId}_export_$tag.inf"
$applyFile  = Join-Path $env:TEMP "${StigId}_apply_$tag.inf"
$dbFile     = Join-Path $env:TEMP "${StigId}_$tag.sdb"
$verifyFile = Join-Path $env:TEMP "${StigId}_verify_$tag.inf"

try {
    # --- Current state --------------------------------------------------------
    & secedit.exe /export /cfg $exportFile /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exportFile)) {
        throw "secedit /export failed (exit code $LASTEXITCODE)."
    }

    $current = Get-AssignedSids $exportFile
    Write-Output "[$StigId] Currently assigned: $(if ($current) { ($current | ForEach-Object { Resolve-ToName $_ }) -join ', ' } else { '(none)' })"

    $unauthorized = $current | Where-Object { $AllowedSids -notcontains $_ }
    if (-not $unauthorized) {
        Write-Output "[$StigId] Already compliant - no unauthorized accounts hold 'Allow log on locally'. No changes made."
        exit 0
    }

    # --- Backup -------------------------------------------------------------
    if (-not (Test-Path -Path $BackupDir)) {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    }
    $stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFile = Join-Path $BackupDir "${StigId}_UserRights_$stamp.inf"
    Copy-Item -Path $exportFile -Destination $backupFile -Force
    Write-Output "[$StigId] Backup of all user rights saved: $backupFile"

    # --- Remediate ----------------------------------------------------------
    $sidList = ($AllowedSids | ForEach-Object { "*$_" }) -join ','
    $inf = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
'@
    $inf += "`r`n$RightName = $sidList`r`n"
    Set-Content -Path $applyFile -Value $inf -Encoding Unicode

    & secedit.exe /configure /db $dbFile /cfg $applyFile /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "secedit /configure failed (exit code $LASTEXITCODE). See %windir%\security\logs\scesrv.log"
    }

    # --- Verify -------------------------------------------------------------
    & secedit.exe /export /cfg $verifyFile /areas USER_RIGHTS /quiet | Out-Null
    $after = Get-AssignedSids $verifyFile
    $afterNames = ($after | ForEach-Object { Resolve-ToName $_ }) -join ', '
    $stillBad = $after | Where-Object { $AllowedSids -notcontains $_ }

    if (-not $stillBad) {
        Write-Output "[$StigId] REMEDIATED - 'Allow log on locally' = $afterNames"
        exit 0
    }
    else {
        Write-Output "[$StigId] STILL OPEN - 'Allow log on locally' = $afterNames (a domain GPO may be overriding local policy)."
        exit 1
    }
}
catch {
    Write-Output "[$StigId] ERROR - $($_.Exception.Message)"
    exit 2
}
finally {
    Remove-Item -Path $exportFile, $applyFile, $dbFile, $verifyFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$dbFile.jfm", ($dbFile -replace '\.sdb$', '.jfm') -Force -ErrorAction SilentlyContinue
}
