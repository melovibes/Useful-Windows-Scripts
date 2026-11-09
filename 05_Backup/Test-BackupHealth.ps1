<#
.SYNOPSIS
    Test-BackupHealth.ps1 - Check whether this PC could actually recover from a
    dead drive, a bad update or a deleted folder. Read-only.

.DESCRIPTION
    Looks at every common way a Windows 11 PC gets backed up and tells you, in
    plain English, what's covered, what's stale and what isn't protected at all.

    Checks:
      System Restore   On or off for the system drive, how many restore points,
                       and how old the newest one is (needs admin to count)
      File History     Turned on or not, where it backs up to, and when it last
                       finished
      OneDrive backup  Whether Desktop, Documents and Pictures are redirected
                       into OneDrive (folder backup), and whether OneDrive runs
      System images    Any WindowsImageBackup folder for this PC on a local or
                       USB drive, and its age
      Recovery         Whether the Windows Recovery Environment (WinRE) is
                       enabled (needs admin)
      BitLocker        If the system drive is encrypted, whether a recovery
                       password exists (you need it to restore a locked drive)
      Your backup      With -BackupPath: whether that folder or share is
                       reachable, its free space and how recently anything in it
                       was written (works with Backup-Folders.ps1 output)
      Unprotected      Size of your Desktop, Documents and Pictures that no
                       method above appears to cover

    Ends with Findings: each problem and what to do about it.

    Safety level : READ-ONLY. Changes nothing, starts no backups, makes no
                   network calls except reading -BackupPath if you give a share.
                   Only file written is the optional -CsvPath.
    Admin        : Optional. Without it, restore point count, WinRE and
                   BitLocker details show as "needs admin".

.PARAMETER BackupPath
    One or more backup destinations to check (drive folder or \\server\share).

.PARAMETER MaxAgeDays
    A backup older than this many days is flagged as stale (default 7).

.PARAMETER MaxScanFiles
    Most files to look at per -BackupPath when finding the newest one
    (default 50000) so huge backups stay quick.

.PARAMETER CsvPath
    Save every check and finding to a CSV file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\05_Backup\Test-BackupHealth.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\05_Backup\Test-BackupHealth.ps1 -BackupPath E:\Backups -MaxAgeDays 3 -CsvPath "$env:USERPROFILE\Desktop\backup-health.csv"
#>
[CmdletBinding()]
param(
    [string[]]$BackupPath,
    [ValidateRange(1, 3650)][int]$MaxAgeDays = 7,
    [ValidateRange(100, 10000000)][int]$MaxScanFiles = 50000,
    [string]$CsvPath
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$sysDrive = $env:SystemDrive
$now = Get-Date
$results = New-Object System.Collections.Generic.List[object]
$findings = New-Object System.Collections.Generic.List[object]
$covered = @{ OneDrive = @(); FileHistory = $false; Image = $false; Custom = $false }

function Add-Check([string]$Area, [string]$Item, [string]$Value, [string]$Status) {
    $results.Add([pscustomobject]@{ Type = 'Check'; Area = $Area; Item = $Item; Value = $Value; Status = $Status })
}
function Add-Finding([string]$Severity, [string]$Text, [string]$Fix) {
    $findings.Add([pscustomobject]@{ Severity = $Severity; Finding = $Text; Fix = $Fix })
}
function Format-Size([double]$Bytes) {
    if ($Bytes -ge 1TB) { '{0:N1} TB' -f ($Bytes / 1TB) }
    elseif ($Bytes -ge 1GB) { '{0:N1} GB' -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { '{0:N0} MB' -f ($Bytes / 1MB) }
    else { '{0:N0} KB' -f ($Bytes / 1KB) }
}
function Format-Age([datetime]$When) {
    $d = $now - $When
    if ($d.TotalDays -ge 1) { '{0:N0} days ago' -f [math]::Floor($d.TotalDays) }
    elseif ($d.TotalHours -ge 1) { '{0:N0} hours ago' -f [math]::Floor($d.TotalHours) }
    else { 'under an hour ago' }
}
function Get-FolderSize([string]$Path) {
    $sum = 0L
    try {
        Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::Offline) -and
                           -not ($_.Attributes -band 0x400000) } |   # skip cloud-only placeholders
            ForEach-Object { $sum += $_.Length }
    } catch { }
    $sum
}
function Write-Section([string]$Title) { Write-Host ''; Write-Host "== $Title ==" -ForegroundColor Cyan }

Write-Host "Backup health check for $env:COMPUTERNAME  ($($now.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor White
if (-not $isAdmin) { Write-Host 'Not running as admin: some details will show as "needs admin".' -ForegroundColor DarkYellow }

# ---------------------------------------------------------------- System Restore
Write-Section 'System Restore'
$srDisabled = $null
try {
    $srKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction Stop
    if ($srKey.PSObject.Properties['DisableSR']) { $srDisabled = [bool]$srKey.DisableSR }
} catch { }
$rp = $null
if ($isAdmin) {
    try { $rp = @(Get-CimInstance -Namespace root/default -ClassName SystemRestore -ErrorAction Stop) } catch { $rp = @() }
}
if ($srDisabled -eq $true) {
    Add-Check 'System Restore' 'Status' 'Off (turned off by policy or setting)' 'Problem'
    Add-Finding 'Medium' 'System Restore is turned off, so a bad driver or update can''t be rolled back.' "Search 'Create a restore point', select $sysDrive, Configure, Turn on system protection (3-5% is plenty)."
} elseif ($null -ne $rp) {
    if ($rp.Count -eq 0) {
        Add-Check 'System Restore' 'Restore points' 'None' 'Problem'
        Add-Finding 'Medium' "There are no restore points on $sysDrive, so System Restore is probably off for that drive." "Search 'Create a restore point', select $sysDrive, Configure, Turn on system protection, then click Create."
    } else {
        $newest = ($rp | ForEach-Object { [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime) } | Sort-Object -Descending)[0]
        $st = if (($now - $newest).TotalDays -gt 30) { 'Stale' } else { 'OK' }
        Add-Check 'System Restore' 'Restore points' "$($rp.Count), newest $(Format-Age $newest)" $st
        if ($st -eq 'Stale') { Add-Finding 'Low' "The newest restore point is $(Format-Age $newest)." "Create one now before big changes: search 'Create a restore point', click Create." }
    }
} else {
    Add-Check 'System Restore' 'Restore points' 'Needs admin to count' 'Unknown'
}
$results | Where-Object Area -eq 'System Restore' | ForEach-Object { Write-Host ("  {0,-16} {1}  [{2}]" -f $_.Item, $_.Value, $_.Status) }

# ---------------------------------------------------------------- File History
Write-Section 'File History'
$fhConfig = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\FileHistory\Configuration\Config1.xml'
$fhOn = $false; $fhTarget = $null; $fhLast = $null
if (Test-Path -LiteralPath $fhConfig) {
    try {
        [xml]$x = Get-Content -LiteralPath $fhConfig -Raw -ErrorAction Stop
        $t = $x.SelectSingleNode('//*[local-name()="TargetUrl"]')
        if ($t) { $fhTarget = $t.InnerText }
        $e = $x.SelectSingleNode('//*[local-name()="ConfigStatus"]')   # 1 = enabled
        $fhOn = ($null -ne $e -and $e.InnerText -eq '1') -or ($null -eq $e -and $fhTarget)
    } catch { }
}
try {
    $p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\FileHistory' -ErrorAction Stop
    if ($p.PSObject.Properties['ProtectedUpToTime'] -and $p.ProtectedUpToTime -gt 0) {
        $fhLast = [datetime]::FromFileTime([int64]$p.ProtectedUpToTime)
    }
} catch { }
if (-not $fhOn) {
    Add-Check 'File History' 'Status' 'Off' 'Info'
} else {
    $where = if ($fhTarget) { $fhTarget } else { 'unknown drive' }
    Add-Check 'File History' 'Status' "On, backing up to $where" 'OK'
    if ($fhLast) {
        $st = if (($now - $fhLast).TotalDays -gt $MaxAgeDays) { 'Stale' } else { 'OK' }
        Add-Check 'File History' 'Last backup' (Format-Age $fhLast) $st
        if ($st -eq 'Stale') { Add-Finding 'High' "File History is on but last finished $(Format-Age $fhLast)." 'Plug in or reconnect the backup drive, then open Control Panel > File History and click Run now.' }
        else { $covered.FileHistory = $true }
    } else {
        Add-Check 'File History' 'Last backup' 'Never finished' 'Problem'
        Add-Finding 'High' 'File History is on but has never finished a backup.' 'Check that its drive is connected, then open Control Panel > File History and click Run now.'
    }
}
$results | Where-Object Area -eq 'File History' | ForEach-Object { Write-Host ("  {0,-16} {1}  [{2}]" -f $_.Item, $_.Value, $_.Status) }

# ---------------------------------------------------------------- OneDrive folder backup
Write-Section 'OneDrive folder backup'
$odRoot = @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) | Where-Object { $_ } | Select-Object -Unique
$odRunning = [bool](Get-Process -Name OneDrive -ErrorAction SilentlyContinue)
$known = [ordered]@{ Desktop = 'Desktop'; Documents = 'Personal'; Pictures = 'My Pictures' }
$shell = $null
try { $shell = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop } catch { }
$folderPaths = @{}
foreach ($k in $known.Keys) {
    $raw = if ($shell -and $shell.PSObject.Properties[$known[$k]]) { $shell.($known[$k]) } else { Join-Path $env:USERPROFILE $k }
    $path = [Environment]::ExpandEnvironmentVariables($raw)
    $folderPaths[$k] = $path
    $inOd = $false
    foreach ($r in $odRoot) { if ($path.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { $inOd = $true } }
    if ($inOd) { $covered.OneDrive += $k }
    Add-Check 'OneDrive' $k ($(if ($inOd) { 'Backed up to OneDrive' } else { 'Not in OneDrive' })) ($(if ($inOd) { 'OK' } else { 'Info' }))
}
Add-Check 'OneDrive' 'App running' ($(if ($odRunning) { 'Yes' } else { 'No' })) ($(if ($odRunning -or -not $covered.OneDrive) { 'OK' } else { 'Problem' }))
if ($covered.OneDrive.Count -gt 0 -and -not $odRunning) {
    Add-Finding 'High' 'Your folders are redirected into OneDrive but OneDrive isn''t running, so changes aren''t syncing.' 'Start OneDrive from the Start menu and check its cloud icon for errors.'
    $covered.OneDrive = @()
}
$results | Where-Object Area -eq 'OneDrive' | ForEach-Object { Write-Host ("  {0,-16} {1}  [{2}]" -f $_.Item, $_.Value, $_.Status) }

# ---------------------------------------------------------------- System images
Write-Section 'System image backups'
$drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2 OR DriveType=3' -ErrorAction SilentlyContinue)
$images = @()
foreach ($d in $drives) {
    $img = Join-Path ($d.DeviceID + '\') ("WindowsImageBackup\" + $env:COMPUTERNAME)
    if (Test-Path -LiteralPath $img) {
        $it = Get-Item -LiteralPath $img -Force
        $newest = (Get-ChildItem -LiteralPath $img -Recurse -Force -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1)
        $when = if ($newest) { $newest.LastWriteTime } else { $it.LastWriteTime }
        $images += [pscustomobject]@{ Drive = $d.DeviceID; When = $when }
    }
}
if ($images.Count -eq 0) {
    Add-Check 'System image' 'Found' 'None on connected drives' 'Info'
} else {
    foreach ($i in $images) {
        $st = if (($now - $i.When).TotalDays -gt 90) { 'Stale' } else { 'OK' }
        Add-Check 'System image' $i.Drive "Last written $(Format-Age $i.When)" $st
        if ($st -eq 'OK') { $covered.Image = $true }
    }
}
$results | Where-Object Area -eq 'System image' | ForEach-Object { Write-Host ("  {0,-16} {1}  [{2}]" -f $_.Item, $_.Value, $_.Status) }

# ---------------------------------------------------------------- Recovery and BitLocker
Write-Section 'Recovery and BitLocker'
if ($isAdmin) {
    $re = (& reagentc.exe /info 2>$null) -join "`n"
    if ($re -match 'Windows RE status:\s*(\S+)') {
        $on = $Matches[1] -match 'Enabled'
        Add-Check 'Recovery' 'WinRE' $Matches[1] ($(if ($on) { 'OK' } else { 'Problem' }))
        if (-not $on) { Add-Finding 'Medium' 'The Windows Recovery Environment is disabled, so Startup Repair and Reset this PC can''t run from boot.' 'In an admin terminal run: reagentc /enable' }
    } else { Add-Check 'Recovery' 'WinRE' 'Could not read' 'Unknown' }
    try {
        $bl = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
        if ($bl.ProtectionStatus -eq 'On' -or $bl.VolumeStatus -ne 'FullyDecrypted') {
            $hasPw = [bool]($bl.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
            Add-Check 'BitLocker' "$sysDrive recovery key" ($(if ($hasPw) { 'Recovery password exists' } else { 'No recovery password' })) ($(if ($hasPw) { 'OK' } else { 'Problem' }))
            if ($hasPw) { Add-Finding 'Info' "$sysDrive is encrypted. A disk image is useless if you lose the recovery key." 'Confirm the key is saved at account.microsoft.com/devices/recoverykey or printed somewhere safe.' }
            else { Add-Finding 'High' "$sysDrive is encrypted but has no recovery password protector." 'In an admin terminal run: manage-bde -protectors -add $sysDrive -RecoveryPassword, then save the key somewhere safe.' }
        } else { Add-Check 'BitLocker' $sysDrive 'Not encrypted' 'Info' }
    } catch { Add-Check 'BitLocker' $sysDrive 'Not available on this edition' 'Info' }
} else {
    Add-Check 'Recovery' 'WinRE' 'Needs admin' 'Unknown'
    Add-Check 'BitLocker' $sysDrive 'Needs admin' 'Unknown'
}
$results | Where-Object { $_.Area -in 'Recovery', 'BitLocker' } | ForEach-Object { Write-Host ("  {0,-16} {1}  [{2}]" -f $_.Item, $_.Value, $_.Status) }

# ---------------------------------------------------------------- Your backup destinations
if ($BackupPath) {
    Write-Section 'Your backup destinations'
    foreach ($bp in $BackupPath) {
        if (-not (Test-Path -LiteralPath $bp)) {
            Add-Check 'Backup path' $bp 'Not reachable' 'Problem'
            Add-Finding 'High' "Backup location $bp isn't reachable right now." 'Connect the drive or check the share, then rerun.'
            continue
        }
        # Prefer the Backup-Folders.ps1 layout <Destination>\<PC name> when present
        $scan = Join-Path $bp $env:COMPUTERNAME
        if (-not (Test-Path -LiteralPath $scan)) { $scan = $bp }
        $newest = $null; $n = 0
        try {
            Get-ChildItem -LiteralPath $scan -Recurse -File -Force -ErrorAction SilentlyContinue |
                Select-Object -First $MaxScanFiles | ForEach-Object {
                    $n++
                    if (-not $newest -or $_.LastWriteTime -gt $newest) { $newest = $_.LastWriteTime }
                }
        } catch { }
        # robocopy keeps source timestamps, so also trust folder write times
        $dirNewest = Get-ChildItem -LiteralPath $scan -Directory -Force -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($dirNewest -and (-not $newest -or $dirNewest.LastWriteTime -gt $newest)) { $newest = $dirNewest.LastWriteTime }
        $free = $null
        try {
            if ($bp -match '^[A-Za-z]:') { $free = (Get-PSDrive -Name $bp.Substring(0, 1) -ErrorAction Stop).Free }
        } catch { }
        $freeText = if ($null -ne $free) { ", $(Format-Size $free) free" } else { '' }
        if (-not $newest) {
            Add-Check 'Backup path' $bp "Reachable but empty$freeText" 'Problem'
            Add-Finding 'High' "Backup location $bp has nothing in it." 'Run your backup, for example Backup-Folders.ps1 -Destination <this path> -Run.'
        } else {
            $st = if (($now - $newest).TotalDays -gt $MaxAgeDays) { 'Stale' } else { 'OK' }
            $capped = if ($n -ge $MaxScanFiles) { " (checked first $MaxScanFiles files)" } else { '' }
            Add-Check 'Backup path' $bp "Newest change $(Format-Age $newest)$freeText$capped" $st
            if ($st -eq 'Stale') { Add-Finding 'High' "Nothing in $bp has changed in over $MaxAgeDays days." 'Run your backup again, or schedule it with Task Scheduler.' }
            else { $covered.Custom = $true }
        }
        if ($null -ne $free -and $free -lt 20GB) { Add-Finding 'Medium' "Backup drive $bp has only $(Format-Size $free) free." 'Free up space there or use a bigger drive before the next backup fails.' }
    }
    $results | Where-Object Area -eq 'Backup path' | ForEach-Object { Write-Host ("  {0}`n    {1}  [{2}]" -f $_.Item, $_.Value, $_.Status) }
}

# ---------------------------------------------------------------- What's not protected
Write-Section 'Unprotected personal folders'
$anyFull = $covered.FileHistory -or $covered.Custom
$unprotected = 0L
foreach ($k in $known.Keys) {
    if ($covered.OneDrive -contains $k -or $anyFull) {
        Add-Check 'Unprotected' $k 'Covered' 'OK'
        continue
    }
    $p = $folderPaths[$k]
    $size = if (Test-Path -LiteralPath $p) { Get-FolderSize $p } else { 0 }
    $unprotected += $size
    Add-Check 'Unprotected' $k "$(Format-Size $size) with no backup found" ($(if ($size -gt 0) { 'Problem' } else { 'OK' }))
}
$results | Where-Object Area -eq 'Unprotected' | ForEach-Object { Write-Host ("  {0,-16} {1}  [{2}]" -f $_.Item, $_.Value, $_.Status) }
if ($unprotected -gt 0) {
    $hint = if (-not $BackupPath) { ' If you back up some other way, rerun with -BackupPath <where it goes>.' } else { '' }
    Add-Finding 'High' "$(Format-Size $unprotected) in Desktop, Documents or Pictures has no backup this script could find.$hint" 'Turn on OneDrive folder backup, File History, or run 05_Backup\Backup-Folders.ps1 to a USB drive or NAS.'
}
if (-not $covered.Image -and -not $anyFull -and $covered.OneDrive.Count -eq 0) {
    Add-Finding 'Medium' 'No backup of any kind was found on this PC.' 'Start with one copy of your files on another drive (Backup-Folders.ps1) and one in the cloud.'
}

# ---------------------------------------------------------------- Findings
Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  No problems found. Backups look current.' -ForegroundColor Green
} else {
    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    foreach ($f in ($findings | Sort-Object { $order[$_.Severity] })) {
        $color = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Low' { 'DarkYellow' } default { 'Gray' } }
        Write-Host ("  [{0}] {1}" -f $f.Severity, $f.Finding) -ForegroundColor $color
        Write-Host ("         Fix: {0}" -f $f.Fix)
    }
}

if ($CsvPath) {
    $rows = @($results) + @($findings | ForEach-Object {
        [pscustomobject]@{ Type = 'Finding'; Area = $_.Severity; Item = $_.Finding; Value = $_.Fix; Status = '' } })
    $rows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Saved report to $CsvPath" -ForegroundColor Green
}
