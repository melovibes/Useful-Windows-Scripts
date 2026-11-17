<#
.SYNOPSIS
    Get-UpdateHealth.ps1 - Check whether Windows Update is actually working:
    failed and stuck updates, pending restarts, paused or blocked updates,
    broken update services, with plain-English fixes. Read-only.

.DESCRIPTION
    "Your device is missing important security and quality fixes" usually
    has a boring cause: updates paused months ago, an update that fails
    every night with the same error, a restart nobody did, a disabled
    service or a policy left behind by an old tweak tool. This script shows
    all of that in one place.

    Reports:
      Windows      Edition, version (e.g. 24H2), build and uptime
      Status       Last successful check and install, and when the newest
                   cumulative update and Defender intelligence update went in
      Restart      Whether a restart is pending, and which part of Windows
                   is waiting for it
      Services     Windows Update, BITS, Update Orchestrator, Cryptographic
                   Services, Windows Modules Installer and the Update
                   Medic service: running state and start type
      Settings     Paused updates, active hours, "get the latest updates as
                   soon as they're available", and any policies that defer,
                   pin a version, point the PC at WSUS or switch updates off
      Disk         Free space on the system drive and the size of the
                   Windows Update download cache
      History      Installs over the last -Days days: succeeded, failed,
                   and updates that failed more than once, with what the
                   error code usually means
      Available    (only with -CheckOnline) updates Windows has not
                   installed yet
      Findings     Numbered list of what to fix first, with how

    Safety level : READ-ONLY. Reads the registry, services and the local
                   Windows Update history through the built-in
                   Microsoft.Update.Session API. Changes nothing, installs
                   nothing, restarts nothing. No network calls unless you
                   pass -CheckOnline (then Windows asks Microsoft Update, or
                   your WSUS server, what is available; nothing is
                   downloaded). Writes a file only if you pass -CsvPath.
                   Fix commands are printed as suggestions only.
    Admin        : Not required.

.PARAMETER Days
    How many days of update history to look at (7-730, default 90).

.PARAMETER Top
    Rows to show in the history lists (default 15).

.PARAMETER CheckOnline
    Also ask Windows Update which updates are available but not installed.
    Can take a minute or two. Nothing is downloaded or installed.

.PARAMETER ShowAll
    Print every history entry in the window, not just failures.

.PARAMETER CsvPath
    Export the update history in the window to this CSV file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-UpdateHealth.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-UpdateHealth.ps1 -Days 30 -CheckOnline

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-UpdateHealth.ps1 -CsvPath "$env:USERPROFILE\Desktop\update-history.csv"
#>

[CmdletBinding()]
param(
    [ValidateRange(7, 730)][int]$Days = 90,
    [ValidateRange(1, 200)][int]$Top = 15,
    [switch]$CheckOnline,
    [switch]$ShowAll,
    [string]$CsvPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$cutoff   = (Get-Date).AddDays(-$Days)
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param([ValidateSet('High', 'Medium', 'Low')][string]$Level, [string]$Text, [string]$Fix)
    $findings.Add([pscustomobject]@{ Level = $Level; Text = $Text; Fix = $Fix })
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function Format-Age {
    param($When)
    if (-not $When) { return 'never / unknown' }
    $span = (Get-Date) - $When
    if ($span.TotalDays -ge 2) { return ('{0:yyyy-MM-dd} ({1} days ago)' -f $When, [int]$span.TotalDays) }
    if ($span.TotalHours -ge 1) { return ('{0:yyyy-MM-dd HH:mm} ({1} hours ago)' -f $When, [int]$span.TotalHours) }
    return ('{0:yyyy-MM-dd HH:mm} (just now)' -f $When)
}

function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

function ConvertTo-LocalTime {
    param($When)
    if (-not $When) { return $null }
    try {
        $d = [datetime]$When
        if ($d.Year -lt 2000) { return $null }   # COM returns 1899/1601 for "never"
        return [datetime]::SpecifyKind($d, [DateTimeKind]::Utc).ToLocalTime()
    } catch { return $null }
}

function Write-Section { param([string]$Title) Write-Host ''; Write-Host "== $Title ==" -ForegroundColor Cyan }

# Common Windows Update error codes and what they usually mean.
$errorCodes = @{
    '0x80070002' = 'A file it needed is missing, often a broken download. Clearing the update cache usually fixes it.'
    '0x80070003' = 'A folder it needed is missing, often a broken download. Clearing the update cache usually fixes it.'
    '0x80070005' = 'Access denied. Security software or changed permissions blocked the install.'
    '0x8007000E' = 'Ran out of memory during the install. Close apps and retry.'
    '0x80070070' = 'Not enough disk space.'
    '0x80070422' = 'The Windows Update service is disabled.'
    '0x80070643' = 'The installer failed. Common with .NET updates and with the recovery partition (WinRE) update when that partition is too small.'
    '0x800F081F' = 'Windows could not find files it needed in the component store. Run DISM RestoreHealth.'
    '0x800F0922' = 'Could not finish: no connection to the update servers, or the System Reserved partition is too full.'
    '0x800F0988' = 'The component store needs cleaning up. Run DISM StartComponentCleanup.'
    '0x80073712' = 'The component store is damaged. Run DISM RestoreHealth, then sfc.'
    '0x8024402C' = 'Could not reach the update server (proxy or DNS problem).'
    '0x80072EE2' = 'The connection to the update server timed out.'
    '0x80072EFD' = 'Could not connect to the update server.'
    '0x80240034' = 'The download failed.'
    '0x80240017' = 'The update does not apply to this PC. Safe to ignore.'
    '0x8024200B' = 'The install failed (general error). Check for a more specific error on the same update.'
}

$resultNames = @{ 0 = 'Not started'; 1 = 'In progress'; 2 = 'Succeeded'; 3 = 'Succeeded with errors'; 4 = 'Failed'; 5 = 'Aborted' }

Write-Host 'Get-UpdateHealth.ps1 - read-only Windows Update check' -ForegroundColor White
Write-Host "History window: last $Days days" -ForegroundColor DarkGray

# --- Windows -----------------------------------------------------------------
Write-Section 'Windows'
$cv       = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$product  = Get-RegValue $cv 'ProductName'
$display  = Get-RegValue $cv 'DisplayVersion'
$build    = Get-RegValue $cv 'CurrentBuild'
$ubr      = Get-RegValue $cv 'UBR'
$edition  = Get-RegValue $cv 'EditionID'
# Windows 11 still reports "Windows 10" in ProductName; the build tells them apart.
if ($product -and $build -and [int]$build -ge 22000) { $product = $product -replace 'Windows 10', 'Windows 11' }
$uptime = $null
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $uptime = (Get-Date) - $os.LastBootUpTime
} catch { }
Write-Host ("  {0} ({1})  version {2}  build {3}.{4}" -f $product, $edition, $display, $build, $ubr)
if ($uptime) { Write-Host ("  Up for {0} days {1} hours" -f [int][math]::Floor($uptime.TotalDays), $uptime.Hours) }
if ($uptime -and $uptime.TotalDays -ge 14) {
    Add-Finding 'Low' ("The PC hasn't restarted in {0} days. Some updates only finish on a restart." -f [int]$uptime.TotalDays) 'Restart (not just shut down and start; Fast Startup skips a real restart).'
}

# --- Status ------------------------------------------------------------------
Write-Section 'Status'
$lastSearch = $null; $lastInstall = $null
try {
    $au = New-Object -ComObject Microsoft.Update.AutoUpdate -ErrorAction Stop
    $lastSearch  = ConvertTo-LocalTime $au.Results.LastSearchSuccessDate
    $lastInstall = ConvertTo-LocalTime $au.Results.LastInstallationSuccessDate
} catch { Write-Host '  [i] Could not read the Windows Update status API.' -ForegroundColor Yellow }

# Full local history (no network).
$history = @()
$historyOk = $false
try {
    $session  = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
    $searcher = $session.CreateUpdateSearcher()
    $count    = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) {
        $history = @($searcher.QueryHistory(0, $count) | Where-Object { $_.Title } | ForEach-Object {
            $hr  = '0x{0:X8}' -f ([int64]$_.HResult -band 0xFFFFFFFFL)
            $kb  = if ($_.Title -match '(KB\d{6,8})') { $Matches[1] } else { '' }
            [pscustomobject]@{
                Date      = ConvertTo-LocalTime $_.Date
                Title     = $_.Title
                KB        = $kb
                Operation = switch ($_.Operation) { 1 { 'Install' } 2 { 'Uninstall' } default { 'Other' } }
                Result    = $resultNames[[int]$_.ResultCode]
                ErrorCode = if ([int]$_.ResultCode -in 4, 5 -or ([int64]$_.HResult -ne 0 -and [int]$_.ResultCode -ne 2)) { $hr } else { '' }
            }
        })
    }
    $historyOk = $true
} catch {
    Write-Host '  [i] Could not read update history from the Windows Update API.' -ForegroundColor Yellow
    Add-Finding 'Medium' 'The Windows Update API did not answer, so update history could not be checked.' 'Make sure the Windows Update service is not disabled (see Services), restart, and run this again.'
}

$succeeded = @($history | Where-Object { $_.Result -like 'Succeeded*' -and $_.Date })
$lastCu = $succeeded | Where-Object { $_.Title -match 'Cumulative Update' -and $_.Title -notmatch '\.NET' } |
          Sort-Object Date -Descending | Select-Object -First 1
$lastDefender = $succeeded | Where-Object { $_.Title -match 'Security Intelligence Update|Definition Update' } |
                Sort-Object Date -Descending | Select-Object -First 1

Write-Host ("  Last successful check   : {0}" -f (Format-Age $lastSearch))
Write-Host ("  Last successful install : {0}" -f (Format-Age $lastInstall))
if ($lastCu) {
    Write-Host ("  Newest cumulative update: {0}  {1}" -f (Format-Age $lastCu.Date), $lastCu.KB)
} else {
    Write-Host  '  Newest cumulative update: none in history (or history was cleared)'
}
Write-Host ("  Defender intelligence   : {0}" -f $(if ($lastDefender) { Format-Age $lastDefender.Date } else { 'none in history (fine if you use other antivirus)' }))

if ($lastSearch -and ((Get-Date) - $lastSearch).TotalDays -gt 7) {
    Add-Finding 'High' ("Windows hasn't successfully checked for updates in {0} days." -f [int]((Get-Date) - $lastSearch).TotalDays) 'Settings > Windows Update > Check for updates. If it errors, see the other findings and the troubleshooter tip at the end.'
}
if ($lastCu -and ((Get-Date) - $lastCu.Date).TotalDays -gt 45) {
    Add-Finding 'High' ("The newest cumulative (security) update installed {0} days ago. Microsoft releases one every month." -f [int]((Get-Date) - $lastCu.Date).TotalDays) 'Settings > Windows Update > Check for updates, then restart. If the same update keeps failing, see its error code below.'
}
if ($lastDefender -and ((Get-Date) - $lastDefender.Date).TotalDays -gt 7) {
    Add-Finding 'Medium' ("Defender's virus definitions last updated {0} days ago." -f [int]((Get-Date) - $lastDefender.Date).TotalDays) 'Windows Security > Virus & threat protection > Protection updates > Check for updates.'
}

# --- Restart -----------------------------------------------------------------
Write-Section 'Restart'
$reasons = New-Object System.Collections.Generic.List[string]
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons.Add('Windows component servicing (an update is half-installed)') }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons.Add('Windows Update') }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Updates\UpdateExeVolatile') { $reasons.Add('An update installer') }
$pfro = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
if ($pfro) { $reasons.Add(('Files waiting to be replaced on restart ({0} entries; apps and drivers do this too)' -f @($pfro | Where-Object { $_ }).Count)) }
$activeName  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
$pendingName = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
if ($activeName -and $pendingName -and $activeName -ne $pendingName) { $reasons.Add('A PC rename') }

if ($reasons.Count -eq 0) {
    Write-Host '  No restart pending.' -ForegroundColor Green
} else {
    Write-Host '  Restart pending for:' -ForegroundColor Yellow
    $reasons | ForEach-Object { Write-Host "    - $_" }
    $updateReasons = @($reasons | Where-Object { $_ -notlike 'Files waiting*' -and $_ -ne 'A PC rename' })
    if ($updateReasons.Count -gt 0) {
        Add-Finding 'High' 'An update is waiting for a restart. Until then it is not protecting you, and new updates may refuse to install.' 'Save your work and restart (Start > Power > Update and restart, or Restart).'
    }
}

# --- Services ----------------------------------------------------------------
Write-Section 'Services'
$svcList = [ordered]@{
    'wuauserv'         = 'Windows Update'
    'BITS'             = 'Background Intelligent Transfer'
    'UsoSvc'           = 'Update Orchestrator'
    'CryptSvc'         = 'Cryptographic Services'
    'TrustedInstaller' = 'Windows Modules Installer'
    'WaaSMedicSvc'     = 'Windows Update Medic'
}
foreach ($name in $svcList.Keys) {
    $svc = $null
    try { $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop } catch { }
    if (-not $svc) {
        Write-Host ("  {0,-32} missing" -f $svcList[$name]) -ForegroundColor Yellow
        Add-Finding 'High' ("The {0} service ({1}) is missing." -f $svcList[$name], $name) 'Run DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow, from an admin terminal.'
        continue
    }
    $color = if ($svc.StartMode -eq 'Disabled') { 'Red' } else { 'Gray' }
    Write-Host ("  {0,-32} {1,-9} start: {2}" -f $svcList[$name], $svc.State, $svc.StartMode) -ForegroundColor $color
    if ($svc.StartMode -eq 'Disabled') {
        Add-Finding 'High' ("The {0} service ({1}) is disabled, so updates can't install. Debloat and 'privacy' tools often do this." -f $svcList[$name], $name) ("From an admin terminal: Set-Service -Name {0} -StartupType Manual (and undo the tool's setting so it doesn't come back)." -f $name)
    }
}

# --- Settings ----------------------------------------------------------------
Write-Section 'Settings'
$ux  = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$au  = "$pol\AU"

$pauseEnd = $null
foreach ($n in 'PauseUpdatesExpiryTime', 'PauseQualityUpdatesEndTime', 'PauseFeatureUpdatesEndTime') {
    $v = Get-RegValue $ux $n
    if ($v) {
        try {
            $d = ([datetime]::Parse($v, [Globalization.CultureInfo]::InvariantCulture)).ToLocalTime()
            if ($d -gt (Get-Date) -and (-not $pauseEnd -or $d -gt $pauseEnd)) { $pauseEnd = $d }
        } catch { }
    }
}
if ($pauseEnd) {
    Write-Host ("  Updates paused until {0:yyyy-MM-dd}" -f $pauseEnd) -ForegroundColor Yellow
    Add-Finding 'Medium' ("Updates are paused until {0:yyyy-MM-dd}." -f $pauseEnd) 'Settings > Windows Update > Resume updates (unless you paused on purpose).'
} else {
    Write-Host '  Updates paused          : no'
}

$ahStart = Get-RegValue $ux 'ActiveHoursStart'
$ahEnd   = Get-RegValue $ux 'ActiveHoursEnd'
if ($null -ne $ahStart -and $null -ne $ahEnd) { Write-Host ("  Active hours            : {0}:00 - {1}:00 (no automatic restarts in this window)" -f $ahStart, $ahEnd) }
$ci = Get-RegValue $ux 'IsContinuousInnovationOptedIn'
Write-Host ("  Get updates ASAP        : {0}" -f $(if ($ci -eq 1) { 'on' } else { 'off' }))

$policyLines = New-Object System.Collections.Generic.List[string]
$noAuto = Get-RegValue $au 'NoAutoUpdate'
$auOpt  = Get-RegValue $au 'AUOptions'
$wsus   = Get-RegValue $pol 'WUServer'
$useWs  = Get-RegValue $au 'UseWUServer'
$noNet  = Get-RegValue $pol 'DoNotConnectToWindowsUpdateInternetLocations'
$pinVer = Get-RegValue $pol 'TargetReleaseVersionInfo'
$pinOn  = Get-RegValue $pol 'TargetReleaseVersion'
$deferF = Get-RegValue $pol 'DeferFeatureUpdatesPeriodInDays'
$deferQ = Get-RegValue $pol 'DeferQualityUpdatesPeriodInDays'
$noDrv  = Get-RegValue $pol 'ExcludeWUDriversInQualityUpdate'

if ($noAuto -eq 1) {
    $policyLines.Add('Automatic updates turned OFF by policy (NoAutoUpdate=1)')
    Add-Finding 'High' 'A policy turns automatic updates off, so security fixes only arrive when someone checks by hand.' 'gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Windows Update > set "Configure Automatic Updates" to Not Configured (or remove NoAutoUpdate under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU).'
} elseif ($auOpt) {
    $auText = switch ($auOpt) { 2 { 'notify before download' } 3 { 'download, notify before install' } 4 { 'download and install on a schedule' } 5 { 'local admin chooses' } 7 { 'download, notify before restart' } default { "option $auOpt" } }
    $policyLines.Add("Automatic updates set by policy: $auText")
    if ($auOpt -eq 2) { Add-Finding 'Low' 'A policy makes Windows only notify you about updates; nothing installs until you act.' 'Fine if you check every month. Otherwise set "Configure Automatic Updates" back to Not Configured.' }
}
if ($wsus -and $useWs -eq 1) {
    $policyLines.Add('Updates come from a WSUS / company update server, not Microsoft')
    if ($lastSearch -and ((Get-Date) - $lastSearch).TotalDays -gt 7) {
        Add-Finding 'Medium' "This PC gets updates from a company (WSUS) server and hasn't reached it lately. On a home PC that is usually a leftover setting." 'If this PC is no longer managed by work or school, remove WUServer/UseWUServer under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate, then restart.'
    }
}
if ($noNet -eq 1) { $policyLines.Add('Blocked from Microsoft Update on the internet (DoNotConnectToWindowsUpdateInternetLocations)') }
if ($pinOn -eq 1 -and $pinVer) {
    $policyLines.Add("Pinned to Windows version $pinVer")
    if ($display -and $pinVer -eq $display) {
        Add-Finding 'Low' ("A policy keeps this PC on version {0}. When that version leaves support it stops getting security fixes." -f $pinVer) 'Check the end-of-service date for your version (Find-OutdatedApps.ps1 shows it) and raise or remove the pin before then.'
    }
}
if ($deferF) { $policyLines.Add("Feature updates deferred $deferF days") }
if ($deferQ) {
    $policyLines.Add("Quality (security) updates deferred $deferQ days")
    if ([int]$deferQ -gt 14) { Add-Finding 'Low' ("Security updates are delayed {0} days by policy." -f $deferQ) 'Lower "Select when Quality Updates are received" in gpedit (Windows Update > Manage updates offered from Windows Update) to 0-7 days.' }
}
if ($noDrv -eq 1) { $policyLines.Add('Drivers excluded from Windows Update') }

if ($policyLines.Count -eq 0) {
    Write-Host '  Policies                : none (Windows Update uses its defaults)'
} else {
    Write-Host '  Policies:' -ForegroundColor Yellow
    $policyLines | ForEach-Object { Write-Host "    - $_" }
}

# --- Disk --------------------------------------------------------------------
Write-Section 'Disk'
$sysDrive = $env:SystemDrive
try {
    $vol = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'" -ErrorAction Stop
    $freeGB = [math]::Round($vol.FreeSpace / 1GB, 1)
    Write-Host ("  Free on {0}            : {1} GB of {2} GB" -f $sysDrive, $freeGB, [math]::Round($vol.Size / 1GB, 0))
    if ($freeGB -lt 10) {
        Add-Finding 'High' ("Only {0} GB free on {1}. Monthly updates need several GB and version upgrades need 20 GB or more." -f $freeGB, $sysDrive) 'Free up space: Settings > System > Storage > Cleanup recommendations, or run 02_Performance\Clear-TempAndCache.ps1 and 01_Organization\Find-OldLargeFiles.ps1.'
    } elseif ($freeGB -lt 20) {
        Add-Finding 'Low' ("{0} GB free on {1}: fine for monthly updates, tight for a version upgrade." -f $freeGB, $sysDrive) 'Free up some space before the next yearly version update.'
    }
} catch { Write-Host '  [i] Could not read free space.' -ForegroundColor Yellow }

$dl = if ($env:SystemRoot) { Join-Path $env:SystemRoot 'SoftwareDistribution\Download' } else { $null }
if ($dl -and (Test-Path $dl)) {
    $bytes = (Get-ChildItem -Path $dl -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    if (-not $bytes) { $bytes = 0 }
    Write-Host ("  Update download cache  : {0}" -f (Format-Size $bytes))
    if ($bytes -gt 5GB) { Add-Finding 'Low' ("The Windows Update download cache is {0}." -f (Format-Size $bytes)) 'Run 02_Performance\Clear-TempAndCache.ps1 -Clean as admin to clear it (Windows re-downloads what it still needs).' }
}

# --- History -----------------------------------------------------------------
Write-Section "History (last $Days days)"
$window = @($history | Where-Object { $_.Date -and $_.Date -ge $cutoff } | Sort-Object Date -Descending)
if (-not $historyOk) {
    Write-Host '  Not available.'
} elseif ($window.Count -eq 0) {
    Write-Host '  No update activity in this window.' -ForegroundColor Yellow
    if (-not $lastCu) { Add-Finding 'Medium' 'Windows has no update history at all. It may have been cleared, or updates have never run.' 'Settings > Windows Update > Check for updates.' }
} else {
    $ok     = @($window | Where-Object { $_.Result -like 'Succeeded*' })
    $failed = @($window | Where-Object { $_.Result -in 'Failed', 'Aborted' })
    Write-Host ("  {0} entries: {1} succeeded, {2} failed or aborted" -f $window.Count, $ok.Count, $failed.Count)

    if ($failed.Count -gt 0) {
        Write-Host ''
        Write-Host '  Failures (newest first):' -ForegroundColor Yellow
        $failed | Select-Object -First $Top | ForEach-Object {
            $title = if ($_.Title.Length -gt 80) { $_.Title.Substring(0, 77) + '...' } else { $_.Title }
            Write-Host ("    {0:yyyy-MM-dd}  {1}  {2}" -f $_.Date, $_.ErrorCode, $title)
        }

        # Same update failing again and again, and never succeeding afterwards.
        $groups = $failed | Group-Object { if ($_.KB) { $_.KB } else { $_.Title } } | Where-Object { $_.Count -ge 2 }
        foreach ($g in $groups) {
            $lastFail = ($g.Group | Sort-Object Date -Descending | Select-Object -First 1)
            $laterOk  = $ok | Where-Object { (($_.KB -and $_.KB -eq $lastFail.KB) -or $_.Title -eq $lastFail.Title) -and $_.Date -gt $lastFail.Date }
            if ($laterOk) { continue }
            $code    = $lastFail.ErrorCode
            $meaning = if ($code -and $errorCodes.ContainsKey($code)) { $errorCodes[$code] } else { 'Search the code on learn.microsoft.com or the Microsoft Q&A forum.' }
            $label   = if ($lastFail.KB) { $lastFail.KB } else { $lastFail.Title }
            if ($code -eq '0x80240017') { continue }
            Add-Finding 'High' ("{0} has failed {1} times (latest {2:yyyy-MM-dd}, error {3}): {4}" -f $label, $g.Count, $lastFail.Date, $code, $meaning) 'Try in order: restart and retry; Settings > System > Troubleshoot > Other troubleshooters > Windows Update; then from an admin terminal DISM /Online /Cleanup-Image /RestoreHealth and sfc /scannow; last resort, download the KB from the Microsoft Update Catalog and install it by hand.'
        }

        $codes = $failed | Where-Object { $_.ErrorCode } | Group-Object ErrorCode | Sort-Object Count -Descending
        if ($codes) {
            Write-Host ''
            Write-Host '  What the error codes usually mean:' -ForegroundColor Yellow
            foreach ($c in $codes) {
                $meaning = if ($errorCodes.ContainsKey($c.Name)) { $errorCodes[$c.Name] } else { 'Not in this script''s list; search the code online.' }
                Write-Host ("    {0} x{1}  {2}" -f $c.Name, $c.Count, $meaning)
            }
        }
    } else {
        Write-Host '  No failed updates in this window.' -ForegroundColor Green
    }

    if ($ShowAll) {
        Write-Host ''
        Write-Host '  All entries:' -ForegroundColor Cyan
        $window | Format-Table @{ n = 'Date'; e = { '{0:yyyy-MM-dd HH:mm}' -f $_.Date } }, Result, ErrorCode, KB, Title -AutoSize -Wrap | Out-String -Width 200 | Write-Host
    }
}

if ($CsvPath) {
    try {
        $window | Select-Object @{ n = 'Date'; e = { '{0:yyyy-MM-dd HH:mm}' -f $_.Date } }, Operation, Result, ErrorCode, KB, Title |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host ''
        Write-Host "  [+] History saved to $CsvPath" -ForegroundColor Green
    } catch { Write-Host "  [!] Could not write $CsvPath : $($_.Exception.Message)" -ForegroundColor Red }
}

# --- Available (opt-in network call) -----------------------------------------
if ($CheckOnline) {
    Write-Section 'Available (not installed)'
    Write-Host '  Asking Windows Update what is available (can take a minute or two)...' -ForegroundColor DarkGray
    try {
        $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $s.Online = $true
        $res = $s.Search('IsInstalled=0 and IsHidden=0')
        $avail = @($res.Updates)
        if ($avail.Count -eq 0) {
            Write-Host '  Nothing waiting. You are up to date.' -ForegroundColor Green
        } else {
            $secCount = 0
            foreach ($u in $avail) {
                $sev  = if ($u.MsrcSeverity) { $u.MsrcSeverity } else { '-' }
                if ($u.MsrcSeverity -in 'Critical', 'Important') { $secCount++ }
                $size = if ($u.MaxDownloadSize -gt 0) { Format-Size $u.MaxDownloadSize } else { '?' }
                $dlState = if ($u.IsDownloaded) { 'downloaded' } else { 'not downloaded' }
                Write-Host ("    {0,-10} {1,-9} {2,-15} {3}" -f $sev, $size, $dlState, $u.Title)
            }
            $lvl = if ($secCount -gt 0) { 'High' } else { 'Low' }
            Add-Finding $lvl ("{0} update(s) are available but not installed ({1} rated Critical or Important)." -f $avail.Count, $secCount) 'Settings > Windows Update > Download & install (or Install now), then restart.'
        }
    } catch {
        Write-Host "  [!] Search failed: $($_.Exception.Message)" -ForegroundColor Red
        Add-Finding 'Medium' 'Windows could not search for updates just now.' 'Check your internet connection, then Settings > System > Troubleshoot > Other troubleshooters > Windows Update.'
    }
}

# --- Findings ----------------------------------------------------------------
Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  Windows Update looks healthy. Nothing to fix.' -ForegroundColor Green
} else {
    $order = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
    $i = 0
    foreach ($f in ($findings | Sort-Object { $order[$_.Level] })) {
        $i++
        $color = switch ($f.Level) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  {0}. [{1}] {2}" -f $i, $f.Level, $f.Text) -ForegroundColor $color
        Write-Host ("     Fix: {0}" -f $f.Fix) -ForegroundColor DarkGray
    }
}
Write-Host ''
Write-Host 'Nothing was changed. Fixes above are suggestions only.' -ForegroundColor DarkGray
