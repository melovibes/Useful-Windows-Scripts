<#
.SYNOPSIS
    Clear-TempAndCache.ps1 - Shows how much space temp folders and caches use, and
    clears them only when you ask.

.DESCRIPTION
    Measures these locations (each one is optional to clean):
      UserTemp        Your temp folder (%TEMP%)
      WindowsTemp     C:\Windows\Temp                              (admin to clean)
      Edge            Microsoft Edge cache, all profiles
      Chrome          Google Chrome cache, all profiles
      Brave           Brave cache, all profiles
      Firefox         Firefox cache, all profiles
      ThumbCache      Explorer thumbnail cache (rebuilds itself)
      CrashDumps      %LOCALAPPDATA%\CrashDumps and Windows Error Reporting files
      DeliveryOpt     Delivery Optimization cache                  (admin to clean)
      WindowsUpdate   C:\Windows\SoftwareDistribution\Download     (admin to clean)

    Browser caches only - never cookies, history, passwords or sign-ins.
    Only files older than -OlderThanDays (default 2) are counted, so anything an
    app is using right now is left alone.

    Safety level : SAFE by default. With no switches it is a PREVIEW: it only
                   measures and lists sizes. Nothing is deleted unless you pass
                   -Clean, and even then it asks you to type YES first (skip the
                   prompt with -Force). Files in use are skipped, not forced.
                   No network calls. Nothing goes to the Recycle Bin, so a clean
                   can't be undone - but these are all caches Windows and apps
                   rebuild on their own.

    Admin        : Preview works without admin (some system folders may read as
                   partial). Cleaning WindowsTemp, DeliveryOpt and WindowsUpdate
                   needs admin; without it those are skipped. WindowsUpdate briefly
                   stops and restarts the Windows Update service (wuauserv) and BITS.

.PARAMETER Clean
    Actually delete the files found. Without this the script is preview-only.

.PARAMETER Force
    With -Clean, skip the "type YES" confirmation.

.PARAMETER Include
    Only these locations (names from the list above). Default: all.

.PARAMETER Exclude
    Skip these locations.

.PARAMETER OlderThanDays
    Only touch files last modified more than this many days ago. Default 2. Use 0
    for everything that isn't locked.

.PARAMETER CloseBrowsers
    With -Clean, close Edge, Chrome, Brave and Firefox first so their caches
    aren't locked. Without it, open browsers are skipped and you're told to close them.

.EXAMPLE
    .\Clear-TempAndCache.ps1
    Preview: how much each location uses.
.EXAMPLE
    .\Clear-TempAndCache.ps1 -Clean -Include UserTemp,Edge,Chrome
.EXAMPLE
    # As admin, everything including the Windows Update download cache
    .\Clear-TempAndCache.ps1 -Clean -CloseBrowsers

.NOTES
    Undo: not possible after -Clean, but every location here is a cache that
    refills as needed. Run the preview first.
#>
[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$Force,
    [ValidateSet('UserTemp','WindowsTemp','Edge','Chrome','Brave','Firefox','ThumbCache','CrashDumps','DeliveryOpt','WindowsUpdate')]
    [string[]]$Include,
    [ValidateSet('UserTemp','WindowsTemp','Edge','Chrome','Brave','Firefox','ThumbCache','CrashDumps','DeliveryOpt','WindowsUpdate')]
    [string[]]$Exclude,
    [ValidateRange(0, 3650)][int]$OlderThanDays = 2,
    [switch]$CloseBrowsers
)

$ErrorActionPreference = 'SilentlyContinue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$cutoff  = (Get-Date).AddDays(-$OlderThanDays)
$local   = $env:LOCALAPPDATA
$roam    = $env:APPDATA

function Format-Size([double]$b) {
    if ($b -ge 1GB) { '{0:N2} GB' -f ($b / 1GB) }
    elseif ($b -ge 1MB) { '{0:N1} MB' -f ($b / 1MB) }
    elseif ($b -ge 1KB) { '{0:N0} KB' -f ($b / 1KB) }
    else { "$([int]$b) B" }
}

# Expand browser profile folders (Default, Profile 1, ...) into their cache folders.
function Get-ChromiumCaches([string]$userData) {
    if (-not (Test-Path -LiteralPath $userData)) { return @() }
    Get-ChildItem -LiteralPath $userData -Directory |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' -or $_.Name -eq 'Guest Profile' } |
        ForEach-Object {
            foreach ($sub in 'Cache', 'Code Cache', 'GPUCache', 'Service Worker\CacheStorage') {
                Join-Path $_.FullName $sub
            }
        }
}
function Get-FirefoxCaches {
    $root = Join-Path $local 'Mozilla\Firefox\Profiles'
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    Get-ChildItem -LiteralPath $root -Directory | ForEach-Object { Join-Path $_.FullName 'cache2' }
}

# Each target: paths to scan, file filter, whether cleaning needs admin, process names that lock it.
$targets = [ordered]@{
    UserTemp      = @{ Paths = @($env:TEMP); Admin = $false; Procs = @() }
    WindowsTemp   = @{ Paths = @("$env:SystemRoot\Temp"); Admin = $true; Procs = @() }
    Edge          = @{ Paths = @(Get-ChromiumCaches "$local\Microsoft\Edge\User Data"); Admin = $false; Procs = @('msedge') }
    Chrome        = @{ Paths = @(Get-ChromiumCaches "$local\Google\Chrome\User Data"); Admin = $false; Procs = @('chrome') }
    Brave         = @{ Paths = @(Get-ChromiumCaches "$local\BraveSoftware\Brave-Browser\User Data"); Admin = $false; Procs = @('brave') }
    Firefox       = @{ Paths = @(Get-FirefoxCaches); Admin = $false; Procs = @('firefox') }
    ThumbCache    = @{ Paths = @("$local\Microsoft\Windows\Explorer"); Filter = 'thumbcache_*.db'; Admin = $false; Procs = @() }
    CrashDumps    = @{ Paths = @("$local\CrashDumps", "$local\Microsoft\Windows\WER\ReportArchive", "$local\Microsoft\Windows\WER\ReportQueue"); Admin = $false; Procs = @() }
    DeliveryOpt   = @{ Paths = @("$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"); Admin = $true; Procs = @() }
    WindowsUpdate = @{ Paths = @("$env:SystemRoot\SoftwareDistribution\Download"); Admin = $true; Procs = @() }
}

$names = @($targets.Keys)
if ($Include) { $names = $names | Where-Object { $_ -in $Include } }
if ($Exclude) { $names = $names | Where-Object { $_ -notin $Exclude } }

Write-Host ""
Write-Host ("Temp and cache " + $(if ($Clean) { 'CLEAN' } else { 'PREVIEW (nothing will be deleted)' })) -ForegroundColor Cyan
Write-Host "Counting files older than $OlderThanDays day(s)." -ForegroundColor DarkGray
if (-not $isAdmin) { Write-Host "[i] Not admin: system folders may be partly unreadable and won't be cleaned." -ForegroundColor Yellow }
Write-Host ""

# ---- Measure ----
$report = foreach ($n in $names) {
    $t = $targets[$n]
    $filter = if ($t.Filter) { $t.Filter } else { '*' }
    $files = foreach ($p in $t.Paths) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            $recurse = -not $t.Filter
            Get-ChildItem -LiteralPath $p -Filter $filter -File -Force -Recurse:$recurse |
                Where-Object { $_.LastWriteTime -lt $cutoff }
        }
    }
    $files = @($files)
    $running = @($t.Procs | Where-Object { Get-Process -Name $_ })
    [pscustomobject]@{
        Location  = $n
        Files     = $files.Count
        Bytes     = [double](($files | Measure-Object Length -Sum).Sum)
        Size      = Format-Size (($files | Measure-Object Length -Sum).Sum)
        Note      = @(
                        if ($t.Admin -and -not $isAdmin) { 'needs admin to clean' }
                        if ($running.Count) { 'browser open' }
                        if (-not ($t.Paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) { 'not found' }
                    ) -join ', '
        FileList  = $files
        NeedAdmin = $t.Admin
        Procs     = $t.Procs
    }
}

$report | Sort-Object Bytes -Descending | Format-Table Location, Files, Size, Note -AutoSize
$total = ($report | Measure-Object Bytes -Sum).Sum
Write-Host ("Total reclaimable: {0}" -f (Format-Size $total)) -ForegroundColor Green

$free = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))
if ($free) { Write-Host ("Free space on {0}: {1}" -f $env:SystemDrive, (Format-Size $free.Free)) -ForegroundColor DarkGray }

if (-not $Clean) {
    Write-Host ""
    Write-Host "Preview only. To delete, run again with -Clean (add -Include to pick locations)." -ForegroundColor Yellow
    return
}

# ---- Clean ----
$toClean = @($report | Where-Object { $_.Files -gt 0 -and -not ($_.NeedAdmin -and -not $isAdmin) })
if (-not $toClean) { Write-Host "Nothing to clean." ; return }

if ($CloseBrowsers) {
    $procs = $toClean | ForEach-Object { $_.Procs } | Select-Object -Unique
    foreach ($p in $procs) {
        if (Get-Process -Name $p) {
            Write-Host "Closing $p..." -ForegroundColor DarkGray
            Get-Process -Name $p | ForEach-Object { [void]$_.CloseMainWindow() }
            Start-Sleep -Seconds 3
            Get-Process -Name $p | Stop-Process
        }
    }
} else {
    $open = $toClean | Where-Object { @($_.Procs | Where-Object { Get-Process -Name $_ }).Count }
    foreach ($o in $open) { Write-Host "[skip] $($o.Location): browser is open. Close it or use -CloseBrowsers." -ForegroundColor Yellow }
    $toClean = @($toClean | Where-Object { $_ -notin $open })
}
if (-not $toClean) { Write-Host "Nothing left to clean." ; return }

$sum = Format-Size (($toClean | Measure-Object Bytes -Sum).Sum)
if (-not $Force) {
    Write-Host ""
    Write-Host ("About to permanently delete {0} from: {1}" -f $sum, (($toClean.Location) -join ', ')) -ForegroundColor Red
    $answer = Read-Host "Type YES to continue"
    if ($answer -cne 'YES') { Write-Host "Cancelled. Nothing deleted."; return }
}

$wuStopped = $false
if ($toClean.Location -contains 'WindowsUpdate') {
    Write-Host "Stopping Windows Update and BITS services..." -ForegroundColor DarkGray
    Stop-Service -Name wuauserv, bits -Force
    $wuStopped = $true
}

$freed = 0; $skipped = 0
try {
    foreach ($r in $toClean) {
        $ok = 0
        foreach ($f in $r.FileList) {
            try {
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                $freed += $f.Length; $ok++
            } catch { $skipped++ }
        }
        Write-Host ("  {0,-14} removed {1} file(s)" -f $r.Location, $ok)
    }
} finally {
    if ($wuStopped) {
        Start-Service -Name bits, wuauserv
        Write-Host "Windows Update and BITS services restarted." -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host ("Freed {0}. {1} file(s) were in use and left alone." -f (Format-Size $freed), $skipped) -ForegroundColor Green
