<#
.SYNOPSIS
    Find-AppLeftovers.ps1 - Find folders left behind by apps you already
    uninstalled (AppData, ProgramData, Program Files) and Start Menu or
    Desktop shortcuts whose target no longer exists. Read-only by default;
    sends items to the Recycle Bin only when you ask and confirm each one.

.DESCRIPTION
    Uninstallers often leave settings, caches and logs behind. Over a few
    years that adds up to gigabytes in folders like %LOCALAPPDATA%\SomeOldGame
    or C:\ProgramData\TrialWare that nothing uses any more. This script lists
    the top-level folders in:

      Roaming        %APPDATA%
      Local          %LOCALAPPDATA%
      LocalPrograms  %LOCALAPPDATA%\Programs
      ProgramData    %ProgramData%
      ProgramFiles   C:\Program Files and C:\Program Files (x86)

    and compares each one with what is still on the PC: installed programs
    (both registry uninstall lists, machine and user), Store apps, services,
    startup entries and scheduled tasks. A folder that matches none of them,
    and is not a known Windows folder, is reported as a likely leftover:

      High    No match, nothing inside changed in -Days days (default 180)
      Medium  No match, but something inside changed recently (could be a
              portable app, a game launcher's data, or a tool you still use)
      Empty   Folder holds no files at all

    It also finds .lnk shortcuts on your Start Menu (your Programs folder and
    the all-users one) and on your Desktop (yours and the Public Desktop)
    whose target file or folder is gone. Advertised shortcuts, web links,
    bare names, and targets on a drive that isn't plugged in are skipped so
    they are not flagged by mistake.

    It ends with the total space you could free (High and Empty folders plus
    broken shortcuts). Matching is by name, so always read the list before
    removing anything: a folder named after a company (for example "Mozilla")
    is kept if any installed app has that publisher.

    Safety level : SAFE by default (read-only). -Recycle asks about each High
                   or Empty folder and each broken shortcut one at a time
                   (y/N) and sends it to the Recycle Bin, so it can be
                   restored. Nothing is ever permanently deleted. Junctions
                   and links are never followed or removed. No network calls.
                   Optional file written: -CsvPath.

    Admin        : Not required. Without admin a few ProgramData and Program
                   Files folders can't be sized fully (shown as "partial"),
                   and -Recycle skips folders you don't have rights to.

.PARAMETER Days
    A folder counts as High confidence only if nothing inside changed in this
    many days. Default 180.

.PARAMETER MinSizeMB
    Hide leftover folders smaller than this many MB (empty folders and broken
    shortcuts are always shown). Default 1.

.PARAMETER OlderThanDays
    Only show leftover folders (and broken shortcuts) whose newest item is
    older than this many days. Default 0, which turns the filter off.

.PARAMETER Scope
    Which folder locations to check. Default: all of Roaming, Local,
    LocalPrograms, ProgramData, ProgramFiles. Shortcuts are always checked.

.PARAMETER ShowMatched
    Also list folders that matched an installed app, with what they matched.

.PARAMETER CsvPath
    Export every folder checked (leftover or not) and every broken shortcut
    to a CSV.

.PARAMETER Recycle
    After the report, offer each High or Empty folder and each broken
    shortcut for removal one at a time. Answer y to send it to the Recycle
    Bin, anything else to keep it.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-AppLeftovers.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-AppLeftovers.ps1 -Scope Roaming,Local -Days 365 -ShowMatched

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-AppLeftovers.ps1 -MinSizeMB 10 -OlderThanDays 365 -CsvPath "$env:USERPROFILE\Desktop\leftovers.csv"

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-AppLeftovers.ps1 -Recycle

.NOTES
    Works in Windows PowerShell 5.1 and PowerShell 7 on Windows 10/11.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$Days = 180,

    [ValidateRange(0, 1000000)]
    [int]$MinSizeMB = 1,

    [ValidateRange(0, 3650)]
    [int]$OlderThanDays = 0,

    [ValidateSet('Roaming', 'Local', 'LocalPrograms', 'ProgramData', 'ProgramFiles')]
    [string[]]$Scope = @('Roaming', 'Local', 'LocalPrograms', 'ProgramData', 'ProgramFiles'),

    [switch]$ShowMatched,

    [string]$CsvPath,

    [switch]$Recycle
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT' -and -not $env:FINDAPPLEFTOVERS_TEST) {
    Write-Error 'This script runs on Windows only.'
    exit 1
}

# ---------------------------------------------------------------- helpers ----

function Get-Norm([string]$Text) {
    # lower-case letters and digits only: "Visual Studio Code" -> "visualstudiocode"
    if (-not $Text) { return '' }
    return (($Text.ToLowerInvariant()) -replace '[^a-z0-9]', '')
}

function Format-Size([double]$Bytes) {
    if ($Bytes -ge 1GB) { return '{0:N1} GB' -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return '{0:N0} MB' -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return '{0:N0} KB' -f ($Bytes / 1KB) }
    return '{0:N0} B' -f $Bytes
}

function Test-LeftoverVisible {
    # Empty folders always pass the size filter; -OlderThanDays 0 turns age off.
    param(
        [int]$Files,
        [double]$SizeMB,
        [datetime]$Newest,
        [int]$MinSizeMB,
        [int]$OlderThanDays,
        [datetime]$Now = ([datetime]::Now),
        [switch]$IsShortcut
    )
    if (-not $IsShortcut -and $Files -gt 0 -and $SizeMB -lt $MinSizeMB) { return $false }
    if ($OlderThanDays -gt 0 -and $Newest -ge $Now.AddDays(-$OlderThanDays)) { return $false }
    return $true
}

function Test-BrokenTarget {
    # $true when $TargetPath looks like a real local path that is gone.
    # Empty, URL, UNC, bare names, and missing drive letters are not flagged.
    param(
        [string]$TargetPath,
        [scriptblock]$TestExists = { param($Path) Test-Path -LiteralPath $Path }
    )
    if ([string]::IsNullOrWhiteSpace($TargetPath)) { return $false }
    $t = [Environment]::ExpandEnvironmentVariables($TargetPath.Trim().Trim('"'))
    if ([string]::IsNullOrWhiteSpace($t)) { return $false }
    if ($t -match '^(https?:|mailto:|ms-settings:|shell:|file://|steam:|microsoft-edge:)') { return $false }
    if ($t.StartsWith('\\')) { return $false }
    # Bare names ("notepad.exe") may resolve via PATH; don't flag them.
    if ($t -notmatch '[\\/]' -and $t -notmatch '^[A-Za-z]:') { return $false }
    if ($t -match '^([A-Za-z]):') {
        $driveRoot = $Matches[1] + ':\'
        if (-not (& $TestExists $driveRoot)) { return $false }
    }
    return -not (& $TestExists $t)
}

function Get-LnkFiles([string]$Root) {
    # Recurse for *.lnk; never follow junctions or symlinks.
    $found = New-Object System.Collections.Generic.List[string]
    if (-not $Root -or -not (Test-Path -LiteralPath $Root)) { return @($found) }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            $info = New-Object System.IO.DirectoryInfo($dir)
            foreach ($item in $info.EnumerateFileSystemInfos()) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($item -is [IO.DirectoryInfo]) {
                    $stack.Push($item.FullName)
                } elseif ([string]::Equals($item.Extension, '.lnk', [StringComparison]::OrdinalIgnoreCase)) {
                    $found.Add($item.FullName)
                }
            }
        } catch {
            # unreadable folder: skip
        }
    }
    return @($found)
}

function Get-ShortcutRoots {
    $desktop = ''
    $publicDesktop = ''
    try { $desktop = [Environment]::GetFolderPath('Desktop') } catch { }
    try { $publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory') } catch { }
    if (-not $desktop -and $env:USERPROFILE) { $desktop = Join-Path $env:USERPROFILE 'Desktop' }
    if (-not $publicDesktop -and $env:PUBLIC) { $publicDesktop = Join-Path $env:PUBLIC 'Desktop' }
    $roaming = $env:APPDATA
    $programData = $env:ProgramData
    $roots = @()
    if ($roaming)     { $roots += [pscustomobject]@{ Name = 'StartMenu';         Path = (Join-Path $roaming     'Microsoft\Windows\Start Menu\Programs') } }
    if ($programData) { $roots += [pscustomobject]@{ Name = 'StartMenuAllUsers'; Path = (Join-Path $programData 'Microsoft\Windows\Start Menu\Programs') } }
    if ($desktop)     { $roots += [pscustomobject]@{ Name = 'Desktop';           Path = $desktop } }
    if ($publicDesktop) { $roots += [pscustomobject]@{ Name = 'PublicDesktop';   Path = $publicDesktop } }
    return $roots
}

function Measure-Folder([string]$Path) {
    # Total size, file count and newest LastWriteTime under $Path.
    # Never follows junctions/symlinks; unreadable folders mark the result partial.
    $size = [double]0; $files = 0; $partial = $false
    $newest = (Get-Item -LiteralPath $Path -Force).LastWriteTime
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            $info = New-Object System.IO.DirectoryInfo($dir)
            foreach ($item in $info.EnumerateFileSystemInfos()) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($item -is [IO.DirectoryInfo]) {
                    $stack.Push($item.FullName)
                } else {
                    $size += $item.Length
                    $files++
                }
                if ($item.LastWriteTime -gt $newest) { $newest = $item.LastWriteTime }
            }
        } catch {
            $partial = $true
        }
    }
    [pscustomobject]@{ Bytes = $size; Files = $files; Newest = $newest; Partial = $partial }
}

# Folders that belong to Windows itself, shared runtimes or common drivers.
# Short or generic names must match exactly; longer ones match as a prefix.
function Test-SystemFolder([string]$Norm) {
    $systemExact = @(
        'tmp', 'temp', 'cache', 'logs', 'log', 'data', 'ssl', 'wer', 'pip', 'npm', 'ati', 'amd', 'hp', 'msi',
        'elan', 'wsl', 'ssh', 'gnupg', 'history', 'desktop', 'documents', 'templates', 'favorites', 'programs',
        'packages', 'comms', 'publishers', 'containers', 'sqm', 'edge', 'teams', 'office', 'skype', 'dell', 'asus', 'acer'
    ) | ForEach-Object { Get-Norm $_ }
    $systemPrefixes = @(
        'microsoft', 'windows', 'connecteddevicesplatform', 'd3dscache', 'crashdumps', 'peerdistrepub',
        'packagecache', 'commonfiles', 'internetexplorer', 'modifiablewindowsapps', 'referenceassemblies',
        'msbuild', 'dotnet', 'packagemanagement', 'powershell', 'regid', 'usoshared', 'usoprivate',
        'softwaredistribution', 'applicationdata', 'temporaryinternetfiles', 'isolatedstorage', 'virtualstore',
        'startmenu', 'mozillamaintenanceservice', 'nvidia', 'intel', 'realtek', 'dolby', 'synaptics',
        'conexant', 'lenovo', 'hewlettpackard', 'qualcomm', 'mediatek', 'broadcom', 'uninstallinformation',
        'defaultuser', 'ssodata', 'docker', 'nodegyp', 'fontcache', 'iconcache', 'gamedvr', 'xboxlive',
        'onedrive', 'officesoftwareprotectionplatform', 'clicktorun', 'devicesync', 'devicemetadatastore',
        'appvagent', 'mspcache', 'desktopenginev2', 'msedge', 'edgeupdate', 'edgewebview'
    ) | ForEach-Object { Get-Norm $_ }
    if ($Norm.Length -lt 2) { return $true }
    if ($systemExact -contains $Norm) { return $true }
    foreach ($p in $systemPrefixes) { if ($Norm.StartsWith($p)) { return $true } }
    if ($Norm -match '^[0-9a-f]{8,}$') { return $true }  # GUID- or hash-named folders: too risky to call leftovers
    return $false
}

# When the test harness dotsources this file, stop before any Windows-only work.
if ($env:FINDAPPLEFTOVERS_TEST) { return }

# ---------------------------------------------------- what is installed ----

Write-Host 'Collecting installed apps, services, startup entries and tasks...' -ForegroundColor Cyan

$names = New-Object System.Collections.Generic.List[object]   # objects: Norm, Label
$paths = New-Object System.Collections.Generic.List[string]   # lower-case paths in use

function Add-Name([string]$Text, [string]$Label) {
    $n = Get-Norm $Text
    if ($n.Length -ge 3) { $names.Add([pscustomobject]@{ Norm = $n; Label = $Label }) }
}

function Add-PathRef([string]$Text) {
    if (-not $Text) { return }
    $t = [Environment]::ExpandEnvironmentVariables($Text).Trim().TrimStart('"').ToLowerInvariant()
    # "C:\Program Files\App\app.exe" -args  ->  c:\program files\app\app.exe
    if ($t -match '^(.*?\.(exe|dll|sys|cmd|bat|ps1|com))(\W|$)') { $t = $Matches[1] }
    $t = $t.Trim('"').TrimEnd('\')
    if ($t -match '^[a-z]:\\') { $paths.Add($t) }
}

$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$appCount = 0
foreach ($key in $uninstallKeys) {
    foreach ($e in @(Get-ItemProperty -Path $key -ErrorAction SilentlyContinue)) {
        $dn = $e.PSObject.Properties['DisplayName']
        if (-not $dn -or -not $dn.Value) { continue }
        $appCount++
        $label = "installed: $($dn.Value)"
        Add-Name $dn.Value $label
        # the first word of the app name ("Steam", "Discord", "Audacity 3.4" -> "audacity")
        $first = ($dn.Value -split '[\s\-_\(\.,]+')[0]
        if ((Get-Norm $first).Length -ge 4) { Add-Name $first $label }
        foreach ($prop in 'Publisher', 'InstallLocation', 'DisplayIcon', 'UninstallString') {
            $p = $e.PSObject.Properties[$prop]
            if (-not $p -or -not $p.Value) { continue }
            if ($prop -eq 'Publisher') {
                Add-Name $p.Value "publisher: $($p.Value)"
                $pub = ($p.Value -split '[\s,\.]+')[0]
                if ((Get-Norm $pub).Length -ge 4) { Add-Name $pub "publisher: $($p.Value)" }
            } else {
                Add-PathRef ([string]$p.Value)
            }
        }
    }
}

$storeCount = 0
try {
    foreach ($pkg in @(Get-AppxPackage -ErrorAction Stop)) {
        $storeCount++
        $label = "store app: $($pkg.Name)"
        Add-Name $pkg.Name $label
        foreach ($part in ($pkg.Name -split '\.')) { if ((Get-Norm $part).Length -ge 4) { Add-Name $part $label } }
        if ($pkg.PSObject.Properties['PublisherDisplayName'] -and $pkg.PublisherDisplayName) { Add-Name $pkg.PublisherDisplayName $label }
        if ($pkg.InstallLocation) { Add-PathRef $pkg.InstallLocation }
    }
} catch { Write-Verbose "Store app list unavailable: $($_.Exception.Message)" }

$svcCount = 0
foreach ($svc in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
    $svcCount++
    Add-PathRef $svc.PathName
}

foreach ($runKey in 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
    $item = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
    if (-not $item) { continue }
    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -notlike 'PS*') { Add-PathRef ([string]$p.Value) }
    }
}

$taskCount = 0
try {
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
        $taskCount++
        foreach ($a in @($task.Actions)) {
            if ($a.PSObject.Properties['Execute'] -and $a.Execute) { Add-PathRef $a.Execute }
        }
    }
} catch { Write-Verbose "Scheduled tasks unavailable: $($_.Exception.Message)" }

$paths = @($paths | Sort-Object -Unique)
Write-Host ("  {0} installed programs, {1} Store apps, {2} services, {3} scheduled tasks" -f $appCount, $storeCount, $svcCount, $taskCount)

function Find-Match([string]$FolderName, [string]$FullPath) {
    $fp = $FullPath.ToLowerInvariant().TrimEnd('\') + '\'
    foreach ($p in $paths) {
        if ($p.StartsWith($fp) -or ($p + '\').StartsWith($fp)) { return "in use by: $p" }
    }
    $fn = Get-Norm $FolderName
    foreach ($n in $names) {
        if ($n.Norm -eq $fn) { return $n.Label }
        if ($fn.Length -ge 4 -and $n.Norm.Contains($fn)) { return $n.Label }
        if ($n.Norm.Length -ge 4 -and $fn.Contains($n.Norm)) { return $n.Label }
    }
    return $null
}

# ---------------------------------------------------------- scan folders ----

$locations = @()
if ($Scope -contains 'Roaming')       { $locations += [pscustomobject]@{ Name = 'Roaming';       Path = $env:APPDATA } }
if ($Scope -contains 'Local')         { $locations += [pscustomobject]@{ Name = 'Local';         Path = $env:LOCALAPPDATA } }
if ($Scope -contains 'LocalPrograms') { $locations += [pscustomobject]@{ Name = 'LocalPrograms'; Path = (Join-Path $env:LOCALAPPDATA 'Programs') } }
if ($Scope -contains 'ProgramData')   { $locations += [pscustomobject]@{ Name = 'ProgramData';   Path = $env:ProgramData } }
if ($Scope -contains 'ProgramFiles') {
    $locations += [pscustomobject]@{ Name = 'ProgramFiles'; Path = $env:ProgramFiles }
    if (${env:ProgramFiles(x86)}) { $locations += [pscustomobject]@{ Name = 'ProgramFiles'; Path = ${env:ProgramFiles(x86)} } }
}

$cutoff = (Get-Date).AddDays(-$Days)
$now = Get-Date
$results = New-Object System.Collections.Generic.List[object]

foreach ($loc in $locations) {
    if (-not $loc.Path -or -not (Test-Path -LiteralPath $loc.Path)) { continue }
    Write-Host "Checking $($loc.Name): $($loc.Path)" -ForegroundColor Cyan
    $dirs = @(Get-ChildItem -LiteralPath $loc.Path -Directory -Force -ErrorAction SilentlyContinue |
              Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
    $i = 0
    foreach ($d in $dirs) {
        $i++
        Write-Progress -Activity "Checking $($loc.Name)" -Status $d.Name -PercentComplete ([int](100 * $i / [math]::Max(1, $dirs.Count)))
        $norm = Get-Norm $d.Name
        if ($loc.Name -eq 'Local' -and $norm -eq 'programs') { continue }   # scanned separately
        if (Test-SystemFolder $norm) {
            $match = 'Windows / system folder'
        } else {
            $match = Find-Match $d.Name $d.FullName
        }
        if ($match -and -not $ShowMatched -and -not $CsvPath) { continue }

        $m = Measure-Folder $d.FullName
        if ($match) {
            $verdict = 'Matched'
        } elseif ($m.Files -eq 0) {
            $verdict = 'Empty'
        } elseif ($m.Newest -lt $cutoff) {
            $verdict = 'High'
        } else {
            $verdict = 'Medium'
        }
        $results.Add([pscustomobject]@{
            Kind         = 'Folder'
            Location     = $loc.Name
            Folder       = $d.Name
            Verdict      = $verdict
            SizeMB       = [math]::Round($m.Bytes / 1MB, 1)
            Size         = (Format-Size $m.Bytes) + $(if ($m.Partial) { ' (partial)' } else { '' })
            Files        = $m.Files
            LastChanged  = $m.Newest.ToString('yyyy-MM-dd')
            Newest       = $m.Newest
            MatchedTo    = $match
            Target       = ''
            Path         = $d.FullName
            Bytes        = $m.Bytes
        })
    }
    Write-Progress -Activity "Checking $($loc.Name)" -Completed
}

# ------------------------------------------------------ broken shortcuts ----

Write-Host 'Checking Start Menu and Desktop shortcuts...' -ForegroundColor Cyan
$shortcuts = New-Object System.Collections.Generic.List[object]
$shell = $null
try {
    $shell = New-Object -ComObject WScript.Shell
} catch {
    Write-Host "  Could not read shortcuts: $($_.Exception.Message)" -ForegroundColor DarkGray
}

if ($shell) {
    try {
        $roots = @(Get-ShortcutRoots)
        foreach ($root in $roots) {
            $lnks = @(Get-LnkFiles $root.Path)
            $i = 0
            foreach ($lnkPath in $lnks) {
                $i++
                Write-Progress -Activity "Checking $($root.Name) shortcuts" -Status $lnkPath -PercentComplete ([int](100 * $i / [math]::Max(1, $lnks.Count)))
                try {
                    $lnk = $shell.CreateShortcut($lnkPath)
                    $target = [string]$lnk.TargetPath
                } catch {
                    continue
                }
                if (-not (Test-BrokenTarget $target)) { continue }
                try {
                    $item = Get-Item -LiteralPath $lnkPath -Force -ErrorAction Stop
                } catch {
                    continue
                }
                $shortcuts.Add([pscustomobject]@{
                    Kind         = 'Shortcut'
                    Location     = $root.Name
                    Folder       = $item.Name
                    Verdict      = 'Broken'
                    SizeMB       = [math]::Round($item.Length / 1MB, 1)
                    Size         = Format-Size $item.Length
                    Files        = 1
                    LastChanged  = $item.LastWriteTime.ToString('yyyy-MM-dd')
                    Newest       = $item.LastWriteTime
                    MatchedTo    = ''
                    Target       = $target
                    Path         = $item.FullName
                    Bytes        = [double]$item.Length
                })
            }
            Write-Progress -Activity "Checking $($root.Name) shortcuts" -Completed
        }
    } finally {
        try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } catch { }
    }
}

# ---------------------------------------------------------------- report ----

$leftovers = @($results | Where-Object {
        $_.Verdict -ne 'Matched' -and
        (Test-LeftoverVisible -Files $_.Files -SizeMB $_.SizeMB -Newest $_.Newest -MinSizeMB $MinSizeMB -OlderThanDays $OlderThanDays -Now $now)
    } | Sort-Object @{ Expression = { switch ($_.Verdict) { 'High' { 0 } 'Empty' { 1 } default { 2 } } } }, @{ Expression = 'Bytes'; Descending = $true })

$broken = @($shortcuts | Where-Object {
        Test-LeftoverVisible -Files $_.Files -SizeMB $_.SizeMB -Newest $_.Newest -MinSizeMB $MinSizeMB -OlderThanDays $OlderThanDays -Now $now -IsShortcut
    } | Sort-Object Location, Folder)

Write-Host ''
Write-Host '=== Likely leftovers ===' -ForegroundColor Yellow
if ($leftovers.Count -eq 0) {
    if ($MinSizeMB -gt 1 -or $OlderThanDays -gt 0) {
        Write-Host 'None found that meet the size and age filters. Every other folder matched an installed app or Windows itself.' -ForegroundColor Green
    } else {
        Write-Host 'None found. Every folder matched an installed app or Windows itself.' -ForegroundColor Green
    }
} else {
    $leftovers | Format-Table -AutoSize -Wrap Verdict, Location, Folder, Size, Files, LastChanged, Path | Out-Host
}

Write-Host '=== Broken shortcuts ===' -ForegroundColor Yellow
if ($broken.Count -eq 0) {
    Write-Host 'None found. Every Start Menu and Desktop shortcut points to something that still exists (or was skipped as a web link, advertised shortcut, or a target on a drive that is not plugged in).' -ForegroundColor Green
} else {
    $broken | Format-Table -AutoSize -Wrap Location, Folder, Target, LastChanged, Path | Out-Host
}

if ($ShowMatched) {
    Write-Host '=== Matched folders (kept) ===' -ForegroundColor Cyan
    $results | Where-Object { $_.Verdict -eq 'Matched' } | Sort-Object Bytes -Descending |
        Format-Table -AutoSize -Wrap Location, Folder, Size, LastChanged, MatchedTo | Out-Host
}

$high   = @($leftovers | Where-Object { $_.Verdict -eq 'High' })
$empty  = @($leftovers | Where-Object { $_.Verdict -eq 'Empty' })
$medium = @($leftovers | Where-Object { $_.Verdict -eq 'Medium' })
$highBytes = ($high | Measure-Object -Property Bytes -Sum).Sum
$medBytes  = ($medium | Measure-Object -Property Bytes -Sum).Sum
$emptyBytes = ($empty | Measure-Object -Property Bytes -Sum).Sum
$brokenBytes = ($broken | Measure-Object -Property Bytes -Sum).Sum
if (-not $highBytes) { $highBytes = 0 }
if (-not $medBytes)  { $medBytes = 0 }
if (-not $emptyBytes) { $emptyBytes = 0 }
if (-not $brokenBytes) { $brokenBytes = 0 }
$freeable = $highBytes + $emptyBytes + $brokenBytes

Write-Host '=== Summary ===' -ForegroundColor Yellow
Write-Host ("  High confidence : {0} folders, {1} (nothing changed in {2} days)" -f $high.Count, (Format-Size $highBytes), $Days)
Write-Host ("  Empty           : {0} folders" -f $empty.Count)
Write-Host ("  Medium          : {0} folders, {1} (changed recently; check before removing)" -f $medium.Count, (Format-Size $medBytes))
Write-Host ("  Broken shortcuts: {0}" -f $broken.Count)
Write-Host ("  Space you could free: {0} (High and Empty folders + broken shortcuts)" -f (Format-Size $freeable)) -ForegroundColor Green
if (@($results | Where-Object { $_.Size -like '*(partial)' }).Count -gt 0) {
    Write-Host '  Some folders could not be read fully; sizes marked (partial). Run as admin for full sizes.' -ForegroundColor DarkGray
}
Write-Host ''
Write-Host 'Tips:' -ForegroundColor Cyan
Write-Host '  - A folder named after a game or app you still use from a USB drive or launcher shows up as Medium; keep it.'
Write-Host '  - Program Files leftovers often hold license files or saved settings; check inside before removing.'
Write-Host '  - A broken shortcut is only the .lnk file; the leftover folder, if any, is listed separately above.'
Write-Host '  - Removing with -Recycle sends folders and shortcuts to the Recycle Bin, so you can restore them if an app complains.'

if ($CsvPath) {
    $csvRows = @($results) + @($shortcuts)
    $csvRows | Select-Object Kind, Location, Folder, Verdict, SizeMB, Files, LastChanged, MatchedTo, Target, Path |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Saved CSV: $CsvPath" -ForegroundColor Green
}

# --------------------------------------------------------------- recycle ----

if ($Recycle) {
    $candidates = @($high) + @($empty) + @($broken)
    if ($candidates.Count -eq 0) {
        Write-Host 'Nothing to recycle: no High or Empty folders, and no broken shortcuts.' -ForegroundColor Green
        return
    }
    Add-Type -AssemblyName Microsoft.VisualBasic
    Write-Host ''
    Write-Host "Reviewing $($candidates.Count) items. Each goes to the Recycle Bin only if you type y." -ForegroundColor Yellow
    $freed = [double]0; $moved = 0
    foreach ($c in $candidates) {
        if ($c.Kind -eq 'Shortcut') {
            $prompt = 'Recycle shortcut {0} (target was {1})? [y/N]' -f $c.Path, $c.Target
        } else {
            $prompt = 'Recycle {0} ({1}, last changed {2})? [y/N]' -f $c.Path, $c.Size, $c.LastChanged
        }
        $answer = Read-Host $prompt
        if ($answer -notmatch '^(y|yes)$') { continue }
        $item = Get-Item -LiteralPath $c.Path -Force -ErrorAction SilentlyContinue
        if (-not $item -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Write-Host '  Skipped: item is gone or is a link.' -ForegroundColor DarkGray
            continue
        }
        try {
            if ($c.Kind -eq 'Shortcut') {
                if ($item.PSIsContainer) {
                    Write-Host '  Skipped: expected a shortcut file.' -ForegroundColor DarkGray
                    continue
                }
                [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(
                    $c.Path,
                    [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
                    [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
            } else {
                [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(
                    $c.Path,
                    [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
                    [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
            }
            $freed += $c.Bytes; $moved++
            Write-Host '  Sent to Recycle Bin.' -ForegroundColor Green
        } catch {
            Write-Host "  Skipped: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ("Recycled {0} items, {1}. Empty the Recycle Bin to free the space." -f $moved, (Format-Size $freed)) -ForegroundColor Green
}
