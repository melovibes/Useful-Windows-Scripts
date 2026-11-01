<#
.SYNOPSIS
    Get-StartupImpact.ps1 - Read-only report of what starts with Windows and how much
    it slows down boot.

.DESCRIPTION
    Lists everything that launches at sign-in or boot:
      - Startup apps from the Run / RunOnce registry keys (current user and all users,
        64-bit and 32-bit) and both Startup folders, with their Enabled/Disabled state
        from Settings > Apps > Startup (the StartupApproved keys)
      - Non-Microsoft scheduled tasks that run at logon or at boot
      - Non-Microsoft services set to start automatically (and whether delayed)

    For each item that is running right now it reads the CPU time and disk I/O the
    process has used since it started and rates it High / Medium / Low with the same
    cut-offs Task Manager uses (High: over 1 s CPU or 3 MB disk; Medium: over 300 ms
    CPU or 300 KB disk). These are totals since launch, not just during boot, so
    apps that have been open all day can read higher than Task Manager shows.

    It also shows your last boot time, whether Fast Startup is on, and (as admin)
    recent boot durations plus any apps or services Windows itself logged as
    slowing down boot (Diagnostics-Performance events 100, 101 and 103).

    Safety level : SAFE (strictly read-only). Nothing is disabled, stopped or changed.
                   No network calls are made. The only file written is -CsvPath.

    Admin        : Works without admin. Running as admin adds boot-duration history,
                   Windows' own "slowed boot" events, and CPU / disk numbers for
                   services that run as SYSTEM.

.PARAMETER All
    Also show disabled startup apps and items that aren't running.

.PARAMETER Days
    How many days of boot history to read (admin only). Default 30.

.PARAMETER CsvPath
    Optional. Export the full startup list to this CSV file.

.EXAMPLE
    .\Get-StartupImpact.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-StartupImpact.ps1" -All -CsvPath "$env:USERPROFILE\Desktop\startup.csv"

.NOTES
    To turn a startup app off: Settings > Apps > Startup, or Task Manager > Startup apps.
    Undo: nothing to undo - this script changes nothing.
#>
[CmdletBinding()]
param(
    [switch]$All,
    [ValidateRange(1, 365)][int]$Days = 30,
    [string]$CsvPath
)

$ErrorActionPreference = 'SilentlyContinue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[i] Not running as admin: boot history and SYSTEM service numbers will be skipped." -ForegroundColor Yellow
}

# ---------- helpers ----------
function Get-ExePath([string]$CommandLine) {
    # Pull the executable path out of a command line like "C:\x\app.exe" --min or C:\x\app.exe /s
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 1) { return $cmd.Substring(1, $end - 1) }
    }
    if ($cmd -match '^(.+?\.(exe|com|bat|cmd|vbs|js|ps1|lnk))(\s|$)') { return $Matches[1] }
    return ($cmd -split '\s+')[0]
}

function Test-Microsoft([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    $company = (Get-Item -LiteralPath $Path).VersionInfo.CompanyName
    return ($company -match 'Microsoft')
}

function Get-ApprovedState([string]$Hive, [string]$Kind, [string]$Name) {
    # Settings > Apps > Startup stores state here; an odd first byte means disabled.
    $key = "$Hive\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$Kind"
    $val = (Get-ItemProperty -Path $key -Name $Name).$Name
    if ($val -is [byte[]] -and $val.Length -gt 0) {
        if ($val[0] -band 1) { return 'Disabled' } else { return 'Enabled' }
    }
    return 'Enabled'
}

function Get-ImpactRating([double]$CpuSec, [double]$DiskMB) {
    if ($CpuSec -gt 1 -or $DiskMB -gt 3) { return 'High' }
    if ($CpuSec -gt 0.3 -or $DiskMB -gt 0.3) { return 'Medium' }
    return 'Low'
}

# Snapshot of running processes, keyed by executable path
$procs = Get-CimInstance Win32_Process | Where-Object ExecutablePath
$procByPath = @{}
foreach ($p in $procs) {
    $k = $p.ExecutablePath.ToLowerInvariant()
    if (-not $procByPath.ContainsKey($k)) { $procByPath[$k] = @() }
    $procByPath[$k] += $p
}
$procById = @{}
foreach ($p in $procs) { $procById[[int]$p.ProcessId] = $p }

function Measure-Procs($List) {
    $List = @($List | Where-Object { $_ })
    $cpu = 0.0; $io = 0.0; $mem = 0.0
    foreach ($p in $List) {
        $cpu += ([double]$p.KernelModeTime + [double]$p.UserModeTime) / 1e7
        $io  += ([double]$p.ReadTransferCount + [double]$p.WriteTransferCount) / 1MB
        $mem += [double]$p.WorkingSetSize / 1MB
    }
    [pscustomobject]@{ Count = $List.Count; CpuSec = [math]::Round($cpu, 1); DiskMB = [math]::Round($io, 1); MemMB = [math]::Round($mem, 0) }
}

$items = New-Object System.Collections.Generic.List[object]
function Add-Item($Type, $Name, $State, $Command, $Location, $Exe, $ProcList) {
    $m = Measure-Procs $ProcList
    $impact = if ($m.Count -gt 0) { Get-ImpactRating $m.CpuSec $m.DiskMB } else { 'Not running' }
    $items.Add([pscustomobject]@{
        Type     = $Type
        Name     = $Name
        State    = $State
        Impact   = $impact
        CpuSec   = if ($m.Count) { $m.CpuSec } else { $null }
        DiskMB   = if ($m.Count) { $m.DiskMB } else { $null }
        MemMB    = if ($m.Count) { $m.MemMB } else { $null }
        Exe      = $Exe
        Command  = $Command
        Location = $Location
    })
}

# ---------- 1. Run keys ----------
$runKeys = @(
    @{ Hive = 'HKCU:'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';             Kind = 'Run' },
    @{ Hive = 'HKCU:'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce';         Kind = 'Run' },
    @{ Hive = 'HKLM:'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run';             Kind = 'Run' },
    @{ Hive = 'HKLM:'; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce';         Kind = 'Run' },
    @{ Hive = 'HKLM:'; Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Kind = 'Run32' }
)
foreach ($rk in $runKeys) {
    $props = Get-ItemProperty -Path $rk.Path
    if (-not $props) { continue }
    foreach ($prop in $props.PSObject.Properties) {
        if ($prop.Name -like 'PS*') { continue }
        $exe = Get-ExePath ([string]$prop.Value)
        $state = Get-ApprovedState $rk.Hive $rk.Kind $prop.Name
        $list = if ($exe) { $procByPath[$exe.ToLowerInvariant()] } else { @() }
        Add-Item 'Startup app' $prop.Name $state ([string]$prop.Value) $rk.Path $exe $list
    }
}

# ---------- 2. Startup folders ----------
$shell = New-Object -ComObject WScript.Shell
$folders = @(
    @{ Hive = 'HKCU:'; Path = [Environment]::GetFolderPath('Startup') },
    @{ Hive = 'HKLM:'; Path = [Environment]::GetFolderPath('CommonStartup') }
)
foreach ($f in $folders) {
    if (-not $f.Path -or -not (Test-Path $f.Path)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $f.Path -File | Where-Object Name -ne 'desktop.ini') {
        $exe = $file.FullName
        if ($file.Extension -eq '.lnk' -and $shell) { $exe = $shell.CreateShortcut($file.FullName).TargetPath }
        $state = Get-ApprovedState $f.Hive 'StartupFolder' $file.Name
        $list = if ($exe) { $procByPath[$exe.ToLowerInvariant()] } else { @() }
        Add-Item 'Startup folder' $file.BaseName $state $file.FullName $f.Path $exe $list
    }
}

# ---------- 3. Scheduled tasks at logon / boot ----------
foreach ($t in Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }) {
    $atStart = $t.Triggers | Where-Object { $_.CimClass.CimClassName -in 'MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger' }
    if (-not $atStart) { continue }
    $action = $t.Actions | Select-Object -First 1
    $exe = Get-ExePath ([string]$action.Execute)
    if ($exe -and (Test-Microsoft $exe)) { continue }
    $cmd = (([string]$action.Execute) + ' ' + ([string]$action.Arguments)).Trim()
    $list = if ($exe) { $procByPath[$exe.ToLowerInvariant()] } else { @() }
    Add-Item 'Scheduled task' $t.TaskName 'Enabled' $cmd $t.TaskPath $exe $list
}

# ---------- 4. Automatic non-Microsoft services ----------
foreach ($s in Get-CimInstance Win32_Service | Where-Object StartMode -eq 'Auto') {
    $exe = Get-ExePath $s.PathName
    if (-not $exe -or $exe -match '\\svchost\.exe$' -or (Test-Microsoft $exe)) { continue }
    $delayed = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)").DelayedAutostart -eq 1
    $state = if ($delayed) { 'Auto (delayed)' } else { 'Auto' }
    $list = if ($s.ProcessId -and $procById.ContainsKey([int]$s.ProcessId)) { @($procById[[int]$s.ProcessId]) } else { @() }
    Add-Item 'Service' $s.DisplayName $state $s.PathName $s.Name $exe $list
}

# ---------- Boot overview ----------
$os = Get-CimInstance Win32_OperatingSystem
$fast = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled
Write-Host ""
Write-Host "=== Boot overview ===" -ForegroundColor Cyan
Write-Host ("Last boot    : {0}  (up {1:%d}d {1:hh}h {1:mm}m)" -f $os.LastBootUpTime, ((Get-Date) - $os.LastBootUpTime))
Write-Host ("Fast Startup : {0}" -f $(if ($fast -eq 1) { 'On (shutdown is really hibernate; use Restart for a clean boot)' } else { 'Off' }))

$bootEvents = @()
if ($isAdmin) {
    $since = (Get-Date).AddDays(-$Days)
    $bootEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100, 101, 103; StartTime = $since }
    $boots = foreach ($e in $bootEvents | Where-Object Id -eq 100) {
        $x = [xml]$e.ToXml()
        $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        [pscustomobject]@{
            Date        = $e.TimeCreated
            BootSec     = [math]::Round([double]$d['BootTime'] / 1000, 1)
            DesktopSec  = [math]::Round([double]$d['MainPathBootTime'] / 1000, 1)
            SettleSec   = [math]::Round([double]$d['BootPostBootTime'] / 1000, 1)
        }
    }
    if ($boots) {
        $avg = ($boots | Measure-Object BootSec -Average).Average
        Write-Host ("Boots logged : {0} in the last {1} days, average {2:N1} s to fully settled" -f @($boots).Count, $Days, $avg)
        Write-Host "               (DesktopSec = until you can use the desktop, SettleSec = extra time to finish loading startup apps)"
        $boots | Sort-Object Date -Descending | Select-Object -First 5 | Format-Table -AutoSize | Out-Host
    } else {
        Write-Host "Boots logged : none in the last $Days days (Fast Startup boots aren't logged here)"
    }

    $slow = foreach ($e in $bootEvents | Where-Object Id -in 101, 103) {
        $x = [xml]$e.ToXml()
        $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        [pscustomobject]@{
            Kind    = if ($e.Id -eq 101) { 'App' } else { 'Service' }
            Name    = if ($d['FriendlyName']) { $d['FriendlyName'] } else { $d['Name'] }
            AddedMs = [int]$d['DegradationTime']
        }
    }
    if ($slow) {
        Write-Host "=== Windows says these slowed boot (last $Days days) ===" -ForegroundColor Cyan
        $slow | Group-Object Kind, Name | ForEach-Object {
            [pscustomobject]@{
                Kind       = $_.Group[0].Kind
                Name       = $_.Group[0].Name
                Times      = $_.Count
                AvgAddedMs = [int](($_.Group | Measure-Object AddedMs -Average).Average)
            }
        } | Sort-Object AvgAddedMs -Descending | Select-Object -First 15 | Format-Table -AutoSize | Out-Host
    }
}

# ---------- Startup list ----------
$rank = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Not running' = 3 }
$shown = $items
if (-not $All) { $shown = $items | Where-Object { $_.State -ne 'Disabled' -and $_.Impact -ne 'Not running' } }

Write-Host ""
Write-Host "=== What starts with Windows ===" -ForegroundColor Cyan
Write-Host "(CPU and disk are totals since each app launched; Impact uses Task Manager's cut-offs)"
$shown | Sort-Object @{ e = { $rank[$_.Impact] } }, @{ e = 'CpuSec'; Descending = $true } |
    Format-Table Type, Name, State, Impact, CpuSec, DiskMB, MemMB -AutoSize | Out-Host

$enabled  = @($items | Where-Object { $_.State -ne 'Disabled' })
$disabled = @($items | Where-Object { $_.State -eq 'Disabled' })
$high     = @($enabled | Where-Object { $_.Impact -eq 'High' -and $_.Type -in 'Startup app', 'Startup folder' })

Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ("{0} items start automatically ({1} startup apps, {2} tasks, {3} services); {4} startup apps are disabled." -f `
    $enabled.Count,
    @($enabled | Where-Object Type -in 'Startup app', 'Startup folder').Count,
    @($enabled | Where-Object Type -eq 'Scheduled task').Count,
    @($enabled | Where-Object Type -eq 'Service').Count,
    $disabled.Count)
if ($high.Count) {
    Write-Host "High-impact startup apps you could turn off if you don't need them right away:" -ForegroundColor Yellow
    foreach ($h in $high) { Write-Host "  - $($h.Name)" }
    Write-Host "Turn them off in Settings > Apps > Startup or Task Manager > Startup apps. They still work when you open them."
} else {
    Write-Host "No high-impact startup apps found." -ForegroundColor Green
}
if (-not $All) { Write-Host "Run with -All to include disabled and not-running items." -ForegroundColor DarkGray }

if ($CsvPath) {
    $items | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Saved full list to $CsvPath" -ForegroundColor Green
}
