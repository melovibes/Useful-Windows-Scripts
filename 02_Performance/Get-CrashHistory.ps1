<#
.SYNOPSIS
    Get-CrashHistory.ps1 - Show what has been crashing on this PC: blue screens,
    unexpected shutdowns, app crashes and hangs, hardware (WHEA) errors and disk
    errors over the last 30 days, with plain-English findings. Read-only.

.DESCRIPTION
    "My PC keeps crashing" usually means one of a few things, and Windows logs
    all of them. This script reads the System and Application event logs (and
    Reliability Monitor, when it is available) and puts the answers in one place.

    Reports:
      Summary       Last boot, uptime, Reliability Monitor score (1-10) and a
                    count of each problem type in the time window
      Blue screens  Each bugcheck with its stop code and a short meaning
                    (for example 0x0000009F DRIVER_POWER_STATE_FAILURE), plus
                    any minidump files in C:\Windows\Minidump
      Shutdowns     Unexpected restarts and power losses (Kernel-Power 41,
                    EventLog 6008), so you can tell crashes from power cuts
      App crashes   Crashes and hangs grouped by app, with how often, when it
                    last happened and the module that crashed (a DLL that
                    shows up across several apps often points to the culprit)
      Hardware      WHEA hardware errors (CPU, memory, PCIe) and disk/NTFS
                    errors such as bad blocks or a drive that stopped responding
      Findings      Numbered list of what to look at first

    Safety level : READ-ONLY. Reads event logs, WMI and file names only.
                   Changes nothing, makes no network calls. Writes a file
                   only if you pass -CsvPath.
    Admin        : Not required. Run as administrator to list minidump files
                   (that folder is protected); everything else works without.

.PARAMETER Days
    How many days back to look (1-365, default 30).

.PARAMETER Top
    Rows in the app crash list (default 10).

.PARAMETER ShowEvents
    Also print every individual event (time, type, details), newest first.

.PARAMETER CsvPath
    Export every event found to this CSV file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-CrashHistory.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-CrashHistory.ps1 -Days 90 -ShowEvents

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-CrashHistory.ps1 -CsvPath "$env:USERPROFILE\Desktop\crashes.csv"
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)][int]$Days = 30,
    [ValidateRange(1, 100)][int]$Top = 10,
    [switch]$ShowEvents,
    [string]$CsvPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$since    = (Get-Date).AddDays(-$Days)
$isAdmin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
$events   = New-Object System.Collections.Generic.List[object]
$findings = New-Object System.Collections.Generic.List[string]

# Common stop codes and what they usually mean.
$stopCodes = @{
    0x0000000A = 'IRQL_NOT_LESS_OR_EQUAL (usually a faulty driver or RAM)'
    0x0000001A = 'MEMORY_MANAGEMENT (often RAM or a driver)'
    0x0000001E = 'KMODE_EXCEPTION_NOT_HANDLED (driver bug)'
    0x0000003B = 'SYSTEM_SERVICE_EXCEPTION (driver or system file)'
    0x00000050 = 'PAGE_FAULT_IN_NONPAGED_AREA (RAM, driver or antivirus)'
    0x0000007E = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (driver bug)'
    0x0000007F = 'UNEXPECTED_KERNEL_MODE_TRAP (hardware or overclocking)'
    0x0000009F = 'DRIVER_POWER_STATE_FAILURE (driver failing sleep/wake)'
    0x000000C5 = 'DRIVER_CORRUPTED_EXPOOL (driver bug)'
    0x000000D1 = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL (network, storage or GPU driver)'
    0x000000EF = 'CRITICAL_PROCESS_DIED (system file damage or disk problem)'
    0x00000101 = 'CLOCK_WATCHDOG_TIMEOUT (CPU, BIOS or overclocking)'
    0x00000116 = 'VIDEO_TDR_FAILURE (graphics driver or GPU)'
    0x00000117 = 'VIDEO_TDR_TIMEOUT_DETECTED (graphics driver or GPU)'
    0x00000124 = 'WHEA_UNCORRECTABLE_ERROR (hardware: CPU, RAM, heat, power)'
    0x00000133 = 'DPC_WATCHDOG_VIOLATION (storage or other driver stuck)'
    0x00000139 = 'KERNEL_SECURITY_CHECK_FAILURE (driver or memory corruption)'
    0x0000013A = 'KERNEL_MODE_HEAP_CORRUPTION (driver bug)'
    0x00000154 = 'UNEXPECTED_STORE_EXCEPTION (disk or storage driver)'
    0x000001CA = 'SYNTHETIC_WATCHDOG_TIMEOUT (system hung)'
}

function Get-StopCodeText([long]$code) {
    if ($code -eq 0) { return '' }
    $hex = '0x{0:X8}' -f $code
    if ($stopCodes.ContainsKey([int]$code)) { return "$hex $($stopCodes[[int]$code])" }
    return $hex
}

function Get-Events([hashtable]$filter) {
    $filter['StartTime'] = $since
    try   { @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) }
    catch { @() }   # "No events were found" or a log that doesn't exist
}

function Add-Event($time, [string]$type, [string]$source, [string]$app, [string]$detail) {
    $events.Add([pscustomobject]@{
        Time   = $time
        Type   = $type
        Source = $source
        App    = $app
        Detail = $detail
    })
}

function Get-Prop($evt, [int]$i) {
    if ($evt.Properties.Count -gt $i -and $null -ne $evt.Properties[$i].Value) { return [string]$evt.Properties[$i].Value }
    return ''
}

Write-Host ''
Write-Host "Crash history for the last $Days days (since $($since.ToString('yyyy-MM-dd')))" -ForegroundColor Cyan
Write-Host ('=' * 70)

# ---------------------------------------------------------------- Blue screens
foreach ($e in Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001 }) {
    $code = 0L
    if ($e.Message -match '0x([0-9a-fA-F]{8})') { $code = [Convert]::ToInt64($Matches[1], 16) }
    Add-Event $e.TimeCreated 'Blue screen' 'BugCheck 1001' '' (Get-StopCodeText $code)
}

# ----------------------------------------------------------- Unexpected shutdowns
foreach ($e in Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41 }) {
    $bug = 0L
    [void][long]::TryParse((Get-Prop $e 0), [ref]$bug)
    $detail = if ($bug -ne 0) { "Restarted after a crash: $(Get-StopCodeText $bug)" }
              else { 'Lost power or stopped responding (no stop code; power cut, held power button, or hard freeze)' }
    Add-Event $e.TimeCreated 'Unexpected shutdown' 'Kernel-Power 41' '' $detail
}
foreach ($e in Get-Events @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6008 }) {
    Add-Event $e.TimeCreated 'Unexpected shutdown' 'EventLog 6008' '' 'The previous shutdown was unexpected'
}

# ------------------------------------------------------------- App crashes/hangs
foreach ($e in Get-Events @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000 }) {
    $app = Get-Prop $e 0; $module = Get-Prop $e 3; $ex = Get-Prop $e 6
    $detail = "Module: $module"
    if ($ex) { $detail += "  Exception: 0x$($ex -replace '^0x','')" }
    Add-Event $e.TimeCreated 'App crash' 'Application Error 1000' $app $detail
}
foreach ($e in Get-Events @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002 }) {
    Add-Event $e.TimeCreated 'App hang' 'Application Hang 1002' (Get-Prop $e 0) 'Stopped responding and was closed'
}

# ----------------------------------------------------------------- Hardware/disk
foreach ($e in Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger' }) {
    if ($e.Level -gt 3) { continue }   # skip informational
    $line = ($e.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    $kind = if ($e.Level -le 2) { 'Hardware error' } else { 'Hardware warning' }
    Add-Event $e.TimeCreated $kind "WHEA $($e.Id)" '' $line
}
$diskIds = @{ 7 = 'Bad block on the disk'; 11 = 'Controller error'; 51 = 'Error during a paging operation';
              153 = 'Disk I/O was retried'; 129 = 'Storage driver reset the device' }
foreach ($prov in 'disk', 'stornvme', 'storahci', 'Ntfs', 'Microsoft-Windows-Ntfs') {
    foreach ($e in Get-Events @{ LogName = 'System'; ProviderName = $prov; Level = 1, 2, 3 }) {
        $d = if ($diskIds.ContainsKey($e.Id)) { $diskIds[$e.Id] }
             else { ($e.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) }
        if ($prov -like '*Ntfs' -and $e.Id -notin 55, 98, 137, 140) { continue }
        Add-Event $e.TimeCreated 'Disk error' "$prov $($e.Id)" '' $d
    }
}

# -------------------------------------------------------------------- Summary
$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
$reliability = $null
try {
    $reliability = Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction Stop |
                   Sort-Object TimeGenerated -Descending | Select-Object -First 1
} catch { }

$count = { param($t) @($events | Where-Object { $_.Type -eq $t }).Count }
$bsod = & $count 'Blue screen'; $shut = & $count 'Unexpected shutdown'
$crash = & $count 'App crash';  $hang = & $count 'App hang'
$hwErr = & $count 'Hardware error'; $hwWarn = & $count 'Hardware warning'
$disk = & $count 'Disk error'

Write-Host ''
Write-Host 'Summary' -ForegroundColor Yellow
if ($os) {
    $up = (Get-Date) - $os.LastBootUpTime
    '{0,-24} {1} (up {2}d {3}h)' -f 'Last boot:', $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm'), $up.Days, $up.Hours
}
if ($reliability) {
    '{0,-24} {1:N1} / 10 (Reliability Monitor, 10 = no problems)' -f 'Stability score:', $reliability.SystemStabilityIndex
} else {
    '{0,-24} {1}' -f 'Stability score:', 'not available (Reliability Monitor data is off or empty)'
}
'{0,-24} {1}' -f 'Blue screens:', $bsod  # BugCheck 1001 events
'{0,-24} {1}' -f 'Unexpected shutdowns:', $shut
'{0,-24} {1} crashes, {2} hangs' -f 'App problems:', $crash, $hang
'{0,-24} {1} errors, {2} warnings' -f 'Hardware (WHEA):', $hwErr, $hwWarn
'{0,-24} {1}' -f 'Disk/NTFS errors:', $disk

# ---------------------------------------------------------------- Blue screens
Write-Host ''
Write-Host 'Blue screens' -ForegroundColor Yellow
# Kernel-Power 41 with a stop code usually repeats a BugCheck 1001 logged minutes
# later; keep it only when there is no matching 1001 (e.g. the dump failed).
$bugChecks = @($events | Where-Object { $_.Type -eq 'Blue screen' })
$bsodRows = @($events | Where-Object {
        $e = $_
        $e.Type -eq 'Blue screen' -or
        ($e.Source -eq 'Kernel-Power 41' -and $e.Detail -like 'Restarted after a crash*' -and
         -not ($bugChecks | Where-Object { [math]::Abs(($_.Time - $e.Time).TotalMinutes) -le 15 }))
    } | Sort-Object Time -Descending)
if ($bsodRows.Count) {
    $bsodRows | Select-Object @{n='Time';e={$_.Time.ToString('yyyy-MM-dd HH:mm')}}, Source,
        @{n='Stop code';e={$_.Detail -replace '^Restarted after a crash: ',''}} | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
} else { Write-Host '  None in this period.' -ForegroundColor Green }

$dumpDir = Join-Path $env:SystemRoot 'Minidump'
if (Test-Path $dumpDir) {
    try {
        $dumps = @(Get-ChildItem $dumpDir -Filter *.dmp -ErrorAction Stop | Sort-Object LastWriteTime -Descending)
        if ($dumps.Count) {
            Write-Host "  Minidumps in $dumpDir ($($dumps.Count)):"
            $dumps | Select-Object -First 10 | ForEach-Object { Write-Host ("    {0}  {1}" -f $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $_.Name) }
        }
    } catch { Write-Host "  Minidump folder exists but needs admin to read." -ForegroundColor DarkGray }
}

# ------------------------------------------------------------------ Shutdowns
Write-Host ''
Write-Host 'Unexpected shutdowns' -ForegroundColor Yellow
$shutRows = @($events | Where-Object { $_.Type -eq 'Unexpected shutdown' } | Sort-Object Time -Descending)
if ($shutRows.Count) {
    $shutRows | Select-Object @{n='Time';e={$_.Time.ToString('yyyy-MM-dd HH:mm')}}, Source, Detail |
        Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
} else { Write-Host '  None in this period.' -ForegroundColor Green }

# ---------------------------------------------------------------- App crashes
Write-Host ''
Write-Host "App crashes and hangs (top $Top)" -ForegroundColor Yellow
$appGroups = @($events | Where-Object { $_.Type -in 'App crash', 'App hang' -and $_.App } | Group-Object App |
    ForEach-Object {
        $g = $_.Group
        $mods = @($g | Where-Object { $_.Detail -match '^Module: (\S+)' } | ForEach-Object { ($_.Detail -split '\s+')[1] } |
                  Group-Object | Sort-Object Count -Descending | Select-Object -First 2 | ForEach-Object { $_.Name })
        [pscustomobject]@{
            App       = $_.Name
            Crashes   = @($g | Where-Object Type -eq 'App crash').Count
            Hangs     = @($g | Where-Object Type -eq 'App hang').Count
            LastSeen  = ($g | Sort-Object Time -Descending | Select-Object -First 1).Time
            Modules   = ($mods -join ', ')
        }
    } | Sort-Object { $_.Crashes + $_.Hangs } -Descending)
if ($appGroups.Count) {
    $appGroups | Select-Object -First $Top App, Crashes, Hangs, @{n='Last seen';e={$_.LastSeen.ToString('yyyy-MM-dd HH:mm')}},
        @{n='Crashed in';e={$_.Modules}} | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
} else { Write-Host '  None in this period.' -ForegroundColor Green }

# ------------------------------------------------------------------- Hardware
Write-Host ''
Write-Host 'Hardware and disk errors' -ForegroundColor Yellow
$hwRows = @($events | Where-Object { $_.Type -in 'Hardware error', 'Hardware warning', 'Disk error' } | Group-Object Type, Source, Detail |
    ForEach-Object { [pscustomobject]@{
        Type = $_.Group[0].Type; Source = $_.Group[0].Source; Count = $_.Count
        Last = ($_.Group | Sort-Object Time -Descending | Select-Object -First 1).Time; Detail = $_.Group[0].Detail } } |
    Sort-Object Last -Descending)
if ($hwRows.Count) {
    $hwRows | Select-Object Type, Source, Count, @{n='Last';e={$_.Last.ToString('yyyy-MM-dd HH:mm')}}, Detail |
        Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
} else { Write-Host '  None in this period.' -ForegroundColor Green }

# --------------------------------------------------------------- All events
if ($ShowEvents -and $events.Count) {
    Write-Host ''
    Write-Host 'All events (newest first)' -ForegroundColor Yellow
    $events | Sort-Object Time -Descending |
        Select-Object @{n='Time';e={$_.Time.ToString('yyyy-MM-dd HH:mm:ss')}}, Type, App, Detail |
        Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
}

# ------------------------------------------------------------------- Findings
if ($bsod -gt 0 -or @($bsodRows).Count -gt 0) {
    # Prefer BugCheck 1001 rows; Kernel-Power 41 usually logs the same crash again.
    $codeRows = @($bsodRows | Where-Object { $_.Type -eq 'Blue screen' })
    if (-not $codeRows.Count) { $codeRows = $bsodRows }
    $codes = @($codeRows | ForEach-Object { ($_.Detail -replace '^Restarted after a crash: ','') } | Where-Object { $_ } |
               Group-Object | Sort-Object Count -Descending)
    if ($codes.Count) {
        $findings.Add("Blue screens: most common stop code is $($codes[0].Name) ($($codes[0].Count)x). Update the driver it points to (chipset, graphics, storage, network) from the PC or part maker, and check Windows Update > Optional updates.")
    }
    if ($codes | Where-Object { $_.Name -like '*WHEA*' -or $_.Name -like '*CLOCK_WATCHDOG*' }) {
        $findings.Add('A hardware-type stop code showed up. Turn off any overclocking or XMP/EXPO memory profile, check temperatures, and run Windows Memory Diagnostic (mdsched.exe).')
    }
}
$powerLoss = @($events | Where-Object { $_.Source -eq 'Kernel-Power 41' -and $_.Detail -like 'Lost power*' }).Count
if ($powerLoss -ge 2) {
    $findings.Add("$powerLoss shutdowns with no stop code. That's a power cut, a held power button, or a hard freeze. If you didn't cut the power, check the power supply, cables or UPS, and the BIOS for a sleep/wake problem.")
}
if ($hwErr -gt 0) {
    $findings.Add("$hwErr WHEA hardware error(s). These come from the CPU, memory or PCIe bus, not from software. Check temperatures, reseat RAM and cards, and update the BIOS.")
} elseif ($hwWarn -ge 5) {
    $findings.Add("$hwWarn corrected hardware warnings (WHEA). Often harmless PCIe noise, but a steady stream is worth a BIOS and chipset driver update.")
}
if ($disk -gt 0) {
    $findings.Add("$disk disk/NTFS error(s). Back up now, then run Get-DiskHealth.ps1 and 'chkdsk C: /scan' to check the drive.")
}
$topMods = @($events | Where-Object { $_.Type -eq 'App crash' -and $_.Detail -match '^Module: (\S+)' } |
    ForEach-Object { [pscustomobject]@{ App = $_.App; Module = ($_.Detail -split '\s+')[1] } } |
    Where-Object { $_.Module -and $_.Module -notmatch '^(unknown|ntdll\.dll|KERNELBASE\.dll|ucrtbase\.dll)$' } |
    Group-Object Module | Where-Object { @($_.Group | Select-Object -ExpandProperty App -Unique).Count -ge 2 } |
    Sort-Object Count -Descending)
foreach ($m in ($topMods | Select-Object -First 2)) {
    $apps = (@($m.Group | Select-Object -ExpandProperty App -Unique) | Select-Object -First 4) -join ', '
    $findings.Add("$($m.Name) crashed several different apps ($apps). A shared DLL like this often belongs to a graphics driver, overlay, antivirus or shell add-on; update or remove whatever installed it.")
}
foreach ($a in ($appGroups | Where-Object { ($_.Crashes + $_.Hangs) -ge 5 } | Select-Object -First 3)) {
    $findings.Add("$($a.App) crashed or hung $($a.Crashes + $a.Hangs) times. Update it, or repair/reinstall it from Settings > Apps > Installed apps.")
}
if ($reliability -and $reliability.SystemStabilityIndex -lt 5) {
    $findings.Add(("Reliability score is low ({0:N1}/10). Open Reliability Monitor (run 'perfmon /rel') to see each day's problems on a timeline." -f $reliability.SystemStabilityIndex))
}
if (-not $isAdmin -and (Test-Path $dumpDir)) {
    $findings.Add('Run as administrator to list minidump files; a tool like WinDbg or BlueScreenView can read them to name the driver behind a blue screen.')
}

Write-Host ''
Write-Host 'Findings' -ForegroundColor Yellow
if ($findings.Count) {
    $i = 1; foreach ($f in $findings) { Write-Host ("  {0}. {1}" -f $i++, $f) }
} else {
    Write-Host '  Nothing stands out. No blue screens, unexpected shutdowns, hardware errors or repeat app crashes in this period.' -ForegroundColor Green
}

# ------------------------------------------------------------------------ CSV
if ($CsvPath) {
    try {
        $events | Sort-Object Time -Descending | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host ''
        Write-Host "Saved $($events.Count) events to $CsvPath" -ForegroundColor Green
    } catch { Write-Warning "Couldn't write ${CsvPath}: $($_.Exception.Message)" }
}
Write-Host ''
