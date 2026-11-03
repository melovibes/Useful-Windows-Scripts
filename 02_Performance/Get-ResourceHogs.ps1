<#
.SYNOPSIS
    Get-ResourceHogs.ps1 - Watches your PC for about 30 seconds and shows which
    apps are using the most CPU, memory and disk, then lists anything worth fixing.

.DESCRIPTION
    Takes a snapshot of every running process, waits (default 30 seconds) while
    showing a progress bar, takes a second snapshot, and compares the two.

    Reports:
      System        Overall CPU use, memory in use and available, commit charge,
                    and how busy the disks were during the sample
      Top CPU       Average CPU % over the sample (100% = every core fully busy)
      Top memory    Memory in use (working set) and private memory per app
      Top disk      Bytes read and written per second during the sample
                    (Windows counts all I/O here, so this can include some
                    network and device traffic too)
      Findings      Plain-English notes, like one app eating most of the CPU,
                    low free memory, or an app reading or writing heavily

    By default, processes with the same name are added together (all chrome.exe
    processes show as one "chrome" row with a process count). Use -PerProcess to
    see each process separately.

    Safety level : READ-ONLY. Stops nothing, changes no settings. -CsvPath only
                   writes the CSV file you name. No network calls.

    Admin        : Optional. Without admin, a few protected system processes can't
                   be measured for CPU and are skipped. Run as administrator for a
                   complete picture.

.PARAMETER Seconds
    How long to watch, in seconds (5 to 600). Default: 30.

.PARAMETER Top
    How many apps to show in each list. Default: 10.

.PARAMETER PerProcess
    Show each process separately (with its process ID) instead of adding up
    processes that share a name.

.PARAMETER CsvPath
    Also export every process (or app group) with all measurements to this CSV file.

.EXAMPLE
    .\Get-ResourceHogs.ps1
    Watch for 30 seconds and show the top 10 CPU, memory and disk users.
.EXAMPLE
    .\Get-ResourceHogs.ps1 -Seconds 60 -Top 15 -CsvPath "$env:USERPROFILE\Desktop\hogs.csv"
    Watch for a minute, show 15 rows per list, and save everything to a CSV.

.NOTES
    Usage:
      powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-ResourceHogs.ps1"
      powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-ResourceHogs.ps1" -PerProcess
      powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-ResourceHogs.ps1" -Seconds 60 -CsvPath "$env:USERPROFILE\Desktop\hogs.csv"
    Tip: start the script, then do whatever feels slow (open the app, play the
    game, start the sync) so it shows up in the sample.
    Works on Windows 10 and 11, Windows PowerShell 5.1 or PowerShell 7.
#>
[CmdletBinding()]
param(
    [ValidateRange(5, 600)]
    [int]$Seconds = 30,
    [ValidateRange(1, 100)]
    [int]$Top = 10,
    [switch]$PerProcess,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$findings = New-Object System.Collections.Generic.List[string]

function Format-Bytes([double]$b) {
    if ($b -ge 1GB) { return '{0:N2} GB' -f ($b / 1GB) }
    if ($b -ge 1MB) { return '{0:N1} MB' -f ($b / 1MB) }
    if ($b -ge 1KB) { return '{0:N0} KB' -f ($b / 1KB) }
    return '{0:N0} B' -f $b
}

function Write-Section([string]$title) {
    Write-Host ''
    Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Get-ProcSnapshot {
    # CPU time and memory from Get-Process; cumulative I/O bytes from raw perf counters.
    $io = @{}
    try {
        Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process -ErrorAction Stop |
            Where-Object { $_.IDProcess -ne 0 -and $_.Name -ne '_Total' } |
            ForEach-Object { $io[[int]$_.IDProcess] = @([double]$_.IOReadBytesPersec, [double]$_.IOWriteBytesPersec) }
    } catch {
        Write-Verbose "Per-process I/O counters unavailable: $($_.Exception.Message)"
    }

    $snap = @{}
    foreach ($p in Get-Process) {
        if ($p.Id -eq 0) { continue }   # Idle
        $cpu = $null
        try { $cpu = $p.TotalProcessorTime.TotalSeconds } catch { }
        $r = $null; $w = $null
        if ($io.ContainsKey($p.Id)) { $r = $io[$p.Id][0]; $w = $io[$p.Id][1] }
        $snap[$p.Id] = [pscustomobject]@{
            Id = $p.Id; Name = $p.ProcessName; Start = $(try { $p.StartTime } catch { $null })
            Cpu = $cpu; WorkingSet = [double]$p.WorkingSet64; Private = [double]$p.PrivateMemorySize64
            Read = $r; Write = $w
        }
    }
    return $snap
}

$cores = [Environment]::ProcessorCount
$os = Get-CimInstance Win32_OperatingSystem
$totalRam = [double]$os.TotalVisibleMemorySize * 1KB

Write-Host "Get-ResourceHogs - watching for $Seconds seconds ($cores logical CPUs, $(Format-Bytes $totalRam) RAM)" -ForegroundColor Green
Write-Host 'Tip: do whatever feels slow now so it shows up in the sample.'

# --- Sample ---------------------------------------------------------------
$sysCpuSamples = New-Object System.Collections.Generic.List[double]
$diskBusySamples = New-Object System.Collections.Generic.List[double]
$before = Get-ProcSnapshot
$sw = [Diagnostics.Stopwatch]::StartNew()

while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
    $left = [math]::Max(0, [int]($Seconds - $sw.Elapsed.TotalSeconds))
    Write-Progress -Activity 'Watching CPU, memory and disk' -Status "$left seconds left" `
        -PercentComplete ([math]::Min(100, [int](100 * $sw.Elapsed.TotalSeconds / $Seconds)))
    try {
        $c = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
        $sysCpuSamples.Add([double]$c.PercentProcessorTime)
    } catch { }
    try {
        $d = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction Stop
        $diskBusySamples.Add([math]::Min(100, 100 - [double]$d.PercentIdleTime))
    } catch { }
    Start-Sleep -Milliseconds 2000
}

$after = Get-ProcSnapshot
$elapsed = $sw.Elapsed.TotalSeconds
Write-Progress -Activity 'Watching CPU, memory and disk' -Completed

# --- Compare snapshots ----------------------------------------------------
$rows = New-Object System.Collections.Generic.List[object]
$skippedCpu = 0
foreach ($id in $after.Keys) {
    $a = $after[$id]
    $b = $null
    if ($before.ContainsKey($id) -and $before[$id].Name -eq $a.Name -and $before[$id].Start -eq $a.Start) { $b = $before[$id] }

    $cpuPct = $null
    if ($null -ne $a.Cpu) {
        $startCpu = if ($b -and $null -ne $b.Cpu) { $b.Cpu } else { 0 }   # new process: all its CPU happened during the sample
        $cpuPct = [math]::Max(0, ($a.Cpu - $startCpu)) / ($elapsed * $cores) * 100
    } else { $skippedCpu++ }

    $readPs = 0.0; $writePs = 0.0
    if ($null -ne $a.Read) {
        $r0 = if ($b -and $null -ne $b.Read) { $b.Read } else { 0 }
        $w0 = if ($b -and $null -ne $b.Write) { $b.Write } else { 0 }
        $readPs = [math]::Max(0, $a.Read - $r0) / $elapsed
        $writePs = [math]::Max(0, $a.Write - $w0) / $elapsed
    }

    $rows.Add([pscustomobject]@{
        Name = $a.Name; Id = $a.Id; Count = 1
        CpuPct = $cpuPct; WorkingSet = $a.WorkingSet; Private = $a.Private
        ReadPerSec = $readPs; WritePerSec = $writePs
    })
}

if (-not $PerProcess) {
    $grouped = foreach ($g in ($rows | Group-Object Name)) {
        $cpuVals = @($g.Group | Where-Object { $null -ne $_.CpuPct } | ForEach-Object { $_.CpuPct })
        [pscustomobject]@{
            Name = $g.Name; Id = ''; Count = $g.Count
            CpuPct = if ($cpuVals.Count) { ($cpuVals | Measure-Object -Sum).Sum } else { $null }
            WorkingSet = ($g.Group | Measure-Object WorkingSet -Sum).Sum
            Private = ($g.Group | Measure-Object Private -Sum).Sum
            ReadPerSec = ($g.Group | Measure-Object ReadPerSec -Sum).Sum
            WritePerSec = ($g.Group | Measure-Object WritePerSec -Sum).Sum
        }
    }
    $rows = @($grouped)
}

$label = if ($PerProcess) { @{ N = 'Process'; E = { "$($_.Name) ($($_.Id))" } } } else { @{ N = 'App'; E = { if ($_.Count -gt 1) { "$($_.Name) (x$($_.Count))" } else { $_.Name } } } }

# --- System summary -------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$freeRam = [double]$os.FreePhysicalMemory * 1KB
$usedPct = 100 * (1 - $freeRam / $totalRam)
$commitUsed = ([double]$os.TotalVirtualMemorySize - [double]$os.FreeVirtualMemory) * 1KB
$commitLimit = [double]$os.TotalVirtualMemorySize * 1KB
$avgCpu = if ($sysCpuSamples.Count) { ($sysCpuSamples | Measure-Object -Average).Average } else { $null }
$maxCpu = if ($sysCpuSamples.Count) { ($sysCpuSamples | Measure-Object -Maximum).Maximum } else { $null }
$avgDisk = if ($diskBusySamples.Count) { ($diskBusySamples | Measure-Object -Average).Average } else { $null }

Write-Section "System over $([int]$elapsed) seconds"
if ($null -ne $avgCpu) { Write-Host ('CPU          : {0:N0}% average, {1:N0}% peak' -f $avgCpu, $maxCpu) }
Write-Host ('Memory       : {0} of {1} in use ({2:N0}%), {3} available' -f (Format-Bytes ($totalRam - $freeRam)), (Format-Bytes $totalRam), $usedPct, (Format-Bytes $freeRam))
Write-Host ('Commit charge: {0} of {1}' -f (Format-Bytes $commitUsed), (Format-Bytes $commitLimit))
if ($null -ne $avgDisk) { Write-Host ('Disk busy    : {0:N0}% average' -f $avgDisk) }
Write-Host ("Processes    : {0} running" -f $after.Count)

# --- Top lists ------------------------------------------------------------
Write-Section "Top $Top by CPU (average % of all cores)"
$rows | Where-Object { $null -ne $_.CpuPct } | Sort-Object CpuPct -Descending | Select-Object -First $Top |
    Format-Table $label, @{ N = 'CPU %'; E = { '{0:N1}' -f $_.CpuPct }; A = 'Right' },
        @{ N = 'Memory'; E = { Format-Bytes $_.WorkingSet }; A = 'Right' } -AutoSize | Out-Host

Write-Section "Top $Top by memory"
$rows | Sort-Object WorkingSet -Descending | Select-Object -First $Top |
    Format-Table $label, @{ N = 'In use'; E = { Format-Bytes $_.WorkingSet }; A = 'Right' },
        @{ N = 'Private'; E = { Format-Bytes $_.Private }; A = 'Right' },
        @{ N = '% of RAM'; E = { '{0:N1}' -f (100 * $_.WorkingSet / $totalRam) }; A = 'Right' } -AutoSize | Out-Host

Write-Section "Top $Top by disk and I/O (per second)"
$ioRows = $rows | Where-Object { ($_.ReadPerSec + $_.WritePerSec) -gt 0 } | Sort-Object { $_.ReadPerSec + $_.WritePerSec } -Descending | Select-Object -First $Top
if ($ioRows) {
    $ioRows | Format-Table $label, @{ N = 'Read/s'; E = { Format-Bytes $_.ReadPerSec }; A = 'Right' },
        @{ N = 'Write/s'; E = { Format-Bytes $_.WritePerSec }; A = 'Right' } -AutoSize | Out-Host
} else {
    Write-Host 'No per-app I/O measured (performance counters may be disabled).'
}

if ($skippedCpu -gt 0) {
    Write-Host "$skippedCpu protected process(es) couldn't be measured for CPU. Run as administrator to include them." -ForegroundColor DarkGray
}

# --- Findings -------------------------------------------------------------
$topCpu = $rows | Where-Object { $null -ne $_.CpuPct } | Sort-Object CpuPct -Descending | Select-Object -First 1
if ($topCpu -and $topCpu.CpuPct -ge 25) {
    $findings.Add(('{0} used {1:N0}% of all CPU on average. If you are not actively using it, close or update it, or check it in Task Manager.' -f $topCpu.Name, $topCpu.CpuPct))
}
if ($null -ne $avgCpu -and $avgCpu -ge 80) {
    $findings.Add(('The CPU was {0:N0}% busy on average. Expect lag until the busiest apps above finish or are closed.' -f $avgCpu))
}
$avail = $freeRam / $totalRam
if ($avail -lt 0.10) {
    $findings.Add(('Only {0} of memory is free ({1:N0}%). Windows will page to disk and feel slow; close the biggest apps in the memory list or add RAM.' -f (Format-Bytes $freeRam), (100 * $avail)))
} elseif ($avail -lt 0.20) {
    $findings.Add(('Memory is getting tight: {0} free ({1:N0}%).' -f (Format-Bytes $freeRam), (100 * $avail)))
}
if ($commitLimit -gt 0 -and ($commitUsed / $commitLimit) -ge 0.9) {
    $findings.Add('Commit charge is above 90% of the limit. Apps may fail with out-of-memory errors; close some apps or let Windows manage the page file size.')
}
foreach ($r in ($rows | Where-Object { $_.WorkingSet -ge 0.25 * $totalRam })) {
    $findings.Add(('{0} is using {1} ({2:N0}% of RAM).' -f $r.Name, (Format-Bytes $r.WorkingSet), (100 * $r.WorkingSet / $totalRam)))
}
if ($null -ne $avgDisk -and $avgDisk -ge 70) {
    $findings.Add(('The disk was {0:N0}% busy on average. Look at the top apps in the disk list (Windows Update, antivirus scans, search indexing and cloud sync are common causes).' -f $avgDisk))
}
foreach ($r in ($rows | Where-Object { ($_.ReadPerSec + $_.WritePerSec) -ge 50MB })) {
    $findings.Add(('{0} moved {1}/s of data on average.' -f $r.Name, (Format-Bytes ($r.ReadPerSec + $r.WritePerSec))))
}

Write-Section 'Findings'
if ($findings.Count) { $findings | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow } }
else { Write-Host 'Nothing stood out. No single app was hogging CPU, memory or disk during the sample.' -ForegroundColor Green }

# --- CSV ------------------------------------------------------------------
if ($CsvPath) {
    $rows | Sort-Object { if ($null -ne $_.CpuPct) { $_.CpuPct } else { -1 } } -Descending |
        Select-Object Name, Id, Count,
            @{ N = 'CpuPercent'; E = { if ($null -ne $_.CpuPct) { [math]::Round($_.CpuPct, 2) } } },
            @{ N = 'WorkingSetMB'; E = { [math]::Round($_.WorkingSet / 1MB, 1) } },
            @{ N = 'PrivateMB'; E = { [math]::Round($_.Private / 1MB, 1) } },
            @{ N = 'ReadKBps'; E = { [math]::Round($_.ReadPerSec / 1KB, 1) } },
            @{ N = 'WriteKBps'; E = { [math]::Round($_.WritePerSec / 1KB, 1) } } |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Saved $($rows.Count) rows to $CsvPath" -ForegroundColor Green
}
