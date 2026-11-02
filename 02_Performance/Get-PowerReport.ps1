<#
.SYNOPSIS
    Get-PowerReport.ps1 - Shows your power plan, sleep settings and battery health,
    then lists anything that is wasting power or slowing the PC down.

.DESCRIPTION
    Checks and reports:
      Power plan      Active plan, other plans installed, and the Windows 11 power
                      mode (Best power efficiency / Balanced / Best performance)
      Timeouts        Screen off, sleep, hibernate and disk timeouts, plugged in
                      and on battery
      Sleep           Which sleep states this PC supports (S3 or Modern Standby),
                      hibernate, Fast Startup, wake timers, devices allowed to wake
                      the PC, and what woke it last
      CPU limits      Minimum and maximum processor state for the active plan
      Battery         Charge, design vs full-charge capacity (health %), cycle
                      count. Skipped on desktops with no battery.
      Blockers        (admin) Apps and drivers currently keeping the PC awake

    Ends with a short list of findings in plain English.

    Safety level : READ-ONLY. Changes no settings. -BatteryReport only writes
                   Windows' own battery report (an HTML file) to the folder you
                   choose. No network calls.

    Admin        : Optional. Without admin everything works except the list of
                   apps blocking sleep (powercfg /requests). Nothing else needs it.

.PARAMETER BatteryReport
    Also create Windows' detailed battery report (powercfg /batteryreport) as an
    HTML file, with charge history and capacity over time. Laptops only.

.PARAMETER OutputPath
    Folder for the battery report. Default: your Desktop.

.PARAMETER Open
    With -BatteryReport, open the report in your browser when it's done.

.EXAMPLE
    .\Get-PowerReport.ps1
    Power plan, sleep settings, battery health and findings.
.EXAMPLE
    .\Get-PowerReport.ps1 -BatteryReport -Open
    Same, plus Windows' full battery report, opened in your browser.

.NOTES
    Usage:
      powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-PowerReport.ps1"
      powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-PowerReport.ps1" -BatteryReport -Open
    Works on Windows 10 and 11, Windows PowerShell 5.1 or PowerShell 7.
#>
[CmdletBinding()]
param(
    [switch]$BatteryReport,
    [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
$findings = New-Object System.Collections.Generic.List[string]

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}
function Add-Finding([string]$Text) { $findings.Add($Text) }

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Reads one setting from the active plan. powercfg output is localized, but the
# last two hex values are always the AC (plugged in) and DC (battery) values.
function Get-PlanValue([string]$SubGroup, [string]$Setting) {
    try {
        $out = & powercfg.exe /query SCHEME_CURRENT $SubGroup $Setting 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        $hex = @([regex]::Matches(($out -join "`n"), '0x[0-9a-fA-F]{8}') | ForEach-Object { $_.Value })
        if ($hex.Count -lt 2) { return $null }
        [pscustomobject]@{
            AC = [Convert]::ToInt64($hex[-2], 16)
            DC = [Convert]::ToInt64($hex[-1], 16)
        }
    } catch { $null }
}

function Format-Seconds([long]$Seconds) {
    if ($Seconds -le 0) { return 'Never' }
    if ($Seconds -lt 60) { return "$Seconds sec" }
    if ($Seconds % 3600 -eq 0) { return "$($Seconds / 3600) hr" }
    return "$([math]::Round($Seconds / 60)) min"
}

$isAdmin = Test-IsAdmin
$hasBattery = $false
try { $hasBattery = [bool](Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop) } catch { }

# ---------------------------------------------------------------- Power plan
Write-Section 'Power plan'
$planLines = & powercfg.exe /list 2>$null
$plans = foreach ($line in $planLines) {
    if ($line -match '([0-9a-fA-F-]{36})\s+\((.+?)\)(\s*\*)?') {
        [pscustomobject]@{ Guid = $Matches[1]; Name = $Matches[2]; Active = [bool]$Matches[3] }
    }
}
$active = $plans | Where-Object Active | Select-Object -First 1
if ($active) {
    Write-Host ("Active plan : {0}" -f $active.Name)
} else {
    Write-Host 'Active plan : (could not read)'
}
$others = $plans | Where-Object { -not $_.Active }
if ($others) { Write-Host ("Other plans : {0}" -f (($others | ForEach-Object Name) -join ', ')) }

# Windows 11 power mode (the slider in Settings > System > Power & battery)
$modeNames = @{
    '961cc777-2547-4f9d-8174-7d86181b8a7a' = 'Best power efficiency'
    '00000000-0000-0000-0000-000000000000' = 'Balanced'
    '3af9b8d9-7c97-431d-ad78-34a8bfea439f' = 'Better performance'
    'ded574b5-45a0-4f42-8737-46345c09c238' = 'Best performance'
}
$modeAC = $null; $modeDC = $null
try {
    $pk = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' -ErrorAction Stop
    if ($pk.ActiveOverlayAcPowerScheme) { $modeAC = $modeNames[[string]$pk.ActiveOverlayAcPowerScheme] }
    if ($pk.ActiveOverlayDcPowerScheme) { $modeDC = $modeNames[[string]$pk.ActiveOverlayDcPowerScheme] }
} catch { }
if ($modeAC) {
    $line = "Power mode  : $modeAC (plugged in)"
    if ($hasBattery -and $modeDC) { $line += ", $modeDC (on battery)" }
    Write-Host $line
}
if ($active -and $active.Name -match 'Ultimate|High performance' -and $hasBattery) {
    Add-Finding "The '$($active.Name)' plan is active on a laptop. It keeps the CPU clocked up and drains the battery much faster; Balanced is usually just as quick."
}
if ($active -and $active.Name -match 'Power saver') {
    Add-Finding "The 'Power saver' plan is active. It caps CPU speed, which can make the PC feel slow. Switch to Balanced unless you need maximum battery life."
}

# ---------------------------------------------------------------- Timeouts
Write-Section 'Timeouts'
$timeouts = @(
    @{ Name = 'Turn off screen'; Sub = 'SUB_VIDEO'; Set = 'VIDEOIDLE' }
    @{ Name = 'Sleep after';     Sub = 'SUB_SLEEP'; Set = 'STANDBYIDLE' }
    @{ Name = 'Hibernate after'; Sub = 'SUB_SLEEP'; Set = 'HIBERNATEIDLE' }
    @{ Name = 'Turn off disk';   Sub = 'SUB_DISK';  Set = 'DISKIDLE' }
)
$timeoutRows = foreach ($t in $timeouts) {
    $v = Get-PlanValue $t.Sub $t.Set
    $row = [ordered]@{ Setting = $t.Name; 'Plugged in' = if ($v) { Format-Seconds $v.AC } else { '?' } }
    if ($hasBattery) { $row['On battery'] = if ($v) { Format-Seconds $v.DC } else { '?' } }
    [pscustomobject]$row
    if ($v -and $t.Set -eq 'STANDBYIDLE') { $sleepVal = $v }
    if ($v -and $t.Set -eq 'VIDEOIDLE')   { $screenVal = $v }
}
$timeoutRows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

if ($hasBattery -and $sleepVal -and $sleepVal.DC -eq 0) {
    Add-Finding 'On battery the PC never goes to sleep by itself. Set "Sleep after" on battery to 15-30 minutes in Settings > System > Power & battery.'
}
if ($hasBattery -and $screenVal -and ($screenVal.DC -eq 0 -or $screenVal.DC -gt 900)) {
    Add-Finding 'On battery the screen stays on for more than 15 minutes (or never turns off). The screen is the biggest battery drain; 3-5 minutes is typical.'
}
if (-not $hasBattery -and $sleepVal -and $sleepVal.AC -eq 0) {
    Add-Finding 'This PC never sleeps on its own. That is fine for a server or always-on machine; otherwise sleep after 30-60 minutes saves power.'
}

# ---------------------------------------------------------------- Sleep and wake
Write-Section 'Sleep and wake'
$aOut = (& powercfg.exe /a 2>$null) -join "`n"
# The first block of /a lists available states; later blocks list unavailable ones.
$availBlock = ($aOut -split "`n\s*`n")[0]
$states = @()
if ($availBlock -match 'S0 Low Power Idle') { $states += 'Modern Standby (S0)' }
if ($availBlock -match 'Standby \(S3\)')   { $states += 'Sleep (S3)' }
if ($availBlock -match 'Hibernate')        { $states += 'Hibernate' }
if ($availBlock -match 'Hybrid Sleep')     { $states += 'Hybrid Sleep' }
if ($availBlock -match 'Fast Startup')     { $states += 'Fast Startup' }
if ($states) {
    Write-Host ("Sleep states available : {0}" -f ($states -join ', '))
} else {
    Write-Host 'Sleep states available : (run "powercfg /a" to see; output may be in another language)'
}

$fastStartup = $null
try {
    $fastStartup = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled
} catch { }
if ($null -ne $fastStartup) {
    Write-Host ("Fast Startup           : {0}" -f $(if ($fastStartup -eq 1) { 'On' } else { 'Off' }))
}

$wakeTimers = Get-PlanValue 'SUB_SLEEP' 'RTCWAKE'
if ($wakeTimers) {
    $wtName = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'Important only' }
    $wt = "Wake timers            : $($wtName[[int]$wakeTimers.AC]) (plugged in)"
    if ($hasBattery) { $wt += ", $($wtName[[int]$wakeTimers.DC]) (on battery)" }
    Write-Host $wt
    if ($hasBattery -and $wakeTimers.DC -eq 1) {
        Add-Finding 'Wake timers are enabled on battery, so scheduled tasks can wake the laptop in your bag. Set them to "Important only" or Disabled.'
    }
}

$wakeDevices = @(& powercfg.exe /devicequery wake_armed 2>$null | Where-Object { $_ -and $_ -notmatch '^\s*NONE\s*$' })
Write-Host ("Devices that can wake  : {0}" -f $(if ($wakeDevices.Count) { $wakeDevices.Count } else { 'none' }))
foreach ($d in $wakeDevices) { Write-Host "   - $d" }
if ($wakeDevices | Where-Object { $_ -match 'Mouse|HID-compliant mouse' }) {
    Add-Finding 'A mouse is allowed to wake the PC, so a bump on the desk wakes it. Turn this off in Device Manager > the mouse > Power Management if that bothers you.'
}

$lastWake = (& powercfg.exe /lastwake 2>$null) -join "`n"
if ($lastWake -match 'Friendly Name:\s*(.+)') {
    Write-Host ("Last woken by          : {0}" -f $Matches[1].Trim())
} elseif ($lastWake -match 'Wake History Count - 0') {
    Write-Host 'Last woken by          : (no wake source recorded)'
}

# ---------------------------------------------------------------- CPU limits
Write-Section 'Processor limits (active plan)'
$minCpu = Get-PlanValue 'SUB_PROCESSOR' 'PROCTHROTTLEMIN'
$maxCpu = Get-PlanValue 'SUB_PROCESSOR' 'PROCTHROTTLEMAX'
if ($minCpu -and $maxCpu) {
    $msg = "Min / max CPU state    : $($minCpu.AC)% / $($maxCpu.AC)% plugged in"
    if ($hasBattery) { $msg += ", $($minCpu.DC)% / $($maxCpu.DC)% on battery" }
    Write-Host $msg
    if ($maxCpu.AC -lt 100) {
        Add-Finding "The CPU is capped at $($maxCpu.AC)% when plugged in, which slows the PC down. Raise 'Maximum processor state' to 100% unless you set this on purpose to keep it cool."
    }
    if ($minCpu.AC -ge 100 -and $hasBattery) {
        Add-Finding 'Minimum processor state is 100%, so the CPU never slows down when idle. This wastes power and adds heat and fan noise.'
    }
} else {
    Write-Host '(not exposed on this PC)'
}

# ---------------------------------------------------------------- Battery
Write-Section 'Battery'
if (-not $hasBattery) {
    Write-Host 'No battery found (desktop PC). Skipping.'
} else {
    $bat = Get-CimInstance -ClassName Win32_Battery | Select-Object -First 1
    $statusNames = @{ 1 = 'Discharging'; 2 = 'Plugged in'; 3 = 'Fully charged'; 4 = 'Low'; 5 = 'Critical'; 6 = 'Charging'; 7 = 'Charging (high)'; 8 = 'Charging (low)'; 9 = 'Charging (critical)'; 11 = 'Partially charged' }
    Write-Host ("Charge                 : {0}% ({1})" -f $bat.EstimatedChargeRemaining, $(if ($statusNames[[int]$bat.BatteryStatus]) { $statusNames[[int]$bat.BatteryStatus] } else { 'unknown' }))

    $design = $null; $full = $null; $cycles = $null
    try { $design = (Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1).DesignedCapacity } catch { }
    try { $full   = (Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1).FullChargedCapacity } catch { }
    try { $cycles = (Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount -ErrorAction Stop | Select-Object -First 1).CycleCount } catch { }

    if ($design -and $full) {
        $health = [math]::Round(100 * $full / $design)
        Write-Host ("Capacity               : {0:N0} mWh now vs {1:N0} mWh new" -f $full, $design)
        Write-Host ("Health                 : {0}%" -f $health)
        if ($health -lt 60) {
            Add-Finding "Battery health is $health% of its original capacity. That is worn; a replacement would roughly double runtime."
        } elseif ($health -lt 80) {
            Add-Finding "Battery health is $health% of its original capacity. Normal wear for an older laptop, but expect noticeably shorter runtime than new."
        }
    } else {
        Write-Host 'Health                 : not reported by this battery. Try -BatteryReport.'
    }
    if ($cycles) { Write-Host ("Charge cycles          : {0}" -f $cycles) }
}

# ---------------------------------------------------------------- Sleep blockers
Write-Section 'What is keeping the PC awake'
if (-not $isAdmin) {
    Write-Host 'Run as administrator to list apps and drivers that are blocking sleep.'
} else {
    $req = & powercfg.exe /requests 2>$null
    $blockers = @($req | Where-Object { $_ -match '^\s*\[' })
    if ($blockers.Count) {
        $req | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "   $_" }
        Add-Finding 'Something is currently blocking sleep or the screen from turning off (see "What is keeping the PC awake"). Media players, browsers playing video and some drivers do this.'
    } else {
        Write-Host 'Nothing is blocking sleep right now.'
    }
}

# ---------------------------------------------------------------- Battery report
if ($BatteryReport) {
    Write-Section 'Battery report'
    if (-not $hasBattery) {
        Write-Host 'No battery found, so there is no battery report to create.'
    } else {
        if (-not (Test-Path -LiteralPath $OutputPath)) { throw "Output folder not found: $OutputPath" }
        $file = Join-Path $OutputPath ("battery-report-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
        & powercfg.exe /batteryreport /output "$file" | Out-Null
        if (Test-Path -LiteralPath $file) {
            Write-Host "Saved: $file"
            if ($Open) { Invoke-Item -LiteralPath $file }
        } else {
            Write-Warning 'powercfg could not create the battery report.'
        }
    }
}

# ---------------------------------------------------------------- Findings
Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host 'Nothing to fix. Power settings look sensible.' -ForegroundColor Green
} else {
    $i = 1
    foreach ($f in $findings) { Write-Host ("{0}. {1}" -f $i, $f) -ForegroundColor Yellow; $i++ }
}
Write-Host ''
Write-Host 'No settings were changed. Adjust them in Settings > System > Power & battery, or Control Panel > Power Options.'
