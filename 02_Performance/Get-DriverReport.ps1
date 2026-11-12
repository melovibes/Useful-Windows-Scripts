<#
.SYNOPSIS
    Get-DriverReport.ps1 - Find devices with problems and drivers that are old,
    unsigned or left over, with plain-English findings. Read-only.

.DESCRIPTION
    Flaky Wi-Fi, crackling audio, a GPU that stutters or a USB device that
    "stopped working" very often comes down to one device driver. This script
    shows the driver side of the PC in one place.

    Reports:
      Summary       Device and driver counts, problem devices, unsigned and
                    old drivers, devices that are no longer connected and
                    third-party driver packages in the driver store
      Problems      Every device with a Device Manager error (yellow "!"),
                    with the error code and what it usually means
      Key drivers   Version, date and maker of the drivers that matter most:
                    graphics, network, audio, storage, Bluetooth, chipset,
                    camera and fingerprint/face sign-in
      Old drivers   Third-party drivers older than -OlderThanYears (default 5)
      Unsigned      Drivers without a valid signature
      Driver store  Third-party packages (oem*.inf) no connected device uses,
                    and older copies that a newer package from the same maker
                    has probably replaced
      Policy        Whether Windows Update is allowed to deliver drivers
      Findings      Numbered list of what to look at first

    Safety level : READ-ONLY. Reads WMI/CIM, the registry and .inf text files
                   in C:\Windows\INF. Changes nothing, removes nothing, makes
                   no network calls. Writes a file only if you pass -CsvPath.
                   Removal commands are printed as suggestions only.
    Admin        : Not required.

.PARAMETER OlderThanYears
    Flag third-party drivers whose driver date is older than this (1-20,
    default 5).

.PARAMETER Top
    Rows in the old drivers and driver store lists (default 15).

.PARAMETER IncludeMicrosoft
    Also count Microsoft's built-in drivers as old. They are off by default
    because many carry a placeholder date (often 6/21/2006) and are fine.

.PARAMETER ShowAll
    Also print every driver in use (device, class, provider, version, date).

.PARAMETER CsvPath
    Export every driver in use, with its flags, to this CSV file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DriverReport.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DriverReport.ps1 -OlderThanYears 3 -ShowAll

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DriverReport.ps1 -CsvPath "$env:USERPROFILE\Desktop\drivers.csv"
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 20)][int]$OlderThanYears = 5,
    [ValidateRange(1, 200)][int]$Top = 15,
    [switch]$IncludeMicrosoft,
    [switch]$ShowAll,
    [string]$CsvPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$cutoff   = (Get-Date).AddYears(-$OlderThanYears)
$findings = New-Object System.Collections.Generic.List[string]
$infDir   = Join-Path $env:SystemRoot 'INF'

# Device Manager error codes and what they usually mean.
$errorCodes = @{
    1  = 'Not configured correctly (reinstall the driver)'
    3  = 'Driver may be corrupted, or the PC is low on memory'
    10 = 'Device cannot start (often a wrong or outdated driver)'
    12 = 'Not enough free resources (conflict with another device)'
    14 = 'Needs a restart to work'
    18 = 'Drivers need to be reinstalled'
    19 = 'Registry settings for this device are damaged'
    21 = 'Windows is removing this device (restart)'
    22 = 'Disabled (someone turned it off in Device Manager)'
    24 = 'Not present, not working, or missing drivers'
    28 = 'No driver installed'
    29 = 'Disabled in firmware (BIOS/UEFI)'
    31 = 'Not working properly; Windows could not load the driver'
    32 = 'Driver service is disabled'
    33 = 'Cannot work out which resources the device needs'
    34 = 'Needs manual configuration'
    35 = 'Firmware (BIOS/UEFI) is missing information for this device'
    37 = 'Driver failed to initialize'
    38 = 'A previous copy of the driver is still in memory (restart)'
    39 = 'Driver is corrupted or missing'
    40 = 'Driver registry entry is damaged'
    41 = 'Driver loaded but the hardware was not found'
    43 = 'Device reported a problem and was stopped (driver or hardware fault)'
    44 = 'An app or service shut this device down'
    45 = 'Not connected right now'
    47 = 'Prepared for safe removal (unplug and plug back in)'
    48 = 'Driver blocked because it has known problems'
    49 = 'Too many devices registered (registry is full)'
    50 = 'Waiting on another device'
    51 = 'Waiting on another device to start'
    52 = 'Driver signature could not be verified'
    54 = 'Device failed and is being reset'
}

# Device classes that matter most for stability and speed.
$keyClasses = [ordered]@{
    'DISPLAY'   = 'Graphics'
    'NET'       = 'Network'
    'MEDIA'     = 'Audio'
    'SCSIADAPTER' = 'Storage'
    'HDC'       = 'Storage'
    'BLUETOOTH' = 'Bluetooth'
    'CAMERA'    = 'Camera'
    'IMAGE'     = 'Camera'
    'BIOMETRIC' = 'Sign-in'
    'SYSTEM'    = 'Chipset'
}

function Write-Section([string]$title) {
    Write-Host ''
    Write-Host $title -ForegroundColor Cyan
    Write-Host ('-' * $title.Length) -ForegroundColor DarkGray
}

function Test-MicrosoftProvider([string]$p) {
    return ($p -match '^\s*Microsoft')
}

function Format-Date($d) {
    if ($d -is [datetime]) { return $d.ToString('yyyy-MM-dd') }
    return ''
}

function Read-InfInfo([string]$path) {
    # Returns provider, class, date and version from an .inf [Version] section.
    $lines = $null
    try { $lines = Get-Content -LiteralPath $path -ErrorAction Stop } catch { return $null }
    $section = ''
    $ver = @{}
    $strings = @{}
    $localStrings = @{}
    foreach ($raw in $lines) {
        $line = ($raw -replace ';.*$', '').Trim()
        if (-not $line) { continue }
        if ($line -match '^\[(.+)\]$') { $section = $Matches[1].Trim().ToLowerInvariant(); continue }
        if ($line -notmatch '^([^=]+?)\s*=\s*(.*)$') { continue }
        $k = $Matches[1].Trim().ToLowerInvariant()
        $v = $Matches[2].Trim().Trim('"')
        if ($section -eq 'version') { $ver[$k] = $v }
        elseif ($section -eq 'strings') { $strings[$k] = $v }
        elseif ($section -like 'strings.*' -and -not $localStrings.ContainsKey($k)) { $localStrings[$k] = $v }
    }
    $resolve = {
        param($s)
        if ($s -match '^%(.+)%$') {
            $key = $Matches[1].ToLowerInvariant()
            if ($strings.ContainsKey($key)) { return $strings[$key] }
            if ($localStrings.ContainsKey($key)) { return $localStrings[$key] }
        }
        return $s
    }
    $provider = ''
    if ($ver.ContainsKey('provider')) { $provider = & $resolve $ver['provider'] }
    $class = ''
    if ($ver.ContainsKey('class')) { $class = $ver['class'] }
    $date = $null; $version = ''
    if ($ver.ContainsKey('driverver')) {
        $parts = $ver['driverver'] -split ','
        $d = [datetime]::MinValue
        $formats = [string[]]@('M/d/yyyy', 'MM/dd/yyyy')
        if ([datetime]::TryParseExact($parts[0].Trim(), $formats,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$d)) { $date = $d }
        if ($parts.Count -gt 1) { $version = $parts[1].Trim() }
    }
    [pscustomobject]@{
        Inf      = [IO.Path]::GetFileName($path)
        Provider = $provider
        Class    = $class
        Date     = $date
        Version  = $version
    }
}

function ConvertTo-Version([string]$s) {
    $v = $null
    if ([version]::TryParse($s, [ref]$v)) { return $v }
    return [version]'0.0'
}

Write-Host "Driver report for this PC - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White

# ------------------------------------------------------------------ Gather
$devices = @()
try { $devices = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop) }
catch { Write-Warning "Couldn't read devices: $($_.Exception.Message)" }

$drivers = @()
try { $drivers = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop | Where-Object { $_.DeviceName }) }
catch { Write-Warning "Couldn't read drivers: $($_.Exception.Message)" }

$ghosts = @()
if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) {
    try { $ghosts = @(Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Status -eq 'Unknown' }) } catch { }
}

$rows = foreach ($d in $drivers) {
    $provider = [string]$d.DriverProviderName
    $isMs     = Test-MicrosoftProvider $provider
    $date     = $null
    if ($d.DriverDate -is [datetime]) { $date = $d.DriverDate }
    $isOld    = ($date -and $date -lt $cutoff -and ($IncludeMicrosoft -or -not $isMs))
    $unsigned = ($d.IsSigned -eq $false)
    [pscustomobject]@{
        Device   = [string]$d.DeviceName
        Class    = [string]$d.DeviceClass
        Provider = $provider
        Version  = [string]$d.DriverVersion
        Date     = $date
        Signed   = [bool]$d.IsSigned
        Signer   = [string]$d.Signer
        Inf      = [string]$d.InfName
        Old      = [bool]$isOld
        Unsigned = [bool]$unsigned
        Microsoft = [bool]$isMs
    }
}
$rows = @($rows)

$problems = @($devices | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 })
$oldRows  = @($rows | Where-Object Old | Sort-Object Date)
$unsignedRows = @($rows | Where-Object Unsigned)

# Third-party driver packages in the driver store.
$store = @()
if (Test-Path $infDir) {
    $store = @(Get-ChildItem -LiteralPath $infDir -Filter 'oem*.inf' -File -ErrorAction SilentlyContinue |
               ForEach-Object { Read-InfInfo $_.FullName } | Where-Object { $_ })
}
$inUseInfs = @{}
foreach ($r in $rows) { if ($r.Inf) { $inUseInfs[$r.Inf.ToLowerInvariant()] = $true } }
$unused = @($store | Where-Object { -not $inUseInfs.ContainsKey($_.Inf.ToLowerInvariant()) })

# An unused package is "probably replaced" when a package from the same maker
# and class with a newer version is in use.
$replaced = foreach ($u in $unused) {
    $newer = $store | Where-Object {
        $inUseInfs.ContainsKey($_.Inf.ToLowerInvariant()) -and
        $_.Provider -eq $u.Provider -and $_.Class -eq $u.Class -and
        (ConvertTo-Version $_.Version) -gt (ConvertTo-Version $u.Version)
    } | Select-Object -First 1
    if ($newer) {
        [pscustomobject]@{
            Inf = $u.Inf; Provider = $u.Provider; Class = $u.Class; Version = $u.Version
            Date = $u.Date; ReplacedBy = "$($newer.Inf) ($($newer.Version))"
        }
    }
}
$replaced = @($replaced)

# ----------------------------------------------------------------- Summary
Write-Section 'Summary'
$summary = [ordered]@{
    'Devices'                        = $devices.Count
    'Drivers in use'                 = $rows.Count
    'Devices with problems'          = $problems.Count
    "Third-party drivers older than $OlderThanYears yr" = $oldRows.Count
    'Unsigned drivers'               = $unsignedRows.Count
    'Devices no longer connected'    = $ghosts.Count
    'Third-party driver packages'    = $store.Count
    'Packages no connected device uses' = $unused.Count
}
foreach ($k in $summary.Keys) { Write-Host ('  {0,-38} {1}' -f $k, $summary[$k]) }

# ---------------------------------------------------------------- Problems
Write-Section 'Devices with problems'
if ($problems.Count -eq 0) {
    Write-Host '  None. Device Manager shows no warnings.' -ForegroundColor Green
} else {
    $problems | Sort-Object ConfigManagerErrorCode, Name | ForEach-Object {
        $code = [int]$_.ConfigManagerErrorCode
        $meaning = 'Unknown error'
        if ($errorCodes.ContainsKey($code)) { $meaning = $errorCodes[$code] }
        [pscustomobject]@{
            Device  = $_.Name
            Class   = $_.PNPClass
            Code    = $code
            Meaning = $meaning
        }
    } | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
}

# ------------------------------------------------------------- Key drivers
Write-Section 'Key drivers'
$key = foreach ($r in $rows) {
    $c = $r.Class.ToUpperInvariant()
    if (-not $keyClasses.Contains($c)) { continue }
    # Chipset: only show third-party system drivers (Intel/AMD chipset, ME, etc.)
    if ($c -eq 'SYSTEM' -and $r.Microsoft) { continue }
    # Network: skip Microsoft's virtual adapters (WAN Miniport and similar)
    if ($c -eq 'NET' -and $r.Microsoft) { continue }
    [pscustomobject]@{
        Kind     = $keyClasses[$c]
        Device   = $r.Device
        Provider = $r.Provider
        Version  = $r.Version
        Date     = Format-Date $r.Date
    }
}
$key = @($key | Sort-Object Kind, Device -Unique)
if ($key.Count -eq 0) { Write-Host '  No key drivers found.' }
else { $key | Format-Table -AutoSize | Out-String -Width 200 | Write-Host }

# ------------------------------------------------------------- Old drivers
Write-Section "Third-party drivers older than $OlderThanYears years"
if ($oldRows.Count -eq 0) { Write-Host '  None.' -ForegroundColor Green }
else {
    $oldRows | Select-Object -First $Top Device, Class, Provider, Version,
        @{ n = 'Date'; e = { Format-Date $_.Date } } |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    if ($oldRows.Count -gt $Top) { Write-Host "  ...and $($oldRows.Count - $Top) more (use -Top or -CsvPath)." }
}

# ---------------------------------------------------------------- Unsigned
Write-Section 'Unsigned drivers'
if ($unsignedRows.Count -eq 0) { Write-Host '  None.' -ForegroundColor Green }
else {
    $unsignedRows | Select-Object Device, Class, Provider, Version, Inf |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host
}

# ------------------------------------------------------------ Driver store
Write-Section 'Driver store (third-party packages)'
Write-Host "  $($store.Count) package(s) in $infDir, $($unused.Count) not used by any connected device."
Write-Host '  An unused package may still be needed for a device you plug in now and then.'
if ($replaced.Count -gt 0) {
    Write-Host ''
    Write-Host '  Probably replaced by a newer package from the same maker:' -ForegroundColor Yellow
    $replaced | Sort-Object Provider, Class, Date | Select-Object -First $Top Inf, Provider, Class, Version,
        @{ n = 'Date'; e = { Format-Date $_.Date } }, ReplacedBy |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    Write-Host '  To remove one yourself (admin terminal; nothing is run by this script):' -ForegroundColor DarkGray
    Write-Host "    pnputil /delete-driver $($replaced[0].Inf)" -ForegroundColor DarkGray
}

# ------------------------------------------------------------------ Policy
Write-Section 'Driver update policy'
$wuNoDrivers = $false
$autoDownloadOff = $false
try {
    $p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop
    if ($p.PSObject.Properties['ExcludeWUDriversInQualityUpdate'] -and $p.ExcludeWUDriversInQualityUpdate -eq 1) { $wuNoDrivers = $true }
} catch { }
try {
    $s = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' -ErrorAction Stop
    if ($s.PSObject.Properties['SearchOrderConfig'] -and $s.SearchOrderConfig -eq 0) { $autoDownloadOff = $true }
} catch { }
if ($wuNoDrivers) { Write-Host '  Windows Update: drivers are EXCLUDED by policy' -ForegroundColor Yellow }
else { Write-Host '  Windows Update: allowed to deliver drivers' }
if ($autoDownloadOff) { Write-Host '  Automatic driver and device app downloads: OFF' -ForegroundColor Yellow }
else { Write-Host '  Automatic driver and device app downloads: on' }

if ($ShowAll) {
    Write-Section 'All drivers in use'
    $rows | Sort-Object Class, Device | Select-Object Device, Class, Provider, Version,
        @{ n = 'Date'; e = { Format-Date $_.Date } }, Signed |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host
}

# ---------------------------------------------------------------- Findings
foreach ($pr in $problems) {
    $code = [int]$pr.ConfigManagerErrorCode
    if ($code -eq 22) {
        $findings.Add("'$($pr.Name)' is disabled in Device Manager. Fine if you meant it; otherwise right-click it there and choose Enable device.")
    } elseif ($code -eq 28) {
        $findings.Add("'$($pr.Name)' has no driver. Try Settings > Windows Update > Advanced options > Optional updates, or the PC or device maker's support page.")
    } elseif ($code -eq 45) {
        continue
    } else {
        $meaning = 'Unknown error'
        if ($errorCodes.ContainsKey($code)) { $meaning = $errorCodes[$code] }
        $findings.Add("'$($pr.Name)' has error $code ($meaning). Updating or reinstalling its driver usually fixes it.")
    }
}
$gpuOld = @($oldRows | Where-Object { $_.Class -eq 'DISPLAY' })
if ($gpuOld.Count) {
    $findings.Add("Your graphics driver ($($gpuOld[0].Device)) is from $(Format-Date $gpuOld[0].Date). A current driver from the GPU maker often fixes stutter, crashes and sleep problems.")
}
$netOld = @($oldRows | Where-Object { $_.Class -eq 'NET' })
if ($netOld.Count) {
    $findings.Add("$($netOld.Count) network driver(s) are over $OlderThanYears years old, such as $($netOld[0].Device). Old Wi-Fi and Ethernet drivers are a common cause of dropouts.")
}
$otherOld = $oldRows.Count - $gpuOld.Count - $netOld.Count
if ($otherOld -gt 0) {
    $findings.Add("$otherOld other third-party driver(s) are over $OlderThanYears years old. Check the PC maker's support page or Optional updates for newer ones.")
}
if ($unsignedRows.Count) {
    $findings.Add("$($unsignedRows.Count) driver(s) are unsigned, such as $($unsignedRows[0].Device). Make sure you know where each came from; unsigned drivers can be unstable or unsafe.")
}
if ($replaced.Count) {
    $findings.Add("$($replaced.Count) old driver package(s) look replaced by newer ones from the same maker. They're harmless but take up space; remove them with pnputil /delete-driver from an admin terminal if you want.")
}
if ($ghosts.Count -ge 50) {
    $findings.Add("Windows remembers $($ghosts.Count) devices that aren't connected (old USB sticks, monitors, phones). Normal, but Device Manager > View > Show hidden devices lets you remove the ones you'll never use again.")
}
if ($wuNoDrivers) {
    $findings.Add('A policy stops Windows Update from delivering drivers, so you need to update them yourself (or remove the policy if you didn''t set it).')
}

Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  Nothing stands out. Your drivers look healthy.' -ForegroundColor Green
} else {
    $i = 1
    foreach ($f in $findings) { Write-Host ("  {0}. {1}" -f $i, $f); $i++ }
}

if ($CsvPath) {
    try {
        $rows | Sort-Object Class, Device | Select-Object Device, Class, Provider, Version,
            @{ n = 'Date'; e = { Format-Date $_.Date } }, Signed, Signer, Inf, Old, Unsigned |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host ''
        Write-Host "Saved $($rows.Count) drivers to $CsvPath" -ForegroundColor Green
    } catch { Write-Warning "Couldn't write ${CsvPath}: $($_.Exception.Message)" }
}
