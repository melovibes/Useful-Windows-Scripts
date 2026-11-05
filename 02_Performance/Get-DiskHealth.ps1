<#
.SYNOPSIS
    Get-DiskHealth.ps1 - Read-only disk and volume health report for Windows 11.
    Answers "is my disk dying or full?"

.DESCRIPTION
    Checks and reports:
      Physical disks   Model, media type (SSD / HDD), size, bus type, health and
                       operational status (Get-PhysicalDisk / Get-Disk), including
                       predictive-failure style statuses when Windows reports them
      Age & updates    Power-on age when reliability counters expose PowerOnHours;
                       otherwise best-effort "first seen by Windows" from the disk's
                       PnP install date. Firmware revision, storage driver version
                       and driver date (firmware flash date is rarely exposed — shown
                       as n/a when Windows does not provide it)
      Volumes          Drive letter, label, file system, size, free space and free %,
                       with warnings when free space is low
      Reliability      Temperature, wear, read/write (incl. uncorrected) errors and
                       power-on hours from Get-StorageReliabilityCounter when the
                       counters are available (often needs admin; skipped cleanly
                       when not). These are Windows' SMART-style counters, not a
                       full vendor SMART dump.
      Top folders      Optional: with -Path, sizes of the largest top-level folders
                       on that drive (light check only — use Survey-Drive.ps1 for a
                       deep survey)
      Findings         Plain-English notes: Warning / Unhealthy / Failed /
                       Predictive Failure disks, low free space, high wear, high
                       temperature, corrected and uncorrected I/O errors

    Safety level : SAFE (strictly read-only). Nothing is deleted, formatted,
                   optimized or repaired. No network calls. The only file written
                   is the optional -CsvPath.

    Admin        : Not required. Run as administrator to unlock storage reliability
                   counters (temperature, wear, error counts, power-on hours) on
                   more disks.

.PARAMETER WarnPercent
    Flag a volume when free space is at or below this percent. Default: 15.

.PARAMETER WarnGB
    Also flag a volume when free space is under this many gigabytes, even if the
    percent looks fine. Default: 20. Set to 0 to disable the GB check.

.PARAMETER Path
    Optional drive or folder. When set, measure the largest top-level folders under
    it (each folder's size is summed recursively, but only the top level is listed).
    For a full space survey use .\01_Organization\Survey-Drive.ps1 instead.

.PARAMETER Top
    How many top-level folders to show when -Path is set. Default: 10.

.PARAMETER CsvPath
    Export disks, volumes and (if measured) top folders to this CSV file.

.EXAMPLE
    .\Get-DiskHealth.ps1
    Disk health, volume free space and findings.

.EXAMPLE
    .\Get-DiskHealth.ps1 -Path C:\ -Top 15 -CsvPath "$env:USERPROFILE\Desktop\disk-health.csv"
    Same, plus the largest folders on C:\, saved to a CSV.

.NOTES
    Usage:
      powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-DiskHealth.ps1"
      powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-DiskHealth.ps1" -Path D:\ -WarnPercent 10
    Tip: a Health status of Warning or Unhealthy, or an operational status like
    Predictive Failure / Pred Fail, means back up now and check the drive in the
    manufacturer's tool (or replace it). This script never repairs.
    Works on Windows 10 and 11, Windows PowerShell 5.1 or PowerShell 7.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 50)]
    [int]$WarnPercent = 15,

    [ValidateRange(0, 1024)]
    [int]$WarnGB = 20,

    [string]$Path,

    [ValidateRange(1, 50)]
    [int]$Top = 10,

    [string]$CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-Header([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}

function Format-Bytes([double]$Bytes) {
    if ($null -eq $Bytes -or $Bytes -lt 0) { return 'n/a' }
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}

function Format-Hours([object]$Hours) {
    if ($null -eq $Hours) { return 'n/a' }
    try {
        $h = [double]$Hours
        if ($h -lt 0) { return 'n/a' }
        if ($h -ge 8760) { return ('{0:N0} h (~{1:N1} years)' -f $h, ($h / 8760.0)) }
        if ($h -ge 24) { return ('{0:N0} h (~{1:N1} days)' -f $h, ($h / 24.0)) }
        return ('{0:N0} h' -f $h)
    } catch { return 'n/a' }
}

function Format-AgeFromHours([object]$Hours) {
    # Human age string for power-on hours (SMART-style PowerOnHours).
    if ($null -eq $Hours) { return $null }
    try {
        $h = [double]$Hours
        if ($h -lt 0) { return $null }
        if ($h -ge 8760) { return ('{0:N1} years powered on' -f ($h / 8760.0)) }
        if ($h -ge 24) { return ('{0:N1} days powered on' -f ($h / 24.0)) }
        return ('{0:N0} hours powered on' -f $h)
    } catch { return $null }
}

function Format-DateSoft([object]$Value) {
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try {
        if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd') }
        # Win32_PnPSignedDriver.DriverDate is often a CIM datetime string
        $dt = [datetime]::Parse([string]$Value)
        return $dt.ToString('yyyy-MM-dd')
    } catch {
        try {
            # DMTF CIM_DATETIME: yyyymmddHHMMSS.mmmmmm+UUU
            $s = [string]$Value
            if ($s.Length -ge 8 -and $s.Substring(0, 8) -match '^\d{8}$') {
                return ('{0}-{1}-{2}' -f $s.Substring(0, 4), $s.Substring(4, 2), $s.Substring(6, 2))
            }
        } catch { }
        return [string]$Value
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Level, [string]$Text) {
    $findings.Add([pscustomobject]@{ Level = $Level; Text = $Text })
}

$csvRows = New-Object System.Collections.Generic.List[object]

Write-Host 'Get-DiskHealth - read-only disk and volume report' -ForegroundColor Green
if (-not $isAdmin) {
    Write-Host '[i] Not running as admin: reliability counters (temp, wear, errors) may be skipped.' -ForegroundColor Yellow
}

# --- Physical disks ------------------------------------------------------------
Write-Header 'Physical disks'

$physicalDisks = @()
$disks = @()
try { $physicalDisks = @(Get-PhysicalDisk -ErrorAction Stop) } catch {
    Write-Host "  Get-PhysicalDisk unavailable: $($_.Exception.Message)" -ForegroundColor DarkGray
}
try { $disks = @(Get-Disk -ErrorAction Stop) } catch {
    Write-Host "  Get-Disk unavailable: $($_.Exception.Message)" -ForegroundColor DarkGray
}

$diskByNumber = @{}
foreach ($d in $disks) {
    try { $diskByNumber[[int]$d.Number] = $d } catch { }
}

# Win32_DiskDrive + signed storage drivers: firmware, PnP id, driver date/version
$wmiByIndex = @{}
$wmiBySerial = @{}
try {
    foreach ($wd in @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop)) {
        try { $wmiByIndex[[int]$wd.Index] = $wd } catch { }
        $ser = ''
        try { $ser = ([string]$wd.SerialNumber).Trim() } catch { }
        if (-not [string]::IsNullOrWhiteSpace($ser) -and -not $wmiBySerial.ContainsKey($ser)) {
            $wmiBySerial[$ser] = $wd
        }
    }
} catch {
    Write-Verbose "Win32_DiskDrive lookup unavailable: $($_.Exception.Message)"
}

$driverByDeviceId = @{}
try {
    foreach ($drv in @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop)) {
        $id = $null
        try { $id = [string]$drv.DeviceID } catch { continue }
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        # Prefer disk/storage class drivers when multiple rows share an id
        if (-not $driverByDeviceId.ContainsKey($id)) {
            $driverByDeviceId[$id] = $drv
        } else {
            $existing = $driverByDeviceId[$id]
            $devClass = ''
            try { $devClass = [string]$drv.DeviceClass } catch { }
            if ($devClass -match 'DISKDRIVE|SCSIADAPTER|HDC') {
                $driverByDeviceId[$id] = $drv
            } elseif ($null -eq $existing) {
                $driverByDeviceId[$id] = $drv
            }
        }
    }
} catch {
    Write-Verbose "Win32_PnPSignedDriver lookup unavailable: $($_.Exception.Message)"
}

function Resolve-DiskWmi {
    param($Number, [string]$Serial)
    if ($null -ne $Number -and $wmiByIndex.ContainsKey([int]$Number)) {
        return $wmiByIndex[[int]$Number]
    }
    if (-not [string]::IsNullOrWhiteSpace($Serial)) {
        $s = $Serial.Trim()
        if ($wmiBySerial.ContainsKey($s)) { return $wmiBySerial[$s] }
    }
    return $null
}

function Get-DiskDriverInfo {
    param($WmiDisk)
    if (-not $WmiDisk) {
        return [pscustomobject]@{ PnpId = $null; DriverVersion = $null; DriverDate = $null; DriverProvider = $null; DriverName = $null }
    }
    $pnp = $null
    try { $pnp = [string]$WmiDisk.PNPDeviceID } catch { }
    $drv = $null
    if (-not [string]::IsNullOrWhiteSpace($pnp) -and $driverByDeviceId.ContainsKey($pnp)) {
        $drv = $driverByDeviceId[$pnp]
    }
    $ver = $null; $date = $null; $prov = $null; $name = $null
    if ($drv) {
        try { $ver = [string]$drv.DriverVersion } catch { }
        try { $date = Format-DateSoft $drv.DriverDate } catch { }
        try { $prov = [string]$drv.DriverProviderName } catch { }
        try { $name = [string]$drv.DeviceName } catch { }
    }
    return [pscustomobject]@{
        PnpId          = $pnp
        DriverVersion  = $ver
        DriverDate     = $date
        DriverProvider = $prov
        DriverName     = $name
    }
}

function Get-DiskFirstSeenDate {
    # Best-effort "when Windows first saw this disk" via PnP install date.
    # Used only when power-on hours are unavailable.
    param([string]$PnpId)
    if ([string]::IsNullOrWhiteSpace($PnpId)) { return $null }
    foreach ($key in @('DEVPKEY_Device_FirstInstallDate', 'DEVPKEY_Device_InstallDate')) {
        try {
            $prop = Get-PnpDeviceProperty -InstanceId $PnpId -KeyName $key -ErrorAction Stop
            if ($prop -and $null -ne $prop.Data) {
                $formatted = Format-DateSoft $prop.Data
                if ($formatted) { return $formatted }
            }
        } catch { }
    }
    # Registry fallback (still read-only)
    try {
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + $PnpId
        if (Test-Path -LiteralPath $regPath) {
            $props = Get-ItemProperty -LiteralPath $regPath -ErrorAction Stop
            foreach ($name in @('FirstInstallDateTime', 'InstallDate')) {
                if ($props.PSObject.Properties.Name -contains $name -and $null -ne $props.$name) {
                    $formatted = Format-DateSoft $props.$name
                    if ($formatted) { return $formatted }
                }
            }
        }
    } catch { }
    return $null
}

$physRows = New-Object System.Collections.Generic.List[object]

if ($physicalDisks.Count -eq 0 -and $disks.Count -eq 0) {
    # Fallback: Win32_DiskDrive
    try {
        foreach ($wd in @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop)) {
            $size = 0.0
            if ($null -ne $wd.Size) { $size = [double]$wd.Size }
            $fw = ''
            try { $fw = [string]$wd.FirmwareRevision } catch { }
            $drvInfo = Get-DiskDriverInfo -WmiDisk $wd
            $row = [pscustomobject]@{
                Number         = $wd.Index
                Friendly       = $wd.Model
                Media          = 'Unknown'
                Bus            = $wd.InterfaceType
                Size           = $size
                Health         = 'Unknown'
                Status         = $wd.Status
                Serial         = $wd.SerialNumber
                Firmware       = $fw
                PnpId          = $drvInfo.PnpId
                DriverVersion  = $drvInfo.DriverVersion
                DriverDate     = $drvInfo.DriverDate
                DriverProvider = $drvInfo.DriverProvider
                PowerOnHours   = $null
                AgeText        = $null
                AgeSource      = $null
                Object         = $null
            }
            $physRows.Add($row)
        }
    } catch {
        Write-Host "  Couldn't read disks: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    # Prefer PhysicalDisk; merge OperationalStatus from Get-Disk when numbers match
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($pd in $physicalDisks) {
        $num = $null
        try { $num = [int]$pd.DeviceId } catch {
            try { $num = [int]$pd.Number } catch { $num = $null }
        }
        $gd = $null
        if ($null -ne $num -and $diskByNumber.ContainsKey($num)) { $gd = $diskByNumber[$num] }
        if ($null -ne $num) { [void]$seen.Add($num) }

        $size = 0.0
        if ($null -ne $pd.Size) { $size = [double]$pd.Size }
        elseif ($gd -and $null -ne $gd.Size) { $size = [double]$gd.Size }

        $health = [string]$pd.HealthStatus
        $op = [string]$pd.OperationalStatus
        if ($gd) {
            if ([string]::IsNullOrWhiteSpace($health) -or $health -eq 'Unknown') {
                try { $health = [string]$gd.HealthStatus } catch { }
            }
            if ([string]::IsNullOrWhiteSpace($op)) {
                try { $op = [string]$gd.OperationalStatus } catch { }
            }
        }

        $media = [string]$pd.MediaType
        if ([string]::IsNullOrWhiteSpace($media) -or $media -eq 'Unspecified') {
            # SpindleSpeed is often 0 on SSDs; helpful hint when MediaType is blank
            try {
                if ($null -ne $pd.SpindleSpeed -and [int]$pd.SpindleSpeed -eq 0 -and $size -gt 0) { $media = 'SSD (likely)' }
            } catch { }
        }

        $serial = ''
        try { $serial = [string]$pd.SerialNumber } catch { }
        $fw = ''
        try { $fw = [string]$pd.FirmwareVersion } catch { }
        if ([string]::IsNullOrWhiteSpace($fw) -and $gd) {
            try { $fw = [string]$gd.FirmwareVersion } catch { }
        }
        $wmi = Resolve-DiskWmi -Number $num -Serial $serial
        if ([string]::IsNullOrWhiteSpace($fw) -and $wmi) {
            try { $fw = [string]$wmi.FirmwareRevision } catch { }
        }
        # Prefer a more specific WMI Status like Pred Fail when Storage cmdlets say OK
        if ($wmi) {
            try {
                $wmiStatus = [string]$wmi.Status
                if ($wmiStatus -match 'Pred|Fail|Error|Degrad') {
                    if ([string]::IsNullOrWhiteSpace($op) -or $op -eq 'OK' -or $op -eq 'Online') {
                        $op = $wmiStatus
                    } elseif ($op -notmatch 'Pred|Fail') {
                        $op = "$op / $wmiStatus"
                    }
                }
            } catch { }
        }
        $drvInfo = Get-DiskDriverInfo -WmiDisk $wmi
        $row = [pscustomobject]@{
            Number         = $num
            Friendly       = [string]$pd.FriendlyName
            Media          = $media
            Bus            = [string]$pd.BusType
            Size           = $size
            Health         = $health
            Status         = $op
            Serial         = $serial
            Firmware       = $fw
            PnpId          = $drvInfo.PnpId
            DriverVersion  = $drvInfo.DriverVersion
            DriverDate     = $drvInfo.DriverDate
            DriverProvider = $drvInfo.DriverProvider
            PowerOnHours   = $null
            AgeText        = $null
            AgeSource      = $null
            Object         = $pd
        }
        $physRows.Add($row)
    }
    # Any Get-Disk entries without a PhysicalDisk match
    foreach ($gd in $disks) {
        $num = $null
        try { $num = [int]$gd.Number } catch { continue }
        if ($seen.Contains($num)) { continue }
        $size = 0.0
        if ($null -ne $gd.Size) { $size = [double]$gd.Size }
        $serial = ''
        try { $serial = [string]$gd.SerialNumber } catch { }
        $fw = ''
        try { $fw = [string]$gd.FirmwareVersion } catch { }
        $healthGd = 'Unknown'
        try { $healthGd = [string]$gd.HealthStatus } catch { }
        $opGd = ''
        try { $opGd = [string]$gd.OperationalStatus } catch { }
        $wmi = Resolve-DiskWmi -Number $num -Serial $serial
        if ([string]::IsNullOrWhiteSpace($fw) -and $wmi) {
            try { $fw = [string]$wmi.FirmwareRevision } catch { }
        }
        if ($wmi) {
            try {
                $wmiStatus = [string]$wmi.Status
                if ($wmiStatus -match 'Pred|Fail|Error|Degrad') {
                    if ([string]::IsNullOrWhiteSpace($opGd) -or $opGd -eq 'OK' -or $opGd -eq 'Online') {
                        $opGd = $wmiStatus
                    } elseif ($opGd -notmatch 'Pred|Fail') {
                        $opGd = "$opGd / $wmiStatus"
                    }
                }
            } catch { }
        }
        $drvInfo = Get-DiskDriverInfo -WmiDisk $wmi
        $row = [pscustomobject]@{
            Number         = $num
            Friendly       = [string]$gd.FriendlyName
            Media          = 'Unknown'
            Bus            = $(try { [string]$gd.BusType } catch { '' })
            Size           = $size
            Health         = $healthGd
            Status         = $opGd
            Serial         = $serial
            Firmware       = $fw
            PnpId          = $drvInfo.PnpId
            DriverVersion  = $drvInfo.DriverVersion
            DriverDate     = $drvInfo.DriverDate
            DriverProvider = $drvInfo.DriverProvider
            PowerOnHours   = $null
            AgeText        = $null
            AgeSource      = $null
            Object         = $null
        }
        $physRows.Add($row)
    }
}

if ($physRows.Count -eq 0) {
    Write-Host '  No physical disks found.' -ForegroundColor Yellow
} else {
    $physRows |
        Sort-Object { if ($null -ne $_.Number) { $_.Number } else { 999 } } |
        Format-Table `
            @{ N = '#'; E = { $_.Number }; A = 'Right' },
            @{ N = 'Model'; E = { $_.Friendly } },
            @{ N = 'Media'; E = { $_.Media } },
            @{ N = 'Bus'; E = { $_.Bus } },
            @{ N = 'Size'; E = { Format-Bytes $_.Size }; A = 'Right' },
            @{ N = 'Health'; E = { $_.Health } },
            @{ N = 'Status'; E = { $_.Status } } -AutoSize | Out-Host

    foreach ($r in $physRows) {
        $csvRows.Add([pscustomobject]@{
            Section = 'Disk'
            Number  = $r.Number
            Name    = $r.Friendly
            Media   = $r.Media
            Bus     = $r.Bus
            SizeGB  = if ($r.Size -gt 0) { [math]::Round($r.Size / 1GB, 2) } else { $null }
            FreeGB  = $null
            FreePct = $null
            Health  = $r.Health
            Status  = $r.Status
            Extra   = ('Serial={0};Firmware={1}' -f $r.Serial, $r.Firmware)
        })
        $h = [string]$r.Health
        if ($h -match 'Unhealthy|Failed|Critical') {
            Add-Finding 'WARN' ("Disk #{0} ({1}) reports Health={2}. Back up everything on it now and replace or check it with the maker's tool." -f $r.Number, $r.Friendly, $h)
        } elseif ($h -match 'Warning|Degraded') {
            Add-Finding 'WARN' ("Disk #{0} ({1}) reports Health={2}. Back up soon and watch for more warnings." -f $r.Number, $r.Friendly, $h)
        }
        $st = [string]$r.Status
        if ($st -match 'Offline|Failed|Lost Communication|Predictive Failure|Pred Fail|Error') {
            Add-Finding 'WARN' ("Disk #{0} ({1}) operational status is '{2}' — treat this as a possible failing drive; back up now." -f $r.Number, $r.Friendly, $st)
        }
    }
}

# --- Reliability counters ------------------------------------------------------
Write-Header 'Reliability (SMART-style: temperature, wear, errors)'

$relAny = $false
foreach ($r in $physRows) {
    $pd = $null
    if ($r.PSObject.Properties.Name -contains 'Object') { $pd = $r.Object }
    if (-not $pd) { continue }

    $counters = $null
    try {
        $counters = Get-StorageReliabilityCounter -PhysicalDisk $pd -ErrorAction Stop
    } catch {
        Write-Verbose ("Reliability for disk #{0}: {1}" -f $r.Number, $_.Exception.Message)
        continue
    }
    if (-not $counters) { continue }
    $relAny = $true

    # Property names vary slightly by driver; read defensively.
    # These are Windows storage reliability counters (SMART-style subset),
    # not a full vendor SMART attribute dump — reallocated/pending sector
    # counts are not always exposed under those names.
    $temp = $null; $tempMax = $null; $wear = $null
    $readErr = $null; $readUncorr = $null; $writeErr = $null; $writeUncorr = $null
    $powerOn = $null; $startStop = $null
    foreach ($c in @($counters)) {
        try { if ($null -ne $c.Temperature) { $temp = $c.Temperature } } catch { }
        try { if ($null -ne $c.TemperatureMax) { $tempMax = $c.TemperatureMax } } catch { }
        try { if ($null -ne $c.Wear) { $wear = $c.Wear } } catch { }
        try { if ($null -ne $c.ReadErrorsTotal) { $readErr = $c.ReadErrorsTotal } } catch { }
        try { if ($null -ne $c.ReadErrorsUncorrected) { $readUncorr = $c.ReadErrorsUncorrected } } catch { }
        try { if ($null -ne $c.WriteErrorsTotal) { $writeErr = $c.WriteErrorsTotal } } catch { }
        try { if ($null -ne $c.WriteErrorsUncorrected) { $writeUncorr = $c.WriteErrorsUncorrected } } catch { }
        try { if ($null -ne $c.PowerOnHours) { $powerOn = $c.PowerOnHours } } catch { }
        try { if ($null -ne $c.StartStopCycleCount) { $startStop = $c.StartStopCycleCount } } catch { }
    }

    if ($null -ne $powerOn) {
        $r.PowerOnHours = $powerOn
        $ageFromPower = Format-AgeFromHours $powerOn
        if ($ageFromPower) {
            $r.AgeText = $ageFromPower
            $r.AgeSource = 'PowerOnHours (Get-StorageReliabilityCounter)'
        }
    }

    Write-Host ("  Disk #{0} ({1})" -f $r.Number, $r.Friendly) -ForegroundColor White
    Write-Host ("    Temperature      : {0}" -f $(if ($null -ne $temp) { "$temp C" } else { 'n/a' }))
    if ($null -ne $tempMax) {
        Write-Host ("    Temp max (seen)  : {0} C" -f $tempMax)
    }
    Write-Host ("    Wear             : {0}" -f $(if ($null -ne $wear) { "$wear %" } else { 'n/a' }))
    Write-Host ("    Read errors      : {0}" -f $(if ($null -ne $readErr) { $readErr } else { 'n/a' }))
    Write-Host ("    Read uncorrected : {0}" -f $(if ($null -ne $readUncorr) { $readUncorr } else { 'n/a' }))
    Write-Host ("    Write errors     : {0}" -f $(if ($null -ne $writeErr) { $writeErr } else { 'n/a' }))
    Write-Host ("    Write uncorrected: {0}" -f $(if ($null -ne $writeUncorr) { $writeUncorr } else { 'n/a' }))
    Write-Host ("    Power-on hours   : {0}" -f (Format-Hours $powerOn))
    if ($null -ne $startStop) {
        Write-Host ("    Start/stop cycles: {0}" -f $startStop)
    }

    $csvRows.Add([pscustomobject]@{
        Section = 'Reliability'
        Number  = $r.Number
        Name    = $r.Friendly
        Media   = $r.Media
        Bus     = $r.Bus
        SizeGB  = if ($r.Size -gt 0) { [math]::Round($r.Size / 1GB, 2) } else { $null }
        FreeGB  = $null
        FreePct = $null
        Health  = $r.Health
        Status  = $r.Status
        Extra   = ('Temp={0};TempMax={1};Wear={2};ReadErr={3};ReadUncorr={4};WriteErr={5};WriteUncorr={6};PowerOnH={7}' -f $temp, $tempMax, $wear, $readErr, $readUncorr, $writeErr, $writeUncorr, $powerOn)
    })

    if ($null -ne $temp -and [double]$temp -ge 70) {
        Add-Finding 'WARN' ("Disk #{0} ({1}) is hot ({2} C). Check airflow and dust; sustained high temps shorten drive life." -f $r.Number, $r.Friendly, $temp)
    } elseif ($null -ne $temp -and [double]$temp -ge 60) {
        Add-Finding 'INFO' ("Disk #{0} ({1}) temperature is {2} C (warm but often normal under load)." -f $r.Number, $r.Friendly, $temp)
    }
    if ($null -ne $wear -and [double]$wear -ge 90) {
        Add-Finding 'WARN' ("Disk #{0} ({1}) wear is {2}%. Plan a replacement and back up now." -f $r.Number, $r.Friendly, $wear)
    } elseif ($null -ne $wear -and [double]$wear -ge 70) {
        Add-Finding 'INFO' ("Disk #{0} ({1}) wear is {2}%. Keep backups current." -f $r.Number, $r.Friendly, $wear)
    }
    if ($null -ne $readUncorr -and [long]$readUncorr -gt 0) {
        Add-Finding 'WARN' ("Disk #{0} ({1}) has {2} uncorrected read error(s). Data may already be damaged — back up immediately and run the manufacturer's diagnostic." -f $r.Number, $r.Friendly, $readUncorr)
    } elseif ($null -ne $readErr -and [long]$readErr -gt 0) {
        Add-Finding 'WARN' ("Disk #{0} ({1}) has {2} read error(s). Back up and run the manufacturer's diagnostic." -f $r.Number, $r.Friendly, $readErr)
    }
    if ($null -ne $writeUncorr -and [long]$writeUncorr -gt 0) {
        Add-Finding 'WARN' ("Disk #{0} ({1}) has {2} uncorrected write error(s). Back up immediately and run the manufacturer's diagnostic." -f $r.Number, $r.Friendly, $writeUncorr)
    } elseif ($null -ne $writeErr -and [long]$writeErr -gt 0) {
        Add-Finding 'WARN' ("Disk #{0} ({1}) has {2} write error(s). Back up and run the manufacturer's diagnostic." -f $r.Number, $r.Friendly, $writeErr)
    }
}

if (-not $relAny) {
    if ($isAdmin) {
        Write-Host '  No reliability counters available on these disks (common for some USB/virtual drives).' -ForegroundColor DarkGray
    } else {
        Write-Host '  No reliability counters returned. Run as admin, or the disks may not expose them.' -ForegroundColor DarkGray
        Add-Finding 'INFO' 'Run as administrator to unlock temperature, wear and error counters when the drive supports them.'
    }
}

# --- Age, firmware & driver ----------------------------------------------------
Write-Header 'Age, firmware & driver'

Write-Host '  Age prefers SMART-style PowerOnHours from reliability counters.' -ForegroundColor DarkGray
Write-Host '  If those are missing, falls back to when Windows first installed/saw the disk (PnP).' -ForegroundColor DarkGray
Write-Host '  Firmware flash date is almost never exposed by Windows; driver date is the storage driver.' -ForegroundColor DarkGray

foreach ($r in @($physRows | Sort-Object { if ($null -ne $_.Number) { $_.Number } else { 999 } })) {
    # Fill age from PnP when power-on hours were not available
    if (-not $r.AgeText) {
        $firstSeen = Get-DiskFirstSeenDate -PnpId $r.PnpId
        if ($firstSeen) {
            $r.AgeText = "first seen by Windows on $firstSeen"
            $r.AgeSource = 'PnP FirstInstallDate / InstallDate (not power-on age)'
        }
    }

    $fwDisplay = if ([string]::IsNullOrWhiteSpace([string]$r.Firmware)) { 'n/a' } else { [string]$r.Firmware }
    $ageDisplay = if ($r.AgeText) { $r.AgeText } else { 'n/a' }
    $ageSrcDisplay = if ($r.AgeSource) { $r.AgeSource } else { 'not available (need admin reliability counters or PnP id)' }
    $drvVer = if ([string]::IsNullOrWhiteSpace([string]$r.DriverVersion)) { 'n/a' } else { [string]$r.DriverVersion }
    $drvDate = if ([string]::IsNullOrWhiteSpace([string]$r.DriverDate)) { 'n/a' } else { [string]$r.DriverDate }
    $drvProv = if ([string]::IsNullOrWhiteSpace([string]$r.DriverProvider)) { '' } else { " ($($r.DriverProvider))" }

    Write-Host ("  Disk #{0} ({1})" -f $r.Number, $r.Friendly) -ForegroundColor White
    Write-Host ("    Age              : {0}" -f $ageDisplay)
    Write-Host ("    Age source       : {0}" -f $ageSrcDisplay)
    Write-Host ("    Firmware         : {0}" -f $fwDisplay)
    Write-Host ("    Firmware updated : n/a (Windows does not expose disk firmware flash date)")
    Write-Host ("    Driver version   : {0}{1}" -f $drvVer, $drvProv)
    Write-Host ("    Driver date      : {0}" -f $drvDate)

    $csvRows.Add([pscustomobject]@{
        Section = 'AgeFirmware'
        Number  = $r.Number
        Name    = $r.Friendly
        Media   = $r.Media
        Bus     = $r.Bus
        SizeGB  = if ($r.Size -gt 0) { [math]::Round($r.Size / 1GB, 2) } else { $null }
        FreeGB  = $null
        FreePct = $null
        Health  = $r.Health
        Status  = $r.Status
        Extra   = ('Age={0};AgeSource={1};Firmware={2};DriverVersion={3};DriverDate={4};PowerOnH={5}' -f $ageDisplay, $ageSrcDisplay, $fwDisplay, $drvVer, $drvDate, $r.PowerOnHours)
    })
}

if ($physRows.Count -eq 0) {
    Write-Host '  No disks to report age/firmware for.' -ForegroundColor DarkGray
}

# --- Volumes -------------------------------------------------------------------
Write-Header 'Volumes'

$volumes = @()
try {
    $volumes = @(Get-Volume -ErrorAction Stop | Where-Object {
        # Skip tiny system stubs with no size; keep lettered and sizable volumes
        ($null -ne $_.Size -and [double]$_.Size -gt 0) -or -not [string]::IsNullOrWhiteSpace([string]$_.DriveLetter)
    })
} catch {
    Write-Host "  Get-Volume unavailable, falling back to Win32_LogicalDisk: $($_.Exception.Message)" -ForegroundColor DarkGray
    try {
        foreach ($ld in @(Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop)) {
            $volumes += [pscustomobject]@{
                DriveLetter     = $(if ($ld.DeviceID) { $ld.DeviceID.TrimEnd(':') } else { $null })
                FileSystemLabel = $ld.VolumeName
                FileSystem      = $ld.FileSystem
                Size            = $ld.Size
                SizeRemaining   = $ld.FreeSpace
                HealthStatus    = 'Unknown'
                DriveType       = $ld.DriveType
            }
        }
    } catch {
        Write-Host "  Couldn't read volumes: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$volRows = New-Object System.Collections.Generic.List[object]
$warnBytes = [double]$WarnGB * 1GB

foreach ($v in $volumes) {
    $letter = $null
    try {
        if ($null -ne $v.DriveLetter -and [string]$v.DriveLetter -ne '') {
            $letter = ([string]$v.DriveLetter).TrimEnd(':')
        }
    } catch { }

    $size = 0.0
    $free = 0.0
    try { if ($null -ne $v.Size) { $size = [double]$v.Size } } catch { }
    try { if ($null -ne $v.SizeRemaining) { $free = [double]$v.SizeRemaining } } catch { }

    # Skip empty CD/DVD / no-media with zero size and no letter
    if ($size -le 0 -and [string]::IsNullOrWhiteSpace($letter)) { continue }

    $pct = $null
    if ($size -gt 0) { $pct = [math]::Round(100.0 * $free / $size, 1) }

    $label = ''
    try { $label = [string]$v.FileSystemLabel } catch { }
    $fs = ''
    try { $fs = [string]$v.FileSystem } catch { }
    $health = 'Unknown'
    try { if ($null -ne $v.HealthStatus) { $health = [string]$v.HealthStatus } } catch { }

    $display = if ($letter) { "${letter}:" } else { '(no letter)' }
    $low = $false
    if ($null -ne $pct -and $pct -le $WarnPercent) { $low = $true }
    if ($WarnGB -gt 0 -and $size -gt 0 -and $free -lt $warnBytes) { $low = $true }

    $row = [pscustomobject]@{
        Letter = $display
        Label  = $label
        FS     = $fs
        Size   = $size
        Free   = $free
        Pct    = $pct
        Health = $health
        Low    = $low
    }
    $volRows.Add($row)

    $csvRows.Add([pscustomobject]@{
        Section = 'Volume'
        Number  = $null
        Name    = ("{0} {1}" -f $display, $label).Trim()
        Media   = $fs
        Bus     = $null
        SizeGB  = if ($size -gt 0) { [math]::Round($size / 1GB, 2) } else { $null }
        FreeGB  = if ($size -gt 0) { [math]::Round($free / 1GB, 2) } else { $null }
        FreePct = $pct
        Health  = $health
        Status  = $(if ($low) { 'LOW SPACE' } else { 'OK' })
        Extra   = $null
    })
}

if ($volRows.Count -eq 0) {
    Write-Host '  No volumes found.' -ForegroundColor Yellow
} else {
    $volRows |
        Sort-Object Letter |
        Format-Table `
            @{ N = 'Drive'; E = { $_.Letter } },
            @{ N = 'Label'; E = { $_.Label } },
            @{ N = 'FS'; E = { $_.FS } },
            @{ N = 'Size'; E = { Format-Bytes $_.Size }; A = 'Right' },
            @{ N = 'Free'; E = { Format-Bytes $_.Free }; A = 'Right' },
            @{ N = 'Free %'; E = { if ($null -ne $_.Pct) { '{0:N1}%' -f $_.Pct } else { 'n/a' } }; A = 'Right' },
            @{ N = 'Health'; E = { $_.Health } },
            @{ N = 'Flag'; E = { if ($_.Low) { 'LOW' } else { '' } } } -AutoSize | Out-Host

    Write-Host ("  Low-space threshold: <= {0}% free, or under {1} GB free." -f $WarnPercent, $WarnGB) -ForegroundColor DarkGray

    foreach ($r in $volRows) {
        if ($r.Health -match 'Warning|Unhealthy|Failed') {
            Add-Finding 'WARN' ("Volume {0} ({1}) health is {2}." -f $r.Letter, $r.Label, $r.Health)
        }
        if ($r.Low -and $null -ne $r.Pct) {
            Add-Finding 'WARN' ("{0} is low on space: {1} free ({2:N1}%). Clear temp files (Clear-TempAndCache.ps1), move large folders, or free space in Settings > System > Storage." -f $r.Letter, (Format-Bytes $r.Free), $r.Pct)
        }
    }
}

# --- Optional light folder sizes -----------------------------------------------
if (-not [string]::IsNullOrWhiteSpace($Path)) {
    Write-Header ("Largest top-level folders under {0}" -f $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "  Path not found: $Path" -ForegroundColor Yellow
        Add-Finding 'INFO' ("-Path '$Path' was not found, so folder sizes were skipped.")
    } else {
        Write-Host '  Measuring top-level folders (this can take a minute on large drives)...' -ForegroundColor DarkGray
        Write-Host '  For a deep survey (file types, age, duplicates) use Survey-Drive.ps1.' -ForegroundColor DarkGray

        $folderRows = New-Object System.Collections.Generic.List[object]
        try {
            $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        } catch {
            $children = @()
            Write-Host "  Couldn't list path: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        foreach ($child in $children) {
            if (-not $child.PSIsContainer) { continue }
            # Skip reparse points (junctions / symlinks) to avoid double-counting
            try {
                if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            } catch { }

            $sum = 0.0
            try {
                # -File only; -Force includes hidden; errors on locked paths are ignored
                $sum = [double]((Get-ChildItem -LiteralPath $child.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum)
            } catch { $sum = 0.0 }
            if ($null -eq $sum) { $sum = 0.0 }

            $folderRows.Add([pscustomobject]@{
                Name = $child.Name
                Path = $child.FullName
                Size = $sum
            })
        }

        # Also note loose files directly in Path
        $loose = 0.0
        try {
            $loose = [double]((Get-ChildItem -LiteralPath $Path -Force -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum)
        } catch { $loose = 0.0 }
        if ($null -eq $loose) { $loose = 0.0 }
        if ($loose -gt 0) {
            $folderRows.Add([pscustomobject]@{
                Name = '(files in root)'
                Path = $Path
                Size = $loose
            })
        }

        $topFolders = @($folderRows | Sort-Object Size -Descending | Select-Object -First $Top)
        if ($topFolders.Count -eq 0) {
            Write-Host '  No folders to measure.' -ForegroundColor DarkGray
        } else {
            $topFolders | Format-Table `
                @{ N = 'Folder'; E = { $_.Name } },
                @{ N = 'Size'; E = { Format-Bytes $_.Size }; A = 'Right' },
                @{ N = 'Path'; E = { $_.Path } } -AutoSize | Out-Host

            foreach ($f in $topFolders) {
                $csvRows.Add([pscustomobject]@{
                    Section = 'Folder'
                    Number  = $null
                    Name    = $f.Name
                    Media   = $null
                    Bus     = $null
                    SizeGB  = [math]::Round($f.Size / 1GB, 3)
                    FreeGB  = $null
                    FreePct = $null
                    Health  = $null
                    Status  = $null
                    Extra   = $f.Path
                })
            }
        }
    }
}

# --- Findings ------------------------------------------------------------------
Write-Header 'Findings'

if ($findings.Count -gt 0) {
    foreach ($f in $findings) {
        $color = if ($f.Level -eq 'WARN') { 'Yellow' } else { 'Gray' }
        Write-Host ('  [{0}] {1}' -f $f.Level, $f.Text) -ForegroundColor $color
    }
} else {
    Write-Host '  Disks look healthy and free space is above the warning thresholds.' -ForegroundColor Green
}

if ($CsvPath) {
    try {
        $dir = Split-Path -Parent $CsvPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host "Saved $($csvRows.Count) rows to $CsvPath" -ForegroundColor Cyan
    } catch {
        Write-Host "Couldn't write CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host 'Read-only: nothing was changed, deleted or repaired.' -ForegroundColor DarkGray
