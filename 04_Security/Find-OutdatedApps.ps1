<#
.SYNOPSIS
    Find-OutdatedApps.ps1 - Read-only audit of installed software: what's out
    of support, what has known security fixes you're missing, what hasn't been
    updated in years, and (optionally) what winget can upgrade.

.DESCRIPTION
    Old software is one of the easiest ways into a PC. This script lists every
    installed desktop app (all-users and current-user), then flags:

      Windows       Your Windows 11 version and edition, and whether Microsoft
                    still sends it security updates
      Unsupported   Apps past end of support: Flash, Silverlight, Python 2 and
                    old Python 3, old .NET runtimes, old Node.js, old Office,
                    Adobe Reader XI / Acrobat 2015-2017, Java 6/7
      Known fixes   Apps older than a release that fixed a well-known
                    exploited bug (7-Zip, WinRAR)
      Stale         Apps whose install/update date is older than -StaleYears
      Duplicates    Several versions of the same runtime side by side
      Upgrades      Apps winget can upgrade (only with -CheckUpdates)
      Findings      Plain-English list of what to fix first, with how

    Support dates are from Microsoft, Python, Node.js and vendor lifecycle
    pages at the time of writing. They're in the $Lifecycle tables below, so
    they're easy to check and update.

    Safety level : SAFE (strictly read-only). Nothing is installed, upgraded
                   or removed. No network calls unless you pass -CheckUpdates,
                   which asks winget to check its sources (Microsoft's winget
                   repository and the Microsoft Store). The only file written
                   is the optional -CsvPath.

    Admin        : Not required. Apps installed only for other user accounts
                   are not listed (Windows keeps those in each user's profile).

.PARAMETER CheckUpdates
    Ask winget which installed apps have newer versions. Contacts winget's
    sources. Uses the Microsoft.WinGet.Client module if installed, otherwise
    winget.exe. Off by default.

.PARAMETER StaleYears
    Flag apps whose install/update date is older than this many years
    (default 3). Windows records the date an app was installed or last
    updated by its installer, so this is a rough guide.

.PARAMETER IncludeStore
    Also list Microsoft Store apps for the current user (names and versions
    only; Store apps update themselves, so they're not flagged).

.PARAMETER IncludeSystem
    Also list entries Windows marks as system components (drivers,
    redistributable pieces, updates). Hidden by default to cut noise.

.PARAMETER List
    Print the full inventory table, not just the flagged apps.

.PARAMETER CsvPath
    Export the full inventory, with flags, to this CSV file.

.EXAMPLE
    .\Find-OutdatedApps.ps1

.EXAMPLE
    .\Find-OutdatedApps.ps1 -CheckUpdates -List

.EXAMPLE
    .\Find-OutdatedApps.ps1 -StaleYears 5 -CsvPath "$env:USERPROFILE\Desktop\apps.csv"

.NOTES
    Works in Windows PowerShell 5.1 and PowerShell 7 on Windows 10/11.
    To actually update something, use the app's own updater or:
        winget upgrade --id <Id>
#>
[CmdletBinding()]
param(
    [switch]$CheckUpdates,
    [ValidateRange(1, 30)][int]$StaleYears = 3,
    [switch]$IncludeStore,
    [switch]$IncludeSystem,
    [switch]$List,
    [string]$CsvPath
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$today = Get-Date

# ---------------------------------------------------------------------------
# Lifecycle data (update these as vendors publish new dates)
# ---------------------------------------------------------------------------
# Windows 11 end of servicing by version, Home/Pro vs Enterprise/Education.
$WinEos = @{
    'HomePro'    = @{ '21H2' = '2023-10-10'; '22H2' = '2024-10-08'; '23H2' = '2025-11-11'; '24H2' = '2026-10-13'; '25H2' = '2027-10-12' }
    'Enterprise' = @{ '21H2' = '2024-10-08'; '22H2' = '2025-10-14'; '23H2' = '2026-11-10'; '24H2' = '2027-10-12'; '25H2' = '2028-10-10' }
}
# .NET (Core) runtime major versions and end of support.
$DotNetEos = @{ 1 = '2019-06-27'; 2 = '2022-08-21'; 3 = '2022-12-13'; 5 = '2022-05-10'; 6 = '2024-11-12'; 7 = '2024-05-14'; 8 = '2026-11-10'; 9 = '2026-11-10' }
# Python 3 minor versions and end of life.
$PythonEos = @{ 5 = '2020-09-13'; 6 = '2021-12-23'; 7 = '2023-06-27'; 8 = '2024-10-07'; 9 = '2025-10-31'; 10 = '2026-10-31' }
# Node.js major versions and end of life.
$NodeEos = @{ 12 = '2022-04-30'; 14 = '2023-04-30'; 16 = '2023-09-11'; 17 = '2022-06-01'; 18 = '2025-04-30'; 19 = '2023-06-01'; 20 = '2026-04-30'; 21 = '2024-06-01'; 23 = '2025-06-01'; 25 = '2026-06-01' }
# Simple name-based rules: regex on DisplayName -> end-of-support date and note.
$NameRules = @(
    @{ Match = 'Adobe Flash Player';                         Date = '2020-12-31'; Note = 'Adobe Flash is dead and a common attack target. Uninstall it.' }
    @{ Match = 'Microsoft Silverlight';                      Date = '2021-10-12'; Note = 'Silverlight is out of support. Uninstall it.' }
    @{ Match = '^Python 2\.';                                Date = '2020-01-01'; Note = 'Python 2 is out of support. Uninstall it unless an old tool needs it.' }
    @{ Match = 'Java(\(TM\))? [67]\b|Java [67] Update';       Date = '2015-04-30'; Note = 'Java 6/7 is years out of support. Uninstall it or move to a current Java.' }
    @{ Match = 'Adobe Reader XI|Acrobat XI';                 Date = '2017-10-15'; Note = 'Adobe Reader/Acrobat XI is out of support. Switch to current Acrobat Reader.' }
    @{ Match = 'Acrobat (Reader )?(DC )?2015';               Date = '2020-04-07'; Note = 'Acrobat 2015 is out of support. Switch to current Acrobat Reader.' }
    @{ Match = 'Acrobat (Reader )?(DC )?2017';               Date = '2022-06-06'; Note = 'Acrobat 2017 is out of support. Switch to current Acrobat Reader.' }
    @{ Match = 'Microsoft Office.*\b2010\b';                 Date = '2020-10-13'; Note = 'Office 2010 gets no security updates. Upgrade Office.' }
    @{ Match = 'Microsoft Office.*\b2013\b';                 Date = '2023-04-11'; Note = 'Office 2013 gets no security updates. Upgrade Office.' }
    @{ Match = 'Microsoft Office.*\b(2016|2019)\b';          Date = '2025-10-14'; Note = 'Office 2016/2019 gets no security updates. Upgrade Office.' }
)
# Minimum versions that contain fixes for well-known exploited bugs.
$MinSafe = @(
    @{ Match = '^7-Zip';  Min = '25.0';  Note = '7-Zip before 25.00 has known file-handling vulnerabilities. Update from 7-zip.org or winget.' }
    @{ Match = '^WinRAR'; Min = '7.13';  Note = 'WinRAR before 7.13 has an actively exploited path bug. Update from rarlab.com or winget.' }
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ('== ' + $Title + ' ') -ForegroundColor Cyan -NoNewline
    Write-Host ('=' * [Math]::Max(3, 70 - $Title.Length)) -ForegroundColor DarkCyan
}

function ConvertTo-Version([string]$Text) {
    if (-not $Text) { return $null }
    $m = [regex]::Match($Text, '\d+(\.\d+){0,3}')
    if (-not $m.Success) { return $null }
    $s = $m.Value
    if ($s -notmatch '\.') { $s += '.0' }
    $v = $null
    if ([version]::TryParse($s, [ref]$v)) { return $v }
    return $null
}

function ConvertFrom-InstallDate([string]$Text) {
    if ($Text -match '^\d{8}$') {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($Text, 'yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$d)) { return $d }
    }
    return $null
}

function Get-EosStatus([string]$Date) {
    $end = [datetime]::ParseExact($Date, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $days = [int]($end - $today.Date).TotalDays
    if ($days -lt 0)      { return @{ Level = 'Unsupported'; Text = "out of support since $Date" } }
    elseif ($days -le 90) { return @{ Level = 'EndingSoon';  Text = "support ends $Date (in $days day(s))" } }
    return $null
}

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Level, [string]$What, [string]$Fix) {
    $findings.Add([pscustomobject]@{ Level = $Level; What = $What; Fix = $Fix })
}

# ---------------------------------------------------------------------------
# Windows version
# ---------------------------------------------------------------------------
Write-Section 'Windows'
try {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $displayVer = $cv.PSObject.Properties['DisplayVersion']
    $ver = if ($displayVer) { $displayVer.Value } else { $null }
    $edition = $cv.EditionID
    $build = "$($cv.CurrentBuild).$($cv.UBR)"
    $name = $cv.ProductName
    # ProductName still says "Windows 10" on many Windows 11 installs; trust the build number.
    if ([int]$cv.CurrentBuild -ge 22000) { $name = $name -replace 'Windows 10', 'Windows 11' }
    Write-Host ("{0} {1} (build {2})" -f $name, $ver, $build)

    if ([int]$cv.CurrentBuild -ge 22000 -and $ver) {
        $track = if ($edition -match 'Enterprise|Education|IoT') { 'Enterprise' } else { 'HomePro' }
        if ($WinEos[$track].ContainsKey($ver)) {
            $st = Get-EosStatus $WinEos[$track][$ver]
            if ($st) {
                Write-Host ("  Windows 11 $ver ($edition): " + $st.Text) -ForegroundColor Yellow
                Add-Finding $st.Level "Windows 11 $ver ($edition) is $($st.Text)." 'Settings > Windows Update > install the latest Windows 11 feature update.'
            } else {
                Write-Host "  Still receiving security updates (until $($WinEos[$track][$ver]))." -ForegroundColor Green
            }
        } else {
            Write-Host "  No support date on file for $ver; check Microsoft's Windows 11 lifecycle page." -ForegroundColor DarkGray
        }
    } elseif ([int]$cv.CurrentBuild -lt 22000) {
        Add-Finding 'Unsupported' 'This PC runs Windows 10, which reached end of support on 2025-10-14 (unless enrolled in Extended Security Updates).' 'Upgrade to Windows 11, or enroll in Extended Security Updates.'
    }
} catch {
    Write-Host "  Could not read Windows version: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Installed apps inventory
# ---------------------------------------------------------------------------
$keys = @(
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             Scope = 'All users' }
    @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = 'All users (32-bit)' }
    @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             Scope = 'Current user' }
)

function Get-Prop($Obj, [string]$Name) {
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value } else { return $null }
}

$apps = New-Object System.Collections.Generic.List[object]
$seen = @{}
foreach ($k in $keys) {
    $entries = @(Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue)
    foreach ($e in $entries) {
        $dn = Get-Prop $e 'DisplayName'
        if (-not $dn) { continue }
        $isSystem = (Get-Prop $e 'SystemComponent') -eq 1 -or (Get-Prop $e 'ParentKeyName') -or ((Get-Prop $e 'ReleaseType') -match 'Update|Hotfix')
        if ($isSystem -and -not $IncludeSystem) { continue }
        $dv = [string](Get-Prop $e 'DisplayVersion')
        $id = "$dn|$dv"
        if ($seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $apps.Add([pscustomobject]@{
            Name        = $dn.Trim()
            Version     = $dv
            Publisher   = [string](Get-Prop $e 'Publisher')
            Installed   = ConvertFrom-InstallDate ([string](Get-Prop $e 'InstallDate'))
            Scope       = $k.Scope
            Location    = [string](Get-Prop $e 'InstallLocation')
            Flag        = ''
            Note        = ''
            Available   = ''
        })
    }
}

if ($IncludeStore) {
    try {
        Get-AppxPackage -ErrorAction Stop | Where-Object { -not $_.IsFramework -and $_.SignatureKind -eq 'Store' } | ForEach-Object {
            $apps.Add([pscustomobject]@{
                Name = $_.Name; Version = [string]$_.Version; Publisher = ($_.Publisher -replace '^CN=([^,]+).*', '$1')
                Installed = $null; Scope = 'Store (current user)'; Location = ''; Flag = ''; Note = ''; Available = ''
            })
        }
    } catch {
        Write-Host "  Could not list Store apps: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

Write-Section 'Installed apps'
$byScope = $apps | Group-Object Scope | Sort-Object Name
foreach ($g in $byScope) { Write-Host ("  {0,-22} {1,4}" -f $g.Name, $g.Count) }
Write-Host ("  {0,-22} {1,4}" -f 'Total', $apps.Count)

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
function Set-Flag($App, [string]$Level, [string]$Note) {
    # Keep the most serious flag on each app.
    $rank = @{ '' = 0; 'Stale' = 1; 'Update' = 2; 'EndingSoon' = 3; 'KnownFix' = 4; 'Unsupported' = 5 }
    if ($rank[$Level] -gt $rank[$App.Flag]) { $App.Flag = $Level; $App.Note = $Note }
}

foreach ($a in $apps) {
    if ($a.Scope -like 'Store*') { continue }
    $v = ConvertTo-Version $a.Version
    $nameVer = ConvertTo-Version $a.Name

    foreach ($r in $NameRules) {
        if ($a.Name -match $r.Match) {
            $st = Get-EosStatus $r.Date
            if ($st) { Set-Flag $a $st.Level ($r.Note + " ($($st.Text))") }
        }
    }

    # .NET runtimes, SDKs and hosting bundles (Core / 5+). .NET Framework 4.8 is part of Windows and not checked.
    if ($a.Name -match '^Microsoft (\.NET|ASP\.NET)' -and $a.Name -notmatch 'Framework') {
        $nv = if ($nameVer) { $nameVer } else { $v }
        if ($nv -and $DotNetEos.ContainsKey($nv.Major)) {
            $st = Get-EosStatus $DotNetEos[$nv.Major]
            if ($st) { Set-Flag $a $st.Level ".NET $($nv.Major) is $($st.Text). Uninstall it if no app needs it, or install a supported .NET version." }
        }
    }

    # Python 3.x from python.org
    if ($a.Name -match '^Python 3\.(\d+)') {
        $minor = [int]$Matches[1]
        if ($minor -lt 5) { Set-Flag $a 'Unsupported' 'This Python 3 release is long out of support.' }
        elseif ($PythonEos.ContainsKey($minor)) {
            $st = Get-EosStatus $PythonEos[$minor]
            if ($st) { Set-Flag $a $st.Level "Python 3.$minor is $($st.Text). Install a current Python and remove this one if nothing needs it." }
        }
    }

    # Node.js
    if ($a.Name -match '^Node\.js' -and $v) {
        if ($NodeEos.ContainsKey($v.Major)) {
            $st = Get-EosStatus $NodeEos[$v.Major]
            if ($st) { Set-Flag $a $st.Level "Node.js $($v.Major) is $($st.Text). Install the current LTS from nodejs.org or winget." }
        } elseif ($v.Major -lt 12) { Set-Flag $a 'Unsupported' 'This Node.js release is long out of support.' }
    }

    foreach ($r in $MinSafe) {
        if ($a.Name -match $r.Match) {
            $cand = if ($v) { $v } else { $nameVer }
            if ($cand -and $cand -lt [version]$r.Min) { Set-Flag $a 'KnownFix' $r.Note }
        }
    }

    if ($a.Installed -and $a.Installed -lt $today.AddYears(-$StaleYears)) {
        $yrs = [Math]::Round(($today - $a.Installed).TotalDays / 365.25, 1)
        Set-Flag $a 'Stale' "Installed or last updated $yrs years ago."
    }
}

# ---------------------------------------------------------------------------
# Optional: winget upgrade check (network)
# ---------------------------------------------------------------------------
$upgrades = @()
if ($CheckUpdates) {
    Write-Section 'Available upgrades (winget)'
    try {
        if (Get-Command Get-WinGetPackage -ErrorAction SilentlyContinue) {
            $upgrades = @(Get-WinGetPackage -ErrorAction Stop | Where-Object { $_.IsUpdateAvailable } | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; Id = $_.Id; Version = [string]$_.InstalledVersion; Available = [string]($_.AvailableVersions | Select-Object -First 1) }
            })
        } elseif (Get-Command winget.exe -ErrorAction SilentlyContinue) {
            # Text output; columns are found from the header line. Non-interactive so it never waits for input.
            $raw = & winget.exe upgrade --include-unknown --disable-interactivity 2>$null
            $lines = @($raw | ForEach-Object { ($_ -split "`r")[-1] })
            $h = -1
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^Name\s+Id\s+Version\s+Available') { $h = $i; break }
            }
            if ($h -ge 0) {
                $hdr = $lines[$h]
                $cId = $hdr.IndexOf('Id'); $cVer = $hdr.IndexOf('Version'); $cAv = $hdr.IndexOf('Available')
                $cSrc = $hdr.IndexOf('Source'); if ($cSrc -lt 0) { $cSrc = [int]::MaxValue }
                $list = New-Object System.Collections.Generic.List[object]
                for ($i = $h + 2; $i -lt $lines.Count; $i++) {
                    $l = $lines[$i]
                    if (-not $l.Trim() -or $l -match '^\d+ (upgrades?|package)' -or $l.Length -le $cAv) { break }
                    $end = [Math]::Min($cSrc, $l.Length)
                    $list.Add([pscustomobject]@{
                        Name      = $l.Substring(0, $cId).Trim()
                        Id        = $l.Substring($cId, $cVer - $cId).Trim()
                        Version   = $l.Substring($cVer, $cAv - $cVer).Trim()
                        Available = $l.Substring($cAv, $end - $cAv).Trim()
                    })
                }
                $upgrades = @($list)
            } elseif (($raw | Out-String) -match 'No installed package|No applicable upgrade') {
                $upgrades = @()
            } else {
                Write-Host '  Could not read winget output. If winget asks you to accept source agreements, run "winget upgrade" once by hand.' -ForegroundColor DarkGray
            }
        } else {
            Write-Host '  winget is not installed. Get "App Installer" from the Microsoft Store to enable this check.' -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  winget check failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }

    if ($upgrades.Count -gt 0) {
        $upgrades | Sort-Object Name | Format-Table Name, Id, Version, Available -AutoSize | Out-String -Width 200 | Write-Host
        foreach ($u in $upgrades) {
            $match = $apps | Where-Object { $_.Name -eq $u.Name -or $_.Name -like "$($u.Name)*" } | Select-Object -First 1
            if ($match) { $match.Available = $u.Available; Set-Flag $match 'Update' "Newer version $($u.Available) available (winget upgrade --id $($u.Id))." }
        }
        Add-Finding 'Update' "$($upgrades.Count) app(s) have newer versions available." 'Update them in each app, or run: winget upgrade --all  (review the list first).'
    } else {
        Write-Host '  No upgrades reported.' -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# Report flagged apps
# ---------------------------------------------------------------------------
$order = @{ 'Unsupported' = 0; 'KnownFix' = 1; 'EndingSoon' = 2; 'Update' = 3; 'Stale' = 4 }
$serious = @($apps | Where-Object { $_.Flag -in 'Unsupported', 'KnownFix', 'EndingSoon' } | Sort-Object { $order[$_.Flag] }, Name)
$stale   = @($apps | Where-Object { $_.Flag -eq 'Stale' } | Sort-Object Installed)

Write-Section 'Out of support or missing security fixes'
if ($serious.Count -eq 0) {
    Write-Host '  None found.' -ForegroundColor Green
} else {
    foreach ($a in $serious) {
        $color = if ($a.Flag -eq 'EndingSoon') { 'Yellow' } else { 'Red' }
        Write-Host ("  [{0}] {1} {2}" -f $a.Flag, $a.Name, $a.Version) -ForegroundColor $color
        Write-Host ("      {0}" -f $a.Note)
        $lvl = if ($a.Flag -eq 'EndingSoon') { 'EndingSoon' } else { 'Unsupported' }
        Add-Finding $lvl "$($a.Name) $($a.Version)" $a.Note
    }
}

Write-Section "Not updated in $StaleYears+ years"
if ($stale.Count -eq 0) {
    Write-Host '  None.' -ForegroundColor Green
} else {
    $stale | Select-Object -First 25 | Format-Table Name, Version, @{ n = 'Installed'; e = { $_.Installed.ToString('yyyy-MM-dd') } }, Publisher -AutoSize | Out-String -Width 200 | Write-Host
    if ($stale.Count -gt 25) { Write-Host "  ...and $($stale.Count - 25) more (use -List or -CsvPath)." -ForegroundColor DarkGray }
    Add-Finding 'Stale' "$($stale.Count) app(s) haven't been installed or updated in $StaleYears+ years." 'Uninstall the ones you no longer use (Settings > Apps > Installed apps), and update the rest.'
}

# Duplicate runtimes (several versions of the same family side by side)
Write-Section 'Several versions side by side'
$families = $apps | Where-Object { $_.Scope -notlike 'Store*' -and $_.Name -match '^(Python|Java|Node\.js|Microsoft \.NET|Microsoft ASP\.NET|Microsoft Windows Desktop Runtime)' } |
    Group-Object { ($_.Name -replace '\s*\(.*?\)', '' -replace '[\d\.]+', '' -replace '\s+', ' ').Trim() } |
    Where-Object { @($_.Group.Version | Select-Object -Unique).Count -gt 1 }
if (-not $families) {
    Write-Host '  None.' -ForegroundColor Green
} else {
    foreach ($f in $families) {
        Write-Host ("  {0}: {1}" -f $f.Name, (($f.Group | Sort-Object Version | ForEach-Object { $_.Version }) -join ', '))
    }
    Write-Host '  Side-by-side runtimes are often needed by different apps; remove only the unsupported ones above.' -ForegroundColor DarkGray
}

if ($List) {
    Write-Section 'Full inventory'
    $apps | Sort-Object Name | Format-Table Name, Version, @{ n = 'Installed'; e = { if ($_.Installed) { $_.Installed.ToString('yyyy-MM-dd') } } }, Scope, Flag -AutoSize | Out-String -Width 220 | Write-Host
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  Nothing to fix. Your installed software looks current.' -ForegroundColor Green
} else {
    $fo = @{ 'Unsupported' = 0; 'EndingSoon' = 1; 'Update' = 2; 'Stale' = 3 }
    $n = 0
    foreach ($f in ($findings | Sort-Object { $fo[$_.Level] })) {
        $n++
        $color = switch ($f.Level) { 'Unsupported' { 'Red' } 'EndingSoon' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  {0}. {1}" -f $n, $f.What) -ForegroundColor $color
        Write-Host ("     Fix: {0}" -f $f.Fix)
    }
}
if (-not $CheckUpdates) {
    Write-Host ''
    Write-Host '  Tip: add -CheckUpdates to see which apps winget can upgrade (contacts winget sources).' -ForegroundColor DarkGray
}

if ($CsvPath) {
    try {
        $apps | Sort-Object Name | Select-Object Name, Version, Publisher,
            @{ n = 'Installed'; e = { if ($_.Installed) { $_.Installed.ToString('yyyy-MM-dd') } } }, Scope, Flag, Note, Available, Location |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host "Inventory saved to $CsvPath" -ForegroundColor Green
    } catch {
        Write-Host "Could not write CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}
