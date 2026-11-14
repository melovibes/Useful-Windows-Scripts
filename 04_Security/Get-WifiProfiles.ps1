<#
.SYNOPSIS
    Get-WifiProfiles.ps1 - Audit the Wi-Fi networks this PC remembers and flag
    the risky ones. Read-only by default; removes profiles only when you ask.

.DESCRIPTION
    Windows quietly remembers every Wi-Fi network you have ever joined: hotel,
    airport and coffee-shop hotspots, old routers, a friend's guest network.
    Many of them are set to connect automatically, so a stranger can set up a
    hotspot with the same name and your laptop joins it on its own.

    This script lists every saved Wi-Fi profile with:
      Security      Open, WEP, WPA, WPA2 or WPA3, Personal or Enterprise, and
                    the cipher (AES, TKIP, none)
      Auto          Whether Windows joins it automatically when in range
      Hidden        Whether it's a hidden network (the PC keeps calling out for
                    it by name everywhere it goes)
      Category      Public or Private network (Private allows file sharing and
                    device discovery)
      Last used     When the PC last connected (from the Network List)
      Flags         What's wrong with it, if anything

    Then it prints plain-English findings, worst first:
      High    Open (no password) or WEP networks that auto-connect
      Medium  WPA / TKIP networks, open networks marked Private, hidden
              networks, random hardware addresses turned off on an open network
      Low     Networks not used in a long time (default 365 days)

    Wi-Fi passwords are NEVER read or shown. The profiles are exported to a
    temporary folder without key=clear (any key stays encrypted), parsed, and
    the folder is deleted straight away.

    -Remove 'Name' and -RemoveStale delete saved profiles with
    "netsh wlan delete profile" after you type YES. You'll need the password
    again to rejoin a removed network.

    Safety level : SAFE by default (read-only). -Remove / -RemoveStale delete
                   Wi-Fi profiles only after confirmation (unless -Force).
                   No network calls. Extra files written: optional -CsvPath,
                   plus a temp export folder that is removed when done.

    Admin        : Not required to read. Removing a profile saved for all users
                   may need an elevated prompt.

.PARAMETER StaleDays
    A profile not connected for at least this many days is flagged as stale.
    Default: 365. Set 0 to turn the stale check off.

.PARAMETER Remove
    One or more profile names to delete (exact names from the report).

.PARAMETER RemoveStale
    Delete every profile flagged as stale (never the network you're on now).

.PARAMETER Force
    Skip the YES prompt for -Remove / -RemoveStale.

.PARAMETER CsvPath
    Export the profile table to this CSV file. It contains network names, so
    keep it private.

.EXAMPLE
    .\Get-WifiProfiles.ps1
    Lists saved Wi-Fi networks and findings. Changes nothing.

.EXAMPLE
    .\Get-WifiProfiles.ps1 -StaleDays 180 -CsvPath "$env:USERPROFILE\Desktop\wifi.csv"

.EXAMPLE
    .\Get-WifiProfiles.ps1 -RemoveStale
    Deletes profiles not used in a year, after you type YES.

.NOTES
    Works on Windows 10 and 11, Windows PowerShell 5.1 or PowerShell 7.
    A PC with no Wi-Fi adapter (or with the WLAN AutoConfig service stopped)
    has nothing to report.
#>
[CmdletBinding()]
param(
    [int]$StaleDays = 365,
    [string[]]$Remove,
    [switch]$RemoveStale,
    [switch]$Force,
    [string]$CsvPath
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Get-NodeText($Node, [string]$LocalName) {
    # Namespace-agnostic lookup (profiles mix v1, v2 and v3 namespaces).
    if ($null -eq $Node) { return $null }
    $n = $Node.SelectSingleNode(".//*[local-name()='$LocalName']")
    if ($n) { return $n.InnerText.Trim() }
    return $null
}

function Convert-SystemTime([byte[]]$Bytes) {
    # NetworkList stores dates as a 16-byte SYSTEMTIME in local time.
    if (-not $Bytes -or $Bytes.Length -lt 16) { return $null }
    $v = for ($i = 0; $i -lt 8; $i++) { [BitConverter]::ToUInt16($Bytes, $i * 2) }
    try { return New-Object DateTime ([int]$v[0]), ([int]$v[1]), ([int]$v[3]), ([int]$v[4]), ([int]$v[5]), ([int]$v[6]) }
    catch { return $null }
}

function Get-SecurityLabel([string]$Auth, [string]$Enc, [bool]$OneX) {
    $kind = switch -Regex ($Auth) {
        '^open$'        { if ($Enc -eq 'WEP') { 'WEP' } else { 'Open' }; break }
        '^shared$'      { 'WEP (shared key)'; break }
        '^OWE$'         { 'Enhanced Open (OWE)'; break }
        '^WPAPSK$'      { 'WPA-Personal'; break }
        '^WPA$'         { 'WPA-Enterprise'; break }
        '^WPA2PSK$'     { 'WPA2-Personal'; break }
        '^WPA2$'        { 'WPA2-Enterprise'; break }
        '^WPA3SAE$'     { 'WPA3-Personal'; break }
        '^WPA3(ENT.*)?$' { 'WPA3-Enterprise'; break }
        default         { if ($Auth) { $Auth } else { 'Unknown' } }
    }
    if ($OneX -and $kind -notmatch 'Enterprise') { $kind += ' (802.1X)' }
    if ($Enc -and $Enc -ne 'none' -and $kind -notmatch 'WEP') { $kind += " ($Enc)" }
    return $kind
}

# --- Is there Wi-Fi at all? ---------------------------------------------------
$svc = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host 'No WLAN AutoConfig service on this PC (no Wi-Fi support). Nothing to check.' -ForegroundColor Yellow
    return
}
if ($svc.Status -ne 'Running') {
    Write-Host "The WLAN AutoConfig service is $($svc.Status). Start it (or turn Wi-Fi on) and run again." -ForegroundColor Yellow
    return
}

# --- Export profiles (keys stay encrypted) and parse them ---------------------
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("wifiaudit-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$profiles = New-Object System.Collections.Generic.List[object]
try {
    $null = & netsh.exe wlan export profile "folder=$tmp" 2>&1
    foreach ($f in Get-ChildItem -LiteralPath $tmp -Filter *.xml -File) {
        try {
            [xml]$x = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
        } catch { continue }
        $root = $x.DocumentElement
        $name = Get-NodeText $root 'name'
        $ssidNode = $root.SelectSingleNode(".//*[local-name()='SSIDConfig']")
        $ssid = Get-NodeText $ssidNode 'name'
        if (-not $ssid) { $ssid = $name }
        $hidden = (Get-NodeText $ssidNode 'nonBroadcast') -eq 'true'
        $mode = Get-NodeText $root 'connectionMode'
        $type = Get-NodeText $root 'connectionType'
        $auth = Get-NodeText $root 'authentication'
        $enc  = Get-NodeText $root 'encryption'
        $onex = (Get-NodeText $root 'useOneX') -eq 'true'
        $rand = Get-NodeText $root 'enableRandomization'   # only present if set per network
        $profiles.Add([pscustomobject]@{
            Name           = $name
            SSID           = $ssid
            Auth           = $auth
            Encryption     = $enc
            OneX           = $onex
            Security       = Get-SecurityLabel $auth $enc $onex
            AutoConnect    = ($mode -eq 'auto')
            Hidden         = $hidden
            AdHoc          = ($type -eq 'IBSS')
            RandomMacOff   = ($rand -eq 'false')
            Category       = ''
            LastConnected  = $null
            Created        = $null
            Current        = $false
            Flags          = ''
            Severity       = 0
        })
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($profiles.Count -eq 0) {
    Write-Host 'No saved Wi-Fi profiles found.' -ForegroundColor Green
    return
}

# --- Join with the Network List (category, first/last connected) -------------
$nlRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
$nl = @()
if (Test-Path $nlRoot) {
    $nl = foreach ($k in Get-ChildItem $nlRoot -ErrorAction SilentlyContinue) {
        try { $p = Get-ItemProperty $k.PSPath -ErrorAction Stop } catch { continue }
        if (($p.PSObject.Properties.Name -contains 'NameType') -and $p.NameType -ne 71) { continue } # 71 = wireless
        $last = $null; $made = $null
        if ($p.PSObject.Properties.Name -contains 'DateLastConnected') { $last = Convert-SystemTime $p.DateLastConnected }
        if ($p.PSObject.Properties.Name -contains 'DateCreated')       { $made = Convert-SystemTime $p.DateCreated }
        $cat = if ($p.PSObject.Properties.Name -contains 'Category') { $p.Category } else { $null }
        [pscustomobject]@{
            ProfileName = [string]$p.ProfileName
            Description = if ($p.PSObject.Properties.Name -contains 'Description') { [string]$p.Description } else { '' }
            Category    = $cat
            Last        = $last
            Created     = $made
        }
    }
}

$current = @()
try { $current = @(Get-NetConnectionProfile -ErrorAction Stop) } catch { }

$now = Get-Date
foreach ($p in $profiles) {
    # Windows may append " 2", " 3" to the Network List name; match those too.
    $pat = '^' + [regex]::Escape($p.SSID) + '( \d+)?$'
    $hits = @($nl | Where-Object { $_.ProfileName -match $pat -or $_.Description -eq $p.SSID -or $_.ProfileName -eq $p.Name })
    if ($hits.Count) {
        $best = $hits | Sort-Object { if ($_.Last) { $_.Last } else { [datetime]::MinValue } } -Descending | Select-Object -First 1
        $p.LastConnected = $best.Last
        $p.Created = ($hits | Where-Object Created | Sort-Object Created | Select-Object -First 1 -ExpandProperty Created)
        $p.Category = switch ($best.Category) { 0 { 'Public' } 1 { 'Private' } 2 { 'Domain' } default { '' } }
    }
    $cur = $current | Where-Object { $_.Name -match $pat -or $_.Name -eq $p.Name } | Select-Object -First 1
    if ($cur) {
        $p.Current = $true
        $p.Category = [string]$cur.NetworkCategory
        $p.LastConnected = $now
    }

    $flags = New-Object System.Collections.Generic.List[string]
    $sev = 0
    $isOpen = $p.Auth -eq 'open' -and ($p.Encryption -eq 'none' -or -not $p.Encryption)
    $isWep  = $p.Encryption -eq 'WEP' -or $p.Auth -eq 'shared'
    if ($isWep) { $flags.Add('WEP is broken'); $sev = [math]::Max($sev, 2) }
    if (($isOpen -or $isWep) -and $p.AutoConnect) { $flags.Add('auto-joins with no real password'); $sev = 3 }
    elseif ($isOpen) { $flags.Add('open network'); $sev = [math]::Max($sev, 1) }
    if ($p.Auth -in 'WPA', 'WPAPSK' -or $p.Encryption -eq 'TKIP') { $flags.Add('old WPA/TKIP'); $sev = [math]::Max($sev, 2) }
    if ($isOpen -and $p.Category -eq 'Private') { $flags.Add('open network set to Private'); $sev = [math]::Max($sev, 2) }
    if ($p.Hidden) { $flags.Add('hidden: PC broadcasts its name'); $sev = [math]::Max($sev, 2) }
    if ($p.AdHoc) { $flags.Add('ad-hoc network'); $sev = [math]::Max($sev, 2) }
    if ($isOpen -and $p.RandomMacOff) { $flags.Add('random hardware address off'); $sev = [math]::Max($sev, 1) }
    if ($StaleDays -gt 0 -and -not $p.Current -and $p.LastConnected -and ($now - $p.LastConnected).TotalDays -ge $StaleDays) {
        $flags.Add("unused $([int]($now - $p.LastConnected).TotalDays) days"); $sev = [math]::Max($sev, 1)
    }
    $p.Flags = $flags -join '; '
    $p.Severity = $sev
}

# --- Report -------------------------------------------------------------------
$sevName = @{ 0 = ''; 1 = 'Low'; 2 = 'Medium'; 3 = 'High' }
Write-Section "Saved Wi-Fi networks ($($profiles.Count))"
$profiles |
    Sort-Object @{ e = 'Current'; d = $true }, @{ e = 'Severity'; d = $true }, @{ e = { if ($_.LastConnected) { $_.LastConnected } else { [datetime]::MinValue } }; d = $true } |
    Select-Object @{ n = 'Network'; e = { if ($_.Current) { "$($_.Name) *" } else { $_.Name } } },
                  Security,
                  @{ n = 'Auto'; e = { if ($_.AutoConnect) { 'Yes' } else { 'No' } } },
                  @{ n = 'Hidden'; e = { if ($_.Hidden) { 'Yes' } else { '' } } },
                  Category,
                  @{ n = 'Last used'; e = { if ($_.Current) { 'now' } elseif ($_.LastConnected) { $_.LastConnected.ToString('yyyy-MM-dd') } else { '?' } } },
                  @{ n = 'Risk'; e = { $sevName[$_.Severity] } },
                  Flags |
    Format-Table -AutoSize -Wrap | Out-Host
Write-Host '  * = connected now. "?" = Windows has no last-connected date for it.' -ForegroundColor DarkGray

$byKind = $profiles | Group-Object { ($_.Security -replace ' \(.*$', '') } | Sort-Object Count -Descending
Write-Section 'By security type'
$byKind | ForEach-Object { '  {0,-24} {1}' -f $_.Name, $_.Count } | Out-Host

# --- Findings -----------------------------------------------------------------
Write-Section 'Findings'
$findings = New-Object System.Collections.Generic.List[string]
$autoOpen = @($profiles | Where-Object { $_.Severity -eq 3 })
if ($autoOpen.Count) {
    $findings.Add("HIGH: $($autoOpen.Count) open or WEP network(s) join automatically. Anyone can create a hotspot with the same name and your PC will connect to it. Remove them, or in Settings > Network & internet > Wi-Fi > Manage known networks, turn off 'Connect automatically when in range'.")
}
$weak = @($profiles | Where-Object { $_.Flags -match 'WEP is broken|WPA/TKIP' })
if ($weak.Count) {
    $findings.Add("MEDIUM: $($weak.Count) network(s) use WEP or WPA/TKIP, which can be cracked. If one is your own router, switch it to WPA2-AES or WPA3 in the router settings.")
}
$priv = @($profiles | Where-Object { $_.Flags -match 'set to Private' })
if ($priv.Count) {
    $findings.Add("MEDIUM: $($priv.Count) open network(s) are marked Private, so file sharing and device discovery are on there. Set them to Public in the network's properties.")
}
$hid = @($profiles | Where-Object Hidden)
if ($hid.Count) {
    $findings.Add("MEDIUM: $($hid.Count) hidden network(s). To find a hidden network the PC calls out for it by name wherever you go, which makes you easier to track. Unhide the network on the router if it's yours.")
}
$stale = @($profiles | Where-Object { $_.Flags -match 'unused' })
if ($stale.Count) {
    $findings.Add("LOW: $($stale.Count) network(s) not used in $StaleDays+ days. Old profiles are an easy way to get lured onto a fake hotspot. Run with -RemoveStale to clean them up.")
}
$noDate = @($profiles | Where-Object { -not $_.LastConnected -and -not $_.Current })
if ($noDate.Count) {
    $findings.Add("INFO: $($noDate.Count) profile(s) have no last-connected date (often added by policy, a setup tool or another PC). Remove any you don't recognise.")
}
if ($profiles.Count -ge 25) {
    $findings.Add("INFO: $($profiles.Count) saved networks is a lot. Consider pruning the ones you won't use again.")
}
if ($findings.Count -eq 0) {
    Write-Host '  Nothing risky found.' -ForegroundColor Green
} else {
    $i = 1
    foreach ($f in $findings) {
        $color = if ($f -like 'HIGH*') { 'Red' } elseif ($f -like 'MEDIUM*') { 'Yellow' } else { 'Gray' }
        Write-Host ("  {0}. {1}" -f $i++, $f) -ForegroundColor $color
    }
}

if ($CsvPath) {
    $profiles | Select-Object Name, SSID, Security, Auth, Encryption, AutoConnect, Hidden, AdHoc, Category, LastConnected, Created, Current, @{ n = 'Risk'; e = { $sevName[$_.Severity] } }, Flags |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "CSV written: $CsvPath (contains network names; keep it private)" -ForegroundColor DarkGray
}

# --- Optional removal ---------------------------------------------------------
$toRemove = New-Object System.Collections.Generic.List[object]
if ($Remove) {
    foreach ($r in $Remove) {
        $m = $profiles | Where-Object { $_.Name -eq $r } | Select-Object -First 1
        if ($m) { $toRemove.Add($m) } else { Write-Host "  No saved profile named '$r'." -ForegroundColor Yellow }
    }
}
if ($RemoveStale) {
    foreach ($s in $stale) { if (-not ($toRemove | Where-Object Name -eq $s.Name)) { $toRemove.Add($s) } }
}
$toRemove = @($toRemove | Where-Object { -not $_.Current })
if (($Remove -or $RemoveStale) -and $toRemove.Count -eq 0) {
    Write-Host ''
    Write-Host 'Nothing to remove (the network you are on now is never removed).' -ForegroundColor Yellow
}
if ($toRemove.Count) {
    Write-Section "Remove $($toRemove.Count) Wi-Fi profile(s)"
    $toRemove | ForEach-Object { "  - $($_.Name)  [$($_.Security)]" } | Out-Host
    Write-Host '  You will need the password again to rejoin any of these.' -ForegroundColor DarkGray
    if (-not $Force) {
        $ans = Read-Host 'Type YES to remove them'
        if ($ans -cne 'YES') { Write-Host 'Cancelled. Nothing removed.' -ForegroundColor Yellow; return }
    }
    $ok = 0
    foreach ($t in $toRemove) {
        $out = & netsh.exe wlan delete profile "name=$($t.Name)" 2>&1
        if ($LASTEXITCODE -eq 0) { $ok++; Write-Host "  Removed: $($t.Name)" -ForegroundColor Green }
        else { Write-Host "  Could not remove $($t.Name): $(($out | Out-String).Trim()) (an all-users profile may need an admin prompt)" -ForegroundColor Red }
    }
    Write-Host "Removed $ok of $($toRemove.Count)."
}
