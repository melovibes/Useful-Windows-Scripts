<#
.SYNOPSIS
    Get-BrowserExtensions.ps1 - List every browser extension on this PC and flag
    the risky ones (can read every site, not from a store, policy-forced,
    developer-mode, outdated Manifest V2, allowed in Incognito). Read-only.
    Uses the permissions the browser has actually granted, not just the manifest.

.DESCRIPTION
    Browser extensions see what you see. A "free PDF converter" that can read
    and change data on every site can also read your bank and email tabs. This
    script reads extension data straight from your browser profiles on disk, so
    it works even when the browser is closed, and it never opens the browser.

    Browsers checked (every profile of each, for your account):
      Google Chrome, Microsoft Edge, Brave, Vivaldi, Chromium, Opera, Opera GX
      and Mozilla Firefox.

    Site access and permissions come from what the browser has actually granted
    (for example "On click" or specific sites), not only from what the
    extension's manifest asks for. Optional permissions the user has not
    granted are ignored. When granted-permission data is missing (older
    settings), the script falls back to the manifest.

    Reports:
      Summary      Extensions per browser and profile, and how many were flagged
      Extensions   Name, version, browser/profile, on/off, where it came from,
                   installed and last-updated dates, Incognito/InPrivate if
                   allowed, and a risk level (High / Medium / Low)
      Forced       Extensions force-installed through browser policy in the
                   registry (normal on work PCs, a red flag on a home PC)
      Findings     Numbered, plain-English list of what to review first,
                   including High/Medium extensions allowed in Incognito and
                   the same extension in more than one browser or profile

    Risk levels are a guide, not a verdict:
      High    Can read/change every site AND has a powerful permission (cookies,
              web request interception, scripting, debugger, native apps, proxy
              or managing other extensions); or it was loaded unpacked
              (developer mode) or from outside any store.
      Medium  Can read/change every site, or has a powerful permission.
      Low     Narrow permissions.
    Allowed-in-Incognito is a separate flag; it does not raise the risk level.

    Built-in component extensions that ship with the browser are hidden unless
    you pass -IncludeBuiltIn.

    Safety level : READ-ONLY. Reads profile files and the registry only. Changes
                   nothing, makes no network calls, never launches a browser.
                   Writes a file only if you pass -CsvPath.
    Admin        : Not required. Only your own account's profiles are read.

.PARAMETER Browser
    Only check these browsers. Any of: Chrome, Edge, Brave, Vivaldi, Chromium,
    Opera, OperaGX, Firefox. Default: all that are installed.

.PARAMETER IncludeBuiltIn
    Also list component extensions bundled with the browser.

.PARAMETER IncludeDisabled
    Also list disabled extensions in the table (they're counted either way).

.PARAMETER StaleDays
    Flag enabled extensions whose files haven't changed in this many days
    (often abandoned, and abandoned extensions get sold). Default: 730.

.PARAMETER List
    Show every extension, not just Medium and High risk ones.

.PARAMETER ShowPermissions
    Print each listed extension's permissions and site access under it,
    including when access is on click or limited to specific sites.

.PARAMETER CsvPath
    Export every extension (with permissions, flags, and install date) to this
    CSV file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\04_Security\Get-BrowserExtensions.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\04_Security\Get-BrowserExtensions.ps1 -Browser Chrome,Edge -List -ShowPermissions

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\04_Security\Get-BrowserExtensions.ps1 -CsvPath "$env:USERPROFILE\Desktop\extensions.csv"

.NOTES
    Works in Windows PowerShell 5.1 and PowerShell 7. To remove an extension,
    open the browser's extensions page (chrome://extensions, edge://extensions,
    brave://extensions, about:addons) and click Remove there. To stop an
    extension running in private windows, turn off "Allow in Incognito" or
    "Run in Private Windows" on that same page.
#>

[CmdletBinding()]
param(
    [ValidateSet('Chrome', 'Edge', 'Brave', 'Vivaldi', 'Chromium', 'Opera', 'OperaGX', 'Firefox')]
    [string[]]$Browser,
    [switch]$IncludeBuiltIn,
    [switch]$IncludeDisabled,
    [ValidateRange(0, 36500)]
    [int]$StaleDays = 730,
    [switch]$List,
    [switch]$ShowPermissions,
    [string]$CsvPath
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Tables (easy to review and extend)
# ---------------------------------------------------------------------------
$ChromiumBrowsers = @(
    @{ Name = 'Chrome';   Root = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data';                 Multi = $true;  Policy = 'Google\Chrome' }
    @{ Name = 'Edge';     Root = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data';                Multi = $true;  Policy = 'Microsoft\Edge' }
    @{ Name = 'Brave';    Root = Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data';   Multi = $true;  Policy = 'BraveSoftware\Brave' }
    @{ Name = 'Vivaldi';  Root = Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data';                       Multi = $true;  Policy = $null }
    @{ Name = 'Chromium'; Root = Join-Path $env:LOCALAPPDATA 'Chromium\User Data';                      Multi = $true;  Policy = 'Chromium' }
    @{ Name = 'Opera';    Root = Join-Path $env:APPDATA      'Opera Software\Opera Stable';             Multi = $false; Policy = $null }
    @{ Name = 'OperaGX';  Root = Join-Path $env:APPDATA      'Opera Software\Opera GX Stable';          Multi = $false; Policy = $null }
)

# Permissions that give an extension real power over your browsing.
$PowerfulPerms = @(
    'cookies', 'webRequest', 'webRequestBlocking', 'scripting', 'debugger',
    'nativeMessaging', 'proxy', 'management', 'history', 'tabs', 'webNavigation',
    'clipboardRead', 'downloads', 'privacy', 'desktopCapture', 'tabCapture',
    'declarativeNetRequestWithHostAccess', 'contentSettings', 'browsingData'
)
# The worst of those: combined with all-site access, or alone, they mean High.
$CriticalPerms = @('debugger', 'nativeMessaging', 'proxy', 'management')
$AllSitesPatterns = @('<all_urls>', '*://*/*', 'http://*/*', 'https://*/*', '*://*/', 'http://*/', 'https://*/', 'file:///*')

# Chromium "location" values from the browser's extension settings.
$ChromiumLocation = @{
    1 = 'Store/user'; 2 = 'External (app installer)'; 3 = 'External (registry)'
    4 = 'Unpacked (developer mode)'; 5 = 'Built-in'; 6 = 'External (app installer)'
    7 = 'Policy'; 8 = 'Command line'; 9 = 'Policy'; 10 = 'Built-in'
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ("== {0} ==" -f $Title) -ForegroundColor Cyan
}

function Get-Prop($Obj, [string]$Name) {
    # Works on PSCustomObject (ConvertFrom-Json) and dictionaries (JavaScriptSerializer).
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Name)) { return $Obj[$Name] }
        return $null
    }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-Keys($Obj) {
    if ($null -eq $Obj) { return @() }
    if ($Obj -is [System.Collections.IDictionary]) { return @($Obj.Keys) }
    return @($Obj.PSObject.Properties | ForEach-Object { $_.Name })
}

$script:JsonSerializer = $null
function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $text = [System.IO.File]::ReadAllText($Path)
    } catch { return $null }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    # Strip a UTF-8 BOM some manifests carry.
    $text = $text.TrimStart([char]0xFEFF)
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        # PowerShell 7: hashtables cope with the empty and duplicate-case keys
        # that browser preference files sometimes have.
        try { return (ConvertFrom-Json -InputObject $text -AsHashtable -ErrorAction Stop) } catch { return $null }
    }
    try {
        return ($text | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        # Windows PowerShell 5.1 chokes on empty keys and duplicate-case keys,
        # which browser preference files sometimes have. Fall back to .NET.
        try {
            if (-not $script:JsonSerializer) {
                Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
                $script:JsonSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                $script:JsonSerializer.MaxJsonLength = [int]::MaxValue
            }
            return $script:JsonSerializer.DeserializeObject($text)
        } catch { return $null }
    }
}

function Resolve-MsgName([string]$Value, [string]$ExtDir, [string]$DefaultLocale) {
    # Turns "__MSG_appName__" into the real name from _locales\<locale>\messages.json.
    if ($Value -notmatch '^__MSG_(.+)__$') { return $Value }
    $key = $Matches[1]
    $locales = @()
    if ($DefaultLocale) { $locales += $DefaultLocale }
    $locales += 'en', 'en_US', 'en_GB'
    foreach ($loc in ($locales | Select-Object -Unique)) {
        $msgs = Read-JsonFile (Join-Path $ExtDir "_locales\$loc\messages.json")
        if (-not $msgs) { continue }
        foreach ($k in (Get-Keys $msgs)) {
            if ($k -ieq $key) {
                $m = Get-Prop (Get-Prop $msgs $k) 'message'
                if ($m) { return [string]$m }
            }
        }
    }
    return $Value
}

function Get-StringList($Obj, [string]$Name) {
    $out = @()
    foreach ($x in @(Get-Prop $Obj $Name)) {
        if ($x -is [string] -and $x.Length) { $out += $x }
    }
    return $out
}

function Test-AllSites([string[]]$Patterns) {
    foreach ($p in $Patterns) {
        if ($AllSitesPatterns -contains $p) { return $true }
        if ($p -match '^(\*|https?)://\*/') { return $true }
    }
    return $false
}

function Get-GrantSet($Grant) {
    # $null if the grant object is missing; otherwise the API perms and hosts
    # actually listed on it (empty lists are still a real, present object).
    if ($null -eq $Grant) { return $null }
    $perms = @()
    $hosts = @()
    foreach ($k in 'api', 'permissions', 'manifest_permissions') {
        foreach ($x in (Get-StringList $Grant $k)) {
            if ($x -match '://|^<all_urls>$') { $hosts += $x }
            else { $perms += $x }
        }
    }
    foreach ($k in 'explicit_host', 'explicit_hosts', 'scriptable_host', 'scriptable_hosts') {
        $hosts += Get-StringList $Grant $k
    }
    return @{
        Perms = @($perms | Select-Object -Unique)
        Hosts = @($hosts | Select-Object -Unique)
    }
}

function Get-ManifestAccess($Manifest) {
    # Requested (not optional) permissions and hosts from the manifest only.
    $perms = @()
    $hosts = @()
    foreach ($x in (Get-StringList $Manifest 'permissions')) {
        if ($x -match '://|^<all_urls>$') { $hosts += $x }
        else { $perms += $x }
    }
    # optional_permissions and optional_host_permissions are not granted.
    $hosts += Get-StringList $Manifest 'host_permissions'
    foreach ($cs in @(Get-Prop $Manifest 'content_scripts')) {
        $hosts += Get-StringList $cs 'matches'
    }
    return @{
        Perms = @($perms | Select-Object -Unique)
        Hosts = @($hosts | Select-Object -Unique)
    }
}

function Test-Withholding($Settings) {
    $w = Get-Prop $Settings 'withholding_permissions'
    if ($null -eq $w) { return $false }
    if ($w -is [bool]) { return [bool]$w }
    if ($w -is [int] -or $w -is [long] -or $w -is [int64] -or $w -is [double] -or $w -is [decimal]) {
        return [int]$w -ne 0
    }
    if ($w -is [string]) {
        if ($w -eq 'true' -or $w -eq 'True' -or $w -eq '1') { return $true }
        return $false
    }
    if ($w -is [System.Collections.IDictionary]) { return $w.Count -gt 0 }
    $keys = @(Get-Keys $w)
    return ($keys.Count -gt 0)
}

function Get-ChromiumAccess($Settings, $Manifest) {
    # Prefer active_permissions, then granted_permissions. Fall back to the
    # manifest only when neither is present (older settings or leftover entries).
    $manifestAcc = Get-ManifestAccess $Manifest
    $active = Get-GrantSet (Get-Prop $Settings 'active_permissions')
    $granted = Get-GrantSet (Get-Prop $Settings 'granted_permissions')
    $usedGrant = $false
    $perms = $manifestAcc.Perms
    $hosts = $manifestAcc.Hosts
    if ($null -ne $active) {
        $perms = $active.Perms
        $hosts = $active.Hosts
        $usedGrant = $true
    } elseif ($null -ne $granted) {
        $perms = $granted.Perms
        $hosts = $granted.Hosts
        $usedGrant = $true
    }

    $withholding = Test-Withholding $Settings
    $allSites = $false
    $siteAccess = 'none'
    if ($usedGrant) {
        $hostsAreAll = Test-AllSites $hosts
        # Withheld, or all-sites in the manifest but not in granted/active hosts:
        # do not treat as "reads every site".
        if ($withholding) {
            if (@($hosts).Count -gt 0 -and -not $hostsAreAll) { $siteAccess = 'specific sites' }
            else { $siteAccess = 'on click' }
        } elseif ($hostsAreAll) {
            $allSites = $true
            $siteAccess = 'all sites'
        } elseif (@($hosts).Count -gt 0) {
            $siteAccess = 'specific sites'
        } elseif ((Test-AllSites $manifestAcc.Hosts) -or @($manifestAcc.Hosts).Count -gt 0) {
            $siteAccess = 'on click'
        } else {
            $siteAccess = 'none'
        }
    } else {
        if (Test-AllSites $hosts) { $allSites = $true; $siteAccess = 'all sites' }
        elseif (@($hosts).Count -gt 0) { $siteAccess = 'specific sites' }
        else { $siteAccess = 'none' }
    }
    return @{
        Perms = $perms
        Hosts = $hosts
        AllSites = $allSites
        SiteAccess = $siteAccess
    }
}

function Get-FirefoxAccess($Addon) {
    # userPermissions are what the user has granted. Do not use
    # optionalPermissions for risk or site access.
    $up = Get-Prop $Addon 'userPermissions'
    $perms = @()
    $hosts = @()
    $usedGrant = $false
    if ($null -ne $up) {
        $usedGrant = $true
        $perms = @(Get-StringList $up 'permissions')
        $hosts = @(Get-StringList $up 'origins')
    }
    $allSites = Test-AllSites $hosts
    $siteAccess = 'none'
    if ($allSites) { $siteAccess = 'all sites' }
    elseif (@($hosts).Count -gt 0) { $siteAccess = 'specific sites' }
    elseif ($usedGrant) {
        $opt = Get-Prop $Addon 'optionalPermissions'
        $optHosts = @()
        if ($null -ne $opt) { $optHosts = @(Get-StringList $opt 'origins') }
        if ((Test-AllSites $optHosts) -or @($optHosts).Count -gt 0) { $siteAccess = 'on click' }
    }
    return @{
        Perms = $perms
        Hosts = $hosts
        AllSites = $allSites
        SiteAccess = $siteAccess
    }
}

function Get-Risk([string[]]$Perms, [bool]$AllSites, [string]$Source, [string]$SiteAccess) {
    $powerful = @($Perms | Where-Object { $PowerfulPerms -contains $_ })
    $critical = @($Perms | Where-Object { $CriticalPerms -contains $_ })
    $why = @()
    if ($AllSites) { $why += 'reads/changes every site' }
    elseif ($SiteAccess -eq 'specific sites') { $why += 'site access is limited to specific sites' }
    elseif ($SiteAccess -eq 'on click') { $why += 'site access is on click, not every site' }
    if ($powerful.Count) { $why += ($powerful -join ', ') }
    $level = 'Low'
    if ($AllSites -or $powerful.Count) { $level = 'Medium' }
    if ($critical.Count -or ($AllSites -and @($powerful | Where-Object { $_ -in 'cookies', 'webRequest', 'webRequestBlocking', 'scripting', 'declarativeNetRequestWithHostAccess' }).Count)) { $level = 'High' }
    if ($Source -match 'Unpacked|Command line|Not from a store|Sideloaded') { $level = 'High'; $why += $Source.ToLower() }
    [pscustomobject]@{ Level = $level; Why = ($why -join '; ') }
}

function Test-IncognitoAllowed($Value) {
    # Chromium settings: boolean, or spanning / split / not_allowed.
    # Firefox addons: not_allowed, spanning, or split.
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int64] -or $Value -is [double] -or $Value -is [decimal]) {
        return [int]$Value -ne 0
    }
    $s = [string]$Value
    if ($s -eq 'True' -or $s -eq 'true' -or $s -eq '1') { return $true }
    if ($s -eq 'spanning' -or $s -eq 'split') { return $true }
    return $false
}

function ConvertFrom-ChromeFileTime($Value) {
    # Windows FILETIME: 100-ns ticks since 1601-01-01, often a decimal string.
    # Skip missing or unparsable values rather than guessing.
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) { return $null }
    try {
        $ticks = $null
        if ($Value -is [int64] -or $Value -is [int] -or $Value -is [long] -or $Value -is [decimal]) {
            $ticks = [int64]$Value
        } elseif ($Value -is [double] -or $Value -is [float]) {
            return $null
        } else {
            $s = [string]$Value
            if ($s -notmatch '^\d+$') { return $null }
            $ticks = [int64]$s
        }
        if ($null -eq $ticks -or $ticks -le 0) { return $null }
        $dt = [DateTime]::FromFileTime($ticks)
        if ($dt.Year -lt 1990 -or $dt -gt (Get-Date).AddYears(1)) { return $null }
        return $dt
    } catch {
        return $null
    }
}

function ConvertFrom-UnixMs($Value) {
    if ($null -eq $Value -or $Value -eq '') { return $null }
    try {
        $ms = [int64]$Value
        if ($ms -le 0) { return $null }
        $dt = [DateTimeOffset]::FromUnixTimeMilliseconds($ms).LocalDateTime
        if ($dt.Year -lt 1990 -or $dt -gt (Get-Date).AddYears(1)) { return $null }
        return $dt
    } catch {
        return $null
    }
}

$exts = New-Object System.Collections.Generic.List[object]
$profilesSeen = New-Object System.Collections.Generic.List[object]

function Add-Extension($Data) { $exts.Add([pscustomobject]$Data) }

# ---------------------------------------------------------------------------
# Chromium-based browsers
# ---------------------------------------------------------------------------
function Get-ChromiumProfiles($B) {
    if (-not (Test-Path -LiteralPath $B.Root)) { return @() }
    if (-not $B.Multi) { return @([pscustomobject]@{ Dir = $B.Root; Name = 'Default' }) }
    Get-ChildItem -LiteralPath $B.Root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' } |
        ForEach-Object {
            # Use the folder name, not the display name: display names are often a person's name.
            [pscustomobject]@{ Dir = $_.FullName; Name = $_.Name }
        }
}

foreach ($b in $ChromiumBrowsers) {
    if ($Browser -and ($Browser -notcontains $b.Name)) { continue }
    foreach ($prof in (Get-ChromiumProfiles $b)) {
        $profilesSeen.Add([pscustomobject]@{ Browser = $b.Name; Profile = $prof.Name })
        # Settings live in Secure Preferences on newer builds, Preferences on older ones.
        $settings = @{}
        foreach ($f in 'Preferences', 'Secure Preferences') {
            $j = Read-JsonFile (Join-Path $prof.Dir $f)
            $s = Get-Prop (Get-Prop $j 'extensions') 'settings'
            foreach ($id in (Get-Keys $s)) { $settings[$id] = Get-Prop $s $id }
        }
        $extRoot = Join-Path $prof.Dir 'Extensions'
        $ids = @()
        if (Test-Path -LiteralPath $extRoot) {
            $ids += Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
        }
        $ids += $settings.Keys
        foreach ($id in ($ids | Where-Object { $_ -match '^[a-p]{32}$' } | Select-Object -Unique)) {
            $st = $settings[$id]
            $manifestDir = $null
            $p = Get-Prop $st 'path'
            if ($p) {
                if ([System.IO.Path]::IsPathRooted([string]$p)) { $manifestDir = [string]$p }
                else { $manifestDir = Join-Path $extRoot ([string]$p) }
            }
            if (-not $manifestDir -or -not (Test-Path -LiteralPath (Join-Path $manifestDir 'manifest.json'))) {
                $verDir = Get-ChildItem -LiteralPath (Join-Path $extRoot $id) -Directory -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($verDir) { $manifestDir = $verDir.FullName }
            }
            $manifest = $null
            if ($manifestDir) { $manifest = Read-JsonFile (Join-Path $manifestDir 'manifest.json') }
            if (-not $manifest) { $manifest = Get-Prop $st 'manifest' }
            if (-not $manifest) { continue }   # leftover entry with nothing on disk

            $locNum = 0
            $locRaw = Get-Prop $st 'location'
            if ($null -ne $locRaw) { $locNum = [int]$locRaw }
            $isBuiltIn = $locNum -in 5, 10
            if ($isBuiltIn -and -not $IncludeBuiltIn) { continue }
            $type = [string](Get-Prop $manifest 'type')
            if ((Get-Prop $manifest 'theme') -or $type -eq 'theme') { continue }   # themes have no code

            $source = $ChromiumLocation[$locNum]
            if (-not $source) { $source = 'Unknown' }
            $fromStore = Get-Prop $st 'from_webstore'
            if ($locNum -eq 1 -and $fromStore -eq $false) {
                # Edge add-ons come from a different store and are often marked false here.
                $upd = [string](Get-Prop $manifest 'update_url')
                if ($upd -match 'microsoft\.com|google\.com|opera\.com') { $source = 'Store' }
                else { $source = 'Not from a store' }
            } elseif ($locNum -eq 1) { $source = 'Store' }

            $enabled = $true
            $state = Get-Prop $st 'state'
            $reasons = Get-Prop $st 'disable_reasons'
            if ($null -ne $state -and [int]$state -eq 0) { $enabled = $false }
            if ($null -ne $reasons) {
                if ($reasons -is [System.Collections.IEnumerable] -and -not ($reasons -is [string])) { if (@($reasons).Count) { $enabled = $false } }
                elseif ([int]$reasons -ne 0) { $enabled = $false }
            }

            $mv = Get-Prop $manifest 'manifest_version'
            $access = Get-ChromiumAccess $st $manifest
            $perms = @($access.Perms)
            $hosts = @($access.Hosts)
            $allSites = [bool]$access.AllSites
            $siteAccess = [string]$access.SiteAccess

            $updated = $null
            if ($manifestDir -and (Test-Path -LiteralPath $manifestDir)) {
                $updated = (Get-Item -LiteralPath $manifestDir).LastWriteTime
                $mf = Get-Item -LiteralPath (Join-Path $manifestDir 'manifest.json') -ErrorAction SilentlyContinue
                if ($mf -and $mf.LastWriteTime -gt $updated) { $updated = $mf.LastWriteTime }
            }
            $installed = ConvertFrom-ChromeFileTime (Get-Prop $st 'first_install_time')
            if (-not $installed) { $installed = ConvertFrom-ChromeFileTime (Get-Prop $st 'install_time') }
            $incognito = Test-IncognitoAllowed (Get-Prop $st 'incognito')
            $name = Resolve-MsgName ([string](Get-Prop $manifest 'name')) $manifestDir ([string](Get-Prop $manifest 'default_locale'))
            if ($isBuiltIn) { $source = 'Built-in' }
            $risk = Get-Risk $perms $allSites $source $siteAccess

            Add-Extension @{
                Browser = $b.Name; Profile = $prof.Name; Name = $name; Id = $id
                Version = [string](Get-Prop $manifest 'version'); Enabled = $enabled
                Source = $source; Manifest = $mv; Installed = $installed; Updated = $updated
                Incognito = $incognito; AllSites = $allSites; SiteAccess = $siteAccess
                Permissions = ($perms | Select-Object -Unique) -join ' '
                Sites = (($hosts | Select-Object -First 15) -join ' '); Risk = $risk.Level; Why = $risk.Why
                Path = $manifestDir
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Firefox
# ---------------------------------------------------------------------------
if (-not $Browser -or $Browser -contains 'Firefox') {
    $ffRoot = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
    if (Test-Path -LiteralPath $ffRoot) {
        foreach ($pd in (Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue)) {
            $j = Read-JsonFile (Join-Path $pd.FullName 'extensions.json')
            if (-not $j) { continue }
            # Folder names look like "abcd1234.default-release"; keep only the part after the dot.
            $pname = ($pd.Name -replace '^[^.]+\.', '')
            $profilesSeen.Add([pscustomobject]@{ Browser = 'Firefox'; Profile = $pname })
            foreach ($a in @(Get-Prop $j 'addons')) {
                if ([string](Get-Prop $a 'type') -ne 'extension') { continue }
                $loc = [string](Get-Prop $a 'location')
                $isBuiltIn = $loc -in 'app-builtin', 'app-system-defaults', 'app-system-addons', 'app-system-share', 'app-system-local', 'app-system-user'
                if ($isBuiltIn -and -not $IncludeBuiltIn) { continue }
                $dl = Get-Prop $a 'defaultLocale'
                $name = [string](Get-Prop $dl 'name')
                if (-not $name) { $name = [string](Get-Prop $a 'id') }
                $access = Get-FirefoxAccess $a
                $perms = @($access.Perms)
                $hosts = @($access.Hosts)
                $allSites = [bool]$access.AllSites
                $siteAccess = [string]$access.SiteAccess
                $signed = Get-Prop $a 'signedState'
                $srcUri = [string](Get-Prop $a 'sourceURI')
                $source = 'Store'
                if ($isBuiltIn) { $source = 'Built-in' }
                elseif ($loc -eq 'app-profile' -and $null -ne $signed -and [int]$signed -le 0) { $source = 'Sideloaded (unsigned)' }
                elseif ($loc -eq 'app-temporary') { $source = 'Unpacked (developer mode)' }
                elseif ($loc -ne 'app-profile') { $source = "External ($loc)" }
                elseif ($srcUri -and $srcUri -notmatch 'addons\.mozilla\.org|mozilla\.net') { $source = 'Not from a store' }
                $updated = ConvertFrom-UnixMs (Get-Prop $a 'updateDate')
                $installed = ConvertFrom-UnixMs (Get-Prop $a 'installDate')
                $incognito = Test-IncognitoAllowed (Get-Prop $a 'incognito')
                $enabled = [bool](Get-Prop $a 'active')
                $risk = Get-Risk $perms $allSites $source $siteAccess
                Add-Extension @{
                    Browser = 'Firefox'; Profile = $pname; Name = $name; Id = [string](Get-Prop $a 'id')
                    Version = [string](Get-Prop $a 'version'); Enabled = $enabled
                    Source = $source; Manifest = $null; Installed = $installed; Updated = $updated
                    Incognito = $incognito; AllSites = $allSites; SiteAccess = $siteAccess
                    Permissions = ($perms -join ' ')
                    Sites = (($hosts | Select-Object -First 15) -join ' '); Risk = $risk.Level; Why = $risk.Why
                    Path = [string](Get-Prop $a 'path')
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Policy force-installed extensions (registry)
# ---------------------------------------------------------------------------
$forced = New-Object System.Collections.Generic.List[object]
foreach ($b in $ChromiumBrowsers) {
    if (-not $b.Policy) { continue }
    if ($Browser -and ($Browser -notcontains $b.Name)) { continue }
    foreach ($hive in 'HKLM', 'HKCU') {
        $key = "${hive}:\Software\Policies\$($b.Policy)\ExtensionInstallForcelist"
        if (-not (Test-Path $key)) { continue }
        $item = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -notmatch '^\d+$') { continue }
            $val = [string]$p.Value
            $fid = ($val -split ';')[0]
            $fupd = ''
            if ($val -like '*;*') { $fupd = $val.Substring($val.IndexOf(';') + 1) }
            $match = $exts | Where-Object { $_.Browser -eq $b.Name -and $_.Id -eq $fid } | Select-Object -First 1
            $fname = '(not installed yet)'
            if ($match) { $fname = $match.Name }
            $forced.Add([pscustomobject]@{ Browser = $b.Name; Scope = $hive; Id = $fid; Name = $fname; UpdateUrl = $fupd })
        }
    }
}
$ffPol = 'HKLM:\Software\Policies\Mozilla\Firefox\Extensions\Install'
if ((-not $Browser -or $Browser -contains 'Firefox') -and (Test-Path $ffPol)) {
    $item = Get-ItemProperty -Path $ffPol -ErrorAction SilentlyContinue
    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -notmatch '^\d+$') { continue }
        $forced.Add([pscustomobject]@{ Browser = 'Firefox'; Scope = 'HKLM'; Id = ''; Name = '(policy install)'; UpdateUrl = [string]$p.Value })
    }
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
Write-Host 'Browser extension audit (read-only)' -ForegroundColor White
Write-Host ("Checked {0:yyyy-MM-dd HH:mm}" -f (Get-Date)) -ForegroundColor DarkGray

Write-Section 'Summary'
if ($profilesSeen.Count -eq 0) {
    Write-Host '  No supported browser profiles found for this account.' -ForegroundColor Yellow
} else {
    $profilesSeen | Sort-Object Browser, Profile -Unique | ForEach-Object {
        $pb = $_.Browser; $pp = $_.Profile
        $mine = @($exts | Where-Object { $_.Browser -eq $pb -and $_.Profile -eq $pp })
        $on = @($mine | Where-Object { $_.Enabled }).Count
        $hi = @($mine | Where-Object { $_.Risk -eq 'High' -and $_.Enabled }).Count
        $color = 'Gray'
        if ($hi) { $color = 'Yellow' }
        Write-Host ("  {0,-9} {1,-18} {2,3} extensions ({3} on, {4} high risk)" -f $pb, $pp, $mine.Count, $on, $hi) -ForegroundColor $color
    }
}

Write-Section 'Extensions'
$rank = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
$show = $exts | Where-Object { ($_.Enabled -or $IncludeDisabled) -and ($List -or $_.Risk -ne 'Low') } |
    Sort-Object @{ e = { $rank[$_.Risk] } }, Browser, Name
if (-not $show) {
    if ($List) { Write-Host '  None found.' }
    else { Write-Host '  No enabled Medium or High risk extensions. Use -List to see everything.' -ForegroundColor Green }
} else {
    foreach ($e in $show) {
        $color = switch ($e.Risk) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
        $state = 'on'
        if (-not $e.Enabled) { $state = 'off' }
        $upd = '?'
        if ($e.Updated) { $upd = $e.Updated.ToString('yyyy-MM-dd') }
        $mvTxt = ''
        if ($e.Manifest) { $mvTxt = " MV$($e.Manifest)" }
        $meta = "{0} / {1}, {2}{3}, {4}" -f $e.Browser, $e.Profile, $state, $mvTxt, $e.Source
        if ($e.Installed) { $meta += (", installed {0}" -f $e.Installed.ToString('yyyy-MM-dd')) }
        $meta += ", updated $upd"
        if ($e.Incognito) { $meta += ', incognito' }
        Write-Host ("  [{0,-6}] {1} {2}  ({3})" -f $e.Risk, $e.Name, $e.Version, $meta) -ForegroundColor $color
        if ($e.Why) { Write-Host ("           Why: {0}" -f $e.Why) -ForegroundColor DarkGray }
        if ($ShowPermissions) {
            if ($e.Permissions) { Write-Host ("           Permissions: {0}" -f $e.Permissions) -ForegroundColor DarkGray }
            $accessTxt = $e.SiteAccess
            if ($e.SiteAccess -eq 'on click') { $accessTxt = 'on click (not every site)' }
            elseif ($e.SiteAccess -eq 'specific sites') { $accessTxt = 'specific sites (not every site)' }
            elseif ($e.SiteAccess -eq 'all sites') { $accessTxt = 'every site' }
            elseif ($e.SiteAccess -eq 'none') { $accessTxt = 'none' }
            Write-Host ("           Site access: {0}" -f $accessTxt) -ForegroundColor DarkGray
            if ($e.Sites) { Write-Host ("           Sites: {0}" -f $e.Sites) -ForegroundColor DarkGray }
            Write-Host ("           Id: {0}" -f $e.Id) -ForegroundColor DarkGray
        }
    }
}

if ($forced.Count) {
    Write-Section 'Forced by policy'
    foreach ($f in $forced) {
        Write-Host ("  {0,-8} {1}  {2} {3}" -f $f.Browser, $f.Scope, $f.Id, $f.Name) -ForegroundColor Yellow
        if ($f.UpdateUrl) { Write-Host ("           From: {0}" -f $f.UpdateUrl) -ForegroundColor DarkGray }
    }
}

# Findings
$findings = New-Object System.Collections.Generic.List[object]
$on = @($exts | Where-Object { $_.Enabled })
foreach ($e in ($on | Where-Object { $_.Source -match 'Unpacked|Command line' })) {
    $findings.Add([pscustomobject]@{ Order = 0; What = "$($e.Name) in $($e.Browser) was loaded unpacked (developer mode). Malware uses this to skip store review."; Fix = 'If you did not load it yourself while writing an extension, remove it and turn off Developer mode on the extensions page.' })
}
foreach ($e in ($on | Where-Object { $_.Source -match 'Not from a store|Sideloaded' })) {
    $findings.Add([pscustomobject]@{ Order = 0; What = "$($e.Name) in $($e.Browser) didn't come from a browser store."; Fix = 'Remove it unless you know exactly which program installed it and why.' })
}
foreach ($f in $forced) {
    $findings.Add([pscustomobject]@{ Order = 1; What = "$($f.Browser) has an extension force-installed by policy ($($f.Scope)): $($f.Id) $($f.Name)."; Fix = 'Normal on a work PC managed by IT. On a home PC, adware sets this so you cannot remove the extension; delete the ExtensionInstallForcelist entry under Software\Policies (admin needed for HKLM) and run a Defender full scan.' })
}
foreach ($e in ($on | Where-Object { $_.Risk -eq 'High' -and $_.Source -notmatch 'Unpacked|Command line|Not from a store|Sideloaded' })) {
    $findings.Add([pscustomobject]@{ Order = 2; What = "$($e.Name) in $($e.Browser) has high access: $($e.Why)."; Fix = 'Keep it only if you use it and trust the developer. Otherwise remove it, or set its site access to "On click" or specific sites.' })
}
$incogOn = @($on | Where-Object { $_.Incognito -and $_.Risk -in @('High', 'Medium') })
foreach ($g in ($incogOn | Group-Object Browser, Name, Id)) {
    $sample = $g.Group[0]
    $places = @($g.Group | ForEach-Object { $_.Profile } | Select-Object -Unique) -join ', '
    $findings.Add([pscustomobject]@{ Order = 3; What = "$($sample.Name) in $($sample.Browser) is allowed to run in Incognito or InPrivate windows ($places)."; Fix = 'Turn off "Allow in Incognito" (Chrome, Edge, Brave, Opera) or "Run in Private Windows" (Firefox) on the extensions page unless this extension really needs it.' })
}
$mv2 = @($on | Where-Object { $_.Manifest -eq 2 })
if ($mv2.Count) {
    $findings.Add([pscustomobject]@{ Order = 4; What = "$($mv2.Count) extension(s) still use Manifest V2, which Chrome and Edge are phasing out: $((($mv2 | ForEach-Object { $_.Name }) | Select-Object -Unique) -join ', ')."; Fix = 'They may stop working or stop getting fixes. Look for an updated version or a replacement.' })
}
if ($StaleDays -gt 0) {
    $cut = (Get-Date).AddDays(-$StaleDays)
    $stale = @($on | Where-Object { $_.Updated -and $_.Updated -lt $cut -and $_.Source -ne 'Built-in' })
    if ($stale.Count) {
        $findings.Add([pscustomobject]@{ Order = 5; What = "$($stale.Count) enabled extension(s) haven't changed in over $StaleDays days: $((($stale | ForEach-Object { $_.Name }) | Select-Object -Unique) -join ', ')."; Fix = 'Abandoned extensions are often sold and turned into adware. Remove the ones you no longer use.' })
    }
}
$reviewable = @($exts | Where-Object { $_.Source -ne 'Built-in' })
foreach ($g in ($reviewable | Group-Object Id | Where-Object { @($_.Group | ForEach-Object { "$($_.Browser)/$($_.Profile)" } | Select-Object -Unique).Count -gt 1 })) {
    $sample = $g.Group[0]
    $places = @($g.Group | ForEach-Object { "$($_.Browser)/$($_.Profile)" } | Select-Object -Unique) -join ', '
    $hot = @($g.Group | Where-Object { $_.Risk -eq 'High' -or $_.Source -match 'Not from a store|Sideloaded|Unpacked|Command line' })
    $what = "$($sample.Name) ($($sample.Id)) is installed in more than one place: $places."
    if ($hot.Count) {
        $what = "$($sample.Name) ($($sample.Id)) is a high-risk or non-store extension installed in more than one place: $places."
    }
    $findings.Add([pscustomobject]@{ Order = 6; What = $what; Fix = 'If you do not want it, remove it from each browser and profile listed.' })
}
foreach ($g in ($reviewable | Group-Object Name | Where-Object {
    $ids = @($_.Group | Select-Object -ExpandProperty Id -Unique)
    $browsers = @($_.Group | Select-Object -ExpandProperty Browser -Unique)
    $ids.Count -gt 1 -and $browsers.Count -gt 1
})) {
    $browsers = @($g.Group | Select-Object -ExpandProperty Browser -Unique) -join ', '
    $findings.Add([pscustomobject]@{ Order = 6; What = "$($g.Name) appears in more than one browser under different IDs ($browsers)."; Fix = 'Chrome, Edge and Firefox often give the same add-on different IDs. Remove it from each browser if you no longer want it.' })
}
$off = @($exts | Where-Object { -not $_.Enabled })
if ($off.Count) {
    $findings.Add([pscustomobject]@{ Order = 7; What = "$($off.Count) extension(s) are installed but turned off."; Fix = 'Remove the ones you do not need; a browser can turn them back on after an update.' })
}

Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  Nothing to review. Your extensions look tidy.' -ForegroundColor Green
} else {
    $n = 0
    foreach ($f in ($findings | Sort-Object Order)) {
        $n++
        $color = 'Gray'
        if ($f.Order -le 1) { $color = 'Red' } elseif ($f.Order -le 3) { $color = 'Yellow' }
        Write-Host ("  {0}. {1}" -f $n, $f.What) -ForegroundColor $color
        Write-Host ("     Fix: {0}" -f $f.Fix)
    }
}
Write-Host ''
Write-Host '  Changes nothing. Remove extensions from each browser''s extensions page.' -ForegroundColor DarkGray

if ($CsvPath) {
    try {
        $exts | Sort-Object Browser, Profile, Name | Select-Object Browser, Profile, Name, Version, Id, Enabled, Source, Manifest,
            @{ n = 'Installed'; e = { if ($_.Installed) { $_.Installed.ToString('yyyy-MM-dd') } } },
            @{ n = 'Updated'; e = { if ($_.Updated) { $_.Updated.ToString('yyyy-MM-dd') } } },
            Risk, Why, AllSites, SiteAccess, Incognito, Permissions, Sites, Path |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host "Saved to $CsvPath" -ForegroundColor Green
    } catch {
        Write-Host "Could not write CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}
