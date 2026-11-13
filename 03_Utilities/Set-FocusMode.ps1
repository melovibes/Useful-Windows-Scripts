<#
.SYNOPSIS
    Set-FocusMode.ps1 - Toggle a social-media block in the Windows hosts file
    so you can focus. Run it once to block, run it again to unblock.

.DESCRIPTION
    A simple on/off "focus" switch. With no switches it toggles a clearly
    marked block in C:\Windows\System32\drivers\etc\hosts:
        # >>> Set-FocusMode START
        ...
        # <<< Set-FocusMode END
    If the block is missing, it is added. If it is already there, it is
    removed. Only that marked block is ever changed; your other hosts
    entries (including a Block-Distractions.ps1 block, or anything from
    PowerToys Hosts File Editor) are left untouched. Reruns replace the
    block instead of duplicating it.

    Default sites (always included; edit the arrays at the top of the
    script to change them):
      Facebook, Instagram, Threads, X/Twitter, TikTok, Snapchat, Reddit,
      Pinterest, Tumblr, Twitch.
    Optional (off unless you pass the switch):
      -IncludeYouTube, -IncludeLinkedIn, -IncludeDiscord.
    Each name is written as both 0.0.0.0 (IPv4) and :: (IPv6), and the
    script also adds www., m. and mobile. variants plus key app and CDN
    hostnames so the block actually works. Hosts entries are exact-match
    only, so a few CDN subdomains with random names may still resolve;
    see NOTES.

    Safety level : MEDIUM. It edits a system file, but only inside its
                   own marked block. Unlike Block-Distractions.ps1, a run
                   with no switches DOES change the file (it toggles).
                   Use -Status to look without changing anything.
                   Before the first change, a copy is saved next to hosts
                   as hosts.focus-backup and is not overwritten later.
                   No network calls.

    Admin        : Changing the system hosts file needs an elevated
                   PowerShell (Run as administrator). -Status does not.
                   If you are not elevated, the script explains how and
                   can offer to relaunch; pass -Elevate to get the
                   approval prompt immediately.

    IMPORTANT
      * DNS-over-HTTPS (Secure DNS) bypasses the hosts file. This script
        does not change browser settings. If a site still loads, turn it
        off yourself:
          Chrome : Settings > Privacy and security > Security > "Use secure DNS" -> Off
          Edge   : Settings > Privacy, search, and services > Security > "Use secure DNS" -> Off
          Firefox: Settings > Privacy & Security > DNS over HTTPS -> Off
          Windows: Settings > Network & internet > (adapter) > DNS server assignment > DNS over HTTPS Off
      * Already-open tabs and apps may keep using a connection until you
        close them. After a change, the script flushes the DNS cache;
        restart your browsers too.
      * For broader category blocklists (shopping, adult, gambling and
        so on) see Block-Distractions.ps1. The two scripts use different
        markers and can coexist. A site listed in both stays blocked
        until both blocks are removed.

.PARAMETER On
    Turn focus on (add or refresh the block). Alias: -Block.

.PARAMETER Off
    Turn focus off (remove the block). Also removes a leftover timed
    unblock task. Alias: -Unblock.

.PARAMETER Status
    Show whether the focus block is present, how many names it has, and
    which site groups are in it. Changes nothing.

.PARAMETER IncludeYouTube
    Also block YouTube (youtube.com, youtu.be, ytimg.com, googlevideo.com
    and related hosts). Off by default because work and training videos
    often live there. Hosts cannot block only Shorts.

.PARAMETER IncludeLinkedIn
    Also block LinkedIn. Off by default because many people need it for
    work.

.PARAMETER IncludeDiscord
    Also block Discord. Off by default because some teams use it for work.

.PARAMETER Sites
    Extra domains to block, e.g. -Sites 'example.com','news.example.net'.
    http:// prefixes, paths and leading *. are stripped. Protected
    domains (Microsoft, Google Workspace, GitHub, Apple and similar)
    are refused and nothing is written.

.PARAMETER Exclude
    Domains to leave unblocked, even if they are in the default list,
    e.g. -Exclude 'reddit.com'. Matches the name and its subdomains.

.PARAMETER Minutes
    With a turn-on (-On, or a toggle that turns focus on): after writing
    the block, schedule a one-time task named Set-FocusMode-Unblock that
    runs this script with -Off after N minutes (1 to 1440). The task
    runs as SYSTEM so it can edit hosts even if you are not logged in.
    -Off, or a toggle that turns focus off, removes that task. If the
    task cannot be created, the block is still applied and the script
    prints how to unblock by hand. Timed unblock is only scheduled when
    writing the real system hosts file.

.PARAMETER Elevate
    If this run needs to edit the system hosts file and the window is
    not already elevated, relaunch it as administrator (you will get
    the usual approval prompt) instead of just printing instructions.

.EXAMPLE
    .\Set-FocusMode.ps1

.EXAMPLE
    .\Set-FocusMode.ps1 -On -IncludeYouTube

.EXAMPLE
    .\Set-FocusMode.ps1 -Off

.EXAMPLE
    .\Set-FocusMode.ps1 -Status

.EXAMPLE
    .\Set-FocusMode.ps1 -On -Minutes 45

.EXAMPLE
    .\Set-FocusMode.ps1 -On -Sites 'example.com' -Exclude 'reddit.com'

.NOTES
    Usage:
      powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Set-FocusMode.ps1"
      powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Set-FocusMode.ps1" -On -IncludeYouTube
      powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Set-FocusMode.ps1" -Off
      powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Set-FocusMode.ps1" -Status
      powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Set-FocusMode.ps1" -On -Minutes 45
    Undo: run the script again (toggle) or run with -Off. To restore the
    hosts file from before the first Set-FocusMode change, copy
    hosts.focus-backup over hosts (from an elevated prompt).
    -HostsPath points at a copy of a hosts file for testing; admin checks,
    DNS flush and timed-unblock scheduling are skipped.
    Works on Windows 10 and 11, Windows PowerShell 5.1 or PowerShell 7.
#>
[CmdletBinding()]
param(
    [Alias('Block')]
    [switch]$On,

    [Alias('Unblock')]
    [switch]$Off,

    [switch]$Status,

    [switch]$IncludeYouTube,
    [switch]$IncludeLinkedIn,
    [switch]$IncludeDiscord,

    [string[]]$Sites,
    [string[]]$Exclude,

    [ValidateRange(1, 1440)]
    [int]$Minutes,

    [switch]$Elevate,

    [Parameter(DontShow)]
    [string]$HostsPath
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Markers and default domain lists. Edit the arrays below to change what
# is blocked; keep each entry as a bare hostname (no http://, no path).
# www., m. and mobile. variants are added automatically.
# ---------------------------------------------------------------------------
$script:StartMarker = '# >>> Set-FocusMode START'
$script:EndMarker   = '# <<< Set-FocusMode END'
$script:BackupSuffix = '.focus-backup'
$script:UnblockTaskName = 'Set-FocusMode-Unblock'
$script:BlockHeader = '# Managed by Set-FocusMode.ps1. Do not edit this block by hand; rerun the script to update or remove it.'

# Always-on groups. Add or remove hostnames here to taste.
$script:DefaultSiteGroups = [ordered]@{
    'Facebook' = @(
        'facebook.com', 'fb.com', 'fbcdn.net', 'fbsbx.com', 'facebook.net',
        'messenger.com', 'fb.me', 'fb.watch', 'fb.gg',
        'graph.facebook.com', 'edge-chat.facebook.com', 'connect.facebook.net',
        'upload.facebook.com', 'developers.facebook.com', 'business.facebook.com',
        'web.facebook.com', 'l.facebook.com', 'lm.facebook.com',
        'login.facebook.com', 'mbasic.facebook.com', 'touch.facebook.com',
        'apps.facebook.com', 'static.xx.fbcdn.net', 'scontent.xx.fbcdn.net'
    )
    'Instagram' = @(
        'instagram.com', 'cdninstagram.com', 'instagr.am', 'ig.me',
        'api.instagram.com', 'graph.instagram.com', 'i.instagram.com',
        'scontent.cdninstagram.com'
    )
    'Threads' = @(
        'threads.net', 'threads.com'
    )
    'X/Twitter' = @(
        'x.com', 'twitter.com', 't.co', 'twimg.com',
        'api.twitter.com', 'api.x.com', 'abs.twimg.com', 'pbs.twimg.com',
        'video.twimg.com', 'mobile.twitter.com', 'tweetdeck.twitter.com',
        'ads-twitter.com'
    )
    'TikTok' = @(
        'tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'tiktokcdn-us.com',
        'tiktokv.us', 'byteoversea.com', 'ibytedtos.com', 'ttwstatic.com',
        'muscdn.com', 'musical.ly', 'vm.tiktok.com'
    )
    'Snapchat' = @(
        'snapchat.com', 'snap.com', 'snapkit.com', 'sc-cdn.net',
        'app.snapchat.com', 'accounts.snapchat.com', 'cf-st.sc-cdn.net'
    )
    'Reddit' = @(
        'reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com',
        'redditinc.com', 'old.reddit.com', 'new.reddit.com', 'np.reddit.com',
        'i.redd.it', 'v.redd.it', 'preview.redd.it', 'oauth.reddit.com',
        'gql.reddit.com', 'amp.reddit.com', 'sh.reddit.com'
    )
    'Pinterest' = @(
        'pinterest.com', 'pinimg.com', 'pin.it', 'api.pinterest.com',
        'i.pinimg.com', 's.pinimg.com', 'ct.pinterest.com'
    )
    'Tumblr' = @(
        'tumblr.com', 'tmblr.co', 'assets.tumblr.com', 'media.tumblr.com',
        'static.tumblr.com', 'api.tumblr.com', '64.media.tumblr.com',
        '66.media.tumblr.com', '49.media.tumblr.com'
    )
    'Twitch' = @(
        'twitch.tv', 'twitch.com', 'twitchcdn.net', 'ttvnw.net', 'jtvnw.net',
        'twitchsvc.net', 'ext-twitch.tv', 'api.twitch.tv', 'id.twitch.tv',
        'player.twitch.tv', 'clips.twitch.tv', 'gql.twitch.tv',
        'static.twitchcdn.net', 'assets.twitch.tv'
    )
}

# Optional groups, only included when the matching switch is passed.
$script:OptionalSiteGroups = [ordered]@{
    'YouTube' = @{
        Switch  = 'IncludeYouTube'
        Domains = @(
            'youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com',
            'youtube-nocookie.com', 'youtubekids.com', 'youtubeeducation.com',
            'youtubegaming.com', 'music.youtube.com', 'i.ytimg.com',
            'i9.ytimg.com', 's.ytimg.com'
        )
    }
    'LinkedIn' = @{
        Switch  = 'IncludeLinkedIn'
        Domains = @(
            'linkedin.com', 'lnkd.in', 'licdn.com',
            'api.linkedin.com', 'platform.linkedin.com',
            'media.licdn.com', 'static.licdn.com'
        )
    }
    'Discord' = @{
        Switch  = 'IncludeDiscord'
        Domains = @(
            'discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net',
            'discord.media', 'discord.gift', 'discord.co',
            'gateway.discord.gg', 'cdn.discordapp.com', 'media.discordapp.net',
            'images-ext-1.discordapp.net', 'images-ext-2.discordapp.net',
            'status.discord.com', 'ptb.discord.com', 'canary.discord.com'
        )
    }
}

# Never block these (exact name or any subdomain). A built-in or -Sites
# entry that matches stops the script with no changes.
$script:AllowList = @(
    'microsoft.com', 'windowsupdate.com', 'windows.com', 'windows.net',
    'live.com', 'office.com', 'office.net', 'office365.com',
    'microsoftonline.com', 'sharepoint.com', 'outlook.com',
    'msftconnecttest.com', 'azure.com',
    'google.com', 'googleapis.com', 'gstatic.com', 'gmail.com',
    'googleusercontent.com', 'gvt1.com',
    'github.com', 'githubusercontent.com',
    'apple.com', 'icloud.com',
    'dropbox.com', 'dropboxapi.com',
    'zoom.us', 'slack.com',
    'cloudflare.com', 'digicert.com', 'letsencrypt.org'
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $identity
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-IsWindowsOs {
    if ($env:OS -eq 'Windows_NT') { return $true }
    try {
        if ($PSVersionTable.PSVersion.Major -ge 6 -and (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) -and $IsWindows) {
            return $true
        }
    } catch { }
    return $false
}

function Test-IsSystemHosts {
    param([string]$Path)
    if (-not $env:windir) { return $false }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $systemHosts = [IO.Path]::GetFullPath((Join-Path $env:windir 'System32\drivers\etc\hosts'))
    try {
        $full = [IO.Path]::GetFullPath($Path)
    } catch {
        return $false
    }
    return ($full -ieq $systemHosts)
}

function Test-IsProtectedDomain {
    param([string]$Domain)
    foreach ($allowed in $script:AllowList) {
        if ($Domain -eq $allowed -or $Domain.EndsWith(".$allowed")) { return $true }
    }
    return $false
}

function Split-NameList {
    param([string[]]$Values)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($value in @($Values)) {
        if ($null -eq $value) { continue }
        foreach ($piece in ($value -split '[,;\s]+')) {
            if (-not [string]::IsNullOrWhiteSpace($piece)) { $out.Add($piece) }
        }
    }
    return ,$out.ToArray()
}

function Normalize-DomainName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $domain = $Value.Trim().ToLowerInvariant()
    $domain = $domain -replace '^https?://', ''
    $domain = $domain.TrimStart('.')
    if ($domain.StartsWith('*.')) { $domain = $domain.Substring(2) }
    $domain = ($domain -split '/', 2)[0]
    $domain = ($domain -split '\?', 2)[0]
    $domain = ($domain -split '#', 2)[0]
    $domain = $domain.TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($domain)) { return $null }
    if ($domain -match '[^\w\.\-]') { return $null }
    if ($domain -notmatch '^[a-z0-9]') { return $null }
    if ($domain -eq 'localhost') { return $null }
    if ($domain -match '^\d+\.\d+\.\d+\.\d+$') { return $null }
    if ($domain -match ':') { return $null }
    if ($domain -notmatch '\.') { return $null }
    return $domain
}

function Get-ExpandedDomainNames {
    param([string[]]$Domains)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $prefixes = @('www', 'm', 'mobile')
    foreach ($raw in @($Domains)) {
        $domain = Normalize-DomainName $raw
        if (-not $domain) { continue }
        [void]$seen.Add($domain)
        foreach ($prefix in $prefixes) {
            if ($domain.StartsWith("$prefix.")) { continue }
            [void]$seen.Add("$prefix.$domain")
        }
    }
    return @($seen | Sort-Object)
}

function Test-IsExcludedDomain {
    param(
        [string]$Domain,
        [string[]]$Excluded
    )
    foreach ($item in @($Excluded)) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        if ($Domain -eq $item -or $Domain.EndsWith(".$item")) { return $true }
    }
    return $false
}

function Get-FocusDomainGroups {
    param(
        [switch]$WithYouTube,
        [switch]$WithLinkedIn,
        [switch]$WithDiscord,
        [string[]]$ExtraSites,
        [string[]]$ExcludeSites
    )

    # Match -Exclude against the normalized roots the user typed (and their subdomains).
    $excludeRoots = New-Object System.Collections.Generic.List[string]
    foreach ($item in (Split-NameList $ExcludeSites)) {
        $n = Normalize-DomainName $item
        if ($n) { $excludeRoots.Add($n) }
    }
    $excludeRoots = @($excludeRoots)

    $groups = [ordered]@{}
    foreach ($name in $script:DefaultSiteGroups.Keys) {
        $groups[$name] = @($script:DefaultSiteGroups[$name])
    }
    if ($WithYouTube)  { $groups['YouTube']  = @($script:OptionalSiteGroups['YouTube'].Domains) }
    if ($WithLinkedIn) { $groups['LinkedIn'] = @($script:OptionalSiteGroups['LinkedIn'].Domains) }
    if ($WithDiscord)  { $groups['Discord']  = @($script:OptionalSiteGroups['Discord'].Domains) }

    $extras = @(Split-NameList $ExtraSites)
    if ($extras.Count -gt 0) { $groups['Custom'] = $extras }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $result = [ordered]@{}
    $protectedHits = New-Object System.Collections.Generic.List[string]

    foreach ($name in $groups.Keys) {
        $keep = New-Object System.Collections.Generic.List[string]
        foreach ($domain in (Get-ExpandedDomainNames $groups[$name])) {
            if (Test-IsExcludedDomain -Domain $domain -Excluded $excludeRoots) { continue }
            if (Test-IsProtectedDomain $domain) {
                $protectedHits.Add("$domain ($name)")
                continue
            }
            if ($seen.Add($domain)) { $keep.Add($domain) }
        }
        if ($keep.Count -gt 0) { $result[$name] = @($keep) }
    }

    if ($protectedHits.Count -gt 0) {
        $list = $protectedHits -join ', '
        throw "Refusing to block protected domain(s): $list. Critical services (Microsoft, Google, GitHub, Apple, Dropbox, Zoom, Slack and similar) are never blocked. Nothing was changed."
    }

    return $result
}

function Get-FocusDomainCount {
    param([System.Collections.IDictionary]$Groups)
    $n = 0
    foreach ($name in $Groups.Keys) { $n += @($Groups[$name]).Count }
    return $n
}

function New-FocusHostsBlock {
    param([System.Collections.IDictionary]$Groups)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($script:StartMarker)
    $lines.Add($script:BlockHeader)
    foreach ($name in $Groups.Keys) {
        $lines.Add("# --- $name ---")
        foreach ($domain in @($Groups[$name])) {
            $lines.Add("0.0.0.0 $domain")
            $lines.Add(":: $domain")
        }
    }
    $lines.Add($script:EndMarker)
    return ,$lines.ToArray()
}

function Read-HostsFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Hosts file not found: $Path"
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $offset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $offset = 3
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        throw "Hosts file is UTF-16, which Windows does not use for hosts. Convert it to ANSI/ASCII or UTF-8 and try again, or restore hosts.focus-backup."
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        throw "Hosts file is UTF-16, which Windows does not use for hosts. Convert it to ANSI/ASCII or UTF-8 and try again, or restore hosts.focus-backup."
    }
    $text = [Text.Encoding]::UTF8.GetString($bytes, $offset, $bytes.Length - $offset)
    $newline = "`r`n"
    if ($text.Contains("`r`n")) { $newline = "`r`n" }
    elseif ($text.Contains("`n")) { $newline = "`n" }
    elseif ($text.Contains("`r")) { $newline = "`r" }
    $parts = [regex]::Split($text, '\r\n|\n|\r')
    $hadTrailingNewline = $false
    if ($parts.Length -gt 0 -and $parts[$parts.Length - 1] -eq '' -and $text.Length -gt 0) {
        $hadTrailingNewline = $true
        $lines = @($parts[0..($parts.Length - 2)])
    } else {
        $lines = @($parts)
        if ($lines.Count -eq 1 -and $lines[0] -eq '' -and $bytes.Length -eq $offset) {
            $lines = @()
        }
    }
    return @{
        Lines = @($lines)
        Newline = $newline
        HadTrailingNewline = $hadTrailingNewline
        OriginalBytes = $bytes
    }
}

function Split-FocusHostsBlock {
    param([string[]]$Lines)
    $starts = New-Object System.Collections.Generic.List[int]
    $ends = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $trim = $Lines[$i].Trim()
        if ($trim -eq $script:StartMarker) { $starts.Add($i) }
        if ($trim -eq $script:EndMarker)   { $ends.Add($i) }
    }
    if ($starts.Count -gt 1 -or $ends.Count -gt 1) {
        throw "More than one Set-FocusMode block was found in the hosts file. Fix it by hand (or restore hosts.focus-backup) before rerunning."
    }
    if ($starts.Count -ne $ends.Count) {
        throw "Found an unmatched Set-FocusMode start or end marker. Fix the hosts file by hand (or restore hosts.focus-backup) before rerunning."
    }
    if ($starts.Count -eq 0) {
        return @{
            HasBlock = $false
            Prefix   = @($Lines)
            Block    = @()
            Suffix   = @()
            Domains  = @()
        }
    }
    if ($starts[0] -gt $ends[0]) {
        throw "Set-FocusMode end marker appears before the start marker. Fix the hosts file by hand (or restore hosts.focus-backup) before rerunning."
    }

    $prefix = @()
    if ($starts[0] -gt 0) { $prefix = @($Lines[0..($starts[0] - 1)]) }
    $block  = @($Lines[$starts[0]..$ends[0]])
    $suffix = @()
    if ($ends[0] -lt ($Lines.Count - 1)) { $suffix = @($Lines[($ends[0] + 1)..($Lines.Count - 1)]) }

    $domains = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in $block) {
        $t = $line.Trim()
        if ($t -match '^(0\.0\.0\.0|::)\s+([A-Za-z0-9\.\-]+)\s*$') {
            [void]$domains.Add($Matches[2])
        }
    }

    return @{
        HasBlock = $true
        Prefix   = $prefix
        Block    = $block
        Suffix   = $suffix
        Domains  = @($domains | Sort-Object)
    }
}

function Get-SiteGroupsFromDomains {
    param([string[]]$Domains)
    $present = New-Object System.Collections.Generic.List[string]
    $allGroups = [ordered]@{}
    foreach ($name in $script:DefaultSiteGroups.Keys) { $allGroups[$name] = @($script:DefaultSiteGroups[$name]) }
    foreach ($name in $script:OptionalSiteGroups.Keys) { $allGroups[$name] = @($script:OptionalSiteGroups[$name].Domains) }
    foreach ($name in $allGroups.Keys) {
        $hit = $false
        foreach ($d in $allGroups[$name]) {
            $n = Normalize-DomainName $d
            if ($n -and ($Domains -contains $n)) { $hit = $true; break }
        }
        if ($hit) { $present.Add($name) }
    }
    return ,$present.ToArray()
}

function Join-HostsLines {
    param(
        [string[]]$Prefix,
        [string[]]$Block,
        [string[]]$Suffix,
        [string]$Newline
    )
    $prefix = @($Prefix)
    $suffix = @($Suffix)
    while ($prefix.Count -gt 0 -and [string]::IsNullOrWhiteSpace($prefix[$prefix.Count - 1])) {
        if ($prefix.Count -eq 1) { $prefix = @(); break }
        $prefix = @($prefix[0..($prefix.Count - 2)])
    }
    while ($suffix.Count -gt 0 -and [string]::IsNullOrWhiteSpace($suffix[0])) {
        if ($suffix.Count -eq 1) { $suffix = @(); break }
        $suffix = @($suffix[1..($suffix.Count - 1)])
    }

    $all = New-Object System.Collections.Generic.List[string]
    foreach ($l in $prefix) { $all.Add($l) }
    if ($Block -and $Block.Count -gt 0) {
        if ($all.Count -gt 0) { $all.Add('') }
        foreach ($l in $Block) { $all.Add($l) }
    }
    if ($suffix.Count -gt 0) {
        if ($all.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($all[$all.Count - 1])) { $all.Add('') }
        foreach ($l in $suffix) { $all.Add($l) }
    }
    $text = ($all.ToArray() -join $Newline) + $Newline
    return $text
}

function Get-HostsBackupPath {
    param([string]$Path)
    return ($Path + $script:BackupSuffix)
}

function Write-HostsFileText {
    param(
        [string]$Path,
        [string]$Text,
        [string]$Newline
    )

    $useAscii = $true
    foreach ($ch in $Text.ToCharArray()) {
        if ([int]$ch -gt 127) { $useAscii = $false; break }
    }
    if ($useAscii) {
        $encoding = New-Object System.Text.ASCIIEncoding
    } else {
        $encoding = New-Object System.Text.UTF8Encoding $false
        Write-Host "[i] The hosts file has non-ASCII characters, so it was written as UTF-8 without a BOM." -ForegroundColor Cyan
    }
    $bytes = $encoding.GetBytes($Text)

    $backupPath = Get-HostsBackupPath $Path
    if (-not (Test-Path -LiteralPath $backupPath)) {
        Copy-Item -LiteralPath $Path -Destination $backupPath
        Write-Host "[+] Backup saved (first change only): $backupPath" -ForegroundColor Green
    }

    $tempPath = $Path + '.focus-tmp'
    $maxTries = 6
    $lastError = $null
    for ($try = 1; $try -le $maxTries; $try++) {
        try {
            $fs = [IO.File]::Open($tempPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $fs.Write($bytes, 0, $bytes.Length)
            } finally {
                $fs.Dispose()
            }
            $lastError = $null
            break
        } catch {
            $lastError = $_
            if ($try -eq $maxTries) { break }
            Start-Sleep -Milliseconds (200 * $try)
        }
    }
    if ($lastError) {
        throw "Could not write a temporary hosts file (it may be locked). Close any hosts editor and try again. $($lastError.Exception.Message)"
    }

    $replaced = $false
    for ($try = 1; $try -le $maxTries; $try++) {
        try {
            [IO.File]::Copy($tempPath, $Path, $true)
            $replaced = $true
            break
        } catch {
            $lastError = $_
            if ($try -eq $maxTries) { break }
            Start-Sleep -Milliseconds (200 * $try)
        }
    }
    if (Test-Path -LiteralPath $tempPath) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
    if (-not $replaced) {
        throw "Could not update the hosts file (it may be locked by another program). Close any hosts editor and try again. The backup is at $backupPath. $($lastError.Exception.Message)"
    }
}

function Clear-FocusDnsCache {
    $flushed = $false
    try {
        Clear-DnsClientCache -ErrorAction Stop
        $flushed = $true
    } catch { }
    if (-not $flushed) {
        try {
            $null = & ipconfig /flushdns 2>&1
            $flushed = $true
        } catch { }
    }
    if ($flushed) {
        Write-Host "[+] DNS cache flushed. Restart your browsers so they pick up the change." -ForegroundColor Green
    } else {
        Write-Host "[i] Could not flush the DNS cache automatically. Run 'ipconfig /flushdns' from an elevated prompt, then restart your browsers." -ForegroundColor Yellow
    }
}

function Write-SecureDnsWarning {
    Write-Host "[!] Already-open tabs and apps may keep using a connection until you close them." -ForegroundColor Yellow
    Write-Host "[!] Browsers with Secure DNS (DNS over HTTPS) turned on can skip the hosts file." -ForegroundColor Yellow
    Write-Host "    If a site still loads, turn off 'Use secure DNS' in Chrome or Edge, or 'DNS over HTTPS' in Firefox." -ForegroundColor Yellow
    Write-Host "    This script does not change those settings." -ForegroundColor Yellow
}

function Remove-FocusUnblockTask {
    $removed = $false
    if (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue) {
        $existing = Get-ScheduledTask -TaskName $script:UnblockTaskName -ErrorAction SilentlyContinue
        if ($existing) {
            try {
                Unregister-ScheduledTask -TaskName $script:UnblockTaskName -Confirm:$false -ErrorAction Stop
                $removed = $true
            } catch { }
        }
    }
    return $removed
}

function Get-FocusUnblockTaskInfo {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return $null }
    $task = Get-ScheduledTask -TaskName $script:UnblockTaskName -ErrorAction SilentlyContinue
    if (-not $task) { return $null }
    try {
        $info = $task | Get-ScheduledTaskInfo -ErrorAction Stop
        return $info
    } catch {
        return $task
    }
}

function Register-FocusUnblockTask {
    param(
        [int]$MinutesToWait,
        [string]$ScriptFile
    )
    if (-not (Test-Path -LiteralPath $ScriptFile)) {
        throw "Cannot schedule an automatic unblock because this script's path is unknown or missing."
    }
    if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        throw "The Scheduled Tasks cmdlets are not available on this PC."
    }

    $null = Remove-FocusUnblockTask
    $runAt = (Get-Date).AddMinutes($MinutesToWait)
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptFile`" -Off"
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powershell)) { $powershell = 'powershell.exe' }

    $action = New-ScheduledTaskAction -Execute $powershell -Argument $arg
    $trigger = New-ScheduledTaskTrigger -Once -At $runAt
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $null = Register-ScheduledTask -TaskName $script:UnblockTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
    return $runAt
}

function ConvertTo-ProcessArgumentString {
    param([string[]]$Parts)
    $quoted = foreach ($part in $Parts) {
        if ($part -match '\s' -or $part -match '"') {
            '"' + ($part -replace '"', '\"') + '"'
        } else {
            $part
        }
    }
    return ($quoted -join ' ')
}

function Get-RelaunchArgumentList {
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('-NoProfile')
    $parts.Add('-ExecutionPolicy')
    $parts.Add('Bypass')
    $parts.Add('-File')
    $parts.Add($PSCommandPath)
    if ($On) { $parts.Add('-On') }
    if ($Off) { $parts.Add('-Off') }
    if ($Status) { $parts.Add('-Status') }
    if ($IncludeYouTube) { $parts.Add('-IncludeYouTube') }
    if ($IncludeLinkedIn) { $parts.Add('-IncludeLinkedIn') }
    if ($IncludeDiscord) { $parts.Add('-IncludeDiscord') }
    $siteItems = @(Split-NameList $Sites)
    if ($siteItems.Count -gt 0) {
        $parts.Add('-Sites')
        foreach ($s in $siteItems) { $parts.Add($s) }
    }
    $excludeItems = @(Split-NameList $Exclude)
    if ($excludeItems.Count -gt 0) {
        $parts.Add('-Exclude')
        foreach ($s in $excludeItems) { $parts.Add($s) }
    }
    if ($Minutes -gt 0) {
        $parts.Add('-Minutes')
        $parts.Add("$Minutes")
    }
    if (-not [string]::IsNullOrWhiteSpace($HostsPath)) {
        $parts.Add('-HostsPath')
        $parts.Add($HostsPath)
    }
    # Do not pass -Elevate again; the new window should already be elevated.
    return ,$parts.ToArray()
}

function Request-Elevation {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path -LiteralPath $PSCommandPath)) {
        Write-Host "[!] Cannot relaunch automatically because this script's path is unknown." -ForegroundColor Red
        return $false
    }
    $exe = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($exe)) {
        $exe = Join-Path $PSHOME 'powershell.exe'
    }
    $argString = ConvertTo-ProcessArgumentString (Get-RelaunchArgumentList)
    try {
        $proc = Start-Process -FilePath $exe -Verb RunAs -ArgumentList $argString -Wait -PassThru
        if ($null -ne $proc.ExitCode) { exit $proc.ExitCode }
        exit 0
    } catch {
        Write-Host "[!] Elevation was cancelled or failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Write-FocusStatus {
    param(
        [string]$State,
        [string]$Action,
        [int]$DomainCount = 0,
        [string[]]$GroupNames,
        [string]$Target,
        [datetime]$UnblockAt
    )
    Write-Host ""
    Write-Host "Set-FocusMode" -ForegroundColor Cyan
    Write-Host "-------------" -ForegroundColor Cyan
    Write-Host ("Status  : {0}" -f $State)
    if (-not [string]::IsNullOrWhiteSpace($Action)) {
        Write-Host ("Action  : {0}" -f $Action)
    }
    if ($DomainCount -gt 0) {
        $lineCount = $DomainCount * 2
        Write-Host ("Domains : {0} host names ({1} hosts-file lines, IPv4 + IPv6)" -f $DomainCount, $lineCount)
    }
    if ($GroupNames -and $GroupNames.Count -gt 0) {
        Write-Host ("Sites   : {0}" -f ($GroupNames -join ', '))
    }
    Write-Host ("Target  : {0}" -f $Target)
    if ($PSBoundParameters.ContainsKey('UnblockAt') -and $UnblockAt) {
        Write-Host ("Unblock : scheduled at {0}" -f $UnblockAt.ToString('yyyy-MM-dd HH:mm'))
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Argument checks and hosts path
# ---------------------------------------------------------------------------
if ($On -and $Off) {
    throw "Use only one of -On or -Off (or neither, to toggle). "
}
if ($Status -and ($On -or $Off)) {
    throw "-Status cannot be combined with -On or -Off."
}
if ($PSBoundParameters.ContainsKey('Minutes') -and ($Off -or $Status)) {
    throw "-Minutes can only be used when turning focus on (with -On, or a toggle that turns it on)."
}

if ([string]::IsNullOrWhiteSpace($HostsPath)) {
    if ($env:windir) {
        $HostsPath = Join-Path $env:windir 'System32\drivers\etc\hosts'
    } else {
        $HostsPath = 'C:\Windows\System32\drivers\etc\hosts'
    }
}

$isSystemFile = Test-IsSystemHosts -Path $HostsPath
$wantStatusOnly = [bool]$Status
$needsWrite = -not $wantStatusOnly

if ($needsWrite -and $isSystemFile) {
    if (-not (Test-IsWindowsOs)) {
        throw "The system hosts file can only be changed on Windows."
    }
    if (-not (Test-IsAdministrator)) {
        Write-Host "[!] Administrator rights are required to change the hosts file." -ForegroundColor Red
        Write-Host "    Right-click Terminal or PowerShell, choose 'Run as administrator', then rerun this command." -ForegroundColor Red
        Write-Host "    Or rerun with -Elevate to get the approval prompt now. -Status works without admin." -ForegroundColor Red
        $shouldElevate = [bool]$Elevate
        if (-not $shouldElevate) {
            $interactive = $false
            try { $interactive = [Environment]::UserInteractive } catch { $interactive = $false }
            if ($interactive -and -not [Console]::IsInputRedirected) {
                $answer = Read-Host 'Relaunch as administrator now? [Y/N]'
                if ($answer -match '^[Yy]') { $shouldElevate = $true }
            }
        }
        if ($shouldElevate) {
            $ok = Request-Elevation
            if (-not $ok) { exit 1 }
        }
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Read and decide the action
# ---------------------------------------------------------------------------
$hostsData = Read-HostsFile -Path $HostsPath
$split = Split-FocusHostsBlock -Lines $hostsData.Lines
$hasBlock = [bool]$split.HasBlock
$existingCount = @($split.Domains).Count
$existingGroups = @()
if ($hasBlock) { $existingGroups = @(Get-SiteGroupsFromDomains -Domains $split.Domains) }

$action = 'toggle'
if ($On) { $action = 'on' }
elseif ($Off) { $action = 'off' }
elseif ($Status) { $action = 'status' }
elseif ($hasBlock) { $action = 'off' }
else { $action = 'on' }

if ($action -eq 'status') {
    $state = $(if ($hasBlock) { 'ON' } else { 'OFF' })
    $statusAction = $(if ($hasBlock) { "Focus block is present." } else { "No Set-FocusMode block found." })
    $unblockAt = $null
    $taskInfo = Get-FocusUnblockTaskInfo
    $statusParams = @{
        State       = $state
        Action      = $statusAction
        DomainCount = $existingCount
        GroupNames  = $existingGroups
        Target      = $HostsPath
    }
    if ($taskInfo -and $taskInfo.NextRunTime -and $taskInfo.NextRunTime -gt [datetime]::MinValue) {
        $statusParams['UnblockAt'] = $taskInfo.NextRunTime
    }
    Write-FocusStatus @statusParams
    if ($hasBlock) {
        Write-Host "To unblock: run this script again, or run it with -Off." -ForegroundColor Cyan
    } else {
        Write-Host "To block: run this script again, or run it with -On." -ForegroundColor Cyan
    }
    exit 0
}

if ($action -eq 'off') {
    $removedTask = $false
    if ($isSystemFile) { $removedTask = Remove-FocusUnblockTask }
    if (-not $hasBlock) {
        Write-FocusStatus -State 'OFF' -Action 'No Set-FocusMode block found. Nothing to remove.' -Target $HostsPath
        if ($removedTask) {
            Write-Host "[+] Removed a leftover Set-FocusMode-Unblock scheduled task." -ForegroundColor Green
        }
        exit 0
    }

    $newText = Join-HostsLines -Prefix $split.Prefix -Block @() -Suffix $split.Suffix -Newline $hostsData.Newline
    Write-HostsFileText -Path $HostsPath -Text $newText -Newline $hostsData.Newline
    Write-FocusStatus -State 'OFF' -Action ("Removed the focus block ({0} host names)." -f $existingCount) -DomainCount $existingCount -GroupNames $existingGroups -Target $HostsPath
    if ($removedTask) {
        Write-Host "[+] Removed the Set-FocusMode-Unblock scheduled task." -ForegroundColor Green
    }
    if ($isSystemFile) {
        Clear-FocusDnsCache
        Write-SecureDnsWarning
    }
    exit 0
}

# action is 'on'
$groups = Get-FocusDomainGroups -WithYouTube:$IncludeYouTube -WithLinkedIn:$IncludeLinkedIn -WithDiscord:$IncludeDiscord -ExtraSites $Sites -ExcludeSites $Exclude
$domainCount = Get-FocusDomainCount $groups
if ($domainCount -le 0) {
    throw "Nothing to block (the list is empty after applying -Exclude). Nothing was changed."
}
$blockLines = New-FocusHostsBlock -Groups $groups
$newText = Join-HostsLines -Prefix $split.Prefix -Block $blockLines -Suffix $split.Suffix -Newline $hostsData.Newline
$groupNames = @($groups.Keys)

$currentText = ($hostsData.Lines -join $hostsData.Newline)
if ($hostsData.Lines.Count -gt 0 -or $hostsData.HadTrailingNewline) {
    $currentText = ($hostsData.Lines -join $hostsData.Newline) + $hostsData.Newline
}
$unchanged = ($currentText -eq $newText)

$unblockAt = $null
$minutesBound = $PSBoundParameters.ContainsKey('Minutes')

if ($unchanged -and -not $minutesBound) {
    Write-FocusStatus -State 'ON' -Action 'Focus is already on with this same list. No changes.' -DomainCount $domainCount -GroupNames $groupNames -Target $HostsPath
    exit 0
}

if (-not $unchanged) {
    Write-HostsFileText -Path $HostsPath -Text $newText -Newline $hostsData.Newline
    $verb = $(if ($hasBlock) { 'Updated' } else { 'Added' })
    $actionText = "{0} the focus block ({1} host names)." -f $verb, $domainCount
} else {
    $actionText = "Focus is already on with this same list."
}

if ($minutesBound) {
    if ($isSystemFile) {
        try {
            $scriptFile = $PSCommandPath
            $unblockAt = Register-FocusUnblockTask -MinutesToWait $Minutes -ScriptFile $scriptFile
            $actionText = $actionText + (" Automatic unblock scheduled in {0} minute(s)." -f $Minutes)
        } catch {
            Write-Host "[!] Could not schedule an automatic unblock: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "    The block is in place. Unblock later with:" -ForegroundColor Yellow
            Write-Host "      powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Off" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[i] -Minutes is set, but automatic unblock is only scheduled when writing the system hosts file." -ForegroundColor Cyan
        Write-Host "    Unblock later with:  powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Off" -ForegroundColor Cyan
    }
}

$statusParams = @{
    State       = 'ON'
    Action      = $actionText
    DomainCount = $domainCount
    GroupNames  = $groupNames
    Target      = $HostsPath
}
if ($unblockAt) { $statusParams['UnblockAt'] = $unblockAt }
Write-FocusStatus @statusParams

if ($isSystemFile -and -not $unchanged) {
    Clear-FocusDnsCache
    Write-SecureDnsWarning
}

if (-not $minutesBound) {
    Write-Host "To unblock: run this script again, or run it with -Off." -ForegroundColor Cyan
} elseif (-not $unblockAt) {
    Write-Host "To unblock: run this script with -Off." -ForegroundColor Cyan
} else {
    Write-Host ("To unblock sooner: run this script with -Off. Otherwise it turns off at {0}." -f $unblockAt.ToString('yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
}

exit 0
