<#
.SYNOPSIS
    Find-RemoteAccess.ps1 - Show every way someone could remotely see or
    control this PC: Windows' own remote features, installed remote-control
    apps (TeamViewer, AnyDesk, ScreenConnect and more), and signs of a
    hidden proxy, tunnel or bandwidth-sharing tool. Read-only.

.DESCRIPTION
    Tech-support scams almost always end with a remote-control app left on the
    PC, and old remote setups (RDP opened for one job, an SSH server you tried
    once, a TeamViewer install from years ago) tend to stay switched on. This
    script lists all of them in one place so you can decide what to keep. It
    also looks for less obvious ways this PC could be used as a relay: a
    renamed tunnel tool, a proxy you did not set, or software that shares
    your connection with strangers.

    Reports:
      Built-in     Remote Desktop (on/off, Network Level Authentication, port,
                   firewall rules, who is allowed in), Remote Assistance,
                   Quick Assist, OpenSSH Server (and how many authorized keys
                   exist, never the keys themselves), WinRM / PowerShell
                   Remoting, the Remote Registry service and the
                   LocalAccountTokenFilterPolicy setting
      Apps         Remote-control, remote-support (RMM) apps found in
                   installed programs, services, running processes or
                   startup entries, with version, install date, whether they
                   start with Windows (unattended access), whether they are
                   running and which ports they listen on
      Proxy/tunnel Listening ports (TCP and UDP) and established outbound
                   connections whose program is unsigned or runs from a
                   user-writable folder; WinINET and WinHTTP proxy settings;
                   netsh portproxy relay rules; VPN connections; TAP /
                   Wintun / WireGuard-style adapters that do not match a
                   known installed VPN; known tunnel and bandwidth-sharing
                   tools (ngrok, cloudflared, frp, Chisel, Tor, reverse SSH,
                   Honeygain and similar); inbound firewall allow rules for
                   programs in user folders, and recently added any-program
                   rules
      Findings     Numbered list of what to look at first, with how to fix it

    Safety level : READ-ONLY. Reads the registry, services, processes,
                   firewall rules, listening ports, connection table, local
                   proxy settings and scheduled tasks. Changes nothing,
                   uninstalls nothing, makes no network calls. Writes a file
                   only if you pass -CsvPath. Fixes are printed as
                   suggestions only. A Microsoft Defender Offline scan is
                   recommended in the closing note; the command is printed
                   and never run.
    Admin        : Not required. As admin it can also count keys in the
                   OpenSSH administrators_authorized_keys file, list
                   members of Remote Desktop Users on every edition, and
                   see paths and signatures of some system processes.

.PARAMETER RecentDays
    Flag remote apps installed in the last N days (1-365, default 30). A remote
    app you don't remember installing recently is the classic scam sign. Also
    used as the window for "recently added" firewall rules.

.PARAMETER Detailed
    Also print matching firewall rule names, service paths, the evidence
    each app was found by, and remote addresses for flagged connections.

.PARAMETER SkipNetwork
    Skip the scan of listening ports and established outbound connections
    for unsigned or user-folder programs. Proxy settings, tunnel tools and
    firewall rules are still checked.

.PARAMETER CsvPath
    Export every built-in feature, app, proxy, adapter and tool found to
    this CSV file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-RemoteAccess.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-RemoteAccess.ps1 -RecentDays 7 -Detailed

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-RemoteAccess.ps1 -SkipNetwork

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-RemoteAccess.ps1 -CsvPath "$env:USERPROFILE\Desktop\remote-access.csv"
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)][int]$RecentDays = 30,
    [switch]$Detailed,
    [switch]$SkipNetwork,
    [string]$CsvPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$findings = New-Object System.Collections.Generic.List[object]
$rows     = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param([string]$Level, [string]$Text, [string]$Fix)
    $findings.Add([pscustomobject]@{ Level = $Level; Text = $Text; Fix = $Fix })
}
function Add-Row {
    param([string]$Kind, [string]$Name, [string]$Status, [string]$Detail)
    $rows.Add([pscustomobject]@{ Kind = $Kind; Name = $Name; Status = $Status; Detail = $Detail })
}
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}
function Write-Section { param([string]$Title) Write-Host ''; Write-Host "== $Title ==" -ForegroundColor Cyan }
function Write-Line {
    param([string]$Label, [string]$Value, [string]$Color = 'Gray')
    Write-Host ("  {0,-26}: {1}" -f $Label, $Value) -ForegroundColor $Color
}
function Get-FileLineCount {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return 0 }
        @(Get-Content -LiteralPath $Path -ErrorAction Stop | Where-Object { $_ -match '^\s*(ssh-|ecdsa-|sk-)' -or $_ -match '\s(ssh-|ecdsa-|sk-)' }).Count
    } catch { -1 }
}

# --- Matching helpers (also used by the unit-test harness) -------------------
# FINDREMOTEACCESS_TEST: when set, the script defines the helpers and catalogs
# below, then returns so tests can call them without touching Windows.

function Get-CommandExe {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $c = $Command.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $tok = ($c -split '\s+', 2)[0]
    return $tok.Trim('"')
}

function Test-UserWritablePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    $p = $p -replace '/', '\'

    if ($p -match '(?i)\\Users\\[^\\]+\\AppData\\') { return $true }
    if ($p -match '(?i)\\Users\\Public(\\|$)') { return $true }
    if ($p -match '(?i)\\Users\\[^\\]+\\Downloads(\\|$)') { return $true }
    if ($p -match '(?i)^[A-Za-z]:\\Temp(\\|$)') { return $true }
    if ($p -match '(?i)\\Windows\\Temp(\\|$)') { return $true }
    if ($p -match '(?i)\\AppData\\Local\\Temp(\\|$)') { return $true }

    if ($p -match '(?i)^[A-Za-z]:\\ProgramData\\([^\\]+)(\\|$)(.*)$') {
        $first = $Matches[1]
        $known = @(
            'Microsoft', 'Windows', 'Package Cache', 'USOShared', 'USOPrivate',
            'ssh', 'NVIDIA Corporation', 'Adobe', 'Intel', 'Lenovo', 'Dell',
            'Hewlett-Packard', 'HP', 'Apple Inc', 'Apple', 'Packages'
        )
        foreach ($k in $known) {
            if ($first -eq $k) { return $false }
        }
        return $true
    }
    return $false
}

function Test-SuspiciousNetworkProcess {
    param([string]$Path, [string]$Signed, [string]$Signer)
    $userWrite = Test-UserWritablePath $Path
    $unsigned = ($Signed -eq 'No' -or $Signed -like 'Bad*')
    if ($unsigned) { return $true }
    if ($userWrite) {
        if ($Signed -eq 'Yes' -and $Signer -match '(?i)^Microsoft\b') { return $false }
        return $true
    }
    return $false
}

function Test-LoopbackAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $a = $Address
    if ($a -match '^::ffff:(\d+\.\d+\.\d+\.\d+)$') { $a = $Matches[1] }
    if ($a -eq '::1' -or $a -eq '127.0.0.1') { return $true }
    if ($a -like '127.*') { return $true }
    return $false
}

function Test-BuiltinTunnelAdapter {
    param([string]$Description, [string]$Name)
    $t = (([string]$Description) + ' ' + ([string]$Name))
    if ([string]::IsNullOrWhiteSpace($t)) { return $false }
    return [bool]($t -match '(?i)WAN Miniport|Microsoft Teredo|Teredo Tunneling|Microsoft 6to4|Microsoft ISATAP|Microsoft IP-HTTPS|Kernel Debug Network Adapter|Hyper-V|vEthernet|Windows Subsystem for Linux|\bWSL\b|Wi-Fi Direct|Microsoft Wi-Fi Direct|\bBluetooth\b|VirtualBox Host-Only|VMware.*(Virtual|Adapter)|\bNpcap\b|Loopback')
}

function Test-TunnelAdapterName {
    param([string]$Description, [string]$Name)
    $t = (([string]$Description) + ' ' + ([string]$Name))
    if ([string]::IsNullOrWhiteSpace($t)) { return $false }
    if (Test-BuiltinTunnelAdapter $Description $Name) { return $false }
    if ($t -match '(?i)\b(TAP-Windows|TAP-Win32|TAP-Win64|TAP-Proton|TAP-Nord|TAP-OpenVPN|TAP-Windows Adapter|Wintun|WireGuard|OpenVPN|ZeroTier|Tailscale|NordLynx|Cloudflare WARP|ProtonVPN|Mullvad|Hamachi|SoftEther|VPN Client Adapter)\b') {
        return $true
    }
    if ($t -match '(?i)(^|[^A-Za-z])TAP($|[^A-Za-z]|-)') { return $true }
    return $false
}

function Get-MatchingVpnProduct {
    param([string]$Description, [string]$Name, [string[]]$InstalledText)
    $t = (([string]$Description) + ' ' + ([string]$Name))
    $blob = if ($InstalledText) { $InstalledText -join "`n" } else { '' }
    $hits = @()
    foreach ($p in $script:vpnProductPatterns) {
        $inAdapter = [bool]($t -match $p.Rx)
        $inInstall = [bool]($blob -and $blob -match $p.Rx)
        if ($inAdapter -or ($inInstall -and ($t -match '(?i)Wintun|\bTAP\b|TAP-Windows'))) {
            if ($hits -notcontains $p.N) { $hits += $p.N }
        }
    }
    return $hits
}

function Test-ReverseTunnelCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $false }
    if ($Command -notmatch '(?i)(^|[\\/""\s])(ssh|plink|ssh\.exe|plink\.exe)("|\s|$)') { return $false }
    if ($Command -match '(?i)(?:^|\s)-R(\s+\S|\s*$)') { return $true }
    if ($Command -match '(?i)(?:^|\s)-D(\s+\S|\s*$)') { return $true }
    return $false
}

function Test-AnyProgramPath {
    param([string]$Program)
    if ([string]::IsNullOrWhiteSpace($Program)) { return $true }
    $p = $Program.Trim().Trim('"')
    return ($p -eq 'Any' -or $p -eq '*' -or $p -eq 'System')
}

function Test-BuiltinFirewallGroup {
    param([string]$Group)
    if ([string]::IsNullOrWhiteSpace($Group)) { return $false }
    return ($Group -match '^@')
}

function Parse-WinHttpProxy {
    param([string]$Text)
    $result = [pscustomobject]@{ Direct = $true; Server = ''; Bypass = ''; Raw = [string]$Text }
    if ([string]::IsNullOrWhiteSpace($Text)) { return $result }
    $result.Direct = [bool]($Text -match '(?i)Direct access')
    if ($Text -match '(?im)Proxy Server\(s\)\s*:\s*(.+)$') {
        $result.Server = $Matches[1].Trim()
        $result.Direct = $false
    }
    if ($Text -match '(?im)Bypass List\s*:\s*(.+)$') {
        $result.Bypass = $Matches[1].Trim()
    }
    return $result
}

function Parse-PortProxyOutput {
    param([string]$Text)
    $rows = @()
    if ([string]::IsNullOrWhiteSpace($Text)) { return $rows }
    foreach ($line in ($Text -split '\r?\n')) {
        $t = $line.Trim()
        if ($t -eq '') { continue }
        if ($t -match '(?i)^(listen|address|connect|-)') { continue }
        $parts = @($t -split '\s+')
        if ($parts.Count -ge 4 -and $parts[1] -match '^\d+$' -and $parts[3] -match '^\d+$') {
            $rows += [pscustomobject]@{
                ListenAddress  = $parts[0]
                ListenPort     = $parts[1]
                ConnectAddress = $parts[2]
                ConnectPort    = $parts[3]
            }
        }
    }
    return $rows
}

function Find-RelayCatalogMatches {
    param([string]$Text)
    $hits = @()
    if ([string]::IsNullOrWhiteSpace($Text)) { return $hits }
    foreach ($tool in $script:relayCatalog) {
        if ($Text -match $tool.Rx) { $hits += $tool }
    }
    return $hits
}

$script:relayCatalog = @(
    @{ N = 'ngrok';             Kind = 'Tunnel';    Rx = '(?i)\bngrok(\.exe)?\b' }
    @{ N = 'Cloudflare Tunnel'; Kind = 'Tunnel';    Rx = '(?i)cloudflared(\.exe)?|\bCloudflare Tunnel\b' }
    @{ N = 'frp';               Kind = 'Tunnel';    Rx = '(?i)(?<![A-Za-z])frp[cs]?(?:\.exe)?(?![A-Za-z])' }
    @{ N = 'Chisel';            Kind = 'Tunnel';    Rx = '(?i)\bchisel\.exe\b|\bchisel\s+(client|server)\b|\bjpillora[/\\]chisel\b' }
    @{ N = 'Tor';               Kind = 'Tunnel';    Rx = '(?i)(^|[\\/])tor\.exe\b|\bTor Browser\b|\bTorBrowser\b' }
    @{ N = 'Honeygain';         Kind = 'Proxyware'; Rx = '(?i)\bHoneygain\b' }
    @{ N = 'IPRoyal Pawns';     Kind = 'Proxyware'; Rx = '(?i)\bPawns\.app\b|\bIPRoyal\b|\bpawns-windows\b|\bPawnsApp\b' }
    @{ N = 'PacketStream';      Kind = 'Proxyware'; Rx = '(?i)\bPacketStream\b' }
    @{ N = 'Peer2Profit';       Kind = 'Proxyware'; Rx = '(?i)\bPeer2Profit\b|\bpeer2profit\b' }
    @{ N = 'EarnApp';           Kind = 'Proxyware'; Rx = '(?i)\bEarnApp\b' }
    @{ N = 'Bright Data';       Kind = 'Proxyware'; Rx = '(?i)\bBright Data\b|\bBrightData\b|\bLuminati\b' }
    @{ N = 'Repocket';          Kind = 'Proxyware'; Rx = '(?i)\bRepocket\b' }
    @{ N = 'Traffmonetizer';    Kind = 'Proxyware'; Rx = '(?i)\bTraffmonetizer\b' }
    @{ N = 'Grass';             Kind = 'Proxyware'; Rx = '(?i)\bGetGrass\b|\bGrass\.io\b|\bGrassMiner\b|\bGrassNode\b|\bgrass-desktop\b|\bGrassDesktop\b|(^|[\\/])grass\.exe\b' }
)

$script:relayExeNames = @(
    'ngrok.exe', 'cloudflared.exe', 'frpc.exe', 'frps.exe', 'frp.exe',
    'chisel.exe', 'tor.exe', 'honeygain.exe', 'pawns.exe', 'pawns-windows.exe',
    'packetstream.exe', 'peer2profit.exe', 'earnapp.exe', 'repocket.exe',
    'traffmonetizer.exe', 'grass.exe', 'grass-desktop.exe'
)

$script:vpnProductPatterns = @(
    @{ N = 'WireGuard';         Rx = '(?i)\bWireGuard\b' }
    @{ N = 'OpenVPN';           Rx = '(?i)\bOpenVPN\b' }
    @{ N = 'Tailscale';         Rx = '(?i)\bTailscale\b' }
    @{ N = 'ZeroTier';          Rx = '(?i)\bZeroTier\b' }
    @{ N = 'NordVPN';           Rx = '(?i)\bNordVPN\b|\bNordLynx\b' }
    @{ N = 'ExpressVPN';        Rx = '(?i)\bExpressVPN\b' }
    @{ N = 'Mullvad';           Rx = '(?i)\bMullvad\b' }
    @{ N = 'Proton VPN';        Rx = '(?i)\bProtonVPN\b|\bProton VPN\b' }
    @{ N = 'Cloudflare WARP';   Rx = '(?i)\bCloudflare WARP\b|\bCloudflareWARP\b' }
    @{ N = 'Surfshark';         Rx = '(?i)\bSurfshark\b' }
    @{ N = 'CyberGhost';        Rx = '(?i)\bCyberGhost\b' }
    @{ N = 'Private Internet Access'; Rx = '(?i)\bPrivate Internet Access\b|\bPIA VPN\b' }
    @{ N = 'Cisco Secure Client'; Rx = '(?i)\bCisco AnyConnect\b|\bCisco Secure Client\b' }
    @{ N = 'GlobalProtect';     Rx = '(?i)\bGlobalProtect\b' }
    @{ N = 'FortiClient';       Rx = '(?i)\bFortiClient\b' }
    @{ N = 'Hamachi';           Rx = '(?i)\bHamachi\b' }
    @{ N = 'SoftEther';         Rx = '(?i)\bSoftEther\b' }
)

# When the test harness dotsources this file, stop before any Windows-only work.
if ($env:FINDREMOTEACCESS_TEST) { return }

$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }

Write-Host 'Find-RemoteAccess.ps1 - read-only remote access check' -ForegroundColor White
Write-Host ("Running as admin: {0}. Recent-install window: {1} days.{2}" -f $(if ($isAdmin) { 'yes' } else { 'no' }), $RecentDays, $(if ($SkipNetwork) { ' Connection scan skipped.' } else { '' })) -ForegroundColor DarkGray

# --- Shared data -------------------------------------------------------------
$services = @()
try { $services = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch { Write-Host '  [i] Could not read services.' -ForegroundColor Yellow }
$svcByName = @{}
foreach ($s in $services) { $svcByName[$s.Name] = $s }

$procs = @()
try { $procs = @(Get-Process -ErrorAction SilentlyContinue) } catch { }

$listen = @()
try { $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } catch { }
function Get-PortsForPids {
    param([int[]]$ProcessIds)
    if (-not $ProcessIds) { return '' }
    $p = @($listen | Where-Object { $ProcessIds -contains $_.OwningProcess } | ForEach-Object {
        $scope = if ($_.LocalAddress -in '127.0.0.1', '::1') { 'local only' } else { 'network' }
        "{0} ({1})" -f $_.LocalPort, $scope
    } | Sort-Object -Unique)
    $p -join ', '
}

$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
$isHome = $false
if ($os -and $os.Caption -match 'Home') { $isHome = $true }

# --- Built-in: Remote Desktop ------------------------------------------------
Write-Section 'Built-in remote access'

$tsKey   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpTcp  = "$tsKey\WinStations\RDP-Tcp"
$deny    = Get-RegValue $tsKey 'fDenyTSConnections'
$nla     = Get-RegValue $rdpTcp 'UserAuthentication'
$rdpPort = Get-RegValue $rdpTcp 'PortNumber'
if ($null -eq $rdpPort) { $rdpPort = 3389 }
$rdpOn   = ($deny -eq 0) -and -not $isHome

if ($isHome) {
    Write-Line 'Remote Desktop' 'not available on Windows Home (this PC can connect out, but nobody can connect in)' 'Green'
    Add-Row 'Built-in' 'Remote Desktop' 'Not available (Home edition)' ''
} elseif ($rdpOn) {
    $nlaText = if ($nla -eq 0) { 'OFF' } else { 'on' }
    Write-Line 'Remote Desktop' ("ON  (port {0}, Network Level Authentication {1})" -f $rdpPort, $nlaText) 'Yellow'

    $fwText = 'unknown'
    $rdpRules = @()
    try {
        $rdpRules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop |
            Where-Object { $_.Group -eq '@FirewallAPI.dll,-28752' -or $_.DisplayGroup -match 'Remote Desktop' })
        if ($rdpRules.Count -eq 0) { $fwText = 'no inbound rule enabled (blocked by the firewall)' }
        else {
            $profiles = @($rdpRules | ForEach-Object { $_.Profile.ToString() -split ',\s*' } | Sort-Object -Unique)
            $fwText = 'allowed on ' + ($profiles -join ', ') + ' networks'
        }
    } catch { }
    Write-Line '  Firewall' $fwText
    if ($Detailed) { $rdpRules | ForEach-Object { Write-Host ("      rule: {0} [{1}]" -f $_.DisplayName, $_.Profile) -ForegroundColor DarkGray } }

    $members = $null
    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-555' -ErrorAction Stop | ForEach-Object { $_.Name })
        $memText = if ($members.Count -eq 0) { 'none (only Administrators can sign in remotely)' } else { "{0} account(s): {1}" -f $members.Count, ($members -join ', ') }
        Write-Line '  Remote Desktop Users' $memText
    } catch { Write-Line '  Remote Desktop Users' 'could not read (run as admin to see)' 'DarkGray' }

    Add-Row 'Built-in' 'Remote Desktop' 'On' ("port $rdpPort; NLA $nlaText; firewall: $fwText")
    if ($nla -eq 0) {
        Add-Finding 'High' 'Remote Desktop is on without Network Level Authentication, so anyone who can reach the PC gets a sign-in screen before proving who they are.' 'Settings > System > Remote Desktop > Advanced settings > turn on "Require devices to use Network Level Authentication", or turn Remote Desktop off if you do not use it.'
    }
    if ($fwText -match 'Public') {
        Add-Finding 'High' 'Remote Desktop is allowed through the firewall on Public networks (coffee shops, hotels).' 'Windows Security > Firewall & network protection > Allow an app through firewall > Remote Desktop: untick Public.'
    }
    if ($rdpPort -ne 3389) {
        Add-Finding 'Low' "Remote Desktop listens on a non-standard port ($rdpPort). Fine if you set that on purpose; if not, someone else configured it." 'If unexpected, turn Remote Desktop off in Settings > System > Remote Desktop.'
    }
    Add-Finding 'Medium' 'Remote Desktop is turned on. Only keep it on if you actually connect to this PC from another device.' 'Settings > System > Remote Desktop > Off.'
} else {
    Write-Line 'Remote Desktop' 'off' 'Green'
    Add-Row 'Built-in' 'Remote Desktop' 'Off' ''
}

# --- Built-in: Remote Assistance and Quick Assist ----------------------------
$raKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
$raHelp = Get-RegValue $raKey 'fAllowToGetHelp'
$raFull = Get-RegValue $raKey 'fAllowFullControl'
if ($raHelp -eq 1) {
    $ctl = if ($raFull -eq 1) { 'helpers may take control' } else { 'view only' }
    Write-Line 'Remote Assistance' ("allowed ({0}; needs an invitation each time)" -f $ctl) 'Yellow'
    Add-Row 'Built-in' 'Remote Assistance' 'Allowed' $ctl
    Add-Finding 'Low' 'Remote Assistance invitations are allowed. It still needs an invitation, but most people never use it.' 'Control Panel > System > Remote settings > untick "Allow Remote Assistance connections to this computer".'
} else {
    Write-Line 'Remote Assistance' 'off' 'Green'
    Add-Row 'Built-in' 'Remote Assistance' 'Off' ''
}

$qa = $null
try { $qa = Get-AppxPackage -Name 'MicrosoftCorporationII.QuickAssist' -ErrorAction Stop | Select-Object -First 1 } catch { }
$qaRunning = @($procs | Where-Object { $_.ProcessName -eq 'QuickAssist' }).Count -gt 0
if ($qa) {
    $qaText = if ($qaRunning) { 'installed and RUNNING now' } else { 'installed (only works while you share a code)' }
    Write-Line 'Quick Assist' $qaText $(if ($qaRunning) { 'Yellow' } else { 'Gray' })
    Add-Row 'Built-in' 'Quick Assist' $(if ($qaRunning) { 'Running' } else { 'Installed' }) $qa.Version
    if ($qaRunning) {
        Add-Finding 'High' 'Quick Assist is running right now. If you did not start a session with someone you know, close it.' 'Close Quick Assist. Microsoft and banks never call you to ask for a Quick Assist code.'
    }
} else {
    Write-Line 'Quick Assist' 'not installed'
    Add-Row 'Built-in' 'Quick Assist' 'Not installed' ''
}

# --- Built-in: OpenSSH Server ------------------------------------------------
$sshd = $svcByName['sshd']
if ($sshd) {
    $userKeys  = Get-FileLineCount (Join-Path $env:USERPROFILE '.ssh\authorized_keys')
    $adminFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $adminKeys = Get-FileLineCount $adminFile
    $adminText = if ($adminKeys -lt 0) { 'unreadable (run as admin)' } else { "$adminKeys" }
    $color = if ($sshd.State -eq 'Running') { 'Yellow' } else { 'Gray' }
    Write-Line 'OpenSSH Server' ("{0}, start: {1}; keys: yours {2}, administrators {3}" -f $sshd.State, $sshd.StartMode, $userKeys, $adminText) $color
    $ports = Get-PortsForPids @([int]$sshd.ProcessId)
    if ($ports) { Write-Line '  Listening' $ports }
    Add-Row 'Built-in' 'OpenSSH Server' $sshd.State ("start $($sshd.StartMode); user keys $userKeys; admin keys $adminText; ports $ports")
    if ($sshd.State -eq 'Running' -or $sshd.StartMode -eq 'Auto') {
        Add-Finding 'Medium' 'The OpenSSH Server is running or starts with Windows, so this PC accepts SSH logins.' 'If you do not need it: Settings > System > Optional features > OpenSSH Server > Remove (or set the "OpenSSH SSH Server" service to Manual and stop it).'
    }
    if (($userKeys -gt 0) -or ($adminKeys -gt 0)) {
        Add-Finding 'Medium' 'There are SSH authorized keys on this PC; whoever holds the matching private keys can log in without a password.' "Open the authorized_keys files and remove any key you don't recognize."
    }
} else {
    Write-Line 'OpenSSH Server' 'not installed' 'Green'
    Add-Row 'Built-in' 'OpenSSH Server' 'Not installed' ''
}

# --- Built-in: WinRM, Remote Registry, token filter --------------------------
$winrm = $svcByName['WinRM']
$listenerKeys = @()
try { $listenerKeys = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener' -ErrorAction Stop) } catch { }
$winrmPorts = @($listen | Where-Object { $_.LocalPort -in 5985, 5986 } | ForEach-Object { $_.LocalPort } | Sort-Object -Unique)
if ($winrm) {
    $wText = "{0}, start: {1}; listeners: {2}" -f $winrm.State, $winrm.StartMode, $listenerKeys.Count
    if ($winrmPorts) { $wText += '; listening on ' + ($winrmPorts -join ', ') }
    $color = if ($winrm.State -eq 'Running' -and $listenerKeys.Count -gt 0) { 'Yellow' } else { 'Gray' }
    Write-Line 'WinRM / PS Remoting' $wText $color
    Add-Row 'Built-in' 'WinRM' $winrm.State $wText
    if ($winrm.State -eq 'Running' -and $listenerKeys.Count -gt 0) {
        Add-Finding 'Medium' 'PowerShell Remoting (WinRM) is set up, so admins on your network can run commands on this PC.' 'If you did not set this up on purpose, run "Disable-PSRemoting -Force" as admin, then set the WinRM service to Manual and stop it.'
    }
}

$rr = $svcByName['RemoteRegistry']
if ($rr) {
    Write-Line 'Remote Registry' ("{0}, start: {1}" -f $rr.State, $rr.StartMode) $(if ($rr.State -eq 'Running') { 'Yellow' } else { 'Gray' })
    Add-Row 'Built-in' 'Remote Registry' $rr.State "start $($rr.StartMode)"
    if ($rr.State -eq 'Running' -or $rr.StartMode -eq 'Auto') {
        Add-Finding 'Medium' 'The Remote Registry service is running or set to start automatically (it is off by default on Windows 11).' 'services.msc > Remote Registry > Startup type: Disabled > Stop.'
    }
}

$latfp = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
if ($latfp -eq 1) {
    Write-Line 'LocalAccountTokenFilter' '1 (local admin accounts get full rights over the network)' 'Yellow'
    Add-Row 'Built-in' 'LocalAccountTokenFilterPolicy' '1' 'remote UAC restrictions off'
    Add-Finding 'Medium' 'LocalAccountTokenFilterPolicy is 1, which turns off a UAC protection for local admin accounts used over the network. Old remote tools and guides set this.' 'If nothing you use needs it, delete that value under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System and restart.'
} else {
    Write-Line 'LocalAccountTokenFilter' 'default' 'Green'
}

# --- Third-party remote apps -------------------------------------------------
Write-Section 'Remote-control and support apps'

# Name, regex, type. Regexes match installed program names, service names and
# paths, process names and startup entries.
$catalog = @(
    @{ N = 'TeamViewer';             R = 'TeamViewer';                                    T = 'Remote control' }
    @{ N = 'AnyDesk';                R = 'AnyDesk';                                       T = 'Remote control' }
    @{ N = 'RustDesk';               R = 'RustDesk';                                      T = 'Remote control' }
    @{ N = 'HopToDesk';              R = 'HopToDesk';                                     T = 'Remote control' }
    @{ N = 'ScreenConnect';          R = 'ScreenConnect|ConnectWise Control';             T = 'Remote support' }
    @{ N = 'Splashtop';              R = 'Splashtop';                                     T = 'Remote control' }
    @{ N = 'LogMeIn / GoTo';         R = 'LogMeIn|GoToAssist|GoTo Resolve|LMIGuardian';   T = 'Remote support' }
    @{ N = 'Chrome Remote Desktop';  R = 'Chrome Remote Desktop|chromoting|remoting_host'; T = 'Remote control' }
    @{ N = 'Parsec';                 R = '\bParsec\b|parsecd';                            T = 'Remote control' }
    @{ N = 'VNC server';             R = 'RealVNC|TightVNC|UltraVNC|TigerVNC|winvnc|tvnserver|vncserver'; T = 'Remote control' }
    @{ N = 'Zoho Assist';            R = 'Zoho Assist|ZohoMeeting|ZA_Connect';            T = 'Remote support' }
    @{ N = 'Remote Utilities';       R = 'Remote Utilities|rutserv|rfusclient';           T = 'Remote control' }
    @{ N = 'Ammyy Admin';            R = 'Ammyy';                                         T = 'Remote control' }
    @{ N = 'Supremo';                R = '\bSupremo';                                     T = 'Remote control' }
    @{ N = 'NetSupport Manager';     R = 'NetSupport';                                    T = 'Remote control' }
    @{ N = 'Radmin';                 R = '\bRadmin';                                      T = 'Remote control' }
    @{ N = 'Jump Desktop';           R = 'Jump Desktop';                                  T = 'Remote control' }
    @{ N = 'SimpleHelp';             R = 'SimpleHelp';                                    T = 'Remote support' }
    @{ N = 'DWService';              R = 'DWAgent|DWService';                             T = 'Remote control' }
    @{ N = 'MeshCentral agent';      R = 'MeshAgent|Mesh Agent';                          T = 'Remote management' }
    @{ N = 'Atera';                  R = '\bAtera';                                       T = 'Remote management' }
    @{ N = 'NinjaOne';               R = 'NinjaRMM|NinjaOne';                             T = 'Remote management' }
    @{ N = 'Kaseya';                 R = 'Kaseya';                                        T = 'Remote management' }
    @{ N = 'Action1';                R = '\bAction1';                                     T = 'Remote management' }
)

# Installed programs (machine and current user)
$installed = @()
$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($p in $uninstallPaths) {
    try {
        $installed += @(Get-ItemProperty -Path $p -ErrorAction Stop | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName })
    } catch { }
}

# Startup entries
$startup = @()
foreach ($k in 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
    try {
        $props = Get-ItemProperty -Path $k -ErrorAction Stop
        foreach ($pr in $props.PSObject.Properties) {
            if ($pr.Name -notlike 'PS*') { $startup += [pscustomobject]@{ Name = $pr.Name; Command = [string]$pr.Value } }
        }
    } catch { }
}
foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    if ($folder -and (Test-Path -LiteralPath $folder)) {
        Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue | ForEach-Object { $startup += [pscustomobject]@{ Name = $_.BaseName; Command = $_.FullName } }
    }
}

$found = New-Object System.Collections.Generic.List[object]
foreach ($tool in $catalog) {
    $rx = $tool.R
    $prog = @($installed | Where-Object { $_.DisplayName -match $rx })
    $svc  = @($services  | Where-Object { $_.Name -match $rx -or $_.DisplayName -match $rx -or ($_.PathName -and $_.PathName -match $rx) })
    $proc = @($procs     | Where-Object { $_.ProcessName -match $rx -or ($_.PSObject.Properties['Path'] -and $_.Path -and $_.Path -match $rx) })
    $run  = @($startup   | Where-Object { $_.Name -match $rx -or $_.Command -match $rx })
    if (($prog.Count + $svc.Count + $proc.Count + $run.Count) -eq 0) { continue }

    $version = ($prog | ForEach-Object { if ($_.PSObject.Properties['DisplayVersion']) { $_.DisplayVersion } } | Select-Object -First 1)
    $installDate = $null
    foreach ($pg in $prog) {
        if ($pg.PSObject.Properties['InstallDate'] -and $pg.InstallDate -match '^\d{8}$') {
            try { $d = [datetime]::ParseExact($pg.InstallDate, 'yyyyMMdd', $null); if (-not $installDate -or $d -gt $installDate) { $installDate = $d } } catch { }
        }
    }
    $autoSvc   = @($svc | Where-Object { $_.StartMode -eq 'Auto' })
    $isRunning = ($proc.Count -gt 0) -or (@($svc | Where-Object { $_.State -eq 'Running' }).Count -gt 0)
    $unattended = ($autoSvc.Count -gt 0) -or ($run.Count -gt 0)
    $pids  = @($proc | ForEach-Object { [int]$_.Id }) + @($svc | Where-Object { $_.ProcessId } | ForEach-Object { [int]$_.ProcessId })
    $ports = Get-PortsForPids ($pids | Sort-Object -Unique)
    $evidence = @()
    if ($prog.Count) { $evidence += 'installed' }
    if ($svc.Count)  { $evidence += "service ($(@($svc | ForEach-Object { $_.Name }) -join ', '))" }
    if ($proc.Count) { $evidence += 'running process' }
    if ($run.Count)  { $evidence += 'startup entry' }
    $isRecent = $installDate -and ($installDate -gt (Get-Date).AddDays(-$RecentDays))

    $found.Add([pscustomobject]@{
        Name = $tool.N; Type = $tool.T; Version = $version; InstallDate = $installDate
        Recent = [bool]$isRecent; Unattended = $unattended; Running = $isRunning
        Ports = $ports; Evidence = ($evidence -join '; ')
        ServicePaths = (@($svc | ForEach-Object { $_.PathName }) -join ' | ')
    })
}

if ($found.Count -eq 0) {
    Write-Host '  None of the known remote-control or support apps were found.' -ForegroundColor Green
} else {
    foreach ($f in $found) {
        $color = if ($f.Recent -or ($f.Unattended -and $f.Running)) { 'Yellow' } else { 'Gray' }
        $dateText = if ($f.InstallDate) { $f.InstallDate.ToString('yyyy-MM-dd') } else { 'unknown' }
        $verText  = if ($f.Version) { "v$($f.Version)" } else { 'version ?' }
        Write-Host ("  {0} ({1})" -f $f.Name, $f.Type) -ForegroundColor $color
        Write-Host ("      {0}, installed {1}{2}" -f $verText, $dateText, $(if ($f.Recent) { '  <- recent' } else { '' })) -ForegroundColor $color
        Write-Host ("      Starts with Windows: {0}   Running now: {1}" -f $(if ($f.Unattended) { 'yes' } else { 'no' }), $(if ($f.Running) { 'yes' } else { 'no' }))
        if ($f.Ports) { Write-Host ("      Listening on: {0}" -f $f.Ports) }
        if ($Detailed) {
            Write-Host ("      Found by: {0}" -f $f.Evidence) -ForegroundColor DarkGray
            if ($f.ServicePaths) { Write-Host ("      Service: {0}" -f $f.ServicePaths) -ForegroundColor DarkGray }
        }
        Add-Row $f.Type $f.Name $(if ($f.Running) { 'Running' } else { 'Installed' }) ("version $($f.Version); installed $dateText; starts with Windows $($f.Unattended); ports $($f.Ports); found by $($f.Evidence)")

        if ($f.Recent) {
            Add-Finding 'High' ("{0} was installed on {1}. If you did not install it yourself, or someone asked you to install it over the phone, treat it as a scam." -f $f.Name, $dateText) 'Uninstall it (Settings > Apps > Installed apps), change your important passwords from another device, and call your bank if you shared any card or banking details.'
        }
        if ($f.Unattended -and $f.Type -ne 'Tunnel') {
            Add-Finding 'Medium' ("{0} starts with Windows, so anyone with its ID and password (or the company that manages it) can connect without you clicking Accept." -f $f.Name) "If you don't use unattended access, turn it off in the app's settings or uninstall the app."
        }
        if ($f.Type -eq 'Remote management') {
            Add-Finding 'Medium' ("{0} is a remote-management agent normally installed by an IT company. On a personal PC with no IT support, it should not be there." -f $f.Name) 'If no company manages this PC, uninstall it and check who installed it.'
        }
        if ($f.Type -eq 'Tunnel') {
            Add-Finding 'Medium' ("{0} can expose programs on this PC to the internet." -f $f.Name) 'Remove it if you are not using it for development.'
        }
    }
    if ($found.Count -ge 3) {
        Add-Finding 'Low' ("{0} different remote apps are present. Most people need one at most." -f $found.Count) 'Keep the one you use and uninstall the rest.'
    }
}

# --- Proxy / tunnel / hidden relay ------------------------------------------
Write-Section 'Proxy / tunnel / hidden relay'

$wmiProcs = @()
try { $wmiProcs = @(Get-CimInstance Win32_Process -ErrorAction Stop) } catch { }
$wmiByPid = @{}
foreach ($wp in $wmiProcs) {
    try { $wmiByPid[[int]$wp.ProcessId] = $wp } catch { }
}

$sigCache = @{}
function Get-SignerInfo {
    param([string]$Path)
    if (-not $Path) { return [pscustomobject]@{ Signed = 'Unknown'; Signer = '' } }
    if ($sigCache.ContainsKey($Path)) { return $sigCache[$Path] }
    $r = [pscustomobject]@{ Signed = 'Unknown'; Signer = '' }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($sig.Status -eq 'Valid') {
            $r.Signed = 'Yes'
            if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN="?([^,"]+)') {
                $r.Signer = $Matches[1]
            }
        } elseif ($sig.Status -eq 'NotSigned') {
            $r.Signed = 'No'
        } else {
            $r.Signed = "Bad ($($sig.Status))"
        }
    } catch { }
    $sigCache[$Path] = $r
    return $r
}

function Get-PidPath {
    param([int]$ProcessId)
    if ($ProcessId -eq 4) { return (Join-Path $env:SystemRoot 'System32\ntoskrnl.exe') }
    if ($wmiByPid.ContainsKey($ProcessId) -and $wmiByPid[$ProcessId].ExecutablePath) {
        return [string]$wmiByPid[$ProcessId].ExecutablePath
    }
    $gp = @($procs | Where-Object { $_.Id -eq $ProcessId } | Select-Object -First 1)
    if ($gp -and $gp[0].PSObject.Properties['Path'] -and $gp[0].Path) { return [string]$gp[0].Path }
    return ''
}

# (a) Listening ports and established outbound from unsigned / user-folder programs
if ($SkipNetwork) {
    Write-Line 'Connection scan' 'skipped (-SkipNetwork)' 'DarkGray'
} else {
    $udp = @()
    try { $udp = @(Get-NetUDPEndpoint -ErrorAction Stop) } catch { }
    $estab = @()
    try { $estab = @(Get-NetTCPConnection -State Established -ErrorAction Stop) } catch { }

    $byPid = @{}
    function Get-PidBucket {
        param([int]$ProcessId)
        if (-not $byPid.ContainsKey($ProcessId)) {
            $byPid[$ProcessId] = [pscustomobject]@{
                ProcessId = $ProcessId
                Listen    = New-Object System.Collections.Generic.List[string]
                Remotes   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            }
        }
        return $byPid[$ProcessId]
    }

    foreach ($c in $listen) {
        try { $id = [int]$c.OwningProcess } catch { continue }
        $scope = if (Test-LoopbackAddress $c.LocalAddress) { 'local only' } else { 'network' }
        [void](Get-PidBucket $id).Listen.Add(("TCP {0} ({1})" -f $c.LocalPort, $scope))
    }
    foreach ($u in $udp) {
        try { $id = [int]$u.OwningProcess } catch { continue }
        $scope = if (Test-LoopbackAddress $u.LocalAddress) { 'local only' } else { 'network' }
        [void](Get-PidBucket $id).Listen.Add(("UDP {0} ({1})" -f $u.LocalPort, $scope))
    }
    foreach ($c in $estab) {
        try { $id = [int]$c.OwningProcess } catch { continue }
        $remote = [string]$c.RemoteAddress
        if (Test-LoopbackAddress $remote) { continue }
        [void](Get-PidBucket $id).Remotes.Add($remote)
    }

    $flaggedConns = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($byPid.Keys)) {
        $path = Get-PidPath $id
        if ($id -eq 4) {
            $sig = [pscustomobject]@{ Signed = 'Yes'; Signer = 'Microsoft Windows' }
        } else {
            $sig = Get-SignerInfo $path
        }
        if (-not (Test-SuspiciousNetworkProcess $path $sig.Signed $sig.Signer)) { continue }
        $bucket = $byPid[$id]
        $procName = '?'
        if ($wmiByPid.ContainsKey($id) -and $wmiByPid[$id].Name) {
            $procName = [System.IO.Path]::GetFileNameWithoutExtension([string]$wmiByPid[$id].Name)
        } else {
            $gp = @($procs | Where-Object { $_.Id -eq $id } | Select-Object -First 1)
            if ($gp) { $procName = $gp[0].ProcessName }
        }
        $listenText = (@($bucket.Listen | Sort-Object -Unique) -join ', ')
        $remoteCount = $bucket.Remotes.Count
        $networkListen = @($bucket.Listen | Where-Object { $_ -match '\(network\)' }).Count -gt 0
        $flaggedConns.Add([pscustomobject]@{
            Name = $procName; ProcessId = $id; Path = $path
            Signed = $sig.Signed; Signer = $sig.Signer
            ListenText = $listenText; RemoteCount = $remoteCount
            Remotes = @($bucket.Remotes); NetworkListen = $networkListen
        })
    }

    if ($flaggedConns.Count -eq 0) {
        Write-Line 'Unsigned / user-folder' 'no listening ports or outbound connections from unsigned or user-folder programs' 'Green'
    } else {
        Write-Host '  Programs that are unsigned or running from a user-writable folder:' -ForegroundColor Yellow
        foreach ($fc in $flaggedConns) {
            $who = if ($fc.Signer) { $fc.Signer } else { $fc.Signed }
            Write-Host ("    {0} (PID {1}; {2})" -f $fc.Name, $fc.ProcessId, $who) -ForegroundColor Yellow
            if ($fc.Path) { Write-Host ("      Path: {0}" -f $fc.Path) -ForegroundColor DarkGray }
            if ($fc.ListenText) { Write-Host ("      Listening: {0}" -f $fc.ListenText) }
            Write-Host ("      Outbound: {0} remote address(es)" -f $fc.RemoteCount)
            if ($Detailed -and $fc.RemoteCount -gt 0) {
                Write-Host ("      Remotes: {0}" -f ($fc.Remotes -join ', ')) -ForegroundColor DarkGray
            }
            Add-Row 'Connection' $fc.Name $(if ($fc.NetworkListen) { 'Listening' } else { 'Outbound' }) ("PID $($fc.ProcessId); signed $($fc.Signed) $($fc.Signer); listen $($fc.ListenText); remotes $($fc.RemoteCount); $($fc.Path)")
            if ($fc.NetworkListen) {
                Add-Finding 'High' ("{0} is unsigned or running from a user folder and is listening for network connections." -f $fc.Name) 'If you do not recognize this program, stop it, uninstall it and consider a Microsoft Defender Offline scan (Start-MpWDOScan, which restarts the PC).'
            } elseif ($fc.RemoteCount -gt 0) {
                Add-Finding 'High' ("{0} is unsigned or running from a user folder and has {1} outbound connection(s)." -f $fc.Name, $fc.RemoteCount) 'If you do not recognize this program, stop it and uninstall it. Check what it is talking to if you still have a copy.'
            } else {
                Add-Finding 'Low' ("{0} is unsigned or running from a user folder and is listening only on this PC (loopback)." -f $fc.Name) 'Fine for a local tool you installed; remove it if you do not recognize it.'
            }
        }
    }
}

# (b) Proxy / VPN configuration
$inet = $null
try { $inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop } catch { }
$userProxyOn = $false
$userProxyServer = ''
$pacUrl = ''
if ($inet) {
    if ($inet.PSObject.Properties['ProxyEnable'] -and $inet.ProxyEnable -eq 1) {
        $userProxyOn = $true
        if ($inet.PSObject.Properties['ProxyServer']) { $userProxyServer = [string]$inet.ProxyServer }
    }
    if ($inet.PSObject.Properties['AutoConfigURL'] -and $inet.AutoConfigURL) { $pacUrl = [string]$inet.AutoConfigURL }
}
if ($userProxyOn) {
    $px = if ($userProxyServer) { $userProxyServer } else { 'enabled (no server listed)' }
    Write-Line 'User proxy (WinINET)' $px 'Yellow'
    Add-Row 'Proxy' 'WinINET' 'Enabled' $px
    Add-Finding 'Medium' ("A user proxy is set ({0}). Fine if you set it or your workplace did; unexpected proxies are a common adware trick." -f $px) 'Settings > Network & internet > Proxy. Turn off a manual proxy you do not recognize and clear any unexpected setup script.'
} else {
    Write-Line 'User proxy (WinINET)' 'none' 'Green'
    Add-Row 'Proxy' 'WinINET' 'Off' ''
}
if ($pacUrl) {
    Write-Line 'Proxy setup script' $pacUrl 'Yellow'
    Add-Row 'Proxy' 'AutoConfigURL' 'Set' $pacUrl
    Add-Finding 'Medium' ("A proxy auto-config script is set ({0}). Make sure you recognize it." -f $pacUrl) 'Settings > Network & internet > Proxy > Automatic proxy setup: turn off a script you did not set.'
} else {
    Write-Line 'Proxy setup script' 'none' 'Green'
}

$winhttpRaw = ''
$netshExe = if ($env:SystemRoot) { Join-Path $env:SystemRoot 'System32\netsh.exe' } else { 'netsh.exe' }
try { $winhttpRaw = (& $netshExe winhttp show proxy 2>&1 | Out-String) } catch { }
$winhttp = Parse-WinHttpProxy $winhttpRaw
if ($winhttp.Direct) {
    Write-Line 'System proxy (WinHTTP)' 'direct' 'Green'
    Add-Row 'Proxy' 'WinHTTP' 'Direct' ''
} else {
    $wh = if ($winhttp.Server) { $winhttp.Server } else { 'a system proxy is set' }
    Write-Line 'System proxy (WinHTTP)' $wh 'Yellow'
    Add-Row 'Proxy' 'WinHTTP' 'Set' $wh
    Add-Finding 'Medium' ("A system-wide WinHTTP proxy is set ({0})." -f $wh) 'From an admin prompt: netsh winhttp reset proxy  (only if you do not need a workplace proxy).'
}

$portproxyRaw = ''
try { $portproxyRaw = (& $netshExe interface portproxy show all 2>&1 | Out-String) } catch { }
$portproxy = @(Parse-PortProxyOutput $portproxyRaw)
if ($portproxy.Count -eq 0) {
    Write-Line 'Port proxy rules' 'none' 'Green'
    Add-Row 'Port proxy' 'none' 'None' ''
} else {
    Write-Line 'Port proxy rules' ("{0} rule(s)  (these forward a local port to another address)" -f $portproxy.Count) 'Yellow'
    foreach ($pr in $portproxy) {
        $pt = "{0}:{1} -> {2}:{3}" -f $pr.ListenAddress, $pr.ListenPort, $pr.ConnectAddress, $pr.ConnectPort
        Write-Host ("      {0}" -f $pt) -ForegroundColor Yellow
        Add-Row 'Port proxy' "$($pr.ListenAddress):$($pr.ListenPort)" 'Forward' $pt
        Add-Finding 'High' ("A port-proxy rule forwards {0}." -f $pt) 'If you did not set this, remove it from an admin prompt: netsh interface portproxy reset  (or delete the one rule with netsh interface portproxy delete).'
    }
}

$vpnConns = @()
try { $vpnConns += @(Get-VpnConnection -ErrorAction Stop) } catch { }
try { $vpnConns += @(Get-VpnConnection -AllUserConnection -ErrorAction Stop) } catch { }
$vpnSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$vpnUniq = New-Object System.Collections.Generic.List[object]
foreach ($v in $vpnConns) {
    $vn = [string]$v.Name
    if ($vn -and $vpnSeen.Add($vn)) { $vpnUniq.Add($v) }
}
if ($vpnUniq.Count -eq 0) {
    Write-Line 'VPN connections' 'none'
    Add-Row 'VPN' 'none' 'None' ''
} else {
    $vNames = @($vpnUniq | ForEach-Object {
        $st = if ($_.PSObject.Properties['ConnectionStatus']) { [string]$_.ConnectionStatus } else { '' }
        $tt = if ($_.PSObject.Properties['TunnelType']) { [string]$_.TunnelType } else { '' }
        $bits = @($_.Name)
        if ($tt) { $bits += $tt }
        if ($st) { $bits += $st }
        $bits -join ', '
    })
    Write-Line 'VPN connections' ("{0}: {1}" -f $vpnUniq.Count, ($vNames -join '; '))
    foreach ($v in $vpnUniq) {
        $detail = @()
        if ($v.PSObject.Properties['TunnelType']) { $detail += [string]$v.TunnelType }
        if ($v.PSObject.Properties['ConnectionStatus']) { $detail += [string]$v.ConnectionStatus }
        Add-Row 'VPN' $v.Name $(if ($v.PSObject.Properties['ConnectionStatus']) { [string]$v.ConnectionStatus } else { 'Present' }) ($detail -join '; ')
    }
}

$installedNames = @($installed | ForEach-Object { [string]$_.DisplayName })
$adapterHint = $installedNames + @($services | ForEach-Object { @($_.Name, $_.DisplayName) }) + @($vpnUniq | ForEach-Object { [string]$_.Name })
$adapters = @()
try { $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) } catch {
    try { $adapters = @(Get-NetAdapter -ErrorAction Stop) } catch { }
}
$tunnelAdapters = @()
$unexpectedAdapters = @()
foreach ($ad in $adapters) {
    $desc = if ($ad.PSObject.Properties['InterfaceDescription']) { [string]$ad.InterfaceDescription } else { '' }
    $nm = if ($ad.PSObject.Properties['Name']) { [string]$ad.Name } else { '' }
    if (-not (Test-TunnelAdapterName $desc $nm)) { continue }
    $products = @(Get-MatchingVpnProduct $desc $nm $adapterHint)
    $status = if ($ad.PSObject.Properties['Status']) { [string]$ad.Status } else { '' }
    $item = [pscustomobject]@{ Name = $nm; Description = $desc; Status = $status; Products = $products }
    $tunnelAdapters += $item
    if ($products.Count -eq 0) { $unexpectedAdapters += $item }
}
if ($tunnelAdapters.Count -eq 0) {
    Write-Line 'Tunnel adapters' 'none beyond Windows built-ins' 'Green'
    Add-Row 'Adapter' 'none' 'None' ''
} else {
    foreach ($ta in $tunnelAdapters) {
        $prodText = if ($ta.Products.Count) { 'matches ' + ($ta.Products -join ', ') } else { 'no matching VPN app found' }
        $color = if ($ta.Products.Count) { 'Gray' } else { 'Yellow' }
        Write-Line 'Tunnel adapter' ("{0} ({1}; {2}; {3})" -f $ta.Name, $ta.Description, $ta.Status, $prodText) $color
        Add-Row 'Adapter' $ta.Name $(if ($ta.Products.Count) { 'Known VPN' } else { 'Unexpected' }) ("$($ta.Description); $($ta.Status); $prodText")
    }
    foreach ($ua in $unexpectedAdapters) {
        Add-Finding 'Medium' ("Tunnel adapter '{0}' ({1}) does not match a known installed VPN app." -f $ua.Name, $ua.Description) 'If you did not install a VPN or tunnel tool, disable the adapter in Settings > Network & internet > Advanced network settings and run a Defender Offline scan.'
    }
}

# (c) Known tunnel / proxyware tools, plus reverse SSH / plink in tasks
$tasks = @()
try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) } catch { }
$taskCommands = @()
foreach ($tk in $tasks) {
    $acts = @()
    try { $acts = @($tk.Actions) } catch { }
    $cmd = @($acts | ForEach-Object {
        $ex = if ($_.PSObject.Properties['Execute']) { [string]$_.Execute } else { '' }
        $ag = if ($_.PSObject.Properties['Arguments']) { [string]$_.Arguments } else { '' }
        ($ex + ' ' + $ag).Trim()
    }) -join ' | '
    $tname = ''
    if ($tk.PSObject.Properties['TaskPath'] -and $tk.PSObject.Properties['TaskName']) {
        $tname = ([string]$tk.TaskPath).TrimEnd('\') + '\' + [string]$tk.TaskName
    } elseif ($tk.PSObject.Properties['TaskName']) { $tname = [string]$tk.TaskName }
    $taskCommands += [pscustomobject]@{ Name = $tname; Command = $cmd }
}

$fileHits = New-Object System.Collections.Generic.List[object]
$searchRoots = New-Object System.Collections.Generic.List[string]
foreach ($root in @(
    ${env:ProgramFiles},
    ${env:ProgramFiles(x86)},
    $env:ProgramData,
    $env:LOCALAPPDATA,
    $env:APPDATA,
    $(if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Downloads' } else { $null }),
    $(if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Desktop' } else { $null }),
    $(if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Documents' } else { $null }),
    $env:TEMP,
    $(if ($env:SystemRoot) { Join-Path $env:SystemRoot 'Temp' } else { $null })
)) {
    if ($root -and (Test-Path -LiteralPath $root)) { $searchRoots.Add($root) }
}
foreach ($root in $searchRoots) {
    foreach ($exe in $script:relayExeNames) {
        try {
            Get-ChildItem -LiteralPath $root -Filter $exe -File -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                ForEach-Object { $fileHits.Add($_) }
        } catch { }
    }
}

$relayHits = New-Object 'System.Collections.Generic.Dictionary[string,object]'
function Add-RelayEvidence {
    param([string]$Name, [string]$Kind, [string]$Evidence, [string]$Detail)
    if (-not $relayHits.ContainsKey($Name)) {
        $relayHits[$Name] = [pscustomobject]@{
            Name = $Name; Kind = $Kind
            Evidence = New-Object System.Collections.Generic.List[string]
            AutoStart = $false; Running = $false; Detail = New-Object System.Collections.Generic.List[string]
        }
    }
    $item = $relayHits[$Name]
    if ($Evidence -and -not $item.Evidence.Contains($Evidence)) { $item.Evidence.Add($Evidence) }
    if ($Detail) { $item.Detail.Add($Detail) }
}

foreach ($tool in $script:relayCatalog) {
    $rx = $tool.Rx
    $prog = @($installed | Where-Object { $_.DisplayName -match $rx })
    $svc  = @($services  | Where-Object { $_.Name -match $rx -or $_.DisplayName -match $rx -or ($_.PathName -and $_.PathName -match $rx) })
    $proc = @($procs     | Where-Object { $_.ProcessName -match $rx -or ($_.PSObject.Properties['Path'] -and $_.Path -and $_.Path -match $rx) })
    $run  = @($startup   | Where-Object { $_.Name -match $rx -or $_.Command -match $rx })
    $tsk  = @($taskCommands | Where-Object { $_.Name -match $rx -or $_.Command -match $rx })
    $files = @($fileHits | Where-Object { $_.Name -match $rx -or $_.FullName -match $rx })
    if (($prog.Count + $svc.Count + $proc.Count + $run.Count + $tsk.Count + $files.Count) -eq 0) { continue }

    if ($prog.Count) { Add-RelayEvidence $tool.N $tool.Kind 'installed' ((@($prog | ForEach-Object { $_.DisplayName }) | Select-Object -Unique) -join ', ') }
    if ($svc.Count)  {
        Add-RelayEvidence $tool.N $tool.Kind 'service' ((@($svc | ForEach-Object { $_.Name }) -join ', '))
        if (@($svc | Where-Object { $_.StartMode -eq 'Auto' }).Count) { $relayHits[$tool.N].AutoStart = $true }
        if (@($svc | Where-Object { $_.State -eq 'Running' }).Count) { $relayHits[$tool.N].Running = $true }
    }
    if ($proc.Count) {
        Add-RelayEvidence $tool.N $tool.Kind 'running process' ((@($proc | ForEach-Object { $_.ProcessName }) | Select-Object -Unique) -join ', ')
        $relayHits[$tool.N].Running = $true
    }
    if ($run.Count)  {
        Add-RelayEvidence $tool.N $tool.Kind 'startup entry' ((@($run | ForEach-Object { $_.Name }) -join ', '))
        $relayHits[$tool.N].AutoStart = $true
    }
    if ($tsk.Count)  {
        Add-RelayEvidence $tool.N $tool.Kind 'scheduled task' ((@($tsk | ForEach-Object { $_.Name }) -join ', '))
        $relayHits[$tool.N].AutoStart = $true
    }
    if ($files.Count) {
        Add-RelayEvidence $tool.N $tool.Kind 'file' ((@($files | ForEach-Object { $_.FullName }) | Select-Object -Unique) -join ', ')
    }
}

# Reverse SSH / plink in tasks, startup, or a running command line
$revHits = New-Object System.Collections.Generic.List[object]
foreach ($s in $startup) {
    if (Test-ReverseTunnelCommand $s.Command) {
        $revHits.Add([pscustomobject]@{ Where = 'startup entry'; Name = $s.Name; Command = $s.Command })
    }
}
foreach ($t in $taskCommands) {
    if (Test-ReverseTunnelCommand $t.Command) {
        $revHits.Add([pscustomobject]@{ Where = 'scheduled task'; Name = $t.Name; Command = $t.Command })
    }
}
foreach ($wp in $wmiProcs) {
    $cl = if ($wp.PSObject.Properties['CommandLine'] -and $wp.CommandLine) { [string]$wp.CommandLine } else { '' }
    if (Test-ReverseTunnelCommand $cl) {
        $revHits.Add([pscustomobject]@{ Where = 'running process'; Name = [string]$wp.Name; Command = $cl })
    }
}

if ($relayHits.Count -eq 0 -and $revHits.Count -eq 0) {
    Write-Line 'Tunnel / proxyware tools' 'none of the known tools were found' 'Green'
} else {
    foreach ($name in @($relayHits.Keys | Sort-Object)) {
        $h = $relayHits[$name]
        $ev = ($h.Evidence -join '; ')
        $auto = if ($h.AutoStart) { 'yes' } else { 'no' }
        $runText = if ($h.Running) { 'running' } else { 'not running' }
        $color = if ($h.Kind -eq 'Proxyware' -or $h.AutoStart -or $h.Running) { 'Yellow' } else { 'Gray' }
        Write-Line $h.Name ("{0}; auto-start {1}; {2}; found by {3}" -f $h.Kind, $auto, $runText, $ev) $color
        if ($Detailed -and $h.Detail.Count) {
            Write-Host ("      {0}" -f ($h.Detail -join ' | ')) -ForegroundColor DarkGray
        }
        Add-Row $h.Kind $h.Name $(if ($h.Running) { 'Running' } else { 'Present' }) ("auto-start $auto; $ev")
        if ($h.Kind -eq 'Proxyware') {
            Add-Finding 'High' ("{0} is a bandwidth-sharing (residential proxy) app. It can sell access to this PC's internet connection." -f $h.Name) 'If you did not install it on purpose, uninstall it (Settings > Apps), then change important passwords from another device.'
        } elseif ($h.AutoStart -or $h.Running) {
            Add-Finding 'High' ("{0} is installed and starts with Windows or is running now. It can expose programs on this PC to the internet." -f $h.Name) 'If you are not using it, uninstall it and check startup entries and scheduled tasks for leftovers.'
        } else {
            Add-Finding 'Medium' ("{0} is present. It can expose programs on this PC to the internet." -f $h.Name) 'Remove it if you are not using it on purpose (for example a developer tunnel you started yourself).'
        }
    }
    foreach ($rh in $revHits) {
        Write-Line 'Reverse SSH / plink' ("{0}: {1}" -f $rh.Where, $rh.Name) 'Yellow'
        if ($Detailed) { Write-Host ("      {0}" -f $rh.Command) -ForegroundColor DarkGray }
        Add-Row 'Tunnel' 'Reverse SSH / plink' 'Present' ("$($rh.Where): $($rh.Name)")
        Add-Finding 'High' ("A {0} ({1}) looks like a reverse SSH or plink tunnel, which can expose this PC to someone else." -f $rh.Where, $rh.Name) 'If you did not set this up, delete the task or startup entry, stop the process, and run a Microsoft Defender Offline scan.'
    }
}

# (d) Inbound firewall allow rules for user-writable programs, and recent any-program rules
$recentFw = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
try {
    $since = (Get-Date).AddDays(-1 * $RecentDays)
    $fwEvents = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
        Id = 2004
        StartTime = $since
    } -ErrorAction Stop)
    foreach ($ev in $fwEvents) {
        foreach ($prop in @($ev.Properties)) {
            $val = [string]$prop.Value
            if ($val) { [void]$recentFw.Add($val) }
        }
        if ($ev.PSObject.Properties['Message'] -and $ev.Message) {
            if ($ev.Message -match '(?i)Rule Name:\s*(.+)$') { [void]$recentFw.Add($Matches[1].Trim()) }
        }
    }
} catch { }

$fwFlagged = New-Object System.Collections.Generic.List[object]
try {
    $fwRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
    foreach ($rule in $fwRules) {
        $app = $null
        try { $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop | Select-Object -First 1 } catch { }
        $prog = 'Any'
        if ($app -and $app.PSObject.Properties['Program'] -and $app.Program) {
            $prog = [Environment]::ExpandEnvironmentVariables([string]$app.Program)
        }
        $group = if ($rule.PSObject.Properties['Group']) { [string]$rule.Group } else { '' }
        $disp  = if ($rule.PSObject.Properties['DisplayName'] -and $rule.DisplayName) { [string]$rule.DisplayName } else { [string]$rule.Name }
        $isRecent = $false
        foreach ($key in @($rule.Name, $disp, $(if ($rule.PSObject.Properties['InstanceID']) { [string]$rule.InstanceID } else { $null }))) {
            if ($key -and $recentFw.Contains($key)) { $isRecent = $true }
        }
        if ($rule.PSObject.Properties['CreationTime'] -and $rule.CreationTime) {
            try {
                if ([datetime]$rule.CreationTime -gt (Get-Date).AddDays(-1 * $RecentDays)) { $isRecent = $true }
            } catch { }
        }
        $any = Test-AnyProgramPath $prog
        $userProg = (-not $any) -and (Test-UserWritablePath $prog)
        $builtin = Test-BuiltinFirewallGroup $group
        if ($userProg) {
            $fwFlagged.Add([pscustomobject]@{ Name = $disp; Why = 'program in a user-writable folder'; Program = $prog; Recent = $isRecent })
        } elseif ($any -and ((-not $builtin) -or $isRecent)) {
            $why = if (-not $builtin) { 'custom any-program allow rule' } else { "built-in any-program rule added in the last $RecentDays days" }
            $fwFlagged.Add([pscustomobject]@{ Name = $disp; Why = $why; Program = 'Any'; Recent = $isRecent })
        }
    }
} catch {
    Write-Line 'Firewall rules' 'could not read inbound allow rules' 'DarkGray'
}

if ($fwFlagged.Count -eq 0) {
    Write-Line 'Firewall (inbound)' 'no user-folder program rules or unexpected any-program allow rules' 'Green'
} else {
    Write-Line 'Firewall (inbound)' ("{0} rule(s) to review" -f $fwFlagged.Count) 'Yellow'
    foreach ($fr in $fwFlagged) {
        Write-Host ("      {0}: {1}" -f $fr.Name, $fr.Why) -ForegroundColor Yellow
        if ($Detailed -and $fr.Program -and $fr.Program -ne 'Any') {
            Write-Host ("        Program: {0}" -f $fr.Program) -ForegroundColor DarkGray
        }
        Add-Row 'Firewall' $fr.Name 'Allow' $fr.Why
        $lvl = if ($fr.Why -match 'any-program' -and $fr.Why -match 'custom') { 'High' } else { 'Medium' }
        Add-Finding $lvl ("Firewall allows inbound connections: {0} ({1})." -f $fr.Name, $fr.Why) 'Windows Security > Firewall & network protection > Advanced settings > Inbound rules: disable or delete any rule you did not create.'
    }
}

# --- Export ------------------------------------------------------------------
if ($CsvPath) {
    try {
        $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host ''
        Write-Host "Saved $($rows.Count) rows to $CsvPath" -ForegroundColor DarkGray
    } catch { Write-Host "  [!] Could not write CSV: $($_.Exception.Message)" -ForegroundColor Red }
}

# --- Findings ----------------------------------------------------------------
Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  No remote access is switched on, and no unexpected remote apps, proxies or tunnel tools were found.' -ForegroundColor Green
} else {
    $order = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
    $i = 0
    foreach ($f in ($findings | Sort-Object { $order[$_.Level] })) {
        $i++
        $color = switch ($f.Level) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  {0}. [{1}] {2}" -f $i, $f.Level, $f.Text) -ForegroundColor $color
        Write-Host ("     Fix: {0}" -f $f.Fix) -ForegroundColor DarkGray
    }
}
Write-Host ''
Write-Host ''
Write-Host 'A script cannot promise to catch malware that hides from Windows. For a deeper check, run a Microsoft Defender Offline scan from an admin PowerShell window (this restarts the PC; this script does not start it):' -ForegroundColor DarkGray
Write-Host '  Start-MpWDOScan' -ForegroundColor Gray
Write-Host ''
Write-Host 'Nothing was changed. Fixes above are suggestions only.' -ForegroundColor DarkGray
