<#
.SYNOPSIS
    Get-ListeningPorts.ps1 - Read-only audit of what on this PC is listening for
    network connections, who could reach it, and whether the firewall lets it in.

.DESCRIPTION
    Answers "what is this PC exposing to my network?". It lists every program
    listening on a TCP port (and UDP with -IncludeUdp) and, for each one, shows:
      - Port, protocol and address it listens on
      - Reach: "This PC only" (loopback), "All networks" (0.0.0.0 / ::) or one address
      - Process name, PID, file path and the Windows services hosted in it
      - Whether the file is signed, and by whom
      - Whether an enabled inbound firewall rule allows it (by program or port)
    It also lists your network connections and their profile (Public / Private /
    Domain), the folders you share over SMB, and ends with plain-English findings:
    risky ports open to the network (Telnet, FTP, SMB, RDP, VNC, WinRM...),
    unsigned or user-folder programs listening on all networks, and shares or
    listeners exposed while on a Public network.

    Safety level : SAFE (strictly read-only). Nothing is changed, stopped or
                   blocked. No network calls: it only reads Windows' own tables
                   (Get-NetTCPConnection, Get-NetUDPEndpoint, firewall rules,
                   SMB shares). The only file written is the optional -CsvPath.

    Admin        : Not required. Run as admin to see the paths and signatures
                   of SYSTEM processes and services.

.PARAMETER All
    Also show listeners that only accept connections from this PC (loopback).
    These can't be reached from the network, so they're hidden by default.

.PARAMETER IncludeUdp
    Also list UDP endpoints. UDP has no "listening" state, so this list is
    longer and noisier (DNS, mDNS, SSDP and similar are normal).

.PARAMETER SkipFirewall
    Don't match listeners to inbound firewall rules. Faster on PCs with
    hundreds of rules.

.PARAMETER CsvPath
    Export the full listener list to a CSV file.

.EXAMPLE
    .\Get-ListeningPorts.ps1

.EXAMPLE
    .\Get-ListeningPorts.ps1 -All -IncludeUdp -CsvPath "$env:USERPROFILE\Desktop\ports.csv"

.NOTES
    To close something this flags: uninstall or reconfigure the app, stop and
    disable its service in services.msc, or remove its inbound rule in
    "Windows Defender Firewall with Advanced Security". This script does none
    of that for you.
#>
[CmdletBinding()]
param(
    [switch]$All,
    [switch]$IncludeUdp,
    [switch]$SkipFirewall,
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

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# Ports worth a second look when reachable from the network
$riskyPorts = @{
    20 = 'FTP data'; 21 = 'FTP'; 23 = 'Telnet'; 69 = 'TFTP'; 135 = 'RPC endpoint mapper'
    137 = 'NetBIOS name'; 138 = 'NetBIOS datagram'; 139 = 'NetBIOS session'; 445 = 'SMB file sharing'
    1433 = 'SQL Server'; 1900 = 'SSDP/UPnP'; 3306 = 'MySQL'; 3389 = 'Remote Desktop'
    5432 = 'PostgreSQL'; 5800 = 'VNC (web)'; 5900 = 'VNC'; 5985 = 'WinRM (HTTP)'
    5986 = 'WinRM (HTTPS)'; 6379 = 'Redis'; 8080 = 'HTTP proxy/alt web'; 27017 = 'MongoDB'
}

function Get-Reach([string]$Address) {
    if ($Address -in '127.0.0.1', '::1' -or $Address -like '127.*') { return 'This PC only' }
    if ($Address -in '0.0.0.0', '::') { return 'All networks' }
    return "Only $Address"
}

# --- Gather processes and services once ----------------------------------------
$procs = @{}
foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
    $procs[[int]$p.ProcessId] = $p
}
$svcByPid = @{}
foreach ($s in Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue) {
    $k = [int]$s.ProcessId
    if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = New-Object System.Collections.Generic.List[string] }
    $svcByPid[$k].Add($s.Name)
}
$sigCache = @{}
function Get-SignerInfo([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ Signed = 'Unknown'; Signer = '' } }
    if ($sigCache.ContainsKey($Path)) { return $sigCache[$Path] }
    $r = [pscustomobject]@{ Signed = 'Unknown'; Signer = '' }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -eq 'Valid') {
            $r.Signed = 'Yes'
            if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN="?([^,"]+)') { $r.Signer = $Matches[1] }
        } elseif ($sig.Status -eq 'NotSigned') { $r.Signed = 'No' }
        else { $r.Signed = "Bad ($($sig.Status))" }
    } catch { }
    $sigCache[$Path] = $r
    return $r
}

# --- Firewall: enabled inbound allow rules -------------------------------------
$fwPrograms = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$fwPorts    = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$fwAnyRule  = $false
$fwChecked  = $false
if (-not $SkipFirewall) {
    Write-Host 'Reading inbound firewall rules (can take a few seconds)...' -ForegroundColor DarkGray
    try {
        $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
        if ($rules.Count) {
            $apps  = @($rules | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)
            $ports = @($rules | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
            for ($i = 0; $i -lt $rules.Count; $i++) {
                $prog = if ($i -lt $apps.Count) { [Environment]::ExpandEnvironmentVariables([string]$apps[$i].Program) } else { 'Any' }
                $pf   = if ($i -lt $ports.Count) { $ports[$i] } else { $null }
                $lp   = if ($pf) { @($pf.LocalPort) } else { @('Any') }
                $proto = if ($pf) { [string]$pf.Protocol } else { 'Any' }
                if ($prog -and $prog -ne 'Any') { [void]$fwPrograms.Add($prog) }
                elseif ($lp -contains 'Any') { if ($proto -eq 'Any') { $fwAnyRule = $true } }
                else { foreach ($x in $lp) { [void]$fwPorts.Add("$proto/$x") } }
            }
        }
        $fwChecked = $true
    } catch {
        Write-Host "  Couldn't read firewall rules: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Test-FirewallAllows([string]$Proto, [int]$Port, [string]$Path) {
    if (-not $fwChecked) { return 'Not checked' }
    if ($Path -and $fwPrograms.Contains($Path)) { return 'Allowed (program rule)' }
    if ($fwPorts.Contains("$Proto/$Port") -or $fwPorts.Contains("Any/$Port")) { return 'Allowed (port rule)' }
    foreach ($entry in $fwPorts) {
        $parts = $entry.Split('/')
        if (($parts[0] -eq $Proto -or $parts[0] -eq 'Any') -and $parts[1] -match '^(\d+)-(\d+)$') {
            if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return 'Allowed (port rule)' }
        }
    }
    if ($fwAnyRule) { return 'Maybe (broad rule)' }
    return 'No rule'
}

# --- Build the listener list ----------------------------------------------------
$endpoints = New-Object System.Collections.Generic.List[object]
foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
    $endpoints.Add([pscustomobject]@{ Proto = 'TCP'; Addr = $c.LocalAddress; Port = [int]$c.LocalPort; ProcId = [int]$c.OwningProcess })
}
if ($IncludeUdp) {
    foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $endpoints.Add([pscustomobject]@{ Proto = 'UDP'; Addr = $u.LocalAddress; Port = [int]$u.LocalPort; ProcId = [int]$u.OwningProcess })
    }
}

$userDirPattern = '\\(AppData|Temp|Downloads|Users\\Public)\\'
$rows = foreach ($e in $endpoints) {
    $reach = Get-Reach $e.Addr
    $p = $procs[$e.ProcId]
    $name = if ($e.ProcId -eq 4) { 'System (kernel)' } elseif ($p) { $p.Name } else { '?' }
    $path = if ($p) { [string]$p.ExecutablePath } else { '' }
    $svcs = if ($svcByPid.ContainsKey($e.ProcId)) { ($svcByPid[$e.ProcId] | Sort-Object -Unique) -join ', ' } else { '' }
    $sig  = if ($e.ProcId -eq 4) { [pscustomobject]@{ Signed = 'Yes'; Signer = 'Microsoft Windows' } } else { Get-SignerInfo $path }
    $fw   = if ($reach -eq 'This PC only') { 'n/a' } else { Test-FirewallAllows $e.Proto $e.Port $path }
    [pscustomobject]@{
        Proto    = $e.Proto
        Port     = $e.Port
        Address  = $e.Addr
        Reach    = $reach
        Process  = $name
        PID      = $e.ProcId
        Services = $svcs
        Signed   = $sig.Signed
        Signer   = $sig.Signer
        Firewall = $fw
        Known    = if ($riskyPorts.ContainsKey($e.Port)) { $riskyPorts[$e.Port] } else { '' }
        UserDir  = [bool]($path -match $userDirPattern)
        Path     = $path
    }
}
# Collapse IPv4/IPv6 duplicates of the same listener
$rows = @($rows | Sort-Object Proto, Port, Process, Reach -Unique | Sort-Object Proto, Port)
$shown = if ($All) { $rows } else { @($rows | Where-Object Reach -ne 'This PC only') }

# --- Network profiles ------------------------------------------------------------
Write-Header 'Network connections'
$profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
$onPublic = $false
if ($profiles.Count) {
    foreach ($np in $profiles) {
        $color = if ($np.NetworkCategory -eq 'Public') { 'Yellow' } else { 'Gray' }
        if ($np.NetworkCategory -eq 'Public') { $onPublic = $true }
        Write-Host ("  {0,-28} {1,-10} {2}" -f $np.InterfaceAlias, $np.NetworkCategory, $np.Name) -ForegroundColor $color
    }
} else { Write-Host '  No active network connections.' -ForegroundColor DarkGray }

# --- Listeners -----------------------------------------------------------------
$title = if ($All) { 'Listening ports (all)' } else { 'Listening ports reachable from the network' }
Write-Header "$title - $($shown.Count) of $($rows.Count)"
if ($shown.Count) {
    $shown | Format-Table Proto, Port, Reach, Process, PID, Signed, Firewall, Known, Services -AutoSize -Wrap | Out-Host
} else {
    Write-Host '  Nothing is listening on the network.' -ForegroundColor Green
}
if (-not $All) {
    $hidden = $rows.Count - $shown.Count
    if ($hidden -gt 0) { Write-Host "  $hidden more listen only on this PC (loopback). Use -All to see them." -ForegroundColor DarkGray }
}

# --- SMB shares ----------------------------------------------------------------
Write-Header 'Shared folders (SMB)'
$shares = @()
try {
    $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special -and $_.Name -notmatch '\$$' })
    if ($shares.Count) {
        $shares | Format-Table Name, Path, Description -AutoSize | Out-Host
    } else { Write-Host '  No shared folders (only the built-in admin shares).' -ForegroundColor Green }
} catch { Write-Host "  Couldn't read shares: $($_.Exception.Message)" -ForegroundColor DarkGray }

# --- Findings ------------------------------------------------------------------
Write-Header 'Findings'
$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Level, [string]$Text) { $findings.Add([pscustomobject]@{ Level = $Level; Text = $Text }) }

$net = @($rows | Where-Object Reach -ne 'This PC only')
foreach ($r in ($net | Where-Object Known | Sort-Object Port -Unique)) {
    $lvl = if ($r.Port -in 21, 23, 69, 5800, 5900, 6379, 27017) { 'WARN' } else { 'INFO' }
    if ($r.Firewall -like 'Allowed*' -and $r.Port -in 3389, 5985, 5986, 1433, 3306, 5432) { $lvl = 'WARN' }
    Add-Finding $lvl ("{0} {1} ({2}) is listening ({3}); firewall: {4}. Turn it off if you don't use it." -f $r.Proto, $r.Port, $r.Known, $r.Process, $r.Firewall)
}
foreach ($r in ($net | Where-Object { $_.Signed -eq 'No' -or $_.Signed -like 'Bad*' })) {
    Add-Finding 'WARN' ("{0} (PID {1}) is unsigned and listens on {2} port {3}: {4}" -f $r.Process, $r.PID, $r.Proto, $r.Port, $r.Path)
}
foreach ($r in ($net | Where-Object UserDir)) {
    Add-Finding 'WARN' ("{0} runs from a user folder and listens on {1} port {2}. Make sure you installed it: {3}" -f $r.Process, $r.Proto, $r.Port, $r.Path)
}
if ($onPublic -and $shares.Count) {
    Add-Finding 'WARN' "You're on a Public network and sharing $($shares.Count) folder(s). Switch the network to Private if it's your home network, or stop sharing on untrusted Wi-Fi."
}
if ($onPublic -and @($net | Where-Object { $_.Firewall -like 'Allowed*' }).Count) {
    Add-Finding 'INFO' 'Some listeners have inbound allow rules. Check that those rules are limited to Private/Domain profiles if you use public Wi-Fi.'
}
if (-not $isAdmin -and @($rows | Where-Object Signed -eq 'Unknown').Count) {
    Add-Finding 'INFO' 'Some processes could not be inspected without admin. Run as admin for full paths and signatures.'
}

if ($findings.Count) {
    foreach ($f in $findings) {
        $color = if ($f.Level -eq 'WARN') { 'Yellow' } else { 'Gray' }
        Write-Host ("  [{0}] {1}" -f $f.Level, $f.Text) -ForegroundColor $color
    }
} else {
    Write-Host '  Nothing stands out. Only expected programs are listening.' -ForegroundColor Green
}

if ($CsvPath) {
    try {
        $rows | Select-Object Proto, Port, Address, Reach, Process, PID, Services, Signed, Signer, Firewall, Known, Path |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host "Saved $($rows.Count) rows to $CsvPath" -ForegroundColor Cyan
    } catch { Write-Host "Couldn't write CSV: $($_.Exception.Message)" -ForegroundColor Red }
}
Write-Host ''
Write-Host 'Read-only: nothing was changed.' -ForegroundColor DarkGray
