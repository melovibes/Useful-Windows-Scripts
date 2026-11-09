<#
.SYNOPSIS
    Get-ActiveConnections.ps1 - Read-only snapshot of which programs on this PC
    have network connections right now, and whether they're talking to your LAN
    or the internet.

.DESCRIPTION
    Answers "what is this PC talking to?" It is the outbound companion to
    Get-ListeningPorts.ps1 (which shows what is exposed inbound).

    Reports:
      Networks      Active connections and their profile (Public / Private / Domain)
      Summary       How many TCP connections, how many programs, and how many
                    remotes are this PC, your LAN or the internet
      By program    Each app with connection counts, signature and path
                    (processes with the same name are added together; use
                    -PerProcess to split them)
      Destinations  Where each program is connected, grouped by remote address
                    and port. Loopback is hidden unless you pass -All
      Findings      Unsigned or user-folder programs reaching the internet,
                    names that look like Windows components but aren't signed
                    by Microsoft, and unusually busy programs

    Safety level : SAFE (strictly read-only). Nothing is changed, stopped or
                   blocked. No network calls unless you pass -Resolve, which
                   looks up remote hostnames through your configured DNS
                   servers. The only file written is the optional -CsvPath.

    Admin        : Not required. Run as admin to see the paths and signatures
                   of SYSTEM processes and services.

.PARAMETER All
    Also show loopback connections (this PC talking to itself). Hidden by default.

.PARAMETER IncludeOther
    Also include TCP states other than Established (for example SynSent or
    TimeWait). Listening sockets are left out; use Get-ListeningPorts.ps1
    for those.

.PARAMETER Resolve
    Look up a hostname for each remote address (queries your DNS servers).
    Off by default so the script makes no network calls.

.PARAMETER PerProcess
    Show each process separately (with its process ID) instead of adding up
    processes that share a name.

.PARAMETER Top
    How many destination rows to show (default 40). The program summary
    always lists every app. The CSV, if requested, always has every connection.

.PARAMETER CsvPath
    Export every connection (ungrouped) to this CSV file.

.EXAMPLE
    .\Get-ActiveConnections.ps1

.EXAMPLE
    .\Get-ActiveConnections.ps1 -PerProcess

.EXAMPLE
    .\Get-ActiveConnections.ps1 -Resolve -CsvPath "$env:USERPROFILE\Desktop\connections.csv"

.NOTES
    Usage:
      powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Get-ActiveConnections.ps1"
      powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Get-ActiveConnections.ps1" -PerProcess
      powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Get-ActiveConnections.ps1" -Resolve -CsvPath "$env:USERPROFILE\Desktop\connections.csv"
    This is a snapshot of connections at one moment, not a bandwidth measurement.
    For inbound listeners see Get-ListeningPorts.ps1; for latency and Wi-Fi see
    Test-HomeNetwork.ps1.
    Works on Windows 10 and 11, Windows PowerShell 5.1 or PowerShell 7.
#>
[CmdletBinding()]
param(
    [switch]$All,
    [switch]$IncludeOther,
    [switch]$Resolve,
    [switch]$PerProcess,
    [ValidateRange(1, 1000)]
    [int]$Top = 40,
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

$userDirPattern = '\\(AppData|Temp|Downloads|Users\\Public)\\'

# Programs that routinely open many connections; high counts here are normal.
$busyOk = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
@(
    'chrome', 'msedge', 'msedgewebview2', 'firefox', 'brave', 'opera', 'vivaldi',
    'chromium', 'iexplore', 'waterfox', 'slack', 'teams', 'ms-teams', 'discord',
    'spotify', 'onedrive', 'dropbox', 'googledrivefs', 'steam', 'steamwebhelper',
    'epicgameslauncher', 'outlook', 'olk', 'skype', 'zoom', 'svchost',
    'searchapp', 'searchhost', 'runtimebroker', 'system', 'thunderbird'
) | ForEach-Object { [void]$busyOk.Add($_) }

function Get-RemoteScope([string]$Address) {
    if ([string]::IsNullOrWhiteSpace($Address)) { return 'Unknown' }
    if ($Address -match '^::ffff:(\d+\.\d+\.\d+\.\d+)$') { $Address = $Matches[1] }
    if ($Address -eq '::1' -or $Address -like '127.*') { return 'This PC' }

    if ($Address -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') {
        $a = [int]$Matches[1]
        $b = [int]$Matches[2]
        if ($a -eq 127) { return 'This PC' }
        if ($a -eq 10) { return 'LAN' }
        if ($a -eq 192 -and $b -eq 168) { return 'LAN' }
        if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return 'LAN' }
        if ($a -eq 169 -and $b -eq 254) { return 'Link-local' }
        if ($a -ge 224) { return 'Multicast' }
        return 'Internet'
    }

    $lower = $Address.ToLowerInvariant()
    if ($lower -like 'fe80:*') { return 'Link-local' }
    if ($lower -match '^(fc|fd)[0-9a-f]{0,2}:') { return 'LAN' }
    if ($lower -like 'fec0:*') { return 'LAN' }
    if ($lower.StartsWith('ff')) { return 'Multicast' }
    return 'Internet'
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

$dnsCache = @{}
function Get-RemoteName([string]$Address) {
    if (-not $Resolve) { return '' }
    $scope = Get-RemoteScope $Address
    if ($scope -in 'This PC', 'Multicast', 'Unknown') { return '' }
    if ($dnsCache.ContainsKey($Address)) { return $dnsCache[$Address] }
    $name = ''
    try {
        $ar = [System.Net.Dns]::BeginGetHostEntry($Address, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(1500)) {
            $entry = [System.Net.Dns]::EndGetHostEntry($ar)
            if ($entry.HostName -and $entry.HostName -ne $Address) { $name = $entry.HostName }
        }
    } catch { }
    $dnsCache[$Address] = $name
    return $name
}

# --- Collect TCP connections ---------------------------------------------------
Write-Host 'Reading TCP connections...' -ForegroundColor DarkGray
$raw = @()
try {
    $raw = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -ne 'Listen' })
} catch {
    Write-Host "Couldn't read TCP connections: $($_.Exception.Message)" -ForegroundColor Red
    return
}
if (-not $IncludeOther) {
    $raw = @($raw | Where-Object { [string]$_.State -eq 'Established' })
}

if ($Resolve -and $raw.Count) {
    Write-Host 'Looking up remote hostnames (this queries your DNS servers)...' -ForegroundColor DarkGray
}

$rows = foreach ($c in $raw) {
    $procId = 0
    try { $procId = [int]$c.OwningProcess } catch { $procId = 0 }
    $remote = [string]$c.RemoteAddress
    $scope = Get-RemoteScope $remote
    $p = $null
    if ($procs.ContainsKey($procId)) { $p = $procs[$procId] }
    $name = if ($procId -eq 4) { 'System' } elseif ($p) { [System.IO.Path]::GetFileNameWithoutExtension([string]$p.Name) } else { '?' }
    if ($name -match '\.exe$') { $name = $name.Substring(0, $name.Length - 4) }
    $path = if ($p) { [string]$p.ExecutablePath } else { '' }
    $svcs = if ($svcByPid.ContainsKey($procId)) { ($svcByPid[$procId] | Sort-Object -Unique) -join ', ' } else { '' }
    $sig = if ($procId -eq 4) {
        [pscustomobject]@{ Signed = 'Yes'; Signer = 'Microsoft Windows' }
    } else {
        Get-SignerInfo $path
    }
    [pscustomobject]@{
        Process       = $name
        PID           = $procId
        State         = [string]$c.State
        LocalAddress  = [string]$c.LocalAddress
        LocalPort     = [int]$c.LocalPort
        RemoteAddress = $remote
        RemotePort    = [int]$c.RemotePort
        Scope         = $scope
        Hostname      = Get-RemoteName $remote
        Signed        = $sig.Signed
        Signer        = $sig.Signer
        Services      = $svcs
        UserDir       = [bool]($path -match $userDirPattern)
        Path          = $path
    }
}
$rows = @($rows)

$shown = if ($All) { $rows } else { @($rows | Where-Object { $_.Scope -ne 'This PC' }) }

# --- Network profiles ----------------------------------------------------------
Write-Header 'Network connections'
$profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
$onPublic = $false
if ($profiles.Count) {
    foreach ($np in $profiles) {
        $color = if ($np.NetworkCategory -eq 'Public') { 'Yellow' } else { 'Gray' }
        if ($np.NetworkCategory -eq 'Public') { $onPublic = $true }
        Write-Host ("  {0,-28} {1,-10} {2}" -f $np.InterfaceAlias, $np.NetworkCategory, $np.Name) -ForegroundColor $color
    }
} else {
    Write-Host '  No active network connections.' -ForegroundColor DarkGray
}

# --- Summary -------------------------------------------------------------------
$scopeCounts = @{
    'This PC'    = @($rows | Where-Object Scope -eq 'This PC').Count
    'LAN'        = @($rows | Where-Object Scope -eq 'LAN').Count
    'Internet'   = @($rows | Where-Object Scope -eq 'Internet').Count
    'Link-local' = @($rows | Where-Object Scope -eq 'Link-local').Count
    'Multicast'  = @($rows | Where-Object Scope -eq 'Multicast').Count
}
$programCount = @($shown | Select-Object -ExpandProperty Process -Unique).Count
$stateNote = if ($IncludeOther) { 'non-listening TCP' } else { 'established TCP' }
Write-Header ("Summary - {0} {1} connection(s) from {2} program(s)" -f $shown.Count, $stateNote, $programCount)
Write-Host ("  Internet {0,-6} LAN {1,-6} This PC {2,-6} Link-local {3,-6} Multicast {4}" -f `
    $scopeCounts['Internet'], $scopeCounts['LAN'], $scopeCounts['This PC'], $scopeCounts['Link-local'], $scopeCounts['Multicast'])
if (-not $All -and $scopeCounts['This PC'] -gt 0) {
    Write-Host ("  {0} loopback connection(s) hidden. Use -All to see them." -f $scopeCounts['This PC']) -ForegroundColor DarkGray
}
if (-not $isAdmin) {
    Write-Host '  Run as admin to include paths and signatures of system processes.' -ForegroundColor DarkGray
}

# --- By program ----------------------------------------------------------------
function Get-ProgramRows {
    param([object[]]$InputRows, [switch]$Split)
    if ($Split) {
        return @(
            $InputRows | Group-Object Process, PID | ForEach-Object {
                $g = @($_.Group)
                [pscustomobject]@{
                    Process   = $g[0].Process
                    Processes = [string]$g[0].PID
                    Total     = $g.Count
                    Internet  = @($g | Where-Object Scope -eq 'Internet').Count
                    LAN       = @($g | Where-Object Scope -eq 'LAN').Count
                    Other     = @($g | Where-Object { $_.Scope -notin 'Internet', 'LAN' }).Count
                    Signed    = $g[0].Signed
                    Signer    = $g[0].Signer
                    Services  = $g[0].Services
                    UserDir   = $g[0].UserDir
                    Path      = $g[0].Path
                }
            } | Sort-Object Internet, Total -Descending
        )
    }
    return @(
        $InputRows | Group-Object Process | ForEach-Object {
            $g = @($_.Group)
            $pidCount = @($g | Select-Object -ExpandProperty PID -Unique).Count
            $signed = if (@($g | Where-Object Signed -eq 'No').Count) { 'No' }
                elseif (@($g | Where-Object { $_.Signed -like 'Bad*' }).Count) { @($g | Where-Object { $_.Signed -like 'Bad*' })[0].Signed }
                elseif (@($g | Where-Object Signed -eq 'Yes').Count) { 'Yes' }
                else { $g[0].Signed }
            $signerRow = $g | Where-Object { $_.Signer } | Select-Object -First 1
            $pathRow = $g | Where-Object { $_.Path } | Select-Object -First 1
            [pscustomobject]@{
                Process   = $g[0].Process
                Processes = [string]$pidCount
                Total     = $g.Count
                Internet  = @($g | Where-Object Scope -eq 'Internet').Count
                LAN       = @($g | Where-Object Scope -eq 'LAN').Count
                Other     = @($g | Where-Object { $_.Scope -notin 'Internet', 'LAN' }).Count
                Signed    = $signed
                Signer    = if ($signerRow) { [string]$signerRow.Signer } else { '' }
                Services  = (($g | ForEach-Object { $_.Services }) | Where-Object { $_ } | Sort-Object -Unique) -join ', '
                UserDir   = [bool](@($g | Where-Object UserDir).Count)
                Path      = if ($pathRow) { [string]$pathRow.Path } else { '' }
            }
        } | Sort-Object Internet, Total -Descending
    )
}

$byProgram = Get-ProgramRows -InputRows $shown -Split:$PerProcess
$procTitle = if ($PerProcess) { 'By program (each process)' } else { 'By program' }
Write-Header $procTitle
if ($byProgram.Count) {
    $byProgram | Format-Table Process, Processes, Total, Internet, LAN, Other, Signed, Signer, Services -AutoSize -Wrap | Out-Host
} else {
    Write-Host '  No matching connections right now.' -ForegroundColor Green
}

# --- Destinations --------------------------------------------------------------
$dest = @(
    $shown | Group-Object Process, RemoteAddress, RemotePort, Scope | ForEach-Object {
        $g = @($_.Group)
        [pscustomobject]@{
            Process  = $g[0].Process
            Remote   = $g[0].RemoteAddress
            Port     = $g[0].RemotePort
            Scope    = $g[0].Scope
            Count    = $g.Count
            Hostname = $g[0].Hostname
            State    = if ($IncludeOther) { (($g | ForEach-Object { $_.State }) | Sort-Object -Unique) -join ', ' } else { '' }
            Signed   = $g[0].Signed
        }
    } | Sort-Object @{ Expression = { if ($_.Scope -eq 'Internet') { 0 } elseif ($_.Scope -eq 'LAN') { 1 } else { 2 } } }, Count -Descending
)
$destShown = @($dest | Select-Object -First $Top)
$destTitle = if ($dest.Count -gt $destShown.Count) {
    "Destinations - top $Top of $($dest.Count) (process + remote + port)"
} else {
    "Destinations - $($dest.Count) (process + remote + port)"
}
Write-Header $destTitle
if ($destShown.Count) {
    if ($Resolve -and $IncludeOther) {
        $destShown | Format-Table Process, Scope, Remote, Port, Count, Hostname, State, Signed -AutoSize -Wrap | Out-Host
    } elseif ($Resolve) {
        $destShown | Format-Table Process, Scope, Remote, Port, Count, Hostname, Signed -AutoSize -Wrap | Out-Host
    } elseif ($IncludeOther) {
        $destShown | Format-Table Process, Scope, Remote, Port, Count, State, Signed -AutoSize -Wrap | Out-Host
    } else {
        $destShown | Format-Table Process, Scope, Remote, Port, Count, Signed -AutoSize -Wrap | Out-Host
    }
    if ($dest.Count -gt $destShown.Count) {
        Write-Host ("  {0} more destination(s) not shown. Raise -Top or use -CsvPath." -f ($dest.Count - $destShown.Count)) -ForegroundColor DarkGray
    }
} else {
    Write-Host '  No matching destinations right now.' -ForegroundColor Green
}

# --- Findings ------------------------------------------------------------------
Write-Header 'Findings'
$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Level, [string]$Text) {
    $findings.Add([pscustomobject]@{ Level = $Level; Text = $Text })
}

$internetRows = @($shown | Where-Object Scope -eq 'Internet')
foreach ($p in @($internetRows | Where-Object { $_.Signed -eq 'No' -or $_.Signed -like 'Bad*' } | Group-Object Process)) {
    $sample = $p.Group[0]
    Add-Finding 'WARN' ("{0} is unsigned ({1}) and has {2} internet connection(s): {3}" -f $p.Name, $sample.Signed, $p.Count, $sample.Path)
}
foreach ($p in @($internetRows | Where-Object UserDir | Group-Object Process)) {
    $sample = $p.Group[0]
    Add-Finding 'WARN' ("{0} runs from a user folder and has {1} internet connection(s). Make sure you installed it: {2}" -f $p.Name, $p.Count, $sample.Path)
}
foreach ($p in @($shown | Where-Object {
            $_.Scope -ne 'This PC' -and
            $_.Process -match '(?i)(windows|microsoft|svchost|runtimebroker|servicehost|netservice)' -and
            (
                $_.Signed -eq 'No' -or
                $_.Signed -like 'Bad*' -or
                ($_.Signed -eq 'Yes' -and $_.Signer -notmatch 'Microsoft')
            )
        } | Group-Object Process)) {
    $sample = $p.Group[0]
    Add-Finding 'WARN' ("{0} sounds like a Windows component but is not signed by Microsoft (signed: {1}, signer: {2}). Path: {3}" -f $p.Name, $sample.Signed, $sample.Signer, $sample.Path)
}

foreach ($p in $byProgram) {
    $shortName = $p.Process
    if ($shortName -match '^(.*)\.exe$') { $shortName = $Matches[1] }
    if ($p.Internet -ge 50 -and -not $busyOk.Contains($shortName)) {
        Add-Finding 'INFO' ("{0} has {1} internet connection(s). Browsers and chat apps do this often; unexpected programs with this many are worth a look." -f $p.Process, $p.Internet)
    }
}

if ($onPublic -and $scopeCounts['Internet'] -gt 0) {
    Add-Finding 'INFO' 'This PC is on a Public network and has internet connections. That is normal at a cafe or hotspot; treat unexpected programs above with extra caution.'
}
if (-not $isAdmin -and @($shown | Where-Object Signed -eq 'Unknown').Count) {
    Add-Finding 'INFO' 'Some processes could not be inspected without admin. Run as admin for full paths and signatures.'
}
if ($IncludeOther) {
    $syn = @($shown | Where-Object State -eq 'SynSent').Count
    if ($syn -ge 10) {
        Add-Finding 'INFO' ("{0} connection(s) are stuck in SynSent (the other side has not answered). That can mean a down server, a firewall or a program retrying a lot." -f $syn)
    }
}

if ($findings.Count) {
    # De-duplicate identical texts (e.g. unsigned + user-folder overlap is fine to both show)
    foreach ($f in $findings) {
        $color = if ($f.Level -eq 'WARN') { 'Yellow' } else { 'Gray' }
        Write-Host ("  [{0}] {1}" -f $f.Level, $f.Text) -ForegroundColor $color
    }
} else {
    Write-Host '  Nothing stands out. Only expected programs appear to have network connections.' -ForegroundColor Green
}

if ($CsvPath) {
    try {
        $rows | Select-Object Process, PID, State, LocalAddress, LocalPort, RemoteAddress, RemotePort, Scope, Hostname, Signed, Signer, Services, Path |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host "Saved $($rows.Count) rows to $CsvPath" -ForegroundColor Cyan
    } catch {
        Write-Host "Couldn't write CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host 'Read-only: nothing was changed.' -ForegroundColor DarkGray

