<#
.SYNOPSIS
    Test-HomeNetwork.ps1 - Read-only network health check for a Windows PC:
    adapters, Wi-Fi signal, gateway and internet latency, packet loss, DNS speed,
    proxy settings and the hosts file, with a plain-English list of problems.

.DESCRIPTION
    For the "is it my PC, the Wi-Fi, the router or the internet?" question.
    It reports:
      - Active adapters: name, type, link speed, IPv4 address, gateway, DNS servers
        (flags self-assigned 169.254.x.x addresses, missing gateways and slow
        Ethernet links)
      - Wi-Fi: SSID, band, channel, signal %, radio type and link rates
      - Gateway MAC address (from the ARP/neighbor table)
      - Ping stats to the gateway, public resolvers and any -Targets you add:
        average, best, worst, jitter and packet loss
      - DNS lookup time against each DNS server the PC is set to use
      - Optional: the largest packet that gets through without fragmenting (MTU)
      - Proxy settings (WinINET and WinHTTP) - an unexpected proxy can mean
        adware or "proxyware"
      - How many active entries are in the hosts file

    Safety level : SAFE (read-only). Changes no settings, adapters or files.
                   Network traffic goes only to your own gateway, your configured
                   DNS servers, Cloudflare (1.1.1.1) and Google (8.8.8.8) public
                   DNS, and any -Targets you name. -NoInternet skips the public ones.
                   The only file written is the optional -JsonPath report.

    Admin        : Not required.

.PARAMETER Count
    Pings sent to each target. Default 20.

.PARAMETER Targets
    Extra hosts or IPs to ping, e.g. a NAS, AP or another PC: '192.168.1.20','nas.local'.

.PARAMETER HostsWarnThreshold
    Warn in the summary when the hosts file has more active entries than this. Default 50.

.PARAMETER DnsName
    Name to look up when timing DNS servers. Default www.microsoft.com.

.PARAMETER NoInternet
    Skip the public targets (1.1.1.1 and 8.8.8.8). Local checks only.

.PARAMETER CheckMtu
    Find the largest unfragmented packet to 1.1.1.1 (or the gateway with -NoInternet).

.PARAMETER JsonPath
    Save all results to a JSON file.

.EXAMPLE
    .\Test-HomeNetwork.ps1
.EXAMPLE
    .\Test-HomeNetwork.ps1 -Count 50 -Targets '192.168.1.20' -CheckMtu
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Test-HomeNetwork.ps1" -NoInternet -JsonPath "$env:USERPROFILE\Desktop\net.json"

.NOTES
    Undo: nothing to undo - this script changes nothing.
    Works in Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 500)]
    [int]$Count = 20,
    [string[]]$Targets = @(),
    [string]$DnsName = 'www.microsoft.com',
    [switch]$NoInternet,
    [switch]$CheckMtu,
    [ValidateRange(0, 1000000)]
    [int]$HostsWarnThreshold = 50,
    [string]$JsonPath
)

$ErrorActionPreference = 'Stop'
$Problems = New-Object System.Collections.Generic.List[string]
$Report = [ordered]@{ ComputerName = $env:COMPUTERNAME; Time = (Get-Date).ToString('s') }

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Add-Problem([string]$Text) {
    $Problems.Add($Text)
}

# Ping a host $Count times and return latency, jitter and loss.
function Measure-Ping([string]$Target, [int]$N) {
    $pinger = New-Object System.Net.NetworkInformation.Ping
    $times = New-Object System.Collections.Generic.List[double]
    $lost = 0
    for ($i = 0; $i -lt $N; $i++) {
        try {
            $reply = $pinger.Send($Target, 1000)
            if ($reply.Status -eq 'Success') { $times.Add([double]$reply.RoundtripTime) } else { $lost++ }
        } catch { $lost++ }
        if ($i -lt $N - 1) { Start-Sleep -Milliseconds 200 }
    }
    $pinger.Dispose()
    $result = [ordered]@{ Target = $Target; Sent = $N; LossPct = [math]::Round(100 * $lost / $N, 1)
                          AvgMs = $null; MinMs = $null; MaxMs = $null; JitterMs = $null }
    if ($times.Count -gt 0) {
        $stats = $times | Measure-Object -Average -Minimum -Maximum
        $result.AvgMs = [math]::Round($stats.Average, 1)
        $result.MinMs = $stats.Minimum
        $result.MaxMs = $stats.Maximum
        if ($times.Count -gt 1) {
            $diffs = for ($j = 1; $j -lt $times.Count; $j++) { [math]::Abs($times[$j] - $times[$j - 1]) }
            $result.JitterMs = [math]::Round(($diffs | Measure-Object -Average).Average, 1)
        } else { $result.JitterMs = 0 }
    }
    [pscustomobject]$result
}

# Largest ICMP payload that passes with Don't Fragment set (binary search).
function Find-MaxPayload([string]$Target) {
    $pinger = New-Object System.Net.NetworkInformation.Ping
    $opts = New-Object System.Net.NetworkInformation.PingOptions(64, $true)
    $lo = 500; $hi = 1472; $best = $null
    while ($lo -le $hi) {
        $mid = [int][math]::Floor(($lo + $hi) / 2)
        $ok = $false
        try { $ok = ($pinger.Send($Target, 1000, (New-Object byte[] $mid), $opts).Status -eq 'Success') } catch { }
        if ($ok) { $best = $mid; $lo = $mid + 1 } else { $hi = $mid - 1 }
    }
    $pinger.Dispose()
    $best
}

# ---------------------------------------------------------------- Adapters
Write-Section 'Active adapters'
$configs = @(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' })
$adapterRows = foreach ($c in $configs) {
    $ipv4 = @($c.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', '
    $gw = @($c.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', '
    $dns = @($c.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ', '
    $row = [pscustomobject]@{
        Name      = $c.InterfaceAlias
        Type      = $c.NetAdapter.MediaType
        LinkSpeed = $c.NetAdapter.LinkSpeed
        IPv4      = $ipv4
        Gateway   = $gw
        DNS       = $dns
    }
    if ($ipv4 -match '(^|, )169\.254\.') { Add-Problem "$($row.Name) has a self-assigned 169.254.x.x address: DHCP isn't answering." }
    if ($ipv4 -and -not $gw -and $c.InterfaceAlias -notmatch 'vEthernet|VMware|VirtualBox|Loopback|Tailscale|ZeroTier') {
        Add-Problem "$($row.Name) has an address but no default gateway."
    }
    if ($c.NetAdapter.MediaType -eq '802.3' -and $c.NetAdapter.ReceiveLinkSpeed -gt 0 -and $c.NetAdapter.ReceiveLinkSpeed -lt 1000000000 -and $c.InterfaceAlias -notmatch 'vEthernet') {
        Add-Problem "$($row.Name) is linked at $($c.NetAdapter.LinkSpeed), not 1 Gbps or more. Check the cable or switch port."
    }
    $row
}
$adapterRows | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
$Report.Adapters = $adapterRows

$gateways = @($configs | ForEach-Object { $_.IPv4DefaultGateway } | ForEach-Object { $_.NextHop } | Where-Object { $_ } | Select-Object -Unique)
$dnsServers = @($configs | ForEach-Object { $_.DNSServer } | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
if ($gateways.Count -eq 0) { Add-Problem 'No default gateway found on any active adapter.' }

# ---------------------------------------------------------------- Wi-Fi
$wifi = $null
try { $wlanText = (netsh wlan show interfaces) 2>$null } catch { $wlanText = $null }
if ($wlanText -and ($wlanText -match '^\s*SSID\s*:')) {
    Write-Section 'Wi-Fi'
    $fields = @{}
    foreach ($line in $wlanText) {
        if ($line -match '^\s*([^:]+?)\s*:\s*(.+?)\s*$') { if (-not $fields.ContainsKey($Matches[1])) { $fields[$Matches[1]] = $Matches[2] } }
    }
    $signal = $null
    if ($fields['Signal'] -match '(\d+)') { $signal = [int]$Matches[1] }
    $wifi = [pscustomobject]@{
        SSID      = $fields['SSID']
        BSSID     = $fields['AP BSSID']
        Band      = $fields['Band']
        Channel   = $fields['Channel']
        Radio     = $fields['Radio type']
        SignalPct = $signal
        RxMbps    = $fields['Receive rate (Mbps)']
        TxMbps    = $fields['Transmit rate (Mbps)']
    }
    $wifi | Format-List | Out-String | Write-Host
    if ($signal -ne $null -and $signal -lt 60) { Add-Problem "Wi-Fi signal is weak ($signal%). Move closer to an access point or use Ethernet." }
    if ($fields['Band'] -match '2\.4') { Add-Problem 'Wi-Fi is on 2.4 GHz. 5 or 6 GHz is usually much faster if this PC is in range.' }
}
$Report.WiFi = $wifi

# ---------------------------------------------------------------- Gateway MAC
if ($gateways.Count -gt 0) {
    Write-Section 'Gateway'
    foreach ($g in $gateways) {
        $n = Get-NetNeighbor -IPAddress $g -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress } | Select-Object -First 1
        $mac = if ($n) { $n.LinkLayerAddress } else { '(not in neighbor table yet)' }
        Write-Host ("{0}  MAC {1}" -f $g, $mac)
    }
}

# ---------------------------------------------------------------- Ping
Write-Section "Ping ($Count each)"
$pingTargets = New-Object System.Collections.Generic.List[string]
foreach ($g in $gateways) { $pingTargets.Add($g) }
if (-not $NoInternet) { $pingTargets.Add('1.1.1.1'); $pingTargets.Add('8.8.8.8') }
foreach ($t in $Targets) { if ($t) { $pingTargets.Add($t) } }

$pingRows = foreach ($t in ($pingTargets | Select-Object -Unique)) {
    Write-Host "  pinging $t ..." -ForegroundColor DarkGray
    $r = Measure-Ping -Target $t -N $Count
    $isGw = $gateways -contains $t
    if ($r.LossPct -ge 100) { Add-Problem "$t did not answer any pings." }
    elseif ($r.LossPct -gt 2) { Add-Problem "$t dropped $($r.LossPct)% of pings." }
    if ($isGw -and $r.AvgMs -gt 10) { Add-Problem "Gateway $t averages $($r.AvgMs) ms. On a healthy LAN it's under 5 ms (Wi-Fi interference or a busy router)." }
    if (-not $isGw -and $r.AvgMs -gt 60) { Add-Problem "$t averages $($r.AvgMs) ms, which is slow for a nearby host." }
    if ($r.JitterMs -gt 20) { Add-Problem "$t has $($r.JitterMs) ms of jitter, which hurts calls and gaming." }
    $r
}
$pingRows | Format-Table Target, Sent, LossPct, AvgMs, MinMs, MaxMs, JitterMs -AutoSize | Out-String | Write-Host
$Report.Ping = $pingRows

# ---------------------------------------------------------------- DNS
Write-Section "DNS lookup of $DnsName"
$dnsRows = foreach ($s in $dnsServers) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ok = $true; $answer = ''
    try {
        $res = Resolve-DnsName -Name $DnsName -Server $s -DnsOnly -QuickTimeout -NoHostsFile -ErrorAction Stop
        $answer = @($res | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -First 2) -join ', '
    } catch { $ok = $false; $answer = $_.Exception.Message }
    $sw.Stop()
    if (-not $ok) { Add-Problem "DNS server $s failed to resolve $DnsName." }
    elseif ($sw.ElapsedMilliseconds -gt 150) { Add-Problem "DNS server $s took $($sw.ElapsedMilliseconds) ms to answer." }
    [pscustomobject]@{ Server = $s; OK = $ok; Ms = $sw.ElapsedMilliseconds; Answer = $answer }
}
if ($dnsServers.Count -eq 0) { Add-Problem 'No IPv4 DNS servers are configured.' }
$dnsRows | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
$Report.Dns = $dnsRows

# ---------------------------------------------------------------- MTU
if ($CheckMtu) {
    Write-Section 'MTU'
    $mtuTarget = if ($NoInternet) { $gateways | Select-Object -First 1 } else { '1.1.1.1' }
    if ($mtuTarget) {
        $payload = Find-MaxPayload -Target $mtuTarget
        if ($payload) {
            $mtu = $payload + 28
            Write-Host "Largest unfragmented payload to $mtuTarget is $payload bytes (path MTU $mtu)."
            if ($mtu -lt 1500) { Add-Problem "Path MTU to $mtuTarget is $mtu, below the usual 1500 (normal on PPPoE or VPN, otherwise worth checking)." }
            $Report.Mtu = [pscustomobject]@{ Target = $mtuTarget; Payload = $payload; Mtu = $mtu }
        } else { Write-Host "No reply from $mtuTarget with Don't Fragment set." }
    }
}

# ---------------------------------------------------------------- Proxy
Write-Section 'Proxy'
$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$userProxy = if ($inet -and $inet.ProxyEnable -eq 1) { $inet.ProxyServer } else { $null }
$pac = if ($inet) { $inet.AutoConfigURL } else { $null }
$winhttp = ((netsh winhttp show proxy) 2>$null | Out-String).Trim()
$winhttpDirect = $winhttp -match 'Direct access'
Write-Host ("User proxy (WinINET): {0}" -f $(if ($userProxy) { $userProxy } else { 'none' }))
Write-Host ("PAC script          : {0}" -f $(if ($pac) { $pac } else { 'none' }))
Write-Host ("System (WinHTTP)    : {0}" -f $(if ($winhttpDirect) { 'direct' } else { $winhttp }))
if ($userProxy) { Add-Problem "A user proxy is set ($userProxy). If you didn't set it, check for adware or proxyware." }
if ($pac) { Add-Problem "A proxy auto-config script is set ($pac). Make sure you recognize it." }
if ($winhttp -and -not $winhttpDirect) { Add-Problem 'A system-wide WinHTTP proxy is set. Make sure you recognize it.' }
$Report.Proxy = [pscustomobject]@{ User = $userProxy; Pac = $pac; WinHttpDirect = $winhttpDirect }

# ---------------------------------------------------------------- Hosts file
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsCount = 0
if (Test-Path $hostsPath) {
    $hostsCount = @(Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#\s]' }).Count
}
Write-Section 'Hosts file'
Write-Host "$hostsCount active entries in $hostsPath"
$Report.HostsEntries = $hostsCount
if ($hostsCount -gt $HostsWarnThreshold) {
    Add-Problem "Hosts file has $hostsCount active entries; likely a blocklist, check it if sites fail to load."
}

# ---------------------------------------------------------------- Summary
Write-Section 'Summary'
if ($Problems.Count -eq 0) {
    Write-Host 'No problems found.' -ForegroundColor Green
} else {
    foreach ($p in $Problems) { Write-Host "  ! $p" -ForegroundColor Yellow }
}
$Report.Problems = @($Problems)

if ($JsonPath) {
    $Report | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonPath -Encoding UTF8
    Write-Host "Saved report to $JsonPath"
}
