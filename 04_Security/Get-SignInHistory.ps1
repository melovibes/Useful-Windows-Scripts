<#
.SYNOPSIS
    Get-SignInHistory.ps1 - Show who signed in to this PC and how, failed
    password attempts and where they came from, lockouts, and changes to
    local accounts and the Administrators group, with plain-English
    findings. Read-only.

.DESCRIPTION
    "Has anyone been in my PC?" is hard to answer from Event Viewer. This
    script reads the sign-in records Windows already keeps and turns them
    into a short report.

    Reports:
      Accounts       Local accounts: enabled or not, administrator or not,
                     last sign-in, password last set, and whether a
                     password is required
      Sign-ins       Successful sign-ins over the last -Days days, grouped
                     by account and type: at the keyboard, unlock, Remote
                     Desktop, cached (offline) and RunAs, with first and
                     last time and where remote ones came from
      Failed         Failed sign-ins grouped by account, type and source
                     address, with the reason in plain English (wrong
                     password, no such user, account disabled, locked out)
      Changes        Accounts created, deleted, enabled, disabled, renamed
                     or locked out, passwords reset, members added to or
                     removed from local groups such as Administrators, and
                     the Security log being cleared
      Log coverage   How far back the Security log goes and whether
                     sign-in auditing is turned on, so you know what the
                     report can and can't see
      Findings       Numbered list of what to look at first, with how

    Without admin, Windows does not let you read the Security log, so the
    script falls back to the sign-in and sign-out records in the System
    log (no failed attempts or account changes). Run it as admin for the
    full report.

    Safety level : READ-ONLY. Reads event logs, local accounts and group
                   membership, and the audit policy. Changes nothing,
                   turns no auditing on, makes no network calls (no
                   reverse DNS lookups of addresses). Writes a file only
                   if you pass -CsvPath. Fixes are printed as suggestions
                   only.
    Admin        : Optional, but needed for failed sign-ins, account
                   changes, Remote Desktop source addresses and the audit
                   policy check.

.PARAMETER Days
    How many days back to look (1-365, default 14). The Security log is
    often only a few weeks deep, so older entries may already be gone.

.PARAMETER Top
    Rows to show in each list (default 15).

.PARAMETER IncludeNetwork
    Also count network sign-ins (type 3: file shares, printers, remote
    admin tools). These are noisy on most PCs, so they are left out by
    default. Failed network sign-ins are always shown.

.PARAMETER Detailed
    Also print the most recent individual sign-ins, not just the summary.

.PARAMETER CsvPath
    Export every sign-in, failed attempt and account change in the window
    to this CSV file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-SignInHistory.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-SignInHistory.ps1 -Days 60 -Detailed

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-SignInHistory.ps1 -CsvPath "$env:USERPROFILE\Desktop\sign-ins.csv"
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)][int]$Days = 14,
    [ValidateRange(1, 200)][int]$Top = 15,
    [switch]$IncludeNetwork,
    [switch]$Detailed,
    [string]$CsvPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$cutoff    = (Get-Date).AddDays(-$Days)
$windowMs  = [int64]$Days * 86400000
$maxEvents = 20000
$findings  = New-Object System.Collections.Generic.List[object]
$rows      = New-Object System.Collections.Generic.List[object]

$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

function Add-Finding {
    param([ValidateSet('High', 'Medium', 'Low')][string]$Level, [string]$Text, [string]$Fix)
    $findings.Add([pscustomobject]@{ Level = $Level; Text = $Text; Fix = $Fix })
}

function Write-Section { param([string]$Title) Write-Host ''; Write-Host "== $Title ==" -ForegroundColor Cyan }

function Format-Age {
    param($When)
    if (-not $When) { return 'never / unknown' }
    $span = (Get-Date) - $When
    if ($span.TotalDays -ge 2) { return ('{0:yyyy-MM-dd} ({1} days ago)' -f $When, [int]$span.TotalDays) }
    if ($span.TotalHours -ge 1) { return ('{0:yyyy-MM-dd HH:mm} ({1} hours ago)' -f $When, [int]$span.TotalHours) }
    return ('{0:yyyy-MM-dd HH:mm} (just now)' -f $When)
}

# Returns the named <Data> fields of an event as a hashtable.
function Get-EventData {
    param($Ev)
    $h = @{}
    try {
        $xml = [xml]$Ev.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $h[$d.Name] = [string]$d.'#text' }
        }
    } catch { }
    return $h
}

function Get-Field {
    param([hashtable]$Data, [string]$Name)
    if ($Data.ContainsKey($Name) -and $Data[$Name]) { return $Data[$Name] }
    return ''
}

function Resolve-Sid {
    param([string]$Sid)
    if (-not $Sid -or $Sid -eq '-') { return '' }
    try { return (New-Object Security.Principal.SecurityIdentifier $Sid).Translate([Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

# Accounts Windows uses for itself; not interesting in a sign-in report.
function Test-SystemAccount {
    param([string]$Name, [string]$Domain)
    if (-not $Name -or $Name -eq '-') { return $true }
    if ($Name.EndsWith('$')) { return $true }
    if ($Name -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|defaultuser\d*|WsiAccount)$') { return $true }
    if ($Domain -match '^(Font Driver Host|Window Manager|NT AUTHORITY|NT SERVICE)$') { return $true }
    return $false
}

# Local, LAN or Internet, without any network lookup.
function Get-AddressKind {
    param([string]$Address)
    if (-not $Address -or $Address -eq '-' -or $Address -eq 'LOCAL') { return 'This PC' }
    $a = $Address -replace '^::ffff:', ''
    if ($a -eq '127.0.0.1' -or $a -eq '::1') { return 'This PC' }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($a, [ref]$ip)) { return 'Unknown' }
    if ($ip.AddressFamily -eq 'InterNetwork') {
        $b = $ip.GetAddressBytes()
        if ($b[0] -eq 10) { return 'LAN' }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return 'LAN' }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return 'LAN' }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return 'LAN' }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return 'VPN/CGNAT' }
        return 'Internet'
    }
    if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal) { return 'LAN' }
    if ($a -match '^f[cd]') { return 'LAN' }
    return 'Internet'
}

$logonTypes = @{
    '2' = 'At the keyboard'; '3' = 'Network'; '4' = 'Batch (scheduled task)'; '5' = 'Service'
    '7' = 'Unlock'; '8' = 'Network (cleartext)'; '9' = 'RunAs /netonly'; '10' = 'Remote Desktop'
    '11' = 'Cached (offline)'; '12' = 'Cached Remote Desktop'; '13' = 'Cached unlock'
}
function Get-LogonTypeName { param([string]$T) if ($logonTypes.ContainsKey($T)) { return $logonTypes[$T] } return "Type $T" }

$failReasons = @{
    '0XC000006A' = 'Wrong password'
    '0XC0000064' = 'No such user name'
    '0XC000006D' = 'Bad user name or password'
    '0XC000006E' = 'Account restriction'
    '0XC000006F' = 'Outside allowed sign-in hours'
    '0XC0000070' = 'Not allowed from this computer'
    '0XC0000071' = 'Password expired'
    '0XC0000072' = 'Account disabled'
    '0XC0000193' = 'Account expired'
    '0XC0000224' = 'Must change password first'
    '0XC0000234' = 'Account locked out'
    '0XC000015B' = 'Not allowed to sign in this way'
    '0XC0000133' = 'PC clock out of sync with the server'
    '0XC0000413' = 'Blocked by authentication firewall'
}
function Get-FailReason {
    param([string]$Status, [string]$SubStatus)
    foreach ($code in @($SubStatus, $Status)) {
        if ($code) {
            $c = $code.ToUpper()
            if ($failReasons.ContainsKey($c)) { return $failReasons[$c] }
        }
    }
    if ($SubStatus -and $SubStatus -ne '0x0') { return "Code $SubStatus" }
    return "Code $Status"
}

Write-Host 'Get-SignInHistory.ps1 - read-only sign-in and account activity report' -ForegroundColor White
Write-Host ("Window: last {0} days (since {1:yyyy-MM-dd HH:mm}){2}" -f $Days, $cutoff, $(if ($isAdmin) { '' } else { ' - not admin, limited report' })) -ForegroundColor DarkGray

# --- Accounts -----------------------------------------------------------------
Write-Section 'Accounts'
$adminSids = @{}
$adminGroupName = 'Administrators'
try { $adminGroupName = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1] } catch { }
try {
    foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) { $adminSids[$m.SID.Value] = $m.Name }
} catch {
    # Get-LocalGroupMember fails when the group holds an orphaned or cloud SID; fall back to ADSI.
    try {
        $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$adminGroupName,group"
        foreach ($m in @($grp.Invoke('Members'))) {
            $sidBytes = $m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null)
            $name = $m.GetType().InvokeMember('Name', 'GetProperty', $null, $m, $null)
            if ($sidBytes) { $adminSids[(New-Object Security.Principal.SecurityIdentifier $sidBytes, 0).Value] = $name }
        }
    } catch { Write-Host '  Could not read the Administrators group.' -ForegroundColor DarkYellow }
}

$localUsers = @()
try { $localUsers = @(Get-LocalUser -ErrorAction Stop) } catch { Write-Host '  Could not list local accounts (Get-LocalUser unavailable).' -ForegroundColor DarkYellow }
$localNames = @{}
foreach ($u in $localUsers) {
    $localNames[$u.Name.ToLower()] = $true
    $sid   = $u.SID.Value
    $admin = $adminSids.ContainsKey($sid)
    $state = if ($u.Enabled) { 'Enabled' } else { 'Disabled' }
    $color = if (-not $u.Enabled) { 'DarkGray' } elseif ($admin) { 'Yellow' } else { 'Gray' }
    Write-Host ("  {0,-22} {1,-9} {2,-6} last sign-in {3}" -f $u.Name, $state, $(if ($admin) { 'Admin' } else { '' }), (Format-Age $u.LastLogon)) -ForegroundColor $color
    if ($Detailed) {
        Write-Host ("      password set {0}; password required: {1}; source: {2}" -f (Format-Age $u.PasswordLastSet), $u.PasswordRequired, $u.PrincipalSource) -ForegroundColor DarkGray
    }
    if (-not $u.Enabled) { continue }
    if ($sid -match '-500$') {
        Add-Finding 'Medium' "The built-in Administrator account ($($u.Name)) is enabled. It is a well-known target for password guessing." "If you don't use it: Disable-LocalUser -Name '$($u.Name)' (as admin)."
    }
    if ($sid -match '-501$') {
        Add-Finding 'High' "The Guest account ($($u.Name)) is enabled." "Disable-LocalUser -Name '$($u.Name)' (as admin)."
    }
    if (-not $u.PasswordRequired -and $u.PrincipalSource -eq 'Local' -and $sid -notmatch '-50[1-3]$') {
        Add-Finding 'Medium' "Local account '$($u.Name)' is enabled and may not need a password." "Set a password in Settings > Accounts, or: net user `"$($u.Name)`" /passwordreq:yes (as admin)."
    }
    if ($sid -notmatch '-50[0-3]$') {
        if (-not $u.LastLogon) {
            Add-Finding 'Low' "Enabled account '$($u.Name)' has never signed in." "If nobody uses it, disable or remove it in Settings > Accounts > Other users."
        } elseif (((Get-Date) - $u.LastLogon).TotalDays -gt 180) {
            Add-Finding 'Low' "Enabled account '$($u.Name)' hasn't signed in for over 6 months." "If nobody uses it, disable or remove it in Settings > Accounts > Other users."
        }
    }
}
if ($adminSids.Count -gt 0) {
    $others = @($adminSids.Keys | Where-Object { $sid = $_; -not ($localUsers | Where-Object { $_.SID.Value -eq $sid }) } | ForEach-Object { $adminSids[$_] })
    if ($others.Count -gt 0) { Write-Host ("  Other members of {0}: {1}" -f $adminGroupName, ($others -join ', ')) -ForegroundColor DarkGray }
}

# --- Read the logs ---------------------------------------------------------------
$securityOk = $false
$signIns = New-Object System.Collections.Generic.List[object]
$failed  = New-Object System.Collections.Generic.List[object]
$changes = New-Object System.Collections.Generic.List[object]
$truncated = $false

if ($isAdmin) {
    $types = @('2', '7', '9', '10', '11', '12', '13')
    if ($IncludeNetwork) { $types += '3' }
    $typeFilter = ($types | ForEach-Object { "Data[@Name='LogonType']='$_'" }) -join ' or '
    $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $windowMs]]] and *[EventData[$typeFilter]]"
    try {
        $ev = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents $maxEvents -ErrorAction Stop)
        $securityOk = $true
        if ($ev.Count -ge $maxEvents) { $truncated = $true }
        foreach ($e in $ev) {
            $d = Get-EventData $e
            $user = Get-Field $d 'TargetUserName'; $dom = Get-Field $d 'TargetDomainName'
            if (Test-SystemAccount $user $dom) { continue }
            $src = Get-Field $d 'IpAddress'
            $signIns.Add([pscustomobject]@{
                Time = $e.TimeCreated; Account = "$dom\$user"; Type = (Get-LogonTypeName (Get-Field $d 'LogonType'))
                Source = $src; SourceKind = (Get-AddressKind $src); Workstation = (Get-Field $d 'WorkstationName')
                Process = (Get-Field $d 'ProcessName')
            })
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found') { $securityOk = $true }
        else { Write-Host "  Could not read the Security log: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    }

    if ($securityOk) {
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $cutoff } -MaxEvents $maxEvents -ErrorAction Stop)
            if ($ev.Count -ge $maxEvents) { $truncated = $true }
            foreach ($e in $ev) {
                $d = Get-EventData $e
                $user = Get-Field $d 'TargetUserName'; $dom = Get-Field $d 'TargetDomainName'
                if ($user.EndsWith('$')) { continue }
                $src = Get-Field $d 'IpAddress'
                $failed.Add([pscustomobject]@{
                    Time = $e.TimeCreated; Account = $(if ($dom -and $dom -ne '-') { "$dom\$user" } else { $user }); User = $user
                    Type = (Get-LogonTypeName (Get-Field $d 'LogonType')); Source = $src; SourceKind = (Get-AddressKind $src)
                    Workstation = (Get-Field $d 'WorkstationName'); Reason = (Get-FailReason (Get-Field $d 'Status') (Get-Field $d 'SubStatus'))
                })
            }
        } catch { if ($_.Exception.Message -notmatch 'No events were found') { Write-Host "  Could not read failed sign-ins: $($_.Exception.Message)" -ForegroundColor DarkYellow } }

        $changeIds = @{
            4720 = 'Account created'; 4722 = 'Account enabled'; 4723 = 'Password changed by user'; 4724 = 'Password reset'
            4725 = 'Account disabled'; 4726 = 'Account deleted'; 4740 = 'Account locked out'; 4767 = 'Account unlocked'
            4781 = 'Account renamed'; 4732 = 'Added to group'; 4733 = 'Removed from group'; 1102 = 'Security log cleared'
        }
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @($changeIds.Keys); StartTime = $cutoff } -MaxEvents 2000 -ErrorAction Stop)
            foreach ($e in $ev) {
                $d = Get-EventData $e
                $what = $changeIds[[int]$e.Id]
                $by = Get-Field $d 'SubjectUserName'
                $target = Get-Field $d 'TargetUserName'
                $group = ''; $groupSid = ''
                if ($e.Id -eq 4732 -or $e.Id -eq 4733) {
                    $group = $target; $groupSid = Get-Field $d 'TargetSid'
                    $target = Get-Field $d 'MemberName'
                    if (-not $target -or $target -eq '-') { $target = Resolve-Sid (Get-Field $d 'MemberSid') }
                    $what = "$what $group"
                }
                if ($e.Id -eq 4781) { $target = "{0} -> {1}" -f (Get-Field $d 'OldTargetUserName'), (Get-Field $d 'NewTargetUserName') }
                if ($e.Id -eq 1102) { $xml = [xml]$e.ToXml(); try { $by = $xml.Event.UserData.LogFileCleared.SubjectUserName } catch { $by = '' } }
                $changes.Add([pscustomobject]@{ Time = $e.TimeCreated; Id = [int]$e.Id; What = $what; Target = $target; By = $by; GroupSid = $groupSid })
            }
        } catch { if ($_.Exception.Message -notmatch 'No events were found') { Write-Host "  Could not read account changes: $($_.Exception.Message)" -ForegroundColor DarkYellow } }
    }
}

# Fallback (and extra detail): Winlogon sign-in records in the System log, readable without admin.
if (-not $securityOk) {
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Winlogon'; Id = 7001; StartTime = $cutoff } -MaxEvents $maxEvents -ErrorAction Stop)
        foreach ($e in $ev) {
            $d = Get-EventData $e
            $acct = Resolve-Sid (Get-Field $d 'UserSid')
            $signIns.Add([pscustomobject]@{
                Time = $e.TimeCreated; Account = $acct; Type = 'Sign-in (System log)'; Source = ''; SourceKind = 'This PC'; Workstation = ''; Process = ''
            })
        }
    } catch { if ($_.Exception.Message -notmatch 'No events were found') { Write-Host "  Could not read the System log: $($_.Exception.Message)" -ForegroundColor DarkYellow } }
}

# Remote Desktop sessions (works without admin on most PCs).
$rdp = New-Object System.Collections.Generic.List[object]
try {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id = @(21, 25); StartTime = $cutoff } -MaxEvents 5000 -ErrorAction Stop)
    foreach ($e in $ev) {
        $u = ''; $addr = ''
        try {
            $xml = [xml]$e.ToXml()
            $u = [string]$xml.Event.UserData.EventXML.User
            $addr = [string]$xml.Event.UserData.EventXML.Address
        } catch { }
        $kind = Get-AddressKind $addr
        if ($kind -eq 'This PC') { continue }   # console sessions, not remote
        $rdp.Add([pscustomobject]@{ Time = $e.TimeCreated; Account = $u; What = $(if ($e.Id -eq 21) { 'RDP sign-in' } else { 'RDP reconnect' }); Source = $addr; SourceKind = $kind })
    }
} catch { }

# --- Sign-ins -------------------------------------------------------------------
Write-Section "Sign-ins (last $Days days)"
if ($signIns.Count -eq 0) {
    Write-Host '  No sign-ins found in this window.' -ForegroundColor DarkGray
} else {
    $groups = $signIns | Group-Object Account, Type | Sort-Object Count -Descending
    Write-Host ("  {0,-30} {1,-24} {2,6}  {3,-16} {4}" -f 'Account', 'How', 'Count', 'First', 'Last') -ForegroundColor DarkGray
    foreach ($g in ($groups | Select-Object -First $Top)) {
        $first = ($g.Group | Measure-Object Time -Minimum).Minimum
        $last  = ($g.Group | Measure-Object Time -Maximum).Maximum
        $s = $g.Group[0]
        $color = if ($s.Type -match 'Remote Desktop') { 'Yellow' } else { 'Gray' }
        Write-Host ("  {0,-30} {1,-24} {2,6}  {3:yyyy-MM-dd HH:mm}  {4:yyyy-MM-dd HH:mm}" -f $s.Account, $s.Type, $g.Count, $first, $last) -ForegroundColor $color
    }
    if (@($groups).Count -gt $Top) { Write-Host ("  ... {0} more (use -Top)" -f (@($groups).Count - $Top)) -ForegroundColor DarkGray }

    $night = @($signIns | Where-Object { $_.Type -notmatch 'Unlock' -and $_.Time.Hour -ge 1 -and $_.Time.Hour -lt 5 })
    if ($night.Count -gt 0) { Write-Host ("  {0} sign-in(s) between 1 AM and 5 AM - check these were you." -f $night.Count) -ForegroundColor DarkYellow }

    $runAs = @($signIns | Where-Object { $_.Type -eq 'RunAs /netonly' })
    if ($runAs.Count -gt 0) { Write-Host ("  {0} RunAs /netonly sign-in(s): a program ran with other saved credentials." -f $runAs.Count) -ForegroundColor DarkGray }

    if ($Detailed) {
        Write-Host ''
        Write-Host '  Most recent:' -ForegroundColor DarkGray
        foreach ($s in ($signIns | Sort-Object Time -Descending | Select-Object -First $Top)) {
            $from = if ($s.Source -and $s.Source -ne '-') { " from $($s.Source) ($($s.SourceKind))" } else { '' }
            Write-Host ("    {0:yyyy-MM-dd HH:mm}  {1,-30} {2}{3}" -f $s.Time, $s.Account, $s.Type, $from) -ForegroundColor Gray
        }
    }
}
if (-not $securityOk) {
    Write-Host '  Not admin: only basic sign-ins from the System log are shown. Run as admin for failed attempts and account changes.' -ForegroundColor DarkYellow
}

$remoteIn = @($signIns | Where-Object { $_.Type -match 'Remote Desktop' }) + @($rdp.ToArray())
if ($remoteIn.Count -gt 0) {
    Write-Host ''
    Write-Host '  Remote Desktop sign-ins:' -ForegroundColor Yellow
    foreach ($g in ($remoteIn | Where-Object { $_.Source } | Group-Object Source | Sort-Object Count -Descending | Select-Object -First $Top)) {
        $last = ($g.Group | Measure-Object Time -Maximum).Maximum
        $acct = ($g.Group | Select-Object -ExpandProperty Account -Unique) -join ', '
        Write-Host ("    {0,-40} {1,-10} {2,4}x  last {3:yyyy-MM-dd HH:mm}  as {4}" -f $g.Name, $g.Group[0].SourceKind, $g.Count, $last, $acct) -ForegroundColor Gray
    }
    $internetRdp = @($remoteIn | Where-Object { $_.SourceKind -eq 'Internet' })
    if ($internetRdp.Count -gt 0) {
        $ips = ($internetRdp | Select-Object -ExpandProperty Source -Unique | Select-Object -First 5) -join ', '
        Add-Finding 'High' "Someone signed in over Remote Desktop from the internet ($($internetRdp.Count) time(s), from $ips)." 'If that was not you, change the password of that account now, turn off Remote Desktop (Settings > System > Remote Desktop) and close any port forward to 3389 on your router.'
    } else {
        Add-Finding 'Low' "There were $($remoteIn.Count) Remote Desktop sign-in(s) from your network." 'Fine if you use Remote Desktop at home. If not, turn it off in Settings > System > Remote Desktop.'
    }
}

# --- Failed ---------------------------------------------------------------------
if ($securityOk) {
    Write-Section "Failed sign-ins (last $Days days)"
    if ($failed.Count -eq 0) {
        Write-Host '  None.' -ForegroundColor Green
    } else {
        Write-Host ("  {0} failed attempt(s)." -f $failed.Count) -ForegroundColor Gray
        Write-Host ("  {0,-26} {1,-18} {2,-26} {3,5}  {4,-26} {5}" -f 'Account', 'How', 'From', 'Count', 'Reason', 'Last') -ForegroundColor DarkGray
        $fg = $failed | Group-Object Account, Type, Source, Reason | Sort-Object Count -Descending
        foreach ($g in ($fg | Select-Object -First $Top)) {
            $f = $g.Group[0]
            $last = ($g.Group | Measure-Object Time -Maximum).Maximum
            $from = if ($f.Source -and $f.Source -ne '-') { "$($f.Source) ($($f.SourceKind))" } else { 'This PC' }
            $color = if ($f.SourceKind -eq 'Internet') { 'Red' } elseif ($g.Count -ge 5) { 'Yellow' } else { 'Gray' }
            Write-Host ("  {0,-26} {1,-18} {2,-26} {3,5}  {4,-26} {5:yyyy-MM-dd HH:mm}" -f $f.Account, $f.Type, $from, $g.Count, $f.Reason, $last) -ForegroundColor $color
        }
        if (@($fg).Count -gt $Top) { Write-Host ("  ... {0} more (use -Top)" -f (@($fg).Count - $Top)) -ForegroundColor DarkGray }

        foreach ($g in ($failed | Where-Object { $_.SourceKind -eq 'Internet' } | Group-Object Source)) {
            if ($g.Count -ge 5) {
                $names = ($g.Group | Select-Object -ExpandProperty User -Unique | Select-Object -First 5) -join ', '
                Add-Finding 'High' "$($g.Count) failed sign-ins from internet address $($g.Name) (tried: $names). Something is guessing passwords from outside." 'Turn off Remote Desktop / SMB exposure or the router port forward that lets it in, and make sure every account has a strong password.'
            }
        }
        foreach ($g in ($failed | Where-Object { $_.SourceKind -eq 'LAN' } | Group-Object Source)) {
            if ($g.Count -ge 10) {
                Add-Finding 'Medium' "$($g.Count) failed sign-ins from $($g.Name) on your network." 'Often an old saved password on another PC, phone or NAS mapping a share. If you do not recognise the device, find it in your router and investigate.'
            }
        }
        foreach ($g in ($failed | Where-Object { $_.SourceKind -eq 'This PC' } | Group-Object Account)) {
            if ($g.Count -ge 10) {
                Add-Finding 'Medium' "$($g.Count) failed sign-ins at this PC for $($g.Name)." 'If that was not a forgotten PIN or password, someone may have tried to get in at the keyboard.'
            }
        }
        $unknown = @($failed | Where-Object { $_.Reason -eq 'No such user name' -and $_.SourceKind -ne 'This PC' })
        if ($unknown.Count -ge 3) {
            $names = ($unknown | Select-Object -ExpandProperty User -Unique | Select-Object -First 8) -join ', '
            Add-Finding 'Medium' "$($unknown.Count) remote sign-in attempts used user names that don't exist here ($names)." 'Typical of automated password guessing. Check nothing on this PC is reachable from the internet.'
        }
    }

    # --- Changes --------------------------------------------------------------------
    Write-Section "Account changes (last $Days days)"
    if ($changes.Count -eq 0) {
        Write-Host '  None.' -ForegroundColor Green
    } else {
        foreach ($c in ($changes | Sort-Object Time -Descending | Select-Object -First ([Math]::Max($Top, 30)))) {
            $color = if ($c.Id -eq 1102 -or ($c.Id -eq 4732 -and $c.GroupSid -eq 'S-1-5-32-544')) { 'Red' } elseif ($c.Id -in 4720, 4726, 4740) { 'Yellow' } else { 'Gray' }
            $by = if ($c.By -and $c.By -ne '-') { " by $($c.By)" } else { '' }
            Write-Host ("  {0:yyyy-MM-dd HH:mm}  {1,-34} {2}{3}" -f $c.Time, $c.What, $c.Target, $by) -ForegroundColor $color
        }
        foreach ($c in ($changes | Where-Object { $_.Id -eq 4732 -and $_.GroupSid -eq 'S-1-5-32-544' })) {
            Add-Finding 'High' ("'{0}' was added to {1} on {2:yyyy-MM-dd HH:mm}." -f $c.Target, $adminGroupName, $c.Time) "If you didn't do this, remove it: Remove-LocalGroupMember -SID S-1-5-32-544 -Member '$($c.Target)' (as admin), then check Find-RemoteAccess.ps1 and Find-SuspiciousStartup.ps1."
        }
        foreach ($c in ($changes | Where-Object { $_.Id -eq 4720 })) {
            Add-Finding 'Medium' ("A new account '{0}' was created on {1:yyyy-MM-dd HH:mm}." -f $c.Target, $c.Time) 'Make sure you or an installer you trust created it. Unknown accounts can be removed in Settings > Accounts > Other users.'
        }
        foreach ($c in ($changes | Where-Object { $_.Id -eq 1102 })) {
            Add-Finding 'High' ("The Security log was cleared on {0:yyyy-MM-dd HH:mm}{1}." -f $c.Time, $(if ($c.By) { " by $($c.By)" } else { '' })) 'Clearing the log is a common way to hide a break-in. If you did not do it, run a full Defender scan and check for unknown accounts and remote access tools.'
        }
        $locks = @($changes | Where-Object { $_.Id -eq 4740 })
        if ($locks.Count -gt 0) {
            Add-Finding 'Medium' ("{0} account lockout(s): {1}." -f $locks.Count, (($locks | Select-Object -ExpandProperty Target -Unique) -join ', ')) 'Lockouts happen after too many wrong passwords. Check the failed sign-ins above for where they came from.'
        }
    }
}

# --- Log coverage ---------------------------------------------------------------
Write-Section 'Log coverage'
if ($securityOk) {
    try {
        $log = Get-WinEvent -ListLog Security -ErrorAction Stop
        $oldest = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop
        Write-Host ("  Security log: {0:N0} MB max, oldest entry {1}" -f ($log.MaximumSizeInBytes / 1MB), (Format-Age $oldest.TimeCreated)) -ForegroundColor Gray
        if ($oldest.TimeCreated -gt $cutoff) {
            Write-Host ("  The log only reaches back to {0:yyyy-MM-dd}; anything older is gone." -f $oldest.TimeCreated) -ForegroundColor DarkYellow
            if ($log.MaximumSizeInBytes -lt 64MB) {
                Add-Finding 'Low' ("The Security log only keeps {0:N0} MB, which here covers about {1} days." -f ($log.MaximumSizeInBytes / 1MB), [int]((Get-Date) - $oldest.TimeCreated).TotalDays) 'For a longer history: wevtutil sl Security /ms:268435456 (256 MB, as admin).'
            }
        }
    } catch { }
    try {
        # Logon subcategory GUID; /r gives CSV output that does not depend on the Windows language.
        $csv = & auditpol.exe /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /r 2>$null
        if ($LASTEXITCODE -eq 0 -and $csv) {
            $row = $csv | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1
            $setting = [string]$row.'Inclusion Setting'
            Write-Host "  Logon auditing: $setting" -ForegroundColor Gray
            if ($setting -notmatch 'Failure') {
                Add-Finding 'Medium' 'Failed sign-ins are not being recorded, so password guessing would go unnoticed.' 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable (as admin).'
            }
        }
    } catch { }
} else {
    Write-Host '  Security log not read (needs admin). Coverage and audit policy not checked.' -ForegroundColor DarkGray
}
if ($truncated) { Write-Host "  Stopped at $maxEvents events per query; use a smaller -Days for a complete count." -ForegroundColor DarkYellow }

# --- CSV --------------------------------------------------------------------------
if ($CsvPath) {
    foreach ($s in $signIns) { $rows.Add([pscustomobject]@{ Time = $s.Time; Kind = 'Sign-in'; Account = $s.Account; How = $s.Type; Source = $s.Source; SourceKind = $s.SourceKind; Detail = $s.Process }) }
    foreach ($r in $rdp)     { $rows.Add([pscustomobject]@{ Time = $r.Time; Kind = $r.What; Account = $r.Account; How = 'Remote Desktop'; Source = $r.Source; SourceKind = $r.SourceKind; Detail = '' }) }
    foreach ($f in $failed)  { $rows.Add([pscustomobject]@{ Time = $f.Time; Kind = 'Failed sign-in'; Account = $f.Account; How = $f.Type; Source = $f.Source; SourceKind = $f.SourceKind; Detail = $f.Reason }) }
    foreach ($c in $changes) { $rows.Add([pscustomobject]@{ Time = $c.Time; Kind = 'Account change'; Account = $c.Target; How = $c.What; Source = ''; SourceKind = ''; Detail = $(if ($c.By) { "by $($c.By)" } else { '' }) }) }
    try {
        $rows | Sort-Object Time -Descending | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host ''
        Write-Host "Saved $($rows.Count) rows to $CsvPath" -ForegroundColor Green
    } catch { Write-Host "Could not write CSV: $($_.Exception.Message)" -ForegroundColor Red }
}

# --- Findings ---------------------------------------------------------------------
Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  Nothing unusual in the sign-in history.' -ForegroundColor Green
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
Write-Host 'Nothing was changed. Fixes above are suggestions only.' -ForegroundColor DarkGray
