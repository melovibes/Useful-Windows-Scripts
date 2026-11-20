<#
.SYNOPSIS
    Get-DefenderReport.ps1 - Deep-dive into Microsoft Defender Antivirus:
    which protections are really on, how fresh the signatures and scans are,
    risky exclusions, recent detections and what happened to them, warning
    signs in the Defender event log, and Attack Surface Reduction rules,
    with plain-English findings. Read-only.

.DESCRIPTION
    Windows Security shows a green tick when Defender is "on", but that tick
    hides a lot: an exclusion for your whole Downloads folder, a threat that
    was allowed instead of removed, signature updates that have been failing
    for a week, or something switching real-time protection off. This script
    reads what Defender already knows about itself and turns it into a short
    report. (Test-SecurityPosture.ps1 does a quick on/off check; this goes
    deeper.)

    Reports:
      Status       Running mode (Normal, Passive because another antivirus
                   is in charge, EDR block mode), real-time protection,
                   behavior monitoring, download scanning (IOAV), script
                   scanning, network protection, cloud protection (MAPS) and
                   automatic sample submission, PUA blocking, tamper
                   protection, engine/platform/signature versions,
                   signature age and last quick and full scan
      Exclusions   Excluded folders/files, extensions, processes and IP
                   addresses, with risky ones flagged: whole drives,
                   user-writable folders (Temp, Downloads, AppData, Public),
                   program and script extensions (.exe .ps1 .js .vbs .bat)
                   and broad processes (powershell.exe, cmd.exe)
      Detections   Threats found in the last -Days days: name, severity,
                   category, file, what Defender did (quarantined, removed,
                   allowed, failed) and whether it worked, with repeats
                   grouped; also threats you have told Defender to allow
      Events       From the Defender Operational log: real-time protection
                   turned off, settings changes (exclusion changes shown),
                   tamper protection blocking a change, failed scans,
                   failed signature/engine/platform updates, engine errors,
                   and blocks by ASR rules, Controlled Folder Access and
                   network protection
      ASR          Attack Surface Reduction rules by friendly name with
                   Block / Audit / Warn / Off state, Controlled Folder Access
                   state and how many apps are allowed through it
      Findings     Numbered list of what to look at first, with how to fix it

    If Defender is not installed, not running, or in passive mode because
    another antivirus is active, the script says so, names the antivirus
    Windows Security Center reports, and shows whatever Defender data is
    still available.

    Safety level : READ-ONLY. Reads Defender status and settings
                   (Get-MpComputerStatus, Get-MpPreference), detection
                   history (Get-MpThreat, Get-MpThreatDetection), the
                   Defender Operational event log, Security Center and
                   Defender policy registry keys. Changes nothing, never
                   updates signatures or starts a scan, makes no network
                   calls. Writes a file only if you pass -CsvPath or
                   -HtmlPath. Fixes are printed as suggestions only.
    Admin        : Optional, but needed to see exclusions (Windows hides
                   them from non-admins and shows "N/A: Must be an
                   administrator to view exclusions"), and on some PCs to
                   read detection history and the Defender event log.

.PARAMETER Days
    How many days back to look for detections and events (1-365, default 30).

.PARAMETER Detailed
    Show every detection and every event in the window, not just the
    grouped summary, plus each ASR rule GUID.

.PARAMETER CsvPath
    Export detections, events and exclusions to this CSV file, with a Type
    column (Detection, Event, Exclusion).

.PARAMETER HtmlPath
    Also save the report (status, findings, detections, events and
    exclusions) as a simple HTML page at this path.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DefenderReport.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DefenderReport.ps1 -Days 90 -Detailed

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DefenderReport.ps1 -CsvPath "$env:USERPROFILE\Desktop\defender.csv"

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DefenderReport.ps1 -HtmlPath "$env:USERPROFILE\Desktop\defender.html"
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)][int]$Days = 30,
    [switch]$Detailed,
    [string]$CsvPath,
    [string]$HtmlPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$cutoff    = (Get-Date).AddDays(-$Days)
$top       = 15
$maxEvents = 20000
$findings  = New-Object System.Collections.Generic.List[object]
$rows      = New-Object System.Collections.Generic.List[object]
$status    = New-Object System.Collections.Generic.List[object]
$adminNote = 'Run PowerShell as administrator'

$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

function Add-Finding {
    param([ValidateSet('High', 'Medium', 'Low')][string]$Level, [string]$Text, [string]$Fix)
    $findings.Add([pscustomobject]@{ Level = $Level; Text = $Text; Fix = $Fix })
}
function Add-Row {
    param([string]$Type, $Time, [string]$Name, [string]$Severity, [string]$Status, [string]$Resource, [string]$Detail)
    $rows.Add([pscustomobject]@{ Type = $Type; Time = $Time; Name = $Name; Severity = $Severity; Status = $Status; Resource = $Resource; Detail = $Detail })
}
function Write-Section { param([string]$Title) Write-Host ''; Write-Host "== $Title ==" -ForegroundColor Cyan }
function Write-Line {
    param([string]$Label, [string]$Value, [string]$Color = 'Gray')
    Write-Host ("  {0,-26}: {1}" -f $Label, $Value) -ForegroundColor $Color
    $status.Add([pscustomobject]@{ Setting = $Label; Value = $Value })
}

# Safe property read: older Defender builds lack some properties, and StrictMode
# throws on a missing one.
function Get-Prop {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Format-Age {
    param($When)
    if (-not $When) { return 'never / unknown' }
    try { $When = [datetime]$When } catch { return 'never / unknown' }
    if ($When.Year -lt 2000) { return 'never / unknown' }
    $span = (Get-Date) - $When
    if ($span.TotalDays -ge 2) { return ('{0:yyyy-MM-dd} ({1} days ago)' -f $When, [int]$span.TotalDays) }
    if ($span.TotalHours -ge 1) { return ('{0:yyyy-MM-dd HH:mm} ({1} hours ago)' -f $When, [int]$span.TotalHours) }
    return ('{0:yyyy-MM-dd HH:mm} (just now)' -f $When)
}
function Get-AgeDays {
    param($When)
    if (-not $When) { return $null }
    try { $d = [datetime]$When } catch { return $null }
    if ($d.Year -lt 2000) { return $null }
    return [math]::Floor(((Get-Date) - $d).TotalDays)
}
function Format-OnOff {
    param($Value)
    if ($null -eq $Value) { return 'unknown' }
    if ($Value) { return 'On' } else { return 'OFF' }
}
function Get-OnOffColor {
    param($Value)
    if ($null -eq $Value) { return 'DarkGray' }
    if ($Value) { return 'Green' } else { return 'Red' }
}

# Returns the named <Data> fields of an event as a hashtable.
function Get-EventData {
    param($Ev)
    $h = @{}
    try {
        $xml = [xml]$Ev.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) {
            # InnerText, not '#text': StrictMode throws on '#text' for an empty <Data/> (e.g. "Old Value" of a new exclusion).
            $n = $d.GetAttribute('Name')
            if ($n) { $h[$n] = [string]$d.InnerText }
        }
    } catch { }
    return $h
}
function Get-Field {
    param([hashtable]$Data, [string[]]$Names)
    foreach ($n in $Names) { if ($Data.ContainsKey($n) -and $Data[$n]) { return $Data[$n] } }
    return ''
}
function Get-FirstLine {
    param([string]$Text, [int]$Max = 160)
    if (-not $Text) { return '' }
    $line = ($Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $line) { return '' }
    $line = $line.Trim()
    if ($line.Length -gt $Max) { $line = $line.Substring(0, $Max - 3) + '...' }
    return $line
}
function Limit-Text {
    param([string]$Text, [int]$Max)
    if (-not $Text) { return '' }
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, $Max - 2) + '..'
}
function Test-Hidden {
    # Non-admins (and admins when HideExclusionsFromLocalAdmins is set) get this text instead of the real list.
    param($List)
    foreach ($v in @($List)) { if ([string]$v -match '^N/A') { return $true } }
    return $false
}
function Get-CleanList {
    param($List)
    return @(@($List) | Where-Object { $_ -and ([string]$_).Trim() -and [string]$_ -notmatch '^N/A' } | ForEach-Object { [string]$_ })
}
function Format-Resource {
    # Detection resources look like "file:_C:\path\x.exe" or "webfile:_C:\x|https://...".
    param([string]$Res)
    if (-not $Res) { return '' }
    return ($Res -replace '^[A-Za-z]+:_', '')
}

# --- Risk checks for exclusions (also used by the test harness) ------------------
$userWritablePattern = '(?i)(\\temp(\\|$)|%temp%|%tmp%|\\tmp(\\|$)|\\downloads(\\|$)|\\appdata(\\|$)|%appdata%|%localappdata%|\\users\\public(\\|$)|%public%|\\windows\\temp(\\|$)|\\\$recycle\.bin|%userprofile%\\?$)'
$sharedFolderPattern = '(?i)(\\desktop(\\|$)|\\documents(\\|$)|\\programdata(\\|$))'
$riskyExtensions = @('exe', 'dll', 'sys', 'scr', 'com', 'pif', 'msi', 'msp', 'ps1', 'psm1', 'psd1', 'bat', 'cmd',
    'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'lnk', 'jar', 'cpl', 'reg', 'iso', 'img', 'vhd', 'vhdx',
    'zip', 'rar', '7z', 'docm', 'xlsm', 'pptm')
$broadProcesses = @('powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'explorer.exe', 'svchost.exe', 'conhost.exe',
    'python.exe', 'pythonw.exe', 'node.exe', 'java.exe', 'javaw.exe', 'wmic.exe', 'bitsadmin.exe', 'certutil.exe',
    'msbuild.exe', 'installutil.exe', 'schtasks.exe', 'curl.exe', 'winword.exe', 'excel.exe', 'outlook.exe')

function Get-ExclusionRisk {
    # Returns @(Level, Reason) or $null when the exclusion looks reasonable.
    param([string]$Kind, [string]$Value)
    $v = $Value.Trim()
    switch ($Kind) {
        'Path' {
            if ($v -match '^\*?$' -or $v -match '^[A-Za-z]:\\?\*?$' -or $v -match '^\\\\[^\\]+\\?$' -or $v -match '^%systemdrive%\\?$') {
                return @('High', 'excludes a whole drive')
            }
            if ($v -match '(?i)^([A-Za-z]:|%systemdrive%)\\(windows|program files|program files \(x86\)|users|programdata)\\?\*?$' -or $v -match '(?i)^%(windir|systemroot|programfiles|programdata)%\\?$') {
                return @('High', 'excludes a whole system folder')
            }
            if ($v -match '(?i)^([A-Za-z]:\\users\\[^\\]+|%userprofile%)\\?\*?$') { return @('High', 'excludes an entire user profile') }
            if ($v -match $userWritablePattern) { return @('High', 'user-writable folder where downloads and malware land') }
            if ($v -match $sharedFolderPattern) { return @('Medium', 'folder that standard users and their programs can write to') }
            if ($v -match '(?i)\*\.(\w+)$' -and $riskyExtensions -contains $Matches[1].ToLower()) { return @('Medium', "wildcard for .$($Matches[1]) files") }
            if ($v -match '\*.*\*' -or $v -match '(?i)\\\*\\') { return @('Medium', 'broad wildcard') }
            return $null
        }
        'Extension' {
            $e = $v.TrimStart('*').TrimStart('.').ToLower()
            if ($riskyExtensions -contains $e) { return @('High', "every .$e file anywhere is skipped") }
            return $null
        }
        'Process' {
            $leaf = ($v -split '\\')[-1].ToLower()
            if ($v -match '^\*' -or $leaf -eq '*' -or $leaf -eq '*.exe') { return @('High', 'wildcard process') }
            if ($broadProcesses -contains $leaf) { return @('High', "anything $leaf opens is skipped") }
            if ($v -match $userWritablePattern) { return @('Medium', 'process lives in a user-writable folder') }
            return $null
        }
        'IpAddress' {
            if ($v -match '^0\.0\.0\.0' -or $v -match '/[0-7]$') { return @('High', 'very broad address range') }
            return $null
        }
    }
    return $null
}

# Attack Surface Reduction rules (Microsoft's documented GUID list).
$asrNames = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables unless they meet prevalence, age or trusted list'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executables'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec and WMI commands'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
}
function Get-AsrActionName {
    param($Action)
    switch ([string]$Action) {
        '0' { 'Off' } '1' { 'Block' } '2' { 'Audit' } '5' { 'Not configured' } '6' { 'Warn' }
        'Disabled' { 'Off' } 'Enabled' { 'Block' } 'AuditMode' { 'Audit' } 'Warn' { 'Warn' }
        default { "Unknown ($Action)" }
    }
}

$threatStatusNames = @{
    0 = 'Unknown'; 1 = 'Detected'; 2 = 'Cleaned'; 3 = 'Quarantined'; 4 = 'Removed'; 5 = 'Allowed'; 6 = 'Blocked'
    102 = 'Quarantine failed'; 103 = 'Remove failed'; 104 = 'Allow failed'; 105 = 'Abandoned'; 107 = 'Block failed'
}
$severityNames = @{ 0 = 'Unknown'; 1 = 'Low'; 2 = 'Moderate'; 4 = 'High'; 5 = 'Severe' }
$categoryNames = @{
    0 = 'Invalid'; 1 = 'Adware'; 2 = 'Spyware'; 3 = 'Password stealer'; 4 = 'Trojan downloader'; 5 = 'Worm'; 6 = 'Backdoor'
    7 = 'Remote access trojan'; 8 = 'Trojan'; 9 = 'Email flooder'; 10 = 'Keylogger'; 11 = 'Dialer'; 12 = 'Monitoring software'
    13 = 'Browser modifier'; 14 = 'Cookie'; 15 = 'Browser plugin'; 16 = 'AOL exploit'; 17 = 'Nuker'; 18 = 'Security disabler'
    19 = 'Joke program'; 20 = 'Hostile ActiveX control'; 21 = 'Software bundler'; 22 = 'Stealth notifier'; 23 = 'Settings modifier'
    24 = 'Toolbar'; 25 = 'Remote control software'; 26 = 'Trojan FTP'; 27 = 'Potentially unwanted software'; 28 = 'ICQ exploit'
    29 = 'Trojan telnet'; 30 = 'Exploit'; 31 = 'File sharing program'; 32 = 'Malware creation tool'; 33 = 'Remote control software'
    34 = 'Tool'; 36 = 'Trojan denial of service'; 37 = 'Trojan dropper'; 38 = 'Trojan mass mailer'; 39 = 'Trojan monitoring software'
    40 = 'Trojan proxy server'; 42 = 'Virus'; 43 = 'Known'; 44 = 'Unknown'; 45 = 'SPP'; 46 = 'Behavior'; 47 = 'Vulnerability'
    48 = 'Policy'; 49 = 'Enterprise unwanted software'; 50 = 'Ransomware'; 51 = 'ASR rule'
}
$defaultActionNames = @{ 1 = 'Clean'; 2 = 'Quarantine'; 3 = 'Remove'; 6 = 'Allow'; 8 = 'User defined'; 9 = 'No action'; 10 = 'Block' }
function Get-MapName { param([hashtable]$Map, $Key) if ($null -eq $Key -or [string]$Key -eq '') { return 'Unknown' } try { $k = [int]$Key; if ($Map.ContainsKey($k)) { return $Map[$k] } } catch { } return "$Key" }

Write-Host 'Get-DefenderReport.ps1 - read-only Microsoft Defender Antivirus report' -ForegroundColor White
Write-Host ("Window: last {0} days (since {1:yyyy-MM-dd HH:mm}){2}" -f $Days, $cutoff, $(if ($isAdmin) { '' } else { ' - not admin, some data may be hidden' })) -ForegroundColor DarkGray

# --- Read Defender ---------------------------------------------------------------
$haveCmdlets = [bool](Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
$mp = $null; $pref = $null; $mpError = ''; $prefError = ''
if ($haveCmdlets) {
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mpError = $_.Exception.Message }
    try { $pref = Get-MpPreference -ErrorAction Stop } catch { $prefError = $_.Exception.Message }
}

# Which antivirus does Windows Security Center think is in charge? (local WMI, no network)
$avProducts = @()
try {
    foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
        $state = [int](Get-Prop $p 'productState')
        $on = (($state -shr 12) -band 0xF) -eq 1
        $avProducts += [pscustomobject]@{ Name = [string](Get-Prop $p 'displayName'); Enabled = $on }
    }
} catch { }
$otherAv = @($avProducts | Where-Object { $_.Enabled -and $_.Name -notmatch 'Defender' })

# --- Status -----------------------------------------------------------------------
Write-Section 'Status'
$mode = ''
$sigAge = $null
if (-not $haveCmdlets) {
    Write-Host '  The Defender PowerShell cmdlets are not available on this PC (Defender removed, or not Windows 10/11).' -ForegroundColor DarkYellow
} elseif (-not $mp) {
    Write-Host "  Could not read Defender status: $mpError" -ForegroundColor DarkYellow
    Write-Host '  This usually means the Defender service is not running, often because another antivirus has replaced it.' -ForegroundColor DarkGray
}
if ($avProducts.Count -gt 0) {
    $list = ($avProducts | ForEach-Object { '{0} ({1})' -f $_.Name, $(if ($_.Enabled) { 'on' } else { 'off' }) }) -join ', '
    Write-Line 'Security Center antivirus' $list
}

if ($mp) {
    $mode         = [string](Get-Prop $mp 'AMRunningMode')
    $avOn         = Get-Prop $mp 'AntivirusEnabled'
    $rtp          = Get-Prop $mp 'RealTimeProtectionEnabled'
    $behavior     = Get-Prop $mp 'BehaviorMonitorEnabled'
    $ioav         = Get-Prop $mp 'IoavProtectionEnabled'
    $onAccess     = Get-Prop $mp 'OnAccessProtectionEnabled'
    $tamper       = Get-Prop $mp 'IsTamperProtected'
    $tamperSource = [string](Get-Prop $mp 'TamperProtectionSource')
    $sigUpdated   = Get-Prop $mp 'AntivirusSignatureLastUpdated'
    $sigAge       = Get-AgeDays $sigUpdated
    if ($null -eq $sigAge) { $a = Get-Prop $mp 'AntivirusSignatureAge'; if ($null -ne $a -and [int64]$a -lt 65535) { $sigAge = [int64]$a } }
    $quickEnd     = Get-Prop $mp 'QuickScanEndTime'
    $fullEnd      = Get-Prop $mp 'FullScanEndTime'
    $quickAge     = Get-AgeDays $quickEnd
    $fullAge      = Get-AgeDays $fullEnd

    $passive = $mode -match 'Passive'
    $modeText = switch -Regex ($mode) {
        '^Normal'      { 'Normal (Defender is your active antivirus)' }
        'SxS Passive'  { 'Passive - limited periodic scanning alongside another antivirus' }
        'Passive'      { 'Passive - another antivirus is in charge' }
        'EDR Block'    { 'EDR block mode - Defender for Endpoint remediates behind another antivirus' }
        default        { $(if ($mode) { $mode } else { 'unknown' }) }
    }
    Write-Line 'Running mode' $modeText $(if ($mode -match '^Normal') { 'Green' } elseif ($passive) { 'Yellow' } else { 'Gray' })
    Write-Line 'Summary' ("Antivirus {0}, real-time {1}, signatures {2}" -f (Format-OnOff $avOn), (Format-OnOff $rtp), $(if ($null -ne $sigAge) { "$sigAge day(s) old" } else { 'age unknown' })) $(if ($avOn -and $rtp) { 'Green' } else { 'Yellow' })
    Write-Line 'Real-time protection'   (Format-OnOff $rtp)      (Get-OnOffColor $rtp)
    Write-Line 'On-access scanning'     (Format-OnOff $onAccess) (Get-OnOffColor $onAccess)
    Write-Line 'Behavior monitoring'    (Format-OnOff $behavior) (Get-OnOffColor $behavior)
    Write-Line 'Download scanning (IOAV)' (Format-OnOff $ioav)   (Get-OnOffColor $ioav)
    if ($pref) {
        $scriptScan = -not [bool](Get-Prop $pref 'DisableScriptScanning')
        Write-Line 'Script scanning' (Format-OnOff $scriptScan) (Get-OnOffColor $scriptScan)
    }
    $tamperText = (Format-OnOff $tamper) + $(if ($tamperSource -and $tamperSource -ne 'N/A') { " (set by $tamperSource)" } else { '' })
    Write-Line 'Tamper protection' $tamperText (Get-OnOffColor $tamper)

    if (-not $passive -and $mode -notmatch 'EDR Block') {
        if ($avOn -eq $false) {
            Add-Finding 'High' 'Defender antivirus is turned off and no other antivirus is reported as active.' 'Windows Security > Virus & threat protection > Manage settings, turn Real-time protection on; if a third-party antivirus was removed, restart so Defender takes over.'
        }
        if ($rtp -eq $false) {
            Add-Finding 'High' 'Real-time protection is off, so files are not scanned when they are opened or downloaded.' 'Windows Security > Virus & threat protection > Manage settings > Real-time protection: On. Or, as admin: Set-MpPreference -DisableRealtimeMonitoring $false'
        }
        if ($behavior -eq $false) {
            Add-Finding 'High' 'Behavior monitoring is off, so Defender cannot catch malware by what it does.' 'As admin: Set-MpPreference -DisableBehaviorMonitoring $false (if it turns itself off again, check for a policy or another tool changing it).'
        }
        if ($ioav -eq $false) {
            Add-Finding 'Medium' 'Scanning of downloaded files and attachments (IOAV) is off.' 'As admin: Set-MpPreference -DisableIOAVProtection $false'
        }
        if ($pref -and [bool](Get-Prop $pref 'DisableScriptScanning')) {
            Add-Finding 'Medium' 'Script scanning is off, so malicious PowerShell and JavaScript are not checked.' 'As admin: Set-MpPreference -DisableScriptScanning $false'
        }
    }
    if ($tamper -eq $false) {
        Add-Finding 'Medium' 'Tamper protection is off, so malware (or a script) can quietly turn Defender settings off.' 'Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On.'
    }
    if ($passive -and $otherAv.Count -eq 0) {
        Add-Finding 'High' 'Defender is in passive mode but Windows Security Center reports no other active antivirus.' 'Check Windows Security > Virus & threat protection > Microsoft Defender Antivirus options; if the other antivirus was uninstalled, restart and make sure Defender becomes active.'
    }
} elseif ($otherAv.Count -gt 0) {
    Write-Host ("  Another antivirus is active: {0}. Defender details are not available." -f (($otherAv | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor DarkGray
} elseif ($avProducts.Count -gt 0 -or $haveCmdlets) {
    Add-Finding 'High' 'Defender status could not be read and no other active antivirus was found.' 'Open Windows Security > Virus & threat protection. If it shows an error, run "sfc /scannow" as admin and restart.'
}

if ($pref) {
    $maps = [string](Get-Prop $pref 'MAPSReporting')
    $mapsText = switch ($maps) { '0' { 'OFF' } '1' { 'On (basic)' } '2' { 'On (advanced)' } 'Disabled' { 'OFF' } 'Basic' { 'On (basic)' } 'Advanced' { 'On (advanced)' } default { "unknown ($maps)" } }
    Write-Line 'Cloud protection (MAPS)' $mapsText $(if ($mapsText -eq 'OFF') { 'Red' } else { 'Green' })
    $submit = [string](Get-Prop $pref 'SubmitSamplesConsent')
    $submitText = switch ($submit) { '0' { 'Always prompt' } '1' { 'Send safe samples automatically' } '2' { 'Never send' } '3' { 'Send all samples automatically' } default { "unknown ($submit)" } }
    Write-Line 'Sample submission' $submitText $(if ($submit -eq '2') { 'Yellow' } else { 'Green' })
    $pua = [string](Get-Prop $pref 'PUAProtection')
    $puaText = switch ($pua) { '0' { 'OFF' } '1' { 'On (block)' } '2' { 'Audit only' } 'Disabled' { 'OFF' } 'Enabled' { 'On (block)' } 'AuditMode' { 'Audit only' } default { "unknown ($pua)" } }
    Write-Line 'PUA blocking' $puaText $(if ($puaText -eq 'On (block)') { 'Green' } else { 'Yellow' })
    $np = [string](Get-Prop $pref 'EnableNetworkProtection')
    $npText = switch ($np) { '0' { 'OFF' } '1' { 'On (block)' } '2' { 'Audit only' } 'Disabled' { 'OFF' } 'Enabled' { 'On (block)' } 'AuditMode' { 'Audit only' } default { "unknown ($np)" } }
    Write-Line 'Network protection' $npText $(if ($npText -eq 'On (block)') { 'Green' } else { 'Yellow' })

    if (-not ($mode -match 'Passive')) {
        if ($mapsText -eq 'OFF') {
            Add-Finding 'Medium' 'Cloud-delivered protection is off, so Defender cannot check brand-new threats with Microsoft in seconds.' 'Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection: On. Or, as admin: Set-MpPreference -MAPSReporting Advanced'
        }
        if ($submit -eq '2') {
            Add-Finding 'Low' 'Automatic sample submission is set to never, which weakens cloud protection for unknown files.' 'Windows Security > Virus & threat protection > Manage settings > Automatic sample submission: On. Or, as admin: Set-MpPreference -SubmitSamplesConsent SendSafeSamples'
        }
        if ($puaText -ne 'On (block)') {
            Add-Finding 'Medium' "Potentially unwanted app blocking is $puaText (bundled adware, coin miners and 'PC cleaners' get through)." 'Windows Security > App & browser control > Reputation-based protection settings > Potentially unwanted app blocking: On. Or, as admin: Set-MpPreference -PUAProtection Enabled'
        }
        if ($npText -eq 'OFF') {
            Add-Finding 'Low' 'Network protection is off (it blocks connections to known malicious and scam sites from any app, not just Edge).' 'As admin: Set-MpPreference -EnableNetworkProtection Enabled (test for a few days; a few older apps may need an exclusion).'
        }
    }
} elseif ($haveCmdlets) {
    Write-Host "  Could not read Defender settings: $prefError" -ForegroundColor DarkYellow
}

if ($mp) {
    Write-Line 'Engine version'    ([string](Get-Prop $mp 'AMEngineVersion'))
    Write-Line 'Platform version'  ([string](Get-Prop $mp 'AMProductVersion'))
    Write-Line 'Signature version' ([string](Get-Prop $mp 'AntivirusSignatureVersion'))
    $sigColor = if ($null -eq $sigAge) { 'DarkGray' } elseif ($sigAge -gt 3) { 'Red' } else { 'Green' }
    Write-Line 'Signatures updated' (Format-Age $sigUpdated) $sigColor
    Write-Line 'Last quick scan' (Format-Age $quickEnd) $(if ($null -eq $quickAge -or $quickAge -gt 14) { 'Yellow' } else { 'Green' })
    Write-Line 'Last full scan'  (Format-Age $fullEnd) $(if ($null -eq $fullAge) { 'DarkGray' } else { 'Gray' })

    if ($null -ne $sigAge -and $sigAge -gt 3) {
        $lvl = if ($sigAge -gt 7) { 'High' } else { 'Medium' }
        Add-Finding $lvl "Defender signatures are $sigAge days old (more than 3), so recent threats may be missed." 'Settings > Windows Update > Check for updates, or Windows Security > Virus & threat protection > Protection updates > Check for updates. If it keeps failing, see the update errors under Events.'
    }
    if ([bool](Get-Prop $mp 'DefenderSignaturesOutOfDate') -and ($null -eq $sigAge -or $sigAge -le 3)) {
        Add-Finding 'Medium' 'Defender reports its signatures as out of date.' 'Windows Security > Virus & threat protection > Protection updates > Check for updates.'
    }
    if (-not ($mode -match 'Passive')) {
        if ($null -eq $quickAge) {
            Add-Finding 'Low' 'No completed quick scan is on record.' 'Windows Security > Virus & threat protection > Quick scan (Defender normally schedules this itself when the PC is idle).'
        } elseif ($quickAge -gt 14) {
            Add-Finding 'Low' "The last quick scan was $quickAge days ago. Scheduled scans may not be getting a chance to run (PC asleep or off when idle)." 'Windows Security > Virus & threat protection > Quick scan, and leave the PC on and idle now and then.'
        }
    }
}

# --- Exclusions -----------------------------------------------------------------
Write-Section 'Exclusions'
$exclusionsHidden = $false
$exclusionCount = 0
if ($pref) {
    $kinds = [ordered]@{ 'Path' = 'ExclusionPath'; 'Extension' = 'ExclusionExtension'; 'Process' = 'ExclusionProcess'; 'IpAddress' = 'ExclusionIpAddress' }
    $labels = @{ 'Path' = 'Folders/files'; 'Extension' = 'Extensions'; 'Process' = 'Processes'; 'IpAddress' = 'IP addresses' }
    foreach ($k in $kinds.Keys) {
        $raw = Get-Prop $pref $kinds[$k]
        if (Test-Hidden $raw) { $exclusionsHidden = $true; continue }
        $items = @(Get-CleanList $raw)
        if ($items.Count -eq 0) { continue }
        Write-Host ("  {0} ({1}):" -f $labels[$k], $items.Count) -ForegroundColor Gray
        foreach ($item in $items) {
            $exclusionCount++
            $risk = Get-ExclusionRisk $k $item
            if ($risk) {
                Write-Host ("    {0,-60} RISKY: {1}" -f $item, $risk[1]) -ForegroundColor $(if ($risk[0] -eq 'High') { 'Red' } else { 'Yellow' })
                $param = "-Exclusion$k"
                Add-Finding $risk[0] ("Defender exclusion '{0}' {1}." -f $item, $risk[1]) ("If you don't know why it is there, remove it: Windows Security > Virus & threat protection > Manage settings > Add or remove exclusions, or as admin: Remove-MpPreference {0} '{1}'" -f $param, ($item -replace "'", "''"))
                Add-Row 'Exclusion' $null $item $risk[0] $k $item $risk[1]
            } else {
                Write-Host ("    {0}" -f $item) -ForegroundColor Gray
                Add-Row 'Exclusion' $null $item '' $k $item ''
            }
        }
    }
    $asrOnly = Get-Prop $pref 'AttackSurfaceReductionOnlyExclusions'
    if (-not (Test-Hidden $asrOnly)) {
        $asrEx = @(Get-CleanList $asrOnly)
        if ($asrEx.Count -gt 0) {
            Write-Host ("  ASR-only exclusions ({0}):" -f $asrEx.Count) -ForegroundColor Gray
            foreach ($item in $asrEx) { Write-Host "    $item" -ForegroundColor Gray; Add-Row 'Exclusion' $null $item '' 'ASR only' $item '' }
        }
    }
    if ($exclusionsHidden) {
        Write-Host '  Exclusions are hidden: "N/A: Must be an administrator to view exclusions".' -ForegroundColor DarkYellow
        if ($isAdmin) {
            Write-Host '  You are admin, so a policy (HideExclusionsFromLocalAdmins) is hiding them, usually set by work or school management.' -ForegroundColor DarkGray
        } else {
            Write-Host "  $adminNote to see them. Malware often adds exclusions, so this is worth checking." -ForegroundColor DarkGray
        }
    } elseif ($exclusionCount -eq 0) {
        Write-Host '  No exclusions. Good.' -ForegroundColor Green
    }
} else {
    Write-Host '  Not available (Defender settings could not be read).' -ForegroundColor DarkGray
}

# --- Detections -----------------------------------------------------------------
Write-Section "Detections (last $Days days)"
$detections = New-Object System.Collections.Generic.List[object]
$detectionSource = ''
$threatById = @{}
if ($haveCmdlets) {
    try {
        foreach ($t in @(Get-MpThreat -ErrorAction Stop)) {
            $id = Get-Prop $t 'ThreatID'
            if ($null -ne $id) { $threatById[[string]$id] = $t }
        }
    } catch { }
    try {
        $all = @(Get-MpThreatDetection -ErrorAction Stop)
        $detectionSource = 'Get-MpThreatDetection'
        foreach ($d in $all) {
            $when = Get-Prop $d 'InitialDetectionTime'
            if (-not $when) { $when = Get-Prop $d 'LastThreatStatusChangeTime' }
            if (-not $when -or [datetime]$when -lt $cutoff) { continue }
            $tid = [string](Get-Prop $d 'ThreatID')
            $t = $null
            if ($threatById.ContainsKey($tid)) { $t = $threatById[$tid] }
            $name = [string](Get-Prop $t 'ThreatName'); if (-not $name) { $name = "Threat ID $tid" }
            $statusId = Get-Prop $d 'ThreatStatusID'
            $resources = @(Get-Prop $d 'Resources') | Where-Object { $_ } | ForEach-Object { Format-Resource ([string]$_) }
            $detections.Add([pscustomobject]@{
                Time     = [datetime]$when
                Name     = $name
                Severity = (Get-MapName $severityNames (Get-Prop $t 'SeverityID'))
                Category = (Get-MapName $categoryNames (Get-Prop $t 'CategoryID'))
                Resource = ($resources -join '; ')
                Action   = (Get-MapName $threatStatusNames $statusId)
                Success  = Get-Prop $d 'ActionSuccess'
                Process  = [string](Get-Prop $d 'ProcessName')
                Active   = [bool](Get-Prop $t 'IsActive')
            })
        }
    } catch {
        Write-Host "  Could not read detection history: $($_.Exception.Message)" -ForegroundColor DarkYellow
        if (-not $isAdmin) { Write-Host "  $adminNote for detection history; falling back to the event log." -ForegroundColor DarkGray }
    }
}

# --- Read the Defender event log ---------------------------------------------------
$eventInfo = @{
    1002 = @('Scan stopped before finishing', 'Scan')
    1005 = @('Scan failed', 'Scan')
    1006 = @('Malware found', 'Detection');          1116 = @('Malware found', 'Detection')
    1007 = @('Action taken on malware', 'Detection'); 1117 = @('Action taken on malware', 'Detection')
    1008 = @('Action on malware FAILED', 'Detection'); 1118 = @('Action on malware FAILED', 'Detection')
    1119 = @('Critical error acting on malware', 'Detection')
    1015 = @('Suspicious behavior detected', 'Detection')
    1121 = @('ASR rule blocked', 'ASR');             1122 = @('ASR rule audited', 'ASR')
    1123 = @('Controlled Folder Access blocked', 'CFA'); 1124 = @('Controlled Folder Access audited', 'CFA')
    1125 = @('Network protection audited', 'Network'); 1126 = @('Network protection blocked', 'Network')
    2001 = @('Signature update failed', 'Update')
    2003 = @('Engine update failed', 'Update')
    2004 = @('Signatures failed to load (reverted)', 'Update')
    2006 = @('Platform update failed', 'Update')
    3002 = @('Real-time protection error', 'Error')
    5001 = @('Real-time protection DISABLED', 'Protection')
    5004 = @('Real-time protection config changed', 'Config')
    5007 = @('Configuration changed', 'Config')
    5008 = @('Engine failure', 'Error')
    5010 = @('Spyware scanning DISABLED', 'Protection')
    5012 = @('Virus scanning DISABLED', 'Protection')
    5013 = @('Tamper protection blocked a change', 'Tamper')
}
$events = New-Object System.Collections.Generic.List[object]
$eventsOk = $false
$eventsTruncated = $false
try {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; StartTime = $cutoff } -MaxEvents $maxEvents -ErrorAction Stop)
    $eventsOk = $true
    if ($ev.Count -ge $maxEvents) { $eventsTruncated = $true }
    foreach ($e in $ev) {
        $id = [int]$e.Id
        if (-not $eventInfo.ContainsKey($id)) { continue }
        $d = Get-EventData $e
        $msg = ''
        try { $msg = [string]$e.Message } catch { }
        $detail = ''; $resource = ''
        switch ($id) {
            { $_ -in 1121, 1122 } {
                $rid = (Get-Field $d @('ID')).ToLower()
                $rname = if ($asrNames.ContainsKey($rid)) { $asrNames[$rid] } else { $rid }
                $resource = Get-Field $d @('Path')
                $detail = "{0}; by {1}" -f $rname, (Get-Field $d @('Process Name'))
            }
            { $_ -in 1123, 1124, 1125, 1126 } {
                $resource = Get-Field $d @('Path', 'Remote Address', 'Domain')
                $detail = 'by ' + (Get-Field $d @('Process Name'))
            }
            { $_ -in 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119 } {
                $resource = Format-Resource (Get-Field $d @('Path'))
                $detail = "{0} ({1}); action: {2}" -f (Get-Field $d @('Threat Name')), (Get-Field $d @('Severity Name')), (Get-Field $d @('Action Name'))
            }
            5007 {
                $old = Get-Field $d @('Old Value'); $new = Get-Field $d @('New Value')
                $resource = $(if ($new) { $new } else { $old })
                $detail = $(if ($old -and $new) { "changed from: $old" } elseif ($new) { 'added/set' } else { 'removed' })
            }
            default {
                $detail = Get-Field $d @('Error Description', 'Error Code', 'Feature Name', 'Reason')
            }
        }
        if (-not $detail -or $detail -match '^(by |; by )?$') { $detail = Get-FirstLine $msg }
        $events.Add([pscustomobject]@{
            Time = $e.TimeCreated; Id = $id; Name = $eventInfo[$id][0]; Group = $eventInfo[$id][1]
            Resource = $resource; Detail = $detail; Data = $d
        })
    }
} catch {
    if ($_.Exception.Message -match 'No events were found') { $eventsOk = $true }
    else {
        Write-Host "  Could not read the Defender event log: $($_.Exception.Message)" -ForegroundColor DarkYellow
        if (-not $isAdmin) { Write-Host "  $adminNote if the log is restricted on this PC." -ForegroundColor DarkGray }
    }
}

# Fall back to detection events when the detection history could not be read.
if (-not $detectionSource -and $events.Count -gt 0) {
    $detectionSource = 'event log'
    foreach ($e in ($events | Where-Object { $_.Id -in 1116, 1117, 1118, 1119, 1006, 1007, 1008 })) {
        $action = switch ($e.Id) { { $_ -in 1116, 1006 } { 'Detected' } { $_ -in 1117, 1007 } { Get-Field $e.Data @('Action Name') } default { 'Action failed' } }
        $sev = Get-Field $e.Data @('Severity Name'); if (-not $sev) { $sev = 'Unknown' }
        $cat = Get-Field $e.Data @('Category Name'); if (-not $cat) { $cat = 'Unknown' }
        $detections.Add([pscustomobject]@{
            Time = $e.Time; Name = (Get-Field $e.Data @('Threat Name')); Severity = $sev; Category = $cat
            Resource = $e.Resource; Action = $action; Success = $(if ($e.Id -in 1118, 1119, 1008) { $false } else { $null })
            Process = (Get-Field $e.Data @('Process Name')); Active = $false
        })
    }
}

if ($detections.Count -eq 0) {
    if ($detectionSource) { Write-Host '  No threats detected in this window.' -ForegroundColor Green }
    else { Write-Host '  Detection history not available.' -ForegroundColor DarkGray }
} else {
    Write-Host ("  Source: {0}" -f $detectionSource) -ForegroundColor DarkGray
    $groups = @($detections | Group-Object Name, Resource, Action | Sort-Object { ($_.Group | Measure-Object Time -Maximum).Maximum } -Descending)
    Write-Host ("  {0,-38} {1,-9} {2,-22} {3,-18} {4,4}  {5,-16}" -f 'Threat', 'Severity', 'Category', 'Action', 'Seen', 'Last') -ForegroundColor DarkGray
    $show = if ($Detailed) { $groups } else { $groups | Select-Object -First $top }
    foreach ($g in $show) {
        $s = $g.Group[0]
        $last = ($g.Group | Measure-Object Time -Maximum).Maximum
        $failed = ($s.Action -match 'fail|Abandoned') -or ($s.Success -eq $false)
        $color = if ($failed -or $s.Action -eq 'Allowed' -or $s.Active) { 'Red' } elseif ($s.Severity -in 'High', 'Severe') { 'Yellow' } else { 'Gray' }
        $actionText = $s.Action + $(if ($s.Success -eq $false -and $s.Action -notmatch 'fail') { ' (FAILED)' } else { '' })
        Write-Host ("  {0,-38} {1,-9} {2,-22} {3,-18} {4,4}  {5:yyyy-MM-dd HH:mm}" -f (Limit-Text $s.Name 38), (Limit-Text $s.Severity 9), (Limit-Text $s.Category 22), (Limit-Text $actionText 18), $g.Count, $last) -ForegroundColor $color
        if ($s.Resource) { Write-Host ("      {0}" -f $s.Resource) -ForegroundColor DarkGray }
    }
    if (-not $Detailed -and $groups.Count -gt $top) { Write-Host ("  ... {0} more (use -Detailed)" -f ($groups.Count - $top)) -ForegroundColor DarkGray }
    if ($Detailed) {
        Write-Host ''
        Write-Host '  Every detection:' -ForegroundColor DarkGray
        foreach ($d in ($detections | Sort-Object Time -Descending)) {
            Write-Host ("    {0:yyyy-MM-dd HH:mm}  {1,-38} {2,-18} {3}" -f $d.Time, (Limit-Text $d.Name 38), (Limit-Text $d.Action 18), $d.Resource) -ForegroundColor Gray
        }
    }

    foreach ($d in $detections) {
        Add-Row 'Detection' $d.Time $d.Name $d.Severity $d.Action $d.Resource ("Category: {0}; Success: {1}; Process: {2}" -f $d.Category, $d.Success, $d.Process)
    }
    $failedDet = @($detections | Where-Object { $_.Action -match 'fail|Abandoned' -or $_.Success -eq $false } | Select-Object -ExpandProperty Name -Unique)
    if ($failedDet.Count -gt 0) {
        Add-Finding 'High' ("Defender could not finish removing: {0}." -f ($failedDet -join ', ')) 'Run a Microsoft Defender Offline scan: Windows Security > Virus & threat protection > Scan options > Microsoft Defender Offline scan > Scan now (the PC restarts). Then check Protection history.'
    }
    $allowedDet = @($detections | Where-Object { $_.Action -eq 'Allowed' } | Select-Object -ExpandProperty Name -Unique)
    if ($allowedDet.Count -gt 0) {
        Add-Finding 'High' ("Detected threat(s) were ALLOWED to stay: {0}." -f ($allowedDet -join ', ')) 'Windows Security > Virus & threat protection > Protection history > open the item and choose Remove, unless you are certain it is a tool you trust.'
    }
    $active = @($detections | Where-Object { $_.Active } | Select-Object -ExpandProperty Name -Unique)
    if ($active.Count -gt 0) {
        Add-Finding 'High' ("Defender still lists these threats as active: {0}." -f ($active -join ', ')) 'Windows Security > Virus & threat protection > Current threats > Start actions; if they come back, run a Microsoft Defender Offline scan.'
    }
    $repeat = @($groups | Where-Object { $_.Count -ge 3 })
    foreach ($g in ($repeat | Select-Object -First 3)) {
        Add-Finding 'Medium' ("'{0}' was detected {1} times, so something keeps bringing it back{2}." -f $g.Group[0].Name, $g.Count, $(if ($g.Group[0].Resource) { " ($($g.Group[0].Resource))" } else { '' })) 'Look for the program or browser extension that downloads it (Find-SuspiciousStartup.ps1, Get-BrowserExtensions.ps1) and run a Microsoft Defender Offline scan.'
    }
}

# Threats you told Defender to allow (Allowed threats / per-threat default action overrides).
if ($pref) {
    $ids = @(Get-Prop $pref 'ThreatIDDefaultAction_Ids')
    $acts = @(Get-Prop $pref 'ThreatIDDefaultAction_Actions')
    $allowed = @()
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($null -eq $ids[$i] -or [string]$ids[$i] -match '^N/A') { continue }
        $a = if ($i -lt $acts.Count) { $acts[$i] } else { $null }
        $aName = Get-MapName $defaultActionNames $a
        if ($aName -in 'Allow', 'No action') {
            $tName = if ($threatById.ContainsKey([string]$ids[$i])) { [string](Get-Prop $threatById[[string]$ids[$i]] 'ThreatName') } else { "Threat ID $($ids[$i])" }
            $allowed += "$tName ($aName)"
        }
    }
    if ($allowed.Count -gt 0) {
        Write-Host ''
        Write-Host ("  Allowed threats ({0}):" -f $allowed.Count) -ForegroundColor Yellow
        foreach ($a in $allowed) { Write-Host "    $a" -ForegroundColor Yellow }
        Add-Finding 'Medium' ("{0} threat(s) are on Defender's allowed list: {1}." -f $allowed.Count, ($allowed -join ', ')) 'If you did not allow these on purpose: Windows Security > Virus & threat protection > Protection history > Allowed threats > Don''t allow. Or, as admin: Remove-MpPreference -ThreatIDDefaultAction_Ids <id>'
    }
}

# --- Events -----------------------------------------------------------------------
Write-Section "Events (last $Days days)"
if (-not $eventsOk) {
    Write-Host '  The Defender event log could not be read.' -ForegroundColor DarkGray
} elseif ($events.Count -eq 0) {
    Write-Host '  No notable Defender events in this window.' -ForegroundColor Green
} else {
    if ($eventsTruncated) { Write-Host ("  Only the newest {0} events were read." -f $maxEvents) -ForegroundColor DarkYellow }
    $byId = @($events | Group-Object Id | Sort-Object Count -Descending)
    Write-Host ("  {0,-6} {1,-42} {2,6}  {3,-16}" -f 'ID', 'Event', 'Count', 'Last') -ForegroundColor DarkGray
    foreach ($g in $byId) {
        $s = $g.Group[0]
        $last = ($g.Group | Measure-Object Time -Maximum).Maximum
        $color = switch ($s.Group) { 'Protection' { 'Red' } 'Tamper' { 'Yellow' } 'Update' { 'Yellow' } 'Error' { 'Yellow' } 'Detection' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  {0,-6} {1,-42} {2,6}  {3:yyyy-MM-dd HH:mm}" -f $s.Id, $s.Name, $g.Count, $last) -ForegroundColor $color
    }

    # Exclusion-related configuration changes are worth seeing one by one.
    $exChanges = @($events | Where-Object { $_.Id -eq 5007 -and $_.Resource -match '\\Exclusions\\' })
    if ($exChanges.Count -gt 0) {
        Write-Host ''
        Write-Host ("  Exclusion changes ({0}):" -f $exChanges.Count) -ForegroundColor Yellow
        foreach ($c in ($exChanges | Sort-Object Time -Descending | Select-Object -First $(if ($Detailed) { 100000 } else { $top }))) {
            $what = ($c.Resource -replace '^.*\\Exclusions\\', '') -replace '\s*=\s*0x0\s*$', ''
            Write-Host ("    {0:yyyy-MM-dd HH:mm}  {1,-12} {2}" -f $c.Time, $c.Detail, $what) -ForegroundColor Yellow
        }
    }
    # ASR / CFA / network protection blocks, grouped by what was blocked.
    $blocks = @($events | Where-Object { $_.Group -in 'ASR', 'CFA', 'Network' })
    if ($blocks.Count -gt 0) {
        Write-Host ''
        Write-Host '  Blocks and audits:' -ForegroundColor Gray
        foreach ($g in (@($blocks | Group-Object Name, Resource, Detail | Sort-Object Count -Descending) | Select-Object -First $(if ($Detailed) { 100000 } else { $top }))) {
            $s = $g.Group[0]
            Write-Host ("    {0,-34} {1,4}x  {2}  ({3})" -f $s.Name, $g.Count, $s.Resource, $s.Detail) -ForegroundColor Gray
        }
    }
    if ($Detailed) {
        Write-Host ''
        Write-Host '  Every event:' -ForegroundColor DarkGray
        foreach ($e in ($events | Sort-Object Time -Descending)) {
            Write-Host ("    {0:yyyy-MM-dd HH:mm}  {1,-5} {2,-36} {3} {4}" -f $e.Time, $e.Id, $e.Name, $e.Resource, $e.Detail).TrimEnd() -ForegroundColor Gray
        }
    }

    foreach ($e in $events) { Add-Row 'Event' $e.Time ("{0} {1}" -f $e.Id, $e.Name) '' $e.Group $e.Resource $e.Detail }

    $count = { param($ids) @($events | Where-Object { $_.Id -in $ids }).Count }
    $n = & $count @(5001, 5010, 5012)
    if ($n -gt 0) {
        $lastOff = ($events | Where-Object { $_.Id -in 5001, 5010, 5012 } | Measure-Object Time -Maximum).Maximum
        Add-Finding 'High' ("Defender protection was switched off {0} time(s), last on {1:yyyy-MM-dd HH:mm}. If that wasn't you, something may be disabling it." -f $n, $lastOff) 'Turn Tamper Protection on (Windows Security > Virus & threat protection > Manage settings), then run a Microsoft Defender Offline scan.'
    }
    $n = & $count @(5013)
    if ($n -gt 0) {
        Add-Finding 'Medium' "Tamper protection blocked $n attempt(s) to change Defender settings. Usually a 'tweak' tool or script, occasionally malware." 'Check what you ran around those times; if nothing, run a Microsoft Defender Offline scan.'
    }
    $exAdds = @($exChanges | Where-Object { $_.Detail -eq 'added/set' })
    if ($exAdds.Count -gt 0) {
        Add-Finding 'Medium' ("{0} Defender exclusion(s) were added in the last {1} days. Malware often adds exclusions for itself." -f $exAdds.Count, $Days) 'Review them under Exclusions (as admin) and remove any you did not add: Remove-MpPreference -ExclusionPath ''<path>'''
    }
    $n = & $count @(2001, 2003, 2004, 2006)
    if ($n -gt 0) {
        $lvl = if ($null -ne $sigAge -and $sigAge -gt 3) { 'High' } else { 'Low' }
        Add-Finding $lvl "Defender updates failed $n time(s) (signature, engine or platform)." 'Settings > Windows Update > Check for updates. If it keeps failing, check the PC can reach Windows Update (proxy, VPN, DNS filter) and that the date and time are correct.'
    }
    $n = & $count @(3002, 5008)
    if ($n -gt 0) {
        Add-Finding 'Medium' "Defender's engine or real-time protection reported $n error(s)." 'Install all Windows updates and restart. If errors continue, as admin: "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -GetFiles and look at the support log.'
    }
    $n = & $count @(1005)
    if ($n -gt 0) {
        Add-Finding 'Low' "$n Defender scan(s) failed." 'Run a quick scan from Windows Security; if it fails again, install updates and restart.'
    }
    $n = & $count @(1123)
    if ($n -gt 0) {
        $apps = @($events | Where-Object { $_.Id -eq 1123 } | ForEach-Object { $_.Detail -replace '^by ', '' } | Where-Object { $_ } | Select-Object -Unique)
        Add-Finding 'Low' ("Controlled Folder Access blocked {0} change(s) to protected folders, by: {1}." -f $n, (($apps | Select-Object -First 5) -join ', ')) 'If an app you trust was blocked: Windows Security > Virus & threat protection > Ransomware protection > Allow an app through Controlled folder access.'
    }
    $n = & $count @(1121)
    if ($n -gt 0) {
        Add-Finding 'Low' "Attack Surface Reduction rules blocked $n action(s). Usually good news; check none were apps you need." 'See the list under Events. To let a trusted file through one rule, as admin: Add-MpPreference -AttackSurfaceReductionOnlyExclusions ''<path>'''
    }
}

# --- Attack Surface Reduction -------------------------------------------------------
Write-Section 'Attack Surface Reduction'
$asr = [ordered]@{}
if ($pref) {
    $rids = @(Get-Prop $pref 'AttackSurfaceReductionRules_Ids')
    $racts = @(Get-Prop $pref 'AttackSurfaceReductionRules_Actions')
    for ($i = 0; $i -lt $rids.Count; $i++) {
        if (-not $rids[$i] -or [string]$rids[$i] -match '^N/A') { continue }
        $asr[([string]$rids[$i]).ToLower()] = @((Get-AsrActionName $(if ($i -lt $racts.Count) { $racts[$i] } else { $null })), 'local')
    }
}
# Rules set by Group Policy live under the Policies key.
foreach ($key in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules')) {
    try {
        $item = Get-ItemProperty -Path $key -ErrorAction Stop
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -match '^[0-9a-fA-F]{8}-') { $asr[$p.Name.ToLower()] = @((Get-AsrActionName $p.Value), 'policy') }
        }
    } catch { }
}
$asrOn = 0
if ($asr.Count -eq 0) {
    Write-Host '  No ASR rules configured (normal on home PCs; they are off by default).' -ForegroundColor DarkGray
} else {
    foreach ($id in $asr.Keys) {
        $name = if ($asrNames.ContainsKey($id)) { $asrNames[$id] } else { "Unknown rule $id" }
        $state = $asr[$id][0]
        if ($state -in 'Block', 'Warn') { $asrOn++ }
        $color = switch ($state) { 'Block' { 'Green' } 'Warn' { 'Green' } 'Audit' { 'Yellow' } default { 'DarkGray' } }
        Write-Host ("  {0,-68} {1,-15}{2}" -f $name, $state, $(if ($asr[$id][1] -eq 'policy') { ' (policy)' } else { '' })) -ForegroundColor $color
        if ($Detailed) { Write-Host ("      {0}" -f $id) -ForegroundColor DarkGray }
        $status.Add([pscustomobject]@{ Setting = "ASR: $name"; Value = $state })
    }
}
if ($asrOn -eq 0 -and -not ($mode -match 'Passive')) {
    Add-Finding 'Low' 'No Attack Surface Reduction rules are blocking. Three safe ones for most home PCs: credential stealing from LSASS, vulnerable signed drivers, and Office apps creating child processes.' 'As admin (try AuditMode first if you rely on Office macros): Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,56a863a9-875e-4185-98a7-b882c64b5ce5,d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled'
}

if ($pref) {
    $cfa = [string](Get-Prop $pref 'EnableControlledFolderAccess')
    $cfaText = switch ($cfa) { '0' { 'OFF' } '1' { 'On (block)' } '2' { 'Audit only' } '3' { 'Block disk changes only' } '4' { 'Audit disk changes only' }
                               'Disabled' { 'OFF' } 'Enabled' { 'On (block)' } 'AuditMode' { 'Audit only' } default { "unknown ($cfa)" } }
    $cfaApps = Get-Prop $pref 'ControlledFolderAccessAllowedApplications'
    $appsText = if (Test-Hidden $cfaApps) { 'hidden (admin needed)' } else { [string]@(Get-CleanList $cfaApps).Count }
    $folders = @(Get-CleanList (Get-Prop $pref 'ControlledFolderAccessProtectedFolders'))
    Write-Host ''
    Write-Line 'Controlled Folder Access' $cfaText $(if ($cfaText -eq 'On (block)') { 'Green' } else { 'DarkGray' })
    Write-Line 'CFA allowed apps' $appsText
    if ($folders.Count -gt 0) { Write-Line 'CFA extra protected folders' ([string]$folders.Count) }
    if ($Detailed -and -not (Test-Hidden $cfaApps)) { foreach ($a in (Get-CleanList $cfaApps)) { Write-Host "    allowed: $a" -ForegroundColor DarkGray } }
    if ($cfaText -eq 'OFF' -and -not ($mode -match 'Passive')) {
        Add-Finding 'Low' 'Controlled Folder Access (ransomware protection for Documents, Pictures and Desktop) is off.' 'Optional: Windows Security > Virus & threat protection > Ransomware protection > Manage ransomware protection > Controlled folder access: On. Expect to allow a few apps the first week.'
    }
    if (-not (Test-Hidden $cfaApps)) {
        foreach ($a in (Get-CleanList $cfaApps)) {
            if ($a -match $userWritablePattern) {
                Add-Finding 'Medium' "Controlled Folder Access allows '$a', which lives in a user-writable folder." "If you don't recognize it: Windows Security > Ransomware protection > Allow an app through Controlled folder access > remove it. Or, as admin: Remove-MpPreference -ControlledFolderAccessAllowedApplications '$($a -replace "'", "''")'"
            }
        }
    }
}

# --- Exports ----------------------------------------------------------------------
if ($CsvPath) {
    try {
        $rows | Sort-Object Type, @{ Expression = { $_.Time }; Descending = $true } | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host ''
        Write-Host "Saved $($rows.Count) rows to $CsvPath" -ForegroundColor Green
    } catch { Write-Host "Could not write CSV: $($_.Exception.Message)" -ForegroundColor Red }
}

$order = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
$sorted = @($findings | Sort-Object { $order[$_.Level] })

if ($HtmlPath) {
    try {
        $i = 0
        $fRows = @($sorted | ForEach-Object { $i++; [pscustomobject]@{ '#' = $i; Severity = $_.Level; Finding = $_.Text; Fix = $_.Fix } })
        $css = 'body{font-family:Segoe UI,Arial,sans-serif;margin:24px}table{border-collapse:collapse;margin-bottom:24px}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}th{background:#eee}'
        $body = New-Object System.Collections.Generic.List[string]
        $body.Add("<h1>Microsoft Defender report</h1><p>$(Get-Date -Format 'yyyy-MM-dd HH:mm') - last $Days days - admin: $isAdmin</p>")
        $body.Add('<h2>Status</h2>');     $body.Add((($status | ConvertTo-Html -Fragment) -join "`n"))
        $body.Add('<h2>Findings</h2>')
        if ($fRows.Count -gt 0) { $body.Add((($fRows | ConvertTo-Html -Fragment) -join "`n")) } else { $body.Add('<p>Nothing to fix.</p>') }
        $body.Add('<h2>Detections, events and exclusions</h2>')
        if ($rows.Count -gt 0) { $body.Add((($rows | ConvertTo-Html -Fragment) -join "`n")) } else { $body.Add('<p>None.</p>') }
        $body.Add('<p>Read-only report. Nothing was changed.</p>')
        ConvertTo-Html -Title 'Microsoft Defender report' -Head "<style>$css</style>" -Body ($body -join "`n") |
            Out-File -FilePath $HtmlPath -Encoding UTF8 -ErrorAction Stop
        Write-Host "Saved HTML report to $HtmlPath" -ForegroundColor Green
    } catch { Write-Host "Could not write HTML: $($_.Exception.Message)" -ForegroundColor Red }
}

# --- Findings ---------------------------------------------------------------------
Write-Section 'Findings'
if ($sorted.Count -eq 0) {
    Write-Host '  Nothing to fix. Defender looks healthy.' -ForegroundColor Green
} else {
    $i = 0
    foreach ($f in $sorted) {
        $i++
        $color = switch ($f.Level) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  {0}. [{1}] {2}" -f $i, $f.Level, $f.Text) -ForegroundColor $color
        Write-Host ("     Fix: {0}" -f $f.Fix) -ForegroundColor DarkGray
    }
}
if (-not $isAdmin) {
    Write-Host ''
    Write-Host '  Not admin: exclusions (and on some PCs detection history and the event log) are hidden. Run as admin for the full report.' -ForegroundColor DarkYellow
}
Write-Host ''
Write-Host 'Nothing was changed. Fixes above are suggestions only.' -ForegroundColor DarkGray
