<#
.SYNOPSIS
    Get-PrivacyReport.ps1 - Shows which apps used your camera, microphone,
    location and other private data recently (including any using them right
    now), which apps are allowed to, and how Windows 11's own privacy settings
    are set. Read-only.

.DESCRIPTION
    Windows quietly records the last time each app used the camera, microphone,
    location and other sensitive features. Settings only shows a little of it.
    This script reads that record from the registry and prints it plainly, so
    you can answer "what turned my webcam light on?" or "why does this app need
    my location?".

    Reports:
      Recent use    Apps that used a sensitive feature in the last -Days days,
                    newest first, with "IN USE NOW" for anything active right
                    now. Desktop apps show their full path.
      Access        For each feature: whether it's on for the PC and for your
                    account, and how many apps are allowed or denied.
      Settings      Diagnostic data level, advertising ID, tailored
                    experiences, online speech recognition, inking and typing
                    data, website language list, app-launch tracking, Start and
                    lock screen suggestions, and whether Recall has saved
                    snapshots on this PC.
      Findings      Numbered, plain-English list of what to review first, such
                    as a desktop app using the microphone from a Temp or
                    Downloads folder, or an app whose file no longer exists.

    Features checked: camera, microphone, location, screen capture, contacts,
    calendar, call history, email, messages, tasks, notifications, account
    info, documents, pictures, videos, whole file system, radios (Bluetooth and
    Wi-Fi on/off), app diagnostics, presence sensing and motion activity.

    Safety level : READ-ONLY. Reads the registry and checks whether files exist.
                   Changes nothing and makes no network calls. Writes a file
                   only if you pass -CsvPath.
    Admin        : Not required. Only your own account's usage is read.

.USAGE
    powershell -ExecutionPolicy Bypass -File .\04_Security\Get-PrivacyReport.ps1
    powershell -ExecutionPolicy Bypass -File .\04_Security\Get-PrivacyReport.ps1 -Days 7 -Feature Camera,Microphone
    powershell -ExecutionPolicy Bypass -File .\04_Security\Get-PrivacyReport.ps1 -ShowAll -CsvPath "$env:USERPROFILE\Desktop\privacy.csv"

.PARAMETER Days
    How far back "Recent use" looks, 1 to 3650 (default 30).

.PARAMETER Feature
    Only check these features. Any of: Camera, Microphone, Location,
    ScreenCapture, Contacts, Calendar, CallHistory, Email, Messages, Tasks,
    Notifications, AccountInfo, Documents, Pictures, Videos, FileSystem,
    Radios, AppDiagnostics, Presence, Activity. Default: all.

.PARAMETER ShowAll
    Also list every app with a saved allow/deny choice, used or not.

.PARAMETER CsvPath
    Export every app entry (feature, app, type, allowed, last used, in use now,
    path exists) to this CSV file.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$Days = 30,
    [ValidateSet('Camera','Microphone','Location','ScreenCapture','Contacts','Calendar',
                 'CallHistory','Email','Messages','Tasks','Notifications','AccountInfo',
                 'Documents','Pictures','Videos','FileSystem','Radios','AppDiagnostics',
                 'Presence','Activity')]
    [string[]]$Feature,
    [switch]$ShowAll,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

# Friendly name -> ConsentStore key name, and how sensitive it is (High shows in findings)
$Features = [ordered]@{
    Camera         = @{ Key = 'webcam';                        Level = 'High' }
    Microphone     = @{ Key = 'microphone';                    Level = 'High' }
    Location       = @{ Key = 'location';                      Level = 'High' }
    ScreenCapture  = @{ Key = 'graphicsCaptureProgrammatic';   Level = 'High' }
    Contacts       = @{ Key = 'contacts';                      Level = 'Medium' }
    Calendar       = @{ Key = 'appointments';                  Level = 'Medium' }
    CallHistory    = @{ Key = 'phoneCallHistory';              Level = 'Medium' }
    Email          = @{ Key = 'email';                         Level = 'Medium' }
    Messages       = @{ Key = 'chat';                          Level = 'Medium' }
    Tasks          = @{ Key = 'userDataTasks';                 Level = 'Low' }
    Notifications  = @{ Key = 'userNotificationListener';      Level = 'Medium' }
    AccountInfo    = @{ Key = 'userAccountInformation';        Level = 'Low' }
    Documents      = @{ Key = 'documentsLibrary';              Level = 'Medium' }
    Pictures       = @{ Key = 'picturesLibrary';               Level = 'Medium' }
    Videos         = @{ Key = 'videosLibrary';                 Level = 'Low' }
    FileSystem     = @{ Key = 'broadFileSystemAccess';         Level = 'Medium' }
    Radios         = @{ Key = 'radios';                        Level = 'Low' }
    AppDiagnostics = @{ Key = 'appDiagnostics';                Level = 'Low' }
    Presence       = @{ Key = 'humanPresence';                 Level = 'Low' }
    Activity       = @{ Key = 'activity';                      Level = 'Low' }
}
if ($Feature) { foreach ($k in @($Features.Keys)) { if ($Feature -notcontains $k) { $Features.Remove($k) } } }

$userStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
$pcStore   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
$cutoff    = (Get-Date).AddDays(-$Days)
$findings  = [System.Collections.Generic.List[object]]::new()

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}
function Add-Finding([string]$Severity, [string]$Text, [string]$Fix) {
    $findings.Add([pscustomobject]@{ Severity = $Severity; Text = $Text; Fix = $Fix })
}
function Get-RegValue([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}
function ConvertFrom-FileTimeSafe($Value) {
    if ($null -eq $Value) { return $null }
    try { $v = [int64]$Value } catch { return $null }
    if ($v -le 0) { return $null }
    try { [DateTime]::FromFileTime($v) } catch { $null }
}
function Format-Age($When) {
    if (-not $When) { return 'never' }
    $span = (Get-Date) - $When
    if ($span.TotalMinutes -lt 1) { return 'just now' }
    if ($span.TotalHours -lt 1)   { return ('{0} min ago' -f [int]$span.TotalMinutes) }
    if ($span.TotalDays -lt 1)    { return ('{0} h ago' -f [int]$span.TotalHours) }
    return ('{0} days ago' -f [int][math]::Floor($span.TotalDays))
}

# Map package family names to a readable package name (current user only, no admin)
$pkgNames = @{}
try {
    foreach ($p in Get-AppxPackage -ErrorAction Stop) {
        if ($p.PackageFamilyName -and -not $pkgNames.ContainsKey($p.PackageFamilyName)) {
            $pkgNames[$p.PackageFamilyName] = $p.Name
        }
    }
} catch { Write-Verbose "Get-AppxPackage failed: $_" }

Write-Host 'Privacy report (read-only)' -ForegroundColor White
Write-Host ("Computer time: {0:yyyy-MM-dd HH:mm}   Recent use window: last {1} days" -f (Get-Date), $Days)

# ------------------------------------------------------------------ collect
$entries = [System.Collections.Generic.List[object]]::new()
$access  = [System.Collections.Generic.List[object]]::new()

foreach ($name in $Features.Keys) {
    $key     = $Features[$name].Key
    $level   = $Features[$name].Level
    $userKey = "$userStore\$key"
    $pcKey   = "$pcStore\$key"

    $pcValue   = Get-RegValue $pcKey 'Value'
    $userValue = Get-RegValue $userKey 'Value'
    $allowed = 0; $denied = 0

    if (Test-Path -LiteralPath $userKey) {
        $children = @(Get-ChildItem -LiteralPath $userKey -ErrorAction SilentlyContinue)
        $appKeys  = [System.Collections.Generic.List[object]]::new()
        foreach ($c in $children) {
            if ($c.PSChildName -eq 'NonPackaged') {
                foreach ($np in @(Get-ChildItem -LiteralPath $c.PSPath -ErrorAction SilentlyContinue)) {
                    $appKeys.Add(@{ Item = $np; Type = 'Desktop app' })
                }
            } else {
                $appKeys.Add(@{ Item = $c; Type = 'Store app' })
            }
        }

        foreach ($a in $appKeys) {
            $item  = $a.Item
            $raw   = $item.PSChildName
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction Stop } catch { continue }

            $value = $null; $startRaw = $null; $stopRaw = $null
            if ($props.PSObject.Properties['Value'])             { $value    = $props.Value }
            if ($props.PSObject.Properties['LastUsedTimeStart']) { $startRaw = $props.LastUsedTimeStart }
            if ($props.PSObject.Properties['LastUsedTimeStop'])  { $stopRaw  = $props.LastUsedTimeStop }
            $start = ConvertFrom-FileTimeSafe $startRaw
            $stop  = ConvertFrom-FileTimeSafe $stopRaw
            $inUse = [bool]($start -and -not $stop)
            $last  = if ($stop) { $stop } else { $start }

            if ($value -eq 'Allow') { $allowed++ } elseif ($value -eq 'Deny') { $denied++ }

            if ($a.Type -eq 'Desktop app') {
                $path    = $raw -replace '#', '\'
                $display = Split-Path -Leaf $path
                $exists  = Test-Path -LiteralPath $path
            } else {
                $path    = $raw
                $display = if ($pkgNames.ContainsKey($raw)) { $pkgNames[$raw] } else { ($raw -split '_')[0] }
                $exists  = $pkgNames.Count -eq 0 -or $pkgNames.ContainsKey($raw)
            }

            $entries.Add([pscustomobject]@{
                Feature    = $name
                Level      = $level
                App        = $display
                Type       = $a.Type
                Allowed    = if ($value) { $value } else { '' }
                LastUsed   = $last
                InUseNow   = $inUse
                PathExists = $exists
                Path       = $path
            })
        }
    }

    $access.Add([pscustomobject]@{
        Feature    = $name
        ForPC      = if ($pcValue -eq 'Deny') { 'Off' } elseif ($pcValue -eq 'Allow') { 'On' } else { 'Default' }
        ForYou     = if ($userValue -eq 'Deny') { 'Off' } elseif ($userValue -eq 'Allow') { 'On' } else { 'Default' }
        AppsAllowed = $allowed
        AppsDenied  = $denied
    })
}

# ------------------------------------------------------------------ recent use
Write-Section "Recent use (last $Days days)"
$recent = @($entries | Where-Object { $_.InUseNow -or ($_.LastUsed -and $_.LastUsed -ge $cutoff) } |
            Sort-Object @{ Expression = 'InUseNow'; Descending = $true }, @{ Expression = 'LastUsed'; Descending = $true })
if ($recent.Count -eq 0) {
    Write-Host '  No app used these features in this window.' -ForegroundColor Green
} else {
    $recent | Select-Object Feature, App, Type,
        @{ N = 'When'; E = { if ($_.InUseNow) { 'IN USE NOW' } else { '{0:yyyy-MM-dd HH:mm} ({1})' -f $_.LastUsed, (Format-Age $_.LastUsed) } } },
        @{ N = 'Where'; E = { if ($_.Type -eq 'Desktop app') { $_.Path } else { '' } } } |
        Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
}

# ------------------------------------------------------------------ access
Write-Section 'Access by feature'
Write-Host '  ForPC / ForYou: Off means turned off in Settings > Privacy & security for the whole PC or for your account.' -ForegroundColor DarkGray
$access | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

if ($ShowAll) {
    Write-Section 'Every saved app choice'
    $entries | Sort-Object Feature, App | Select-Object Feature, App, Type, Allowed,
        @{ N = 'LastUsed'; E = { if ($_.InUseNow) { 'IN USE NOW' } elseif ($_.LastUsed) { '{0:yyyy-MM-dd HH:mm}' -f $_.LastUsed } else { 'never' } } },
        PathExists |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host
}

# ------------------------------------------------------------------ settings
Write-Section 'Windows privacy settings'
$settings = [System.Collections.Generic.List[object]]::new()
function Add-Setting([string]$Name, [string]$State, [bool]$Shares, [string]$Where) {
    $settings.Add([pscustomobject]@{ Setting = $Name; State = $State; SharesMore = $(if ($Shares) { 'Yes' } else { '' }); WhereToChange = $Where })
}

$telPolicy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry'
$telLocal  = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' 'AllowTelemetry'
$tel = if ($null -ne $telPolicy) { $telPolicy } else { $telLocal }
$telText = switch ($tel) { 0 { 'Off / security only (policy)' } 1 { 'Required only' } 2 { 'Enhanced (legacy)' } 3 { 'Optional (full)' } default { 'Not set (Windows default)' } }
Add-Setting 'Diagnostic data' $telText ($tel -ge 2) 'Settings > Privacy & security > Diagnostics & feedback'

$adId = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled'
Add-Setting 'Advertising ID' $(if ($adId -eq 0) { 'Off' } elseif ($adId -eq 1) { 'On' } else { 'Not set' }) ($adId -eq 1) 'Settings > Privacy & security > General'

$tailored = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled'
Add-Setting 'Tailored experiences' $(if ($tailored -eq 0) { 'Off' } elseif ($tailored -eq 1) { 'On' } else { 'Not set' }) ($tailored -eq 1) 'Settings > Privacy & security > Diagnostics & feedback'

$speech = Get-RegValue 'HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' 'HasAccepted'
Add-Setting 'Online speech recognition' $(if ($speech -eq 1) { 'On' } else { 'Off' }) ($speech -eq 1) 'Settings > Privacy & security > Speech'

$ink  = Get-RegValue 'HKCU:\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection'
$text = Get-RegValue 'HKCU:\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection'
$inkOn = -not ($ink -eq 1 -and $text -eq 1)
Add-Setting 'Inking & typing personalization' $(if ($inkOn) { 'On' } else { 'Off' }) $inkOn 'Settings > Privacy & security > Inking & typing personalization'

$lang = Get-RegValue 'HKCU:\Control Panel\International\User Profile' 'HttpAcceptLanguageOptOut'
Add-Setting 'Websites see your language list' $(if ($lang -eq 1) { 'Off' } else { 'On' }) $false 'Settings > Privacy & security > General'

$track = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_TrackProgs'
Add-Setting 'Track app launches (Start and search)' $(if ($track -eq 0) { 'Off' } else { 'On' }) $false 'Settings > Privacy & security > General'

$cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$sugg = @('SubscribedContent-338388Enabled', 'SubscribedContent-338393Enabled', 'SubscribedContent-353694Enabled', 'SoftLandingEnabled', 'RotatingLockScreenOverlayEnabled') |
        Where-Object { (Get-RegValue $cdm $_) -ne 0 }
Add-Setting 'Suggestions and tips (Start, Settings, lock screen)' $(if (@($sugg).Count -eq 0) { 'Off' } else { "On ($(@($sugg).Count) of 5)" }) $false 'Settings > Privacy & security > General, and Personalization > Lock screen'

$recallPolicy = Get-RegValue 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis'
if ($null -eq $recallPolicy) { $recallPolicy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis' }
$recallData = $false
try { $recallData = @(Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'CoreAIPlatform*\UKP') -ErrorAction SilentlyContinue).Count -gt 0 } catch { }
$recallText = if ($recallPolicy -eq 1) { 'Blocked by policy' } elseif ($recallData) { 'Has saved snapshots' } else { 'No snapshots found' }
Add-Setting 'Recall (Copilot+ PCs)' $recallText $recallData 'Settings > Privacy & security > Recall & snapshots'

$settings | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host

# ------------------------------------------------------------------ findings
foreach ($e in $entries) {
    if ($e.Type -ne 'Desktop app') { continue }
    $recentEnough = $e.InUseNow -or ($e.LastUsed -and $e.LastUsed -ge $cutoff)
    if (-not $recentEnough) { continue }
    if ($e.Path -match '\\(Temp|Downloads)\\' -and $e.Level -eq 'High') {
        Add-Finding 'High' "$($e.App) used the $($e.Feature.ToLower()) from an unusual folder: $($e.Path)" 'Programs rarely run from Temp or Downloads. Scan it with Microsoft Defender and uninstall it if you don''t recognize it.'
    } elseif (-not $e.PathExists -and $e.Level -eq 'High') {
        Add-Finding 'Medium' "$($e.App) used the $($e.Feature.ToLower()) $(Format-Age $e.LastUsed), but its file is gone: $($e.Path)" 'Often an updater or a portable app. If you don''t recognize it, run a full Defender scan.'
    }
}
$nowInUse = @($entries | Where-Object InUseNow)
foreach ($e in $nowInUse) {
    if ($e.Level -eq 'High') {
        Add-Finding 'Info' "$($e.App) is using the $($e.Feature.ToLower()) right now." 'Fine if you have it open on purpose. If not, close it, or deny it in Settings > Privacy & security.'
    }
}
foreach ($a in $access) {
    if ($Features[$a.Feature].Level -eq 'High' -and $a.ForPC -ne 'Off' -and $a.ForYou -ne 'Off' -and $a.AppsAllowed -ge 15) {
        Add-Finding 'Low' "$($a.AppsAllowed) apps are allowed to use the $($a.Feature.ToLower())." "Review the list in Settings > Privacy & security > $($a.Feature) and turn off the ones that don't need it."
    }
}
if ($tel -eq 3) { Add-Finding 'Low' 'Optional diagnostic data is on, so Windows sends more usage data to Microsoft.' 'Settings > Privacy & security > Diagnostics & feedback > turn off "Send optional diagnostic data".' }
if ($adId -eq 1) { Add-Finding 'Low' 'The advertising ID is on, so apps can show you ads based on your activity.' 'Settings > Privacy & security > General > turn off the first switch.' }
if ($recallData -and $recallPolicy -ne 1) { Add-Finding 'Info' 'Recall has saved snapshots of your screen on this PC.' 'Settings > Privacy & security > Recall & snapshots to pause it, filter apps and sites, or delete snapshots.' }

Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  Nothing stands out.' -ForegroundColor Green
} else {
    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $i = 0
    foreach ($f in ($findings | Sort-Object { $order[$_.Severity] })) {
        $i++
        $color = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'Yellow' } 'Low' { 'White' } default { 'Gray' } }
        Write-Host ("  {0}. [{1}] {2}" -f $i, $f.Severity, $f.Text) -ForegroundColor $color
        Write-Host ("     Fix: {0}" -f $f.Fix) -ForegroundColor DarkGray
    }
}

if ($CsvPath) {
    $entries | Select-Object Feature, App, Type, Allowed,
        @{ N = 'LastUsed'; E = { if ($_.LastUsed) { $_.LastUsed.ToString('yyyy-MM-dd HH:mm:ss') } else { '' } } },
        InUseNow, PathExists, Path |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Saved $($entries.Count) entries to $CsvPath" -ForegroundColor Green
}
Write-Host ''
Write-Host 'Nothing was changed.' -ForegroundColor DarkGray
