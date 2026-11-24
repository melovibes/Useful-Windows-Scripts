<#
.SYNOPSIS
    Find-Bloatware.ps1 - Lists the preinstalled, promoted and trial apps on a
    Windows 11 PC, how much space they take, whether they run in the
    background, and which Windows settings keep adding more. Read-only unless
    you pass -Remove.

.DESCRIPTION
    New Windows 11 PCs (and feature updates) come with apps most people never
    open: games and promos pinned to Start, Microsoft extras, trial antivirus
    and OEM utilities. This script finds them and sorts each one into:

      Safe to remove  Games, promos and ad-supported apps (Candy Crush,
                      Solitaire, TikTok, Disney+, Booking.com and similar)
      Optional        Microsoft extras that are fine to remove if you don't
                      use them (News, Weather, Tips, Clipchamp, Maps, Teams
                      personal, Feedback Hub and similar)
      Check first     Things some people rely on: Xbox apps (needed for some
                      PC games), Phone Link, OEM utilities that deliver driver
                      and firmware updates, trial antivirus that is your only
                      antivirus

    Reports:
      Store apps      Matched Store apps for your account with size, version
                      and whether they are running right now
      For new users   Apps provisioned for every new account (admin only);
                      these come back for each new user even if you remove
                      your own copy
      Desktop apps    Trialware and OEM bundles from Programs and Features,
                      with the uninstall command to run yourself
      Settings        Windows settings that silently install suggested apps,
                      show Start and lock screen ads, or turn on Widgets
      Findings        Plain-English summary with what to do first

    Safety level : SAFE by default (read-only). Nothing is removed, changed or
                   stopped unless you pass -Remove, which first asks you to
                   type YES and then asks about each app one by one. -Remove
                   only removes Store apps for your own account (the same as
                   right-click > Uninstall in Start). It never removes
                   provisioned packages, desktop programs, system or framework
                   packages, and never edits settings; for those it prints the
                   command or click path for you to use yourself.
                   Makes no network calls. The only file written is the
                   optional -CsvPath.

    Admin        : Not required. Run as admin to also see apps provisioned for
                   new users (Get-AppxProvisionedPackage needs admin).

.PARAMETER All
    List every removable Store app for your account, not just the matched ones
    (still skips framework, resource and system packages).

.PARAMETER NoSize
    Skip measuring each app's install folder (faster).

.PARAMETER Remove
    After typing YES, asks about each matched Store app (Safe to remove first,
    then Optional, then Check first) and removes the ones you answer "y" to,
    for your account only. Removed apps can be reinstalled from the
    Microsoft Store.

.PARAMETER CsvPath
    Export every app found (Store, provisioned and desktop) to this CSV file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-Bloatware.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-Bloatware.ps1 -All -CsvPath "$env:USERPROFILE\Desktop\apps.csv"

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Find-Bloatware.ps1 -Remove
#>

[CmdletBinding()]
param(
    [switch]$All,
    [switch]$NoSize,
    [switch]$Remove,
    [string]$CsvPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$findings = New-Object System.Collections.Generic.List[object]
$rows     = New-Object System.Collections.Generic.List[object]

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
function Get-Prop {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}
function Format-Size {
    param($Bytes)
    if ($null -eq $Bytes) { return '-' }
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}
function Get-FolderSize {
    param([string]$Path)
    if ($NoSize -or -not $Path) { return $null }
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
        if ($null -eq $sum) { return 0 }
        return [int64]$sum
    } catch { return $null }
}

function Get-SizeSum {
    param($Items)
    $total = [int64]0; $any = $false
    foreach ($i in @($Items)) { if ($null -ne $i -and $null -ne $i.SizeBytes) { $total += [int64]$i.SizeBytes; $any = $true } }
    if ($any) { return $total }
    return $null
}

# ---------- Known apps ----------
# Pattern (matched against the Store package name, or the desktop display name),
# friendly name, level, note.
$S = 'Safe to remove'; $O = 'Optional'; $C = 'Check first'
$knownStore = @(
    @('king.com.*',                          'King games (Candy Crush and others)', $S, 'Promoted game'),
    @('*CandyCrush*',                        'Candy Crush',                         $S, 'Promoted game'),
    @('*BubbleWitch*',                       'Bubble Witch',                        $S, 'Promoted game'),
    @('*MarchofEmpires*',                    'March of Empires',                    $S, 'Promoted game'),
    @('*HiddenCity*',                        'Hidden City',                         $S, 'Promoted game'),
    @('*Royal*Revolt*',                      'Royal Revolt',                        $S, 'Promoted game'),
    @('*Asphalt*',                           'Asphalt',                             $S, 'Promoted game'),
    @('Microsoft.MicrosoftSolitaireCollection','Solitaire Collection',              $S, 'Ad-supported game'),
    @('*Disney*',                            'Disney+',                             $S, 'Promoted app'),
    @('*SpotifyAB.SpotifyMusic*',            'Spotify (Store promo)',               $O, 'Keep if you use Spotify'),
    @('*TikTok*',                            'TikTok',                              $S, 'Promoted app'),
    @('*Facebook*',                          'Facebook',                            $S, 'Promoted app'),
    @('*Instagram*',                         'Instagram',                           $S, 'Promoted app'),
    @('*Netflix*',                           'Netflix',                             $O, 'Promoted app; keep if you use it'),
    @('*AmazonVideo*',                       'Prime Video',                         $O, 'Promoted app; keep if you use it'),
    @('*Hulu*',                              'Hulu',                                $O, 'Promoted app; keep if you use it'),
    @('*Twitter*',                           'X / Twitter',                         $O, 'Promoted app'),
    @('*LinkedInforWindows*',                'LinkedIn',                            $O, 'Promoted app'),
    @('*Booking*',                           'Booking.com',                         $S, 'Promoted app'),
    @('*McAfeeSecurity*',                    'McAfee (Store)',                      $C, 'Trial antivirus; remove only if Defender or another antivirus is on'),
    @('*Dolby*',                             'Dolby Access',                        $C, 'Needed for Dolby Atmos audio on some PCs'),
    @('Microsoft.BingNews',                  'News',                                $O, 'Microsoft extra'),
    @('Microsoft.BingWeather',               'Weather',                             $O, 'Microsoft extra'),
    @('Microsoft.BingFinance',               'Money',                               $O, 'Microsoft extra'),
    @('Microsoft.BingSports',                'Sports',                              $O, 'Microsoft extra'),
    @('Microsoft.BingSearch',                'Bing Search',                         $O, 'Microsoft extra'),
    @('Microsoft.GetHelp',                   'Get Help',                            $O, 'Microsoft extra'),
    @('Microsoft.Getstarted',                'Tips',                                $O, 'Microsoft extra'),
    @('Microsoft.WindowsFeedbackHub',        'Feedback Hub',                        $O, 'Microsoft extra'),
    @('Microsoft.People',                    'People',                              $O, 'Microsoft extra'),
    @('Microsoft.WindowsMaps',               'Maps',                                $O, 'Microsoft extra'),
    @('Microsoft.MixedReality.Portal',       'Mixed Reality Portal',                $O, 'Only needed for VR headsets'),
    @('Microsoft.Microsoft3DViewer',         '3D Viewer',                           $O, 'Microsoft extra'),
    @('Microsoft.Print3D',                   'Print 3D',                            $O, 'Microsoft extra'),
    @('Microsoft.SkypeApp',                  'Skype',                               $O, 'Skype was retired in 2025'),
    @('Microsoft.MicrosoftOfficeHub',        'Microsoft 365 (Office) hub',          $O, 'Launcher only; Office apps are separate'),
    @('Microsoft.Office.OneNote',            'OneNote for Windows 10',              $O, 'Old OneNote app'),
    @('Microsoft.ZuneMusic',                 'Media Player',                        $O, 'Default music player; keep if you play local music'),
    @('Microsoft.ZuneVideo',                 'Movies & TV',                         $O, 'Microsoft extra'),
    @('Clipchamp.Clipchamp',                 'Clipchamp',                           $O, 'Video editor'),
    @('MicrosoftTeams',                      'Teams (personal)',                    $O, 'Not the work/school Teams'),
    @('MSTeams',                             'Teams',                               $C, 'Keep if you use Teams for work'),
    @('Microsoft.Todos',                     'Microsoft To Do',                     $O, 'Microsoft extra'),
    @('Microsoft.PowerAutomateDesktop',      'Power Automate',                      $O, 'Microsoft extra'),
    @('Microsoft.OutlookForWindows',         'Outlook (new)',                       $O, 'Keep if you use it for mail'),
    @('Microsoft.windowscommunicationsapps', 'Mail and Calendar (old)',             $O, 'Retired; replaced by new Outlook'),
    @('Microsoft.Copilot',                   'Copilot',                             $O, 'Microsoft extra'),
    @('Microsoft.Windows.DevHome',           'Dev Home',                            $O, 'Retired developer dashboard'),
    @('Microsoft.WindowsSoundRecorder',      'Sound Recorder',                      $O, 'Microsoft extra'),
    @('Microsoft.YourPhone',                 'Phone Link',                          $C, 'Keep if you link your phone'),
    @('Microsoft.XboxApp',                   'Xbox Console Companion',              $O, 'Old Xbox app'),
    @('Microsoft.GamingApp',                 'Xbox app',                            $C, 'Needed for Game Pass PC games'),
    @('Microsoft.XboxGamingOverlay',         'Xbox Game Bar',                       $C, 'Used for game capture and some game overlays'),
    @('Microsoft.XboxGameOverlay',           'Xbox Game Bar plugin',                $C, 'Used by some games'),
    @('Microsoft.XboxSpeechToTextOverlay',   'Xbox speech overlay',                 $C, 'Used by some games'),
    @('Microsoft.Xbox.TCUI',                 'Xbox sign-in UI',                     $C, 'Needed by games that use Xbox sign-in'),
    @('Microsoft.XboxIdentityProvider',      'Xbox Identity Provider',              $C, 'Needed by games that use Xbox sign-in'),
    @('AD2F1837.*',                          'HP app',                              $C, 'OEM utility; some deliver drivers and BIOS updates'),
    @('DellInc.*',                           'Dell app',                            $C, 'OEM utility; some deliver drivers and BIOS updates'),
    @('E046963F.*',                          'Lenovo app',                          $C, 'OEM utility; Lenovo Vantage delivers drivers and BIOS updates'),
    @('B9ECED6F.*',                          'ASUS app',                            $C, 'OEM utility (Armoury Crate, MyASUS)'),
    @('AcerIncorporated.*',                  'Acer app',                            $C, 'OEM utility'),
    @('9426MICRO-STARINTERNATION.*',         'MSI app',                             $C, 'OEM utility'),
    @('*CyberLink*',                         'CyberLink app',                       $O, 'OEM-bundled media app')
)
$knownDesktop = @(
    @('McAfee*',                 $C, 'Trial antivirus; remove only if Defender or another antivirus is on. Use the McAfee removal tool (MCPR) if the normal uninstall fails'),
    @('Norton*',                 $C, 'Trial antivirus; remove only if Defender or another antivirus is on. Use the Norton Remove and Reinstall tool if the normal uninstall fails'),
    @('*WildTangent*',           $S, 'OEM game bundle'),
    @('*Booking.com*',           $S, 'Promo shortcut'),
    @('*Dropbox*promotion*',     $S, 'Promo'),
    @('*ExpressVPN*',            $O, 'Often a preinstalled trial'),
    @('*CyberLink*',             $O, 'OEM-bundled media app'),
    @('*Candy Crush*',           $S, 'Promoted game'),
    @('*Amazon*Assistant*',      $S, 'Shopping add-on'),
    @('HP Wolf*',                $C, 'HP security add-on; overlaps with Defender'),
    @('HP Support Assistant*',   $C, 'Delivers HP driver and BIOS updates'),
    @('HP Documentation*',       $O, 'OEM manuals'),
    @('Dell SupportAssist*',     $C, 'Delivers Dell driver and BIOS updates'),
    @('Dell Digital Delivery*',  $O, 'Only needed to download software bought with the PC'),
    @('Lenovo Vantage*',         $C, 'Delivers Lenovo driver and BIOS updates'),
    @('*Microsoft 365*- *',      $C, 'Preinstalled Office in other languages is common; remove extra language copies you do not use'),
    @('*OneNote*- *',            $C, 'Preinstalled OneNote in other languages; remove extra language copies')
)

function Find-Known {
    param([string]$Name, $List)
    foreach ($k in $List) { if ($Name -like $k[0]) { return $k } }
    return $null
}

$levelOrder = @{ 'Safe to remove' = 0; 'Optional' = 1; 'Check first' = 2; 'Not listed' = 3 }
function Get-LevelColor {
    param([string]$Level)
    switch ($Level) { 'Safe to remove' { 'Yellow' } 'Optional' { 'Gray' } 'Check first' { 'DarkCyan' } default { 'DarkGray' } }
}

# ---------- Running Store apps ----------
$runningPaths = @{}
try {
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = Get-Prop $p 'Path'
        if ($path -and $path -like '*\WindowsApps\*') {
            $folder = ($path -split '\\WindowsApps\\', 2)[1]
            if ($folder) { $runningPaths[($folder -split '\\')[0].ToLower()] = $true }
        }
    }
} catch { }

# ---------- Store apps for this account ----------
Write-Host 'Find-Bloatware: scanning installed apps (read-only)...' -ForegroundColor White
$storeApps = New-Object System.Collections.Generic.List[object]
$appx = @()
$appxOk = $true
try { $appx = @(Get-AppxPackage -ErrorAction Stop) } catch {
    $appxOk = $false
    Write-Host "  Could not list Store apps: $($_.Exception.Message)" -ForegroundColor DarkYellow
}
foreach ($a in $appx) {
    $name = [string](Get-Prop $a 'Name')
    if (-not $name) { continue }
    if ((Get-Prop $a 'IsFramework') -eq $true) { continue }
    if ((Get-Prop $a 'IsResourcePackage') -eq $true) { continue }
    $nonRemovable = (Get-Prop $a 'NonRemovable') -eq $true
    $sig = [string](Get-Prop $a 'SignatureKind')
    if ($sig -eq 'System' -or $nonRemovable) { continue }
    $k = Find-Known -Name $name -List $knownStore
    if (-not $k -and -not $All) { continue }
    $loc = [string](Get-Prop $a 'InstallLocation')
    $leaf = ''
    if ($loc) { $leaf = (Split-Path -Leaf $loc).ToLower() }
    $full = [string](Get-Prop $a 'PackageFullName')
    $running = $false
    if ($leaf -and $runningPaths.ContainsKey($leaf)) { $running = $true }
    elseif ($full -and $runningPaths.ContainsKey($full.ToLower())) { $running = $true }
    $obj = [pscustomobject]@{
        Source   = 'Store'
        Name     = $(if ($k) { $k[1] } else { $name })
        Package  = $name
        FullName = $full
        Version  = [string](Get-Prop $a 'Version')
        Level    = $(if ($k) { $k[2] } else { 'Not listed' })
        Note     = $(if ($k) { $k[3] } else { '' })
        SizeBytes = (Get-FolderSize -Path $loc)
        Running  = $running
        Publisher = [string](Get-Prop $a 'Publisher')
        HowToRemove = "Remove-AppxPackage -Package '$full'"
    }
    $storeApps.Add($obj)
    $rows.Add($obj)
}
$storeApps = @($storeApps | Sort-Object @{ Expression = { $levelOrder[$_.Level] } }, Name)

Write-Section 'Store apps for your account'
if (-not $appxOk) {
    Write-Host '  Skipped (Get-AppxPackage failed).' -ForegroundColor DarkGray
} elseif ($storeApps.Count -eq 0) {
    Write-Host '  None of the known preinstalled or promoted Store apps are installed.' -ForegroundColor Green
} else {
    Write-Host ('  {0,-15} {1,-34} {2,9} {3,-8} {4}' -f 'Level', 'App', 'Size', 'Running', 'Note') -ForegroundColor White
    foreach ($s in $storeApps) {
        $nm = $s.Name; if ($nm.Length -gt 34) { $nm = $nm.Substring(0, 31) + '...' }
        $run = ''; if ($s.Running) { $run = 'yes' }
        Write-Host ('  {0,-15} {1,-34} {2,9} {3,-8} {4}' -f $s.Level, $nm, (Format-Size $s.SizeBytes), $run, $s.Note) -ForegroundColor (Get-LevelColor $s.Level)
    }
    $matchedSize = Get-SizeSum -Items @($storeApps | Where-Object { $_.Level -ne 'Not listed' })
    if ($matchedSize) { Write-Host ('  Matched apps use about {0} on disk.' -f (Format-Size $matchedSize)) -ForegroundColor White }
}

# ---------- Provisioned for new users ----------
Write-Section 'Provisioned for new accounts'
$provisioned = @()
if ($isAdmin) {
    try {
        foreach ($p in @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)) {
            $dn = [string](Get-Prop $p 'DisplayName')
            $k = Find-Known -Name $dn -List $knownStore
            if (-not $k) { continue }
            $obj = [pscustomobject]@{
                Source = 'Provisioned'; Name = $k[1]; Package = $dn; FullName = [string](Get-Prop $p 'PackageName')
                Version = [string](Get-Prop $p 'Version'); Level = $k[2]; Note = $k[3]; SizeBytes = $null; Running = $false
                Publisher = ''; HowToRemove = "Remove-AppxProvisionedPackage -Online -PackageName '$([string](Get-Prop $p 'PackageName'))'"
            }
            $provisioned += $obj
            $rows.Add($obj)
        }
        $provisioned = @($provisioned | Sort-Object @{ Expression = { $levelOrder[$_.Level] } }, Name)
        if ($provisioned.Count -eq 0) { Write-Host '  No known bloatware is provisioned for new accounts.' -ForegroundColor Green }
        foreach ($p in $provisioned) {
            Write-Host ('  {0,-15} {1}' -f $p.Level, $p.Name) -ForegroundColor (Get-LevelColor $p.Level)
        }
    } catch { Write-Host "  Could not list provisioned apps: $($_.Exception.Message)" -ForegroundColor DarkYellow }
} else {
    Write-Host '  Skipped: run PowerShell as administrator to see apps installed for every new account.' -ForegroundColor DarkGray
}

# ---------- Desktop programs ----------
Write-Section 'Desktop programs (trialware and OEM bundles)'
$desktop = New-Object System.Collections.Generic.List[object]
$seen = @{}
$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($key in $uninstallKeys) {
    $entries = @()
    try { $entries = @(Get-ItemProperty -Path $key -ErrorAction SilentlyContinue) } catch { }
    foreach ($e in $entries) {
        $dn = [string](Get-Prop $e 'DisplayName')
        if (-not $dn) { continue }
        if ((Get-Prop $e 'SystemComponent') -eq 1) { continue }
        $k = Find-Known -Name $dn -List $knownDesktop
        if (-not $k) { continue }
        if ($seen.ContainsKey($dn)) { continue }
        $seen[$dn] = $true
        $size = $null
        $est = Get-Prop $e 'EstimatedSize'
        if ($est) { try { $size = [int64]$est * 1KB } catch { } }
        $cmd = [string](Get-Prop $e 'QuietUninstallString')
        if (-not $cmd) { $cmd = [string](Get-Prop $e 'UninstallString') }
        if (-not $cmd) { $cmd = 'Settings > Apps > Installed apps' }
        $obj = [pscustomobject]@{
            Source = 'Desktop'; Name = $dn; Package = ''; FullName = ''; Version = [string](Get-Prop $e 'DisplayVersion')
            Level = $k[1]; Note = $k[2]; SizeBytes = $size; Running = $false
            Publisher = [string](Get-Prop $e 'Publisher'); HowToRemove = $cmd
        }
        $desktop.Add($obj)
        $rows.Add($obj)
    }
}
$desktop = @($desktop | Sort-Object @{ Expression = { $levelOrder[$_.Level] } }, Name)
if ($desktop.Count -eq 0) {
    Write-Host '  No known trialware or OEM bundles in Programs and Features.' -ForegroundColor Green
} else {
    foreach ($d in $desktop) {
        Write-Host ('  {0,-15} {1} {2}  ({3})' -f $d.Level, $d.Name, $d.Version, (Format-Size $d.SizeBytes)) -ForegroundColor (Get-LevelColor $d.Level)
        Write-Host ('                  {0}' -f $d.Note) -ForegroundColor DarkGray
    }
    Write-Host '  Remove these from Settings > Apps > Installed apps (this script never runs uninstallers).' -ForegroundColor DarkGray
}

# ---------- Settings that add more ----------
Write-Section 'Settings that install or advertise apps'
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return (Get-Prop $item $Name)
    } catch { return $null }
}
$cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
$adv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
# Value, meaning of 1 (or missing = Windows default on), where to turn it off
$settings = @(
    @($cdm, 'SilentInstalledAppsEnabled',     'Windows installs suggested apps without asking', ('Run: Set-ItemProperty "' + $cdm + '" SilentInstalledAppsEnabled 0'), 'Medium'),
    @($cdm, 'SubscribedContent-338388Enabled', 'Suggestions (ads) in Start',                    'Settings > Personalization > Start > turn off "Show recommendations for tips, shortcuts, new apps and more"', 'Low'),
    @($adv, 'Start_IrisRecommendations',       'Tips and app promotions in Start',              'Settings > Personalization > Start > turn off "Show recommendations for tips, shortcuts, new apps and more"', 'Low'),
    @($cdm, 'SubscribedContent-338389Enabled', 'Tips and suggestions notifications',            'Settings > System > Notifications > Additional settings > turn off "Get tips and suggestions when using Windows"', 'Low'),
    @($cdm, 'SubscribedContent-310093Enabled', '"Welcome experience" after updates',            'Settings > System > Notifications > Additional settings > turn off "Show the Windows welcome experience"', 'Low'),
    @($cdm, 'RotatingLockScreenOverlayEnabled','Fun facts and tips on the lock screen',         'Settings > Personalization > Lock screen > turn off "Get fun facts, tips, tricks, and more"', 'Low'),
    @($adv, 'TaskbarDa',                       'Widgets on the taskbar (runs in the background)','Settings > Personalization > Taskbar > turn off Widgets', 'Low')
)
foreach ($s in $settings) {
    $v = Get-RegValue -Path $s[0] -Name $s[1]
    $on = ($null -eq $v -or [int]$v -ne 0)
    $state = 'Off'; $color = 'Green'
    if ($on) { $state = 'On'; if ($null -eq $v) { $state = 'On (default)' }; $color = 'Yellow' }
    Write-Host ('  {0,-50} {1}' -f $s[2], $state) -ForegroundColor $color
    $rows.Add([pscustomobject]@{ Source = 'Setting'; Name = $s[2]; Package = $s[1]; FullName = ''; Version = ''; Level = $state; Note = ''; SizeBytes = $null; Running = $false; Publisher = ''; HowToRemove = $s[3] })
    if ($on -and -not @($findings | Where-Object { $_.Fix -eq $s[3] }).Count) { Add-Finding -Level $s[4] -Text "$($s[2]) is on." -Fix $s[3] }
}
$policy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures'
if ($policy -eq 1) { Write-Host '  Consumer features policy is set: Windows will not add promoted apps for new accounts.' -ForegroundColor Green }

# ---------- Findings ----------
$safe  = @($storeApps | Where-Object { $_.Level -eq 'Safe to remove' })
$opt   = @($storeApps | Where-Object { $_.Level -eq 'Optional' })
$runS  = @($storeApps | Where-Object { $_.Running -and $_.Level -ne 'Not listed' })
$avTrial = @($desktop | Where-Object { $_.Name -like 'McAfee*' -or $_.Name -like 'Norton*' }) + @($storeApps | Where-Object { $_.Package -like '*McAfee*' })
if ($safe.Count -gt 0) {
    $sz = Get-SizeSum -Items $safe
    $szText = ''; if ($sz) { $szText = " ($(Format-Size $sz))" }
    Add-Finding -Level 'Medium' -Text ("{0} game or promo app(s) you can safely remove{1}: {2}." -f $safe.Count, $szText, (($safe | Select-Object -ExpandProperty Name -Unique) -join ', ')) -Fix 'Right-click each in Start > Uninstall, or run this script with -Remove.'
}
if ($opt.Count -gt 0) {
    Add-Finding -Level 'Low' -Text ("{0} Microsoft extra(s) you may not use: {1}." -f $opt.Count, (($opt | Select-Object -ExpandProperty Name -Unique) -join ', ')) -Fix 'Remove the ones you never open; all can be reinstalled from the Microsoft Store.'
}
if ($runS.Count -gt 0) {
    Add-Finding -Level 'Medium' -Text ("Running right now: {0}." -f (($runS | Select-Object -ExpandProperty Name -Unique) -join ', ')) -Fix 'Remove them, or stop them running in the background: Settings > Apps > Installed apps > ... > Advanced options > Background app permissions > Never.'
}
if ($avTrial.Count -gt 0) {
    Add-Finding -Level 'Medium' -Text ("Trial antivirus installed: {0}. Once the trial ends it nags and may stop protecting you, while Defender stays switched off." -f (($avTrial | Select-Object -ExpandProperty Name -Unique) -join ', ')) -Fix 'If you do not plan to pay for it, uninstall it; Microsoft Defender turns itself back on. Check with Test-SecurityPosture.ps1 afterwards.'
}
$provSafe = @($provisioned | Where-Object { $_.Level -eq 'Safe to remove' })
if ($provSafe.Count -gt 0) {
    Add-Finding -Level 'Low' -Text ("{0} promo app(s) are provisioned and will be installed for every new account: {1}." -f $provSafe.Count, (($provSafe | Select-Object -ExpandProperty Name -Unique) -join ', ')) -Fix 'As admin, run the HowToRemove command from the -CsvPath export for each one (Remove-AppxProvisionedPackage -Online -PackageName <name>).'
}

Write-Section 'Findings'
if ($findings.Count -eq 0) {
    Write-Host '  Nothing to clean up. This PC has no known bloatware and the app-suggestion settings are off.' -ForegroundColor Green
} else {
    $i = 0
    foreach ($f in @($findings | Sort-Object @{ Expression = { @{ High = 0; Medium = 1; Low = 2 }[$_.Level] } })) {
        $i++
        $c = 'Gray'; if ($f.Level -eq 'High') { $c = 'Red' } elseif ($f.Level -eq 'Medium') { $c = 'Yellow' }
        Write-Host ("  {0}. [{1}] {2}" -f $i, $f.Level, $f.Text) -ForegroundColor $c
        if ($f.Fix) { Write-Host ("     Fix: {0}" -f $f.Fix) -ForegroundColor DarkGray }
    }
}

# ---------- CSV ----------
if ($CsvPath) {
    try {
        $rows | Select-Object Source, Level, Name, Package, Version, Publisher, @{ n = 'SizeMB'; e = { if ($null -ne $_.SizeBytes) { [math]::Round($_.SizeBytes / 1MB, 1) } } }, Running, Note, HowToRemove |
            Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ''
        Write-Host "Saved $($rows.Count) rows to $CsvPath" -ForegroundColor Green
    } catch { Write-Host "Could not write CSV: $($_.Exception.Message)" -ForegroundColor Red }
}

# ---------- Optional removal ----------
if ($Remove) {
    $candidates = @($storeApps | Where-Object { $_.Level -ne 'Not listed' -and $_.FullName })
    Write-Section 'Remove Store apps'
    if ($candidates.Count -eq 0) {
        Write-Host '  Nothing to remove.' -ForegroundColor Green
    } else {
        Write-Host "  $($candidates.Count) matched Store app(s) can be removed for your account only." -ForegroundColor White
        Write-Host '  You will be asked about each one. Removed apps can be reinstalled from the Microsoft Store.' -ForegroundColor White
        $answer = Read-Host '  Type YES to continue'
        if ($answer -cne 'YES') {
            Write-Host '  Cancelled. Nothing was removed.' -ForegroundColor DarkGray
        } else {
            $removed = 0; $failed = 0
            foreach ($c in $candidates) {
                $q = Read-Host ("  Remove {0} [{1}]? (y/N)" -f $c.Name, $c.Level)
                if ($q -notmatch '^(y|yes)$') { continue }
                try {
                    Remove-AppxPackage -Package $c.FullName -ErrorAction Stop
                    Write-Host "    Removed $($c.Name)" -ForegroundColor Green
                    $removed++
                } catch {
                    Write-Host "    Could not remove $($c.Name): $($_.Exception.Message)" -ForegroundColor Red
                    $failed++
                }
            }
            Write-Host ("  Done: {0} removed, {1} failed." -f $removed, $failed) -ForegroundColor White
        }
    }
}
Write-Host ''
