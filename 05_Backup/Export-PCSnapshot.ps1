<#
.SYNOPSIS
    Export-PCSnapshot.ps1 - Save a "how this PC is set up" snapshot so you can
    rebuild it after a reset or a new PC, and see what changed since last time.

.DESCRIPTION
    File backups save your documents. This saves the list of everything else you
    would have to remember when setting the PC up again, into one dated folder:

      apps-winget.json     Apps winget knows, ready for "winget import" on the
                           new PC (skipped with -NoWinget or if winget is missing)
      installed-apps.csv   Every installed desktop app from the uninstall
                           registry (name, version, publisher, install date,
                           machine-wide or just you)
      store-apps.csv       Microsoft Store apps you installed (frameworks and
                           built-in system apps left out)
      ps-modules.csv       PowerShell modules installed outside Windows itself
      printers.csv         Printers, their drivers and ports
      mapped-drives.csv    Network drive letters and where they point
      path-entries.txt     Folders in your user PATH, plus the NAMES (not
                           values) of your other user environment variables
      fonts.csv            Fonts you installed yourself
      features.csv         Optional Windows features that are turned on
                           (needs admin; skipped otherwise)
      system.txt           Windows edition, version and build, PC model, CPU,
                           memory and disks (no serial numbers or product keys)
      bookmarks\           With -IncludeBookmarks: a copy of the bookmark files
                           from Chrome, Edge and Brave profiles
      RESTORE.txt          How to use the snapshot on a fresh install

    -Compare <older snapshot folder> then shows apps added, removed and updated
    since that snapshot.

    Safety level : Changes nothing on the PC. Writes only into the new snapshot
                   folder (and the optional -Zip file). Never reads passwords,
                   product keys, Wi-Fi keys or environment variable values.
                   winget export may refresh winget's source list from Microsoft
                   if its cache is out of date; -NoWinget avoids that. No other
                   network calls.
    Admin        : Optional. Without it, features.csv is skipped and apps
                   installed only for other users aren't listed.
    Privacy      : The snapshot holds app names, printer and share names, and
                   folder paths. Keep it with your private backups, not online.

.PARAMETER OutputPath
    Parent folder for snapshots (default Documents\PC-Snapshots). Each run makes
    a new <PC name>_<yyyy-MM-dd_HHmm> folder inside it.

.PARAMETER Compare
    An older snapshot folder to compare this one against.

.PARAMETER NoWinget
    Skip "winget export" (no apps-winget.json).

.PARAMETER IncludeBookmarks
    Also copy Chrome, Edge and Brave bookmark files into the snapshot.

.PARAMETER Zip
    Also pack the snapshot into a .zip next to the folder.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Export-PCSnapshot.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Export-PCSnapshot.ps1 -OutputPath E:\Backups\Snapshots -IncludeBookmarks -Zip

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Export-PCSnapshot.ps1 -Compare "$env:USERPROFILE\Documents\PC-Snapshots\MYPC_2026-10-01_0900"
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PC-Snapshots'),
    [string]$Compare,
    [switch]$NoWinget,
    [switch]$IncludeBookmarks,
    [switch]$Zip
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Compare -and -not (Test-Path -LiteralPath (Join-Path $Compare 'installed-apps.csv'))) {
    throw "-Compare folder has no installed-apps.csv: $Compare"
}

$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmm'
$snapDir  = Join-Path $OutputPath ("{0}_{1}" -f $env:COMPUTERNAME, $stamp)
New-Item -ItemType Directory -Path $snapDir -Force | Out-Null
$summary  = New-Object System.Collections.Generic.List[object]

function Add-Result([string]$Item, [string]$Status, [string]$Detail) {
    $summary.Add([pscustomobject]@{ Item = $Item; Status = $Status; Detail = $Detail })
}

function Save-Step([string]$Item, [scriptblock]$Action) {
    try {
        $detail = & $Action
        Add-Result $Item 'Saved' ([string]$detail)
    } catch {
        Add-Result $Item 'Skipped' $_.Exception.Message
    }
}

Write-Host "Saving snapshot to $snapDir" -ForegroundColor Cyan

# --- Installed desktop apps (registry) -------------------------------------
Save-Step 'installed-apps.csv' {
    $keys = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             Scope = 'Machine' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Scope = 'Machine (32-bit)' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';             Scope = 'Current user' }
    )
    $apps = foreach ($k in $keys) {
        Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue | Where-Object {
            $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -and
            -not ($_.PSObject.Properties['SystemComponent'] -and $_.SystemComponent -eq 1) -and
            -not ($_.PSObject.Properties['ParentKeyName'] -and $_.ParentKeyName)
        } | ForEach-Object {
            $date = ''
            if ($_.PSObject.Properties['InstallDate'] -and $_.InstallDate -match '^\d{8}$') {
                $date = '{0}-{1}-{2}' -f $_.InstallDate.Substring(0,4), $_.InstallDate.Substring(4,2), $_.InstallDate.Substring(6,2)
            }
            [pscustomobject]@{
                Name        = ([string]$_.DisplayName).Trim()
                Version     = if ($_.PSObject.Properties['DisplayVersion']) { [string]$_.DisplayVersion } else { '' }
                Publisher   = if ($_.PSObject.Properties['Publisher'])      { [string]$_.Publisher }      else { '' }
                InstallDate = $date
                Scope       = $k.Scope
            }
        }
    }
    $apps = @($apps | Sort-Object Name, Version -Unique)
    $apps | Export-Csv -LiteralPath (Join-Path $snapDir 'installed-apps.csv') -NoTypeInformation -Encoding UTF8
    "$($apps.Count) apps"
}

# --- winget export ---------------------------------------------------------
if ($NoWinget) {
    Add-Result 'apps-winget.json' 'Skipped' '-NoWinget'
} else {
    Save-Step 'apps-winget.json' {
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { throw 'winget not found (install App Installer from the Store)' }
        $file = Join-Path $snapDir 'apps-winget.json'
        & winget.exe export --output $file --source winget --include-versions --accept-source-agreements --disable-interactivity 2>&1 | Out-Null
        if (-not (Test-Path -LiteralPath $file)) { throw "winget export failed (exit code $LASTEXITCODE)" }
        $json = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        $n = 0
        foreach ($s in @($json.Sources)) { $n += @($s.Packages).Count }
        "$n apps winget can reinstall"
    }
}

# --- Store apps --------------------------------------------------------------
Save-Step 'store-apps.csv' {
    $store = @(Get-AppxPackage -ErrorAction Stop | Where-Object {
        -not $_.IsFramework -and $_.SignatureKind -eq 'Store' -and -not $_.NonRemovable
    } | Sort-Object Name | Select-Object Name, Version, Publisher, PackageFamilyName)
    $store | Export-Csv -LiteralPath (Join-Path $snapDir 'store-apps.csv') -NoTypeInformation -Encoding UTF8
    "$($store.Count) Store apps"
}

# --- PowerShell modules ------------------------------------------------------
Save-Step 'ps-modules.csv' {
    $winDir = $env:WINDIR
    $mods = @(Get-Module -ListAvailable -ErrorAction SilentlyContinue | Where-Object {
        $_.ModuleBase -notlike "$winDir\*"
    } | Sort-Object Name, Version -Unique | Select-Object Name, @{n='Version';e={[string]$_.Version}}, @{n='Location';e={
        if ($_.ModuleBase -like "$env:USERPROFILE\*") { 'Current user' } else { 'All users' } }})
    $mods | Export-Csv -LiteralPath (Join-Path $snapDir 'ps-modules.csv') -NoTypeInformation -Encoding UTF8
    "$($mods.Count) modules"
}

# --- Printers ----------------------------------------------------------------
Save-Step 'printers.csv' {
    if (-not (Get-Command Get-Printer -ErrorAction SilentlyContinue)) { throw 'Get-Printer not available' }
    $skip = 'Microsoft Print to PDF', 'Microsoft XPS Document Writer', 'Fax', 'OneNote (Desktop)', 'OneNote for Windows 10'
    $pr = @(Get-Printer -ErrorAction Stop | Where-Object { $skip -notcontains $_.Name } |
        Select-Object Name, DriverName, PortName, Shared, Type)
    $pr | Export-Csv -LiteralPath (Join-Path $snapDir 'printers.csv') -NoTypeInformation -Encoding UTF8
    "$($pr.Count) printers"
}

# --- Mapped drives -----------------------------------------------------------
Save-Step 'mapped-drives.csv' {
    $drives = @(Get-ChildItem -Path 'HKCU:\Network' -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty -LiteralPath $_.PSPath
        [pscustomobject]@{ Letter = "$($_.PSChildName):"; RemotePath = $p.RemotePath }
    })
    $drives | Export-Csv -LiteralPath (Join-Path $snapDir 'mapped-drives.csv') -NoTypeInformation -Encoding UTF8
    "$($drives.Count) mapped drives"
}

# --- User PATH and variable names ---------------------------------------------
Save-Step 'path-entries.txt' {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries  = @(if ($userPath) { $userPath -split ';' | Where-Object { $_ } })
    $names    = @([Environment]::GetEnvironmentVariables('User').Keys | Where-Object { $_ -ne 'Path' } | Sort-Object)
    $out = @('# User PATH entries') + $entries + @('', '# Other user environment variables (names only, values not saved)') + $names
    $out | Set-Content -LiteralPath (Join-Path $snapDir 'path-entries.txt') -Encoding UTF8
    "$($entries.Count) PATH entries, $($names.Count) variable names"
}

# --- User-installed fonts ----------------------------------------------------
Save-Step 'fonts.csv' {
    $fonts = foreach ($key in 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts',
                              'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts') {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $file = [string]$p.Value
            # Windows' own fonts are stored as bare file names in C:\Windows\Fonts; skip them.
            if ($key -like 'HKLM:*' -and $file -notmatch '\\') { continue }
            [pscustomobject]@{ Font = $p.Name; File = $file; Scope = if ($key -like 'HKCU:*') { 'Current user' } else { 'All users' } }
        }
    }
    $fonts = @($fonts)
    $fonts | Export-Csv -LiteralPath (Join-Path $snapDir 'fonts.csv') -NoTypeInformation -Encoding UTF8
    "$($fonts.Count) fonts you installed"
}

# --- Optional features ---------------------------------------------------------
if ($isAdmin) {
    Save-Step 'features.csv' {
        $f = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object State -eq 'Enabled' |
            Sort-Object FeatureName | Select-Object FeatureName)
        $f | Export-Csv -LiteralPath (Join-Path $snapDir 'features.csv') -NoTypeInformation -Encoding UTF8
        "$($f.Count) features on"
    }
} else {
    Add-Result 'features.csv' 'Skipped' 'needs admin'
}

# --- System summary -------------------------------------------------------------
Save-Step 'system.txt' {
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $cpu  = @(Get-CimInstance Win32_Processor)[0]
    $cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $disp = if ($cv.PSObject.Properties['DisplayVersion']) { $cv.DisplayVersion } else { '' }
    $ubr  = if ($cv.PSObject.Properties['UBR']) { ".$($cv.UBR)" } else { '' }
    $disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object { '  {0} ({1:N0} GB)' -f $_.Model, ($_.Size / 1GB) })
    $lines = @(
        "Snapshot taken : $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
        "Windows        : $($os.Caption) $disp (build $($os.BuildNumber)$ubr)",
        "PC             : $($cs.Manufacturer) $($cs.Model)",
        "CPU            : $($cpu.Name.Trim())",
        ('Memory         : {0:N0} GB' -f ($cs.TotalPhysicalMemory / 1GB)),
        'Disks          :'
    ) + $disks
    $lines | Set-Content -LiteralPath (Join-Path $snapDir 'system.txt') -Encoding UTF8
    "$($os.Caption) $disp"
}

# --- Bookmarks (opt-in) ---------------------------------------------------------
if ($IncludeBookmarks) {
    Save-Step 'bookmarks\' {
        $browsers = @{
            'Chrome' = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
            'Edge'   = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
            'Brave'  = Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'
        }
        $n = 0
        foreach ($b in $browsers.Keys) {
            if (-not (Test-Path -LiteralPath $browsers[$b])) { continue }
            Get-ChildItem -LiteralPath $browsers[$b] -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } | ForEach-Object {
                    $src = Join-Path $_.FullName 'Bookmarks'
                    if (Test-Path -LiteralPath $src) {
                        $dest = Join-Path $snapDir "bookmarks\$b\$($_.Name)"
                        New-Item -ItemType Directory -Path $dest -Force | Out-Null
                        Copy-Item -LiteralPath $src -Destination $dest
                        $n++
                    }
                }
        }
        if ($n -eq 0) { throw 'no Chrome, Edge or Brave bookmark files found' }
        "$n bookmark files (Firefox not included)"
    }
}

# --- Restore notes -------------------------------------------------------------
@'
How to use this snapshot on a fresh Windows install
====================================================

1. Reinstall apps winget knows (from this folder, in Terminal):
       winget import -i .\apps-winget.json --accept-package-agreements --accept-source-agreements
   Anything that fails or isn't in winget: check installed-apps.csv and
   store-apps.csv and install it by hand.

2. PowerShell modules: Install-Module <Name> for each line in ps-modules.csv.

3. Printers: add each one in Settings > Bluetooth & devices > Printers & scanners.
   printers.csv shows the driver and port each one used.

4. Network drives: in Terminal, for each line in mapped-drives.csv:
       net use <Letter> <RemotePath> /persistent:yes

5. PATH: add the folders in path-entries.txt back under
   Settings > System > About > Advanced system settings > Environment Variables.

6. Fonts: reinstall the font files listed in fonts.csv.

7. Windows features: turn on the ones in features.csv under
   "Turn Windows features on or off".

8. Bookmarks (if saved): close the browser and copy the Bookmarks file back
   into the matching profile folder, or import it from the browser's settings.
'@ | Set-Content -LiteralPath (Join-Path $snapDir 'RESTORE.txt') -Encoding UTF8

# --- Compare with an older snapshot ---------------------------------------------
if ($Compare) {
    $old = @{}; $new = @{}
    Import-Csv -LiteralPath (Join-Path $Compare 'installed-apps.csv') | ForEach-Object { $old[$_.Name] = $_.Version }
    Import-Csv -LiteralPath (Join-Path $snapDir 'installed-apps.csv') | ForEach-Object { $new[$_.Name] = $_.Version }
    $changes = @(@(
        foreach ($k in $new.Keys) {
            if (-not $old.ContainsKey($k))      { [pscustomobject]@{ Change = 'Added';   App = $k; Was = '';        Now = $new[$k] } }
            elseif ($old[$k] -ne $new[$k])       { [pscustomobject]@{ Change = 'Updated'; App = $k; Was = $old[$k]; Now = $new[$k] } }
        }
        foreach ($k in $old.Keys) {
            if (-not $new.ContainsKey($k))      { [pscustomobject]@{ Change = 'Removed'; App = $k; Was = $old[$k]; Now = '' } }
        }
    ) | Sort-Object Change, App)
    $changes | Export-Csv -LiteralPath (Join-Path $snapDir 'changes-since-compare.csv') -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host "Changes since $(Split-Path $Compare -Leaf)" -ForegroundColor Cyan
    if ($changes.Count -eq 0) { Write-Host '  No app changes.' }
    else { $changes | Format-Table -AutoSize | Out-String -Width 200 | Write-Host }
}

# --- Zip (optional) ---------------------------------------------------------------
if ($Zip) {
    Save-Step 'zip' {
        $zipPath = "$snapDir.zip"
        Compress-Archive -Path (Join-Path $snapDir '*') -DestinationPath $zipPath -Force
        $zipPath
    }
}

Write-Host ''
$summary | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
Write-Host "Done. Snapshot folder: $snapDir" -ForegroundColor Green
Write-Host 'It lists your apps, printers and shares: keep it with your private backups.' -ForegroundColor Yellow
