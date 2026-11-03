<#
.SYNOPSIS
    Sorts photos and videos into Year\Month folders by the date they were taken.

.DESCRIPTION
    Scans a folder (and subfolders) for photos and videos and works out when each one
    was taken, in this order:
      1. The EXIF "date taken" stamp inside the file (JPEG, HEIC, most camera RAW files)
      2. A date in the file name (IMG_20230514_..., PXL_20230514..., 2023-05-14 ...)
      3. The file's Last Modified date (skip this with -NoFileDate)
    Then it plans a move into <Destination>\<Year>\<MM - Month>\.

    SAFETY
      - Preview by default: it only shows the plan and changes nothing.
      - -Run moves (or -Copy copies) files, after you type YES (-Force skips the prompt).
      - Never deletes anything. Name clashes get " (2)", " (3)"... added; a file that is
        byte-for-byte identical to one already at the target is left where it is and reported.
      - Every move is written to a CSV log, and -UndoLog <log.csv> moves files back.
      - No network access. No admin needed.

.PARAMETER Path         Folder to sort (required).
.PARAMETER Destination  Where Year\Month folders go (default: same as -Path).
.PARAMETER Run          Actually move files (asks you to type YES).
.PARAMETER Copy         With -Run, copy instead of move, leaving the originals alone.
.PARAMETER Force        With -Run, skip the YES prompt.
.PARAMETER NoFileDate   Don't fall back to Last Modified; files with no EXIF or name date go to "Unknown date".
.PARAMETER NoRecurse    Only look at files directly in -Path.
.PARAMETER Extensions   File types to include (default common photo, RAW and video types).
.PARAMETER MonthFormat  Month folder style: "Number" (05), "Name" (05 - May, default) or "Flat" (2023-05).
.PARAMETER LogPath      Where to write the move log CSV (default: <Destination>\Sort-PhotosByDate-<time>.csv).
.PARAMETER UndoLog      Move files listed in a previous log back where they came from (asks YES).

.EXAMPLE
    # Preview only
    .\Sort-PhotosByDate.ps1 -Path "$env:USERPROFILE\Pictures\Phone dump"
.EXAMPLE
    # Copy into a new library, keeping the originals
    .\Sort-PhotosByDate.ps1 -Path E:\DCIM -Destination D:\Photos -Run -Copy
.EXAMPLE
    # Undo a run
    .\Sort-PhotosByDate.ps1 -UndoLog D:\Photos\Sort-PhotosByDate-20261103-0900.csv
#>
[CmdletBinding(DefaultParameterSetName = 'Sort')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Sort')][string]$Path,
    [Parameter(ParameterSetName = 'Sort')][string]$Destination,
    [Parameter(ParameterSetName = 'Sort')][switch]$Run,
    [Parameter(ParameterSetName = 'Sort')][switch]$Copy,
    [switch]$Force,
    [Parameter(ParameterSetName = 'Sort')][switch]$NoFileDate,
    [Parameter(ParameterSetName = 'Sort')][switch]$NoRecurse,
    [Parameter(ParameterSetName = 'Sort')][string[]]$Extensions = @(
        '.jpg','.jpeg','.heic','.heif','.png','.gif','.webp','.tif','.tiff',
        '.cr2','.cr3','.nef','.arw','.dng','.orf','.rw2','.raf',
        '.mp4','.mov','.m4v','.avi','.mts','.3gp'),
    [Parameter(ParameterSetName = 'Sort')][ValidateSet('Number','Name','Flat')][string]$MonthFormat = 'Name',
    [Parameter(ParameterSetName = 'Sort')][string]$LogPath,
    [Parameter(Mandatory, ParameterSetName = 'Undo')][string]$UndoLog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Confirm-Yes([string]$Prompt) {
    if ($Force) { return $true }
    (Read-Host "$Prompt Type YES to continue") -ceq 'YES'
}

function Get-UniquePath([string]$Target) {
    if (-not (Test-Path -LiteralPath $Target)) { return $Target }
    $dir = Split-Path $Target -Parent
    $base = [IO.Path]::GetFileNameWithoutExtension($Target)
    $ext = [IO.Path]::GetExtension($Target)
    $i = 2
    while (Test-Path -LiteralPath (Join-Path $dir "$base ($i)$ext")) { $i++ }
    Join-Path $dir "$base ($i)$ext"
}

function Test-ValidDate([int]$y, [int]$m, [int]$d) {
    $y -ge 1980 -and $y -le ((Get-Date).Year + 1) -and $m -ge 1 -and $m -le 12 -and $d -ge 1 -and $d -le 31
}

# Reads the EXIF date-taken stamp ("YYYY:MM:DD HH:MM:SS") from the start of the file.
# Works for JPEG, HEIC and most RAW files without any extra modules.
$exifRegex = [regex]'((?:19|20)\d\d):([01]\d):([0-3]\d) ([0-2]\d):([0-5]\d):([0-5]\d)'
function Get-ExifDate([string]$File) {
    try {
        $fs = [IO.File]::OpenRead($File)
        try {
            $buf = New-Object byte[] ([Math]::Min(262144, $fs.Length))
            [void]$fs.Read($buf, 0, $buf.Length)
        } finally { $fs.Dispose() }
        $text = [Text.Encoding]::ASCII.GetString($buf)
        $dates = foreach ($m in $exifRegex.Matches($text)) {
            $g = $m.Groups
            if (Test-ValidDate $g[1].Value $g[2].Value $g[3].Value) {
                try { [datetime]::new([int]$g[1].Value, [int]$g[2].Value, [int]$g[3].Value, [int]$g[4].Value, [int]$g[5].Value, [int]$g[6].Value) } catch { }
            }
        }
        # EXIF stores ModifyDate, DateTimeOriginal and DateTimeDigitized; the earliest is the capture time.
        if ($dates) { return ($dates | Sort-Object | Select-Object -First 1) }
    } catch { }
    $null
}

$nameRegex = [regex]'(?<!\d)((?:19|20)\d\d)[-_.]?([01]\d)[-_.]?([0-3]\d)(?!\d)'
function Get-NameDate([string]$Name) {
    foreach ($m in $nameRegex.Matches($Name)) {
        $g = $m.Groups
        if (Test-ValidDate $g[1].Value $g[2].Value $g[3].Value) {
            try { return [datetime]::new([int]$g[1].Value, [int]$g[2].Value, [int]$g[3].Value) } catch { }
        }
    }
    $null
}

function Get-MonthFolder([datetime]$Date) {
    switch ($MonthFormat) {
        'Number' { Join-Path $Date.ToString('yyyy') $Date.ToString('MM') }
        'Flat'   { $Date.ToString('yyyy-MM') }
        default  { Join-Path $Date.ToString('yyyy') ($Date.ToString('MM') + ' - ' + [Globalization.CultureInfo]::InvariantCulture.DateTimeFormat.GetMonthName($Date.Month)) }
    }
}

# ---------------------------------------------------------------- Undo
if ($PSCmdlet.ParameterSetName -eq 'Undo') {
    $rows = @(Import-Csv -LiteralPath $UndoLog | Where-Object { $_.Action -eq 'Moved' })
    if (-not $rows) { Write-Host 'Nothing to undo (only moved files can be undone).'; return }
    Write-Host "$($rows.Count) file(s) will be moved back to where they came from."
    if (-not (Confirm-Yes 'Undo these moves?')) { Write-Host 'Cancelled. Nothing changed.'; return }
    $back = 0
    foreach ($r in $rows) {
        if (-not (Test-Path -LiteralPath $r.NewPath)) { Write-Warning "Missing, skipped: $($r.NewPath)"; continue }
        $parent = Split-Path $r.OriginalPath -Parent
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Move-Item -LiteralPath $r.NewPath -Destination (Get-UniquePath $r.OriginalPath)
        $back++
    }
    Write-Host "Moved $back file(s) back. Empty Year/Month folders were left in place."
    return
}

# ---------------------------------------------------------------- Plan
if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Folder not found: $Path" }
$Path = (Resolve-Path -LiteralPath $Path).ProviderPath
if (-not $Destination) { $Destination = $Path }
if (Test-Path -LiteralPath $Destination) { $Destination = (Resolve-Path -LiteralPath $Destination).ProviderPath }
if ($Copy -and -not $Run) { Write-Host '-Copy only matters with -Run; showing a preview.' }

$extSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$Extensions | ForEach-Object { [void]$extSet.Add(($(if ($_.StartsWith('.')) { $_ } else { ".$_" }))) }

$gciArgs = @{ LiteralPath = $Path; File = $true; ErrorAction = 'SilentlyContinue' }
if (-not $NoRecurse) { $gciArgs.Recurse = $true }
$files = @(Get-ChildItem @gciArgs | Where-Object { $extSet.Contains($_.Extension) })

$plan = foreach ($f in $files) {
    $date = Get-ExifDate $f.FullName; $source = 'EXIF'
    if (-not $date) { $date = Get-NameDate $f.BaseName; $source = 'File name' }
    if (-not $date -and -not $NoFileDate) { $date = $f.LastWriteTime; $source = 'Last modified' }
    $folder = if ($date) { Get-MonthFolder $date } else { $source = 'None'; 'Unknown date' }
    $target = Join-Path (Join-Path $Destination $folder) $f.Name
    $already = [string]::Equals((Split-Path $f.FullName -Parent), (Split-Path $target -Parent), [StringComparison]::OrdinalIgnoreCase)
    [pscustomobject]@{
        File = $f; Date = $date; DateSource = $source; Folder = $folder; Target = $target; AlreadyThere = $already
    }
}
$plan = @($plan)
$todo = @($plan | Where-Object { -not $_.AlreadyThere })

Write-Host ''
Write-Host "Sort-PhotosByDate  |  $Path  ->  $Destination" -ForegroundColor Cyan
Write-Host ("Found {0} photo/video file(s); {1} already in the right folder; {2} to {3}." -f `
    $plan.Count, ($plan.Count - $todo.Count), $todo.Count, $(if ($Copy) { 'copy' } else { 'move' }))
if (-not $todo) { Write-Host 'Nothing to do.'; return }

Write-Host "`nDate source:"
$todo | Group-Object DateSource | Sort-Object Count -Descending |
    ForEach-Object { '  {0,-14} {1,6}' -f $_.Name, $_.Count } | Write-Host
Write-Host "`nTarget folders:"
$todo | Group-Object Folder | Sort-Object Name |
    ForEach-Object { '  {0,-24} {1,6} file(s)  {2,9:N1} MB' -f $_.Name, $_.Count, (($_.Group.File | Measure-Object Length -Sum).Sum / 1MB) } | Write-Host
if ($todo | Where-Object DateSource -eq 'Last modified') {
    Write-Host "`nNote: some files had no EXIF or name date and use Last Modified, which can be the copy date. Use -NoFileDate to send them to 'Unknown date' instead." -ForegroundColor Yellow
}

if (-not $Run) {
    Write-Host "`nPreview only. Nothing was changed. Add -Run to $(if ($Copy) { 'copy' } else { 'move' }) these files." -ForegroundColor Green
    return
}

# ---------------------------------------------------------------- Run
$verb = if ($Copy) { 'Copy' } else { 'Move' }
if (-not (Confirm-Yes "$verb $($todo.Count) file(s) into Year/Month folders under ${Destination}?")) {
    Write-Host 'Cancelled. Nothing changed.'; return
}
if (-not $LogPath) {
    if (-not (Test-Path -LiteralPath $Destination)) { New-Item -ItemType Directory -Path $Destination -Force | Out-Null }
    $LogPath = Join-Path $Destination ("Sort-PhotosByDate-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

$log = [Collections.Generic.List[object]]::new()
$done = 0; $dupes = 0; $failed = 0
foreach ($p in $todo) {
    $row = [ordered]@{ OriginalPath = $p.File.FullName; NewPath = ''; Action = ''; DateTaken = $p.Date; DateSource = $p.DateSource }
    try {
        $dir = Split-Path $p.Target -Parent
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $target = $p.Target
        if (Test-Path -LiteralPath $target) {
            $existing = Get-Item -LiteralPath $target
            if ($existing.Length -eq $p.File.Length -and
                (Get-FileHash -LiteralPath $target).Hash -eq (Get-FileHash -LiteralPath $p.File.FullName).Hash) {
                $row.NewPath = $target; $row.Action = 'Skipped: identical copy already there'; $dupes++
                $log.Add([pscustomobject]$row); continue
            }
            $target = Get-UniquePath $target
        }
        if ($Copy) { Copy-Item -LiteralPath $p.File.FullName -Destination $target; $row.Action = 'Copied' }
        else       { Move-Item -LiteralPath $p.File.FullName -Destination $target; $row.Action = 'Moved' }
        $row.NewPath = $target; $done++
    } catch {
        $row.Action = "Failed: $($_.Exception.Message)"; $failed++
    }
    $log.Add([pscustomobject]$row)
}
$log | Export-Csv -LiteralPath $LogPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host ("{0} {1} file(s). {2} identical duplicate(s) left in place. {3} failed." -f `
    $(if ($Copy) { 'Copied' } else { 'Moved' }), $done, $dupes, $failed) -ForegroundColor Green
Write-Host "Log: $LogPath"
if (-not $Copy) { Write-Host "To undo: .\Sort-PhotosByDate.ps1 -UndoLog `"$LogPath`"" }
