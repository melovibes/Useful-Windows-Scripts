<#
.SYNOPSIS
    Find-OldLargeFiles.ps1 - Find old, large files cluttering common folders
    (Downloads, Desktop, Documents and more). Preview by default; move, recycle
    or permanently delete only when you ask.

.DESCRIPTION
    Answers "what's eating space that I haven't touched in months?" It walks the
    folders you name (default: your Downloads, Desktop, Documents, Videos and
    Pictures) and lists files that are both older than a cutoff and larger than a
    size floor. By age it uses LastWriteTime (when the file was last changed).

    Reports:
      Summary     How many matching files, total size, cloud-only skipped, and
                  which folder holds most
      By folder   Count and size of matches under each top-level path
      By type     Top extensions by total size (what kind of clutter it is)
      Largest     The biggest matching files with age, size and full path
      Findings    Plain-English notes (for example a huge Downloads folder, or
                  ISO / installer files that look safe to archive)

    With no switches it only prints the report. -MoveTo relocates matching files
    into an archive folder (keeps relative paths under each source root) after you
    type YES, and writes a CSV move log so -UndoLog can reverse it. -Clean sends
    matches to the Recycle Bin after YES (use -Permanent with -Clean for a real
    delete). -Force skips the YES prompt when combined with -MoveTo, -Clean or
    -UndoLog. Never both -MoveTo and -Clean.

    OneDrive Files On-Demand cloud-only placeholders are skipped by default so
    their logical size is not counted as freeable local space and moving them
    does not force a download. Pass -IncludeCloudOnly to count them.

    Safety level : SAFE by default (read-only preview). -MoveTo, -Clean and
                   -UndoLog change files only after confirmation (unless -Force).
                   Junctions and reparse points are skipped so linked folders are
                   not double-counted or walked into other drives. No network
                   calls. Extra files written: optional -CsvPath and the move log
                   under -MoveTo (or -LogPath).

    Admin        : Not required.

.PARAMETER Path
    One or more folders to scan. Default: Downloads, Desktop, Documents, Videos
    and Pictures under your user profile. Missing folders are skipped quietly.

.PARAMETER OlderThanDays
    Only files whose LastWriteTime is at least this many days ago. Default: 90.
    Set to 0 to ignore age (size filter only).

.PARAMETER MinSizeMB
    Only files at least this many megabytes. Default: 50. Set to 0 for any size
    (still subject to -OlderThanDays).

.PARAMETER Top
    How many largest matching files to show in the console list. Default: 40.
    The CSV (if requested) still includes every match.

.PARAMETER Extensions
    Optional list of extensions to include, for example '.iso','.zip','.mkv'.
    When omitted, every extension is considered.

.PARAMETER Exclude
    Folder name segments to skip anywhere under a path (case-insensitive).
    Default: node_modules, .git, AppData, '$Recycle.Bin', 'System Volume Information'.

.PARAMETER IncludeCloudOnly
    Include OneDrive / Files On-Demand cloud-only placeholders. Off by default
    because their Length is the full cloud size (not local) and moving them
    forces a download.

.PARAMETER MoveTo
    After confirmation, move matching files under this archive folder. Each source
    root gets a subfolder named after it (for example Downloads\...). Name clashes
    get ' (2)' added. Never overwrites an existing file. Writes a CSV move log
    (see -LogPath) so you can undo with -UndoLog.

.PARAMETER Clean
    After confirmation, send matching files to the Recycle Bin (recoverable).
    Prefer -MoveTo first. Combine with -Permanent for a real delete.

.PARAMETER Permanent
    With -Clean only: permanently delete instead of sending to the Recycle Bin.

.PARAMETER Force
    With -MoveTo, -Clean or -UndoLog, skip the YES prompt.

.PARAMETER CsvPath
    Export every matching file (path, size, dates, source root) to this CSV.

.PARAMETER LogPath
    Where to write the -MoveTo CSV log. Default:
    <MoveTo>\Find-OldLargeFiles-<yyyyMMdd-HHmmss>.csv

.PARAMETER UndoLog
    Reverse a previous -MoveTo run from its CSV log. Moves files listed as Moved
    back to their original paths (never overwrites; asks YES unless -Force).

.EXAMPLE
    .\Find-OldLargeFiles.ps1
    Preview old large files in the default user folders.

.EXAMPLE
    .\Find-OldLargeFiles.ps1 -OlderThanDays 180 -MinSizeMB 100 -CsvPath "$env:USERPROFILE\Desktop\old-large.csv"
    Stricter cutoff, save the full list.

.EXAMPLE
    .\Find-OldLargeFiles.ps1 -Path "$env:USERPROFILE\Downloads" -Extensions '.iso','.zip','.exe' -MoveTo D:\Archive\OldDownloads
    Move old installers and archives from Downloads into D:\Archive\OldDownloads
    (writes a move log; undo with -UndoLog).

.EXAMPLE
    .\Find-OldLargeFiles.ps1 -UndoLog D:\Archive\OldDownloads\Find-OldLargeFiles-20261106-0900.csv
    Move files from a previous -MoveTo run back where they came from.

.EXAMPLE
    .\Find-OldLargeFiles.ps1 -Clean
    Send matching files to the Recycle Bin after typing YES.

.NOTES
    Usage:
      powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1"
      powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1" -Path D:\ -OlderThanDays 365 -MinSizeMB 200
      powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1" -MoveTo D:\Archive\Clutter
      powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1" -UndoLog D:\Archive\Clutter\Find-OldLargeFiles-20261106-0900.csv
    Tip: run the preview, skim the list, then -MoveTo an external drive before you
    ever use -Clean. LastWriteTime can be newer than "when I last opened it" if an
    indexer or backup touched the file.
    Works on Windows 10 and 11, Windows PowerShell 5.1 or PowerShell 7.
#>
[CmdletBinding(DefaultParameterSetName = 'Preview')]
param(
    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Move')]
    [Parameter(ParameterSetName = 'Clean')]
    [string[]]$Path,

    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Move')]
    [Parameter(ParameterSetName = 'Clean')]
    [ValidateRange(0, 36500)]
    [int]$OlderThanDays = 90,

    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Move')]
    [Parameter(ParameterSetName = 'Clean')]
    [ValidateRange(0, 1048576)]
    [int]$MinSizeMB = 50,

    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Move')]
    [Parameter(ParameterSetName = 'Clean')]
    [ValidateRange(1, 500)]
    [int]$Top = 40,

    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Move')]
    [Parameter(ParameterSetName = 'Clean')]
    [string[]]$Extensions,

    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Move')]
    [Parameter(ParameterSetName = 'Clean')]
    [string[]]$Exclude = @('node_modules', '.git', 'AppData', '$Recycle.Bin', 'System Volume Information'),

    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Move')]
    [Parameter(ParameterSetName = 'Clean')]
    [switch]$IncludeCloudOnly,

    [Parameter(ParameterSetName = 'Move')]
    [string]$MoveTo,

    [Parameter(ParameterSetName = 'Clean')]
    [switch]$Clean,

    [Parameter(ParameterSetName = 'Clean')]
    [switch]$Permanent,

    [switch]$Force,

    [Parameter(ParameterSetName = 'Preview')]
    [Parameter(ParameterSetName = 'Move')]
    [Parameter(ParameterSetName = 'Clean')]
    [string]$CsvPath,

    [Parameter(ParameterSetName = 'Move')]
    [string]$LogPath,

    [Parameter(Mandatory, ParameterSetName = 'Undo')]
    [string]$UndoLog
)

$ErrorActionPreference = 'Stop'
$findings = New-Object System.Collections.Generic.List[string]

# FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS / OFFLINE / UNPINNED — OneDrive cloud-only markers
$AttrRecallOnDataAccess = 0x00400000
$AttrOffline            = 0x00001000
$AttrUnpinned           = 0x00100000

function Format-Bytes([double]$b) {
    if ($null -eq $b -or $b -lt 0) { return '0 B' }
    if ($b -ge 1GB) { return '{0:N2} GB' -f ($b / 1GB) }
    if ($b -ge 1MB) { return '{0:N1} MB' -f ($b / 1MB) }
    if ($b -ge 1KB) { return '{0:N0} KB' -f ($b / 1KB) }
    return '{0:N0} B' -f $b
}

function Write-Section([string]$title) {
    Write-Host ''
    Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Confirm-Yes([string]$Prompt) {
    if ($Force) { return $true }
    $answer = Read-Host ("{0} Type YES to continue" -f $Prompt)
    return ($answer -ceq 'YES')
}

function Test-ExcludedPath([string]$fullName, [string[]]$names) {
    if (-not $names -or $names.Count -eq 0) { return $false }
    $parts = $fullName -split '[\\/]'
    foreach ($p in $parts) {
        foreach ($n in $names) {
            if ($p -and $n -and ($p -ieq $n)) { return $true }
        }
    }
    return $false
}

function Test-CloudOnlyFile([System.IO.FileInfo]$fi) {
    # OneDrive Files On-Demand: cloud-only placeholders carry RECALL_ON_DATA_ACCESS
    # and/or OFFLINE (and often UNPINNED) without hydrated local data.
    $attrs = [int]$fi.Attributes
    if (($attrs -band $AttrRecallOnDataAccess) -ne 0) { return $true }
    if (($attrs -band $AttrOffline) -ne 0) { return $true }
    if (($attrs -band $AttrUnpinned) -ne 0 -and ($attrs -band $AttrRecallOnDataAccess) -ne 0) { return $true }
    return $false
}

function Get-UniqueDestination([string]$destPath) {
    if (-not (Test-Path -LiteralPath $destPath)) { return $destPath }
    $dir = Split-Path -Parent $destPath
    $base = [System.IO.Path]::GetFileNameWithoutExtension($destPath)
    $ext = [System.IO.Path]::GetExtension($destPath)
    $i = 2
    while ($true) {
        $candidate = Join-Path $dir ("{0} ({1}){2}" -f $base, $i, $ext)
        if (-not (Test-Path -LiteralPath $candidate)) { return $candidate }
        $i++
    }
}

function Remove-ToRecycleBin([string]$filePath) {
    # Prefer VisualBasic FileIO so the item lands in the Recycle Bin.
    # Falls back to permanent delete only if the assembly is unavailable (unlikely on Windows).
    try {
        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(
            $filePath,
            [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
            [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin
        )
        return 'Recycled'
    } catch {
        throw ("Recycle Bin delete unavailable ({0}). Re-run with -Permanent, or free the file and try again." -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- Undo
if ($PSCmdlet.ParameterSetName -eq 'Undo') {
    if (-not (Test-Path -LiteralPath $UndoLog -PathType Leaf)) {
        throw ("Undo log not found: {0}" -f $UndoLog)
    }
    $rows = @(Import-Csv -LiteralPath $UndoLog | Where-Object { $_.Action -eq 'Moved' })
    if (-not $rows -or $rows.Count -eq 0) {
        Write-Host 'Nothing to undo (only rows with Action=Moved can be undone).'
        return
    }
    Write-Host ("Find-OldLargeFiles - Undo") -ForegroundColor Green
    Write-Host ("{0} file(s) will be moved back to where they came from." -f $rows.Count)
    if (-not (Confirm-Yes 'Undo these moves?')) {
        Write-Host 'Cancelled. Nothing changed.'
        return
    }
    $back = 0
    $missing = 0
    $skipped = 0
    foreach ($r in $rows) {
        if ([string]::IsNullOrWhiteSpace($r.NewPath) -or -not (Test-Path -LiteralPath $r.NewPath)) {
            Write-Warning ("Missing, skipped: {0}" -f $r.NewPath)
            $missing++
            continue
        }
        if ([string]::IsNullOrWhiteSpace($r.OriginalPath)) {
            Write-Warning ("No OriginalPath in log row for {0}; skipped." -f $r.NewPath)
            $skipped++
            continue
        }
        try {
            $parent = Split-Path -Parent $r.OriginalPath
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }
            # Never overwrite an existing file at the original path.
            $dest = Get-UniqueDestination $r.OriginalPath
            Move-Item -LiteralPath $r.NewPath -Destination $dest -Force:$false -ErrorAction Stop
            $back++
        } catch {
            Write-Warning ("Could not restore {0}: {1}" -f $r.NewPath, $_.Exception.Message)
            $skipped++
        }
    }
    Write-Host ("Moved {0} file(s) back. {1} missing, {2} skipped. Empty archive folders were left in place." -f `
        $back, $missing, $skipped) -ForegroundColor Green
    return
}

# --- Defaults ---------------------------------------------------------------
if ($Permanent -and -not $Clean) {
    throw '-Permanent only applies with -Clean.'
}
if ($Clean -and $MoveTo) {
    throw 'Use either -MoveTo or -Clean, not both.'
}
if ($Force -and -not $Clean -and -not $MoveTo) {
    Write-Host 'Note: -Force only applies with -MoveTo, -Clean or -UndoLog; preview ignores it.' -ForegroundColor DarkYellow
}

if (-not $Path -or $Path.Count -eq 0) {
    $homePath = $env:USERPROFILE
    if (-not $homePath) { throw 'USERPROFILE is not set; pass -Path explicitly.' }
    $Path = @(
        (Join-Path $homePath 'Downloads'),
        (Join-Path $homePath 'Desktop'),
        (Join-Path $homePath 'Documents'),
        (Join-Path $homePath 'Videos'),
        (Join-Path $homePath 'Pictures')
    )
}

$extSet = $null
if ($Extensions -and $Extensions.Count -gt 0) {
    $extSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $Extensions) {
        $norm = $e.Trim()
        if (-not $norm.StartsWith('.')) { $norm = ".$norm" }
        [void]$extSet.Add($norm)
    }
}

$minBytes = [int64]$MinSizeMB * 1MB
$cutoff = if ($OlderThanDays -gt 0) { (Get-Date).AddDays(-$OlderThanDays) } else { [datetime]::MinValue }

$roots = New-Object System.Collections.Generic.List[object]
foreach ($p in $Path) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    try {
        $resolved = (Resolve-Path -LiteralPath $p -ErrorAction Stop).ProviderPath
    } catch {
        Write-Host ("Skipping missing path: {0}" -f $p) -ForegroundColor DarkGray
        continue
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        Write-Host ("Skipping (not a folder): {0}" -f $resolved) -ForegroundColor DarkGray
        continue
    }
    $roots.Add([pscustomobject]@{
        Label = Split-Path -Leaf $resolved
        FullName = $resolved
    })
}

if ($roots.Count -eq 0) {
    throw 'No folders to scan. Check -Path.'
}

$mode = 'Preview'
if ($MoveTo) { $mode = 'Move' }
elseif ($Clean) {
    if ($Permanent) { $mode = 'CleanPermanent' }
    else { $mode = 'CleanRecycle' }
}

Write-Host ("Find-OldLargeFiles - {0}" -f $mode) -ForegroundColor Green
Write-Host ("Cutoff: older than {0} day(s) (LastWrite before {1:yyyy-MM-dd}), min size {2} MB" -f `
    $OlderThanDays, $(if ($OlderThanDays -gt 0) { $cutoff } else { 'n/a' }), $MinSizeMB)
Write-Host ("Folders: {0}" -f (($roots | ForEach-Object { $_.FullName }) -join '; '))
if (-not $IncludeCloudOnly) {
    Write-Host 'Cloud-only (OneDrive placeholder) files: skipped by default (pass -IncludeCloudOnly to count them).'
}

# --- Scan -------------------------------------------------------------------
$matches = New-Object System.Collections.Generic.List[object]
$errors = 0
$cloudSkipped = 0
$cloudSkippedBytes = [int64]0

foreach ($root in $roots) {
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($root.FullName)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        if (Test-ExcludedPath $dir $Exclude) { continue }

        # Skip reparse points (junctions / symlinks) so we don't walk other volumes.
        try {
            $dirInfo = New-Object System.IO.DirectoryInfo $dir
            if (($dirInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                if ($dir -ne $root.FullName) { continue }
            }
        } catch {
            $errors++
            continue
        }

        try {
            foreach ($sub in [System.IO.Directory]::EnumerateDirectories($dir)) {
                if (Test-ExcludedPath $sub $Exclude) { continue }
                try {
                    $subInfo = New-Object System.IO.DirectoryInfo $sub
                    if (($subInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                } catch { continue }
                $stack.Push($sub)
            }
        } catch {
            $errors++
        }

        try {
            foreach ($filePath in [System.IO.Directory]::EnumerateFiles($dir)) {
                try {
                    $fi = New-Object System.IO.FileInfo $filePath
                    if ($fi.Length -lt $minBytes) { continue }
                    if ($fi.LastWriteTime -gt $cutoff -and $OlderThanDays -gt 0) { continue }
                    if ($extSet -and -not $extSet.Contains($fi.Extension)) { continue }

                    if (-not $IncludeCloudOnly -and (Test-CloudOnlyFile $fi)) {
                        $cloudSkipped++
                        $cloudSkippedBytes += [int64]$fi.Length
                        continue
                    }

                    $ageDays = [math]::Floor(((Get-Date) - $fi.LastWriteTime).TotalDays)
                    $matches.Add([pscustomobject]@{
                        SourceRoot = $root.FullName
                        SourceLabel = $root.Label
                        FullName = $fi.FullName
                        Name = $fi.Name
                        Extension = $(if ($fi.Extension) { $fi.Extension.ToLowerInvariant() } else { '(none)' })
                        Length = [int64]$fi.Length
                        LastWriteTime = $fi.LastWriteTime
                        CreationTime = $fi.CreationTime
                        AgeDays = [int]$ageDays
                    })
                } catch {
                    $errors++
                }
            }
        } catch {
            $errors++
        }
    }
}

$totalBytes = ($matches | Measure-Object -Property Length -Sum).Sum
if (-not $totalBytes) { $totalBytes = [int64]0 }

Write-Section 'Summary'
Write-Host ("Matching files : {0}" -f $matches.Count)
Write-Host ("Total size     : {0}" -f (Format-Bytes $totalBytes))
if ($cloudSkipped -gt 0) {
    Write-Host ("Cloud-only skipped : {0} file(s) ({1} logical size) — not counted, not hydrated" -f `
        $cloudSkipped, (Format-Bytes $cloudSkippedBytes)) -ForegroundColor DarkYellow
} elseif (-not $IncludeCloudOnly) {
    Write-Host 'Cloud-only skipped : 0'
}
if ($errors -gt 0) {
    Write-Host ("Access errors  : {0} (folders or files skipped)" -f $errors) -ForegroundColor DarkYellow
}

# --- By folder --------------------------------------------------------------
Write-Section 'By folder'
$byFolder = $matches |
    Group-Object SourceLabel |
    ForEach-Object {
        $sum = ($_.Group | Measure-Object Length -Sum).Sum
        [pscustomobject]@{
            Folder = $_.Name
            Files = $_.Count
            SizeBytes = [int64]$sum
            Size = Format-Bytes $sum
        }
    } |
    Sort-Object SizeBytes -Descending

if ($byFolder) {
    $byFolder | Format-Table Folder, Files, Size -AutoSize | Out-Host
} else {
    Write-Host 'No matching files.'
}

# --- By type (extension) ----------------------------------------------------
Write-Section 'By type (top 10 extensions)'
$byType = $matches |
    Group-Object Extension |
    ForEach-Object {
        $sum = ($_.Group | Measure-Object Length -Sum).Sum
        [pscustomobject]@{
            Extension = $_.Name
            Files = $_.Count
            SizeBytes = [int64]$sum
            Size = Format-Bytes $sum
        }
    } |
    Sort-Object SizeBytes -Descending |
    Select-Object -First 10

if ($byType) {
    $byType | Format-Table Extension, Files, Size -AutoSize | Out-Host
} else {
    Write-Host 'No matching files.'
}

# --- Largest ----------------------------------------------------------------
Write-Section ("Largest matches (top {0})" -f $Top)
$largest = $matches | Sort-Object Length -Descending | Select-Object -First $Top
if ($largest) {
    $largest |
        Select-Object @{N = 'Size'; E = { Format-Bytes $_.Length } },
            @{N = 'AgeDays'; E = { $_.AgeDays } },
            @{N = 'LastWrite'; E = { $_.LastWriteTime.ToString('yyyy-MM-dd') } },
            @{N = 'Folder'; E = { $_.SourceLabel } },
            Name,
            FullName |
        Format-Table -AutoSize | Out-Host
} else {
    Write-Host 'Nothing to list.'
}

# --- Findings ---------------------------------------------------------------
Write-Section 'Findings'
if ($matches.Count -eq 0) {
    $findings.Add('No files matched. Try a lower -MinSizeMB, a smaller -OlderThanDays, or a different -Path.')
} else {
    $findings.Add(("{0} across {1} file(s) match the age and size filters." -f (Format-Bytes $totalBytes), $matches.Count))

    $topFolder = $byFolder | Select-Object -First 1
    if ($topFolder -and $totalBytes -gt 0 -and ($topFolder.SizeBytes / $totalBytes) -ge 0.5) {
        $findings.Add(("{0} holds most of it ({1}, {2} file(s))." -f $topFolder.Folder, $topFolder.Size, $topFolder.Files))
    }

    $topExt = $byType | Select-Object -First 1
    if ($topExt -and $totalBytes -gt 0 -and ($topExt.SizeBytes / $totalBytes) -ge 0.4) {
        $findings.Add(("Most of the size is {0} files ({1}, {2} file(s))." -f $topExt.Extension, $topExt.Size, $topExt.Files))
    }

    $installerExt = @('.iso', '.img', '.exe', '.msi', '.msix', '.appx', '.zip', '.7z', '.rar', '.cab')
    $installers = @($matches | Where-Object { $installerExt -contains $_.Extension })
    if ($installers.Count -gt 0) {
        $instBytes = ($installers | Measure-Object Length -Sum).Sum
        $findings.Add(("{0} look like installers or archives ({1}) — often safe to archive after you confirm you still have the download link." -f `
            $installers.Count, (Format-Bytes $instBytes)))
    }

    $mediaExt = @('.mp4', '.mkv', '.avi', '.mov', '.wmv', '.m4v', '.mp3', '.flac', '.wav', '.aac')
    $media = @($matches | Where-Object { $mediaExt -contains $_.Extension })
    if ($media.Count -gt 0) {
        $mediaBytes = ($media | Measure-Object Length -Sum).Sum
        $findings.Add(("{0} are media files ({1}). Prefer -MoveTo an external drive over deleting." -f `
            $media.Count, (Format-Bytes $mediaBytes)))
    }

    $huge = @($matches | Where-Object { $_.Length -ge 1GB })
    if ($huge.Count -gt 0) {
        $findings.Add(("{0} file(s) are 1 GB or larger — start with those if you want space quickly." -f $huge.Count))
    }

    if ($mode -eq 'Preview') {
        $findings.Add('Preview only. Re-run with -MoveTo <folder> to archive (writes a log; undo with -UndoLog), or -Clean to send to the Recycle Bin (asks YES). Add -Permanent with -Clean for a real delete.')
    }
}

if ($cloudSkipped -gt 0) {
    $findings.Add(("{0} OneDrive / cloud-only placeholder file(s) ({1} logical size) were skipped so they are not counted as freeable local space and moving them would not force a download. Pass -IncludeCloudOnly to include them." -f `
        $cloudSkipped, (Format-Bytes $cloudSkippedBytes)))
}

foreach ($f in $findings) {
    Write-Host ("- {0}" -f $f)
}

# --- CSV --------------------------------------------------------------------
if ($CsvPath) {
    $dir = Split-Path -Parent $CsvPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $matches |
        Sort-Object Length -Descending |
        Select-Object SourceLabel, SourceRoot, FullName, Name, Extension, Length,
            @{N = 'SizeMB'; E = { [math]::Round($_.Length / 1MB, 2) } },
            LastWriteTime, CreationTime, AgeDays |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host ("CSV written: {0}" -f $CsvPath) -ForegroundColor Green
}

if ($mode -eq 'Preview') {
    Write-Host ''
    Write-Host 'Done. Nothing was moved or deleted.' -ForegroundColor Green
    return
}

if ($matches.Count -eq 0) {
    Write-Host ''
    Write-Host 'Nothing to move or delete.' -ForegroundColor Green
    return
}

# --- Confirm ----------------------------------------------------------------
if ($mode -eq 'Move') {
    if ([string]::IsNullOrWhiteSpace($MoveTo)) { throw '-MoveTo needs a folder path.' }
    $archiveRoot = $MoveTo
    if (-not [System.IO.Path]::IsPathRooted($archiveRoot)) {
        $archiveRoot = Join-Path (Get-Location) $archiveRoot
    }
    # Refuse to archive into a folder we're scanning.
    foreach ($root in $roots) {
        $a = $archiveRoot.TrimEnd('\', '/')
        $r = $root.FullName.TrimEnd('\', '/')
        if ($a -ieq $r -or $a.StartsWith($r + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
            $r.StartsWith($a + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw ("-MoveTo '{0}' overlaps a scanned folder '{1}'. Pick an archive location outside the scan." -f $MoveTo, $root.FullName)
        }
    }
    Write-Host ''
    Write-Host ("About to MOVE {0} file(s) ({1}) into: {2}" -f $matches.Count, (Format-Bytes $totalBytes), $archiveRoot) -ForegroundColor Yellow
    Write-Host 'A CSV move log will be written so you can undo with -UndoLog.' -ForegroundColor DarkYellow
    if (-not (Confirm-Yes 'Move these files?')) {
        Write-Host 'Cancelled. Nothing changed.'
        return
    }
} elseif ($mode -eq 'CleanRecycle') {
    Write-Host ''
    Write-Host ("About to send {0} file(s) ({1}) to the RECYCLE BIN (recoverable)." -f `
        $matches.Count, (Format-Bytes $totalBytes)) -ForegroundColor Yellow
    if (-not (Confirm-Yes 'Send these files to the Recycle Bin?')) {
        Write-Host 'Cancelled. Nothing changed.'
        return
    }
} else {
    # CleanPermanent
    Write-Host ''
    Write-Host ("About to PERMANENTLY DELETE {0} file(s) ({1}). This CANNOT be undone from the Recycle Bin." -f `
        $matches.Count, (Format-Bytes $totalBytes)) -ForegroundColor Red
    if (-not (Confirm-Yes 'PERMANENTLY delete these files?')) {
        Write-Host 'Cancelled. Nothing changed.'
        return
    }
}

# --- Act --------------------------------------------------------------------
$ok = 0
$skipped = 0
$bytesDone = [int64]0

if ($mode -eq 'Move') {
    if (-not (Test-Path -LiteralPath $archiveRoot)) {
        New-Item -ItemType Directory -Path $archiveRoot -Force | Out-Null
    }
    if (-not $LogPath) {
        $LogPath = Join-Path $archiveRoot ("Find-OldLargeFiles-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    } else {
        $logDir = Split-Path -Parent $LogPath
        if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
    }

    $log = New-Object System.Collections.Generic.List[object]
    foreach ($m in $matches) {
        $row = [ordered]@{
            OriginalPath = $m.FullName
            NewPath = ''
            Action = ''
            Length = $m.Length
            SourceLabel = $m.SourceLabel
            Extension = $m.Extension
            LastWriteTime = $m.LastWriteTime
        }
        try {
            $relative = $m.FullName.Substring($m.SourceRoot.Length).TrimStart('\', '/')
            $dest = Join-Path (Join-Path $archiveRoot $m.SourceLabel) $relative
            $destDir = Split-Path -Parent $dest
            if (-not (Test-Path -LiteralPath $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            $dest = Get-UniqueDestination $dest
            Move-Item -LiteralPath $m.FullName -Destination $dest -Force:$false -ErrorAction Stop
            $row.NewPath = $dest
            $row.Action = 'Moved'
            $ok++
            $bytesDone += $m.Length
        } catch {
            $row.Action = ("Failed: {0}" -f $_.Exception.Message)
            $skipped++
            Write-Verbose ("Skip {0}: {1}" -f $m.FullName, $_.Exception.Message)
        }
        $log.Add([pscustomobject]$row)
    }
    $log | Export-Csv -LiteralPath $LogPath -NoTypeInformation -Encoding UTF8
    Write-Host ''
    Write-Host ("Moved {0} file(s) ({1}). {2} skipped (in use or access denied)." -f $ok, (Format-Bytes $bytesDone), $skipped) -ForegroundColor Green
    Write-Host ("Log: {0}" -f $LogPath)
    Write-Host ("To undo: .\Find-OldLargeFiles.ps1 -UndoLog `"{0}`"" -f $LogPath)
} elseif ($mode -eq 'CleanRecycle') {
    foreach ($m in $matches) {
        try {
            $result = Remove-ToRecycleBin $m.FullName
            if ($result -eq 'Recycled') {
                $ok++
                $bytesDone += $m.Length
            }
        } catch {
            $skipped++
            Write-Verbose ("Skip {0}: {1}" -f $m.FullName, $_.Exception.Message)
            Write-Warning ("Could not recycle {0}: {1}" -f $m.Name, $_.Exception.Message)
        }
    }
    Write-Host ''
    Write-Host ("Sent {0} file(s) ({1}) to the Recycle Bin. {2} skipped (in use, access denied, or Recycle Bin unavailable)." -f `
        $ok, (Format-Bytes $bytesDone), $skipped) -ForegroundColor Green
} else {
    foreach ($m in $matches) {
        try {
            Remove-Item -LiteralPath $m.FullName -Force -ErrorAction Stop
            $ok++
            $bytesDone += $m.Length
        } catch {
            $skipped++
            Write-Verbose ("Skip {0}: {1}" -f $m.FullName, $_.Exception.Message)
        }
    }
    Write-Host ''
    Write-Host ("Permanently deleted {0} file(s) ({1}). {2} skipped (in use or access denied)." -f `
        $ok, (Format-Bytes $bytesDone), $skipped) -ForegroundColor Green
}
