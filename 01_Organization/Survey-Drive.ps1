<#
.SYNOPSIS
    Survey-Drive.ps1 - Read-only survey of a messy drive or folder: what's taking
    space, what's old, what's duplicated, and whether it holds an old Windows install.

.DESCRIPTION
    Built for the "old drive I can't find anything on" problem. Point it at a drive
    (H:\, I:\) or any folder and it reports:
      - Overview: file count, total size, oldest and newest files
      - Biggest top-level folders (with file counts)
      - Largest files
      - Space by file type (extension) and by kind (Video, Photos, Archives...)
      - Age buckets by last-modified date (< 1 yr, 1-3 yrs, 3-5 yrs, 5-10 yrs, 10+ yrs)
      - Leftover Windows installs (\Windows, \Users\<name>, Program Files, Windows.old)
        and the personal folders inside each old user profile
      - Optional: duplicate files (same size, then same SHA-256 hash) and wasted space

    Safety level : SAFE (strictly read-only). Nothing is moved, renamed or deleted.
                   No network calls. The only files written are the optional
                   -CsvPath / -HtmlPath reports.

    Admin        : Not required. Folders you can't read (old profiles, System Volume
                   Information) are skipped and counted. Run as admin for better
                   coverage of an old Windows install.

.PARAMETER Path
    Drive or folder to survey, e.g. H:\ or "I:\Users\user". Required.

.PARAMETER Top
    How many rows to show in the "biggest" lists. Default 25.

.PARAMETER MinLargeMB
    Only files at least this big (MB) show in "Largest files". Default 100.

.PARAMETER FindDuplicates
    Also look for duplicate files. Hashes only files that share an exact size,
    so it's much faster than hashing everything, but can still take a while.

.PARAMETER MinDupMB
    Skip files smaller than this (MB) when looking for duplicates. Default 1.

.PARAMETER Exclude
    Folder names to skip anywhere in the tree, e.g. 'node_modules','$RECYCLE.BIN'.

.PARAMETER CsvPath
    Export the full file list (path, size, kind, dates, duplicate group) to CSV.

.PARAMETER HtmlPath
    Save the report as a simple HTML page you can open in a browser.

.EXAMPLE
    .\Survey-Drive.ps1 -Path H:\
.EXAMPLE
    .\Survey-Drive.ps1 -Path I:\ -FindDuplicates -HtmlPath "$env:USERPROFILE\Desktop\I-drive.html"
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File ".\01_Organization\Survey-Drive.ps1" -Path "I:\Users\user" -CsvPath .\old-profile.csv

.NOTES
    Undo: nothing to undo - this script changes nothing.
    Works in Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,
    [int]$Top = 25,
    [double]$MinLargeMB = 100,
    [switch]$FindDuplicates,
    [double]$MinDupMB = 1,
    [string[]]$Exclude = @('$RECYCLE.BIN', 'System Volume Information'),
    [string]$CsvPath,
    [string]$HtmlPath
)

$ErrorActionPreference = 'Stop'

function Format-Size([double]$Bytes) {
    if ($Bytes -ge 1TB) { return '{0:N2} TB' -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return '{0:N0} KB' -f ($Bytes / 1KB) }
    return "$Bytes B"
}

$Kinds = [ordered]@{
    'Video'     = '.mp4 .mkv .avi .mov .wmv .m4v .mpg .mpeg .flv .webm .3gp .ts .vob'
    'Photos'    = '.jpg .jpeg .png .gif .bmp .tif .tiff .heic .webp .raw .cr2 .nef .arw .dng .psd'
    'Music'     = '.mp3 .flac .wav .m4a .aac .ogg .wma .alac .aiff'
    'Documents' = '.pdf .doc .docx .xls .xlsx .ppt .pptx .txt .rtf .odt .csv .md'
    'Archives'  = '.zip .rar .7z .tar .gz .bz2 .xz'
    'DiskImages'= '.iso .img .vhd .vhdx .vmdk .wim .esd .bak .gho .tib'
    'Programs'  = '.exe .msi .dll .sys .cab .msu .appx .msix'
    'Code'      = '.ps1 .py .js .ts .cs .cpp .h .java .html .css .json .xml .bat .cmd .sh'
}
$KindOf = @{}
foreach ($k in $Kinds.Keys) { foreach ($e in $Kinds[$k].Split(' ')) { $KindOf[$e] = $k } }

# ---------- Scan ----------
$root = (Resolve-Path -LiteralPath $Path).ProviderPath
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Not a folder: $Path" }

Write-Host "Surveying $root (read-only)..." -ForegroundColor Cyan
$files   = New-Object System.Collections.Generic.List[object]
$skipped = 0
$stack   = New-Object System.Collections.Generic.Stack[string]
$stack.Push($root)
$excludeSet = @{}; foreach ($x in $Exclude) { $excludeSet[$x.ToLowerInvariant()] = $true }
$sw = [Diagnostics.Stopwatch]::StartNew()

while ($stack.Count -gt 0) {
    $dir = $stack.Pop()
    try {
        $di = New-Object System.IO.DirectoryInfo $dir
        foreach ($item in $di.EnumerateFileSystemInfos()) {
            if ($item -is [System.IO.DirectoryInfo]) {
                # Don't follow junctions/symlinks (old profiles are full of them)
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($excludeSet.ContainsKey($item.Name.ToLowerInvariant())) { continue }
                $stack.Push($item.FullName)
            } else {
                $files.Add($item)
                if ($files.Count % 20000 -eq 0) {
                    Write-Progress -Activity 'Scanning' -Status ("{0:N0} files" -f $files.Count) -CurrentOperation $dir
                }
            }
        }
    } catch {
        $skipped++
    }
}
Write-Progress -Activity 'Scanning' -Completed
$totalBytes = ($files | Measure-Object -Property Length -Sum).Sum
if (-not $totalBytes) { $totalBytes = 0 }

$report = New-Object System.Text.StringBuilder
function Out-Section([string]$Title, $Rows) {
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Yellow
    if ($Rows) { $Rows | Format-Table -AutoSize | Out-String -Width 220 | Write-Host }
    else { Write-Host '  (none)' }
    [void]$report.AppendLine("<h2>$([Net.WebUtility]::HtmlEncode($Title))</h2>")
    if ($Rows) { [void]$report.AppendLine(($Rows | ConvertTo-Html -Fragment | Out-String)) }
    else { [void]$report.AppendLine('<p>(none)</p>') }
}

# ---------- Overview ----------
$byDate = $files | Sort-Object LastWriteTime
$overview = [pscustomobject]@{
    Path        = $root
    Files       = '{0:N0}' -f $files.Count
    TotalSize   = Format-Size $totalBytes
    Oldest      = if ($byDate) { $byDate[0].LastWriteTime.ToString('yyyy-MM-dd') } else { '-' }
    Newest      = if ($byDate) { $byDate[-1].LastWriteTime.ToString('yyyy-MM-dd') } else { '-' }
    SkippedDirs = $skipped
    ScanTime    = '{0:N0}s' -f $sw.Elapsed.TotalSeconds
}
Out-Section 'Overview' @($overview)

# ---------- Top-level folders ----------
$prefixLen = $root.TrimEnd('\').Length + 1
$topFolders = $files | Group-Object {
    $rel = $_.FullName.Substring([Math]::Min($prefixLen, $_.FullName.Length))
    $i = $rel.IndexOf('\')
    if ($i -lt 0) { '(files in root)' } else { $rel.Substring(0, $i) }
} | ForEach-Object {
    $sum = ($_.Group | Measure-Object Length -Sum).Sum
    [pscustomobject]@{ Folder = $_.Name; Size = Format-Size $sum; Files = $_.Count
        Share = '{0:P0}' -f ($(if ($totalBytes) { $sum / $totalBytes } else { 0 })); Bytes = $sum }
} | Sort-Object Bytes -Descending | Select-Object -First $Top Folder, Size, Files, Share
Out-Section "Biggest top-level folders" $topFolders

# ---------- Largest files ----------
$minLarge = [long]($MinLargeMB * 1MB)
$largest = $files | Where-Object { $_.Length -ge $minLarge } | Sort-Object Length -Descending |
    Select-Object -First $Top @{n='Size';e={Format-Size $_.Length}},
        @{n='Modified';e={$_.LastWriteTime.ToString('yyyy-MM-dd')}}, FullName
Out-Section "Largest files (>= $MinLargeMB MB)" $largest

# ---------- By kind and extension ----------
$byKind = $files | Group-Object { $k = $KindOf[$_.Extension.ToLowerInvariant()]; if ($k) { $k } else { 'Other' } } |
    ForEach-Object { $s = ($_.Group | Measure-Object Length -Sum).Sum
        [pscustomobject]@{ Kind = $_.Name; Size = Format-Size $s; Files = $_.Count; Bytes = $s } } |
    Sort-Object Bytes -Descending | Select-Object Kind, Size, Files
Out-Section 'Space by kind' $byKind

$byExt = $files | Group-Object { if ($_.Extension) { $_.Extension.ToLowerInvariant() } else { '(none)' } } |
    ForEach-Object { $s = ($_.Group | Measure-Object Length -Sum).Sum
        [pscustomobject]@{ Extension = $_.Name; Size = Format-Size $s; Files = $_.Count; Bytes = $s } } |
    Sort-Object Bytes -Descending | Select-Object -First $Top Extension, Size, Files
Out-Section 'Space by file type' $byExt

# ---------- Age buckets ----------
$now = Get-Date
$ages = $files | Group-Object {
    $y = ($now - $_.LastWriteTime).TotalDays / 365.25
    if ($y -lt 1) { '1: < 1 year' } elseif ($y -lt 3) { '2: 1-3 years' } elseif ($y -lt 5) { '3: 3-5 years' }
    elseif ($y -lt 10) { '4: 5-10 years' } else { '5: 10+ years' }
} | Sort-Object Name | ForEach-Object { $s = ($_.Group | Measure-Object Length -Sum).Sum
    [pscustomobject]@{ LastModified = $_.Name.Substring(3); Size = Format-Size $s; Files = $_.Count } }
Out-Section 'Age (last modified)' $ages

# ---------- Old Windows installs ----------
$winRows = @()
$candidates = @($root) + @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'Windows.old*' } | ForEach-Object FullName)
foreach ($c in $candidates) {
    if (Test-Path -LiteralPath (Join-Path $c 'Windows\System32')) {
        $usersDir = Join-Path $c 'Users'
        $profiles = Get-ChildItem -LiteralPath $usersDir -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin 'Public', 'Default', 'Default User', 'All Users' -and
                -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
        foreach ($p in $profiles) {
            foreach ($sub in 'Desktop', 'Documents', 'Pictures', 'Videos', 'Music', 'Downloads', 'OneDrive') {
                $sp = Join-Path $p.FullName $sub
                if (Test-Path -LiteralPath $sp) {
                    $pref = $sp.TrimEnd('\') + '\'
                    $hits = $files | Where-Object { $_.FullName.StartsWith($pref, [StringComparison]::OrdinalIgnoreCase) }
                    $s = ($hits | Measure-Object Length -Sum).Sum
                    if (-not $s) { $s = 0 }
                    $winRows += [pscustomobject]@{ Install = $c; Profile = $p.Name; Folder = $sub
                        Size = Format-Size $s; Files = @($hits).Count }
                }
            }
        }
        if (-not $profiles) { $winRows += [pscustomobject]@{ Install = $c; Profile = '(none found)'; Folder = '-'; Size = '-'; Files = 0 } }
    }
}
Out-Section 'Old Windows installs and personal folders worth rescuing' $winRows

# ---------- Duplicates ----------
$dupOf = @{}
if ($FindDuplicates) {
    $minDup = [long]($MinDupMB * 1MB)
    $sizeGroups = $files | Where-Object { $_.Length -ge $minDup } | Group-Object Length | Where-Object Count -gt 1
    $toHash = ($sizeGroups | Measure-Object Count -Sum).Sum
    $done = 0; $dupGroups = @(); $gid = 0
    foreach ($g in $sizeGroups) {
        $hashed = foreach ($f in $g.Group) {
            $done++
            if ($done % 50 -eq 0) { Write-Progress -Activity 'Hashing same-size files' -Status "$done / $toHash" }
            try { [pscustomobject]@{ File = $f; Hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash } } catch { }
        }
        foreach ($h in ($hashed | Group-Object Hash | Where-Object Count -gt 1)) {
            $gid++
            $keep = $h.Group | Sort-Object { $_.File.LastWriteTime } | Select-Object -First 1
            foreach ($x in $h.Group) { $dupOf[$x.File.FullName] = $gid }
            $dupGroups += [pscustomobject]@{ Group = $gid; Copies = $h.Count; Size = Format-Size $g.Name
                Wasted = Format-Size (([long]$g.Name) * ($h.Count - 1)); WastedBytes = ([long]$g.Name) * ($h.Count - 1)
                Oldest = $keep.File.FullName; Others = (($h.Group | Where-Object { $_ -ne $keep }).File.FullName -join ' | ') }
        }
    }
    Write-Progress -Activity 'Hashing same-size files' -Completed
    $wasted = ($dupGroups | Measure-Object WastedBytes -Sum).Sum
    if (-not $wasted) { $wasted = 0 }
    Write-Host ''
    Write-Host ("Duplicates: {0} groups, {1} reclaimable (nothing was deleted)" -f $dupGroups.Count, (Format-Size $wasted)) -ForegroundColor Green
    Out-Section "Duplicate files (top $Top by wasted space)" ($dupGroups | Sort-Object WastedBytes -Descending |
        Select-Object -First $Top Group, Copies, Size, Wasted, Oldest, Others)
}

# ---------- Exports ----------
if ($CsvPath) {
    $files | Select-Object FullName, @{n='SizeMB';e={[Math]::Round($_.Length / 1MB, 2)}}, Extension,
        @{n='Kind';e={ $k = $KindOf[$_.Extension.ToLowerInvariant()]; if ($k) { $k } else { 'Other' } }},
        LastWriteTime, CreationTime, @{n='DuplicateGroup';e={ $dupOf[$_.FullName] }} |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV saved: $CsvPath" -ForegroundColor Green
}
if ($HtmlPath) {
    $css = 'body{font-family:Segoe UI,Arial;margin:24px}table{border-collapse:collapse;margin-bottom:16px}td,th{border:1px solid #ccc;padding:4px 8px;font-size:13px}th{background:#eee}'
    $html = "<html><head><meta charset='utf-8'><title>Drive survey: $([Net.WebUtility]::HtmlEncode($root))</title><style>$css</style></head><body><h1>Drive survey: $([Net.WebUtility]::HtmlEncode($root))</h1><p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm'). Read-only scan; nothing was changed.</p>$($report.ToString())</body></html>"
    Set-Content -LiteralPath $HtmlPath -Value $html -Encoding UTF8
    Write-Host "HTML report saved: $HtmlPath" -ForegroundColor Green
}
Write-Host ''
Write-Host 'Done. Nothing was moved, renamed or deleted.' -ForegroundColor Cyan
