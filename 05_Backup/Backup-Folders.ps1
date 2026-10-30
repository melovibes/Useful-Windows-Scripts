<#
.SYNOPSIS
    Back up your important folders to another drive with robocopy. Preview by default.

.DESCRIPTION
    Copies folders (Desktop, Documents, Pictures, Videos and Music by default) to a
    destination such as a USB drive or NAS share, into <Destination>\<PC name>\<folder>.
    Only new and changed files are copied, so reruns are fast.

    Safety:
      - Without -Run it only PREVIEWS (robocopy /L): shows how many files and how much
        data would be copied and whether it fits. Nothing is written.
      - With -Run it copies, but never deletes anything in the destination.
      - -Mirror makes the destination an exact copy, which DELETES destination files
        that no longer exist in the source. It needs -Run and you must type YES.
      - Refuses to back up into a folder inside the source (or the reverse).
    No admin needed. No network calls except to a share you name as -Destination.

.USAGE
    # Preview (changes nothing)
    powershell -ExecutionPolicy Bypass -File .\05_Backup\Backup-Folders.ps1 -Destination E:\Backups

    # Copy for real, with a log
    powershell -ExecutionPolicy Bypass -File .\05_Backup\Backup-Folders.ps1 -Destination E:\Backups -Run -LogPath .\backup.log

    # Pick your own folders
    powershell -ExecutionPolicy Bypass -File .\05_Backup\Backup-Folders.ps1 -Source "$env:USERPROFILE\Documents","D:\Projects" -Destination \\nas\backup -Run

.PARAMETER Source
    Folders to back up. Default: Desktop, Documents, Pictures, Videos, Music (skips ones that don't exist).
.PARAMETER Destination
    Where backups go (drive folder or UNC share). Required.
.PARAMETER Run
    Actually copy. Without it, the script only previews.
.PARAMETER Mirror
    Make the destination match the source exactly, deleting extra files there. Needs -Run and typed confirmation.
.PARAMETER ExcludeDirs
    Folder names to skip anywhere in the tree.
.PARAMETER ExcludeFiles
    File name patterns to skip.
.PARAMETER Threads
    Robocopy multithreading (1-128, default 8).
.PARAMETER LogPath
    Append robocopy output to this log file.
#>
[CmdletBinding()]
param(
    [string[]]$Source,
    [Parameter(Mandatory)][string]$Destination,
    [switch]$Run,
    [switch]$Mirror,
    [string[]]$ExcludeDirs = @('node_modules', '.git', '$RECYCLE.BIN', 'System Volume Information'),
    [string[]]$ExcludeFiles = @('desktop.ini', 'Thumbs.db', '~$*', '*.tmp'),
    [ValidateRange(1, 128)][int]$Threads = 8,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

if ($Mirror -and -not $Run) { throw '-Mirror only makes sense with -Run. Preview first without either switch.' }
if (-not (Get-Command robocopy.exe -ErrorAction SilentlyContinue)) { throw 'robocopy.exe not found (it ships with Windows).' }

if (-not $Source) {
    $Source = 'Desktop', 'MyDocuments', 'MyPictures', 'MyVideos', 'MyMusic' |
        ForEach-Object { [Environment]::GetFolderPath($_) } | Where-Object { $_ }
}

$sources = foreach ($s in $Source) {
    if (Test-Path -LiteralPath $s -PathType Container) { (Resolve-Path -LiteralPath $s).ProviderPath.TrimEnd('\') }
    else { Write-Warning "Skipping missing folder: $s" }
}
$sources = @($sources | Select-Object -Unique)
if (-not $sources) { throw 'No source folders to back up.' }

$destRoot = Join-Path $Destination $env:COMPUTERNAME
$destFull = [IO.Path]::GetFullPath($destRoot).TrimEnd('\')

function Test-Nested([string]$a, [string]$b) {
    $a = $a.TrimEnd('\') + '\'; $b = $b.TrimEnd('\') + '\'
    $a.StartsWith($b, [StringComparison]::OrdinalIgnoreCase) -or $b.StartsWith($a, [StringComparison]::OrdinalIgnoreCase)
}
foreach ($s in $sources) {
    if (Test-Nested $s $destFull) { throw "Destination '$destFull' overlaps source '$s'. Pick a destination outside your source folders." }
}

# Give each source a unique folder name in the destination.
$jobs = @(); $used = @{}
foreach ($s in $sources) {
    $name = Split-Path $s -Leaf
    if (-not $name) { $name = ($s -replace '[:\\]', '') + '_drive' }
    $base = $name; $i = 2
    while ($used.ContainsKey($name)) { $name = "$base ($i)"; $i++ }
    $used[$name] = $true
    $jobs += [pscustomobject]@{ Source = $s; Target = Join-Path $destRoot $name }
}

if ($Mirror) {
    Write-Host ''
    Write-Host 'MIRROR MODE: files in these destination folders that are not in the source will be DELETED:' -ForegroundColor Red
    $jobs | ForEach-Object { Write-Host "  $($_.Target)" -ForegroundColor Red }
    $answer = Read-Host 'Type YES to continue'
    if ($answer -cne 'YES') { Write-Host 'Cancelled. Nothing was changed.'; return }
}

$mode = if (-not $Run) { 'PREVIEW (nothing will be written)' } elseif ($Mirror) { 'MIRROR' } else { 'COPY (no deletes)' }
Write-Host ''
Write-Host "Backup-Folders: $mode" -ForegroundColor Cyan
Write-Host "Destination: $destRoot"
Write-Host ''

function Get-RoboStat([string[]]$lines, [string]$label) {
    # Parses the robocopy summary row: "Label : Total Copied Skipped Mismatch FAILED Extras" (English output).
    $row = $lines | Where-Object { $_ -match "^\s*$label\s*:\s*\d" } | Select-Object -Last 1
    if (-not $row) { return $null }
    $n = [regex]::Matches(($row -split ':', 2)[1], '\d+') | ForEach-Object { [int64]$_.Value }
    if ($n.Count -ge 6) { [pscustomobject]@{ Total = $n[0]; Copied = $n[1]; Failed = $n[4]; Extras = $n[5] } }
}

function Format-Size([int64]$b) {
    if ($b -ge 1GB) { '{0:N1} GB' -f ($b / 1GB) } elseif ($b -ge 1MB) { '{0:N1} MB' -f ($b / 1MB) } else { '{0:N0} KB' -f ($b / 1KB) }
}

$summary = @(); $totalBytes = 0; $worst = 0
foreach ($j in $jobs) {
    $roboArgs = @($j.Source, $j.Target, '/E', '/COPY:DAT', '/DCOPY:DAT', '/R:1', '/W:2', '/XJ', '/FFT',
              '/NP', '/NDL', '/NFL', '/BYTES', "/MT:$Threads")
    if ($Mirror) { $roboArgs += '/PURGE' }
    if (-not $Run) { $roboArgs += '/L' }
    if ($ExcludeDirs) { $roboArgs += '/XD'; $roboArgs += $ExcludeDirs }
    if ($ExcludeFiles) { $roboArgs += '/XF'; $roboArgs += $ExcludeFiles }

    Write-Host "-> $($j.Source)" -ForegroundColor Yellow
    $out = & robocopy.exe @roboArgs 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    if ($LogPath) { "==== $(Get-Date -Format s) $($j.Source) -> $($j.Target) [$mode] exit $code" , $out | Add-Content -LiteralPath $LogPath }
    if ($code -gt $worst) { $worst = $code }

    $files = Get-RoboStat $out 'Files'
    $bytes = Get-RoboStat $out 'Bytes'
    if ($bytes) { $totalBytes += $bytes.Copied }
    $summary += [pscustomobject]@{
        Folder = Split-Path $j.Source -Leaf
        Files  = if ($files) { $files.Total } else { '?' }
        ToCopy = if ($files) { $files.Copied } else { '?' }
        Size   = if ($bytes) { Format-Size $bytes.Copied } else { '?' }
        Failed = if ($files) { $files.Failed } else { '?' }
        Result = if ($code -ge 8) { "Errors (code $code)" } elseif ($code -eq 0) { 'Up to date' } else { 'OK' }
    }
}

$summary | Format-Table -AutoSize

if (-not $Run) {
    $qualifier = if ($destFull -match '^[A-Za-z]:') { $destFull.Substring(0, 2) } else { $null }
    if ($qualifier) {
        $drive = Get-PSDrive -Name $qualifier.TrimEnd(':') -ErrorAction SilentlyContinue
        if ($drive -and $drive.Free -ne $null) {
            $fit = if ($drive.Free -gt $totalBytes) { 'fits' } else { 'DOES NOT FIT' }
            Write-Host ("Would copy {0}; {1} has {2} free, so it {3}." -f (Format-Size $totalBytes), $qualifier, (Format-Size $drive.Free), $fit)
        }
    } else {
        Write-Host ("Would copy {0}." -f (Format-Size $totalBytes))
    }
    Write-Host 'Preview only. Add -Run to copy.' -ForegroundColor Cyan
} elseif ($worst -ge 8) {
    Write-Host 'Some files could not be copied (often files in use). Rerun later or check the log.' -ForegroundColor Red
} else {
    Write-Host 'Backup finished.' -ForegroundColor Green
}

exit ([int]($worst -ge 8))
