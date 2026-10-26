<#
.SYNOPSIS
    Find-SuspiciousStartup.ps1 - Read-only finder for suspicious services, Run-key
    startup entries and non-Microsoft scheduled tasks.

.DESCRIPTION
    Inspired by a real "WindowsNetService" proxyware infection: a hidden service with a
    Windows-sounding name, no publisher, no uninstall entry, running node.exe from
    C:\Program Files (x86)\WindowsNetService.

    Each autostart item is scored on these red flags:
      - Unsigned / invalid Authenticode signature on the binary
      - Binary outside C:\Windows, C:\Program Files, C:\Program Files (x86)
      - Microsoft/Windows-style name, but the signer is not Microsoft
      - No matching uninstall (Apps & Features) entry
      - Launched by a script host / runtime (node, python, wscript, cscript,
        mshta, powershell, cmd, rundll32, regsvr32)
      - Binary file missing

    Safety level : SAFE (strictly read-only). Nothing is stopped, deleted or changed.
                   No network calls are made. -ShowConnections only reads the local
                   TCP table (Get-NetTCPConnection).

    Admin        : Works without admin. Running as admin adds: full scheduled task
                   list (tasks of other users / SYSTEM), signature checks on files in
                   protected folders, and owning process info for SYSTEM services.

.PARAMETER CsvPath
    Optional. Export the full results to this CSV file (the only file written).

.PARAMETER ShowConnections
    Optional. Show live outbound TCP connections of running flagged processes.

.PARAMETER All
    Show every item, including ones with zero red flags.

.EXAMPLE
    .\Find-SuspiciousStartup.ps1
.EXAMPLE
    .\Find-SuspiciousStartup.ps1 -ShowConnections -CsvPath "$env:USERPROFILE\Desktop\startup-audit.csv"
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Find-SuspiciousStartup.ps1" -All

.NOTES
    Undo: nothing to undo - this script changes nothing.
#>
[CmdletBinding()]
param(
    [string]$CsvPath,
    [switch]$ShowConnections,
    [switch]$All
)

$ErrorActionPreference = 'SilentlyContinue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[i] Not running as admin: some scheduled tasks and protected files may be skipped." -ForegroundColor Yellow
}

$trustedRoots = @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
    Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' }
$hostNames = 'node.exe','python.exe','pythonw.exe','wscript.exe','cscript.exe','mshta.exe',
             'powershell.exe','pwsh.exe','cmd.exe','rundll32.exe','regsvr32.exe'
$fakeMsPattern = '(?i)(windows|microsoft|msft|win32|svchost|system32|defender|update)'

# --- Uninstall entries (for "has no uninstall entry" check) -----------------
$uninstallKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
$uninstallDirs = foreach ($k in $uninstallKeys) {
    Get-ItemProperty -Path $k | ForEach-Object {
        foreach ($v in @($_.InstallLocation, $_.DisplayIcon, $_.UninstallString)) {
            if ($v) {
                $p = ($v -replace '"','') -replace ',\d+$',''
                $d = if ($p -match '\.\w{2,4}(\s|$)') { Split-Path ($p -replace '\s.*\.exe.*$','') -Parent } else { $p }
                if ($d -and $d.Length -gt 3) { $d.TrimEnd('\').ToLower() }
            }
        }
    }
}
$uninstallDirs = $uninstallDirs | Where-Object { $_ } | Sort-Object -Unique

function Get-ExePath([string]$cmd) {
    if (-not $cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
    if ($c -match '^"([^"]+)"') { $p = $Matches[1] }
    elseif ($c -match '^(.+?\.(exe|com|bat|cmd|dll|ps1|vbs|js|sys))(\s|$)') { $p = $Matches[1] }
    else { $p = ($c -split '\s')[0] }
    $p = $p -replace '^\\\?\?\\','' -replace '^\\SystemRoot', $env:windir
    if ($p -match '(?i)^system32\\') { $p = Join-Path $env:windir $p }
    if (-not (Split-Path $p -IsAbsolute)) {
        $found = Get-Command $p -CommandType Application | Select-Object -First 1
        if ($found) { $p = $found.Source }
    }
    return $p
}

function Test-Item([string]$Type, [string]$Name, [string]$Command, $ProcessId) {
    $exe   = Get-ExePath $Command
    $flags = New-Object System.Collections.Generic.List[string]
    $signer = ''; $sigStatus = 'n/a'

    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) {
        $flags.Add('BinaryMissing')
    } else {
        $sig = Get-AuthenticodeSignature -LiteralPath $exe
        $sigStatus = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $signer = ($sig.SignerCertificate.Subject -replace '^CN="?([^",]+).*','$1')
        }
        if ($sig.Status -ne 'Valid') { $flags.Add("Signature:$sigStatus") }

        $inTrusted = $false
        foreach ($r in $trustedRoots) { if ($exe.StartsWith($r, 'OrdinalIgnoreCase')) { $inTrusted = $true } }
        if (-not $inTrusted) { $flags.Add('OutsideTrustedFolders') }

        if (($Name -match $fakeMsPattern -or $exe -match '(?i)\\(WindowsNetService|Microsoft[^\\]*|Windows[^\\]*)\\') -and
            $signer -notmatch '(?i)^Microsoft' -and
            -not $exe.StartsWith((Join-Path $env:windir ''), 'OrdinalIgnoreCase')) {
            $flags.Add('FakeMicrosoftName')
        }

        $isWin = $exe.StartsWith((Join-Path $env:windir ''), 'OrdinalIgnoreCase')
        if (-not $isWin -and $signer -notmatch '(?i)^Microsoft') {
            $dir = (Split-Path $exe -Parent).ToLower()
            $hasEntry = $false
            foreach ($u in $uninstallDirs) {
                if ($dir.StartsWith($u) -or $u.StartsWith($dir)) { $hasEntry = $true; break }
            }
            if (-not $hasEntry) { $flags.Add('NoUninstallEntry') }
        }
    }
    $leaf = if ($exe) { Split-Path $exe -Leaf } else { '' }
    if ($leaf -and $hostNames -contains $leaf.ToLower()) { $flags.Add("ScriptHost:$leaf") }

    [pscustomobject]@{
        Score     = $flags.Count
        Type      = $Type
        Name      = $Name
        Path      = $exe
        Signer    = $signer
        Signature = $sigStatus
        Flags     = ($flags -join ', ')
        PID       = $ProcessId
        Command   = $Command
    }
}

$results = New-Object System.Collections.Generic.List[object]

# --- Services -------------------------------------------------------------
Write-Host "[*] Checking services..." -ForegroundColor Cyan
foreach ($s in Get-CimInstance Win32_Service) {
    if (-not $s.PathName -or $s.PathName -match '(?i)\\svchost\.exe') { continue }
    $pidVal = if ($s.ProcessId) { $s.ProcessId } else { $null }
    $results.Add((Test-Item 'Service' "$($s.Name) ($($s.DisplayName))" $s.PathName $pidVal))
}

# --- Run / RunOnce keys ----------------------------------------------------
Write-Host "[*] Checking Run keys..." -ForegroundColor Cyan
$runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
           'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
foreach ($k in $runKeys) {
    $item = Get-Item -Path $k
    if (-not $item) { continue }
    foreach ($v in $item.GetValueNames()) {
        if (-not $v) { continue }
        $results.Add((Test-Item 'RunKey' "$v  [$($k -replace ':\\SOFTWARE\\.*\\','\..\')]" ([string]$item.GetValue($v)) $null))
    }
}

# --- Scheduled tasks (non-Microsoft) ---------------------------------------
Write-Host "[*] Checking scheduled tasks..." -ForegroundColor Cyan
foreach ($t in Get-ScheduledTask) {
    if ($t.TaskPath -like '\Microsoft\*') { continue }
    foreach ($a in $t.Actions) {
        if (-not $a.Execute) { continue }
        $cmd = if ($a.Execute -match '\s' -and $a.Execute -notmatch '^"') { "`"$($a.Execute)`" $($a.Arguments)" } else { "$($a.Execute) $($a.Arguments)" }
        $results.Add((Test-Item 'Task' "$($t.TaskPath)$($t.TaskName)" $cmd $null))
    }
}

# --- Map running processes to Run-key / task items by path ----------------
$procs = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath }
foreach ($r in $results) {
    if (-not $r.PID -and $r.Path) {
        $m = $procs | Where-Object { $_.ExecutablePath -ieq $r.Path } | Select-Object -First 1
        if ($m) { $r.PID = $m.ProcessId }
    }
}

$shown = if ($All) { $results } else { $results | Where-Object { $_.Score -gt 0 } }
$shown = $shown | Sort-Object -Property @{Expression='Score';Descending=$true}, Type, Name

Write-Host ""
Write-Host ("[=] {0} items checked, {1} with red flags." -f $results.Count, @($results | Where-Object Score -gt 0).Count) -ForegroundColor Green
$shown | Format-Table Score, Type, Name, Signer, Flags, PID, Path -AutoSize -Wrap

# --- Optional live connections (local TCP table only) ---------------------
if ($ShowConnections) {
    Write-Host "[*] Live outbound connections of flagged, running items:" -ForegroundColor Cyan
    $pids = $shown | Where-Object { $_.PID -and $_.Score -gt 0 } | Select-Object -ExpandProperty PID -Unique
    $conns = foreach ($p in $pids) {
        # include child processes (e.g. node.exe launched by a helper service)
        $tree = @($p) + @($procs | Where-Object { $_.ParentProcessId -eq $p } | Select-Object -ExpandProperty ProcessId)
        foreach ($tp in $tree) {
            Get-NetTCPConnection -OwningProcess $tp -State Established |
                Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } |
                ForEach-Object {
                    [pscustomobject]@{
                        PID        = $tp
                        Process    = ($procs | Where-Object ProcessId -eq $tp | Select-Object -First 1).Name
                        Local      = "$($_.LocalAddress):$($_.LocalPort)"
                        Remote     = "$($_.RemoteAddress):$($_.RemotePort)"
                    }
                }
        }
    }
    if ($conns) { $conns | Format-Table -AutoSize } else { Write-Host "    (none)" }
}

if ($CsvPath) {
    $results | Sort-Object -Property @{Expression='Score';Descending=$true}, Type, Name |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Full results exported to $CsvPath" -ForegroundColor Green
}

Write-Host "`nTip: a high score is a lead, not a verdict. Look up unknown items before removing anything." -ForegroundColor DarkGray
