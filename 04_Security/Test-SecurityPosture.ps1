<#
.SYNOPSIS
    Read-only Windows 11 security posture check with plain-English findings.

.DESCRIPTION
    Checks Microsoft Defender (real-time protection, signature age, tamper protection),
    Windows Firewall profiles, BitLocker on the system drive, UAC, Secure Boot, TPM,
    SMBv1, RDP, pending reboot, last installed update, local administrators, and
    guest account. Changes nothing and makes no network calls.
    Some checks (BitLocker, TPM, Secure Boot) need an elevated prompt; without admin
    they are reported as "Skipped" instead of failing.

.USAGE
    powershell -ExecutionPolicy Bypass -File .\04_Security\Test-SecurityPosture.ps1
    powershell -ExecutionPolicy Bypass -File .\04_Security\Test-SecurityPosture.ps1 -IssuesOnly
    powershell -ExecutionPolicy Bypass -File .\04_Security\Test-SecurityPosture.ps1 -ExportPath .\posture.csv

.PARAMETER IssuesOnly
    Show only Warn/Fail results.
.PARAMETER ExportPath
    Also save results to a CSV file at this path.
.PARAMETER MaxSignatureAgeDays
    Defender signatures older than this are flagged (default 3).
.PARAMETER MaxUpdateAgeDays
    Last installed update older than this is flagged (default 45).
#>
[CmdletBinding()]
param(
    [switch]$IssuesOnly,
    [string]$ExportPath,
    [int]$MaxSignatureAgeDays = 3,
    [int]$MaxUpdateAgeDays = 45
)

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

function Add-Result {
    param([string]$Check, [ValidateSet('OK','Warn','Fail','Skipped')][string]$Status, [string]$Detail, [string]$Fix = '')
    $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail; Fix = $Fix })
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Body, [switch]$NeedsAdmin)
    if ($NeedsAdmin -and -not $isAdmin) { Add-Result $Name 'Skipped' 'Needs an elevated prompt.'; return }
    try { & $Body } catch { Add-Result $Name 'Skipped' "Could not check: $($_.Exception.Message)" }
}

function Get-RegValue($Path, $Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# --- Defender ---
Invoke-Check 'Defender' {
    $mp = Get-MpComputerStatus
    if (-not $mp.AntivirusEnabled) { Add-Result 'Defender antivirus' 'Fail' 'Defender antivirus is off (or another AV is in use).' 'Check Windows Security > Virus & threat protection.' }
    else { Add-Result 'Defender antivirus' 'OK' 'Enabled.' }
    if ($mp.RealTimeProtectionEnabled) { Add-Result 'Real-time protection' 'OK' 'On.' }
    else { Add-Result 'Real-time protection' 'Fail' 'Real-time protection is off.' 'Turn it on in Windows Security.' }
    $age = $mp.AntivirusSignatureAge
    if ($age -le $MaxSignatureAgeDays) { Add-Result 'Defender signatures' 'OK' "$age day(s) old." }
    else { Add-Result 'Defender signatures' 'Warn' "$age day(s) old." 'Run Windows Update or: Update-MpSignature' }
    if ($mp.IsTamperProtected) { Add-Result 'Tamper protection' 'OK' 'On.' }
    else { Add-Result 'Tamper protection' 'Warn' 'Tamper protection is off.' 'Windows Security > Virus & threat protection settings.' }
}

# --- Firewall ---
Invoke-Check 'Firewall' {
    foreach ($p in Get-NetFirewallProfile) {
        if ($p.Enabled) { Add-Result "Firewall ($($p.Name))" 'OK' "On; inbound default: $($p.DefaultInboundAction)." }
        else { Add-Result "Firewall ($($p.Name))" 'Fail' 'Firewall profile is off.' 'Windows Security > Firewall & network protection.' }
    }
}

# --- UAC ---
Invoke-Check 'UAC' {
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Get-RegValue $sys 'EnableLUA'
    $prompt = Get-RegValue $sys 'ConsentPromptBehaviorAdmin'
    if ($lua -eq 0) { Add-Result 'UAC' 'Fail' 'UAC is disabled.' 'Control Panel > User Accounts > Change User Account Control settings.' }
    elseif ($prompt -eq 0) { Add-Result 'UAC' 'Warn' 'Admins are elevated without a prompt.' 'Raise the UAC slider to the default level.' }
    else { Add-Result 'UAC' 'OK' 'Enabled with prompts.' }
}

# --- SMBv1 ---
Invoke-Check 'SMBv1' {
    $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
    if ($smb1) { Add-Result 'SMBv1 server' 'Fail' 'Legacy SMBv1 is enabled (WannaCry-era risk).' 'Set-SmbServerConfiguration -EnableSMB1Protocol $false (admin)' }
    else { Add-Result 'SMBv1 server' 'OK' 'Disabled.' }
}

# --- RDP ---
Invoke-Check 'Remote Desktop' {
    $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $nla  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($deny -eq 0) {
        if ($nla -eq 1) { Add-Result 'Remote Desktop' 'Warn' 'RDP is on (with Network Level Authentication).' 'Turn off if unused: Settings > System > Remote Desktop.' }
        else { Add-Result 'Remote Desktop' 'Fail' 'RDP is on without Network Level Authentication.' 'Enable NLA or turn RDP off.' }
    } else { Add-Result 'Remote Desktop' 'OK' 'Off.' }
}

# --- Guest + local admins ---
Invoke-Check 'Local accounts' {
    $guest = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
    if ($guest -and $guest.Enabled) { Add-Result 'Guest account' 'Fail' 'Built-in Guest account is enabled.' 'Disable-LocalUser -SID <guest SID> (admin)' }
    else { Add-Result 'Guest account' 'OK' 'Disabled.' }
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
    $n = $admins.Count
    if ($n -gt 2) { Add-Result 'Local administrators' 'Warn' "$n members in Administrators." 'Review with: Get-LocalGroupMember -SID S-1-5-32-544' }
    else { Add-Result 'Local administrators' 'OK' "$n member(s)." }
}

# --- Updates + pending reboot ---
Invoke-Check 'Windows Update' {
    $last = Get-CimInstance Win32_QuickFixEngineering | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if (-not $last) { Add-Result 'Last update' 'Skipped' 'No update history found.' }
    else {
        $days = [int]((Get-Date) - $last.InstalledOn).TotalDays
        if ($days -le $MaxUpdateAgeDays) { Add-Result 'Last update' 'OK' "$($last.HotFixID) installed $days day(s) ago." }
        else { Add-Result 'Last update' 'Warn' "Last update was $days day(s) ago." 'Settings > Windows Update > Check for updates.' }
    }
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    if ($pending) { Add-Result 'Pending reboot' 'Warn' 'A restart is waiting to finish updates.' 'Restart when convenient.' }
    else { Add-Result 'Pending reboot' 'OK' 'None.' }
}

# --- Admin-only hardware/encryption checks ---
Invoke-Check 'BitLocker' -NeedsAdmin {
    $v = Get-BitLockerVolume -MountPoint $env:SystemDrive
    if ($v.ProtectionStatus -eq 'On') { Add-Result 'BitLocker' 'OK' "$($env:SystemDrive) encrypted ($($v.EncryptionMethod))." }
    else { Add-Result 'BitLocker' 'Warn' "$($env:SystemDrive) is not protected by BitLocker." 'Settings > Privacy & security > Device encryption.' }
}
Invoke-Check 'Secure Boot' -NeedsAdmin {
    if (Confirm-SecureBootUEFI) { Add-Result 'Secure Boot' 'OK' 'On.' }
    else { Add-Result 'Secure Boot' 'Warn' 'Secure Boot is off.' 'Enable in UEFI/BIOS settings.' }
}
Invoke-Check 'TPM' -NeedsAdmin {
    $t = Get-Tpm
    if ($t.TpmPresent -and $t.TpmReady) { Add-Result 'TPM' 'OK' 'Present and ready.' }
    else { Add-Result 'TPM' 'Warn' "Present: $($t.TpmPresent); Ready: $($t.TpmReady)." 'Check tpm.msc or UEFI settings.' }
}

# --- Output ---
$show = if ($IssuesOnly) { $results | Where-Object Status -in 'Warn','Fail' } else { $results }
$colors = @{ OK = 'Green'; Warn = 'Yellow'; Fail = 'Red'; Skipped = 'DarkGray' }
Write-Host "`nSecurity posture check  (admin: $isAdmin)`n" -ForegroundColor Cyan
foreach ($r in $show) {
    Write-Host ('[{0,-7}] ' -f $r.Status) -ForegroundColor $colors[$r.Status] -NoNewline
    Write-Host ('{0}: {1}' -f $r.Check, $r.Detail)
    if ($r.Fix -and $r.Status -in 'Warn','Fail') { Write-Host "          Fix: $($r.Fix)" -ForegroundColor DarkCyan }
}
$fail = @($results | Where-Object Status -eq 'Fail').Count
$warn = @($results | Where-Object Status -eq 'Warn').Count
Write-Host "`nSummary: $fail fail, $warn warning(s), $(@($results | Where-Object Status -eq 'OK').Count) OK." -ForegroundColor Cyan
if ($ExportPath) { $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8; Write-Host "Saved to $ExportPath" }
