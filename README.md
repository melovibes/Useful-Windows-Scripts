# Useful Windows 11 Scripts 🛠️💻

A growing collection of practical, well-commented PowerShell and Python scripts that make life on Windows 11 easier, faster, safer or less annoying.

Made for power users, IT folks, small-business PCs and anyone who hates doing the same thing 50 times by hand.

## 📋 Script index

| Script | Category | What it does | Safety | Admin? |
|---|---|---|---|---|
| [Organize_Downloads.py](01_Organization/Organize_Downloads.py) | 01 Organization | Sorts your Downloads folder into subfolders by file type | Moves files | No |
| [Survey-Drive.ps1](01_Organization/Survey-Drive.ps1) | 01 Organization | Reports what's taking space on a messy drive: biggest folders and files, file types, age, old Windows installs and duplicates | Read-only | No |
| [Sort-PhotosByDate.ps1](01_Organization/Sort-PhotosByDate.ps1) | 01 Organization | Sorts photos and videos into Year\Month folders by the date they were taken (EXIF, then file name, then file date) | Preview by default; moves or copies with -Run after typing YES, never deletes, undo log | No |
| [Find-OldLargeFiles.ps1](01_Organization/Find-OldLargeFiles.ps1) | 01 Organization | Finds files that are both old and large in Downloads, Desktop, Documents and other folders you name; skips OneDrive cloud-only placeholders by default; preview by default, optional move (with undo log), Recycle Bin, or permanent delete after typing YES | Preview by default; -MoveTo / -Clean / -UndoLog change files after YES | No |
| [Get-StartupImpact.ps1](02_Performance/Get-StartupImpact.ps1) | 02 Performance | Lists startup apps, logon tasks and auto-start services with their CPU and disk impact, plus boot times and what Windows says slowed boot | Read-only | Optional |
| [Clear-TempAndCache.ps1](02_Performance/Clear-TempAndCache.ps1) | 02 Performance | Measures temp folders, browser caches, crash dumps and the Windows Update cache, and clears them only with `-Clean` | Preview by default; deletes with -Clean after typing YES | Optional (needed for system caches) |
| [Get-PowerReport.ps1](02_Performance/Get-PowerReport.ps1) | 02 Performance | Shows your power plan and mode, screen and sleep timeouts, wake settings, CPU limits and battery health, then lists anything wasting power or slowing the PC | Read-only | Optional |
| [Get-ResourceHogs.ps1](02_Performance/Get-ResourceHogs.ps1) | 02 Performance | Watches the PC for about 30 seconds and lists the apps using the most CPU, memory and disk, with system totals and plain-English findings | Read-only | Optional |
| [Get-DiskHealth.ps1](02_Performance/Get-DiskHealth.ps1) | 02 Performance | Reports physical disk model, media, health/operational status (incl. predictive failure), volume free space, drive age (power-on hours or PnP first-seen), firmware + storage driver date/version, and SMART-style reliability counters (temp, wear, read/write and uncorrected errors) when available, plus plain-English findings | Read-only | Optional |
| [Get-CrashHistory.ps1](02_Performance/Get-CrashHistory.ps1) | 02 Performance | Shows what's been crashing over the last 30 days: blue screens with their stop codes, unexpected shutdowns (crash vs. power loss), app crashes and hangs grouped by app and crashing module, WHEA hardware errors and disk errors, plus the Reliability Monitor score and plain-English findings | Read-only | Optional |
| [Block-Distractions.ps1](03_Utilities/Block-Distractions.ps1) | 03 Utilities | Blocks distracting and risky sites via the hosts file | Dry run by default, with backup and undo | To apply |
| [Test-HomeNetwork.ps1](03_Utilities/Test-HomeNetwork.ps1) | 03 Utilities | Checks adapters, Wi-Fi signal, gateway and internet latency, packet loss, DNS speed and proxy settings, then lists problems in plain English | Read-only | No |
| [Get-ActiveConnections.ps1](03_Utilities/Get-ActiveConnections.ps1) | 03 Utilities | Shows which programs have network connections right now, whether each remote end is this PC, your LAN or the internet, whether the program is signed, and plain-English findings | Read-only | Optional |
| [Find-SuspiciousStartup.ps1](04_Security/Find-SuspiciousStartup.ps1) | 04 Security | Flags suspicious services, startup entries and scheduled tasks | Read-only | Optional |
| [Test-SecurityPosture.ps1](04_Security/Test-SecurityPosture.ps1) | 04 Security | Checks Defender, firewall, BitLocker, UAC, Secure Boot, TPM, SMBv1, RDP, updates and local accounts, then lists problems with fixes | Read-only | Optional |
| [Get-ListeningPorts.ps1](04_Security/Get-ListeningPorts.ps1) | 04 Security | Lists every program listening for network connections, who can reach it, whether it's signed and whether the firewall lets it in, plus your shared folders and plain-English findings | Read-only | Optional |
| [Find-OutdatedApps.ps1](04_Security/Find-OutdatedApps.ps1) | 04 Security | Lists installed apps and flags what's out of support (old Python, .NET, Node.js, Office, Flash, Java and more), what's missing well-known security fixes, what hasn't been updated in years, whether your Windows 11 version still gets updates, and optionally what winget can upgrade | Read-only | No |
| [Backup-Folders.ps1](05_Backup/Backup-Folders.ps1) | 05 Backup | Backs up Desktop, Documents, Pictures and other folders to a USB drive or NAS with robocopy, copying only new and changed files | Preview by default; never deletes unless `-Mirror` and you type YES | No |
| [Test-BackupHealth.ps1](05_Backup/Test-BackupHealth.ps1) | 05 Backup | Checks System Restore, File History, OneDrive folder backup, system images, the recovery environment, BitLocker recovery keys and your own backup drive or NAS, then shows what isn't backed up and how to fix it | Read-only | Optional |

## 📂 Categories

- **01_Organization**: file and folder tidying, Explorer tweaks
- **02_Performance**: service optimizations, startup, gaming tweaks, telemetry
- **03_Utilities**: quick tools, network diagnostics, cleanup, system shortcuts
- **04_Security**: security posture checks, startup and persistence audits
- **05_Backup**: backups of your files to another drive or NAS

---

## 01_Organization

### Organize_Downloads.py

Sorts everything in your Downloads folder into subfolders like Images, Videos, Documents, Archives and Executables. Anything unrecognized goes to **Other**.

```powershell
python .\01_Organization\Organize_Downloads.py
```

- Needs [Python 3](https://www.python.org/downloads/).
- Edit the `FOLDERS` list at the top of the script to change the categories.

### Survey-Drive.ps1

A read-only survey for that old drive you can't find anything on. It shows the biggest top-level folders and files, space by file type and by kind (Video, Photos, Archives and more), and how old everything is. It also spots leftover Windows installs and lists the Desktop, Documents and Pictures folders inside each old user profile, so you know what's worth rescuing before you wipe anything. Junctions are skipped, so old profiles don't get counted twice.

```powershell
# Quick survey
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Survey-Drive.ps1" -Path H:\

# Full survey with duplicates and a report you can open in a browser
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Survey-Drive.ps1" -Path I:\ -FindDuplicates -HtmlPath "$env:USERPROFILE\Desktop\I-drive.html"
```

| Switch | What it does |
|---|---|
| `-Path <drive or folder>` | What to survey (required) |
| `-Top <n>` | Rows in each "biggest" list (default 25) |
| `-MinLargeMB <n>` | Size cutoff for "Largest files" (default 100) |
| `-FindDuplicates` | Find duplicate files by size, then SHA-256 hash, and total the wasted space |
| `-MinDupMB <n>` | Skip files smaller than this when finding duplicates (default 1) |
| `-Exclude 'a','b'` | Folder names to skip |
| `-CsvPath <file>` | Export every file with size, kind, dates and duplicate group |
| `-HtmlPath <file>` | Save the report as an HTML page |

Works without admin; run as admin to read more of an old Windows install. **Changes nothing.**

### Sort-PhotosByDate.ps1

Turns a messy phone dump or camera card into a tidy `2023\05 - May` library. For each photo or video it reads the "date taken" stamp from the file's EXIF data (JPEG, HEIC and most camera RAW files), falls back to a date in the file name (like `IMG_20230514_...` or `PXL_20230514...`), and finally to the file's Last Modified date. With no switches it only shows the plan: how many files go where and which date source each used. `-Run` moves the files (or `-Copy` copies them) after you type YES. It never deletes anything: name clashes get ` (2)` added, and a file that's byte-for-byte identical to one already in place is left where it is. Every run writes a CSV log, and `-UndoLog` puts moved files back.

```powershell
# Preview (changes nothing)
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Sort-PhotosByDate.ps1" -Path "$env:USERPROFILE\Pictures\Phone dump"

# Copy a camera card into your photo library, keeping the originals
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Sort-PhotosByDate.ps1" -Path E:\DCIM -Destination D:\Photos -Run -Copy

# Undo a move
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Sort-PhotosByDate.ps1" -UndoLog "D:\Photos\Sort-PhotosByDate-20261103-090000.csv"
```

| Switch | What it does |
|---|---|
| `-Path <folder>` | Folder to sort (required) |
| `-Destination <folder>` | Where the Year\Month folders go (default: same as `-Path`) |
| `-Run` | Actually move the files (asks you to type YES) |
| `-Copy` | With `-Run`, copy instead of move |
| `-Force` | Skip the YES prompt |
| `-NoFileDate` | Don't use Last Modified; undated files go to `Unknown date` |
| `-NoRecurse` | Only sort files directly in `-Path` |
| `-Extensions '.jpg','.mp4'` | File types to include (default: common photo, RAW and video types) |
| `-MonthFormat Number\|Name\|Flat` | `2023\05`, `2023\05 - May` (default) or `2023-05` |
| `-LogPath <file>` | Where to save the CSV log (default: in the destination) |
| `-UndoLog <file>` | Move files from an earlier run back where they came from |

Works without admin and needs no extra modules. Last Modified can be the date a file was copied rather than taken, so check the "Date source" counts in the preview.

---

### Find-OldLargeFiles.ps1

Answers "what's eating space that I haven't touched in months?" It walks your Downloads, Desktop, Documents, Videos and Pictures (or folders you pass) and lists files that are both older than a cutoff (default 90 days by LastWriteTime) and larger than a size floor (default 50 MB). With no switches it only shows a summary by folder, a breakdown by file type (top extensions by size), the largest matches and plain-English findings (for example installers and archives that are often safe to archive).

OneDrive Files On-Demand cloud-only placeholders are **skipped by default** so their logical cloud size is not counted as freeable local space and moving them does not force a download — pass `-IncludeCloudOnly` to include them (the Summary and Findings report how many were skipped).

`-MoveTo` relocates matches into an archive folder after you type YES, keeping relative paths, never overwriting, and writing a CSV move log (default `<MoveTo>\Find-OldLargeFiles-<time>.csv`, or `-LogPath`) so `-UndoLog` can reverse the run. `-Clean` sends matches to the **Recycle Bin** after YES; add `-Permanent` with `-Clean` for a real delete. Junctions are skipped so linked folders aren't walked twice.

```powershell
# Preview (changes nothing)
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1"

# Stricter cutoffs and a CSV of every match
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1" -OlderThanDays 180 -MinSizeMB 100 -CsvPath "$env:USERPROFILE\Desktop\old-large.csv"

# Move old installers and archives from Downloads onto another drive
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1" -Path "$env:USERPROFILE\Downloads" -Extensions '.iso','.zip','.exe','.msi' -MoveTo D:\Archive\OldDownloads

# Undo a previous -MoveTo run
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1" -UndoLog D:\Archive\OldDownloads\Find-OldLargeFiles-20261106-0900.csv

# Send matches to the Recycle Bin (recoverable)
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Find-OldLargeFiles.ps1" -Clean
```

| Switch | What it does |
|---|---|
| `-Path 'a','b'` | Folders to scan (default Downloads, Desktop, Documents, Videos, Pictures) |
| `-OlderThanDays <n>` | Only files last changed at least this many days ago (default 90; 0 = ignore age) |
| `-MinSizeMB <n>` | Only files at least this many MB (default 50; 0 = any size) |
| `-Top <n>` | How many largest files to show on screen (default 40; CSV still has all) |
| `-Extensions '.iso','.zip'` | Only these file types |
| `-Exclude 'a','b'` | Folder names to skip (default `node_modules`, `.git`, `AppData`, recycle/system folders) |
| `-IncludeCloudOnly` | Include OneDrive cloud-only placeholders (skipped by default) |
| `-MoveTo <folder>` | Move matches into this archive folder after typing YES; writes a CSV move log |
| `-LogPath <file>` | Where to write the `-MoveTo` CSV log (default under `-MoveTo`) |
| `-UndoLog <file>` | Reverse a previous `-MoveTo` run from its CSV log (asks YES; never overwrites) |
| `-Clean` | Send matches to the Recycle Bin after typing YES |
| `-Permanent` | With `-Clean` only: permanently delete instead of Recycle Bin |
| `-Force` | With `-MoveTo`, `-Clean` or `-UndoLog`, skip the YES prompt |
| `-CsvPath <file>` | Export every match to CSV |

Works without admin. Preview changes nothing; `-MoveTo` refuses an archive path that overlaps a scanned folder; `-UndoLog` never overwrites an existing file at the original path.

---

## 02_Performance

### Get-StartupImpact.ps1

A read-only answer to "why does my PC take so long to start?" It lists everything that launches with Windows: startup apps from the registry and Startup folders (with their on/off state from Settings), non-Microsoft scheduled tasks that run at logon or boot, and non-Microsoft auto-start services. For each one that's running it shows CPU time, disk I/O and memory, and rates it High, Medium or Low using Task Manager's cut-offs. It also shows your last boot and whether Fast Startup is on. Run it as admin to add recent boot times and the apps and services Windows itself logged as slowing down boot. It ends with a short list of high-impact startup apps you could turn off.

```powershell
# Quick report
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-StartupImpact.ps1"

# Everything, including disabled items, saved to a CSV
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-StartupImpact.ps1" -All -CsvPath "$env:USERPROFILE\Desktop\startup.csv"
```

| Switch | What it does |
|---|---|
| `-All` | Also show disabled startup apps and items that aren't running |
| `-Days <n>` | Days of boot history to read when run as admin (default 30) |
| `-CsvPath <file>` | Export the full startup list to CSV |

CPU and disk are totals since each app launched, so apps left open all day can rate higher than Task Manager shows. Works without admin; run as admin for boot history and SYSTEM services. **Changes nothing.**

### Clear-TempAndCache.ps1

Shows how much space your temp folders and caches are using, and clears them only when you ask. It covers your temp folder, C:\Windows\Temp, the Edge, Chrome, Brave and Firefox caches (all profiles, cache only, never cookies, history or passwords), Explorer's thumbnail cache, crash dumps and error reports, the Delivery Optimization cache, and the Windows Update download cache. Only files older than two days are counted, so nothing an app is using right now gets touched. Run it with no switches for a size report; add `-Clean` to delete, and it asks you to type YES first.

```powershell
# Preview: how much each location uses (deletes nothing)
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Clear-TempAndCache.ps1"

# Clean just your temp folder and browser caches
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Clear-TempAndCache.ps1" -Clean -Include UserTemp,Edge,Chrome

# As admin: clean everything, closing browsers first
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Clear-TempAndCache.ps1" -Clean -CloseBrowsers
```

| Switch | What it does |
|---|---|
| `-Clean` | Delete the files found (asks you to type YES first) |
| `-Force` | With `-Clean`, skip the YES prompt |
| `-Include <names>` | Only these locations: UserTemp, WindowsTemp, Edge, Chrome, Brave, Firefox, ThumbCache, CrashDumps, DeliveryOpt, WindowsUpdate |
| `-Exclude <names>` | Skip these locations |
| `-OlderThanDays <n>` | Only files older than this many days (default 2; 0 means anything not locked) |
| `-CloseBrowsers` | With `-Clean`, close open browsers so their caches can be cleared; otherwise open browsers are skipped |

Preview works without admin. Cleaning C:\Windows\Temp, Delivery Optimization and the Windows Update cache needs admin, and the Windows Update clean briefly stops and restarts the Windows Update and BITS services. Files in use are skipped. Deleted files don't go to the Recycle Bin, but everything here is a cache that Windows and your apps rebuild.

### Get-PowerReport.ps1

Shows how your PC is set up for power in one place: the active power plan and Windows 11 power mode, when the screen turns off and the PC sleeps or hibernates (plugged in and on battery), which sleep states it supports, Fast Startup, wake timers, which devices can wake it and what woke it last, and the CPU minimum and maximum. On a laptop it also shows battery charge, health (today's full capacity compared to when it was new) and charge cycles. It finishes with a short list of things worth changing, like a CPU capped below 100%, a laptop that never sleeps on battery, or a worn battery. It changes no settings.

```powershell
# Power plan, sleep settings, battery health and findings
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-PowerReport.ps1"

# Also save Windows' detailed battery report to the Desktop and open it
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-PowerReport.ps1" -BatteryReport -Open
```

| Switch | What it does |
|---|---|
| `-BatteryReport` | Also create Windows' detailed battery report (HTML, with capacity and usage history). Laptops only |
| `-OutputPath <folder>` | Where to save the battery report (default: your Desktop) |
| `-Open` | With `-BatteryReport`, open the report in your browser |

Works without admin. Run as administrator to also see which apps or drivers are keeping the PC awake right now. Desktops without a battery skip the battery checks.

### Get-ResourceHogs.ps1

Answers "why is my PC slow right now?" It watches every running app for about 30 seconds, then shows the top CPU users (averaged over the whole sample, not a single moment like Task Manager), the biggest memory users, and the apps reading and writing the most data. Processes with the same name are added together, so all your browser processes show as one row. It also shows overall CPU, memory, commit charge and disk activity, and ends with a short list of findings, like one app using most of the CPU, low free memory, or a disk that's constantly busy. It stops nothing and changes no settings.

```powershell
# Watch for 30 seconds and show the top 10 in each list
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-ResourceHogs.ps1"

# Show each process separately, with its process ID
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-ResourceHogs.ps1" -PerProcess

# Watch for a minute and save everything to a CSV on the Desktop
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-ResourceHogs.ps1" -Seconds 60 -CsvPath "$env:USERPROFILE\Desktop\hogs.csv"
```

| Switch | What it does |
|---|---|
| `-Seconds <n>` | How long to watch, 5 to 600 seconds (default 30) |
| `-Top <n>` | Rows in each list (default 10) |
| `-PerProcess` | Show each process separately instead of adding up processes with the same name |
| `-CsvPath <file>` | Export every app (or process) with CPU, memory and I/O to CSV |

Works without admin. Run as administrator to include a few protected system processes in the CPU list. Tip: start it, then do whatever feels slow so it shows up in the sample.

### Get-DiskHealth.ps1

A read-only answer to "is my disk dying or full?" It lists each physical disk (model, SSD/HDD, size, bus type, health and operational status — including Predictive Failure / Pred Fail when Windows reports them), every volume with size and free space, and flags drives that are low on space (default: 15% free or under 20 GB).

For each disk it also reports **age** and **updates**:
- **Age** prefers SMART-style `PowerOnHours` from `Get-StorageReliabilityCounter` (shown as days/years powered on). If those counters are missing, it falls back to when Windows first installed/saw the disk via PnP install date, and labels that source clearly (that is not power-on age).
- **Firmware** revision from `Get-PhysicalDisk` / `Get-Disk` / `Win32_DiskDrive`.
- **Firmware updated**: Windows almost never exposes a disk firmware flash date, so this is reported as n/a rather than guessed.
- **Storage driver** version and driver date from `Win32_PnPSignedDriver` matched to the disk's PnP id (this is the Windows driver package date, not a firmware flash).

When Windows exposes them, reliability counters show temperature (and max), wear percent, read/write errors including uncorrected counts, power-on hours and start/stop cycles. These are Windows' SMART-style counters, not a full vendor SMART dump — classic reallocated/pending sector attributes are only visible when the driver surfaces them through those error fields. With `-Path` it lists the largest top-level folders on that drive (a light check only — use Survey-Drive.ps1 for a deep survey). It ends with plain-English findings for Warning / Unhealthy / Failed / Predictive Failure disks, high wear, temperature, corrected and uncorrected I/O errors, and tight free space.

```powershell
# Quick health, age, firmware and free-space report
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-DiskHealth.ps1"

# Also list the biggest folders on C:\, and save everything to a CSV
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-DiskHealth.ps1" -Path C:\ -Top 15 -CsvPath "$env:USERPROFILE\Desktop\disk-health.csv"
```

| Switch | What it does |
|---|---|
| `-WarnPercent <n>` | Flag volumes at or below this free-space percent (default 15) |
| `-WarnGB <n>` | Also flag volumes with under this many GB free (default 20; 0 disables) |
| `-Path <drive or folder>` | Measure the largest top-level folders under this path |
| `-Top <n>` | How many folders to show with `-Path` (default 10) |
| `-CsvPath <file>` | Export disks, age/firmware, volumes and folders to CSV |

Works without admin; run as admin to unlock temperature, wear, error and power-on-hour counters on more disks. **Changes nothing.**

### Get-CrashHistory.ps1

Answers "why does my PC keep crashing or restarting?" It reads the System and Application event logs and puts every problem from the last 30 days in one place. Blue screens are listed with their stop code and a short meaning (for example `0x0000009F DRIVER_POWER_STATE_FAILURE`, a driver failing sleep or wake). Unexpected shutdowns are split into crashes and plain power losses, so you can tell a bad driver from a tripped breaker or a held power button. App crashes and hangs are grouped by app, with how often and when each last happened and which module crashed; when the same DLL crashes several different apps, it gets called out, because that usually points at a graphics driver, overlay or antivirus add-on. It also lists WHEA hardware errors (CPU, memory, PCIe) and disk errors like bad blocks or retried reads, shows the Reliability Monitor stability score, and ends with a numbered list of what to look at first.

```powershell
# Last 30 days: summary, each problem type and findings
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-CrashHistory.ps1"

# Look back 90 days and print every individual event
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-CrashHistory.ps1" -Days 90 -ShowEvents

# Save every event to a CSV on the Desktop
powershell -ExecutionPolicy Bypass -File ".\02_Performance\Get-CrashHistory.ps1" -CsvPath "$env:USERPROFILE\Desktop\crashes.csv"
```

| Switch | What it does |
|---|---|
| `-Days <n>` | How many days back to look, 1 to 365 (default 30) |
| `-Top <n>` | Rows in the app crash list (default 10) |
| `-ShowEvents` | Also print every event found, newest first |
| `-CsvPath <file>` | Export every event (time, type, source, app, details) to CSV |

Works without admin. Run as administrator to also list the minidump files in `C:\Windows\Minidump`, which a tool like WinDbg or BlueScreenView can open to name the driver behind a blue screen. **Changes nothing** and makes no network calls. For a timeline view of the same data, run `perfmon /rel` to open Reliability Monitor.

---

## 03_Utilities

### Block-Distractions.ps1

Blocks distracting and risky sites through the Windows hosts file. It works alongside PowerToys Hosts File Editor and only touches its own marked block, so reruns replace the block and `-Undo` removes it. Critical work domains (Microsoft, Google Workspace, GitHub, Apple, Dropbox, UniFi, Zoom and Slack) are protected and never blocked.

```powershell
# Preview (no changes)
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Block-Distractions.ps1" -Company

# Apply (run Terminal as administrator)
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Block-Distractions.ps1" -Company -Apply

# Remove the block
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Block-Distractions.ps1" -Undo -Apply
```

| Switch | What it blocks |
|---|---|
| `-Social` | Instagram, Facebook, TikTok, X, Snapchat, Reddit, Pinterest, Threads, Twitch, Kick, BeReal |
| `-Shopping` | Whatnot, Fanatics Live, TikTok Shop, Popshop, NTWRK, Temu, Shein |
| `-Adult` | ~330 major adult sites (`-AdultFromSource` adds ~77k more) |
| `-Security` | Known malware, phishing and scam sites (`-SecurityFromSource` adds ~74k more) |
| `-Proxies` | Free VPNs, web proxies and bandwidth-sharing "proxyware" |
| `-Piracy` | Torrent, crack and repack sites |
| `-Gambling` | Sportsbooks, DFS, online and sweepstakes casinos |
| `-Streaming` | Netflix, Hulu, Disney+, Max, Prime Video and more |
| `-Gaming` | Steam, Epic, Roblox, Battle.net, Discord and browser games |
| `-Crypto` | Exchanges, trading apps and meme-coin sites |
| `-YouTube` | All of YouTube (off by default; can't block only Shorts) |
| `-Company` | Workplace preset: everything above except YouTube |
| `-All` | Every category except YouTube |
| `-Custom 'a.com','b.net'` | Your own extra domains |

> **Heads up:** turn off "Secure DNS" (DNS-over-HTTPS) in Chrome, Edge, Brave and Firefox, or browsers will skip the hosts file. The huge `-FromSource` lists can slow down DNS on some PCs.

### Test-HomeNetwork.ps1

A read-only network health check for the "is it my PC, the Wi-Fi, the router or the internet?" question. It lists active adapters with link speed, IP, gateway and DNS servers, reads Wi-Fi signal, band and channel, and pings your gateway, Cloudflare and Google DNS (plus anything you add) for latency, jitter and packet loss. It also times DNS lookups against each server you use and flags unexpected proxy settings, which can be a sign of adware or proxyware, and a hosts file large enough to be a blocklist. It ends with a plain-English list of anything that looks wrong.

```powershell
# Quick check
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Test-HomeNetwork.ps1"

# Longer test, also ping a NAS and find the path MTU
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Test-HomeNetwork.ps1" -Count 50 -Targets '192.168.1.20' -CheckMtu
```

| Switch | What it does |
|---|---|
| `-Count <n>` | Pings sent to each target (default 20) |
| `-Targets 'a','b'` | Extra hosts or IPs to ping, like a NAS, AP or another PC |
| `-DnsName <name>` | Name to look up when timing DNS servers (default www.microsoft.com) |
| `-NoInternet` | Skip the public targets and test only your local network |
| `-CheckMtu` | Find the largest packet that gets through without fragmenting |
| `-HostsWarnThreshold <n>` | Warn when the hosts file has more active entries than this (default 50) |
| `-JsonPath <file>` | Save all results to a JSON file |

Only talks to your gateway, your DNS servers, 1.1.1.1, 8.8.8.8 and targets you name. Works without admin. **Changes nothing.**

---

### Get-ActiveConnections.ps1

A read-only answer to "what is this PC talking to?" It lists every established TCP connection and groups them by program: how many go to the internet, how many stay on your LAN, whether the file is signed and by whom, and the path. Destinations are grouped by remote address and port so a browser with many tabs does not flood the list. Loopback (this PC talking to itself) is hidden unless you pass `-All`. It ends with findings: unsigned programs or programs running from AppData, Temp or Downloads that reach the internet, names that sound like Windows components but are not signed by Microsoft, and programs with an unusually large number of internet connections. This is a snapshot of who is connected, not a bandwidth measurement — see `Get-ListeningPorts.ps1` for inbound listeners and `Test-HomeNetwork.ps1` for latency and Wi-Fi.

```powershell
# Quick snapshot
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Get-ActiveConnections.ps1"

# Show each process separately, look up remote hostnames, and save every connection to a CSV
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Get-ActiveConnections.ps1" -PerProcess -Resolve -CsvPath "$env:USERPROFILE\Desktop\connections.csv"
```

| Switch | What it does |
|---|---|
| `-All` | Also show loopback connections (this PC talking to itself) |
| `-IncludeOther` | Also include TCP states other than Established (for example SynSent or TimeWait). Listening sockets are left out |
| `-Resolve` | Look up a hostname for each remote address (queries your DNS servers; off by default) |
| `-PerProcess` | Show each process separately instead of adding up processes with the same name |
| `-Top <n>` | How many destination rows to show (default 40). The program list always includes every app |
| `-CsvPath <file>` | Export every connection to CSV |

Makes no network calls unless you pass `-Resolve`. Works without admin; run as admin for the paths and signatures of system processes. **Changes nothing.**

---

## 04_Security

### Find-SuspiciousStartup.ps1

A read-only security check, written after a real proxyware infection ("WindowsNetService"). It lists services, startup Run keys and non-Microsoft scheduled tasks. It then scores each one on a few red flags: it's unsigned, it runs from an odd location, it has a fake "Windows" or "Microsoft" name, it has no uninstall entry, or it runs through a script host like `node.exe` or `python`.

```powershell
powershell -ExecutionPolicy Bypass -File ".\04_Security\Find-SuspiciousStartup.ps1"
```

| Switch | What it does |
|---|---|
| `-All` | Show every item, not just flagged ones |
| `-ShowConnections` | Show live outbound connections of flagged running items |
| `-CsvPath <file>` | Export full results to CSV |

Works without admin; run as admin for full task and signature coverage. **Changes nothing.**

### Test-SecurityPosture.ps1

A quick, read-only security checkup. It reviews Microsoft Defender (real-time protection, signature age, tamper protection), every firewall profile, UAC, legacy SMBv1, Remote Desktop, the Guest account and local admins, recent Windows updates and pending reboots. Run it as admin to also check BitLocker, Secure Boot and the TPM. Each problem comes with a plain-English fix. Nothing is changed.

```powershell
# Quick check
powershell -ExecutionPolicy Bypass -File ".\04_Security\Test-SecurityPosture.ps1"

# Only show problems and save a CSV report
powershell -ExecutionPolicy Bypass -File ".\04_Security\Test-SecurityPosture.ps1" -IssuesOnly -ExportPath .\posture.csv
```

| Switch | What it does |
|---|---|
| `-IssuesOnly` | Shows only warnings and failures |
| `-ExportPath <file>` | Also saves all results to a CSV file |
| `-MaxSignatureAgeDays <n>` | Flags Defender signatures older than this (default 3) |
| `-MaxUpdateAgeDays <n>` | Flags the last installed update if older than this (default 45) |

### Get-ListeningPorts.ps1

A read-only answer to "what is this PC exposing to my network?" It lists every program listening on a TCP port (and UDP with `-IncludeUdp`), whether it's reachable from the network or only from this PC, the process and any Windows services behind it, whether the file is signed and by whom, and whether an enabled inbound firewall rule lets it in. It also shows each network connection's profile (Public, Private or Domain) and the folders you share. It ends with findings: risky ports like Telnet, FTP, SMB, RDP, VNC or WinRM open to the network, unsigned programs or programs running from AppData, Temp or Downloads that are listening, and shared folders while you're on a Public network.

```powershell
# Quick check
powershell -ExecutionPolicy Bypass -File ".\04_Security\Get-ListeningPorts.ps1"

# Everything, including loopback-only listeners and UDP, saved to a CSV
powershell -ExecutionPolicy Bypass -File ".\04_Security\Get-ListeningPorts.ps1" -All -IncludeUdp -CsvPath "$env:USERPROFILE\Desktop\ports.csv"
```

| Switch | What it does |
|---|---|
| `-All` | Also show listeners that only accept connections from this PC |
| `-IncludeUdp` | Also list UDP endpoints (longer and noisier; DNS, mDNS and SSDP are normal) |
| `-SkipFirewall` | Don't match listeners to firewall rules (faster on PCs with many rules) |
| `-CsvPath <file>` | Export the full listener list to CSV |

Makes no network calls; it only reads Windows' own connection, firewall and share tables. Works without admin; run as admin for the paths and signatures of system services. **Changes nothing.**

### Find-OutdatedApps.ps1

A read-only check of the software on this PC, because old apps are an easy way in. It reads every installed desktop app (all users and your account) and flags the ones that are past end of support, like Flash, Silverlight, Python 2 and old Python 3, old .NET runtimes, old Node.js, Office 2010 through 2019, Adobe Reader XI and Java 6/7. It also flags 7-Zip and WinRAR versions from before well-known exploited bugs were fixed, apps nobody has updated in years, and runtimes installed several times side by side. It checks whether your Windows 11 version and edition still get security updates too. With `-CheckUpdates` it asks winget which apps have newer versions. It ends with a numbered list of what to fix first. Support dates sit in tables at the top of the script so they're easy to check and update.

```powershell
# Quick check (no network calls)
powershell -ExecutionPolicy Bypass -File ".\04_Security\Find-OutdatedApps.ps1"

# Also ask winget for upgrades, show every app, and save the inventory to a CSV
powershell -ExecutionPolicy Bypass -File ".\04_Security\Find-OutdatedApps.ps1" -CheckUpdates -List -CsvPath "$env:USERPROFILE\Desktop\apps.csv"
```

| Switch | What it does |
|---|---|
| `-CheckUpdates` | Ask winget which apps have newer versions (contacts winget's sources; off by default) |
| `-StaleYears <n>` | Flag apps not installed or updated in this many years (default 3) |
| `-IncludeStore` | Also list Microsoft Store apps for your account (they update themselves, so they aren't flagged) |
| `-IncludeSystem` | Also list entries Windows hides as system components and updates |
| `-List` | Print the full inventory, not just flagged apps |
| `-CsvPath <file>` | Export the full inventory with flags to CSV |

Makes no network calls unless you pass `-CheckUpdates`. No admin needed; apps installed only for other user accounts aren't listed. **Changes nothing**: to update an app, use its own updater or `winget upgrade --id <Id>`.

---

## 05_Backup

### Backup-Folders.ps1

A simple, safe backup to another drive or a NAS share. It copies your Desktop, Documents, Pictures, Videos and Music (or folders you pick) into `<Destination>\<PC name>\`, and reruns copy only what's new or changed. By default it only previews: it shows how many files and how much data would be copied and whether it fits on the destination. `-Run` copies but never deletes anything in the backup. `-Mirror` makes the backup an exact match, deleting files you've removed, and asks you to type YES first. It refuses to back up into one of the folders it's backing up.

```powershell
# Preview (changes nothing)
powershell -ExecutionPolicy Bypass -File ".\05_Backup\Backup-Folders.ps1" -Destination E:\Backups

# Copy for real and keep a log
powershell -ExecutionPolicy Bypass -File ".\05_Backup\Backup-Folders.ps1" -Destination E:\Backups -Run -LogPath .\backup.log

# Back up your own folders to a NAS share
powershell -ExecutionPolicy Bypass -File ".\05_Backup\Backup-Folders.ps1" -Source "$env:USERPROFILE\Documents","D:\Projects" -Destination \\nas\backup -Run
```

| Switch | What it does |
|---|---|
| `-Destination <folder or share>` | Where the backup goes (required) |
| `-Source 'a','b'` | Folders to back up (default Desktop, Documents, Pictures, Videos, Music) |
| `-Run` | Actually copy; without it the script only previews |
| `-Mirror` | Make the backup match the source exactly, deleting extra files there (needs `-Run` and typed YES) |
| `-ExcludeDirs 'a','b'` | Folder names to skip (default `node_modules`, `.git` and system folders) |
| `-ExcludeFiles 'a','b'` | File patterns to skip (default `desktop.ini`, `Thumbs.db`, Office lock files, `*.tmp`) |
| `-Threads <n>` | Files copied in parallel (default 8) |
| `-LogPath <file>` | Append robocopy output to a log file |

Works without admin. Only writes to the destination you name, and only with `-Run`.

---

### Test-BackupHealth.ps1

Answers "if this drive died tonight, what would I lose?" It checks every common way a Windows 11 PC gets backed up: System Restore and the age of the newest restore point, File History and when it last finished, whether Desktop, Documents and Pictures are backed up to OneDrive (and whether OneDrive is running), system image backups on connected drives, whether the Windows Recovery Environment is enabled, and, if the system drive uses BitLocker, whether a recovery key exists. Point `-BackupPath` at your own backup drive or NAS share (it understands the `<Destination>\<PC name>` layout from `Backup-Folders.ps1`) to check it's reachable, has free space and was written recently. It finishes with how much of your personal folders has no backup at all, and a list of findings with fixes.

```powershell
# Quick check
powershell -ExecutionPolicy Bypass -File ".\05_Backup\Test-BackupHealth.ps1"

# Also check your USB backup, flag anything older than 3 days, and save a CSV
powershell -ExecutionPolicy Bypass -File ".\05_Backup\Test-BackupHealth.ps1" -BackupPath E:\Backups -MaxAgeDays 3 -CsvPath "$env:USERPROFILE\Desktop\backup-health.csv"
```

| Switch | What it does |
|---|---|
| `-BackupPath 'a','b'` | Backup folders or shares to check (reachable, free space, newest change) |
| `-MaxAgeDays <n>` | Flag backups older than this many days (default 7) |
| `-MaxScanFiles <n>` | Most files to look at per backup path when finding the newest (default 50000) |
| `-CsvPath <file>` | Save every check and finding to a CSV |

Read-only: it changes nothing and starts no backups. Works without admin; run as administrator to also count restore points and check the recovery environment and BitLocker.

---

## 🚀 How to run scripts

1. Download or clone the repo.
2. Open **Terminal** (right-click Start). Use **Terminal (Admin)** when a script needs it.
3. `cd` into the repo folder and run the command shown for that script.
4. If Windows says a file is blocked, run `Unblock-File .\path\to\script.ps1` first.

## ⚠️ Important

- Always read the header comments first. They list the safety level, any dry-run or WhatIf support, and undo steps.
- Create a System Restore Point before running anything from `02_Performance` or heavy tweaks.
- Some changes may be reset by Windows feature updates.
- Use responsibly. You break it, you keep both pieces 🪟💥

## 🤝 Contributing

Found a better way, or fixed something that broke in 24H2? PRs welcome. Good comments, parameters and switches, and undo steps are appreciated.

## 📜 License

MIT License: free to use, modify and share. No warranty; run at your own risk.
