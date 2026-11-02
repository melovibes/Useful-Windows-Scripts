# Useful Windows 11 Scripts 🛠️💻

A growing collection of practical, well-commented PowerShell and Python scripts that make life on Windows 11 easier, faster, safer or less annoying.

Made for power users, IT folks, small-business PCs and anyone who hates doing the same thing 50 times by hand.

## 📋 Script index

| Script | Category | What it does | Safety | Admin? |
|---|---|---|---|---|
| [Organize_Downloads.py](01_Organization/Organize_Downloads.py) | 01 Organization | Sorts your Downloads folder into subfolders by file type | Moves files | No |
| [Survey-Drive.ps1](01_Organization/Survey-Drive.ps1) | 01 Organization | Reports what's taking space on a messy drive: biggest folders and files, file types, age, old Windows installs and duplicates | Read-only | No |
| [Get-StartupImpact.ps1](02_Performance/Get-StartupImpact.ps1) | 02 Performance | Lists startup apps, logon tasks and auto-start services with their CPU and disk impact, plus boot times and what Windows says slowed boot | Read-only | Optional |
| [Clear-TempAndCache.ps1](02_Performance/Clear-TempAndCache.ps1) | 02 Performance | Measures temp folders, browser caches, crash dumps and the Windows Update cache, and clears them only with `-Clean` | Preview by default; deletes with -Clean after typing YES | Optional (needed for system caches) |
| [Get-PowerReport.ps1](02_Performance/Get-PowerReport.ps1) | 02 Performance | Shows your power plan and mode, screen and sleep timeouts, wake settings, CPU limits and battery health, then lists anything wasting power or slowing the PC | Read-only | Optional |
| [Block-Distractions.ps1](03_Utilities/Block-Distractions.ps1) | 03 Utilities | Blocks distracting and risky sites via the hosts file | Dry run by default, with backup and undo | To apply |
| [Test-HomeNetwork.ps1](03_Utilities/Test-HomeNetwork.ps1) | 03 Utilities | Checks adapters, Wi-Fi signal, gateway and internet latency, packet loss, DNS speed and proxy settings, then lists problems in plain English | Read-only | No |
| [Find-SuspiciousStartup.ps1](04_Security/Find-SuspiciousStartup.ps1) | 04 Security | Flags suspicious services, startup entries and scheduled tasks | Read-only | Optional |
| [Test-SecurityPosture.ps1](04_Security/Test-SecurityPosture.ps1) | 04 Security | Checks Defender, firewall, BitLocker, UAC, Secure Boot, TPM, SMBv1, RDP, updates and local accounts, then lists problems with fixes | Read-only | Optional |
| [Backup-Folders.ps1](05_Backup/Backup-Folders.ps1) | 05 Backup | Backs up Desktop, Documents, Pictures and other folders to a USB drive or NAS with robocopy, copying only new and changed files | Preview by default; never deletes unless `-Mirror` and you type YES | No |

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
