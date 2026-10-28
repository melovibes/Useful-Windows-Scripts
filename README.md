# Useful Windows 11 Scripts 🛠️💻

A growing collection of practical, well-commented PowerShell and Python scripts that make life on Windows 11 easier, faster, safer or less annoying.

Made for power users, IT folks, small-business PCs and anyone who hates doing the same thing 50 times by hand.

## 📋 Script index

| Script | Category | What it does | Safety | Admin? |
|---|---|---|---|---|
| [Organize_Downloads.py](01_Organization/Organize_Downloads.py) | 01 Organization | Sorts your Downloads folder into subfolders by file type | Moves files | No |
| [Survey-Drive.ps1](01_Organization/Survey-Drive.ps1) | 01 Organization | Reports what's taking space on a messy drive: biggest folders and files, file types, age, old Windows installs and duplicates | Read-only | No |
| [Find-SuspiciousStartup.ps1](03_Utilities/Find-SuspiciousStartup.ps1) | 03 Utilities | Flags suspicious services, startup entries and scheduled tasks | Read-only | Optional |
| [Block-Distractions.ps1](03_Utilities/Block-Distractions.ps1) | 03 Utilities | Blocks distracting and risky sites via the hosts file | Dry run by default, with backup and undo | To apply |
| [Test-HomeNetwork.ps1](03_Utilities/Test-HomeNetwork.ps1) | 03 Utilities | Checks adapters, Wi-Fi signal, gateway and internet latency, packet loss, DNS speed and proxy settings, then lists problems in plain English | Read-only | No |

## 📂 Categories

- **01_Organization**: file and folder tidying, Explorer tweaks
- **02_Performance**: service optimizations, startup, gaming tweaks, telemetry *(coming soon)*
- **03_Utilities**: quick tools, security checks, cleanup, system shortcuts

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

## 03_Utilities

### Find-SuspiciousStartup.ps1

A read-only security check, written after a real proxyware infection ("WindowsNetService"). It lists services, startup Run keys and non-Microsoft scheduled tasks. It then scores each one on a few red flags: it's unsigned, it runs from an odd location, it has a fake "Windows" or "Microsoft" name, it has no uninstall entry, or it runs through a script host like `node.exe` or `python`.

```powershell
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Find-SuspiciousStartup.ps1"
```

| Switch | What it does |
|---|---|
| `-All` | Show every item, not just flagged ones |
| `-ShowConnections` | Show live outbound connections of flagged running items |
| `-CsvPath <file>` | Export full results to CSV |

Works without admin; run as admin for full task and signature coverage. **Changes nothing.**

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
