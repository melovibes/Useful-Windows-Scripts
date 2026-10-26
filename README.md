# Useful Windows 11 Scripts 🛠️💻

A growing collection of practical, well-commented PowerShell, batch, and occasionally VBS/Reg scripts that make life on Windows 11 easier, faster or less annoying.

Perfect for power users, IT enthusiasts, debloaters, customizers and people who hate doing the same thing 50 times manually.

## ✨ Categories

- **01_Organization** → Context menus, File Explorer tweaks, shell extensions, right-click goodies
- **02_Performance** → Service optimizations, visual effects, startup delay, gaming tweaks, telemetry reduction         #Coming Soon
- **03_Utilities** → Quick tools, cleanup scripts, window management, update control, system shortcuts
- **Legacy** → Old experiments, outdated methods, or "don't use unless you know exactly what you're doing" scripts      

## 📂 Folder Structure
Useful-Windows-11-Scripts/

├── 01-Organization/

└──   Organize_Downloads  

#This Python script organizes your Downloads folder by automatically sorting files into separate subfolders based on their file type/extension.

├── 03_Utilities/

└──   Find-SuspiciousStartup.ps1

#Read-only security check. Lists services, startup Run keys and non-Microsoft scheduled tasks, and flags ones that are unsigned, live outside Windows/Program Files, use a fake "Windows"/"Microsoft" name with a non-Microsoft signer, have no uninstall entry, or run through script hosts like node.exe or python. Inspired by a real proxyware infection ("WindowsNetService"). Changes nothing.

Usage:
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Find-SuspiciousStartup.ps1"
  -All               show every item, not just flagged ones
  -ShowConnections   show live outbound connections of flagged running items
  -CsvPath <file>    export full results to CSV
Works without admin; run as admin for full task and signature coverage.

└──   Block-Distractions.ps1

#Blocks distracting and risky sites through the Windows hosts file (social, live shopping, adult, malware/phishing, proxies/VPNs, piracy, gambling, streaming, gaming, crypto). Works alongside PowerToys Hosts File Editor: it only touches its own marked block, so reruns replace it and -Undo removes it. Dry run by default; -Apply writes (admin), saves a timestamped backup and flushes DNS. Critical domains (Microsoft, Google Workspace, GitHub, Apple, Dropbox, UniFi, Zoom, Slack) are protected and never blocked.

Usage (run as administrator to apply):
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Block-Distractions.ps1" -Company          # dry run
powershell -ExecutionPolicy Bypass -File ".\03_Utilities\Block-Distractions.ps1" -Company -Apply
  Categories: -Social -Shopping -Adult -Security -Proxies -Piracy -Gambling -Streaming -Gaming -Crypto
  -Company           workplace preset (all of the above; no YouTube, file sharing or webmail)
  -All               every category except YouTube
  -YouTube           block ALL of YouTube (off by default)
  -AdultFromSource / -SecurityFromSource   add StevenBlack's big lists (~75k each, can slow DNS)
  -Custom 'a.com','b.net'                  extra domains
  -Undo -Apply       remove the block
Note: turn off "Secure DNS" / DNS-over-HTTPS in your browser, or it will bypass the hosts file.

└── README.md

## 🚀 How to Use

Most scripts:

Powershell
Right-click → Run with PowerShell (recommended)

OR via terminal (admin recommended for most):
powershell -ExecutionPolicy Bypass -File ".\01_Organization\Some-Script.py"

## Always read the header comments — many scripts include:

Safety level (Safe / Medium / Aggressive)
Dry-run / WhatIf support
Undo instructions

## ⚠️ Important

Most scripts require Administrator rights
Create a System Restore Point before running anything from 02_Performance or heavy tweaks
Some changes may get reset by Windows Updates / Feature Updates
Use responsibly — you break it, you keep both pieces 🪟💥

## Contributing
Found a better way? Fixed something that broke in 24H2?
Feel free to open a PR!
Nice-to-have: good comments, parameters/switches, and undo steps.

## 📜 License
MIT License — free to use, modify, share. No warranty, run at your own risk.
