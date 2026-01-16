# Useful Windows 11 Scripts 🛠️💻

A growing collection of practical, well-commented PowerShell, batch, and occasionally VBS/Reg scripts that make life on Windows 11 easier, faster or less annoying.

Perfect for power users, IT enthusiasts, debloaters, customizers and people who hate doing the same thing 50 times manually.

## ✨ Categories

- **01_Organization** → Context menus, File Explorer tweaks, shell extensions, right-click goodies
- **02_Performance** → Service optimizations, visual effects, startup delay, gaming tweaks, telemetry reduction         #Coming Soon
- **03_Utilities** → Quick tools, cleanup scripts, window management, update control, system shortcuts                  #Coming Soon
- **Legacy** → Old experiments, outdated methods, or "don't use unless you know exactly what you're doing" scripts      

## 📂 Folder Structure (recommended)
Useful-Windows-11-Scripts/

├── 01-Organization/

└──   Organize_Downloads  #This Python script organizes your Downloads folder by automatically sorting files into separate subfolders based on their file type/extension.

├── 02-Performance/

├── 03-Utilities/

├── _Legacy/              # old/bad experiments - don't use in production

├── docs/                 # extra guides, before/after screenshots

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
