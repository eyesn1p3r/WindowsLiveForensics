
# Windows Live Forensics Tool

[![GitHub stars](https://img.shields.io/github/stars/eyesn1p3r/WindowsLiveForensics?style=social)](https://github.com/eyesn1p3r/WindowsLiveForensics/stargazers)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)](https://learn.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/github/license/eyesn1p3r/WindowsLiveForensics)](https://github.com/eyesn1p3r/WindowsLiveForensics/blob/main/LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green)](https://github.com/eyesn1p3r/WindowsLiveForensics/releases)


**A fully native PowerShell script for live forensic data acquisition on Windows systems.** No external dependencies required.
Designed to support SOC analysts, incident responders, and forensic investigators during rapid triage and compromise assessments.

---

## Overview

This script collects critical forensic artifacts from a live Windows system, including:

- System information and user accounts
- Running processes and services
- Network configurations and active connections
- Windows Event Logs (System, Security, Application)
- Prefetch files and registry keys
- Temporary files, Recycle Bin, and recent documents
- Installed applications and browser history

All results are **archived in a `.zip` file** for easy analysis.

---

## How to Use

### Prerequisites

- **Windows 10/11 or Server 2016/2019/2022**
- **PowerShell 5.1+** (included by default)
- **Administrator rights** (required for full access)

---

### Step 1: Download the Script

```powershell
# Method 1: Clone the repository (requires Git)
git clone https://github.com/eyesn1p3r/WindowsLiveForensics.git

# Method 2: Direct download (no Git required)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/eyesn1p3r/WindowsLiveForensics/main/Scripts/WindowsLiveForensics.ps1" -OutFile "WindowsLiveForensics.ps1"
```

### Step 2: Run the Script

```powershell
# Allow script execution (run as Administrator)
Set-ExecutionPolicy Bypass -Scope Process -Force
.\WindowsLiveForensics.ps1
```

### Step 3: Analyze Results

A `.zip` archive is created in `C:\Temp\` (e.g., `LiveForensics_yyyyMMdd_HHmmss.zip`).  
Open `execution_logs.log` to check for errors.

---

## Output Structure

```
LiveForensics_YYYYMMDD_HHMMSS/
├── Applications/     # Installed applications and software inventory
├── Documents/        # Recent documents and downloads
├── Drivers/          # Driver information
├── Environment/      # Environment variables
├── Files/            # Suspicious files: executables, scripts
├── History/          # Browser & command-line history
├── Logs/             # Windows Event Logs (System, Security, Application)
├── Memory/           # Memory artifacts (pagefile, hiberfil, etc.)
├── Network/          # Active connections, adapters, and ARP cache
├── Prefetch/         # Prefetch files and analysis metadata
├── Processes/        # List of running processes and metadata
├── Registry/         # Extracted registry hives and key dumps
├── Services/         # Services and their startup info
├── System/           # Hostname, OS, time zone, uptime, etc.
├── Tasks/            # Scheduled tasks and AT jobs
├── Temp/             # Temporary files and recycle bin
├── Users/            # User profiles, accounts, SID info
└── execution_logs.log # Log of script activity and error trace
     
```

---

## Analyzing the Results

### 1. Filter Event Logs

```powershell
Import-Csv "C:\Temp\LiveForensics_*\Logs\security_events.csv" |
    Where-Object { $_.Id -eq 4624 } |
    Format-Table -AutoSize
```

### 2. Check Suspicious Processes

```powershell
Import-Csv "C:\Temp\LiveForensics_*\Processes\processes.csv" |
    Where-Object { $_.Path -like "*temp*" -or $_.Name -like "*powershell*" } |
    Sort-Object StartTime -Descending
```

### 3. Review Prefetch Files

```powershell
Get-ChildItem "C:\Temp\LiveForensics_*\Prefetch\Files\*.pf" |
    ForEach-Object { & "C:\Tools\PECmd.exe" -f $_.FullName }
```

### 4. Analyze Browser History

Use DB Browser for SQLite to open:

- Chrome/Edge: `History` file
- Firefox: `places.sqlite`

Sample query:

```sql
SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10;
```

---

## License

This project is licensed under the MIT License – see `LICENSE` for details.

---

## Support

For questions or issues, please open an issue on GitHub.

---

⭐ Star this repository if you find it useful!  
 Follow `@eyesn1p3r` for more security tools!
