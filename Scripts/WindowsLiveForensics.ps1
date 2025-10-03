<#
.SYNOPSIS
    Windows Live Forensics Tool - Live forensic artifact collection for Windows systems.

.DESCRIPTION
    This PowerShell script is designed to collect critical forensic artifacts
    from a live Windows system. It is primarily used for:
    - Security incident response investigations.
    - Compliance audits.
    - Evidence collection for subsequent forensic analysis.

    Key Features:
    - 100% native PowerShell (no external dependencies required).
    - Comprehensive collection of logs, processes, users, network data, registry, etc.
    - Robust error handling and detailed logging.
    - Automatic archiving of results in a ZIP file.

    Limitations:
    - Requires administrator privileges to access all artifacts.
    - Some artifacts (e.g., memory files) can be very large (>1 GB).
    - In-depth analysis (e.g., browser databases) requires external tools.

.NOTES
    Author: Khalil Z.
    Version: 1.0.0
    Date: 10/2025
    License: MIT
    Requirements: Windows 10/11 or Server 2016+, PowerShell 5.1+, administrator rights.
    Recommended tools for analysis:
    - PECmd (for Prefetch file analysis)
    - DB Browser for SQLite (for browser history databases)

.EXAMPLE
    # Run the script
    .\WindowsLiveForensics.ps1
#>


# --- Color Configuration ---
$colorInfo = @{
    Title       = "$([char]0x1b)[36;1m"
    Success     = "$([char]0x1b)[32;1m"
    Warning     = "$([char]0x1b)[33;1m"
    Error       = "$([char]0x1b)[31;1m"
    Info        = "$([char]0x1b)[34;1m"
    Reset       = "$([char]0x1b)[0m"
    Highlight   = "$([char]0x1b)[35;1m"
}

# --- Logging Function ---
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [bool]$NoConsole = $false
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "$($colorInfo[$Level])[$timestamp]$($colorInfo['Reset']) [$Level] $Message"
    $cleanLogLine = $logLine -replace '\x1b\[[0-9;]*m', ''
    $cleanLogLine | Out-File -FilePath $script:errorLogPath -Append -Encoding UTF8
    if (-not $NoConsole) {
        Write-Host $logLine
    }
}

# --- Check Admin Rights ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log -Message "This script must be run as Administrator." -Level "Error"
    Write-Host "$($colorInfo['Warning'])[!] Press any key to exit...$($colorInfo['Reset'])"
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# --- Output Directory ---
$outputDir = "C:\Temp\LiveForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$subDirs = @("System", "Users", "Processes", "Network", "Tasks", "Logs", "Files", "Registry", "Services", "Environment", "Temp", "History", "Drivers", "Documents", "Applications", "Prefetch", "Memory")

# --- Create Directories ---
try {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    foreach ($dir in $subDirs) {
        New-Item -ItemType Directory -Path "$outputDir\$dir" -Force | Out-Null
    }
    $errorLogPath = "$outputDir\execution_logs.log"
    New-Item -ItemType File -Path $errorLogPath -Force | Out-Null
    Write-Log -Message "Output directory created: $($colorInfo['Highlight'])$outputDir$($colorInfo['Reset'])" -Level "Success"
}
catch {
    Write-Log -Message "Failed to create directory: $_" -Level "Error"
    exit 1
}

# --- Safe Command Execution Function ---
function Invoke-SafeCommand {
    param (
        [string]$Command,
        [string]$OutputFile,
        [string]$SubDir = "",
        [int]$MaxLines = 1000
    )
    $fullPath = if ($SubDir) { "$outputDir\$SubDir\$OutputFile" } else { "$outputDir\$OutputFile" }
    Write-Log -Message "Executing: $($colorInfo['Info'])$Command$($colorInfo['Reset'])"
    try {
        if ($Command -match "Get-ChildItem.*-Recurse") {
            $Command = $Command -replace "-Recurse", "-Depth 5 -ErrorAction SilentlyContinue"
        }
        elseif ($Command -match "Get-Process|Get-Service|Get-WinEvent") {
            $Command = "$Command | Select-Object -First $MaxLines"
        }
        $result = Invoke-Expression $Command -ErrorAction Stop
        if ($OutputFile -ne "dummy.txt") {
            if ($OutputFile -match "\.csv$") {
                $result | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8 -Force
            }
            else {
                $result | Out-File -FilePath $fullPath -Encoding UTF8 -Force
            }
        }
        $logMessage = "Saved: $($colorInfo['Success'])$fullPath$($colorInfo['Reset'])"
        Write-Log -Message $logMessage -Level "Success"
        return $true
    }
    catch {
        Write-Log -Message "Error: $Command - $_" -Level "Error"
        return $false
    }
}

# --- 1. System Information ---
Write-Log -Message "Collecting system information..." -Level "Title"
Invoke-SafeCommand -Command "systeminfo" -OutputFile "systeminfo.txt" -SubDir "System"
Invoke-SafeCommand -Command "wmic os get /format:list" -OutputFile "os_info.txt" -SubDir "System"
Invoke-SafeCommand -Command "driverquery /v" -OutputFile "drivers.txt" -SubDir "Drivers"

# --- 2. Users ---
Write-Log -Message "Collecting user information..." -Level "Title"
Invoke-SafeCommand -Command "whoami /all" -OutputFile "whoami.txt" -SubDir "Users"
Invoke-SafeCommand -Command "net user" -OutputFile "net_user.txt" -SubDir "Users"
Invoke-SafeCommand -Command "net localgroup administrators" -OutputFile "admins.txt" -SubDir "Users"

# --- 3. Processes ---
Write-Log -Message "Collecting processes..." -Level "Title"
Invoke-SafeCommand -Command "Get-Process | Select-Object Id,Name,Path,CPU,StartTime | Export-Csv -Path `"$outputDir\Processes\processes.csv`"" -OutputFile "dummy.txt" -SubDir "Processes"

# --- 4. Network ---
Write-Log -Message "Collecting network information..." -Level "Title"
Invoke-SafeCommand -Command "ipconfig /all" -OutputFile "ipconfig.txt" -SubDir "Network"
Invoke-SafeCommand -Command "netstat -ano" -OutputFile "netstat.txt" -SubDir "Network"
Invoke-SafeCommand -Command "arp -a" -OutputFile "arp.txt" -SubDir "Network"
Invoke-SafeCommand -Command "netsh advfirewall show allprofiles" -OutputFile "firewall.txt" -SubDir "Network"

# --- 5. DNS Cache ---
Write-Log -Message "Collecting DNS cache..." -Level "Title"
try {
    $dnsOutput = "$outputDir\Network\dns_cache.txt"
    Get-DnsClientCache | Out-File -FilePath $dnsOutput -Encoding UTF8 -Force
    $logMessage = "DNS cache exported: $($colorInfo['Success'])$dnsOutput$($colorInfo['Reset'])"
    Write-Log -Message $logMessage -Level "Success"
}
catch {
    Write-Log -Message "DNS cache error: $_" -Level "Error"
}

# --- 6. Scheduled Tasks ---
Write-Log -Message "Collecting scheduled tasks..." -Level "Title"
try {
    $tasks = Get-ScheduledTask | ForEach-Object {
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -ErrorAction Stop
            [PSCustomObject]@{
                Name          = $_.TaskName
                LastRunTime   = $taskInfo.LastRunTime
                State         = $_.State
                Author        = $_.Author
                TaskPath      = $_.TaskPath
            }
        }
        catch {
            Write-Log -Message ("Task not found (ignored): ${_}.TaskName") -Level "Warning"
            $null
        }
    } | Where-Object { $_ -ne $null }
    if ($tasks.Count -gt 0) {
        $tasks | Export-Csv -Path "$outputDir\Tasks\scheduled_tasks.csv" -NoTypeInformation -Encoding UTF8 -Force
        $logMessage = "${tasks.Count} tasks exported."
        Write-Log -Message $logMessage -Level "Success"
    }
}
catch {
    Write-Log -Message "Scheduled tasks error: $_" -Level "Error"
}

# --- 7. Windows Event Logs ---
Write-Log -Message "Collecting Windows Event Logs..." -Level "Title"
$eventLogs = @(
    @{ Name = "System";   MaxEvents = 500; OutputFile = "system_events.csv" },
    @{ Name = "Security"; MaxEvents = 500; OutputFile = "security_events.csv" },
    @{ Name = "Application"; MaxEvents = 300; OutputFile = "application_events.csv" },
    @{ Name = "Setup";     MaxEvents = 200; OutputFile = "setup_events.csv" }
)

foreach ($log in $eventLogs) {
    $outputFile = "$outputDir\Logs\$($log.OutputFile)"
    try {
        $events = Get-WinEvent -LogName $log.Name -MaxEvents $log.MaxEvents -ErrorAction Stop
        if ($events) {
            $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
                Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8 -Force
            $logMessage = "${events.Count} ${log.Name} events exported: $($colorInfo['Success'])$outputFile$($colorInfo['Reset'])"
            Write-Log -Message $logMessage -Level "Success"
        } else {
            Write-Log -Message ("No events found for ${log.Name}.") -Level "Warning"
        }
    }
    catch {
        Write-Log -Message ("Error for ${log.Name} log: $_") -Level "Error"
    }
}

# --- 8. Sysmon Logs ---
try {
    $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if ($sysmonLog) {
        Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 500 -ErrorAction Stop |
            Export-Csv -Path "$outputDir\Logs\sysmon_events.csv" -NoTypeInformation -Encoding UTF8 -Force
        Write-Log -Message "500 Sysmon events exported." -Level "Success"
    } else {
        Write-Log -Message "Sysmon not enabled." -Level "Warning"
    }
}
catch {
    Write-Log -Message "Sysmon error: $_" -Level "Error"
}

# --- 9. PowerShell Logs ---
try {
    $psLogs = Get-WinEvent -ListLog "Windows PowerShell" -ErrorAction SilentlyContinue
    if ($psLogs) {
        Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 200 -ErrorAction Stop |
            Export-Csv -Path "$outputDir\Logs\powershell_events.csv" -NoTypeInformation -Encoding UTF8 -Force
        Write-Log -Message "200 PowerShell events exported." -Level "Success"
    } else {
        Write-Log -Message "PowerShell logging not enabled." -Level "Warning"
    }
}
catch {
    Write-Log -Message "PowerShell log error: $_" -Level "Error"
}

# --- 10. Suspicious Files ---
Write-Log -Message "Searching for suspicious files..." -Level "Title"
Invoke-SafeCommand -Command "Get-ChildItem -Path C:\Users\ -Depth 3 -Filter *.exe -ErrorAction SilentlyContinue | Select-Object -First 1000 -Property FullName,LastWriteTime,Length | Export-Csv -Path `"$outputDir\Files\suspicious_executables.csv`"" -OutputFile "dummy.txt" -SubDir "Files"
Invoke-SafeCommand -Command "Get-ChildItem -Path C:\Users\ -Depth 3 -Filter *.ps1 -ErrorAction SilentlyContinue | Select-Object -First 1000 -Property FullName,LastWriteTime,Length | Export-Csv -Path `"$outputDir\Files\suspicious_scripts.csv`"" -OutputFile "dummy.txt" -SubDir "Files"

# --- 11. Registry Keys ---
Write-Log -Message "Collecting critical registry keys..." -Level "Title"
$persistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

foreach ($key in $persistenceKeys) {
    $keyName = $key.Split('\')[-1]
    $outputFile = "$outputDir\Registry\$keyName.txt"
    try {
        $properties = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($properties) {
            $properties | Format-List | Out-File -FilePath $outputFile -Encoding UTF8 -Force
            $logMessage = "Registry key ${key} exported: $($colorInfo['Success'])$outputFile$($colorInfo['Reset'])"
            Write-Log -Message $logMessage -Level "Success"
        }
    }
    catch {
        Write-Log -Message ("Error for registry key ${key}: $_") -Level "Error"
    }
}

# --- 12. Services ---
Write-Log -Message "Collecting services..." -Level "Title"
Invoke-SafeCommand -Command "Get-Service | Select-Object -First 1000 -Property Name,DisplayName,Status,StartType | Export-Csv -Path `"$outputDir\Services\services.csv`"" -OutputFile "dummy.txt" -SubDir "Services"

# --- 13. Environment Variables ---
Write-Log -Message "Collecting environment variables..." -Level "Title"
Invoke-SafeCommand -Command "Get-ChildItem Env:" -OutputFile "env_vars.txt" -SubDir "Environment"

# --- 14. History (PowerShell, CMD, Browsers) ---
Write-Log -Message "Collecting user history..." -Level "Title"
# a. PowerShell History
try {
    Get-History | Export-Csv -Path "$outputDir\History\ps_history.csv" -NoTypeInformation -Encoding UTF8 -Force
    Write-Log -Message "PowerShell history exported." -Level "Success"
}
catch {
    Write-Log -Message "PowerShell history error: $_" -Level "Error"
}
# b. CMD History
try {
    doskey /history > "$outputDir\History\cmd_history.txt"
    Write-Log -Message "CMD history exported." -Level "Success"
}
catch {
    Write-Log -Message "CMD history error: $_" -Level "Error"
}
# c. Browser History
$browserDBs = @(
    @{ Name = "Chrome"; HistoryPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"; OutputDir = "$outputDir\History\Chrome" },
    @{ Name = "Edge"; HistoryPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"; OutputDir = "$outputDir\History\Edge" },
    @{ Name = "Firefox"; HistoryPath = (Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Filter "*.default-release" | Select-Object -First 1 -ExpandProperty FullName) + "\places.sqlite"; OutputDir = "$outputDir\History\Firefox" }
)
foreach ($browser in $browserDBs) {
    try {
        New-Item -ItemType Directory -Path $browser.OutputDir -Force | Out-Null
        if (Test-Path $browser.HistoryPath) {
            Copy-Item -Path $browser.HistoryPath -Destination "$($browser.OutputDir)\History.db" -Force -ErrorAction SilentlyContinue
            $logMessage = "${browser.Name} history database copied for later analysis."
            Write-Log -Message $logMessage -Level "Success"
        } else {
            Write-Log -Message ("${browser.Name} history not found: $($browser.HistoryPath)") -Level "Warning"
        }
    }
    catch {
        Write-Log -Message ("${browser.Name} error: $_") -Level "Error"
    }
}

# --- 15. Recent Documents ---
Write-Log -Message "Collecting recent documents..." -Level "Title"
# a. UserAssist
try {
    $userAssistKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
    $userAssistOutput = "$outputDir\Documents\userassist.txt"
    Get-ItemProperty -Path $userAssistKey -ErrorAction SilentlyContinue |
        Select-Object -Property @{Name="Name";Expression={$_.PSChildName}} |
        Out-File -FilePath $userAssistOutput -Encoding UTF8 -Force
    $logMessage = "UserAssist data exported: $($colorInfo['Success'])$userAssistOutput$($colorInfo['Reset'])"
    Write-Log -Message $logMessage -Level "Success"
}
catch {
    Write-Log -Message "UserAssist error: $_" -Level "Error"
}
# b. Recent Folder
try {
    $recentFolder = [Environment]::GetFolderPath("Recent")
    $recentOutput = "$outputDir\Documents\recent_files.csv"
    if (Test-Path $recentFolder) {
        Get-ChildItem -Path $recentFolder -ErrorAction SilentlyContinue |
            Select-Object FullName, LastWriteTime, Length |
            Export-Csv -Path $recentOutput -NoTypeInformation -Encoding UTF8 -Force
        $logMessage = "Recent files exported: $($colorInfo['Success'])$recentOutput$($colorInfo['Reset'])"
        Write-Log -Message $logMessage -Level "Success"
    }
}
catch {
    Write-Log -Message "Recent folder error: $_" -Level "Error"
}
# c. Downloads
try {
    $downloadsFolder = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
    $downloadsOutput = "$outputDir\Documents\downloads.csv"
    if (Test-Path $downloadsFolder) {
        Get-ChildItem -Path $downloadsFolder -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 100 FullName, LastWriteTime, Length |
            Export-Csv -Path $downloadsOutput -NoTypeInformation -Encoding UTF8 -Force
        $logMessage = "Downloads exported: $($colorInfo['Success'])$downloadsOutput$($colorInfo['Reset'])"
        Write-Log -Message $logMessage -Level "Success"
    }
}
catch {
    Write-Log -Message "Downloads error: $_" -Level "Error"
}

# --- 16. Installed Applications ---
Write-Log -Message "Collecting installed applications..." -Level "Title"
# a. Registry
try {
    $registryOutput = "$outputDir\Applications\installed_software_registry.csv"
    $uninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $installedApps = foreach ($key in $uninstallKeys) {
        Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -ne $null } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    }
    $installedApps | Export-Csv -Path $registryOutput -NoTypeInformation -Encoding UTF8 -Force
    $logMessage = "Installed applications (Registry) exported: $($colorInfo['Success'])$registryOutput$($colorInfo['Reset'])"
    Write-Log -Message $logMessage -Level "Success"
}
catch {
    Write-Log -Message "Registry error: $_" -Level "Error"
}
# b. Microsoft Store
try {
    $storeOutput = "$outputDir\Applications\installed_store_apps.csv"
    Get-AppxPackage |
        Select-Object Name, Version, InstallLocation, PackageFamilyName |
        Export-Csv -Path $storeOutput -NoTypeInformation -Encoding UTF8 -Force
    $logMessage = "Microsoft Store apps exported: $($colorInfo['Success'])$storeOutput$($colorInfo['Reset'])"
    Write-Log -Message $logMessage -Level "Success"
}
catch {
    Write-Log -Message "Store apps error: $_" -Level "Error"
}
# c. Chocolatey
try {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $chocoOutput = "$outputDir\Applications\installed_chocolatey_packages.csv"
        choco list --local-only --limit-output |
            Select-Object -Skip 1 |
            ConvertFrom-Csv -Delimiter '|' -Header "Package", "Version" |
            Export-Csv -Path $chocoOutput -NoTypeInformation -Encoding UTF8 -Force
        $logMessage = "Chocolatey packages exported: $($colorInfo['Success'])$chocoOutput$($colorInfo['Reset'])"
        Write-Log -Message $logMessage -Level "Success"
    }
}
catch {
    Write-Log -Message "Chocolatey error: $_" -Level "Error"
}

# --- 17. Prefetch Files ---
Write-Log -Message "Collecting Prefetch files..." -Level "Title"
try {
    $prefetchDir = "$env:SystemRoot\Prefetch"
    $prefetchOutput = "$outputDir\Prefetch\prefetch_files.csv"
    $prefetchCopyDir = "$outputDir\Prefetch\Files"
    New-Item -ItemType Directory -Path "$outputDir\Prefetch" -Force | Out-Null
    New-Item -ItemType Directory -Path $prefetchCopyDir -Force | Out-Null
    if (Test-Path $prefetchDir) {
        Get-ChildItem -Path $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue |
            Select-Object Name, CreationTime, LastWriteTime, Length |
            Export-Csv -Path $prefetchOutput -NoTypeInformation -Encoding UTF8 -Force
        Copy-Item -Path "$prefetchDir\*.pf" -Destination $prefetchCopyDir -Force -ErrorAction SilentlyContinue
        $logMessage = "Prefetch files exported: $($colorInfo['Success'])$prefetchOutput$($colorInfo['Reset'])"
        Write-Log -Message $logMessage -Level "Success"
        $logMessage = "Prefetch files copied for later analysis: $($colorInfo['Success'])$prefetchCopyDir$($colorInfo['Reset'])"
        Write-Log -Message $logMessage -Level "Success"
    } else {
        Write-Log -Message "Prefetch directory not found: $prefetchDir" -Level "Warning"
    }
}
catch {
    Write-Log -Message "Prefetch error: $_" -Level "Error"
}

# --- 18. Temp Files and Recycle Bin ---
Write-Log -Message "Collecting temp files and Recycle Bin..." -Level "Title"
$tempDirs = @(
    $env:TEMP,
    "$env:SystemRoot\Temp",
    "$env:USERPROFILE\AppData\Local\Temp"
)
foreach ($tempDir in $tempDirs) {
    try {
        if (Test-Path $tempDir) {
            $tempOutput = "$outputDir\Temp\$(Split-Path $tempDir -Leaf)_files.csv"
            Get-ChildItem -Path $tempDir -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 500 FullName, LastWriteTime, Length |
                Export-Csv -Path $tempOutput -NoTypeInformation -Encoding UTF8 -Force
            $logMessage = "Temp files exported from ${tempDir}: $($colorInfo['Success'])$tempOutput$($colorInfo['Reset'])"
            Write-Log -Message $logMessage -Level "Success"
        }
    }
    catch {
        Write-Log -Message ("Temp files error in ${tempDir}: $_") -Level "Error"
    }
}
# b. Recycle Bin
try {
    $recycleBinDir = "$env:USERPROFILE\$Recycle.Bin"
    $recycleOutput = "$outputDir\Temp\recycle_bin.csv"
    if (Test-Path $recycleBinDir) {
        Get-ChildItem -Path "$recycleBinDir\*" -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object FullName, LastWriteTime, Length |
            Export-Csv -Path $recycleOutput -NoTypeInformation -Encoding UTF8 -Force
        $logMessage = "Recycle Bin files exported: $($colorInfo['Success'])$recycleOutput$($colorInfo['Reset'])"
        Write-Log -Message $logMessage -Level "Success"
    }
}
catch {
    Write-Log -Message "Recycle Bin error: $_" -Level "Error"
}

# --- 19. Memory Files ---
Write-Log -Message "Checking memory files..." -Level "Title"
try {
    $memoryFiles = @(
        @{ Name = "pagefile.sys"; Path = "$env:SystemRoot\pagefile.sys" },
        @{ Name = "hiberfil.sys"; Path = "$env:SystemRoot\hiberfil.sys" }
    )
    $memoryDir = "$outputDir\Memory"
    New-Item -ItemType Directory -Path $memoryDir -Force | Out-Null
    foreach ($file in $memoryFiles) {
        if (Test-Path $file.Path) {
            $fileInfo = Get-Item $file.Path
            $sizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
            Write-Log -Message ("{0} found ({1} MB)." -f $file.Name, $sizeMB) -Level "Info"
            if ($fileInfo.Length -lt 1GB) {
                Copy-Item -Path $file.Path -Destination "$memoryDir\$($file.Name)" -Force -ErrorAction SilentlyContinue
                $logMessage = "{0} copied: $($colorInfo['Success'])$memoryDir\$($file.Name)$($colorInfo['Reset'])" -f $file.Name
                Write-Log -Message $logMessage -Level "Success"
            } else {
                $sizeGB = [math]::Round($fileInfo.Length / 1GB, 2)
                Write-Log -Message ("{0} too large ({1} GB), skipped." -f $file.Name, $sizeGB) -Level "Warning"
            }
        } else {
            Write-Log -Message ("{0} not found: {1}" -f $file.Name, $file.Path) -Level "Warning"
        }
    }
}
catch {
    Write-Log -Message "Memory files error: $_" -Level "Error"
}

# --- 20. Archive Results ---
Write-Log -Message "Archiving results..." -Level "Title"
try {
    $zipPath = "$outputDir.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$outputDir\*" -DestinationPath $zipPath -Force
    $logMessage = "Archive created: $($colorInfo['Highlight'])$zipPath$($colorInfo['Reset'])"
    Write-Log -Message $logMessage -Level "Success"
}
catch {
    Write-Log -Message "Archive error: $_" -Level "Error"
}

# --- End ---
Write-Log -Message "Analysis complete. Results in $($colorInfo['Highlight'])$zipPath$($colorInfo['Reset'])" -Level "Success"
Write-Host "$($colorInfo['Warning'])[!] Press any key to exit...$($colorInfo['Reset'])"
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
