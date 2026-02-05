#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot - File and Software Auditor
.DESCRIPTION
    Scans for unauthorized files (media, games) and software that should be removed.
    This is a companion script to the main automation tool.
    
    ⚠️ IMPORTANT: This script only REPORTS findings - it does NOT delete anything!
    You must manually review and delete files to avoid removing forensics evidence.
.NOTES
    Run as Administrator
    DOES NOT DELETE FILES - Only reports what it finds
#>

param(
    [switch]$ShowGUI = $true
)

$LogFile = "FileAudit-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

# Excluded paths - DO NOT scan these (CyberPatriot competition files, forensics)
$ExcludedPaths = @(
    "*CyberPatriot*",
    "*Forensics*",
    "*ForensicQuestion*",
    "*README*",
    "*CYBERPATRIOT*",
    "*Desktop\README*"
)

function Write-AuditLog {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    Write-Host $logMessage
}

function Find-MediaFiles {
    param([string]$SearchPath)
    
    Write-AuditLog "Searching for media files in $SearchPath..." "INFO"
    
    $mediaExtensions = @(
        "*.mp3", "*.mp4", "*.avi", "*.mkv", "*.mov", "*.wmv", "*.flv",
        "*.wav", "*.flac", "*.aac", "*.m4a", "*.wma",
        "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.tiff",
        "*.exe" # Games often have .exe
    )
    
    $results = @()
    foreach ($ext in $mediaExtensions) {
        try {
            $files = Get-ChildItem -Path $SearchPath -Filter $ext -Recurse -ErrorAction SilentlyContinue -File | 
                     Where-Object { 
                         $_.FullName -notlike "*Windows*" -and 
                         $_.FullName -notlike "*Program Files*" -and
                         $_.FullName -notlike "*AppData\Local\Microsoft*" -and
                         # IMPORTANT: Exclude CyberPatriot and Forensics files
                         $_.FullName -notlike "*CyberPatriot*" -and
                         $_.FullName -notlike "*Forensic*" -and
                         $_.FullName -notlike "*CYBERPATRIOT*" -and
                         # Exclude common forensics question files
                         $_.Name -notlike "README*" -and
                         $_.Name -notlike "*forensic*" -and
                         $_.Name -notlike "*answer*" -and
                         $_.Name -notlike "*question*"
                     }
            $results += $files
        } catch {
            # Ignore access denied errors
        }
    }
    
    return $results
}

function Find-UnauthorizedSoftware {
    Write-AuditLog "Scanning for unauthorized software..." "INFO"
    
    $unauthorizedPatterns = @(
        "*BitTorrent*", "*uTorrent*", "*Transmission*",
        "*Wireshark*", "*Nmap*",
        "*CCleaner*",
        "*Steam*", "*Epic Games*", "*Origin*",
        "*Skype*", "*Discord*", "*TeamSpeak*",
        "*VLC*" # Sometimes prohibited
    )
    
    $foundSoftware = @()
    
    # Check installed programs via registry
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($path in $registryPaths) {
        try {
            $programs = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                       Where-Object { $_.DisplayName } |
                       Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString
            
            foreach ($pattern in $unauthorizedPatterns) {
                $matches = $programs | Where-Object { $_.DisplayName -like $pattern }
                $foundSoftware += $matches
            }
        } catch {
            # Ignore errors
        }
    }
    
    # Also check via WMI (slower but more thorough)
    try {
        $wmiPrograms = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue
        foreach ($pattern in $unauthorizedPatterns) {
            $matches = $wmiPrograms | Where-Object { $_.Name -like $pattern }
            foreach ($match in $matches) {
                $foundSoftware += [PSCustomObject]@{
                    DisplayName = $match.Name
                    DisplayVersion = $match.Version
                    Publisher = $match.Vendor
                    UninstallString = $match.IdentifyingNumber
                }
            }
        }
    } catch {
        Write-AuditLog "WMI scan skipped (slower method)" "WARNING"
    }
    
    return $foundSoftware | Sort-Object -Property DisplayName -Unique
}

function Find-SuspiciousProcesses {
    Write-AuditLog "Checking for suspicious running processes..." "INFO"
    
    $suspiciousPatterns = @(
        "*torrent*", "*bittorrent*",
        "*wireshark*", "*nmap*",
        "*netcat*", "*nc.exe*",
        "*vnc*", "*teamviewer*"
    )
    
    $suspiciousProcesses = @()
    $allProcesses = Get-Process
    
    foreach ($pattern in $suspiciousPatterns) {
        $matches = $allProcesses | Where-Object { $_.ProcessName -like $pattern -or $_.Path -like $pattern }
        $suspiciousProcesses += $matches
    }
    
    return $suspiciousProcesses
}

function Find-StartupItems {
    Write-AuditLog "Checking startup items..." "INFO"
    
    $startupItems = @()
    
    # Check registry startup locations
    $startupPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($path in $startupPaths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($items) {
                $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                    $startupItems += [PSCustomObject]@{
                        Location = $path
                        Name = $_.Name
                        Command = $_.Value
                    }
                }
            }
        } catch {
            # Ignore errors
        }
    }
    
    # Check Startup folder
    $startupFolders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -File
            foreach ($file in $files) {
                $startupItems += [PSCustomObject]@{
                    Location = $folder
                    Name = $file.Name
                    Command = $file.FullName
                }
            }
        }
    }
    
    return $startupItems
}

# Main Execution
Write-AuditLog "========================================" "INFO"
Write-AuditLog "CyberPatriot File and Software Auditor" "INFO"
Write-AuditLog "========================================" "INFO"
Write-AuditLog "" "INFO"
Write-AuditLog "⚠️  IMPORTANT SAFETY NOTICE ⚠️" "WARNING"
Write-AuditLog "This script ONLY REPORTS findings - it does NOT delete anything!" "WARNING"
Write-AuditLog "Files related to CyberPatriot and Forensics questions are automatically excluded." "WARNING"
Write-AuditLog "ALWAYS manually review files before deleting to avoid removing forensics evidence!" "WARNING"
Write-AuditLog "" "INFO"

# Check paths to scan
$pathsToScan = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Music",
    "$env:USERPROFILE\Videos",
    "C:\Users\Public"
)

# Find unauthorized software
Write-AuditLog "" "INFO"
Write-AuditLog "=== UNAUTHORIZED SOFTWARE ===" "INFO"
$software = Find-UnauthorizedSoftware
if ($software -and $software.Count -gt 0) {
    Write-AuditLog "Found $($software.Count) potentially unauthorized programs:" "WARNING"
    foreach ($prog in $software) {
        Write-AuditLog "  - $($prog.DisplayName) ($($prog.DisplayVersion))" "WARNING"
        if ($prog.UninstallString) {
            Write-AuditLog "    Uninstall: $($prog.UninstallString)" "INFO"
        }
    }
} else {
    Write-AuditLog "No unauthorized software detected" "SUCCESS"
}

# Find media files
Write-AuditLog "" "INFO"
Write-AuditLog "=== MEDIA FILES ===" "INFO"
$allMediaFiles = @()
foreach ($path in $pathsToScan) {
    if (Test-Path $path) {
        $mediaFiles = Find-MediaFiles -SearchPath $path
        $allMediaFiles += $mediaFiles
    }
}

if ($allMediaFiles.Count -gt 0) {
    Write-AuditLog "Found $($allMediaFiles.Count) potential media files:" "WARNING"
    $grouped = $allMediaFiles | Group-Object Extension
    foreach ($group in $grouped) {
        Write-AuditLog "  $($group.Name): $($group.Count) files" "WARNING"
    }
    Write-AuditLog "" "INFO"
    Write-AuditLog "Detailed file list:" "INFO"
    foreach ($file in $allMediaFiles | Select-Object -First 50) {
        Write-AuditLog "  - $($file.FullName)" "WARNING"
    }
    if ($allMediaFiles.Count -gt 50) {
        Write-AuditLog "  ... and $($allMediaFiles.Count - 50) more files" "WARNING"
    }
} else {
    Write-AuditLog "No unauthorized media files found" "SUCCESS"
}

# Find suspicious processes
Write-AuditLog "" "INFO"
Write-AuditLog "=== SUSPICIOUS PROCESSES ===" "INFO"
$processes = Find-SuspiciousProcesses
if ($processes -and $processes.Count -gt 0) {
    Write-AuditLog "Found $($processes.Count) suspicious processes:" "WARNING"
    foreach ($proc in $processes) {
        Write-AuditLog "  - $($proc.ProcessName) (PID: $($proc.Id))" "WARNING"
        if ($proc.Path) {
            Write-AuditLog "    Path: $($proc.Path)" "INFO"
        }
    }
} else {
    Write-AuditLog "No suspicious processes detected" "SUCCESS"
}

# Find startup items
Write-AuditLog "" "INFO"
Write-AuditLog "=== STARTUP ITEMS ===" "INFO"
$startup = Find-StartupItems
if ($startup -and $startup.Count -gt 0) {
    Write-AuditLog "Found $($startup.Count) startup items:" "INFO"
    foreach ($item in $startup) {
        Write-AuditLog "  - $($item.Name)" "INFO"
        Write-AuditLog "    Location: $($item.Location)" "INFO"
        Write-AuditLog "    Command: $($item.Command)" "INFO"
    }
} else {
    Write-AuditLog "No startup items found" "INFO"
}

Write-AuditLog "" "INFO"
Write-AuditLog "========================================" "INFO"
Write-AuditLog "Audit complete! Review the log file:" "INFO"
Write-AuditLog "$LogFile" "INFO"
Write-AuditLog "========================================" "INFO"

# Open log file in notepad
if ($ShowGUI) {
    Start-Process notepad.exe -ArgumentList $LogFile
}

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
