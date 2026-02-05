#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Automated CyberPatriot Security Hardening Script
.DESCRIPTION
    This script automates common CyberPatriot security hardening tasks based on the checklist.
    It provides a GUI interface for selecting which tasks to perform.
.NOTES
    MUST BE RUN AS ADMINISTRATOR
    
    ⚠️ IMPORTANT SAFETY NOTES:
    - This script does NOT change the current user's password
    - This script does NOT delete files (only configures security settings)
    - This script does NOT interfere with CyberPatriot competition files
    - Always read the competition README before running any automation!
#>

# Add Windows Forms assembly for GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create log file
$LogFile = "CyberPatriot-AutoLog-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    Write-Host $logMessage
}

function Show-Notification {
    param([string]$Title, [string]$Message, [string]$Icon = "Information")
    [System.Windows.Forms.MessageBox]::Show($Message, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::$Icon)
}

# Security Hardening Functions

function Enable-Firewall {
    Write-Log "Enabling Windows Firewall..."
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Log "Firewall enabled successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to enable firewall: $_" "ERROR"
        return $false
    }
}

function Disable-GuestAccount {
    Write-Log "Disabling Guest account..."
    try {
        Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        net user guest /active:no 2>&1 | Out-Null
        Write-Log "Guest account disabled successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to disable guest account: $_" "ERROR"
        return $false
    }
}

function Disable-AdminAccount {
    Write-Log "Disabling built-in Administrator account..."
    try {
        # Don't disable the current user
        $currentUser = $env:USERNAME
        if ($currentUser -ne "Administrator") {
            Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
            net user administrator /active:no 2>&1 | Out-Null
            Write-Log "Administrator account disabled successfully" "SUCCESS"
            return $true
        } else {
            Write-Log "Skipping - Currently logged in as Administrator" "WARNING"
            return $true
        }
    } catch {
        Write-Log "Failed to disable admin account: $_" "ERROR"
        return $false
    }
}

function Set-PasswordPolicies {
    Write-Log "Configuring password policies..."
    try {
        # Using secedit to configure password policies
        $secpol = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 10
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0
LockoutBadCount = 10
LockoutDuration = 30
ResetLockoutCount = 30
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        $secpol | Out-File "$env:TEMP\secpol.cfg" -Encoding Unicode
        secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
        Remove-Item "$env:TEMP\secpol.cfg" -Force
        Write-Log "Password policies configured successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to configure password policies: $_" "ERROR"
        return $false
    }
}

function Disable-InsecureServices {
    param(
        [array]$RequiredServices = @()
    )
    
    Write-Log "Disabling insecure services..."
    
    if ($RequiredServices.Count -gt 0) {
        Write-Log "Using required services list from README ($($RequiredServices.Count) items)" "INFO"
    }
    
    $servicesToDisable = @(
        "RemoteRegistry",
        "RemoteAccess",
        "SSDPSRV",          # SSDP Discovery
        "upnphost",         # UPnP Device Host
        "W3SVC",            # WWW Publishing Service
        "SMTPSVC",          # SMTP
        "ftpsvc",           # FTP
        "TermService",      # Remote Desktop
        "SessionEnv",       # Remote Desktop Configuration
        "UmRdpService"      # Remote Desktop UserMode Port Redirector
    )
    
    $successCount = 0
    foreach ($service in $servicesToDisable) {
        # Check if this service is required per README
        $isRequired = $false
        foreach ($reqService in $RequiredServices) {
            if ($service -like "*$reqService*" -or $reqService -like "*$service*") {
                $isRequired = $true
                break
            }
        }
        
        if ($isRequired) {
            Write-Log "Skipping $service (required per README)" "INFO"
            continue
        }
        
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "Disabled service: $service" "SUCCESS"
                $successCount++
            }
        } catch {
            Write-Log "Could not disable service $service : $_" "WARNING"
        }
    }
    Write-Log "Disabled $successCount insecure services" "SUCCESS"
    return $true
}

function Block-VulnerablePorts {
    Write-Log "Blocking vulnerable ports..."
    $portsToBlock = @{
        "RDP" = @{Protocol = "TCP"; Port = "3389"}
        "SSH" = @{Protocol = "TCP"; Port = "22"}
        "Telnet" = @{Protocol = "TCP"; Port = "23"}
        "SNMP" = @{Protocol = "UDP"; Port = "161,162"}
        "LDAP" = @{Protocol = "TCP"; Port = "389"}
        "FTP-Command" = @{Protocol = "TCP"; Port = "21"}
        "FTP-Data" = @{Protocol = "TCP"; Port = "20"}
    }
    
    $successCount = 0
    foreach ($rule in $portsToBlock.GetEnumerator()) {
        try {
            $ruleName = "Block-$($rule.Key)-CyberPatriot"
            # Remove existing rule if it exists
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound `
                -Action Block `
                -Protocol $rule.Value.Protocol `
                -LocalPort $rule.Value.Port `
                -ErrorAction Stop | Out-Null
            Write-Log "Blocked $($rule.Key) port(s): $($rule.Value.Port)" "SUCCESS"
            $successCount++
        } catch {
            Write-Log "Failed to block $($rule.Key): $_" "WARNING"
        }
    }
    Write-Log "Blocked $successCount port rules" "SUCCESS"
    return $true
}

function Remove-UnauthorizedSoftware {
    Write-Log "Checking for unauthorized software..."
    $unauthorizedApps = @(
        "*BitTorrent*",
        "*uTorrent*",
        "*Wireshark*",
        "*CCleaner*"
    )
    
    $foundApps = @()
    foreach ($app in $unauthorizedApps) {
        $installed = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like $app }
        if ($installed) {
            $foundApps += $installed
        }
    }
    
    if ($foundApps.Count -gt 0) {
        Write-Log "Found $($foundApps.Count) unauthorized applications" "WARNING"
        foreach ($app in $foundApps) {
            Write-Log "  - $($app.Name)" "INFO"
        }
        return $foundApps
    } else {
        Write-Log "No unauthorized software detected" "SUCCESS"
        return $null
    }
}

function Enable-AutomaticUpdates {
    Write-Log "Enabling automatic updates..."
    try {
        $updateService = New-Object -ComObject Microsoft.Update.AutoUpdate
        $updateService.EnableService()
        Write-Log "Automatic updates enabled successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to enable automatic updates: $_" "ERROR"
        return $false
    }
}

function Configure-AuditPolicies {
    Write-Log "Configuring audit policies..."
    try {
        # Enable auditing for security events
        auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
        Write-Log "Audit policies configured successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to configure audit policies: $_" "ERROR"
        return $false
    }
}

function Check-SharedFolders {
    Write-Log "Checking shared folders..."
    try {
        $shares = Get-SmbShare | Where-Object { $_.Name -notin @("ADMIN$", "C$", "IPC$") }
        if ($shares) {
            Write-Log "Found non-default shares:" "WARNING"
            foreach ($share in $shares) {
                Write-Log "  - $($share.Name) at $($share.Path)" "WARNING"
            }
            return $shares
        } else {
            Write-Log "Only default shares present" "SUCCESS"
            return $null
        }
    } catch {
        Write-Log "Failed to check shared folders: $_" "ERROR"
        return $null
    }
}

function Enable-WindowsSecurity {
    Write-Log "Enabling Windows Security features..."
    try {
        # Enable Windows Defender
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Write-Log "Windows Defender real-time protection enabled" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to enable Windows Security: $_" "ERROR"
        return $false
    }
}

function Start-QuickScan {
    Write-Log "Starting Windows Defender quick scan..."
    try {
        Start-MpScan -ScanType QuickScan -AsJob | Out-Null
        Write-Log "Quick scan started successfully (running in background)" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to start quick scan: $_" "ERROR"
        return $false
    }
}

function Start-FullScan {
    Write-Log "Starting Windows Defender FULL scan..."
    Write-Log "WARNING: Full scan can take 30+ minutes!" "WARNING"
    try {
        Start-MpScan -ScanType FullScan -AsJob | Out-Null
        Write-Log "Full scan started successfully (running in background)" "SUCCESS"
        Write-Log "This will continue running even after this script closes" "INFO"
        return $true
    } catch {
        Write-Log "Failed to start full scan: $_" "ERROR"
        return $false
    }
}

function Update-MalwareDefinitions {
    Write-Log "Updating Windows Defender malware definitions..."
    try {
        Update-MpSignature
        Write-Log "Malware definitions updated successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to update malware definitions: $_" "ERROR"
        return $false
    }
}

function Find-SuspiciousFiles {
    Write-Log "Scanning for suspicious file locations..."
    $suspiciousLocations = @(
        "$env:TEMP",
        "$env:USERPROFILE\AppData\Local\Temp",
        "$env:USERPROFILE\Downloads",
        "C:\Windows\Temp"
    )
    
    $suspiciousExtensions = @("*.vbs", "*.bat", "*.ps1", "*.exe", "*.scr", "*.cmd")
    $recentFiles = @()
    
    foreach ($location in $suspiciousLocations) {
        if (Test-Path $location) {
            foreach ($ext in $suspiciousExtensions) {
                try {
                    $files = Get-ChildItem -Path $location -Filter $ext -File -ErrorAction SilentlyContinue |
                             Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
                             Select-Object -First 20
                    if ($files) {
                        $recentFiles += $files
                        foreach ($file in $files) {
                            Write-Log "  Found recent suspicious file: $($file.FullName)" "WARNING"
                        }
                    }
                } catch {
                    # Ignore access denied
                }
            }
        }
    }
    
    if ($recentFiles.Count -gt 0) {
        Write-Log "Found $($recentFiles.Count) suspicious files - review manually!" "WARNING"
    } else {
        Write-Log "No obviously suspicious files found in common locations" "SUCCESS"
    }
    
    return $recentFiles
}

function Check-MalwareRemovalTool {
    Write-Log "Checking for Microsoft Malicious Software Removal Tool..."
    try {
        $mrtPath = "$env:SystemRoot\System32\MRT.exe"
        if (Test-Path $mrtPath) {
            Write-Log "MRT found - You can run it manually: Win+R > mrt" "INFO"
            return $true
        } else {
            Write-Log "MRT not found on system" "WARNING"
            return $false
        }
    } catch {
        Write-Log "Could not check for MRT: $_" "ERROR"
        return $false
    }
}

function Show-UserAccounts {
    Write-Log "Listing user accounts..."
    try {
        $users = Get-LocalUser
        Write-Log "Found $($users.Count) user accounts:" "INFO"
        foreach ($user in $users) {
            Write-Log "  - $($user.Name) (Enabled: $($user.Enabled))" "INFO"
        }
        return $users
    } catch {
        Write-Log "Failed to list user accounts: $_" "ERROR"
        return $null
    }
}

function Enable-SecureLogon {
    Write-Log "Enabling secure logon (Ctrl+Alt+Del)..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 0
        Write-Log "Secure logon enabled successfully" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to enable secure logon: $_" "ERROR"
        return $false
    }
}

function Hide-LastUsername {
    Write-Log "Hiding last username on login screen..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord
        Write-Log "Last username will be hidden on login screen" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to hide last username: $_" "ERROR"
        return $false
    }
}

# GUI Creation

function Create-GUI {
    # Show initial safety warning
    $warningResult = [System.Windows.Forms.MessageBox]::Show(
        "⚠️ IMPORTANT SAFETY REMINDERS ⚠️`n`n" +
        "Before running this script:`n`n" +
        "1. Have you READ the competition README file?`n" +
        "2. Have you WRITTEN DOWN your password?`n" +
        "3. Have you completed FORENSICS QUESTIONS?`n`n" +
        "This script:`n" +
        "✓ Does NOT change your password`n" +
        "✓ Does NOT delete files`n" +
        "✓ Does NOT interfere with competition files`n" +
        "✓ Only applies security configurations`n`n" +
        "Continue?",
        "Safety Check - READ THIS",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($warningResult -ne [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "User cancelled at safety warning" "INFO"
        return
    }
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "CyberPatriot Automation Tool"
    $form.Size = New-Object System.Drawing.Size(600, 700)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    
    # Title Label
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Location = New-Object System.Drawing.Point(10, 10)
    $titleLabel.Size = New-Object System.Drawing.Size(560, 30)
    $titleLabel.Text = "CyberPatriot Automated Security Hardening"
    $titleLabel.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $titleLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($titleLabel)
    
    # Instructions
    $instructionLabel = New-Object System.Windows.Forms.Label
    $instructionLabel.Location = New-Object System.Drawing.Point(10, 45)
    $instructionLabel.Size = New-Object System.Drawing.Size(560, 40)
    $instructionLabel.Text = "Select the security tasks to perform. Results will be logged to:`n$LogFile"
    $form.Controls.Add($instructionLabel)
    
    # Create checkboxes for each task
    $yPosition = 90
    $checkboxes = @()
    
    $tasks = @(
        @{Name = "Enable Firewall"; Function = "Enable-Firewall"; Description = "Turn on Windows Firewall for all profiles"},
        @{Name = "Disable Guest Account"; Function = "Disable-GuestAccount"; Description = "Disable the Guest account"},
        @{Name = "Disable Admin Account"; Function = "Disable-AdminAccount"; Description = "Disable built-in Administrator account"},
        @{Name = "Configure Password Policies"; Function = "Set-PasswordPolicies"; Description = "Set secure password requirements"},
        @{Name = "Disable Insecure Services"; Function = "Disable-InsecureServices"; Description = "Stop and disable RDP, FTP, etc."},
        @{Name = "Block Vulnerable Ports"; Function = "Block-VulnerablePorts"; Description = "Block common attack ports (RDP, SSH, etc.)"},
        @{Name = "Enable Automatic Updates"; Function = "Enable-AutomaticUpdates"; Description = "Enable Windows automatic updates"},
        @{Name = "Configure Audit Policies"; Function = "Configure-AuditPolicies"; Description = "Enable security event auditing"},
        @{Name = "Enable Windows Security"; Function = "Enable-WindowsSecurity"; Description = "Enable Windows Defender"},
        @{Name = "Update Malware Definitions"; Function = "Update-MalwareDefinitions"; Description = "⚠️ Update virus definitions (do this first!)"},
        @{Name = "Run Quick Scan"; Function = "Start-QuickScan"; Description = "Start Windows Defender quick scan (5-10 min)"},
        @{Name = "Run FULL Scan"; Function = "Start-FullScan"; Description = "⚠️ Start FULL malware scan (30+ min, runs in background)"},
        @{Name = "Find Suspicious Files"; Function = "Find-SuspiciousFiles"; Description = "Scan temp folders for recent suspicious files"},
        @{Name = "Enable Secure Logon"; Function = "Enable-SecureLogon"; Description = "Require Ctrl+Alt+Del to log in"},
        @{Name = "Hide Last Username"; Function = "Hide-LastUsername"; Description = "Don't show last username on login"}
    )
    
    foreach ($task in $tasks) {
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Location = New-Object System.Drawing.Point(20, $yPosition)
        $checkbox.Size = New-Object System.Drawing.Size(540, 20)
        $checkbox.Text = $task.Name
        $checkbox.Tag = $task
        $checkbox.Checked = $true
        $checkboxes += $checkbox
        $form.Controls.Add($checkbox)
        $yPosition += 25
        
        # Add description label
        $descLabel = New-Object System.Windows.Forms.Label
        $descLabel.Location = New-Object System.Drawing.Point(40, $yPosition)
        $descLabel.Size = New-Object System.Drawing.Size(520, 15)
        $descLabel.Text = $task.Description
        $descLabel.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
        $descLabel.ForeColor = [System.Drawing.Color]::Gray
        $form.Controls.Add($descLabel)
        $yPosition += 20
    }
    
    # Select All / Deselect All buttons
    $selectAllBtn = New-Object System.Windows.Forms.Button
    $selectAllBtn.Location = New-Object System.Drawing.Point(20, $yPosition)
    $selectAllBtn.Size = New-Object System.Drawing.Size(100, 30)
    $selectAllBtn.Text = "Select All"
    $selectAllBtn.Add_Click({
        foreach ($cb in $checkboxes) {
            $cb.Checked = $true
        }
    })
    $form.Controls.Add($selectAllBtn)
    
    $deselectAllBtn = New-Object System.Windows.Forms.Button
    $deselectAllBtn.Location = New-Object System.Drawing.Point(130, $yPosition)
    $deselectAllBtn.Size = New-Object System.Drawing.Size(100, 30)
    $deselectAllBtn.Text = "Deselect All"
    $deselectAllBtn.Add_Click({
        foreach ($cb in $checkboxes) {
            $cb.Checked = $false
        }
    })
    $form.Controls.Add($deselectAllBtn)
    
    $yPosition += 40
    
    # Progress bar
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(20, $yPosition)
    $progressBar.Size = New-Object System.Drawing.Size(540, 20)
    $progressBar.Style = "Continuous"
    $form.Controls.Add($progressBar)
    
    $yPosition += 30
    
    # Status label
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(20, $yPosition)
    $statusLabel.Size = New-Object System.Drawing.Size(540, 20)
    $statusLabel.Text = "Ready"
    $form.Controls.Add($statusLabel)
    
    $yPosition += 30
    
    # Run button
    $runButton = New-Object System.Windows.Forms.Button
    $runButton.Location = New-Object System.Drawing.Point(180, $yPosition)
    $runButton.Size = New-Object System.Drawing.Size(100, 40)
    $runButton.Text = "Run Selected"
    $runButton.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
    $runButton.BackColor = [System.Drawing.Color]::LightGreen
    $runButton.Add_Click({
        $selectedTasks = $checkboxes | Where-Object { $_.Checked }
        if ($selectedTasks.Count -eq 0) {
            Show-Notification "No Tasks Selected" "Please select at least one task to run." "Warning"
            return
        }
        
        # Disable controls during execution
        $runButton.Enabled = $false
        $viewReportBtn.Enabled = $false
        foreach ($cb in $checkboxes) { $cb.Enabled = $false }
        $selectAllBtn.Enabled = $false
        $deselectAllBtn.Enabled = $false
        
        $progressBar.Maximum = $selectedTasks.Count
        $progressBar.Value = 0
        
        Write-Log "========================================" "INFO"
        Write-Log "Starting CyberPatriot Automation" "INFO"
        Write-Log "Selected $($selectedTasks.Count) tasks" "INFO"
        Write-Log "========================================" "INFO"
        
        $successCount = 0
        $failCount = 0
        
        # Load README data if available
        $readmeData = $null
        $requiredServices = @()
        if (Test-Path "$ScriptPath\ReadmeData.json") {
            try {
                $readmeData = Get-Content "$ScriptPath\ReadmeData.json" -Raw | ConvertFrom-Json
                Write-Log "Loaded README data for filtering" "INFO"
                if ($readmeData.RequiredServices) {
                    $requiredServices = $readmeData.RequiredServices
                }
            } catch {
                Write-Log "Could not load README data: $_" "WARNING"
            }
        }
        
        foreach ($task in $selectedTasks) {
            $statusLabel.Text = "Running: $($task.Tag.Name)..."
            $form.Refresh()
            
            try {
                # Pass README data to functions that need it
                if ($task.Tag.Function -eq "Disable-InsecureServices") {
                    $result = Disable-InsecureServices -RequiredServices $requiredServices
                } else {
                    $result = & $task.Tag.Function
                }
                
                if ($result -ne $false) {
                    $successCount++
                } else {
                    $failCount++
                }
            } catch {
                Write-Log "Exception running $($task.Tag.Name): $_" "ERROR"
                $failCount++
            }
            
            $progressBar.Value++
        }
        
        Write-Log "========================================" "INFO"
        Write-Log "Automation Complete" "INFO"
        Write-Log "Success: $successCount | Failed: $failCount" "INFO"
        Write-Log "========================================" "INFO"
        Write-Log "" "INFO"
        Write-Log "⚠️  IMPORTANT: Run Windows Update LAST!" "WARNING"
        Write-Log "After completing all manual tasks, run Windows Update as the final step." "WARNING"
        Write-Log "========================================" "INFO"
        
        $statusLabel.Text = "Complete! Success: $successCount | Failed: $failCount"
        
        # Re-enable controls
        $runButton.Enabled = $true
        $viewReportBtn.Enabled = $true
        foreach ($cb in $checkboxes) { $cb.Enabled = $true }
        $selectAllBtn.Enabled = $true
        $deselectAllBtn.Enabled = $true
        
        # Show completion message with Windows Update reminder
        Show-Notification "Automation Complete" "Tasks completed!`nSuccess: $successCount`nFailed: $failCount`n`n⚠️ REMEMBER: Run Windows Update LAST!`nAfter all manual tasks are complete.`n`nCheck log file for details." "Information"
    })
    $form.Controls.Add($runButton)
    
    # View Report button
    $viewReportBtn = New-Object System.Windows.Forms.Button
    $viewReportBtn.Location = New-Object System.Drawing.Point(290, $yPosition)
    $viewReportBtn.Size = New-Object System.Drawing.Size(100, 40)
    $viewReportBtn.Text = "View Log"
    $viewReportBtn.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
    $viewReportBtn.Add_Click({
        if (Test-Path $LogFile) {
            notepad.exe $LogFile
        } else {
            Show-Notification "Log Not Found" "No log file has been created yet." "Warning"
        }
    })
    $form.Controls.Add($viewReportBtn)
    
    # Show the form
    $form.ShowDialog() | Out-Null
}

# Main Execution
Write-Log "========================================" "INFO"
Write-Log "CyberPatriot Automation Tool Started" "INFO"
Write-Log "Log file: $LogFile" "INFO"
Write-Log "========================================" "INFO"

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "Script must be run as Administrator!" "ERROR"
    Show-Notification "Administrator Required" "This script must be run as Administrator.`n`nRight-click the script and select 'Run as Administrator'." "Error"
    exit 1
}

# Display GUI
Create-GUI

Write-Log "Script execution completed" "INFO"
