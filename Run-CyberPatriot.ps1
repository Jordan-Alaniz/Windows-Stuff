#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot Master Control Script
.DESCRIPTION
    Orchestrates all CyberPatriot automation and audit scripts in the recommended order.
    Provides a unified interface for running all security hardening and audit tasks.
.NOTES
    MUST BE RUN AS ADMINISTRATOR
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-Banner {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  CyberPatriot Automation Suite" -ForegroundColor Cyan
    Write-Host "  Master Control Script" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Menu {
    param([string]$Title = 'CyberPatriot Automation Menu')
    
    Write-Host "================ $Title ================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "RECOMMENDED WORKFLOW:" -ForegroundColor Green
    Write-Host "  0. Analyze README (Extract competition requirements)"
    Write-Host "  1. Run Quick Audit (Fast scan of current state)"
    Write-Host "  2. Run Security Hardening (Automated fixes)"
    Write-Host "  3. Run File Auditor (Find files to delete)"
    Write-Host "  4. Run User Auditor (Review accounts)"
    Write-Host "  5. Windows Update (RUN THIS LAST!)"
    Write-Host ""
    Write-Host "INDIVIDUAL SCRIPTS:" -ForegroundColor Green
    Write-Host "  [0] Analyze README - Parse competition requirements"
    Write-Host "  [Q] Quick Audit - Fast overview of security issues"
    Write-Host "  [A] Security Hardening - Run CyberPatriot-Auto.ps1"
    Write-Host "  [S] Server Hardening - Run ServerHardening.ps1 (Windows Server only)"
    Write-Host "  [F] File Auditor - Scan for unauthorized files/software"
    Write-Host "  [U] User Auditor - Review user accounts and groups"
    Write-Host ""
    Write-Host "UTILITIES:" -ForegroundColor Green
    Write-Host "  [L] View all log files"
    Write-Host "  [C] Open checklist folder"
    Write-Host "  [H] Open Quick Start guide"
    Write-Host "  [W] Run Windows Update (DO THIS LAST!)"
    Write-Host ""
    Write-Host "  [R] Run all recommended tasks (0-4 in sequence)"
    Write-Host "  [X] Exit"
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
}

function Run-QuickAudit {
    Write-Host "`n[*] Running Quick Audit..." -ForegroundColor Cyan
    Write-Host "This provides a fast overview of the current security state." -ForegroundColor Gray
    Write-Host ""
    
    # Quick checks
    Write-Host "=== FIREWALL STATUS ===" -ForegroundColor Yellow
    try {
        $firewallProfiles = Get-NetFirewallProfile
        foreach ($profile in $firewallProfiles) {
            $status = if ($profile.Enabled) { "ENABLED" } else { "DISABLED" }
            $color = if ($profile.Enabled) { "Green" } else { "Red" }
            Write-Host "$($profile.Name): $status" -ForegroundColor $color
        }
    } catch {
        Write-Host "Could not check firewall status" -ForegroundColor Red
    }
    
    Write-Host "`n=== USER ACCOUNTS ===" -ForegroundColor Yellow
    try {
        $users = Get-LocalUser | Where-Object { $_.Enabled }
        Write-Host "Enabled users: $($users.Count)" -ForegroundColor Cyan
        foreach ($user in $users) {
            Write-Host "  - $($user.Name)" -ForegroundColor Gray
        }
        
        # Check for Guest/Admin
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Write-Host "  WARNING: Guest account is enabled!" -ForegroundColor Red
        }
        
        $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($admin -and $admin.Enabled) {
            Write-Host "  WARNING: Built-in Administrator is enabled!" -ForegroundColor Red
        }
    } catch {
        Write-Host "Could not check user accounts" -ForegroundColor Red
    }
    
    Write-Host "`n=== WINDOWS DEFENDER ===" -ForegroundColor Yellow
    try {
        $defender = Get-MpComputerStatus
        $rtStatus = if ($defender.RealTimeProtectionEnabled) { "ENABLED" } else { "DISABLED" }
        $rtColor = if ($defender.RealTimeProtectionEnabled) { "Green" } else { "Red" }
        Write-Host "Real-time Protection: $rtStatus" -ForegroundColor $rtColor
        Write-Host "Last Quick Scan: $($defender.QuickScanEndTime)" -ForegroundColor Gray
    } catch {
        Write-Host "Could not check Windows Defender status" -ForegroundColor Red
    }
    
    Write-Host "`n=== INSECURE SERVICES ===" -ForegroundColor Yellow
    $insecureServices = @("RemoteRegistry", "TermService", "ftpsvc", "SSDPSRV", "upnphost")
    foreach ($svcName in $insecureServices) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                $status = $svc.Status
                $startup = $svc.StartType
                $color = if ($status -eq "Running" -or $startup -eq "Automatic") { "Red" } else { "Green" }
                Write-Host "$($svcName): $status ($startup)" -ForegroundColor $color
            }
        } catch {
            # Service doesn't exist, which is fine
        }
    }
    
    Write-Host "`n=== AUTOMATIC UPDATES ===" -ForegroundColor Yellow
    try {
        $updateService = New-Object -ComObject Microsoft.Update.AutoUpdate
        $updateEnabled = $updateService.ServiceEnabled
        $color = if ($updateEnabled) { "Green" } else { "Red" }
        $status = if ($updateEnabled) { "ENABLED" } else { "DISABLED" }
        Write-Host "Automatic Updates: $status" -ForegroundColor $color
    } catch {
        Write-Host "Could not check automatic updates" -ForegroundColor Red
    }
    
    Write-Host "`n" 
    Write-Host "Quick audit complete!" -ForegroundColor Green
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Run-SecurityHardening {
    Write-Host "`n[*] Launching Security Hardening Script..." -ForegroundColor Cyan
    $autoScript = Join-Path $ScriptPath "CyberPatriot-Auto.ps1"
    
    if (Test-Path $autoScript) {
        & $autoScript
    } else {
        Write-Host "ERROR: CyberPatriot-Auto.ps1 not found!" -ForegroundColor Red
        Write-Host "Expected location: $autoScript" -ForegroundColor Red
        Write-Host "Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function Run-AnalyzeReadme {
    Write-Host "`n[*] Launching README Analyzer..." -ForegroundColor Cyan
    $readmeScript = Join-Path $ScriptPath "AnalyzeReadme.ps1"
    
    if (Test-Path $readmeScript) {
        & $readmeScript
    } else {
        Write-Host "ERROR: AnalyzeReadme.ps1 not found!" -ForegroundColor Red
        Write-Host "Expected location: $readmeScript" -ForegroundColor Red
        Write-Host "Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function Run-ServerHardening {
    Write-Host "`n[*] Launching Server Hardening Script..." -ForegroundColor Cyan
    $serverScript = Join-Path $ScriptPath "ServerHardening.ps1"
    
    if (Test-Path $serverScript) {
        & $serverScript
    } else {
        Write-Host "ERROR: ServerHardening.ps1 not found!" -ForegroundColor Red
        Write-Host "Expected location: $serverScript" -ForegroundColor Red
        Write-Host "Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function Run-FileAuditor {
    Write-Host "`n[*] Launching File Auditor..." -ForegroundColor Cyan
    $fileAuditScript = Join-Path $ScriptPath "FileAuditor.ps1"
    
    if (Test-Path $fileAuditScript) {
        & $fileAuditScript
    } else {
        Write-Host "ERROR: FileAuditor.ps1 not found!" -ForegroundColor Red
        Write-Host "Expected location: $fileAuditScript" -ForegroundColor Red
        Write-Host "Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function Run-UserAuditor {
    Write-Host "`n[*] Launching User Auditor..." -ForegroundColor Cyan
    $userAuditScript = Join-Path $ScriptPath "UserAuditor.ps1"
    
    if (Test-Path $userAuditScript) {
        & $userAuditScript
    } else {
        Write-Host "ERROR: UserAuditor.ps1 not found!" -ForegroundColor Red
        Write-Host "Expected location: $userAuditScript" -ForegroundColor Red
        Write-Host "Press any key to continue..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function View-AllLogs {
    Write-Host "`n[*] Finding log files..." -ForegroundColor Cyan
    $logs = Get-ChildItem -Path $ScriptPath -Filter "*.txt" | Where-Object { $_.Name -like "*Audit*" -or $_.Name -like "*Log*" }
    
    if ($logs.Count -eq 0) {
        Write-Host "No log files found." -ForegroundColor Yellow
    } else {
        Write-Host "Found $($logs.Count) log file(s):" -ForegroundColor Green
        $logs | Format-Table Name, LastWriteTime, @{Name='Size(KB)';Expression={[math]::Round($_.Length/1KB,2)}} -AutoSize
        
        Write-Host "`nEnter log number to view (or press Enter to skip): " -NoNewline
        $choice = Read-Host
        
        if ($choice -match '^\d+$' -and [int]$choice -gt 0 -and [int]$choice -le $logs.Count) {
            $selectedLog = $logs[[int]$choice - 1]
            Start-Process notepad.exe -ArgumentList $selectedLog.FullName
        }
    }
    
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Open-ChecklistFolder {
    Write-Host "`n[*] Opening checklist folder..." -ForegroundColor Cyan
    $checklistPath = Join-Path $ScriptPath "checklist"
    
    if (Test-Path $checklistPath) {
        Start-Process explorer.exe -ArgumentList $checklistPath
        Write-Host "Checklist folder opened in Explorer." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Checklist folder not found!" -ForegroundColor Red
    }
    
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Open-QuickStartGuide {
    Write-Host "`n[*] Opening Quick Start guide..." -ForegroundColor Cyan
    $guidePath = Join-Path $ScriptPath "QUICK_START.md"
    
    if (Test-Path $guidePath) {
        Start-Process notepad.exe -ArgumentList $guidePath
        Write-Host "Quick Start guide opened." -ForegroundColor Green
    } else {
        Write-Host "ERROR: QUICK_START.md not found!" -ForegroundColor Red
    }
    
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Run-WindowsUpdate {
    Write-Host "`n[*] Opening Windows Update..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  WINDOWS UPDATE - RUN THIS LAST!" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Windows Update should be run AFTER:" -ForegroundColor Cyan
    Write-Host "  ✓ All security hardening is complete" -ForegroundColor Gray
    Write-Host "  ✓ All unauthorized files are deleted" -ForegroundColor Gray
    Write-Host "  ✓ All unauthorized users are removed" -ForegroundColor Gray
    Write-Host "  ✓ All manual tasks are finished" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Opening Windows Update Settings..." -ForegroundColor Green
    Write-Host ""
    
    # Open Windows Update settings
    Start-Process "ms-settings:windowsupdate"
    
    Write-Host "In the Windows Update window:" -ForegroundColor Yellow
    Write-Host "  1. Click 'Check for updates'" -ForegroundColor Gray
    Write-Host "  2. Install all available updates" -ForegroundColor Gray
    Write-Host "  3. Restart if required" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Run-AllTasks {
    Write-Host "`n" 
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "  RUNNING ALL RECOMMENDED TASKS" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host ""
    
    Write-Host "[0/5] Analyzing README..." -ForegroundColor Cyan
    Run-AnalyzeReadme
    
    Write-Host "`n[1/5] Running Quick Audit..." -ForegroundColor Cyan
    Run-QuickAudit
    
    Write-Host "`n[2/5] Running Security Hardening..." -ForegroundColor Cyan
    Run-SecurityHardening
    
    Write-Host "`n[3/5] Running File Auditor..." -ForegroundColor Cyan
    Run-FileAuditor
    
    Write-Host "`n[4/4] Running User Auditor..." -ForegroundColor Cyan
    Run-UserAuditor
    
    Write-Host "`n" 
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ALL TASKS COMPLETE!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Review the log files" -ForegroundColor Gray
    Write-Host "  2. Delete unauthorized files found by File Auditor" -ForegroundColor Gray
    Write-Host "  3. Adjust user accounts as needed" -ForegroundColor Gray
    Write-Host "  4. Run Windows Update" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Press any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Main script execution
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Main menu loop
do {
    Show-Banner
    Show-Menu
    
    Write-Host "Select an option: " -NoNewline -ForegroundColor Cyan
    $choice = Read-Host
    
    switch ($choice.ToUpper()) {
        'Q' { Run-QuickAudit }
        'A' { Run-SecurityHardening }
        'F' { Run-FileAuditor }
        'U' { Run-UserAuditor }
        'L' { View-AllLogs }
        'C' { Open-ChecklistFolder }
        'H' { Open-QuickStartGuide }
        'R' { Run-AllTasks }
        'X' { 
            Write-Host "`nExiting... Good luck with CyberPatriot!" -ForegroundColor Green
            break
        }
        default {
            Write-Host "`nInvalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice.ToUpper() -ne 'X')
