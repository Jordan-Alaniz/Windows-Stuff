# Windows Security Configuration PowerShell Script
# Advanced security hardening for Cyberpatriot competitions
# Run as Administrator

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as administrator'" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Windows Security Configuration Script" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# Function to show progress
function Show-Progress {
    param($Message, $Step, $Total)
    Write-Host "[$Step/$Total] $Message" -ForegroundColor Green
}

# Function to check and report status
function Report-Status {
    param($Message, $Success)
    if ($Success) {
        Write-Host "    ✓ $Message" -ForegroundColor Green
    } else {
        Write-Host "    ✗ $Message" -ForegroundColor Red
    }
}

$TotalSteps = 12
$CurrentStep = 0

# 1. Configure User Account Control
$CurrentStep++
Show-Progress "Configuring User Account Control" $CurrentStep $TotalSteps
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
    Report-Status "UAC enabled" $true
} catch {
    Report-Status "Failed to enable UAC" $false
}

# 2. Disable Guest Account
$CurrentStep++
Show-Progress "Disabling Guest Account" $CurrentStep $TotalSteps
try {
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Report-Status "Guest account disabled" $true
} catch {
    # Fallback to net command
    $result = net user guest /active:no 2>&1
    Report-Status "Guest account disabled (via net command)" ($LASTEXITCODE -eq 0)
}

# 3. Configure Windows Firewall
$CurrentStep++
Show-Progress "Configuring Windows Firewall" $CurrentStep $TotalSteps
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Report-Status "Windows Firewall enabled for all profiles" $true
} catch {
    Report-Status "Failed to configure Windows Firewall" $false
}

# 4. Disable unnecessary services
$CurrentStep++
Show-Progress "Disabling unnecessary services" $CurrentStep $TotalSteps

$ServicesToDisable = @(
    "TlntSvr",          # Telnet
    "simptcp",          # Simple TCP/IP Services
    "RemoteRegistry",   # Remote Registry
    "SNMP",             # SNMP Service
    "SNMPTRAP",         # SNMP Trap
    "WMPNetworkSvc"     # Windows Media Player Network Sharing
)

foreach ($service in $ServicesToDisable) {
    try {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Report-Status "$service service disabled" $true
        }
    } catch {
        # Service might not exist, continue
    }
}

# 5. Configure password policy
$CurrentStep++
Show-Progress "Configuring password policy" $CurrentStep $TotalSteps
try {
    # Note: This requires secedit and may not work on all systems
    $secpolConfig = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 8
PasswordComplexity = 1
PasswordHistorySize = 5
LockoutBadCount = 5
LockoutDuration = 30
ResetLockoutCount = 30
"@
    
    $tempFile = [System.IO.Path]::GetTempFileName()
    $secpolConfig | Out-File -FilePath $tempFile -Encoding ASCII
    
    secedit /configure /db temp.sdb /cfg $tempFile /quiet
    Remove-Item $tempFile -Force
    Report-Status "Password policy configured" $true
} catch {
    Report-Status "Password policy configuration failed (configure manually via secpol.msc)" $false
}

# 6. Disable autorun
$CurrentStep++
Show-Progress "Disabling autorun" $CurrentStep $TotalSteps
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
    Report-Status "Autorun disabled for all drives" $true
} catch {
    Report-Status "Failed to disable autorun" $false
}

# 7. Configure audit policies
$CurrentStep++
Show-Progress "Configuring audit policies" $CurrentStep $TotalSteps
try {
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Policy Change" /success:enable /failure:enable
    Report-Status "Audit policies configured" $true
} catch {
    Report-Status "Failed to configure audit policies" $false
}

# 8. Show hidden files and file extensions
$CurrentStep++
Show-Progress "Configuring file display options" $CurrentStep $TotalSteps
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
    Report-Status "Hidden files and file extensions configured to show" $true
} catch {
    Report-Status "Failed to configure file display options" $false
}

# 9. Configure network security
$CurrentStep++
Show-Progress "Configuring network security" $CurrentStep $TotalSteps
try {
    # Disable NetBIOS over TCP/IP
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) # Disable NetBIOS
    }
    
    # Restrict anonymous access
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 1
    Report-Status "Network security configured" $true
} catch {
    Report-Status "Failed to configure network security" $false
}

# 10. Configure Windows Update
$CurrentStep++
Show-Progress "Configuring Windows Update" $CurrentStep $TotalSteps
try {
    # Enable automatic updates
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4
    Report-Status "Automatic updates enabled" $true
} catch {
    Report-Status "Failed to configure Windows Update" $false
}

# 11. Check for and install Windows Updates
$CurrentStep++
Show-Progress "Checking for Windows Updates" $CurrentStep $TotalSteps
try {
    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        Import-Module PSWindowsUpdate
        $updates = Get-WUList
        if ($updates.Count -gt 0) {
            Write-Host "    Found $($updates.Count) available updates" -ForegroundColor Yellow
            Write-Host "    Run 'Install-WindowsUpdate -AcceptAll -AutoReboot' to install" -ForegroundColor Yellow
        } else {
            Report-Status "No updates available" $true
        }
    } else {
        Write-Host "    PSWindowsUpdate module not available" -ForegroundColor Yellow
        Write-Host "    Check Windows Update manually" -ForegroundColor Yellow
    }
} catch {
    Report-Status "Unable to check for updates" $false
}

# 12. Create system restore point
$CurrentStep++
Show-Progress "Creating system restore point" $CurrentStep $TotalSteps
try {
    Checkpoint-Computer -Description "Security Hardening PowerShell Script" -RestorePointType "MODIFY_SETTINGS"
    Report-Status "System restore point created" $true
} catch {
    Report-Status "Failed to create system restore point" $false
}

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Security configuration completed!" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. Restart the computer for all changes to take effect" -ForegroundColor White
Write-Host "2. Review user accounts and remove unauthorized users" -ForegroundColor White
Write-Host "3. Check for and remove unauthorized software" -ForegroundColor White
Write-Host "4. Run a full antivirus scan" -ForegroundColor White
Write-Host "5. Verify all services are properly configured" -ForegroundColor White
Write-Host "6. Test system functionality" -ForegroundColor White
Write-Host ""

Write-Host "MANUAL CONFIGURATION REQUIRED:" -ForegroundColor Yellow
Write-Host "• Group Policy settings (gpedit.msc)" -ForegroundColor White
Write-Host "• User account passwords" -ForegroundColor White
Write-Host "• Firewall rules review" -ForegroundColor White
Write-Host "• Software inventory and removal" -ForegroundColor White
Write-Host ""

Read-Host "Press Enter to exit"