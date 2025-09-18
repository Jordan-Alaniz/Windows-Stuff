@echo off
REM Windows Security Hardening Script for Cyberpatriot
REM Run as Administrator!

echo ================================================
echo Windows Security Hardening Script
echo ================================================
echo.
echo This script will perform basic security hardening
echo Make sure to run as Administrator!
echo.
pause

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo Starting security hardening...
echo.

REM 1. Disable Guest Account
echo [1/10] Disabling Guest Account...
net user guest /active:no >nul 2>&1
if %errorLevel% equ 0 (
    echo    ✓ Guest account disabled
) else (
    echo    ✗ Failed to disable guest account
)

REM 2. Enable Windows Firewall
echo [2/10] Enabling Windows Firewall...
netsh advfirewall set allprofiles state on >nul 2>&1
if %errorLevel% equ 0 (
    echo    ✓ Windows Firewall enabled for all profiles
) else (
    echo    ✗ Failed to enable Windows Firewall
)

REM 3. Disable unnecessary services
echo [3/10] Disabling unnecessary services...

REM Disable Telnet
sc config tlntsvr start= disabled >nul 2>&1
sc stop tlntsvr >nul 2>&1
echo    ✓ Telnet service disabled

REM Disable Simple TCP/IP Services
sc config simptcp start= disabled >nul 2>&1
sc stop simptcp >nul 2>&1
echo    ✓ Simple TCP/IP Services disabled

REM Disable Remote Registry
sc config remoteregistry start= disabled >nul 2>&1
sc stop remoteregistry >nul 2>&1
echo    ✓ Remote Registry disabled

REM 4. Configure password policy (requires local security policy)
echo [4/10] Configuring password policy...
REM Note: These require secedit or local security policy changes
echo    → Password policy should be configured manually via secpol.msc

REM 5. Disable autorun for all drives
echo [5/10] Disabling autorun...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f >nul 2>&1
if %errorLevel% equ 0 (
    echo    ✓ Autorun disabled for all drives
) else (
    echo    ✗ Failed to disable autorun
)

REM 6. Show hidden files and file extensions
echo [6/10] Configuring file display options...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f >nul 2>&1
echo    ✓ Hidden files and file extensions will be shown

REM 7. Disable anonymous access
echo [7/10] Securing network access...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f >nul 2>&1
echo    ✓ Anonymous access restricted

REM 8. Enable UAC
echo [8/10] Enabling User Account Control...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >nul 2>&1
echo    ✓ User Account Control enabled

REM 9. Set secure screen saver
echo [9/10] Configuring screen saver security...
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 900 /f >nul 2>&1
echo    ✓ Secure screen saver configured (15 minutes)

REM 10. Create system restore point
echo [10/10] Creating system restore point...
powershell -Command "Checkpoint-Computer -Description 'Security Hardening Script' -RestorePointType 'MODIFY_SETTINGS'" >nul 2>&1
if %errorLevel% equ 0 (
    echo    ✓ System restore point created
) else (
    echo    → System restore point creation may have failed
)

echo.
echo ================================================
echo Security hardening completed!
echo ================================================
echo.
echo Next steps to complete manually:
echo 1. Configure password policy (secpol.msc)
echo 2. Review and remove unauthorized users
echo 3. Check for unauthorized software
echo 4. Run Windows Update
echo 5. Perform antivirus scan
echo 6. Review firewall rules
echo.
echo IMPORTANT: Restart the computer for all changes to take effect
echo.
pause