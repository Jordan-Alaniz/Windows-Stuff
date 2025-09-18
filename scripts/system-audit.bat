@echo off
REM System Security Audit Script for Cyberpatriot
REM Performs comprehensive security checks

echo ================================================
echo Windows System Security Audit
echo ================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: Not running as Administrator
    echo Some checks may fail or show incomplete information
    echo.
)

echo Starting system security audit...
echo Date: %date% %time%
echo.

echo ================================================
echo WINDOWS VERSION AND PATCH LEVEL:
echo ================================================
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Hotfix"
echo.

echo ================================================
echo WINDOWS FIREWALL STATUS:
echo ================================================
netsh advfirewall show allprofiles state
echo.

echo ================================================
echo RUNNING SERVICES (POTENTIALLY RISKY):
echo ================================================
echo Checking for potentially risky services...
sc query | findstr "SERVICE_NAME" | findstr -i "telnet\|ftp\|ssh\|vnc\|remote"
echo.

echo ================================================
echo NETWORK CONNECTIONS:
echo ================================================
echo Active network connections:
netstat -an | findstr "LISTENING\|ESTABLISHED" | findstr ":21\|:22\|:23\|:80\|:135\|:139\|:443\|:445\|:3389\|:5900"
echo.

echo ================================================
echo SHARED FOLDERS:
echo ================================================
net share
echo.

echo ================================================
echo STARTUP PROGRAMS:
echo ================================================
echo Registry Run keys:
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
echo.
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul
echo.

echo ================================================
echo SUSPICIOUS PROCESSES:
echo ================================================
echo Looking for common suspicious process names...
tasklist | findstr /i "hack\|crack\|key\|pass\|trojan\|virus\|malware\|bot\|rat\|backdoor"
if %errorLevel% neq 0 (
    echo No obviously suspicious processes found
)
echo.

echo ================================================
echo SYSTEM INTEGRITY:
echo ================================================
echo Running system file checker...
sfc /verifyonly
echo.

echo ================================================
echo WINDOWS UPDATE STATUS:
echo ================================================
echo Checking Windows Update status...
powershell -Command "Get-WUList" 2>nul
if %errorLevel% neq 0 (
    echo Unable to check Windows Update status via PowerShell
    echo Please check Windows Update manually
)
echo.

echo ================================================
echo ANTIVIRUS STATUS:
echo ================================================
echo Checking Windows Defender status...
powershell -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,DefinitionVersion" 2>nul
if %errorLevel% neq 0 (
    echo Unable to check Windows Defender status
)
echo.

echo ================================================
echo INSTALLED PROGRAMS (POTENTIALLY UNWANTED):
echo ================================================
echo Checking for potentially unwanted software...
wmic product get name | findstr /i "game\|torrent\|p2p\|crack\|hack\|keygen"
if %errorLevel% neq 0 (
    echo No obviously unwanted software found via WMI
)
echo.

echo ================================================
echo DISK SPACE AND TEMP FILES:
echo ================================================
dir %temp% /a /s 2>nul | findstr "File(s)" | findstr /v "0 File(s)"
echo.
echo Temp directory: %temp%
echo.

echo ================================================
echo EVENT LOG SECURITY EVENTS (LAST 10):
echo ================================================
echo Recent security events:
wevtutil qe Security /c:10 /rd:true /f:text 2>nul | findstr "Date\|Event ID\|Level"
echo.

echo ================================================
echo RECOMMENDATIONS BASED ON AUDIT:
echo ================================================
echo 1. Review all running services and disable unnecessary ones
echo 2. Close unnecessary network ports and services
echo 3. Remove unauthorized shared folders
echo 4. Clean startup programs and registry entries
echo 5. Update Windows and install all security patches
echo 6. Ensure antivirus is installed, updated, and running
echo 7. Remove any unauthorized or suspicious software
echo 8. Monitor system for unusual processes or network activity
echo 9. Review security event logs for signs of compromise
echo 10. Create system restore point before making changes
echo.

echo ================================================
echo AUDIT COMPLETED
echo ================================================
echo Please review all findings and take appropriate action
echo Save this output for reference: audit_results_%date:~-4,4%%date:~-10,2%%date:~-7,2%.txt
echo.

pause