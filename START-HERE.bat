@echo off
REM CyberPatriot Automation Suite Launcher
REM This batch file launches the PowerShell master control script
REM with Administrator privileges

echo ========================================
echo  CyberPatriot Automation Suite
echo ========================================
echo.
echo This will launch the master control script...
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as Administrator - Good!
    echo.
    echo Starting PowerShell script...
    echo.
    powershell.exe -ExecutionPolicy Bypass -File "%~dp0Run-CyberPatriot.ps1"
) else (
    echo ERROR: This script must be run as Administrator!
    echo.
    echo Please right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

pause
