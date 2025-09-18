@echo off
REM User Account Audit Script for Cyberpatriot
REM This script checks user accounts for security issues

echo ================================================
echo User Account Security Audit
echo ================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: Not running as Administrator
    echo Some checks may fail or show incomplete information
    echo.
)

echo Starting user account audit...
echo.

echo ================================================
echo CURRENT USER ACCOUNTS:
echo ================================================
net user
echo.

echo ================================================
echo ADMINISTRATOR GROUP MEMBERS:
echo ================================================
net localgroup administrators
echo.

echo ================================================
echo GUEST ACCOUNT STATUS:
echo ================================================
net user guest | findstr "Account active"
echo.

echo ================================================
echo USERS WITH BLANK PASSWORDS:
echo ================================================
echo Checking for users with blank passwords...
for /f "tokens=1" %%i in ('net user ^| findstr /v "command User accounts"') do (
    if not "%%i"=="" (
        net user "%%i" | findstr "Password last set" | findstr "Never" >nul
        if !errorLevel! equ 0 (
            echo WARNING: User %%i may have a blank password
        )
    )
)
echo Check complete.
echo.

echo ================================================
echo PASSWORD POLICY INFORMATION:
echo ================================================
net accounts
echo.

echo ================================================
echo CURRENTLY LOGGED ON USERS:
echo ================================================
query user 2>nul
if %errorLevel% neq 0 (
    echo No users currently logged on via Terminal Services
)
echo.

echo ================================================
echo LAST LOGON INFORMATION:
echo ================================================
wmic netloginprofile get name,lastlogon 2>nul
echo.

echo ================================================
echo RECOMMENDATIONS:
echo ================================================
echo 1. Remove any unauthorized user accounts
echo 2. Ensure only necessary users are in Administrator group
echo 3. Disable or delete the Guest account if enabled
echo 4. Set strong passwords for all accounts
echo 5. Enable account lockout policy
echo 6. Configure password complexity requirements
echo.

echo ================================================
echo MANUAL CHECKS NEEDED:
echo ================================================
echo 1. Open Computer Management (compmgmt.msc)
echo 2. Go to Local Users and Groups -^> Users
echo 3. Check each user account properties
echo 4. Verify group memberships
echo 5. Check password policies in secpol.msc
echo.

pause