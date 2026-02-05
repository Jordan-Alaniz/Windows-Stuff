# CyberPatriot Automated Security Hardening Tool

This repository contains an automated PowerShell script for CyberPatriot competitions that performs common security hardening tasks on Windows systems.

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server
- PowerShell 5.1 or higher
- Administrator privileges

### Running the Automation Suite

**EASIEST METHOD - Use the Master Control Script:**

1. **Download or clone this repository**

2. **Open PowerShell as Administrator**
   - Right-click on PowerShell and select "Run as Administrator"

3. **Navigate to the repository directory**
   ```powershell
   cd path\to\Windows-Stuff
   ```

4. **Run the master control script**
   ```powershell
   .\Run-CyberPatriot.ps1
   ```

5. **Follow the interactive menu**
   - Choose Quick Audit for a fast security overview
   - Run Security Hardening to apply automated fixes
   - Run File Auditor to find unauthorized files
   - Run User Auditor to review accounts
   - Or select "R" to run all tasks in sequence!

**ALTERNATIVE - Run individual scripts:**
   ```powershell
   .\CyberPatriot-Auto.ps1    # Main security hardening with GUI
   .\FileAuditor.ps1           # Find unauthorized files/software
   .\UserAuditor.ps1           # Review user accounts
   ```

## 📋 Features

The automated script can perform the following security tasks:

### 🔐 Security Hardening
- **Enable Windows Firewall** - Turns on firewall for all network profiles
- **Disable Guest Account** - Disables the built-in Guest account
- **Disable Administrator Account** - Disables the built-in Administrator account (not your current user)
- **Configure Password Policies** - Sets secure password requirements:
  - Minimum password length: 10 characters
  - Password complexity: Enabled
  - Password history: 24 passwords
  - Maximum password age: 90 days
  - Minimum password age: 1 day
  - Account lockout threshold: 10 attempts
  - Account lockout duration: 30 minutes

### 🛡️ Service Management
- **Disable Insecure Services** - Stops and disables:
  - Remote Desktop (RDP)
  - FTP Service
  - Remote Registry
  - SSDP Discovery
  - UPnP Device Host
  - WWW Publishing Service
  - SMTP Service

### 🔒 Network Security
- **Block Vulnerable Ports** - Creates firewall rules to block:
  - RDP (3389)
  - SSH (22)
  - Telnet (23)
  - SNMP (161, 162)
  - LDAP (389)
  - FTP (20, 21)

### 🔍 Auditing & Monitoring
- **Configure Audit Policies** - Enables logging for:
  - Account Logon events
  - Account Management
  - Logon/Logoff events
  - Policy Changes
  - System events

### 🛠️ Additional Features
- **Enable Automatic Updates** - Configures Windows to automatically update
- **Enable Windows Security** - Activates Windows Defender real-time protection
- **Run Quick Scan** - Starts a Windows Defender malware scan
- **Enable Secure Logon** - Requires Ctrl+Alt+Del before login
- **Hide Last Username** - Prevents displaying the last logged-in username

## 📊 Logging

All actions are logged to a timestamped log file:
- Log files are created in the same directory as the script
- Format: `CyberPatrior-AutoLog-YYYYMMDD-HHMMSS.txt`
- Click "View Log" button in the GUI to open the log file
- Logs include timestamps, action types, and detailed results

## 📁 Repository Structure

```
Windows-Stuff/
├── Run-CyberPatriot.ps1      # ⭐ MASTER CONTROL SCRIPT - Start here!
├── CyberPatriot-Auto.ps1     # Main automation script with GUI
├── FileAuditor.ps1            # Scans for unauthorized files and software
├── UserAuditor.ps1            # Reviews user accounts and permissions
├── README.md                  # This file
├── QUICK_START.md             # Quick reference guide
├── checklist/                 # Reference materials
│   ├── windows-checklist.md   # Manual checklist
│   └── *.pdf                  # Answer keys and guides
└── scripts/                   # Additional utility scripts
```

## 🎮 Master Control Script (Run-CyberPatriot.ps1)

The **Run-CyberPatriot.ps1** script is your main entry point. It provides:
- Interactive menu for easy navigation
- Quick audit to assess current security state
- Orchestrated execution of all tools in the recommended order
- Easy access to logs, checklists, and documentation

Simply run: `.\Run-CyberPatriot.ps1` and follow the menu!

## 🔧 Individual Scripts

### CyberPatriot-Auto.ps1 (Main Automation)
The core security hardening script with GUI interface:
```powershell
.\CyberPatriot-Auto.ps1
```
Features all automated security fixes (firewall, passwords, services, etc.)

### FileAuditor.ps1
Scans for unauthorized files and software that should be removed:
```powershell
.\FileAuditor.ps1
```
- Detects unauthorized software (BitTorrent, Wireshark, CCleaner, etc.)
- Finds media files (music, videos, games)
- Lists suspicious running processes
- Reviews startup items
- Generates detailed audit log

### UserAuditor.ps1
Reviews user accounts, groups, and permissions:
```powershell
.\UserAuditor.ps1
```
- Lists all user accounts with status
- Shows group memberships
- Identifies users with admin privileges
- Reviews password policies
- Opens interactive GUI for user management
- Generates detailed audit log

## ⚠️ Important Notes

### What This Script Does NOT Do
- **Does NOT change your current user's password** - You must manage passwords manually
- **Does NOT delete unauthorized software automatically** - It will detect but requires manual removal
- **Does NOT modify registry beyond security settings** - Only makes documented security changes
- **Does NOT answer forensic questions** - These require manual analysis

### Manual Tasks Still Required

Based on the checklist, you should still manually:

1. **Read the competition README file thoroughly**
2. **Write down your password on another computer** - Critical!
3. **Answer forensic questions** - Cannot be automated
4. **Review user accounts** - Verify which users should exist
5. **Review installed software** - Decide what should be removed
6. **Check for media files** - Delete unauthorized music, games, etc.
7. **Review browser settings** - Configure Firefox/Chrome security
8. **Update browsers** - Firefox, Chrome, Edge
9. **Review shared folders** - Check for unauthorized shares
10. **Run final system updates** - After all other changes

## 🎯 Best Practice Workflow

1. **Before the Competition**
   - Familiarize yourself with the script
   - Read through the checklist folder materials
   - Practice on a test system

2. **During the Competition**
   - Read the README file first (always!)
   - Write down your password
   - Answer forensic questions
   - **Run the automation script:** `.\CyberPatriot-Auto.ps1`
   - **Run the file auditor:** `.\FileAuditor.ps1` (to find files to delete)
   - **Run the user auditor:** `.\UserAuditor.ps1` (to review accounts)
   - Delete unauthorized files and software based on audit results
   - Perform remaining manual tasks from the checklist
   - Review and verify all changes
   - Run system updates last

3. **After Running the Script**
   - Review the log file for any failures
   - Fix any issues that couldn't be automated
   - Verify security settings are applied
   - Test system functionality

## 📚 Additional Resources

- **Checklist Folder**: Contains detailed manual checklists and answer keys from previous competitions
- **Scripts Folder**: Contains additional utility scripts for specific tasks

## 🔧 Troubleshooting

**Script won't run:**
- Ensure you're running PowerShell as Administrator
- Check PowerShell execution policy: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`

**GUI doesn't appear:**
- Verify .NET Framework is installed
- Check if Windows Forms assemblies are available

**Tasks fail:**
- Review the log file for specific error messages
- Some features may not be available on all Windows versions
- Ensure the system has internet connectivity for updates

## 📝 License

This is a tool for educational purposes for CyberPatriot competitions.

## 🤝 Contributing

Feel free to submit issues or pull requests to improve the automation script.

---

**Remember**: This tool is meant to assist, not replace, your security knowledge. Always understand what each task does before running it!
