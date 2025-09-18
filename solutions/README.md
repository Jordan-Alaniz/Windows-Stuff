# Windows Security Solutions Guide

This guide provides detailed step-by-step solutions for common Windows security issues found in Cyberpatriot competitions.

## 📚 Table of Contents

- [User Account Management](#user-account-management)
- [Password Policies](#password-policies)
- [Windows Services](#windows-services)
- [Firewall Configuration](#firewall-configuration)
- [File Permissions](#file-permissions)
- [Malware Removal](#malware-removal)
- [Windows Updates](#windows-updates)
- [Network Security](#network-security)
- [Registry Security](#registry-security)
- [Group Policy](#group-policy)

---

## User Account Management

### Remove Unauthorized Users

**Problem**: Unauthorized user accounts exist on the system

**Solution**:
1. Open **Computer Management** (`compmgmt.msc`)
2. Navigate to **Local Users and Groups** → **Users**
3. Review all user accounts
4. Right-click unauthorized users → **Delete**
5. Alternative: Use Command Prompt as Administrator:
   ```cmd
   net user username /delete
   ```

### Disable Guest Account

**Problem**: Guest account is enabled

**Solution**:
1. Open **Computer Management** (`compmgmt.msc`)
2. Navigate to **Local Users and Groups** → **Users**
3. Right-click **Guest** → **Properties**
4. Check **Account is disabled**
5. Alternative via Command Prompt:
   ```cmd
   net user guest /active:no
   ```

### Remove Users from Administrator Groups

**Problem**: Regular users have administrator privileges

**Solution**:
1. Open **Computer Management** (`compmgmt.msc`)
2. Navigate to **Local Users and Groups** → **Groups**
3. Double-click **Administrators**
4. Select unauthorized users and click **Remove**
5. Verify users are in appropriate groups (Users, Power Users, etc.)

---

## Password Policies

### Set Strong Password Policy

**Problem**: Weak password requirements

**Solution**:
1. Open **Local Security Policy** (`secpol.msc`)
2. Navigate to **Account Policies** → **Password Policy**
3. Configure these settings:
   - **Minimum password length**: 8 characters
   - **Password must meet complexity requirements**: Enabled
   - **Maximum password age**: 90 days
   - **Minimum password age**: 1 day
   - **Enforce password history**: 5 passwords

### Enable Account Lockout Policy

**Problem**: No protection against brute force attacks

**Solution**:
1. Open **Local Security Policy** (`secpol.msc`)
2. Navigate to **Account Policies** → **Account Lockout Policy**
3. Configure:
   - **Account lockout threshold**: 5 invalid attempts
   - **Account lockout duration**: 30 minutes
   - **Reset account lockout counter**: 30 minutes

### Change Default Passwords

**Problem**: Accounts have default or weak passwords

**Solution**:
1. For each user account:
   ```cmd
   net user username newpassword
   ```
2. Or use **Computer Management**:
   - Right-click user → **Set Password**
   - Enter strong password following policy

---

## Windows Services

### Disable Unnecessary Services

**Problem**: Unnecessary services are running, creating security risks

**Solution**:
1. Open **Services** (`services.msc`)
2. Review services and disable these commonly unnecessary ones:
   - **Telnet**: Stop and disable
   - **Simple TCP/IP Services**: Stop and disable
   - **Print Spooler** (if no printing needed): Stop and disable
   - **Remote Registry**: Stop and disable
   - **Routing and Remote Access**: Stop and disable (unless needed)

3. For each service:
   - Right-click → **Properties**
   - Set **Startup type** to **Disabled**
   - Click **Stop** if currently running

### Check Startup Programs

**Problem**: Unnecessary programs start with Windows

**Solution**:
1. Open **Task Manager** (`Ctrl+Shift+Esc`)
2. Click **Startup** tab
3. Disable unnecessary programs:
   - Right-click → **Disable**
4. Alternative: Use **System Configuration** (`msconfig`)
   - **Startup** tab → Uncheck unnecessary items

---

## Firewall Configuration

### Enable Windows Firewall

**Problem**: Windows Firewall is disabled

**Solution**:
1. Open **Windows Defender Firewall** from Control Panel
2. Click **Turn Windows Defender Firewall on or off**
3. Enable firewall for all network types:
   - **Domain networks**
   - **Private networks**
   - **Public networks**
4. Alternative via Command Prompt:
   ```cmd
   netsh advfirewall set allprofiles state on
   ```

### Configure Firewall Rules

**Problem**: Unnecessary firewall rules allow unwanted traffic

**Solution**:
1. Open **Windows Defender Firewall with Advanced Security**
2. Review **Inbound Rules** and **Outbound Rules**
3. Delete unnecessary rules:
   - Right-click rule → **Delete**
4. Create new rules if needed:
   - **Action** → **New Rule**
   - Follow wizard to configure

---

## File Permissions

### Secure Shared Folders

**Problem**: Unnecessary or insecure file shares

**Solution**:
1. Open **Computer Management** (`compmgmt.msc`)
2. Navigate to **Shared Folders** → **Shares**
3. Review all shares and remove unnecessary ones:
   - Right-click → **Stop Sharing**
4. For necessary shares, check permissions:
   - Right-click → **Properties** → **Security** tab
   - Remove **Everyone** if present
   - Add specific users/groups with minimal permissions

### Check File Permissions on Sensitive Directories

**Problem**: System directories have incorrect permissions

**Solution**:
1. Navigate to sensitive directories (C:\Windows, C:\Program Files)
2. Right-click → **Properties** → **Security** tab
3. Ensure **Users** group only has **Read & Execute** permissions
4. Remove **Full Control** for non-admin users
5. Use **icacls** command for bulk changes:
   ```cmd
   icacls "C:\sensitive\folder" /grant Users:RX
   icacls "C:\sensitive\folder" /remove Users:F
   ```

---

## Malware Removal

### Run Antivirus Scan

**Problem**: System may be infected with malware

**Solution**:
1. **Update antivirus definitions**:
   - Open your antivirus software
   - Check for updates
2. **Run full system scan**:
   - Select full/complete scan option
   - Scan all drives and files
3. **Use Windows Defender** (if no third-party AV):
   ```cmd
   "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2
   ```

### Remove Suspicious Programs

**Problem**: Unauthorized software installed

**Solution**:
1. Open **Programs and Features** (`appwiz.cpl`)
2. Look for suspicious programs:
   - Games (unless authorized)
   - Hacking tools
   - P2P software
   - Unknown applications
3. Select and click **Uninstall**
4. Check these common locations:
   - `C:\Program Files`
   - `C:\Program Files (x86)`
   - `%APPDATA%`

### Check Running Processes

**Problem**: Malicious processes running

**Solution**:
1. Open **Task Manager** (`Ctrl+Shift+Esc`)
2. **Processes** tab → Look for suspicious processes
3. Research unknown processes online
4. End suspicious processes:
   - Right-click → **End Process Tree**
5. Use **Process Explorer** for detailed analysis if available

---

## Windows Updates

### Install All Updates

**Problem**: System missing critical security updates

**Solution**:
1. Open **Windows Update** from Settings
2. Click **Check for updates**
3. Install all available updates
4. Restart when prompted
5. Repeat until no more updates available
6. Command line method:
   ```cmd
   UsoClient StartScan
   UsoClient StartDownload
   UsoClient StartInstall
   ```

### Enable Automatic Updates

**Problem**: Automatic updates disabled

**Solution**:
1. Open **Windows Update** settings
2. Click **Advanced options**
3. Configure:
   - **Receive updates for other Microsoft products**: On
   - **Download updates over metered connections**: On (if desired)
4. Alternative via Group Policy:
   - `gpedit.msc` → **Computer Configuration** → **Administrative Templates** → **Windows Components** → **Windows Update**
   - Configure **Automatic Updates**: Enabled

---

## Network Security

### Disable Unnecessary Network Services

**Problem**: Unnecessary network protocols enabled

**Solution**:
1. **Disable NetBIOS over TCP/IP**:
   - Network adapter properties → **Internet Protocol Version 4 (TCP/IPv4)** → **Properties** → **Advanced** → **WINS** tab
   - Select **Disable NetBIOS over TCP/IP**

2. **Disable File and Printer Sharing** (if not needed):
   - Network adapter properties
   - Uncheck **File and Printer Sharing for Microsoft Networks**

### Secure Remote Desktop

**Problem**: RDP enabled with default settings

**Solution**:
1. **Disable RDP** (if not needed):
   - System Properties → **Remote** tab
   - Uncheck **Enable Remote Desktop on this computer**

2. **Secure RDP** (if needed):
   - Change default port 3389
   - Enable Network Level Authentication
   - Configure firewall rules for specific IPs only

---

## Registry Security

### Disable Autorun

**Problem**: Autorun enabled for removable media

**Solution**:
1. Open **Registry Editor** (`regedit`)
2. Navigate to: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
3. Create DWORD: `NoDriveTypeAutoRun`
4. Set value to `255` (disables autorun for all drives)
5. Alternative via Group Policy:
   - `gpedit.msc` → **Computer Configuration** → **Administrative Templates** → **Windows Components** → **AutoPlay Policies**
   - **Turn off Autoplay**: Enabled

### Remove Suspicious Registry Entries

**Problem**: Malicious registry modifications

**Solution**:
1. Check common malware locations:
   - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
2. Remove suspicious entries:
   - Right-click → **Delete**
3. **Always backup registry first**:
   ```cmd
   reg export HKLM backup.reg
   ```

---

## Group Policy

### Configure Security Policies

**Problem**: Insecure local security policies

**Solution**:
1. Open **Local Security Policy** (`secpol.msc`)
2. **Security Settings** → **Local Policies** → **Security Options**
3. Key settings to configure:
   - **Accounts: Guest account status**: Disabled
   - **Interactive logon: Do not display last user name**: Enabled
   - **Microsoft network client: Digitally sign communications**: Enabled
   - **Network access: Do not allow anonymous enumeration**: Enabled
   - **Network security: Do not store LAN Manager hash**: Enabled

### Enable Audit Policies

**Problem**: No auditing of security events

**Solution**:
1. **Local Security Policy** → **Local Policies** → **Audit Policy**
2. Enable auditing for:
   - **Audit account logon events**: Success, Failure
   - **Audit logon events**: Success, Failure
   - **Audit object access**: Failure
   - **Audit policy change**: Success, Failure
   - **Audit privilege use**: Failure
   - **Audit system events**: Success, Failure

---

## Quick Reference Commands

### Useful Command Prompt Commands

```cmd
# System Information
systeminfo
whoami /all
net user
net localgroup administrators

# Network Information
ipconfig /all
netstat -an
arp -a

# Service Management
sc query
sc stop servicename
sc config servicename start= disabled

# File Operations
dir /a:h
attrib -h -s filename
takeown /f filename
icacls filename /grant username:permissions

# Process Management
tasklist
taskkill /f /pid processid
wmic process list full

# System Integrity
sfc /scannow
dism /online /cleanup-image /restorehealth
chkdsk c: /f /r
```

---

## Troubleshooting

### Common Issues and Solutions

**Issue**: Can't access Local Security Policy
**Solution**: Use `gpedit.msc` or run as administrator

**Issue**: Service won't stop
**Solution**: Check dependencies, use `taskkill /f` for processes

**Issue**: Changes not taking effect
**Solution**: Restart the service or reboot the system

**Issue**: Access denied errors
**Solution**: Run Command Prompt as Administrator, check file ownership

**Issue**: Registry changes cause problems
**Solution**: Restore from backup or use System Restore

---

*Remember: Always create backups before making changes, and test in a safe environment first!*