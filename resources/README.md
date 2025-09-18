# Resources and References

This directory contains additional resources, references, and useful materials for Windows security hardening in Cyberpatriot competitions.

## 📚 Quick Reference Guides

### Common Windows Commands

#### User Management
```cmd
# List all users
net user

# Create user
net user username password /add

# Delete user
net user username /delete

# Add user to group
net localgroup groupname username /add

# Remove user from group
net localgroup groupname username /delete

# Disable user
net user username /active:no

# Check user details
net user username
```

#### Service Management
```cmd
# List all services
sc query

# Stop service
sc stop servicename
net stop servicename

# Start service
sc start servicename
net start servicename

# Disable service
sc config servicename start= disabled

# Enable service
sc config servicename start= auto

# Check service status
sc query servicename
```

#### Network Commands
```cmd
# Show network configuration
ipconfig /all

# Show network connections
netstat -an

# Show routing table
route print

# Show ARP table
arp -a

# Flush DNS
ipconfig /flushdns

# Test connectivity
ping hostname
telnet hostname port
```

#### File and Permission Commands
```cmd
# Show file attributes
attrib filename

# Remove hidden/system attributes
attrib -h -s filename

# Take ownership
takeown /f filename

# Show permissions
icacls filename

# Grant permissions
icacls filename /grant username:permissions

# Remove permissions
icacls filename /remove username
```

### PowerShell Commands

#### Security and User Management
```powershell
# Get local users
Get-LocalUser

# Disable user
Disable-LocalUser -Name "username"

# Get group members
Get-LocalGroupMember -Group "Administrators"

# Check UAC status
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

# Get password policy
Get-ADDefaultDomainPasswordPolicy
```

#### System Information
```powershell
# System information
Get-ComputerInfo

# Installed programs
Get-WmiObject -Class Win32_Product

# Running processes
Get-Process

# Services
Get-Service

# Event logs
Get-EventLog -LogName Security -Newest 10
```

## 🔧 Registry Locations

### Important Security Registry Keys

#### User Account Control
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
- EnableLUA (DWORD): 1 = Enabled, 0 = Disabled
```

#### Autorun Prevention
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
- NoDriveTypeAutoRun (DWORD): 255 = Disable all autorun
```

#### Anonymous Access
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
- restrictanonymous (DWORD): 1 = Restrict anonymous access
```

#### Password Policy
```
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
- RequireStrongKey (DWORD): 1 = Require strong keys
```

#### Startup Programs
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

## 🚨 Common Security Issues

### High Priority Issues

#### Unauthorized Users
- Check for accounts like "hacker", "admin", "test"
- Verify all users are authorized
- Remove accounts with suspicious names

#### Weak Passwords
- Default passwords (admin/admin, password, etc.)
- Blank passwords
- Simple passwords (123456, password, etc.)

#### Unnecessary Services
- Telnet (port 23)
- FTP (port 21)
- SSH (port 22) - if not needed
- VNC/Remote Desktop (port 3389) - if not needed
- SNMP (port 161)

#### File Shares
- Administrative shares (C$, ADMIN$)
- Unnecessary user shares
- Shares with Everyone permissions

#### Malware Indicators
- Unknown processes
- High CPU/memory usage
- Unusual network connections
- Suspicious files in temp directories

## 📋 Security Checklists

### Pre-Competition Checklist
- [ ] Backup system
- [ ] Create restore point
- [ ] Document current configuration
- [ ] Prepare tools and scripts
- [ ] Review competition rules

### During Competition Checklist
- [ ] Read all documentation carefully
- [ ] Follow systematic approach
- [ ] Document all changes made
- [ ] Test changes before submission
- [ ] Monitor time remaining

### Post-Configuration Checklist
- [ ] Verify all changes work
- [ ] Test system functionality
- [ ] Check scoring feedback
- [ ] Document lessons learned

## 🛠️ Useful Tools

### Built-in Windows Tools
- **Computer Management** (`compmgmt.msc`)
- **Local Security Policy** (`secpol.msc`)
- **Group Policy Editor** (`gpedit.msc`)
- **Services** (`services.msc`)
- **Event Viewer** (`eventvwr.msc`)
- **Registry Editor** (`regedit`)
- **System Configuration** (`msconfig`)
- **Task Manager** (`taskmgr`)

### Third-party Tools (if allowed)
- **Process Explorer** - Advanced process monitoring
- **Autoruns** - Startup program management
- **Malwarebytes** - Malware detection
- **CCleaner** - System cleanup
- **TreeSize** - Disk space analysis

## 📖 Learning Resources

### Official Documentation
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [Windows Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [CIS Controls](https://www.cisecurity.org/controls/)

### Cyberpatriot Resources
- [Cyberpatriot Official Website](https://www.uscyberpatriot.org/)
- [CyberAces Practice](https://cyberaces.org/)
- [SANS Security Training](https://www.sans.org/)

### Practice Platforms
- Online virtual machines
- Local VM setups
- Previous competition images

## 🎯 Competition Tips

### Time Management
- Start with quick wins (user management, basic services)
- Use automation scripts for repetitive tasks
- Save complex configurations for last
- Monitor scoring throughout

### Documentation
- Keep notes of all changes
- Screenshot important configurations
- Document any issues encountered
- Note time taken for each task

### Testing
- Test changes immediately
- Verify functionality after each change
- Use system restore if needed
- Check scoring frequently

### Common Mistakes to Avoid
- Not reading instructions carefully
- Making changes without testing
- Forgetting to restart services
- Not checking dependencies
- Rushing through without verification

## 📞 Emergency Procedures

### If System Won't Boot
1. Boot into Safe Mode
2. Use System Restore
3. Check recent changes
4. Revert problematic configurations

### If Services Won't Start
1. Check service dependencies
2. Verify permissions
3. Check for conflicting settings
4. Review event logs

### If Network Issues Occur
1. Check firewall settings
2. Verify network adapter configuration
3. Test with minimal configuration
4. Check for conflicting rules

---

*Keep this reference handy during competitions for quick lookup of commands and procedures!*