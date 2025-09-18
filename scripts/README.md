# Automation Scripts

This directory contains automation scripts to help speed up Windows security hardening for Cyberpatriot competitions.

## 📁 Available Scripts

### Batch Scripts (Windows Command Prompt)

#### `security-hardening.bat`
**Purpose**: Basic Windows security hardening  
**Features**:
- Disables Guest account
- Enables Windows Firewall
- Disables unnecessary services (Telnet, Simple TCP/IP, Remote Registry)
- Disables autorun for all drives
- Configures basic security settings
- Creates system restore point

**Usage**:
```cmd
# Run as Administrator
security-hardening.bat
```

#### `user-audit.bat`
**Purpose**: Audits user accounts for security issues  
**Features**:
- Lists all user accounts
- Shows Administrator group members
- Checks Guest account status
- Identifies users with blank passwords
- Shows password policy settings
- Displays logon information

**Usage**:
```cmd
# Can run with standard privileges, but some features require admin
user-audit.bat
```

#### `system-audit.bat`
**Purpose**: Comprehensive system security audit  
**Features**:
- Checks Windows version and patches
- Reviews firewall status
- Identifies risky services
- Shows network connections
- Lists shared folders
- Checks startup programs
- Scans for suspicious processes
- Verifies system integrity
- Checks Windows Update status
- Reviews antivirus status

**Usage**:
```cmd
# Run as Administrator for full functionality
system-audit.bat
```

### PowerShell Scripts

#### `advanced-security-config.ps1`
**Purpose**: Advanced Windows security configuration  
**Features**:
- Comprehensive UAC configuration
- Advanced password policy setup
- Firewall configuration
- Service management
- Audit policy configuration
- Network security hardening
- Windows Update configuration
- System restore point creation

**Usage**:
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\advanced-security-config.ps1
```

## 🚀 Quick Start Guide

### For Beginners
1. Start with `system-audit.bat` to understand current system state
2. Run `user-audit.bat` to check user accounts
3. Execute `security-hardening.bat` for basic hardening
4. Manually verify changes and complete remaining checklist items

### For Advanced Users
1. Run `system-audit.bat` for initial assessment
2. Execute `advanced-security-config.ps1` for comprehensive hardening
3. Use individual scripts as needed for specific tasks
4. Customize scripts for your specific environment

## ⚠️ Important Notes

### Before Running Scripts
- **Always run as Administrator** when indicated
- **Create a system restore point** before making changes
- **Test in a safe environment** before using in competition
- **Read script contents** to understand what changes will be made

### Script Limitations
- Scripts provide baseline security configurations
- Manual review and additional hardening may be required
- Some settings may need adjustment based on specific requirements
- Not all security issues can be automated

### PowerShell Execution Policy
If you get execution policy errors with PowerShell scripts:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 🔧 Customization

### Modifying Scripts
Scripts are designed to be readable and modifiable. Key areas for customization:

- **Service list**: Add/remove services in the disable list
- **Registry settings**: Modify security-related registry entries
- **Password policies**: Adjust complexity requirements
- **Audit settings**: Configure different audit levels

### Adding New Scripts
When creating new scripts, follow these guidelines:
- Include clear comments explaining each action
- Check for Administrator privileges when required
- Provide error handling and status reporting
- Create restore points before making significant changes

## 🛠️ Troubleshooting

### Common Issues

**Script won't run**: Check execution policy and administrator privileges  
**Services fail to disable**: Check service dependencies  
**Registry changes fail**: Verify administrator rights and registry path  
**PowerShell errors**: Check PowerShell version and execution policy  

### Recovery
If scripts cause issues:
1. Use System Restore to revert changes
2. Boot into Safe Mode if necessary
3. Manually reverse changes using the solutions guide
4. Restore from backup if available

## 📋 Script Checklist

When using automation scripts:
- [ ] Backup system/create restore point
- [ ] Run audit scripts first to understand current state
- [ ] Execute hardening scripts as Administrator
- [ ] Verify changes took effect
- [ ] Test system functionality
- [ ] Complete manual tasks not covered by scripts
- [ ] Document what was done

## 🤝 Contributing

To add new scripts or improve existing ones:
1. Follow consistent naming conventions
2. Include comprehensive error handling
3. Add clear documentation and comments
4. Test thoroughly before submission
5. Update this README with new script information

---

*Remember: Automation scripts are tools to speed up common tasks, but manual review and verification are still essential for comprehensive security!*