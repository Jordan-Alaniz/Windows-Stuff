# Windows Cyberpatriot Quick Reference Card

## 🚨 EMERGENCY COMMANDS (Run as Administrator)

### User Management
```cmd
net user                              # List all users
net user username /delete             # Delete user
net user guest /active:no             # Disable guest
net localgroup administrators         # Show admin users
```

### Service Control
```cmd
sc query | findstr telnet            # Check Telnet service
sc stop tlntsvr && sc config tlntsvr start= disabled
net stop "service name"              # Stop service
```

### Firewall
```cmd
netsh advfirewall set allprofiles state on    # Enable firewall
netsh advfirewall show allprofiles            # Check status
```

### Quick Security Fixes
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
```

## 🔍 QUICK AUDIT COMMANDS

### Check for Issues
```cmd
net share                            # List shares
netstat -an | findstr LISTENING      # Open ports
tasklist | findstr /i hack           # Suspicious processes
wmic product get name | findstr game # Installed games
```

### System Info
```cmd
systeminfo | findstr "OS Name"       # Windows version
whoami /groups                       # Current user groups
net accounts                         # Password policy
```

## 📋 PRIORITY CHECKLIST

### Critical (Do First)
- [ ] Delete unauthorized users
- [ ] Disable guest account  
- [ ] Change weak passwords
- [ ] Enable firewall
- [ ] Disable Telnet service

### Important (Do Next)
- [ ] Remove admin rights from regular users
- [ ] Set password policy (8+ chars, complexity)
- [ ] Disable autorun
- [ ] Remove unauthorized software
- [ ] Check shared folders

### Final Steps
- [ ] Run Windows Update
- [ ] Full antivirus scan
- [ ] Check startup programs
- [ ] Review firewall rules
- [ ] Test and restart

## 💾 BACKUP FIRST!
```cmd
# Create restore point before changes
rstrui.exe
```

---
*Print this card for quick reference during competitions!*