# Windows Security Checklist for Cyberpatriot

This checklist covers the essential Windows security hardening steps commonly required in Cyberpatriot competitions.

## 🔐 User Account Security

### User Account Management
- [ ] **Remove unauthorized users** - Check all local users and remove any that shouldn't be there
- [ ] **Disable guest account** - Ensure the guest account is disabled
- [ ] **Set strong password policy** - Minimum 8 characters, complexity requirements
- [ ] **Check user groups** - Ensure users are in appropriate groups only
- [ ] **Remove users from admin groups** - Only necessary users should have admin rights
- [ ] **Enable account lockout policy** - Set lockout threshold (e.g., 5 failed attempts)

### Password Security
- [ ] **Change all default passwords** - Especially for built-in accounts
- [ ] **Set password expiration** - Configure appropriate password age limits
- [ ] **Enable password history** - Prevent reuse of recent passwords
- [ ] **Check for blank passwords** - Ensure no accounts have empty passwords

## 🛡️ System Security

### Windows Updates
- [ ] **Install all critical updates** - Check Windows Update and install all available updates
- [ ] **Enable automatic updates** - Configure to download and install automatically
- [ ] **Check for driver updates** - Ensure all drivers are up to date

### Services Management
- [ ] **Disable unnecessary services** - Review and disable services not needed
- [ ] **Check service permissions** - Ensure services run with minimal privileges
- [ ] **Review startup programs** - Disable unnecessary startup applications

### Firewall Configuration
- [ ] **Enable Windows Firewall** - Turn on firewall for all network profiles
- [ ] **Review firewall rules** - Remove unnecessary inbound/outbound rules
- [ ] **Block suspicious ports** - Close ports not required for operation
- [ ] **Enable firewall logging** - Configure logging for monitoring

## 📁 File System Security

### File Permissions
- [ ] **Review shared folders** - Remove or secure unnecessary shares
- [ ] **Check file permissions** - Ensure sensitive files have proper ACLs
- [ ] **Secure system directories** - Verify permissions on Windows and Program Files
- [ ] **Remove world-writable files** - Find and fix files writable by Everyone

### File Security
- [ ] **Find unauthorized files** - Look for suspicious files (hacking tools, games, etc.)
- [ ] **Check for hidden files** - Review hidden files and folders
- [ ] **Secure backup files** - Protect or remove unnecessary backup files
- [ ] **Check downloads folder** - Remove suspicious downloaded files

## 🔍 Malware Detection

### Antivirus
- [ ] **Install/update antivirus** - Ensure current antivirus with latest definitions
- [ ] **Run full system scan** - Perform comprehensive malware scan
- [ ] **Enable real-time protection** - Turn on continuous monitoring
- [ ] **Schedule regular scans** - Set up automatic scanning

### Manual Checks
- [ ] **Check running processes** - Review Task Manager for suspicious processes
- [ ] **Review installed programs** - Uninstall unauthorized or suspicious software
- [ ] **Check browser extensions** - Remove malicious or unnecessary add-ons
- [ ] **Scan with multiple tools** - Use additional scanners like Malwarebytes

## 🌐 Network Security

### Network Configuration
- [ ] **Disable file sharing** - Turn off unnecessary network sharing
- [ ] **Secure wireless settings** - Use WPA3/WPA2, disable WPS
- [ ] **Review network adapters** - Disable unused network interfaces
- [ ] **Check network discovery** - Turn off if not needed

### Network Services
- [ ] **Disable unnecessary protocols** - Remove protocols like NetBIOS if not needed
- [ ] **Secure remote access** - Disable or properly configure RDP/VNC
- [ ] **Review network shares** - Remove or secure administrative shares
- [ ] **Check open ports** - Use netstat to identify listening services

## ⚙️ Registry and Group Policy

### Registry Security
- [ ] **Backup registry** - Create restore point before making changes
- [ ] **Disable autorun** - Prevent automatic execution from removable media
- [ ] **Secure registry permissions** - Ensure proper access controls
- [ ] **Remove malicious entries** - Check for suspicious registry modifications

### Group Policy Settings
- [ ] **Configure security policies** - Set account policies, audit policies
- [ ] **Enable security auditing** - Turn on logging for security events
- [ ] **Configure user rights** - Assign minimal necessary privileges
- [ ] **Set software restrictions** - Use AppLocker or Software Restriction Policies

## 📊 Auditing and Monitoring

### Event Logging
- [ ] **Enable audit policies** - Turn on auditing for critical events
- [ ] **Review security logs** - Check for signs of compromise
- [ ] **Configure log retention** - Set appropriate log size and retention
- [ ] **Monitor failed logons** - Watch for brute force attempts

### System Monitoring
- [ ] **Check system performance** - Look for signs of malware activity
- [ ] **Review scheduled tasks** - Remove suspicious or unnecessary tasks
- [ ] **Monitor network activity** - Check for unusual network connections
- [ ] **Verify system integrity** - Run sfc /scannow to check system files

## 🔧 Additional Security Measures

### Encryption
- [ ] **Enable BitLocker** - Encrypt system drive if available
- [ ] **Encrypt sensitive data** - Use EFS for important files
- [ ] **Secure USB policies** - Control removable media access

### Backup and Recovery
- [ ] **Create system restore point** - Ensure recovery options are available
- [ ] **Test backup systems** - Verify backup procedures work
- [ ] **Document changes** - Keep record of modifications made

## ✅ Final Verification

- [ ] **Reboot and test** - Restart system and verify it functions properly
- [ ] **Run security scanner** - Perform final security assessment
- [ ] **Document completion** - Record all completed items and any issues
- [ ] **Submit for scoring** - If in competition, submit for automated scoring

---

## 🚨 Emergency Procedures

If you encounter issues:
1. **System won't boot**: Use Safe Mode or recovery options
2. **Services won't start**: Check dependencies and permissions
3. **Network issues**: Verify firewall and network settings
4. **Performance problems**: Check for malware and resource usage

## 📝 Notes Section

Use this space to track specific issues found and solutions applied:

```
[Date/Time] - Issue: Description
              Solution: What was done to fix it
              Result: Outcome

Example:
[10:30 AM] - Issue: Found unauthorized user "hacker123"
             Solution: Deleted user account and checked for created files
             Result: User removed, no malicious files found
```

---
*This checklist should be used systematically. Don't skip steps, and document everything you do!*