# 🎯 CyberPatriot Quick Reference Card

## 🚀 Getting Started (Choose ONE)

**Easiest:** Double-click `START-HERE.bat`

**PowerShell:** `.\Run-CyberPatriot.ps1` (interactive menu)

## 📋 Competition Checklist (Follow in Order!)

```
☐ 1. READ COMPETITION README (FIRST!)
☐ 2. WRITE DOWN PASSWORD (on another device)
☐ 3. ANSWER FORENSICS QUESTIONS (before file scans!)
     - File hashes, steganography, decoding, etc.
☐ 4. RUN: .\MalwareHunter.ps1 (CRITICAL - malware was huge last season!)
☐ 5. RUN: .\CyberPatriot-Auto.ps1 (security hardening)
☐ 6. RUN: .\UserAuditor.ps1 (review accounts)
☐ 7. RUN: .\FileAuditor.ps1 (find files to delete)
☐ 8. MANUALLY DELETE unauthorized files/software
     (Forensics files can be deleted AFTER answering questions!)
☐ 9. Manual cleanup (see below)
☐ 10. Windows Update (do this LAST)
```

## 🛠️ Script Quick Reference

| Script | Purpose | Runtime | Auto-Delete? |
|--------|---------|---------|--------------|
| `MalwareHunter.ps1` | Find malware | 5-10 min | ❌ Reports only |
| `CyberPatriot-Auto.ps1` | Security config | 2-5 min | ❌ Config only |
| `UserAuditor.ps1` | Review accounts | 1-2 min | ❌ Reports only |
| `FileAuditor.ps1` | Find bad files | 3-5 min | ❌ Reports only |

## ⚡ Critical Commands

### Open Tools Quickly (Win+R)
```
lusrmgr.msc        → Users and Groups
services.msc       → Services
appwiz.cpl         → Programs & Features
firewall.cpl       → Firewall
gpedit.msc         → Group Policy
secpol.msc         → Security Policy
compmgmt.msc       → Computer Management
taskschd.msc       → Task Scheduler
mrt                → Malware Removal Tool
```

### Find File Hash (Forensics)
```powershell
Get-FileHash C:\Path\To\File.jpg
Get-FileHash C:\Path\To\File.jpg -Algorithm MD5
```

## 🚨 CRITICAL WARNINGS

### ⚠️ FORENSICS FILES
- Some files look like media but are needed for forensics questions!
- Scripts auto-exclude files with "CyberPatriot", "Forensic", "README" in name
- **Answer ALL forensics questions BEFORE scanning for files**
- After answering, those files may still need to be deleted for points!

### ⚠️ WHAT SCRIPTS DON'T DO
- ❌ Change your password
- ❌ Auto-delete files
- ❌ Answer forensics
- ❌ Make decisions for you

## 🔍 Manual Tasks (After Scripts)

### Users
- **Check admin access** (UserAuditor.ps1 does this automatically!)
  - Verify only authorized users have admin rights
  - Remove unauthorized admins
  - Add missing authorized admins
- **Check password strength** (UserAuditor.ps1 does this automatically!)
  - Force password changes for old passwords (>90 days)
  - Enable password expiration
  - Require passwords for all accounts
  - Set password complexity requirements
- Delete unauthorized users
- Remove users from Administrators group if not authorized
- Ensure all users have strong passwords set

### Software
- Remove via Programs & Features (appwiz.cpl)
  - BitTorrent, Wireshark, CCleaner, games

### Files
- Delete media: Music, Videos, Games
- Check Desktop, Downloads, Public folders
- **But ONLY after forensics are answered!**

### Browsers
- Update: Firefox, Chrome, Edge
- Disable cookies (if required)
- Check extensions

### Services (services.msc)
- Disable: RDP, FTP, Remote Registry, Telnet

### Firewall
- Already done by script
- Verify it's on

### Shared Folders (fsmgmt.msc)
- Only keep: ADMIN$, C$, IPC$

## 🦠 Malware Priority

**Malware was a BIG problem last season!**

1. Update definitions (script does this)
2. Run MalwareHunter.ps1
3. Check: Processes, Files, Startup, Tasks
4. Start FULL scan in background
5. Manually remove confirmed malware

## 📊 Log Files

All scripts create timestamped logs:
- `CyberPatriot-AutoLog-*.txt`
- `MalwareHunt-*.txt`
- `FileAudit-*.txt`
- `UserAudit-*.txt`

View logs: Click "View Log" in GUIs or use notepad

## ⏱️ Time Management

| Phase | Time | Priority |
|-------|------|----------|
| Read README | 2 min | 🔴 CRITICAL |
| Forensics | 10-15 min | 🔴 CRITICAL |
| Malware scan | 15-20 min | 🔴 CRITICAL |
| Scripts | 10-15 min | 🟡 HIGH |
| Manual cleanup | 20-30 min | 🟡 HIGH |
| Updates | 10 min | 🟢 MEDIUM |

**Total: ~90 minutes**

## 💡 Pro Tips

1. ✅ Start malware FULL scan early (runs in background)
2. ✅ Check log files if something fails
3. ✅ Verify changes actually applied
4. ✅ Screenshot important findings
5. ✅ Work methodically, don't rush
6. ✅ Test system still works after changes
7. ✅ Save forensics answers before deleting files!

## 🆘 If Something Goes Wrong

1. Check the log files for errors
2. Scripts don't delete anything - safe to re-run
3. Manual checklist: `checklist/windows-checklist.md`
4. Scripts assist you - they don't replace knowledge

## 🎯 Points Priority

**High Point Tasks:**
1. 🦠 Remove malware (HUGE points!)
2. 🔐 Fix password policies
3. 🚫 Disable insecure services
4. 🧑 Remove unauthorized users
5. 📁 Delete unauthorized files
6. 🔥 Enable firewall
7. 🔄 Enable updates

**Medium Point Tasks:**
- Remove unauthorized software
- Configure auditing
- Fix group memberships
- Secure browser settings

---

**Remember: Scripts HELP you, they don't REPLACE you!**
**Always understand what you're doing!**

**Good luck! 🍀**
