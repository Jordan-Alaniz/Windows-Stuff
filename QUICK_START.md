# Quick Start Guide - CyberPatriot Automation

## ⚠️ CRITICAL: Read This First!

**FORENSICS QUESTIONS WARNING:**
- Some files are needed for forensics questions and give you points!
- FileAuditor.ps1 only REPORTS files - it does NOT delete them
- Competition README files are automatically excluded
- ALWAYS manually review before deleting ANY file
- Complete forensics questions BEFORE using FileAuditor!

## Step-by-Step Competition Workflow

### 1️⃣ FIRST - Before Running Anything
- [ ] **READ THE COMPETITION README** - This is critical! It tells you requirements.
- [ ] **Write down your password on another device** - You'll need it!
- [ ] Take note of any specific competition requirements
- [ ] Identify which files/folders contain forensics questions

### 2️⃣ Answer Forensic Questions (DO THIS BEFORE FILE AUDITOR!)
- [ ] Look for forensic questions in the competition materials
- [ ] **CRITICAL:** Some files may look like unauthorized media but are needed for forensics!
- [ ] Common forensics tasks:
  - Create a new group
  - Find file hashes (use PowerShell: `Get-FileHash <filepath>`)
  - Decode base64/hexadecimal
  - Find hidden files/text in images (steganography)
  - Dehash passwords
  - Find specific text in files
- [ ] **Complete ALL forensics questions before scanning for files to delete**
- [ ] **NOTE:** After answering forensics, you may still need to DELETE those files for security points!
  - Example: An image used for hash question may still be unauthorized media
  - Answer the question FIRST, then delete the file AFTER

### 3️⃣ Run Malware Hunter (CRITICAL - Malware was a BIG problem last season!)
```powershell
# Open PowerShell as Administrator
cd path\to\Windows-Stuff
.\MalwareHunter.ps1
```
This will:
- Update malware definitions
- Scan for malicious processes
- Find suspicious files in temp folders
- Check startup items and scheduled tasks
- Check HOSTS file for malware entries
- Offer to run full system scan

**After reviewing results, delete confirmed malware!**

### 4️⃣ Run the Security Automation Script

**Option A: Run with Master Control (Easiest)**
```powershell
.\Run-CyberPatriot.ps1
```
Or double-click: **START-HERE.bat**

**Option B: Run Security Hardening Directly**
```powershell
.\CyberPatriot-Auto.ps1
```
Then use the graphical interface to select and run security tasks.

### 5️⃣ Run File and User Auditors

**Find unauthorized files:**
```powershell
.\FileAuditor.ps1
```
- Reviews files but does NOT delete them
- Manually review and delete files AFTER forensics are complete

**Review user accounts:**
```powershell
.\UserAuditor.ps1
```
- Shows all accounts, groups, and permissions
- Helps identify unauthorized users

### 6️⃣ Manual Security Tasks

After running the automation, complete these manual tasks:

#### User Management
- [ ] Review all user accounts (Run > lusrmgr.msc)
- [ ] Delete unauthorized users
- [ ] Verify admin privileges are correct
- [ ] Ensure all users have strong passwords (Control Panel > User Accounts)

#### Software Management
- [ ] Open Programs and Features (Win+R > appwiz.cpl)
- [ ] Remove unauthorized software:
  - [ ] BitTorrent/uTorrent
  - [ ] Wireshark
  - [ ] CCleaner
  - [ ] Any games or non-work software
- [ ] Check both under current user AND Public user folders

#### File Management
- [ ] Show hidden files (Explorer > View > Hidden Items)
- [ ] Delete unauthorized media:
  - [ ] Music files
  - [ ] Game files
  - [ ] Movies
- [ ] Check: C:\Users\[Username]\, Public folders, Desktop, Downloads

#### Group Management
- [ ] Open Local Users and Groups (Win+R > lusrmgr.msc > Groups)
- [ ] Review group memberships
- [ ] Add/remove users per competition requirements

#### Shared Folders
- [ ] Check shared folders (Win+R > fsmgmt.msc)
- [ ] Only these should exist: ADMIN$, C$, IPC$
- [ ] Remove any others (except those specified in README)

#### Browser Security
- [ ] Firefox: Disable cookies if required
  - Settings > Privacy & Security > Cookies
- [ ] Update all browsers:
  - Firefox: Menu > Help > About Firefox
  - Chrome: Menu > Help > About Google Chrome
  - Edge: Menu > Help > About Microsoft Edge

#### Final Checks
- [ ] Verify Task Manager startup items (Ctrl+Shift+Esc > Startup tab)
- [ ] Disable unnecessary startup programs
- [ ] Check Task Scheduler for suspicious tasks
- [ ] Review Event Viewer for security issues

### 5️⃣ System Updates
- [ ] Run Windows Update (Settings > Update & Security)
- [ ] Install all available updates
- [ ] Restart if required

### 6️⃣ Final Verification
- [ ] Review the automation log file
- [ ] Test system functionality
- [ ] Verify all competition requirements are met
- [ ] Score should increase if done correctly!

## 🔍 Quick Reference Commands

| Task | Command |
|------|---------|
| Services | `Win+R` > `services.msc` |
| Local Users & Groups | `Win+R` > `lusrmgr.msc` |
| Programs & Features | `Win+R` > `appwiz.cpl` |
| Task Manager | `Ctrl+Shift+Esc` |
| Group Policy | `Win+R` > `gpedit.msc` |
| Security Policy | `Win+R` > `secpol.msc` |
| Firewall | `Win+R` > `wf.msc` |
| Shared Folders | `Win+R` > `fsmgmt.msc` |
| Computer Management | `Win+R` > `compmgmt.msc` |
| File Explorer | `Win+R` > `.` |

## ⚠️ Common Mistakes to Avoid

1. **DON'T** change your own password and forget it
2. **DON'T** disable your own admin account
3. **DON'T** remove required software
4. **DON'T** delete users that should exist (check README)
5. **DON'T** forget to read the competition README first
6. **DON'T** skip forensic questions
7. **DON'T** run updates first (do them last)

## 💡 Pro Tips

- Use the checklist in `checklist/windows-checklist.md` for reference
- Check answer keys in the `checklist/` folder for common patterns
- Log files help you track what the script did
- Test on a practice VM before competition day
- Keep the checklist open while working
- Work methodically - don't rush
- Verify each change actually worked

## 📞 Getting Help

If the automation script fails:
1. Check the log file for error messages
2. Try running individual tasks manually
3. Refer to the detailed checklist
4. Some tasks may need to be done manually on certain Windows versions

Good luck! 🎯
