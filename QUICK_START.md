# Quick Start Guide - CyberPatriot Automation

## Step-by-Step Competition Workflow

### 1️⃣ FIRST - Before Running Anything
- [ ] **READ THE COMPETITION README** - This is critical!
- [ ] **Write down your password on another device** - You'll need it!
- [ ] Take note of any specific competition requirements

### 2️⃣ Answer Forensic Questions
- [ ] Look for forensic questions in the competition materials
- [ ] Common tasks:
  - Create a new group
  - Find file hashes (use PowerShell: `Get-FileHash`)
  - Decode base64/hexadecimal
  - Find hidden files/text in images
  - Dehash passwords

### 3️⃣ Run the Automation Script

**Option A: Run with GUI (Recommended)**
```powershell
# Open PowerShell as Administrator
cd path\to\Windows-Stuff
.\CyberPatriot-Auto.ps1
```
Then use the graphical interface to select and run tasks.

**Option B: Run All Tasks (Advanced)**
If you want to run all tasks without the GUI, you can modify the script or run individual functions.

### 4️⃣ Manual Security Tasks

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
