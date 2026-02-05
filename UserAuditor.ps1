#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CyberPatriot - User Account Auditor
.DESCRIPTION
    Reviews and reports on user accounts, groups, and permissions.
    Helps identify unauthorized users and incorrect group memberships.
.NOTES
    Run as Administrator
#>

Add-Type -AssemblyName System.Windows.Forms

$LogFile = "UserAudit-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

function Write-AuditLog {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    Write-Host $logMessage
}

function Get-UserAccountStatus {
    param(
        [array]$AuthorizedUsers = @(),
        [array]$AuthorizedAdmins = @()
    )
    
    Write-AuditLog "Analyzing user accounts..." "INFO"
    
    $users = Get-LocalUser
    $currentUser = $env:USERNAME
    
    Write-AuditLog "" "INFO"
    Write-AuditLog "=== USER ACCOUNTS ===" "INFO"
    Write-AuditLog "Total users: $($users.Count)" "INFO"
    Write-AuditLog "Current user: $currentUser" "INFO"
    if ($AuthorizedUsers.Count -gt 0) {
        Write-AuditLog "Authorized users from README: $($AuthorizedUsers.Count)" "INFO"
    }
    Write-AuditLog "" "INFO"
    
    foreach ($user in $users) {
        $status = if ($user.Enabled) { "ENABLED" } else { "DISABLED" }
        $passwordSet = if ($user.PasswordLastSet) { $user.PasswordLastSet } else { "NEVER" }
        $lastLogon = if ($user.LastLogon) { $user.LastLogon } else { "NEVER" }
        
        Write-AuditLog "User: $($user.Name)" "INFO"
        Write-AuditLog "  Status: $status" "INFO"
        Write-AuditLog "  Full Name: $($user.FullName)" "INFO"
        Write-AuditLog "  Description: $($user.Description)" "INFO"
        Write-AuditLog "  Password Last Set: $passwordSet" "INFO"
        Write-AuditLog "  Last Logon: $lastLogon" "INFO"
        Write-AuditLog "  Password Expires: $($user.PasswordExpires)" "INFO"
        Write-AuditLog "  Password Required: $($user.PasswordRequired)" "INFO"
        
        # Check against authorized user list
        if ($AuthorizedUsers.Count -gt 0) {
            $isAuthorized = $false
            foreach ($authUser in $AuthorizedUsers) {
                if ($user.Name -eq $authUser -or $user.Name -like $authUser) {
                    $isAuthorized = $true
                    break
                }
            }
            
            # Also check if it's the current user or a built-in system account
            if ($user.Name -eq $currentUser -or 
                $user.Name -eq "Administrator" -or 
                $user.Name -eq "Guest" -or 
                $user.Name -eq "DefaultAccount" -or
                $user.Name -like "IUSR*" -or
                $user.Name -like "ASPNET*") {
                $isAuthorized = $true
            }
            
            if (-not $isAuthorized -and $user.Enabled) {
                Write-AuditLog "  ⚠️  UNAUTHORIZED: User not in README authorized list!" "WARNING"
            } elseif ($isAuthorized) {
                Write-AuditLog "  ✓ Authorized per README" "SUCCESS"
            }
        }
        
        # Check if this is a built-in account
        if ($user.Name -eq "Administrator" -or $user.Name -eq "Guest" -or $user.Name -eq "DefaultAccount") {
            if ($user.Enabled) {
                Write-AuditLog "  WARNING: Built-in account '$($user.Name)' is enabled!" "WARNING"
            }
        }
        
        # Check if user has never logged in
        if (-not $user.LastLogon -and $user.Enabled) {
            Write-AuditLog "  WARNING: User has never logged in but is enabled!" "WARNING"
        }
        
        # Check password age
        if ($user.PasswordLastSet) {
            $passwordAge = (Get-Date) - $user.PasswordLastSet
            if ($passwordAge.TotalDays -gt 90) {
                Write-AuditLog "  WARNING: Password is $([int]$passwordAge.TotalDays) days old!" "WARNING"
            }
        }
        
        Write-AuditLog "" "INFO"
    }
    
    return $users
}

function Get-GroupMemberships {
    Write-AuditLog "=== GROUP MEMBERSHIPS ===" "INFO"
    
    $groups = Get-LocalGroup
    
    foreach ($group in $groups) {
        Write-AuditLog "Group: $($group.Name)" "INFO"
        Write-AuditLog "  Description: $($group.Description)" "INFO"
        
        try {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
            if ($members) {
                Write-AuditLog "  Members:" "INFO"
                foreach ($member in $members) {
                    Write-AuditLog "    - $($member.Name) ($($member.PrincipalSource))" "INFO"
                    
                    # Warn about unusual admin group members
                    if ($group.Name -eq "Administrators" -and $member.Name -notlike "*Administrator*" -and $member.Name -ne "$env:COMPUTERNAME\$env:USERNAME") {
                        Write-AuditLog "      WARNING: Verify this user should be an administrator!" "WARNING"
                    }
                    
                    # Warn about Guest in any group
                    if ($member.Name -like "*Guest*") {
                        Write-AuditLog "      WARNING: Guest account is in this group!" "WARNING"
                    }
                }
            } else {
                Write-AuditLog "  Members: (none)" "INFO"
            }
        } catch {
            Write-AuditLog "  Could not enumerate members: $_" "WARNING"
        }
        
        Write-AuditLog "" "INFO"
    }
}

function Get-AdminUsers {
    Write-AuditLog "=== ADMINISTRATOR ACCESS ===" "INFO"
    
    try {
        $admins = Get-LocalGroupMember -Group "Administrators"
        Write-AuditLog "Users with Administrator privileges:" "INFO"
        foreach ($admin in $admins) {
            Write-AuditLog "  - $($admin.Name) ($($admin.ObjectClass))" "INFO"
        }
        Write-AuditLog "" "INFO"
        return $admins
    } catch {
        Write-AuditLog "Could not enumerate administrators: $_" "ERROR"
        return $null
    }
}

function Verify-AdminAccess {
    <#
    .SYNOPSIS
        Verifies that the right users have admin access
    .DESCRIPTION
        Compares actual administrators against authorized administrators from README
        Identifies users who shouldn't have admin access and users who should
    #>
    param(
        [array]$AuthorizedAdmins = @()
    )
    
    Write-AuditLog "=== ADMIN ACCESS VERIFICATION ===" "INFO"
    
    if ($AuthorizedAdmins.Count -eq 0) {
        Write-AuditLog "No authorized admin list from README - skipping verification" "WARNING"
        Write-AuditLog "Run AnalyzeReadme.ps1 first to get authorized admin list" "INFO"
        Write-AuditLog "" "INFO"
        return
    }
    
    Write-AuditLog "Authorized administrators from README: $($AuthorizedAdmins.Count)" "INFO"
    foreach ($authAdmin in $AuthorizedAdmins) {
        Write-AuditLog "  - $authAdmin" "INFO"
    }
    Write-AuditLog "" "INFO"
    
    try {
        # Get current administrators
        $currentAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        
        # Extract just the usernames (remove domain/computer prefix)
        $currentAdminNames = @()
        foreach ($admin in $currentAdmins) {
            $name = $admin.Name
            # Remove computer/domain prefix
            if ($name -match '\\(.+)$') {
                $name = $matches[1]
            }
            $currentAdminNames += $name
        }
        
        # Check for unauthorized admins
        $unauthorizedAdmins = @()
        foreach ($currentAdmin in $currentAdminNames) {
            $isAuthorized = $false
            
            # Skip built-in system accounts
            if ($currentAdmin -eq "Administrator" -or 
                $currentAdmin -like "IUSR*" -or 
                $currentAdmin -like "ASPNET*" -or
                $currentAdmin -eq $env:USERNAME) {
                $isAuthorized = $true
            } else {
                # Check against authorized list
                foreach ($authAdmin in $AuthorizedAdmins) {
                    if ($currentAdmin -eq $authAdmin -or $currentAdmin -like $authAdmin) {
                        $isAuthorized = $true
                        break
                    }
                }
            }
            
            if (-not $isAuthorized) {
                $unauthorizedAdmins += $currentAdmin
            }
        }
        
        # Check for missing admins (should be admin but aren't)
        $missingAdmins = @()
        foreach ($authAdmin in $AuthorizedAdmins) {
            $isCurrentAdmin = $false
            foreach ($currentAdmin in $currentAdminNames) {
                if ($currentAdmin -eq $authAdmin -or $currentAdmin -like $authAdmin) {
                    $isCurrentAdmin = $true
                    break
                }
            }
            
            if (-not $isCurrentAdmin) {
                $missingAdmins += $authAdmin
            }
        }
        
        # Report findings
        Write-AuditLog "=== ADMIN VERIFICATION RESULTS ===" "INFO"
        
        if ($unauthorizedAdmins.Count -gt 0) {
            Write-AuditLog "⚠️  UNAUTHORIZED ADMINISTRATORS FOUND: $($unauthorizedAdmins.Count)" "WARNING"
            foreach ($unadmin in $unauthorizedAdmins) {
                Write-AuditLog "  ❌ $unadmin - Should NOT have admin access!" "WARNING"
            }
        } else {
            Write-AuditLog "✓ No unauthorized administrators found" "SUCCESS"
        }
        Write-AuditLog "" "INFO"
        
        if ($missingAdmins.Count -gt 0) {
            Write-AuditLog "⚠️  MISSING ADMINISTRATORS: $($missingAdmins.Count)" "WARNING"
            foreach ($missAdmin in $missingAdmins) {
                Write-AuditLog "  ❌ $missAdmin - Should have admin access but doesn't!" "WARNING"
            }
        } else {
            Write-AuditLog "✓ All authorized users have admin access" "SUCCESS"
        }
        Write-AuditLog "" "INFO"
        
        return [PSCustomObject]@{
            UnauthorizedAdmins = $unauthorizedAdmins
            MissingAdmins = $missingAdmins
        }
        
    } catch {
        Write-AuditLog "Error verifying admin access: $_" "ERROR"
        return $null
    }
}

function Test-PasswordStrength {
    <#
    .SYNOPSIS
        Checks if users have strong password configurations
    .DESCRIPTION
        Evaluates password age, complexity requirements, and policy compliance
        Cannot test actual password strength (Windows security) but checks configuration
    #>
    
    Write-AuditLog "=== PASSWORD STRENGTH ANALYSIS ===" "INFO"
    
    # Get all local users
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    
    Write-AuditLog "Analyzing password configuration for $($users.Count) enabled users..." "INFO"
    Write-AuditLog "" "INFO"
    
    $weakPasswordUsers = @()
    $expiredPasswordUsers = @()
    $noPasswordRequiredUsers = @()
    $neverExpiresUsers = @()
    
    foreach ($user in $users) {
        $issues = @()
        
        # Check if password is required
        if (-not $user.PasswordRequired) {
            Write-AuditLog "❌ $($user.Name): Password NOT required!" "WARNING"
            $noPasswordRequiredUsers += $user.Name
            $issues += "No password required"
        }
        
        # Check if password never expires
        if ($user.PasswordNeverExpires) {
            Write-AuditLog "⚠️  $($user.Name): Password set to NEVER expire" "WARNING"
            $neverExpiresUsers += $user.Name
            $issues += "Password never expires"
        }
        
        # Check password age
        if ($user.PasswordLastSet) {
            $passwordAge = (Get-Date) - $user.PasswordLastSet
            
            if ($passwordAge.TotalDays -gt 90) {
                Write-AuditLog "⚠️  $($user.Name): Password is $([int]$passwordAge.TotalDays) days old (>90 days)" "WARNING"
                $weakPasswordUsers += $user.Name
                $issues += "Old password ($([int]$passwordAge.TotalDays) days)"
            } elseif ($passwordAge.TotalDays -gt 60) {
                Write-AuditLog "⚠️  $($user.Name): Password is $([int]$passwordAge.TotalDays) days old (approaching 90 day limit)" "WARNING"
                $issues += "Aging password ($([int]$passwordAge.TotalDays) days)"
            }
        } else {
            Write-AuditLog "❌ $($user.Name): Password has NEVER been set!" "WARNING"
            $weakPasswordUsers += $user.Name
            $issues += "Password never set"
        }
        
        # Check if password is expired
        if ($user.PasswordExpired) {
            Write-AuditLog "❌ $($user.Name): Password is EXPIRED!" "WARNING"
            $expiredPasswordUsers += $user.Name
            $issues += "Password expired"
        }
        
        # Check user flags for weak password indicators
        if ($user.UserMayChangePassword -eq $false -and $user.Name -ne "Administrator" -and $user.Name -ne "Guest") {
            Write-AuditLog "⚠️  $($user.Name): User cannot change their own password" "WARNING"
            $issues += "Cannot change password"
        }
        
        if ($issues.Count -eq 0) {
            Write-AuditLog "✓ $($user.Name): Password configuration OK" "SUCCESS"
        }
        
        Write-AuditLog "" "INFO"
    }
    
    # Summary
    Write-AuditLog "=== PASSWORD STRENGTH SUMMARY ===" "INFO"
    
    if ($noPasswordRequiredUsers.Count -gt 0) {
        Write-AuditLog "❌ Users with NO PASSWORD REQUIRED: $($noPasswordRequiredUsers.Count)" "WARNING"
        foreach ($user in $noPasswordRequiredUsers) {
            Write-AuditLog "    $user" "WARNING"
        }
    } else {
        Write-AuditLog "✓ All users require passwords" "SUCCESS"
    }
    Write-AuditLog "" "INFO"
    
    if ($expiredPasswordUsers.Count -gt 0) {
        Write-AuditLog "❌ Users with EXPIRED passwords: $($expiredPasswordUsers.Count)" "WARNING"
        foreach ($user in $expiredPasswordUsers) {
            Write-AuditLog "    $user" "WARNING"
        }
    } else {
        Write-AuditLog "✓ No expired passwords" "SUCCESS"
    }
    Write-AuditLog "" "INFO"
    
    if ($neverExpiresUsers.Count -gt 0) {
        Write-AuditLog "⚠️  Users with passwords that NEVER EXPIRE: $($neverExpiresUsers.Count)" "WARNING"
        foreach ($user in $neverExpiresUsers) {
            Write-AuditLog "    $user" "WARNING"
        }
    }
    Write-AuditLog "" "INFO"
    
    if ($weakPasswordUsers.Count -gt 0) {
        Write-AuditLog "⚠️  Users with OLD/WEAK password configurations: $($weakPasswordUsers.Count)" "WARNING"
        foreach ($user in $weakPasswordUsers) {
            Write-AuditLog "    $user" "WARNING"
        }
    }
    Write-AuditLog "" "INFO"
    
    Write-AuditLog "RECOMMENDATIONS:" "INFO"
    Write-AuditLog "  1. Ensure all users have password complexity enabled" "INFO"
    Write-AuditLog "  2. Set minimum password length to 10+ characters" "INFO"
    Write-AuditLog "  3. Force password changes for passwords >90 days old" "INFO"
    Write-AuditLog "  4. Enable password expiration (except service accounts)" "INFO"
    Write-AuditLog "  5. Check Group Policy password settings" "INFO"
    Write-AuditLog "" "INFO"
    
    return [PSCustomObject]@{
        NoPasswordRequired = $noPasswordRequiredUsers
        ExpiredPasswords = $expiredPasswordUsers
        NeverExpires = $neverExpiresUsers
        WeakOrOld = $weakPasswordUsers
    }
}

function Get-PasswordPolicies {
    Write-AuditLog "=== PASSWORD POLICIES ===" "INFO"
    
    try {
        # Export current security policy
        secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
        $secpol = Get-Content "$env:TEMP\secpol.cfg"
        Remove-Item "$env:TEMP\secpol.cfg" -Force
        
        # Parse relevant settings
        $settings = @{
            "MinimumPasswordAge" = "Not configured"
            "MaximumPasswordAge" = "Not configured"
            "MinimumPasswordLength" = "Not configured"
            "PasswordComplexity" = "Not configured"
            "PasswordHistorySize" = "Not configured"
            "LockoutBadCount" = "Not configured"
            "LockoutDuration" = "Not configured"
            "ResetLockoutCount" = "Not configured"
        }
        
        foreach ($line in $secpol) {
            foreach ($setting in $settings.Keys) {
                if ($line -match "^$setting\s*=\s*(.+)") {
                    $settings[$setting] = $matches[1].Trim()
                }
            }
        }
        
        Write-AuditLog "Current Password Policy Settings:" "INFO"
        foreach ($setting in $settings.GetEnumerator() | Sort-Object Name) {
            Write-AuditLog "  $($setting.Key): $($setting.Value)" "INFO"
            
            # Check against recommended values
            switch ($setting.Key) {
                "MinimumPasswordLength" {
                    if ([int]$setting.Value -lt 10) {
                        Write-AuditLog "    WARNING: Should be at least 10" "WARNING"
                    }
                }
                "PasswordComplexity" {
                    if ($setting.Value -ne "1") {
                        Write-AuditLog "    WARNING: Should be enabled (1)" "WARNING"
                    }
                }
                "MinimumPasswordAge" {
                    if ([int]$setting.Value -lt 1) {
                        Write-AuditLog "    WARNING: Should be at least 1" "WARNING"
                    }
                }
                "MaximumPasswordAge" {
                    if ([int]$setting.Value -gt 90 -or [int]$setting.Value -eq 0) {
                        Write-AuditLog "    WARNING: Should be 90 or less (not 0)" "WARNING"
                    }
                }
                "LockoutBadCount" {
                    if ([int]$setting.Value -eq 0 -or [int]$setting.Value -gt 10) {
                        Write-AuditLog "    WARNING: Should be between 1-10" "WARNING"
                    }
                }
            }
        }
        Write-AuditLog "" "INFO"
    } catch {
        Write-AuditLog "Could not retrieve password policies: $_" "ERROR"
    }
}

function Show-InteractiveUserManager {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "User Account Manager"
    $form.Size = New-Object System.Drawing.Size(700, 600)
    $form.StartPosition = "CenterScreen"
    
    # Title
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Location = New-Object System.Drawing.Point(10, 10)
    $titleLabel.Size = New-Object System.Drawing.Size(660, 30)
    $titleLabel.Text = "User Account Review"
    $titleLabel.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $titleLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($titleLabel)
    
    # User list
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10, 50)
    $listBox.Size = New-Object System.Drawing.Size(660, 400)
    $listBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    
    # Populate user list
    $users = Get-LocalUser
    foreach ($user in $users) {
        $status = if ($user.Enabled) { "ENABLED " } else { "DISABLED" }
        $passwordAge = if ($user.PasswordLastSet) { 
            [int]((Get-Date) - $user.PasswordLastSet).TotalDays 
        } else { 
            "N/A" 
        }
        $item = "$($user.Name.PadRight(20)) | $status | PwdAge: $($passwordAge.ToString().PadLeft(4)) days"
        $listBox.Items.Add($item) | Out-Null
    }
    
    $form.Controls.Add($listBox)
    
    # Instructions
    $instrLabel = New-Object System.Windows.Forms.Label
    $instrLabel.Location = New-Object System.Drawing.Point(10, 460)
    $instrLabel.Size = New-Object System.Drawing.Size(660, 40)
    $instrLabel.Text = "Review the user accounts above. Use Computer Management (compmgmt.msc)`nor Local Users and Groups (lusrmgr.msc) to make changes."
    $form.Controls.Add($instrLabel)
    
    # Buttons
    $openLusrBtn = New-Object System.Windows.Forms.Button
    $openLusrBtn.Location = New-Object System.Drawing.Point(10, 510)
    $openLusrBtn.Size = New-Object System.Drawing.Size(200, 30)
    $openLusrBtn.Text = "Open User Manager"
    $openLusrBtn.Add_Click({
        Start-Process "lusrmgr.msc"
    })
    $form.Controls.Add($openLusrBtn)
    
    $openLogBtn = New-Object System.Windows.Forms.Button
    $openLogBtn.Location = New-Object System.Drawing.Point(220, 510)
    $openLogBtn.Size = New-Object System.Drawing.Size(200, 30)
    $openLogBtn.Text = "View Audit Log"
    $openLogBtn.Add_Click({
        if (Test-Path $LogFile) {
            Start-Process notepad.exe -ArgumentList $LogFile
        }
    })
    $form.Controls.Add($openLogBtn)
    
    $closeBtn = New-Object System.Windows.Forms.Button
    $closeBtn.Location = New-Object System.Drawing.Point(430, 510)
    $closeBtn.Size = New-Object System.Drawing.Size(100, 30)
    $closeBtn.Text = "Close"
    $closeBtn.Add_Click({ $form.Close() })
    $form.Controls.Add($closeBtn)
    
    $form.ShowDialog() | Out-Null
}

# Main Execution
Write-AuditLog "========================================" "INFO"
Write-AuditLog "CyberPatriot User Account Auditor" "INFO"
Write-AuditLog "========================================" "INFO"

# Try to load README data if available
$readmeData = $null
$authorizedUsers = @()
$authorizedAdmins = @()

if (Test-Path "$PSScriptRoot\ReadmeData.json") {
    try {
        $readmeData = Get-Content "$PSScriptRoot\ReadmeData.json" -Raw | ConvertFrom-Json
        Write-AuditLog "✓ Loaded README data - will check against authorized users" "SUCCESS"
        
        if ($readmeData.AuthorizedUsers) {
            $authorizedUsers = $readmeData.AuthorizedUsers
            Write-AuditLog "  Found $($authorizedUsers.Count) authorized users in README" "INFO"
        }
        
        if ($readmeData.Administrators) {
            $authorizedAdmins = $readmeData.Administrators
            Write-AuditLog "  Found $($authorizedAdmins.Count) authorized administrators in README" "INFO"
        }
    } catch {
        Write-AuditLog "Could not load README data: $_" "WARNING"
        Write-AuditLog "Run AnalyzeReadme.ps1 first to parse competition requirements" "INFO"
    }
} else {
    Write-AuditLog "No README data found - run AnalyzeReadme.ps1 first for better accuracy" "WARNING"
}

Write-AuditLog "" "INFO"

Get-UserAccountStatus -AuthorizedUsers $authorizedUsers -AuthorizedAdmins $authorizedAdmins
Get-GroupMemberships
Get-AdminUsers

# NEW: Verify admin access against README requirements
Verify-AdminAccess -AuthorizedAdmins $authorizedAdmins

# NEW: Check password strength
Test-PasswordStrength

Get-PasswordPolicies

Write-AuditLog "========================================" "INFO"
Write-AuditLog "Audit complete! Review the log file:" "INFO"
Write-AuditLog "$LogFile" "INFO"
Write-AuditLog "========================================" "INFO"

# Show interactive GUI
Show-InteractiveUserManager

Write-Host "`nAudit complete. Log saved to: $LogFile"
