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
    Write-AuditLog "Analyzing user accounts..." "INFO"
    
    $users = Get-LocalUser
    $currentUser = $env:USERNAME
    
    Write-AuditLog "" "INFO"
    Write-AuditLog "=== USER ACCOUNTS ===" "INFO"
    Write-AuditLog "Total users: $($users.Count)" "INFO"
    Write-AuditLog "Current user: $currentUser" "INFO"
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

Get-UserAccountStatus
Get-GroupMemberships
Get-AdminUsers
Get-PasswordPolicies

Write-AuditLog "========================================" "INFO"
Write-AuditLog "Audit complete! Review the log file:" "INFO"
Write-AuditLog "$LogFile" "INFO"
Write-AuditLog "========================================" "INFO"

# Show interactive GUI
Show-InteractiveUserManager

Write-Host "`nAudit complete. Log saved to: $LogFile"
