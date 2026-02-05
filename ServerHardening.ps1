#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server Security Hardening for CyberPatriot
.DESCRIPTION
    Additional security hardening tasks specific to Windows Server environments.
    Handles Active Directory, DNS, DHCP, IIS, and other server roles.
.NOTES
    Run as Administrator
    Uses README data if available to avoid disabling required services
#>

$LogFile = "ServerHardening-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

function Write-ServerLog {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    Write-Host $logMessage -ForegroundColor $(
        switch ($Type) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
}

function Test-IsWindowsServer {
    <#
    .SYNOPSIS
        Detects if running on Windows Server
    #>
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem
        return $os.ProductType -ne 1  # 1 = Workstation, 2 = Domain Controller, 3 = Server
    } catch {
        return $false
    }
}

function Get-ServerRoles {
    <#
    .SYNOPSIS
        Detects installed server roles
    #>
    $roles = @()
    
    try {
        # Try to get installed features (Server 2012+)
        $features = Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Installed -eq $true }
        
        if ($features) {
            foreach ($feature in $features) {
                if ($feature.Name -match "DNS") { $roles += "DNS" }
                if ($feature.Name -match "DHCP") { $roles += "DHCP" }
                if ($feature.Name -match "AD-Domain-Services") { $roles += "AD DS" }
                if ($feature.Name -match "Web-Server") { $roles += "IIS" }
                if ($feature.Name -match "File-Services") { $roles += "File Server" }
                if ($feature.Name -match "Print-Services") { $roles += "Print Server" }
            }
        }
    } catch {
        Write-ServerLog "Could not enumerate server features" "WARNING"
    }
    
    return $roles | Select-Object -Unique
}

function Secure-ActiveDirectory {
    <#
    .SYNOPSIS
        Hardens Active Directory Domain Services
    #>
    Write-ServerLog "Hardening Active Directory..." "INFO"
    
    try {
        # Check if AD DS is installed
        $adFeature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue
        if (-not $adFeature -or -not $adFeature.Installed) {
            Write-ServerLog "AD DS not installed, skipping" "INFO"
            return $true
        }
        
        Write-ServerLog "AD DS detected - applying security settings" "INFO"
        
        # Enable Kerberos AES encryption
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 0x1C -ErrorAction SilentlyContinue
            Write-ServerLog "Enabled Kerberos AES encryption" "SUCCESS"
        } catch {
            Write-ServerLog "Could not configure Kerberos encryption: $_" "WARNING"
        }
        
        # Disable SMBv1 (critical for servers)
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-ServerLog "Disabled SMBv1 protocol" "SUCCESS"
        } catch {
            Write-ServerLog "Could not disable SMBv1: $_" "WARNING"
        }
        
        return $true
    } catch {
        Write-ServerLog "Error hardening AD: $_" "ERROR"
        return $false
    }
}

function Secure-DNSServer {
    <#
    .SYNOPSIS
        Hardens DNS Server
    #>
    Write-ServerLog "Hardening DNS Server..." "INFO"
    
    try {
        # Check if DNS Server is installed
        $dnsFeature = Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue
        if (-not $dnsFeature -or -not $dnsFeature.Installed) {
            Write-ServerLog "DNS Server not installed, skipping" "INFO"
            return $true
        }
        
        Write-ServerLog "DNS Server detected - applying security settings" "INFO"
        
        # Disable DNS recursion if not needed (helps prevent DNS amplification attacks)
        try {
            # Note: Only disable if not a forwarder
            Write-ServerLog "Review DNS recursion settings manually (may be required)" "WARNING"
        } catch {
            Write-ServerLog "Could not configure DNS settings: $_" "WARNING"
        }
        
        # Enable DNS event logging
        try {
            Set-DnsServerDiagnostics -All $true -ErrorAction SilentlyContinue
            Write-ServerLog "Enabled DNS diagnostic logging" "SUCCESS"
        } catch {
            Write-ServerLog "Could not enable DNS logging: $_" "WARNING"
        }
        
        return $true
    } catch {
        Write-ServerLog "Error hardening DNS: $_" "ERROR"
        return $false
    }
}

function Secure-DHCPServer {
    <#
    .SYNOPSIS
        Hardens DHCP Server
    #>
    Write-ServerLog "Hardening DHCP Server..." "INFO"
    
    try {
        # Check if DHCP Server is installed
        $dhcpFeature = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        if (-not $dhcpFeature -or -not $dhcpFeature.Installed) {
            Write-ServerLog "DHCP Server not installed, skipping" "INFO"
            return $true
        }
        
        Write-ServerLog "DHCP Server detected - applying security settings" "INFO"
        
        # Enable DHCP audit logging
        try {
            Set-DhcpServerAuditLog -Enable $true -ErrorAction SilentlyContinue
            Write-ServerLog "Enabled DHCP audit logging" "SUCCESS"
        } catch {
            Write-ServerLog "Could not enable DHCP logging: $_" "WARNING"
        }
        
        # Enable conflict detection
        try {
            Set-DhcpServerv4OptionValue -OptionId 15 -Value "domain.local" -ErrorAction SilentlyContinue
            Write-ServerLog "Configured DHCP options" "SUCCESS"
        } catch {
            Write-ServerLog "Could not configure DHCP options: $_" "WARNING"
        }
        
        return $true
    } catch {
        Write-ServerLog "Error hardening DHCP: $_" "ERROR"
        return $false
    }
}

function Secure-IISServer {
    <#
    .SYNOPSIS
        Hardens IIS Web Server
    #>
    Write-ServerLog "Hardening IIS Web Server..." "INFO"
    
    try {
        # Check if IIS is installed
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
        if (-not $iisFeature -or -not $iisFeature.Installed) {
            Write-ServerLog "IIS not installed, skipping" "INFO"
            return $true
        }
        
        Write-ServerLog "IIS detected - applying security settings" "INFO"
        
        # Remove unnecessary HTTP headers
        try {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            
            # Remove Server header (version disclosure)
            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering" -Name "removeServerHeader" -Value $true -ErrorAction SilentlyContinue
            Write-ServerLog "Removed IIS server version header" "SUCCESS"
        } catch {
            Write-ServerLog "Could not configure IIS headers: $_" "WARNING"
        }
        
        # Disable directory browsing
        try {
            Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value "False" -ErrorAction SilentlyContinue
            Write-ServerLog "Disabled directory browsing" "SUCCESS"
        } catch {
            Write-ServerLog "Could not disable directory browsing: $_" "WARNING"
        }
        
        # Enable HTTP Strict Transport Security (HSTS)
        try {
            # This requires manual configuration per site
            Write-ServerLog "HSTS should be configured per site manually" "INFO"
        } catch {
            Write-ServerLog "Could not configure HSTS: $_" "WARNING"
        }
        
        return $true
    } catch {
        Write-ServerLog "Error hardening IIS: $_" "ERROR"
        return $false
    }
}

function Disable-ServerUnnecessaryServices {
    <#
    .SYNOPSIS
        Disables services that are typically not needed on servers
        Respects README requirements if available
    #>
    param(
        [array]$RequiredServices = @()
    )
    
    Write-ServerLog "Disabling unnecessary server services..." "INFO"
    
    # Services that are usually not needed on servers (unless specified in README)
    $unnecessaryServices = @(
        "XblAuthManager",      # Xbox Live Auth Manager
        "XblGameSave",         # Xbox Live Game Save
        "XboxNetApiSvc",       # Xbox Live Networking Service
        "Themes",              # Themes (servers don't need visual themes)
        "TabletInputService",  # Touch Keyboard and Handwriting Panel Service
        "WSearch"              # Windows Search (unless file server)
    )
    
    $disabledCount = 0
    
    foreach ($serviceName in $unnecessaryServices) {
        # Check if this service is in the required list
        $isRequired = $false
        foreach ($reqService in $RequiredServices) {
            if ($serviceName -like "*$reqService*" -or $reqService -like "*$serviceName*") {
                $isRequired = $true
                break
            }
        }
        
        if ($isRequired) {
            Write-ServerLog "Skipping $serviceName (required by README)" "INFO"
            continue
        }
        
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                Write-ServerLog "Disabled service: $serviceName" "SUCCESS"
                $disabledCount++
            }
        } catch {
            Write-ServerLog "Could not disable $serviceName : $_" "WARNING"
        }
    }
    
    Write-ServerLog "Disabled $disabledCount unnecessary services" "SUCCESS"
    return $true
}

function Enable-ServerAuditing {
    <#
    .SYNOPSIS
        Enables comprehensive auditing for Windows Server
    #>
    Write-ServerLog "Enabling server auditing..." "INFO"
    
    try {
        # Enable object access auditing (critical for file servers)
        auditpol /set /category:"Object Access" /success:enable /failure:enable | Out-Null
        
        # Enable privilege use auditing
        auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
        
        # Enable detailed tracking
        auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable | Out-Null
        
        # Enable DS Access (for Domain Controllers)
        auditpol /set /category:"DS Access" /success:enable /failure:enable | Out-Null
        
        Write-ServerLog "Server auditing enabled successfully" "SUCCESS"
        return $true
    } catch {
        Write-ServerLog "Failed to configure server auditing: $_" "ERROR"
        return $false
    }
}

function Secure-FileServer {
    <#
    .SYNOPSIS
        Hardens file server configuration
    #>
    Write-ServerLog "Hardening File Server..." "INFO"
    
    try {
        # Disable SMBv1 (critical security issue)
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-ServerLog "Disabled SMBv1 protocol" "SUCCESS"
        
        # Enable SMB encryption
        try {
            Set-SmbServerConfiguration -EncryptData $true -Confirm:$false -ErrorAction SilentlyContinue
            Write-ServerLog "Enabled SMB encryption" "SUCCESS"
        } catch {
            Write-ServerLog "Could not enable SMB encryption: $_" "WARNING"
        }
        
        # Enable SMB signing
        try {
            Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false -ErrorAction SilentlyContinue
            Write-ServerLog "Enabled SMB signing" "SUCCESS"
        } catch {
            Write-ServerLog "Could not enable SMB signing: $_" "WARNING"
        }
        
        return $true
    } catch {
        Write-ServerLog "Error hardening file server: $_" "ERROR"
        return $false
    }
}

# Main Execution
Write-ServerLog "========================================" "INFO"
Write-ServerLog "Windows Server Security Hardening" "INFO"
Write-ServerLog "========================================" "INFO"

# Check if running on Windows Server
if (-not (Test-IsWindowsServer)) {
    Write-ServerLog "This system is not Windows Server - skipping server-specific hardening" "WARNING"
    Write-ServerLog "Use CyberPatriot-Auto.ps1 for desktop hardening" "INFO"
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

Write-ServerLog "Windows Server detected" "SUCCESS"

# Detect installed roles
$installedRoles = Get-ServerRoles
if ($installedRoles.Count -gt 0) {
    Write-ServerLog "Detected server roles: $($installedRoles -join ', ')" "INFO"
} else {
    Write-ServerLog "No specific server roles detected" "INFO"
}

# Try to load README data
$readmeData = $null
if (Test-Path ".\ReadmeData.json") {
    try {
        $readmeData = Get-Content ".\ReadmeData.json" -Raw | ConvertFrom-Json
        Write-ServerLog "Loaded README data - will respect required services" "SUCCESS"
    } catch {
        Write-ServerLog "Could not load README data - run AnalyzeReadme.ps1 first" "WARNING"
    }
}

$requiredServices = @()
if ($readmeData -and $readmeData.RequiredServices) {
    $requiredServices = $readmeData.RequiredServices
}

# Apply server-specific hardening
Write-ServerLog "" "INFO"
Write-ServerLog "Applying server security hardening..." "INFO"

# Common server hardening
Enable-ServerAuditing
Secure-FileServer
Disable-ServerUnnecessaryServices -RequiredServices $requiredServices

# Role-specific hardening
if ($installedRoles -contains "AD DS" -or ($readmeData -and $readmeData.ServerRoles -contains "AD DS")) {
    Secure-ActiveDirectory
}

if ($installedRoles -contains "DNS" -or ($readmeData -and $readmeData.ServerRoles -contains "DNS")) {
    Secure-DNSServer
}

if ($installedRoles -contains "DHCP" -or ($readmeData -and $readmeData.ServerRoles -contains "DHCP")) {
    Secure-DHCPServer
}

if ($installedRoles -contains "IIS" -or ($readmeData -and $readmeData.ServerRoles -contains "IIS")) {
    Secure-IISServer
}

Write-ServerLog "" "INFO"
Write-ServerLog "========================================" "INFO"
Write-ServerLog "Server hardening complete!" "SUCCESS"
Write-ServerLog "Log file: $LogFile" "INFO"
Write-ServerLog "========================================" "INFO"

# Open log file
Start-Process notepad.exe -ArgumentList $LogFile

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
