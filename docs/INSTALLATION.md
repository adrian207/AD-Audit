# Installation Guide

**Complete setup instructions for deploying the M&A Technical Discovery Script in your environment.**

**Author**: Adrian Johnson <adrian207@gmail.com>

---

## Installation Summary

**What this guide covers:**
- System requirements and prerequisites
- Permission requirements (on-premises and cloud)
- Module dependencies and auto-installation
- Network and firewall requirements
- Post-installation verification

**Time to complete**: 15-30 minutes (depending on module installation)

---

## System Requirements

### Minimum Requirements
| Component | Requirement |
|-----------|-------------|
| **Operating System** | Windows 10 (1809+), Windows 11, or Windows Server 2016+ |
| **PowerShell** | Version 5.1 or later (7.x recommended) |
| **RAM** | 4 GB minimum, 8 GB recommended |
| **Disk Space** | 500 MB for modules, 1-10 GB for audit output |
| **.NET Framework** | 4.7.2 or later (for GUI) |
| **Network** | Domain connectivity + Internet access |

### Recommended Configuration
| Component | Recommendation |
|-----------|----------------|
| **Operating System** | Windows 11 Pro or Windows Server 2022 |
| **PowerShell** | PowerShell 7.4+ |
| **RAM** | 16 GB (for large environments) |
| **Disk Space** | SSD with 20+ GB free |
| **Network** | 1 Gbps LAN connection |

---

## Permission Requirements

### On-Premises Infrastructure

#### **Domain Controller Access**
- **Domain Admin** role (read-only operations, but elevation required for WMI/CIM)
- Alternative: Custom delegation with these rights:
  - Read all AD objects and attributes
  - Read Group Policy Objects
  - Query domain controllers
  - Remote WMI/CIM access to member servers

#### **Server Inventory Access**
- **Local Administrator** on all target servers (via domain group)
- Alternative: Add audit account to:
  - `BUILTIN\Administrators` (for CIM/WMI)
  - `BUILTIN\Performance Monitor Users` (for performance counters)

#### **SQL Server Access**
- **sysadmin** role on SQL instances (for full inventory)
- Alternative minimum: `VIEW SERVER STATE` + `VIEW ANY DATABASE` permissions

### Microsoft 365 Cloud Services

#### **Required Roles** (choose one approach)

**Option A: Global Reader (Recommended)**
- Assign **Global Reader** role to audit account
- Read-only access to all M365 services
- No modifications possible
- Audit-friendly for compliance

**Option B: Granular Roles** (if Global Reader not available)
- **Directory Readers** (Entra ID)
- **Exchange Administrator** (read-only cmdlets)
- **SharePoint Administrator** (read-only)
- **Teams Administrator** (read-only)
- **Power Platform Administrator** (read-only)
- **Compliance Administrator** (read-only)

**Option C: Custom Role** (enterprise)
- Create custom role with read-only permissions across all workloads
- Requires Azure AD Premium P1 or P2

#### **Authentication Methods**
1. **Interactive (Default)**: Browser-based authentication with MFA support
2. **Service Principal**: For automation (requires app registration)
3. **Certificate-based**: For enhanced security (enterprise)

---

## Network and Firewall Requirements

### Outbound Connectivity Required

#### **Microsoft 365 Endpoints**
- `*.microsoftonline.com` (authentication)
- `*.microsoft.com` (module downloads)
- `graph.microsoft.com` (Microsoft Graph API)
- `outlook.office365.com` (Exchange Online)
- `*.sharepoint.com` (SharePoint Online)
- `api.powerplatform.com` (Power Platform)

**Ports**: 443 (HTTPS)

#### **On-Premises Endpoints**
- Domain Controllers: 135, 139, 445, 389, 636, 3268, 3269, 49152-65535 (RPC dynamic)
- Member Servers: 135, 139, 445, 49152-65535 (RPC dynamic for WMI/CIM)
- SQL Servers: 1433 (default), or custom port

### Firewall Rules

**Windows Firewall (on audit workstation)**:
```powershell
# Enable PowerShell Remoting (if needed)
Enable-PSRemoting -Force

# Allow WMI through firewall
netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes
```

**Domain Controller GPO** (if restrictive policies exist):
- Enable "Remote Event Log Management" exception
- Enable "Windows Management Instrumentation (WMI)" exception

---

## Installation Steps

### Step 1: Download the Script

**Option A: Git Clone** (Recommended)
```powershell
# Install Git if not present
winget install --id Git.Git -e --source winget

# Clone repository
cd C:\Tools
git clone https://github.com/your-org/AD-Audit.git
cd AD-Audit
```

**Option B: Direct Download**
1. Download ZIP from https://github.com/your-org/AD-Audit/releases
2. Extract to `C:\Tools\AD-Audit`
3. Right-click > Properties > Unblock (if downloaded from internet)

### Step 2: Set Execution Policy

```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Verify
Get-ExecutionPolicy -List
```

Expected output:
```
Scope          ExecutionPolicy
-----          ---------------
MachinePolicy  Undefined
UserPolicy     Undefined
Process        Undefined
CurrentUser    RemoteSigned
LocalMachine   Undefined
```

### Step 3: Verify PowerShell Version

```powershell
$PSVersionTable

# You should see:
# PSVersion: 5.1.x or 7.x.x
```

**If PSVersion < 5.1**: Install PowerShell 7
```powershell
winget install --id Microsoft.PowerShell --source winget
```

### Step 4: Pre-Install Modules (Optional but Recommended)

The script will auto-install modules on first run, but pre-installing saves time:

```powershell
# Microsoft Graph (Entra ID)
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Groups -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force

# Exchange Online
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force

# SharePoint Online
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force

# Microsoft Teams
Install-Module MicrosoftTeams -Scope CurrentUser -Force

# Power Platform
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force
Install-Module Microsoft.PowerApps.PowerShell -Scope CurrentUser -Force

# Azure Key Vault (optional - for enterprise encryption)
Install-Module Az.KeyVault -Scope CurrentUser -Force
```

**⏱️ Installation time**: 10-20 minutes for all modules

### Step 5: Test Connectivity

**On-Premises Test:**
```powershell
# Test AD connectivity
Import-Module ActiveDirectory
Get-ADDomain

# Test server connectivity (replace SERVER01 with your server)
Test-WSMan -ComputerName SERVER01

# Test SQL connectivity (replace SERVER01 with your SQL server)
Test-NetConnection -ComputerName SERVER01 -Port 1433
```

**Cloud Connectivity Test:**
```powershell
# Test Microsoft Graph
Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgOrganization
Disconnect-MgGraph

# Test Exchange Online
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Get-OrganizationConfig
Disconnect-ExchangeOnline -Confirm:$false
```

---

## Post-Installation Verification

### Run a Test Audit

```powershell
cd C:\Tools\AD-Audit

# Launch GUI
.\Start-M&A-Audit-GUI.ps1
```

**Expected behavior:**
1. GUI window opens without errors
2. Default values populate (current domain, current user)
3. All checkboxes are functional
4. "Start Audit" button is enabled

### Run a Quick Test (AD Only)

```powershell
.\Run-M&A-Audit.ps1 -CompanyName "TEST" -OutputFolder "C:\Temp\Test-Audit" -OnlyAD
```

**Expected output:**
```
============================================
   M&A Technical Discovery Script v1.0
============================================

[12:00:00] Starting Active Directory audit...
[12:01:00] Collecting forest information...
[12:02:00] Collecting domain information...
[12:05:00] Collecting user inventory... 100 users found
...
============================================
   Audit Completed Successfully!
============================================
```

**Verify output:**
```powershell
# Check output folder exists
Test-Path "C:\Temp\Test-Audit"

# Check CSV files were created
Get-ChildItem "C:\Temp\Test-Audit\RawData\AD" -Filter *.csv

# Check HTML reports were created
Get-ChildItem "C:\Temp\Test-Audit\Reports" -Filter *.html
```

---

## Troubleshooting Installation Issues

### Issue: "Cannot be loaded because running scripts is disabled"

**Cause**: Execution policy is too restrictive

**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue: "Module not found" errors

**Cause**: PowerShell Gallery not accessible or modules not installed

**Solution**:
```powershell
# Check PowerShell Gallery connectivity
Test-NetConnection -ComputerName www.powershellgallery.com -Port 443

# Register PSGallery if needed
Register-PSRepository -Default

# Set PSGallery as trusted
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```

### Issue: "Access Denied" when collecting AD data

**Cause**: Insufficient permissions

**Solution**:
1. Verify you're running as Domain Admin:
   ```powershell
   whoami /groups | Select-String "Domain Admins"
   ```
2. If not, re-launch PowerShell with "Run as different user" and use Domain Admin credentials

### Issue: "Cannot connect to domain controller"

**Cause**: Network connectivity or firewall blocking

**Solution**:
```powershell
# Test DNS resolution
nslookup your-domain.com

# Test LDAP connectivity
Test-NetConnection -ComputerName your-dc.your-domain.com -Port 389

# Test Kerberos
Test-NetConnection -ComputerName your-dc.your-domain.com -Port 88
```

### Issue: Cloud authentication fails

**Cause**: MFA or Conditional Access blocking sign-in

**Solution**:
1. Use **modern authentication** (browser-based) instead of basic auth
2. Add audit workstation to Conditional Access exclusion (temporary)
3. Use **app password** if legacy auth required (not recommended)

---

## Advanced Configuration

### Service Principal Authentication (Automation)

For scheduled/automated audits without user interaction:

1. **Create App Registration** in Azure AD
2. **Assign API permissions**:
   - Microsoft Graph: Directory.Read.All, User.Read.All, Group.Read.All
   - Exchange: Exchange.ManageAsApp
   - SharePoint: Sites.FullControl.All (read-only operations)
3. **Create client secret** or upload certificate
4. **Run audit with service principal**:
   ```powershell
   $credential = Get-Credential  # Use Application ID as username, secret as password
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -Credential $credential
   ```

### Proxy Configuration

If your environment uses a proxy:

```powershell
# Set proxy for PowerShell session
$proxy = "http://proxy.company.com:8080"
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($proxy)
$env:HTTP_PROXY = $proxy
$env:HTTPS_PROXY = $proxy
```

### Custom Module Installation Path

```powershell
# Install modules to custom location
$modulePath = "C:\CustomModules"
New-Item -ItemType Directory -Path $modulePath -Force
$env:PSModulePath = "$modulePath;$env:PSModulePath"

# Install modules to custom path
Save-Module -Name Microsoft.Graph -Path $modulePath
```

---

## Uninstallation

To remove the script and modules:

```powershell
# Remove installed modules
Get-InstalledModule | Where-Object {$_.Name -like "Microsoft.Graph*"} | Uninstall-Module
Uninstall-Module ExchangeOnlineManagement
Uninstall-Module Microsoft.Online.SharePoint.PowerShell
Uninstall-Module MicrosoftTeams
Uninstall-Module Microsoft.PowerApps.*

# Remove script directory
Remove-Item -Path "C:\Tools\AD-Audit" -Recurse -Force

# Remove audit output (optional)
Remove-Item -Path "C:\Audits" -Recurse -Force
```

---

## Next Steps

✅ **Installation complete!**

- 📖 **First-time use**: See [Quick Start Guide](QUICK_START.md)
- 📚 **Detailed usage**: See [User Guide](USER_GUIDE.md)
- 🐛 **Issues**: See [Troubleshooting Guide](TROUBLESHOOTING.md)

---

**Author**: Adrian Johnson <adrian207@gmail.com>  
**Last Updated**: October 20, 2025

