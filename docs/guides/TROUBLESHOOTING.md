# Troubleshooting Guide

> Executive summary: Resolve common issues fast—check logs, verify permissions, confirm connectivity, and apply targeted fixes by category.
>
> Key recommendations:
> - Start with the log and error text; note the first failure
> - Verify permissions and execution policy early
> - Use the category sections for precise remediations
>
> Supporting points:
> - Includes copy-paste fixes and verification commands
> - Covers installation, modules, connectivity, and runtime
> - Maps errors to causes and resolution steps

**Resolve common issues with the M&A Technical Discovery Script**

**Author**: Adrian Johnson <adrian207@gmail.com>

---

## Quick Diagnostic Steps

**If the script fails, follow these steps:**

1. **Check the log file**: `Output\Logs\audit_TIMESTAMP.log`
2. **Look for error messages** (red text in PowerShell window)
3. **Verify permissions** (Domain Admin + Global Reader)
4. **Test connectivity** (domain controllers, servers, M365)
5. **Check disk space** (1-10 GB needed)
6. **Review this guide** for specific error messages

---

## Common Issues by Category

### Installation & Setup Issues

#### **Issue: "Cannot be loaded because running scripts is disabled"**

**Error Message**:
```
.\Run-M&A-Audit.ps1 : File C:\Tools\AD-Audit\Run-M&A-Audit.ps1 cannot be loaded because 
running scripts is disabled on this system.
```

**Cause**: PowerShell execution policy is too restrictive

**Solution**:
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Verify
Get-ExecutionPolicy -List
```

**Alternative** (if you can't change execution policy):
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File ".\Run-M&A-Audit.ps1" -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso"
```

---

#### **Issue: "Module 'ActiveDirectory' not found"**

**Error Message**:
```
Import-Module : The specified module 'ActiveDirectory' was not loaded because no valid module file was found.
```

**Cause**: RSAT (Remote Server Administration Tools) not installed

**Solution**:
```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Or install all RSAT tools
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell
```

**Verify**:
```powershell
Get-Module -ListAvailable ActiveDirectory
```

---

#### **Issue: GUI won't launch - "Add-Type : Cannot add type"**

**Error Message**:
```
Add-Type : Cannot add type. The assembly 'System.Windows.Forms' could not be loaded.
```

**Cause**: Missing .NET Framework 4.5+

**Solution**:
1. Download .NET Framework 4.8: https://dotnet.microsoft.com/download/dotnet-framework/net48
2. Install and reboot
3. Re-launch GUI

**Verify**:
```powershell
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Version
# Should show: 4.8.xxx
```

---

### Permission Issues

#### **Issue: "Access Denied" when collecting AD data**

**Error Message**:
```
Get-ADUser : Access is denied
```

**Cause**: Insufficient Active Directory permissions

**Solution**:
1. Verify you're running as Domain Admin:
   ```powershell
   whoami /groups | Select-String "Domain Admins"
   ```
2. If not, re-launch PowerShell:
   - Right-click PowerShell
   - "Run as different user"
   - Enter Domain Admin credentials

**Alternative**: Check if AD module is connecting to correct domain:
```powershell
Get-ADDomain
# Verify domain name matches your target
```

---

#### **Issue: "Access Denied" when collecting server data**

**Error Message**:
```
Get-CimInstance : Access is denied
Test-WSMan : Access is denied
```

**Cause**: Not a local administrator on target servers

**Solution**:
1. Add audit account to domain group with local admin rights on servers
2. Or use alternate credential:
   ```powershell
   $cred = Get-Credential
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -ADCredential $cred
   ```

**Verify server access**:
```powershell
# Test WMI/CIM access
Test-WSMan -ComputerName SERVER01

# Test admin rights
Invoke-Command -ComputerName SERVER01 -ScriptBlock {whoami /groups}
```

---

#### **Issue: "Access Denied" when connecting to SQL Server**

**Error Message**:
```
Login failed for user 'DOMAIN\User'
```

**Cause**: Not a member of sysadmin role on SQL instance

**Solution**:
1. Add audit account to SQL sysadmin role (for full inventory)
2. Or grant minimum permissions:
   ```sql
   USE master;
   GRANT VIEW SERVER STATE TO [DOMAIN\AuditAccount];
   GRANT VIEW ANY DATABASE TO [DOMAIN\AuditAccount];
   ```

**Verify SQL access**:
```powershell
# Test SQL connectivity
$conn = New-Object System.Data.SqlClient.SqlConnection("Server=SERVER01;Integrated Security=true")
$conn.Open()
$conn.State  # Should show: Open
$conn.Close()
```

---

### Connectivity Issues

#### **Issue: "RPC server is unavailable" when querying servers**

**Error Message**:
```
Get-CimInstance : The RPC server is unavailable
```

**Cause**: Firewall blocking RPC/WMI ports or server is offline

**Solution**:
1. **Test connectivity**:
   ```powershell
   Test-Connection -ComputerName SERVER01 -Count 2
   Test-NetConnection -ComputerName SERVER01 -Port 135  # RPC
   Test-NetConnection -ComputerName SERVER01 -Port 445  # SMB
   ```

2. **Enable firewall rules** (on target server):
   ```powershell
   # Run on target server
   Enable-PSRemoting -Force
   netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes
   ```

3. **Skip offline servers** (in audit):
   ```powershell
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -SkipOfflineServers $true
   ```

---

#### **Issue: "Cannot connect to Microsoft Graph" (M365 modules)**

**Error Message**:
```
Connect-MgGraph : The term 'Connect-MgGraph' is not recognized
```

**Cause**: Microsoft.Graph modules not installed

**Solution**:
```powershell
# Install Microsoft Graph modules
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Users -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Groups -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force

# Verify
Get-Module -ListAvailable Microsoft.Graph*
```

---

#### **Issue: M365 authentication fails or times out**

**Error Message**:
```
Connect-MgGraph : Timeout expired
AADSTS50058: A silent sign-in request was sent but no user is signed in
```

**Cause**: MFA required, Conditional Access blocking, or network connectivity

**Solution**:
1. **Use interactive authentication** (browser-based):
   ```powershell
   # The script will automatically prompt for authentication
   # Use an account with Global Reader role
   ```

2. **Check Conditional Access**:
   - Temporarily exclude audit workstation from CA policies (if safe)
   - Or use compliant device for audit

3. **Test M365 connectivity**:
   ```powershell
   Test-NetConnection -ComputerName graph.microsoft.com -Port 443
   Test-NetConnection -ComputerName login.microsoftonline.com -Port 443
   ```

4. **Clear cached credentials**:
   ```powershell
   Disconnect-MgGraph
   Disconnect-ExchangeOnline -Confirm:$false
   # Re-run audit
   ```

---

### Execution Issues

#### **Issue: Script is extremely slow**

**Symptoms**: Audit takes 4+ hours for medium environment

**Causes**:
- High `MaxParallelServers` value on slow network
- Large event log queries (90+ days)
- Slow/unreachable servers not being skipped

**Solutions**:
1. **Reduce parallelism**:
   ```powershell
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -MaxParallelServers 5
   ```

2. **Reduce event log days**:
   ```powershell
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -ServerEventLogDays 7
   ```

3. **Skip offline servers**:
   ```powershell
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -SkipOfflineServers $true
   ```

4. **Skip time-consuming modules**:
   ```powershell
   # Skip event logs and logon history
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -SkipEventLogs -SkipLogonHistory
   ```

---

#### **Issue: Script hangs or freezes**

**Symptoms**: PowerShell window stops updating, no progress for 30+ minutes

**Causes**:
- Waiting for unresponsive server
- Infinite loop (rare, but possible)
- PowerShell session timeout

**Solutions**:
1. **Check Task Manager**:
   - Is PowerShell consuming CPU? (still working)
   - Is PowerShell idle? (hung)

2. **Check log file** (in real-time):
   ```powershell
   # In separate PowerShell window
   Get-Content "C:\Audits\Contoso-*\Logs\audit_*.log" -Wait -Tail 20
   ```

3. **Cancel and restart**:
   - Press **Ctrl+C** in PowerShell window
   - Identify last successful step in log
   - Re-run with adjusted parameters (skip problematic servers/modules)

---

#### **Issue: Out of memory error**

**Error Message**:
```
Exception of type 'System.OutOfMemoryException' was thrown
```

**Cause**: Processing large dataset (100,000+ users, 1,000+ servers)

**Solutions**:
1. **Close other applications** (free up RAM)
2. **Run on machine with more RAM** (8 GB minimum, 16 GB recommended for large environments)
3. **Process in batches**:
   ```powershell
   # Audit specific OUs separately
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso-OU1" -FocusOUs "OU=Region1,DC=contoso,DC=local"
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso-OU2" -FocusOUs "OU=Region2,DC=contoso,DC=local"
   ```

---

### Output and Report Issues

#### **Issue: No CSV files created**

**Symptoms**: Output folder exists but RawData\ folder is empty

**Cause**: Module failed before data collection completed

**Solutions**:
1. **Check log file** for errors:
   ```powershell
   Get-Content "C:\Audits\Contoso-*\Logs\audit_*.log" | Select-String "ERROR|FAILED"
   ```

2. **Review PowerShell window** for red error text

3. **Re-run with verbose logging**:
   ```powershell
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -Verbose
   ```

---

#### **Issue: HTML reports not generated**

**Symptoms**: CSV files exist, but Reports\ folder is empty

**Cause**: Report generator failed (missing data, PowerShell error)

**Solutions**:
1. **Check if report script exists**:
   ```powershell
   Test-Path ".\Modules\New-AuditReport.ps1"
   ```

2. **Generate reports manually**:
   ```powershell
   .\Modules\New-AuditReport.ps1 -OutputFolder "C:\Audits\Contoso-2025-10-20-143022\RawData" -CompanyName "Contoso"
   ```

3. **Check for missing CSV files**:
   ```powershell
   # Report generator expects these minimum files
   Test-Path "C:\Audits\Contoso-*\RawData\AD\AD_Users.csv"
   Test-Path "C:\Audits\Contoso-*\RawData\AD\AD_Computers.csv"
   ```

---

#### **Issue: Cannot open encrypted files**

**Symptoms**: "Access Denied" when trying to open CSV files

**Cause**: Files are EFS-encrypted and you're not the owner

**Solutions**:
1. **Log in as the user who ran the audit** (EFS is tied to user account)

2. **Use decryption utility**:
   ```powershell
   .\Utilities\Decrypt-AuditData.ps1 -EncryptedPath "C:\Audits\Contoso-*" -OutputPath "C:\Decrypted" -DecryptionMethod EFS
   ```

3. **Check if files are encrypted**:
   ```powershell
   (Get-Item "C:\Audits\Contoso-*").Attributes -band [System.IO.FileAttributes]::Encrypted
   # True = encrypted, False = not encrypted
   ```

4. **Disable encryption** (if re-running audit):
   ```powershell
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -SkipEncryption
   # WARNING: Not recommended for production
   ```

---

#### **Issue: Cannot decrypt password-protected archive**

**Symptoms**: "Wrong password" or "Cannot extract" error

**Causes**:
- Incorrect password
- Archive corrupted
- 7-Zip not installed (for .7z files)

**Solutions**:
1. **Verify password** (check password manager)

2. **Install 7-Zip** (if extracting .7z file):
   ```powershell
   winget install -e --id 7zip.7zip
   ```

3. **Use decryption utility**:
   ```powershell
   .\Utilities\Decrypt-AuditData.ps1 -EncryptedPath "C:\Audits\Contoso-*.7z" -OutputPath "C:\Decrypted" -DecryptionMethod Archive
   # Enter password when prompted
   ```

4. **Check archive integrity**:
   ```powershell
   # If 7-Zip installed
   & "C:\Program Files\7-Zip\7z.exe" t "C:\Audits\Contoso-*.7z"
   # Should show: Everything is Ok
   ```

---

### Module-Specific Issues

#### **Issue: SQL Server discovery finds no instances**

**Symptoms**: SQL inventory CSV files are empty

**Causes**:
- No SQL Servers in environment (unlikely)
- SQL Browser service disabled
- Firewall blocking SQL discovery
- SPNs not registered

**Solutions**:
1. **Manually specify SQL instances**:
   ```powershell
   .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -KnownSQLInstances "SERVER1\SQL2019;SERVER2\SQLEXPRESS"
   ```

2. **Verify SQL Browser service** (on SQL servers):
   ```powershell
   Get-Service -ComputerName SERVER01 -Name SQLBrowser
   # Should be: Running
   ```

3. **Check SPNs**:
   ```powershell
   setspn -Q MSSQLSvc/*
   # Should list SQL Server SPNs
   ```

---

#### **Issue: Exchange Online data incomplete**

**Symptoms**: Fewer mailboxes than expected

**Cause**: Pagination or timeout during data collection

**Solutions**:
1. **Check log file** for timeout errors
2. **Re-run Exchange module** separately (if possible)
3. **Report issue** to script maintainer (may need pagination improvements)

---

#### **Issue: Power Platform module fails**

**Error Message**:
```
Add-PowerAppsAccount : The term 'Add-PowerAppsAccount' is not recognized
```

**Cause**: Power Apps modules not installed

**Solution**:
```powershell
Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force
Install-Module Microsoft.PowerApps.PowerShell -Scope CurrentUser -Force

# Verify
Get-Module -ListAvailable Microsoft.PowerApps*
```

---

##Diagnostic Commands

### Check Script Version

```powershell
Get-Content ".\Run-M&A-Audit.ps1" | Select-String "ScriptVersion"
```

### View Full Error Details

```powershell
# In PowerShell where error occurred
$Error[0] | Format-List * -Force
```

### Export Log File for Support

```powershell
# Copy log file to desktop
Copy-Item "C:\Audits\Contoso-*\Logs\audit_*.log" -Destination "$env:USERPROFILE\Desktop\audit-log.txt"
```

### Test All Prerequisites

```powershell
# Test AD connectivity
Import-Module ActiveDirectory
Get-ADDomain

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

# Test server connectivity
$testServer = "SERVER01"  # Replace with your server
Test-WSMan -ComputerName $testServer
Test-NetConnection -ComputerName $testServer -Port 135

# Test SQL connectivity
$testSQL = "SERVER01"  # Replace with your SQL server
Test-NetConnection -ComputerName $testSQL -Port 1433
```

---

## Getting Additional Help

### Before Contacting Support

Please collect the following information:

1. **PowerShell version**:
   ```powershell
   $PSVersionTable
   ```

2. **Operating system**:
   ```powershell
   [System.Environment]::OSVersion
   ```

3. **Script version**:
   ```powershell
   Get-Content ".\Run-M&A-Audit.ps1" | Select-String "ScriptVersion"
   ```

4. **Error message** (exact text)

5. **Log file**: `Output\Logs\audit_TIMESTAMP.log`

6. **Steps to reproduce**

### Contact Information

**Author**: Adrian Johnson  
**Email**: adrian207@gmail.com

**Include in email**:
- Subject: "M&A Audit Tool - [Brief description of issue]"
- Attach log file
- Describe what you were trying to do
- What error occurred
- What you've already tried

---

## Known Limitations

These are current limitations of the script (not bugs):

1. **Multi-forest audits**: Must run separately for each forest
2. **Pagination**: Very large environments (50,000+ users) may have incomplete data
3. **Hybrid Exchange**: On-premises Exchange Server audit not included (M365 only)
4. **DHCP**: DHCP inventory requires RSAT-DHCP tools and may fail if DHCP not configured
5. **Azure Arc servers**: Not included in server inventory (on-premises only)
6. **Email notifications**: Not yet implemented
7. **Custom reports**: No built-in report customization (requires manual editing of HTML)

---

**Author**: Adrian Johnson <adrian207@gmail.com>  
**Last Updated**: October 20, 2025

