# User Guide

**Complete usage guide for the M&A Technical Discovery Script**

**Author**: Adrian Johnson <adrian207@gmail.com>

---

## Overview

**Purpose**: This guide covers all features, options, and usage scenarios for conducting Microsoft infrastructure audits during mergers and acquisitions.

**Contents**:
1. Getting Started
2. Using the GUI
3. Command-Line Usage
4. Understanding the Reports
5. Security and Encryption
6. Advanced Scenarios
7. Best Practices

---

## 1. Getting Started

### What This Tool Does

The M&A Technical Discovery Script automates the collection of comprehensive infrastructure data for due diligence:

**On-Premises Infrastructure:**
- Active Directory (users, computers, groups, GPOs, trusts, service accounts)
- Server hardware (CPU, memory, storage, NICs, OS versions)
- Installed applications (SQL Server, IIS, Exchange, custom apps)
- SQL Server databases (instances, sizes, backups, logins, jobs)
- Event logs (critical/error events, system health)
- User activity (logon history, stale accounts)

**Microsoft 365 Cloud:**
- Entra ID (Azure AD): users, groups, devices, Conditional Access, apps
- Exchange Online: mailboxes, forwarding rules, transport rules, connectors
- SharePoint & OneDrive: sites, storage, external sharing
- Microsoft Teams: teams, channels, membership, settings
- Power Platform: environments, apps, flows, DLP policies, Dataverse
- Compliance: retention policies, DLP, sensitivity labels, eDiscovery

**Output:**
- 60+ CSV files with raw data
- 5 HTML reports (executive summary + 4 detailed reports)
- Encrypted output for data protection
- Audit metadata and logs

### When to Use This Tool

✅ **M&A Due Diligence**: Comprehensive technical discovery before acquisition  
✅ **Cloud Migration Planning**: Assess current state before Microsoft 365 migration  
✅ **Security Audits**: Identify privileged accounts, stale users, misconfigurations  
✅ **Compliance Reviews**: Document infrastructure for regulatory requirements  
✅ **IT Asset Management**: Maintain inventory of servers, apps, licenses  
✅ **Disaster Recovery Planning**: Identify backup status and recovery requirements  

### Execution Time Estimates

| Environment Size | Users | Servers | SQL Instances | Estimated Time |
|------------------|-------|---------|---------------|----------------|
| **Small** | < 200 | < 20 | < 5 | 15-30 minutes |
| **Medium** | 200-1,000 | 20-100 | 5-20 | 30-90 minutes |
| **Large** | 1,000-5,000 | 100-500 | 20-50 | 1-3 hours |
| **Enterprise** | > 5,000 | > 500 | > 50 | 3-6 hours |

---

## 2. Using the GUI

### Launching the GUI

```powershell
# Navigate to script directory
cd C:\Tools\AD-Audit

# Launch GUI
.\Start-M&A-Audit-GUI.ps1
```

### GUI Sections

#### **Basic Settings** (Required)

**Company Name**
- Purpose: Used in report titles and output folder names
- Example: `Contoso Corporation`
- Format: Any text, no special requirements

**Output Folder**
- Purpose: Where audit results will be saved
- Example: `C:\Audits\Contoso`
- Notes:
  - Folder will be created if it doesn't exist
  - Subfolder with timestamp will be created (e.g., `Contoso-2025-10-20-143022`)
  - Ensure 1-10 GB free space depending on environment size

**Report Title**
- Purpose: Custom title for HTML reports
- Example: `Contoso M&A Technical Discovery - Q4 2025`
- Optional: If blank, defaults to company name + date

**Domain to Audit**
- Purpose: Specify which AD domain to audit
- Example: `contoso.local`
- Default: Current domain if left blank
- Notes: Must have network connectivity to domain controllers

#### **What to Audit**

**Active Directory**
- ☑ Forest and domain information
- ☑ Users, computers, groups
- ☑ GPOs, trusts, service accounts
- ☑ Password policies, DNS zones
- Duration: 5-15 minutes

**Servers**
- ☑ Hardware inventory (CPU, memory, storage)
- ☑ Installed applications
- ☑ Event logs (critical/error events)
- ☑ User logon history
- Duration: 10-40 minutes (depends on server count)

**SQL Server**
- ☑ Instance discovery
- ☑ Database inventory (sizes, backups)
- ☑ SQL logins, Agent jobs, linked servers
- Duration: 5-20 minutes (depends on SQL instance count)

**Microsoft 365**
- ☑ Entra ID, Exchange Online, SharePoint, Teams
- ☑ Power Platform, Compliance
- Duration: 20-60 minutes (depends on cloud data volume)
- Notes: Requires interactive authentication (browser pop-up)

#### **Audit Options**

**Event Log Days**: `7 | 30 | 60 | 90`
- Purpose: How far back to search for critical/error events
- Recommendation: 30 days for most audits
- Impact: Longer periods = slower execution

**Logon History Days**: `30 | 60 | 90 | 180 | 365`
- Purpose: How far back to analyze user logon activity
- Recommendation: 90 days for stale user detection
- Impact: Longer periods = larger dataset

**Stale Account Threshold**: `30 | 60 | 90 | 180`
- Purpose: Days since last logon to mark accounts as "stale"
- Recommendation: 90 days aligns with most company policies
- Impact: Lower threshold = more stale accounts flagged

**Max Parallel Servers**: `1-50` (default: 10)
- Purpose: How many servers to query simultaneously
- Recommendation: 10 for fast networks, 5 for slow/WAN connections
- Impact: Higher = faster but more network traffic

#### **Advanced Options** (Optional)

**Exclude Test OUs**
- Purpose: Skip test/lab environments from audit
- Example: `OU=Test,DC=contoso,DC=local`
- Format: Semicolon-separated list of OU DNs

**Focus on Specific OUs**
- Purpose: Only audit specific OUs (ignore rest)
- Example: `OU=Production,DC=contoso,DC=local;OU=Corporate,DC=contoso,DC=local`
- Format: Semicolon-separated list of OU DNs

**Known SQL Instances**
- Purpose: Manually specify SQL instances (in addition to auto-discovery)
- Example: `SERVER1\SQL2019;SERVER2\SQLEXPRESS`
- Format: Semicolon-separated list of `SERVER\INSTANCE` names

**Network Priority Servers**
- Purpose: Prioritize certain servers for parallel processing
- Example: `SQL*;EXCH*;SP*` (wildcards supported)
- Format: Semicolon-separated list with wildcards

#### **Compliance & Notification**

**Compliance Focus**
- Options: `None | HIPAA | PCI-DSS | SOX | ISO 27001`
- Purpose: Highlight compliance-specific findings in reports
- Impact: Adds compliance-focused sections to reports

**Email Notification**
- Purpose: Send email when audit completes
- Example: `your.email@company.com`
- Notes: Requires SMTP configuration (not yet implemented)

#### **Encryption**

**Encrypt Output Files**
- ☑ Enabled by default (Windows EFS)
- Purpose: Protect sensitive audit data
- Methods: EFS, 7-Zip archive, Azure Key Vault
- See [Section 5: Security and Encryption](#5-security-and-encryption)

### Running the Audit from GUI

1. Fill in all required fields
2. Select what to audit
3. Click **"Start Audit"**
4. A new PowerShell window opens showing progress
5. Wait for completion (30-90 minutes typical)
6. Executive Summary report opens automatically in browser

### Cancelling an Audit

- Click **"Cancel"** button in GUI (before starting)
- Press **Ctrl+C** in the PowerShell execution window (after starting)
- Note: Partial results will be saved

---

## 3. Command-Line Usage

For automation, scripting, or advanced users.

### Basic Syntax

```powershell
.\Run-M&A-Audit.ps1 -CompanyName <string> -OutputFolder <string> [options]
```

### Common Examples

#### **On-Premises Only Audit**
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -OnlyAD
```

#### **Full Audit (On-Prem + M365)**
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso"
```

#### **AD Only (No Servers, No SQL)**
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -OnlyAD `
    -ServerInventory $false `
    -SkipSQL
```

#### **With Custom Stale Threshold**
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -StaleThresholdDays 180
```

#### **With Encrypted Archive**
```powershell
$password = Read-Host -AsSecureString "Enter archive password (16+ chars)"

.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -CreateEncryptedArchive `
    -ArchivePassword $password
```

#### **Skip Cloud Modules (Fast On-Prem Audit)**
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -OnlyAD
```

#### **Skip Power Platform (Reduce Execution Time)**
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -SkipPowerPlatform
```

### All Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-CompanyName` | String | Required | Company name for reports |
| `-OutputFolder` | String | Required | Where to save results |
| `-ADCredential` | PSCredential | Current | Alternate AD credentials |
| `-ReportTitle` | String | Company+Date | Custom report title |
| `-DomainName` | String | Current | Domain to audit |
| `-ServerInventory` | Bool | True | Collect server data |
| `-ServerEventLogDays` | Int | 30 | Event log days (7/30/60/90) |
| `-ServerLogonHistoryDays` | Int | 90 | Logon history days (30/60/90/180/365) |
| `-StaleThresholdDays` | Int | 90 | Stale account days (30/60/90/180) |
| `-MaxParallelServers` | Int | 10 | Concurrent server queries (1-50) |
| `-ServerQueryTimeout` | Int | 300 | Timeout per server (seconds) |
| `-SkipOfflineServers` | Bool | True | Skip unreachable servers |
| `-SkipEventLogs` | Switch | False | Skip event log collection |
| `-SkipLogonHistory` | Switch | False | Skip logon history |
| `-IncludeServerServices` | Switch | False | Collect Windows services |
| `-ExcludeTestOUs` | Switch | False | Skip test OUs |
| `-FocusOUs` | String | All | Specific OUs to audit |
| `-KnownSQLInstances` | String | Auto | Manual SQL instance list |
| `-PriorityServers` | String | None | Priority server list |
| `-ComplianceFocus` | String | None | HIPAA/PCI/SOX/ISO |
| `-NotificationEmail` | String | None | Email on completion |
| `-SkipAD` | Switch | False | Skip AD module |
| `-OnlyAD` | Switch | False | Only AD (skip M365) |
| `-SkipSQL` | Switch | False | Skip SQL inventory |
| `-SkipPowerPlatform` | Switch | False | Skip Power Platform |
| `-CreateEncryptedArchive` | Switch | False | Create encrypted archive |
| `-ArchivePassword` | SecureString | Prompt | Archive password |
| `-SkipEFSEncryption` | Switch | False | Skip EFS encryption |
| `-UseAzureKeyVault` | Switch | False | Use Azure Key Vault |
| `-KeyVaultName` | String | None | Key Vault name |
| `-KeyName` | String | None | Key name in vault |
| `-SkipEncryption` | Switch | False | No encryption (NOT RECOMMENDED) |

---

## 4. Understanding the Reports

### Output Structure

```
C:\Audits\Contoso-2025-10-20-143022\
├── RawData\
│   ├── AD\                     (30+ CSV files: users, computers, groups, GPOs, etc.)
│   ├── EntraID\                (10 CSV files: users, devices, apps, etc.)
│   ├── Exchange\               (9 CSV files: mailboxes, rules, connectors, etc.)
│   ├── SharePoint\             (6 CSV files: sites, OneDrive, Teams, etc.)
│   ├── PowerPlatform\          (7 CSV files: environments, apps, flows, etc.)
│   └── Compliance\             (8 CSV files: retention, DLP, sensitivity, etc.)
├── Reports\
│   ├── Executive_Summary.html      (📊 Boardroom-ready dashboard)
│   ├── AD_Detailed_Report.html     (🔍 Active Directory drill-down)
│   ├── Server_Detailed_Report.html (🖥️ Server infrastructure details)
│   ├── SQL_Detailed_Report.html    (🗄️ SQL database analysis)
│   └── Security_Detailed_Report.html (🔐 Security findings)
├── Logs\
│   └── audit_20251020_143022.log   (Execution log)
└── audit_metadata.json              (Audit metadata)
```

### Executive Summary Report

**Purpose**: Single-page dashboard for executives and stakeholders

**Sections**:

1. **Key Metrics**
   - Total users, computers, servers, mailboxes
   - Microsoft 365 licenses consumed
   - SQL databases and total size
   - Microsoft Teams count

2. **Migration Readiness Score** (0-100%)
   - Algorithmic assessment based on:
     - Stale account ratio (< 20% is good)
     - SQL backup health (no missing backups is good)
     - Virtualization rate (> 50% is good)
     - Privileged account count (< 50 is good)

3. **Active Directory Summary**
   - Forest/domain functional levels
   - User/computer counts
   - Privileged accounts
   - Stale accounts

4. **Server & Application Summary**
   - Total servers (physical vs. virtual)
   - OS distribution (Windows Server versions)
   - Total CPU cores, memory, storage
   - Top 10 installed applications

5. **SQL Server Summary**
   - SQL instances and versions
   - Total databases and size
   - Backup status (success/failures)
   - Top 10 largest databases

6. **Microsoft 365 Summary**
   - Entra ID users (cloud-only vs. synced)
   - Exchange mailboxes and total size
   - SharePoint sites and storage
   - Teams count and channels

7. **Key Findings & Recommendations**
   - 🚨 Critical issues (backup failures, privileged accounts)
   - ⚠️ Warnings (stale accounts, old OS versions)
   - ✅ Good practices (virtualization, backups)

### Detailed Reports

#### **Active Directory Report**

**Sections**:
- Top 20 stale users (inactive for 90+ days)
- Computer OS distribution (Windows 10, 11, Server 2016/2019/2022)
- Largest groups (member counts)
- Unlinked GPOs (not applied anywhere)
- AD trusts (external dependencies)
- Password policies (default + Fine-Grained Password Policies)
- DNS zones (forward lookup zones)

**Use Cases**:
- Identify cleanup opportunities (stale users, unlinked GPOs)
- Plan OS upgrades (Windows Server 2012 EOL)
- Document external dependencies (trusts)

#### **Server Infrastructure Report**

**Sections**:
- Hardware inventory table (CPU, RAM, storage per server)
- Top 10 largest volumes (capacity planning)
- Top 20 most common applications (migration planning)

**Use Cases**:
- Cloud migration sizing (CPU/RAM requirements)
- License consolidation (duplicate apps)
- Storage optimization (large volumes, low utilization)

#### **SQL Databases Report**

**Sections**:
- SQL instance details (version, edition, clustering)
- Top 20 largest databases (migration priority)
- Backup issues (databases with no recent backups)
- Sysadmin logins (security review)
- Failed SQL Agent jobs (operational health)
- Linked servers (external dependencies)

**Use Cases**:
- Azure SQL migration assessment (database sizes, compatibility)
- Backup compliance validation
- Security hardening (reduce sysadmin accounts)
- Job failure remediation

#### **Security Analysis Report**

**Sections**:
- Privileged accounts table (Domain Admins, Enterprise Admins, Schema Admins)
- Service accounts table (SPNs, password age, last logon)
- Security best practices checklist
- Recommendations for improvement

**Use Cases**:
- Privileged access governance (who has admin rights?)
- Service account hygiene (old passwords, unused accounts)
- Compliance evidence (demonstrate security controls)

---

## 5. Security and Encryption

### Why Encryption is Critical

M&A audit data contains **highly sensitive information**:
- User credentials (password ages, last logon times)
- Server configurations (IP addresses, installed apps)
- SQL database schemas and sizes
- Email forwarding rules (potential data exfiltration)
- Privileged account membership

**Regulatory Requirements**: GDPR, HIPAA, PCI-DSS, SOX may require encryption of audit data.

### Encryption Methods

#### **Method 1: Windows EFS (Default)**

**How it works**:
- Encrypts entire output folder using Windows Encrypting File System
- Tied to user account that ran the audit
- No password needed for the owner
- Automatic decryption when owner accesses files

**Advantages**:
- ✅ Zero configuration
- ✅ Automatic decryption for owner
- ✅ No password to remember
- ✅ Fast (built into Windows)

**Limitations**:
- ⚠️ Only works on NTFS volumes
- ⚠️ Doesn't work on network shares
- ⚠️ User must be logged in to decrypt
- ⚠️ If user account is deleted, data is lost (backup recovery key!)

**Usage**:
```powershell
# Enabled by default
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso"
```

**How to verify**:
```powershell
(Get-Item "C:\Audits\Contoso-*").Attributes -band [System.IO.FileAttributes]::Encrypted
# Returns: True
```

**How to decrypt** (automatic):
- Owner just opens the files normally
- Other users see "Access Denied"

#### **Method 2: Password-Protected Archive**

**How it works**:
- Compresses entire output folder
- Encrypts archive with AES-256 using password
- Creates either 7z file (if 7-Zip installed) or encrypted ZIP (PowerShell native)

**Advantages**:
- ✅ Works on any file system (including network shares)
- ✅ Password can be shared with authorized users
- ✅ Portable (can be moved/copied freely)
- ✅ Industry-standard encryption (AES-256)

**Limitations**:
- ⚠️ Requires 16+ character password
- ⚠️ Password must be stored securely (password manager)
- ⚠️ If password is lost, data is unrecoverable
- ⚠️ Manual decryption required

**Usage (7-Zip)**:
```powershell
$password = Read-Host -AsSecureString "Enter archive password (16+ chars)"

.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -CreateEncryptedArchive `
    -ArchivePassword $password
```

**Output**: `C:\Audits\Contoso-2025-10-20-143022.7z`

**How to decrypt**:
```powershell
.\Utilities\Decrypt-AuditData.ps1 `
    -EncryptedPath "C:\Audits\Contoso-2025-10-20-143022.7z" `
    -OutputPath "C:\Decrypted" `
    -DecryptionMethod Archive
```

#### **Method 3: Azure Key Vault (Enterprise)**

**How it works**:
- Generates AES-256 key for file encryption
- Encrypts AES key with RSA key stored in Azure Key Vault
- Stores encrypted AES key + IV in `encryption_key_info.json`
- Centralized key management and audit trail

**Advantages**:
- ✅ Enterprise-grade key management
- ✅ Centralized key storage (no password to remember)
- ✅ Audit trail of key access
- ✅ Key rotation capabilities
- ✅ Integration with Azure security controls

**Limitations**:
- ⚠️ Requires Azure subscription
- ⚠️ Requires Azure Key Vault setup
- ⚠️ Requires network connectivity to Azure
- ⚠️ Additional cost (Key Vault pricing)

**Usage**:
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -UseAzureKeyVault `
    -KeyVaultName "ContosoAuditVault" `
    -KeyName "M&AAuditKey"
```

**How to decrypt**:
```powershell
.\Utilities\Decrypt-AuditData.ps1 `
    -EncryptedPath "C:\Audits\Contoso-2025-10-20-143022" `
    -OutputPath "C:\Decrypted" `
    -DecryptionMethod KeyVault `
    -KeyVaultName "ContosoAuditVault" `
    -KeyName "M&AAuditKey"
```

### Encryption Best Practices

1. **Always use encryption for production audits**
2. **Test decryption immediately after encryption** (verify you can recover data)
3. **Store passwords in enterprise password manager** (not in email/documents)
4. **Document who has access** (chain of custody)
5. **Back up recovery keys** (EFS recovery certificate, Azure Key Vault backups)
6. **Use Azure Key Vault for automated/scheduled audits** (no password management)
7. **Rotate keys regularly** (if using Azure Key Vault)
8. **Delete unencrypted data** (after creating encrypted archive)

---

## 6. Advanced Scenarios

### Scenario 1: Multi-Forest Audit

**Challenge**: Company has multiple AD forests

**Solution**: Run audit separately for each forest

```powershell
# Forest 1
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso-Forest1" `
    -DomainName "forest1.contoso.com" `
    -OutputFolder "C:\Audits\Contoso\Forest1"

# Forest 2
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso-Forest2" `
    -DomainName "forest2.contoso.com" `
    -OutputFolder "C:\Audits\Contoso\Forest2"

# Consolidate results manually or use script
```

### Scenario 2: Scheduled/Automated Audits

**Challenge**: Run audit monthly without user interaction

**Solution**: Use Task Scheduler + Service Principal authentication

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction `
    -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Tools\AD-Audit\Run-M&A-Audit.ps1 -CompanyName 'Contoso' -OutputFolder 'C:\Audits\Contoso' -OnlyAD"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am

Register-ScheduledTask `
    -TaskName "M&A Audit - Weekly" `
    -Action $action `
    -Trigger $trigger `
    -User "DOMAIN\AuditServiceAccount" `
    -Password (Read-Host -AsSecureString "Password") `
    -RunLevel Highest
```

### Scenario 3: Audit Subset of Servers

**Challenge**: Only audit production servers, skip dev/test

**Solution**: Use Focus OUs or Priority Servers

```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -FocusOUs "OU=Production,DC=contoso,DC=local"
```

Or:

```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Contoso" `
    -PriorityServers "PROD-*"
```

### Scenario 4: Export to CMDB or ServiceNow

**Challenge**: Import audit results into asset management system

**Solution**: Use raw CSV files for import

```powershell
# Read CSV files
$servers = Import-Csv "C:\Audits\Contoso-*\RawData\AD\Server_Hardware_Inventory.csv"
$apps = Import-Csv "C:\Audits\Contoso-*\RawData\AD\Server_Applications_Detailed.csv"

# Transform to CMDB format
$cmdbData = $servers | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.ServerName
        OS = $_.OperatingSystem
        CPU_Cores = $_.TotalLogicalProcessors
        RAM_GB = $_.TotalPhysicalMemoryGB
        # ... map to CMDB schema
    }
}

# Export to CMDB import format
$cmdbData | Export-Csv "C:\Audits\CMDB_Import.csv" -NoTypeInformation

# Import to CMDB (example using REST API)
Invoke-RestMethod -Uri "https://cmdb.company.com/api/servers" -Method Post -Body ($cmdbData | ConvertTo-Json)
```

### Scenario 5: Compliance Evidence

**Challenge**: Provide audit evidence for compliance auditors

**Solution**: Use compliance-focused parameters + metadata export

```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits\Compliance\Q4-2025" `
    -ComplianceFocus "HIPAA" `
    -ReportTitle "HIPAA Compliance Audit - Q4 2025" `
    -CreateEncryptedArchive `
    -ArchivePassword $password

# Metadata file (audit_metadata.json) provides:
# - Timestamp of execution
# - User who ran audit
# - Parameters used
# - Modules executed
# - Data quality score
```

---

## 7. Best Practices

### Planning the Audit

✅ **Run during maintenance window** (generates network traffic)  
✅ **Notify stakeholders** (server owners may see increased CPU/memory during CIM queries)  
✅ **Test in lab first** (validate permissions, connectivity)  
✅ **Check disk space** (1-10 GB needed for output)  
✅ **Review firewall rules** (WMI/CIM ports 135, 445, 49152-65535)  

### During Execution

✅ **Don't close the PowerShell window** (audit will stop)  
✅ **Monitor progress** (check log file for errors)  
✅ **Respond to authentication prompts** (M365 modules require interactive sign-in)  
✅ **Be patient** (large environments take time)  
✅ **Check for errors in red text** (partial failures are logged but don't halt execution)  

### After Completion

✅ **Verify output folder** (check CSV files were created)  
✅ **Review Executive Summary** (opens automatically)  
✅ **Test decryption** (ensure you can recover encrypted data)  
✅ **Archive raw CSV files** (for detailed analysis)  
✅ **Share reports with stakeholders** (HTML files are portable)  
✅ **Document findings** (add notes to audit_metadata.json)  

### Security Best Practices

🔐 **Always encrypt output** (EFS minimum, archive preferred for portability)  
🔐 **Use strong passwords** (16+ characters, complexity)  
🔐 **Store passwords in password manager** (not email/documents)  
🔐 **Limit access to audit files** (need-to-know basis)  
🔐 **Delete unencrypted copies** (after creating encrypted archive)  
🔐 **Use Azure Key Vault for automation** (no password management)  
🔐 **Enable audit logging** (track who accessed audit files)  
🔐 **Set retention policy** (delete old audits after N days)  

### Data Quality

✅ **Review data quality score** (shown in logs and metadata.json)  
✅ **Investigate low scores** (< 70% indicates missing data)  
✅ **Check for offline servers** (shown in logs as "unreachable")  
✅ **Verify SQL connectivity** (failed SQL instances are logged)  
✅ **Validate M365 authentication** (check for "Access Denied" errors)  
✅ **Re-run if necessary** (with adjusted parameters)  

---

## Troubleshooting Common Issues

See [Troubleshooting Guide](TROUBLESHOOTING.md) for comprehensive troubleshooting.

---

**Author**: Adrian Johnson <adrian207@gmail.com>  
**Last Updated**: October 20, 2025

