# M&A Technical Discovery Script: Detailed Design Document

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 2.0 | October 20, 2025 | Adrian Johnson | Major revision: Added hybrid identity architecture, DNS/network dependencies, compliance module, Power Platform details, data security plan, validation framework, comprehensive gotchas section, detailed server hardware inventory with event logs and logon history, and comprehensive SQL Server database inventory. |
| 1.9 | October 20, 2025 | Adrian Johnson | Added AD ACL analysis for high-value objects to detect dangerous, non-default permissions. |
| 1.8 | October 20, 2025 | Adrian Johnson | Added inventory of default AD groups and a text-based export of the domain/OU tree structure. |
| 1.7 | October 20, 2025 | Adrian Johnson | Added Computer Inventory, Member Server Inventory, and Group Hygiene checks (nested/empty groups) to the AD module. |
| 1.6 | October 20, 2025 | Adrian Johnson | Added discovery for AD Certificate Services and Entra App credential expiry. Added certificate inventory to Manual Verification. |
| 1.5 | October 20, 2025 | Adrian Johnson | Added server patch status to the Manual Verification Checklist due to permission requirements. |
| 1.4 | October 20, 2025 | Adrian Johnson | Added GPO inventory, DC OS versions, and AD Schema version. Added Manual Verification section for non-scriptable checks like backups. |
| 1.3 | October 20, 2025 | Adrian Johnson | Added krbtgt account password age check as a critical security hygiene indicator. |
| 1.2 | October 20, 2025 | Adrian Johnson | Expanded AD service account discovery beyond SPNs to include multiple heuristics for a comprehensive inventory. |
| 1.1 | October 20, 2025 | Adrian Johnson | Added "gotchas" based on community/MSFT best practices (PIM, Devices, Power Platform, SPNs, etc.) |
| 1.0 | October 20, 2025 | Adrian Johnson | Initial Draft |

---

## 1. Executive Summary

This document outlines the design for a comprehensive PowerShell-based auditing toolset for Merger and Acquisition (M&A) technical discovery and due diligence. The primary purpose of this toolset is to perform deep technical discovery on a target company's Microsoft infrastructure to identify migration risks, estimate workload scope, and assess security posture.

The script will gather critical configuration data from:
- **On-premises Active Directory** (AD) and related services
- **Hybrid identity infrastructure** (AD Connect, ADFS, PTA)
- **Microsoft Entra ID** (Azure AD)
- **Microsoft 365 services** (Exchange Online, SharePoint, OneDrive, Teams)
- **Power Platform** (Power Apps, Power Automate, Power BI, Dataverse)
- **Compliance and security** configurations

The output will be a consolidated, timestamped report package containing:
- **Executive HTML dashboard** with key metrics and risk indicators
- **Detailed CSV exports** for in-depth analysis
- **Migration blocker analysis** with severity ratings
- **Security findings report** highlighting privilege escalation paths and hygiene issues
- **Data volume estimates** for scoping migration timelines

This enables stakeholders to accurately scope the migration effort, budget resources, identify technical debt, and plan remediation activities before migration begins.

### Target Use Cases
1. **M&A Technical Due Diligence**: Pre-acquisition assessment of IT infrastructure health
2. **Tenant-to-Tenant Migration Planning**: Scoping and planning for M365 tenant consolidation
3. **Security Posture Assessment**: Identifying security gaps and privilege escalation risks
4. **IT Infrastructure Documentation**: Creating a comprehensive snapshot of current state

---

## 2. Goals and Objectives

### Primary Goals
1. **Identify Migration Blockers**: Discover technical configurations that will impede, delay, or halt a tenant migration
2. **Estimate Data & Workload Scope**: Quantify the volume of data, users, and objects to be migrated
3. **Assess Identity & Security Posture**: Provide a clear picture of security hygiene and operational maturity
4. **Inventory Key Assets**: Generate comprehensive lists of all users, computers, groups, domains, applications, licenses, and configurations
5. **Produce Actionable Reports**: Consolidate all collected data into human-readable and machine-processable formats

### Success Criteria
- **Completeness**: Captures all critical configuration data points (99%+ coverage of migration-relevant items)
- **Accuracy**: Data collected is verifiable and matches actual configuration
- **Actionability**: Reports clearly identify blockers, risks, and required actions with severity levels
- **Security**: All collected data is encrypted at rest and access-controlled
- **Performance**: Completes full audit of medium-sized tenant (5,000 users) within 2 hours
- **Reliability**: Handles partial failures gracefully and produces useful output even with limited permissions

---

## 3. Solution Architecture

The tool will be a modular PowerShell script toolkit with a central orchestration engine. Each module operates independently and can be run standalone or as part of the full audit suite.

### 3.1 Core Components

```
AD-Audit/
├── Run-M&A-Audit.ps1              # Main orchestration script
├── Modules/
│   ├── Invoke-AD-Audit.ps1        # Active Directory module
│   ├── Invoke-HybridIdentity-Audit.ps1  # ADFS, AD Connect, PTA
│   ├── Invoke-EntraID-Audit.ps1   # Entra ID (Azure AD) module
│   ├── Invoke-Exchange-Audit.ps1  # Exchange Online module
│   ├── Invoke-SPO-Teams-Audit.ps1 # SharePoint, OneDrive, Teams
│   ├── Invoke-PowerPlatform-Audit.ps1  # Power Platform
│   ├── Invoke-Compliance-Audit.ps1     # Security & Compliance
│   └── Invoke-Network-Audit.ps1   # DNS, DHCP, Sites
├── Libraries/
│   ├── Report-Generator.ps1       # HTML/CSV report generation
│   ├── Data-Validator.ps1         # Data quality checks
│   └── Security-Helper.ps1        # Output encryption
├── Output/
│   └── [Timestamp]_CompanyName/
│       ├── Executive-Report.html
│       ├── Security-Findings.html
│       ├── Migration-Blockers.html
│       ├── RawData/
│       │   ├── AD_Users.csv
│       │   ├── AD_Computers.csv
│       │   └── [50+ CSV files]
│       └── audit_metadata.json
└── README.md
```

### 3.2 Execution Flow

1. **Pre-flight Checks**
   - Validate PowerShell version (5.1+ or 7+)
   - Check for required modules
   - Test credentials and permissions
   - Create output directory structure

2. **Module Execution** (Parallel where possible)
   - Each module runs independently
   - Progress displayed to console
   - Errors logged but don't halt other modules
   - Each module produces standardized output objects

3. **Data Validation**
   - Sanity checks on collected data
   - Flag suspicious results (e.g., 0 users found)
   - Calculate data quality score

4. **Report Generation**
   - Consolidate all module outputs
   - Generate HTML dashboards
   - Create CSV exports
   - Encrypt sensitive data

5. **Cleanup and Summary**
   - Display execution summary
   - List any failed modules or permissions issues
   - Provide next steps guidance

### 3.3 Error Handling Strategy

- **Module Independence**: Failure of one module does not halt execution of others
- **Graceful Degradation**: Modules produce partial results if some data unavailable
- **Detailed Logging**: All errors logged with timestamp, module, and context
- **Permission Mapping**: Clear indication of which permissions are missing and impact
- **Retry Logic**: Automatic retry with exponential backoff for API throttling
- **Resume Capability**: Checkpoint files allow resuming long-running audits

### 3.4 Security and Data Protection

**Collected Data Sensitivity**: CRITICAL - Contains admin account lists, ACLs, security configurations

**Protection Measures**:
1. **Encryption at Rest**: All output files encrypted using AES-256
2. **Access Control**: Output folder permissions restricted to audit runner
3. **Data Minimization**: No passwords or credentials collected
4. **Retention Policy**: Recommend 90-day retention, then secure deletion
5. **Chain of Custody**: Audit metadata includes who ran it, when, and from where
6. **Transport Security**: All API calls use TLS 1.2+

#### 3.4.1 Output File Encryption Implementation

**Encryption Strategy**: Dual-approach encryption providing both transparent filesystem encryption and portable encrypted archives.

**Method 1: Windows Encrypting File System (EFS)** - Default
- **When**: Applied automatically after all data collection completes
- **How**: 
  ```powershell
  # Encrypt entire output folder using EFS
  (Get-Item $OutputFolder).Encrypt()
  
  # Recursively encrypt all files and subfolders
  Get-ChildItem $OutputFolder -Recurse | ForEach-Object { $_.Encrypt() }
  ```
- **Encryption Details**:
  - Uses Windows EFS with AES-256 cipher
  - Keys stored in user's certificate store (Windows Certificate Manager)
  - Transparent to authorized user (automatic decryption on read)
  - Files show green name in Windows Explorer indicating encryption
- **Access Control**:
  - Only the audit runner account can decrypt by default
  - Additional users granted access via EFS properties (not recommended)
  - Recovery agent configuration recommended for enterprise deployments
- **Advantages**:
  - Zero user interaction required
  - Transparent decryption for authorized account
  - Windows native, no external dependencies
  - Survives file moves within same NTFS volume
- **Limitations**:
  - NTFS volumes only (not FAT32, exFAT, network shares)
  - Decryption keys tied to Windows user profile
  - Files lose encryption when copied to non-NTFS destinations
  - Requires EFS-capable Windows edition (not Home edition)
- **Recovery Planning**:
  - Configure EFS recovery agent before audit execution
  - Export user's EFS certificate: `certmgr.msc` → Personal → Certificates → Export
  - Store recovery certificate in secure location (offline)
  - Document recovery process in audit metadata

**Method 2: Password-Protected Archive** - Optional
- **When**: User specifies `-CreateEncryptedArchive` parameter
- **How**: 
  ```powershell
  # Create AES-256 encrypted ZIP archive
  7z.exe a -p"$Password" -mhe=on -t7z -mhc=on -mx=9 `
         "$OutputFolder.7z" "$OutputFolder\*"
  
  # Alternative: PowerShell 7+ native encryption
  Compress-Archive -Path "$OutputFolder\*" `
                   -DestinationPath "$OutputFolder.zip" `
                   -CompressionLevel Optimal
  # Then encrypt ZIP using System.Security.Cryptography
  ```
- **Encryption Details**:
  - AES-256 encryption with SHA-256 key derivation
  - Password-based encryption (PBKDF2 with high iteration count)
  - Header encryption enabled (`-mhc=on`) - hides file names
  - File names encrypted (`-mhe=on`) - metadata protection
- **Password Requirements**:
  - Minimum 16 characters (enforced by script)
  - Must include uppercase, lowercase, numbers, special characters
  - Password entropy validation (minimum 80 bits)
  - Password can be passed as SecureString or prompted interactively
- **Implementation Options**:
  - **Option A**: 7-Zip (recommended for maximum compatibility)
    - Requires 7-Zip installed: `choco install 7zip` or manual install
    - Produces `.7z` or `.zip` files
    - Cross-platform extraction (7-Zip available for Windows, Linux, macOS)
  - **Option B**: PowerShell native with .NET Crypto (no dependencies)
    - Uses `System.Security.Cryptography.AesManaged`
    - Produces `.enc` files with custom format
    - Requires companion decryption script
- **Advantages**:
  - Cross-platform portability
  - Explicit password control (can be shared securely)
  - Files can be transferred via network or removable media
  - No dependency on Windows user profile
- **Limitations**:
  - Requires external tool (7-Zip) or custom decryption script
  - Password must be managed securely (not stored in script)
  - Compression adds processing time (5-15 minutes for large datasets)
  - Archive extraction required before analysis

**Method 3: Azure Key Vault Integration** - Enterprise Option
- **When**: User specifies `-UseAzureKeyVault` with Key Vault URL
- **How**:
  ```powershell
  # Retrieve encryption key from Azure Key Vault
  $Key = Get-AzKeyVaultKey -VaultName "ContosoAuditVault" -KeyName "M&AAuditKey"
  
  # Encrypt each file with AKV-managed key
  foreach ($File in Get-ChildItem $OutputFolder -Recurse -File) {
      $EncryptedContent = Invoke-AzKeyVaultKeyOperation `
          -KeyId $Key.Id -Operation Encrypt -Algorithm RSA-OAEP -Value $FileContent
      Set-Content -Path "$File.enc" -Value $EncryptedContent
  }
  ```
- **Key Management**:
  - Encryption keys stored in Azure Key Vault (HSM-backed)
  - Managed identity authentication (no passwords in scripts)
  - Key rotation capability without re-encrypting files
  - Audit logs in Azure Monitor for all key access
- **Advantages**:
  - Enterprise-grade key management
  - Centralized access control (Azure RBAC)
  - Audit trail for all decrypt operations
  - Supports compliance requirements (SOC 2, ISO 27001)
- **Limitations**:
  - Requires Azure subscription and Key Vault setup
  - Internet connectivity required for encryption/decryption
  - Additional Azure costs (~$0.03 per 10,000 operations)
  - More complex setup and configuration

**Encryption Parameter Design**:

```powershell
# Default: EFS encryption only
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso"

# EFS + encrypted archive
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" `
    -CreateEncryptedArchive -ArchivePassword (Read-Host -AsSecureString "Archive Password")

# Skip EFS, archive only (for non-NTFS destinations)
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" `
    -SkipEFSEncryption -CreateEncryptedArchive -ArchivePassword $SecurePassword

# Azure Key Vault (enterprise)
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" `
    -UseAzureKeyVault -KeyVaultName "ContosoAuditVault" -KeyName "M&AAuditKey"

# No encryption (development/testing only - NOT RECOMMENDED)
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" `
    -SkipEncryption -WarningAction Continue
```

**Encryption Verification**:

After encryption, the script validates:
1. **EFS Verification**: `(Get-Item $File).Attributes -match 'Encrypted'`
2. **Archive Verification**: Attempt to open without password (should fail)
3. **Checksum Validation**: SHA-256 hash stored in metadata before encryption
4. **Decryption Test**: Verify audit runner can read files

**Security Warnings**:
- Script displays prominent warning if `-SkipEncryption` is used
- Audit metadata records encryption method used (or if skipped)
- Non-encrypted outputs logged as security event for audit trail
- Recommend enabling BitLocker on audit workstation as defense-in-depth

### 3.5 Performance Optimization

- **Parallel Processing**: Independent modules run in parallel jobs
- **Batching**: Graph API calls batched (up to 20 requests)
- **Filtering**: Server-side filtering where possible
- **Progress Checkpoints**: Save progress every 1000 objects
- **Throttle Management**: Automatic backoff on throttling errors
- **Memory Management**: Stream large datasets to disk rather than holding in memory

---

## 4. Module Breakdown: Data Points & Rationale

### 4.1 On-Premises Active Directory Module (Invoke-AD-Audit.ps1)

**Purpose**: Inventory the foundational on-prem identity source and assess its health, hygiene, and security posture.

**Required Modules**: `ActiveDirectory`, `GroupPolicy`, `DnsServer` (optional), `DhcpServer` (optional)

**Required Permissions**: Domain User (Read-Only) in the target AD forest. For DNS/DHCP: Read access to DNS/DHCP servers.

**Minimum Supported Versions**: Windows Server 2012 R2+ Domain Controllers

#### Data Points to Collect:

##### 4.1.1 Forest & Domain Information
- **Forest Functional Level (FFL)** and **Domain Functional Level (DFL)**
- All domains in forest (FQDN, NetBIOS name, domain SID)
- UPN Suffixes (alternative UPN suffixes configured)
- AD Schema Version (to detect outdated schemas)
- AD Recycle Bin status (enabled/disabled)
- **M&A Rationale**: Functional levels determine upgrade paths and feature availability. Low FFL/DFL indicates technical debt.

##### 4.1.2 Domain & OU Structure
- Text-based tree export of the domain and Organizational Unit (OU) hierarchy
- OU nesting depth (flag deeply nested structures >10 levels)
- Number of OUs per domain
- GPO links per OU
- **M&A Rationale**: Complex OU structures may indicate over-engineered environments or acquisitions that were never integrated.

##### 4.1.3 Domain Controller Inventory
- List of all DCs with:
  - Hostname and IP address
  - Operating System version and patch level
  - Site location
  - FSMO roles held
  - Global Catalog status
  - Last replication time
  - DC hardware (physical/virtual)
- **M&A Rationale**: Aging DC OS versions (Server 2012 R2 or older) require urgent upgrade. FSMO role placement affects migration sequence.

##### 4.1.4 Member Server Inventory (Basic)
- List of all server OS computers that are NOT Domain Controllers:
  - Hostname
  - Operating System version
  - Last logon timestamp
  - OU location
  - Enabled/Disabled status
  - IPv4Address (from AD)
  - PasswordLastSet (computer account)
- **M&A Rationale**: Server count impacts infrastructure migration scope.

##### 4.1.5 Detailed Server Hardware & Application Inventory
**Purpose**: Deep infrastructure assessment for modernization planning and cloud migration sizing.

**Method**: Remote WMI/CIM queries via PowerShell Remoting to all online servers.

**Required Permissions**: Local Administrator on target servers OR Domain Admin (for remote WMI access).

**Challenges**:
- Servers may be offline or unreachable (firewalls, remote sites)
- WinRM may be disabled
- Timeout on slow networks
- Performance: Query servers in parallel batches

**Data Points Per Server**:

**Hardware Specifications**:
- **CPU**: Processor name, core count, logical processor count, CPU speed (GHz)
- **Memory**: Total physical memory (GB), available memory
- **Storage**: 
  - All logical disks (drive letters)
  - Per disk: Total size (GB), free space (GB), % free
  - Disk type (local, network, removable)
- **Network Adapters**:
  - NIC description
  - MAC address
  - IP addresses (IPv4, IPv6)
  - Subnet mask, default gateway
  - DNS servers configured
  - Link speed (Gbps)
  - Adapter status (up/down)
- **System Info**:
  - Manufacturer (Dell, HP, VMware, Microsoft)
  - Model
  - Serial number
  - BIOS version and date
  - Domain membership
  - Last boot time (uptime)
  - Time zone

**Operating System & Patching**:
- **OS Details**:
  - OS Name and version (Windows Server 2012 R2, 2016, 2019, 2022)
  - OS Build number (e.g., 20348.1547)
  - OS Architecture (64-bit, 32-bit)
  - Service Pack level (if applicable)
  - OS Installation date
  - Windows activation status
- **Patch Status**:
  - Last Windows Update install date
  - Count of installed updates (last 90 days)
  - Pending reboot status (yes/no)
  - WSUS/Update source configured
  - Optional: List of missing critical/security updates (requires WSUS API or Windows Update API)

**Installed Applications**:
- Query both:
  - Registry: `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
  - Registry: `HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*` (32-bit apps on 64-bit OS)
- Per application:
  - Application name
  - Version
  - Publisher
  - Install date
  - Install location
  - Estimated size (MB)
- **Key Applications to Flag**:
  - **SQL Server**: Version, edition (Express, Standard, Enterprise), instance names
  - **IIS**: Version, website count, application pool count
  - **Exchange Server**: Version (on-prem Exchange)
  - **SharePoint Server**: Version (on-prem SharePoint)
  - **ADFS**: Version
  - **Custom/LOB applications**: Anything not from Microsoft or major vendors
  - **Antivirus/Security**: Product and version
  - **Backup agents**: Veeam, Commvault, etc.

**Windows Roles & Features**:
- All installed Windows Server roles (using `Get-WindowsFeature`):
  - Web Server (IIS)
  - DNS Server
  - DHCP Server
  - File Server
  - Print Server
  - Remote Desktop Services
  - Hyper-V
  - Failover Clustering
  - Active Directory Certificate Services
  - Windows Server Update Services (WSUS)
  - Any custom roles
- Feature install dates (if available)

**Windows Services** (Optional - can be verbose):
- Non-standard Windows services (exclude Microsoft defaults)
- Service name, display name, startup type, state (running/stopped)
- Service account (LocalSystem, NetworkService, or domain account)
- **Flag services running as domain accounts** (service account dependencies)

**Performance Metrics** (Optional - point-in-time):
- CPU utilization (%)
- Memory utilization (%)
- Disk I/O (reads/writes per sec)
- Network utilization (Mbps)
- **Note**: Point-in-time metrics are less useful than historical averages. Recommend querying performance counters if time permits, or note as limitation.

**Virtualization Detection**:
- Is server virtual or physical?
- If virtual:
  - Hypervisor (VMware ESXi, Hyper-V, Citrix, KVM)
  - VM tools installed (VMware Tools version)
  - Host server (if detectable)

**Clustering & High Availability**:
- Failover cluster membership (yes/no)
- Cluster name
- Cluster nodes
- Cluster resources hosted on this node

**SQL Server Database Inventory** (if SQL Server detected):
- **Detection Method**: 
  - Check for SQL Server in installed applications
  - Query SPNs for MSSQLSvc entries
  - Attempt connection to default/named instances
  - Check for SQL Server Windows services

**Per SQL Server Instance**:
- **Instance Information**:
  - SQL Server version (2012, 2014, 2016, 2017, 2019, 2022)
  - SQL Server edition (Express, Standard, Enterprise, Developer, Web)
  - Service Pack and Cumulative Update level
  - Instance name (MSSQLSERVER for default, or named instance)
  - TCP port number
  - Instance collation
  - Product level and version number (e.g., 15.0.4335.1)
  - Authentication mode (Windows, Mixed)
  - Clustered instance (yes/no)
  - Server collation
- **Service Accounts**:
  - SQL Server Database Engine service account
  - SQL Server Agent service account
  - Service account type (LocalSystem, NetworkService, or domain account)
- **Instance Configuration**:
  - Max server memory (MB)
  - Min server memory (MB)
  - Max degree of parallelism (MAXDOP)
  - Cost threshold for parallelism
  - Instant file initialization enabled (yes/no)
  - Locked pages in memory (yes/no)
- **Licensing Information**:
  - License type (per-core, server+CAL, developer, express)
  - Installed features (Database Engine, Analysis Services, Reporting Services, Integration Services)
  - CPU core count (for licensing calculations)

**Per Database** (on each SQL instance):
- **Database Properties**:
  - Database name
  - Database state (ONLINE, OFFLINE, RESTORING, RECOVERING, SUSPECT, EMERGENCY)
  - Database owner (SQL login or Windows account)
  - Compatibility level (100=2008, 110=2012, 120=2014, 130=2016, 140=2017, 150=2019, 160=2022)
  - Database collation
  - Read-only status (yes/no)
  - Database type (System database vs. User database)
  - Create date
  - Last restore date
- **Database Size & Growth**:
  - Data file size (MB)
  - Log file size (MB)
  - Total database size (MB)
  - Data file free space (MB)
  - Log file free space (MB)
  - Autogrowth settings (data and log)
  - File locations (path to .mdf and .ldf files)
  - Number of data files
  - Number of log files
  - Filegroup configuration
- **Recovery & Backup**:
  - Recovery model (SIMPLE, FULL, BULK_LOGGED)
  - Last full backup date
  - Last differential backup date
  - Last transaction log backup date
  - Days since last full backup
  - Backup compression enabled (yes/no)
  - **Flag databases with no backup in 7+ days** (CRITICAL RISK)
  - **Flag databases with FULL recovery but no log backups** (transaction log will grow indefinitely)
- **High Availability & Disaster Recovery**:
  - Always On Availability Group membership (AG name, role: Primary/Secondary)
  - Synchronization state (SYNCHRONIZED, SYNCHRONIZING, NOT SYNCHRONIZING)
  - Database mirroring status (Principal, Mirror, or None)
  - Log shipping role (Primary, Secondary, Monitor, or None)
  - Replication role (Publisher, Subscriber, Distributor, or None)
- **Security & Access**:
  - Database users count
  - Orphaned users (SQL logins without server login)
  - Database roles with elevated permissions (db_owner, db_securityadmin)
  - Transparent Data Encryption (TDE) enabled (yes/no)
  - Encryption key algorithm (if TDE enabled)
- **Database Options & Flags**:
  - Auto close (should be OFF)
  - Auto shrink (should be OFF - performance killer)
  - Page verify option (CHECKSUM recommended)
  - Snapshot isolation state
  - Read committed snapshot
  - Database chaining enabled
  - Trustworthy setting (security risk if ON for user databases)

**SQL Server Jobs & Maintenance**:
- **SQL Agent Jobs**:
  - Job name
  - Job owner
  - Enabled/Disabled
  - Schedule (frequency)
  - Last run date and status (succeeded, failed)
  - Job steps (brief description)
  - **Flag jobs owned by non-DBA accounts** (may break during migration)
  - **Flag jobs calling external resources** (file shares, linked servers)
- **Maintenance Plans**:
  - Plan name
  - Maintenance tasks (backup, index rebuild, statistics, integrity check)
  - Schedule
- **Linked Servers**:
  - Linked server name
  - Data source (server name)
  - Provider (SQL Server, Oracle, Excel, etc.)
  - Remote login mapping
  - **Flag linked servers pointing to external organizations** (migration blocker)

**SQL Server Logins & Security**:
- **SQL Server Logins** (server-level):
  - Login name
  - Login type (Windows, SQL Server, Certificate, Asymmetric Key)
  - Default database
  - Create date, last login date
  - Server roles (sysadmin, securityadmin, serveradmin, etc.)
  - **Flag SQL logins with sysadmin** (should migrate to Windows auth)
  - **Flag orphaned logins** (logins not used by any database)
  - Password policy enforcement (for SQL logins)

**SQL Server Configuration Issues** (Flags):
- End-of-life SQL Server versions (2012 and older)
- SQL Server on unsupported OS (e.g., SQL 2016 on Server 2008)
- Databases with no backups in 7+ days
- Databases with FULL recovery model but no log backups
- Auto Shrink enabled (performance issue)
- Databases in SUSPECT or EMERGENCY state
- SQL Agent service disabled or stopped
- Tempdb on C: drive (should be on separate, fast storage)
- Tempdb undersized (<8 files or <8GB)
- Max server memory not configured (will consume all RAM)
- Mixed authentication mode with weak SA password (security risk)

**Azure SQL Migration Assessment**:
- **Per Database**:
  - Recommended Azure SQL target: Azure SQL Database, Managed Instance, or SQL Server on VM
  - Compatibility level for Azure SQL
  - Features blocking Azure SQL Database migration (CLR, Service Broker, SQL Agent, etc.)
  - Estimated Azure SQL cost tier (Basic, Standard, Premium, Business Critical)
- **Rationale for Migration Target**:
  - Azure SQL Database: Simple databases, no SQL Agent, no cross-database queries
  - Azure SQL Managed Instance: Complex databases, SQL Agent, linked servers, CLR
  - SQL Server on Azure VM: Lift-and-shift, legacy applications, full control

**Collection Method**:
- Use `Invoke-Sqlcmd` or `dbatools` PowerShell module
- Connect using Windows Authentication (preferred) or SQL Authentication
- Query system DMVs: sys.databases, sys.master_files, sys.backup_history, sys.dm_exec_sessions, sys.server_principals
- Requires VIEW SERVER STATE and VIEW ANY DEFINITION permissions (or sysadmin)

**Performance Considerations**:
- SQL inventory adds 2-5 minutes per SQL Server instance
- Large SQL Servers (100+ databases) may take longer
- Parallel processing: Query multiple SQL instances simultaneously
- Consider timeout for unresponsive instances

**M&A Rationale (CRITICAL)**:
- **SQL Server licensing is the #1 infrastructure cost** in most environments
  - Enterprise edition: ~$15K per core (perpetual)
  - Azure SQL: $500-$5,000/month per database
- **Database sizes determine Azure SQL costs**: 1TB database = ~$3K-$10K/month
- **Custom databases are business-critical**: Breaking them stops business operations
- **End-of-life SQL versions** require immediate upgrade budget (security risk)
- **No backup = data loss risk** during migration
- **FULL recovery without log backups** = transaction log will fill disk
- **Licensing for Azure**:
  - Can use Azure Hybrid Benefit (AHUB) to reduce costs 40%+
  - Need accurate core counts for licensing
- **Always On Availability Groups** are complex to migrate (require downtime or replica reconfiguration)
- **Linked servers to external orgs** are migration blockers
- **Jobs calling external resources** will break post-migration

**Windows Event Logs - Top Issues**:
- **Data Source**: Query System, Application, and Security event logs
- **Time Range**: Configurable (default: last 30 days)
- **Collection Method**: `Get-WinEvent` filtered queries

**Top 10 Critical Events** (by frequency):
- Event log name (System, Application, Security)
- Event ID
- Source (provider name)
- Message/Description (first 500 characters)
- Count of occurrences (in time range)
- First occurrence timestamp
- Last occurrence timestamp
- **Key Events to Flag**:
  - Event ID 1074 (System has been shutdown/restarted)
  - Event ID 6008 (Unexpected shutdown)
  - Event ID 41 (Kernel-Power - system rebooted without cleanly shutting down)
  - Event ID 10016 (DCOM errors - may indicate permission issues)
  - Event ID 36 (Disk errors)
  - Event ID 4625 (Failed logon attempts - Security log)
  - Service crashes (Event ID 7031, 7034)

**Top 10 Error Events** (by frequency):
- Same structure as Critical events
- Level = Error (not Critical)
- Exclude benign/noisy errors (configurable exclusion list)

**Currently Logged On Users**:
- **Method**: Query Win32_ComputerSystem and Win32_LogonSession via WMI/CIM
- Per active session:
  - Username (domain\user)
  - Logon type (Interactive=2, RemoteInteractive=10, Service=5, etc.)
  - Logon time
  - Session state (Active, Disconnected, Idle)
  - Session ID
  - Idle time (minutes)
- **Flag**:
  - Multiple admin accounts logged on simultaneously
  - Sessions idle >24 hours
  - Non-admin users with interactive logons to servers

**Historical User Logon Analysis**:
- **Data Source**: Security event log (Event ID 4624 - successful logon)
- **Time Range**: Configurable (default: last 90 days, options: 30/60/90/180/365 days)
- **Collection Method**: `Get-WinEvent` with XPath filter on Security log
- **Important**: Security log may have limited retention (rolling log), collection limited by retention policy

**Aggregated User Logon Report**:
- Per user account (who logged on):
  - Username (domain\user)
  - Total logon count (in time range)
  - Logon types used (Interactive, RemoteInteractive, Network, etc.)
  - First logon timestamp
  - Last logon timestamp
  - Average logons per week
  - Unique source IP addresses (if available)
  - Unique source computer names (if available)
- **Sort by**: Total logon count (descending)
- **Flag**:
  - Service accounts with interactive logons (should be non-interactive only)
  - Admin accounts with excessive logons (may indicate shared accounts)
  - External IP addresses (potential remote access)
  - After-hours logons (outside business hours)

**Top 20 Most Frequent Users**:
- List of top 20 users by logon frequency
- Include logon count and date range

**Logon Failure Analysis** (Optional):
- Event ID 4625 (Failed logon attempts)
- Count by username
- Count by source IP/computer
- Failure reasons (bad password, account locked, account disabled, etc.)
- **Flag**: High failure counts may indicate brute-force attacks or misconfigured services

**Performance Notes**:
- Event log queries can be slow on servers with large logs (millions of events)
- Limit queries to specific time ranges and event IDs
- Consider parallel processing for multiple servers
- May timeout on servers with very large Security logs

**Security & Compliance Rationale**:
- Event logs reveal operational issues requiring remediation before migration
- Frequent reboots indicate unstable systems
- Disk errors may cause data loss during migration
- Failed logon attempts indicate security threats or misconfigurations

**Reachability Status**:
- Online/Offline (pingable)
- WinRM accessible (yes/no)
- Data collection success (full/partial/failed)
- Error message (if failed)

**M&A Rationale (CRITICAL)**:
- **Hardware specs** determine cloud VM sizing and migration costs
- **Old servers** (5+ years) require immediate refresh budget
- **Application inventory** reveals custom LOB apps requiring migration planning
- **SQL Server** licensing costs significant in cloud
- **Patch status** indicates security hygiene and operational maturity
- **Service account dependencies** must be mapped for migration
- **On-prem Exchange/SharePoint** are migration blockers (must migrate to cloud or decommission)
- **Storage utilization** determines data migration volume and timeline
- **Network config** reveals multi-homed servers and complex networking

##### 4.1.6 AD Sites and Subnets
- All AD sites and associated subnets
- Site links and replication topology
- Bridgehead servers
- **M&A Rationale**: Site topology affects DC placement during migration and reveals geographic distribution.

##### 4.1.7 AD Trusts
- All external and forest trusts:
  - Trust type (forest, external, shortcut)
  - Trust direction (one-way, two-way)
  - Trust transitivity
  - SID filtering status
  - Trust authentication (Kerberos, NTLM)
- **M&A Rationale**: Trusts to external organizations are major migration blockers and security risks.

##### 4.1.8 User Inventory
- Full export of all user objects with key attributes:
  - SamAccountName, UserPrincipalName, DisplayName
  - Enabled/Disabled status
  - PasswordLastSet, PasswordNeverExpires, PasswordNotRequired
  - AccountExpirationDate
  - LastLogonTimestamp (converted to DateTime)
  - MemberOf (group memberships)
  - Manager, Department, Title, Office
  - Mail, ProxyAddresses
  - msDS-UserPasswordExpiryTimeComputed
  - Account control flags (SmartcardRequired, TrustedForDelegation, etc.)
- **Stale Account Detection**: Flag accounts with LastLogon > 90 days
- **M&A Rationale**: User count drives licensing costs. Stale accounts indicate poor hygiene.

##### 4.1.9 Computer Inventory
- Full export of all computer objects with key attributes:
  - Name, DNSHostName, OperatingSystem, OperatingSystemVersion
  - Enabled/Disabled status
  - LastLogonTimestamp
  - OU location
  - IPv4Address
  - PasswordLastSet (computer account password)
  - TrustedForDelegation, TrustedToAuthForDelegation (Kerberos delegation)
  - PrimaryGroup
- **Stale Computer Detection**: Flag computers with LastLogon > 90 days
- **M&A Rationale**: Stale computers indicate poor asset management. Delegation settings are security risks.

##### 4.1.10 Group Inventory and Hygiene
- All groups with:
  - Name, GroupScope (Domain Local, Global, Universal)
  - GroupCategory (Security, Distribution)
  - MemberOf, Members (recursive expansion)
  - OU location
- **Group Hygiene Analysis**:
  - **Empty Groups**: Groups with zero members
  - **Nested Groups**: Groups containing only other groups (no direct user members)
  - **Large Groups**: Groups with >5000 members (can cause token bloat)
  - **Circular Nesting**: Groups that are members of themselves (indirectly)
- **M&A Rationale**: Empty groups indicate poor hygiene. Nested groups complicate permission auditing. Large groups cause Kerberos token bloat.

##### 4.1.11 Privileged Group Membership
- Full recursive expansion of privileged groups:
  - Domain Admins
  - Enterprise Admins
  - Schema Admins
  - Administrators (built-in)
  - Account Operators
  - Backup Operators
  - Server Operators
  - Print Operators
  - DNSAdmins
  - Any group with AdminCount=1
- Include: User name, account status, PasswordLastSet, LastLogon
- **M&A Rationale**: Over-provisioned admin accounts are security risks. AdminCount flag reveals current and past privileged accounts.

##### 4.1.12 Default Group Inventory
- Members of all built-in/default AD groups:
  - Account Operators, Backup Operators, Server Operators, Print Operators
  - Remote Desktop Users, Remote Management Users
  - Distributed COM Users
  - Event Log Readers
  - Hyper-V Administrators
- **M&A Rationale**: Membership in these groups often forgotten but grants significant privileges.

##### 4.1.13 AD Object ACL Analysis (High-Value Targets)
- Audit Access Control Lists on critical AD objects:
  - **Targets**:
    - Domain Root (DC=domain,DC=com)
    - AdminSDHolder container
    - Domain Admins group
    - Enterprise Admins group
    - Schema Admins group
    - All FSMO role holder objects
    - GPO objects
  - **Dangerous Permissions to Flag**:
    - GenericAll (Full Control)
    - WriteDacl (Modify Permissions)
    - WriteOwner (Take Ownership)
    - WriteProperty on group membership
    - ExtendedRight for "Replicating Directory Changes" (DCSync)
    - Self on group membership
  - **Analysis**: Report non-default ACEs granted to non-privileged users/groups
- **M&A Rationale (CRITICAL)**: This analysis uncovers hidden privilege escalation paths created by misconfigurations. It provides much deeper security insight than group membership alone. ACL-based backdoors are common attack vectors.

##### 4.1.14 Password Policy Audit
- **Default Domain Password Policy**:
  - MinPasswordLength
  - PasswordComplexity
  - MinPasswordAge, MaxPasswordAge
  - PasswordHistoryCount
  - LockoutThreshold, LockoutDuration, LockoutObservationWindow
- **Fine-Grained Password Policies (FGPP)**:
  - All PSO objects
  - PSO precedence
  - Applied to which users/groups
  - Policy settings
- **M&A Rationale**: Weak password policies (length <12, complexity disabled) are security red flags. Multiple FGPPs indicate mature security or complex compliance requirements.

##### 4.1.15 Kerberos Delegation Audit
- All accounts configured for delegation:
  - **Unconstrained Delegation**: TrustedForDelegation=True (HIGH RISK)
  - **Constrained Delegation**: TrustedToAuthForDelegation=True
  - **Resource-Based Constrained Delegation**: msDS-AllowedToActOnBehalfOfOtherIdentity
  - Service Principal Names (SPNs) associated with delegated accounts
- **M&A Rationale**: Unconstrained delegation is a critical security vulnerability. Constrained delegation indicates service account usage patterns.

##### 4.1.16 Service Principal Names (SPN) Inventory
- All user and computer accounts with SPNs
- SPN format parsing (service class, hostname, port)
- Accounts with multiple SPNs
- Duplicate SPNs (misconfiguration)
- **M&A Rationale**: SPNs reveal service dependencies. Duplicate SPNs cause Kerberos authentication failures.

##### 4.1.17 krbtgt Account Status
- PasswordLastSet date for the krbtgt account in each domain
- Age of krbtgt password (in days)
- **Flag if**: krbtgt password >180 days old (should be rotated twice per year minimum)
- **M&A Rationale**: Old krbtgt passwords indicate poor security hygiene. Fresh krbtgt rotation is required post-breach. Reveals if org follows security best practices.

##### 4.1.17 Group Policy Object (GPO) Inventory
- List of all GPOs with:
  - GPO Name, GUID
  - Creation date, modification date
  - GPO Status (Enabled/Disabled)
  - Link locations (OUs, sites, domains)
  - Link enabled status
  - Link enforcement (enforced/not enforced)
  - WMI filters applied
  - GPO version numbers (User, Computer)
- **Orphaned GPOs**: GPOs not linked anywhere
- **Disabled GPOs**: GPOs with all settings disabled
- **Empty GPOs**: GPOs with no configured settings
- **M&A Rationale**: GPO count impacts migration complexity. Orphaned GPOs indicate poor housekeeping. GPOs with legacy settings (drive mappings, printer deployments) may break post-migration.

##### 4.1.18 AD Certificate Services (AD CS) Discovery
- Check for presence of Enterprise Certificate Authority:
  - CA server name
  - CA common name
  - CA type (Enterprise Root, Enterprise Subordinate, Standalone)
  - Certificate templates published to AD
  - Auto-enrollment enabled templates
  - Certificate template ACLs (who can enroll)
  - CRL distribution points
  - OCSP responder URLs
- **Certificate Template Security Analysis**:
  - Templates allowing SAN (Subject Alternative Name) - can be abused
  - Templates with low-privilege enrollment rights
  - Templates with exportable private keys
- **M&A Rationale**: AD CS is complex to migrate. Certificate-based authentication requires careful planning. Misconfigured templates are privilege escalation vectors (ESC1-ESC8 attacks).

##### 4.1.19 AD Connect / Azure AD Connect Discovery
- Identify servers running AD Connect:
  - AD Connect version
  - Synchronization schedule
  - Sync rules (inbound, outbound)
  - Attribute mapping
  - OU filtering (which OUs sync to cloud)
  - Directory extension attributes
  - Password Hash Sync enabled/disabled
  - Password Writeback enabled/disabled
  - Device Writeback enabled/disabled
  - Group Writeback enabled/disabled
  - Staging mode enabled/disabled
- **M&A Rationale (CRITICAL)**: AD Connect configuration determines which objects sync to cloud. Custom sync rules complicate migration. Dual AD Connect to single tenant causes conflicts.

##### 4.1.20 Service Account Inventory (Heuristic-Based)
- Identify service accounts through multiple heuristics:
  - Accounts with SPNs
  - Accounts with "svc", "service", "app", "sql", "iis" in the name
  - Accounts with PasswordNeverExpires
  - Accounts in specific OUs (if named "Service Accounts", etc.)
  - Accounts with non-interactive logon rights
  - Accounts used in scheduled tasks (if accessible)
  - Accounts configured for delegation
- **Service Account Hygiene**:
  - Service accounts with interactive logon rights (security risk)
  - Service accounts in privileged groups (over-permissioned)
  - Service accounts with old passwords
- **M&A Rationale**: Service accounts are migration blockers if tied to on-prem resources. Poor service account hygiene is a security risk.

##### 4.1.21 DNS Zone Inventory
- All AD-integrated DNS zones:
  - Zone name, zone type (Primary, Secondary, Stub)
  - Replication scope (Forest, Domain, Legacy)
  - Dynamic updates enabled/secured
  - Aging/scavenging configured
  - Record count per zone
  - Critical records: MX, SPF, DKIM, DMARC, SRV
- **M&A Rationale**: DNS zones must be migrated or recreated. AD-integrated zones simplify replication but complicate migration.

##### 4.1.22 DHCP Server Discovery
- Identify DHCP servers in the domain:
  - Server name, IP address
  - Authorized in AD (yes/no)
  - Scopes configured
  - Scope options (DNS servers, gateways, WINS)
  - Reservations count
  - Lease duration
- **M&A Rationale**: DHCP dependencies on AD (authorization, DNS registration) must be accounted for.

---

### 4.2 Hybrid Identity Infrastructure Module (Invoke-HybridIdentity-Audit.ps1)

**Purpose**: Discover and document the hybrid identity architecture connecting on-premises AD to Entra ID.

**Required Modules**: `ADConnect` (if available), `ActiveDirectory`, `ADFS` (if available)

**Required Permissions**: Read access to AD Connect server, ADFS server (if present)

#### Data Points to Collect:

##### 4.2.1 Authentication Method Detection
- Determine which authentication method is configured:
  - **Password Hash Synchronization (PHS)**
  - **Pass-Through Authentication (PTA)**
  - **Federation (ADFS or third-party IdP)**
  - **Cloud-only** (no hybrid identity)
- **M&A Rationale (CRITICAL)**: Authentication method dramatically affects migration complexity. ADFS is the most complex to migrate.

##### 4.2.2 ADFS Discovery (if present)
- ADFS farm configuration:
  - Primary ADFS server, secondary servers
  - ADFS version
  - Federation service name
  - Certificate (SSL, token signing, token decryption) expiry dates
  - Relying party trusts (to Entra ID and third-party apps)
  - Claims rules for each relying party
  - MFA provider configured (Azure MFA, third-party)
  - Extranet lockout settings
  - Web Application Proxy (WAP) servers
- **M&A Rationale (CRITICAL)**: ADFS presence is a major migration blocker. ADFS to PHS/PTA cutover requires careful planning. Certificate expiry can cause outages.

##### 4.2.3 Pass-Through Authentication (PTA) Discovery
- PTA agent servers:
  - Server names and versions
  - Agent health status
  - High availability configuration (multiple agents)
- **M&A Rationale**: PTA agents must remain operational during migration. Agent placement affects authentication path.

##### 4.2.4 Seamless SSO Configuration
- Seamless SSO enabled/disabled
- AZUREADSSOACC computer account status in AD
- Kerberos decryption key age
- **M&A Rationale**: Seamless SSO simplifies user experience but requires domain-joined devices. Key must be rotated regularly.

##### 4.2.5 Third-Party Identity Providers
- Non-Microsoft IdPs integrated with Entra ID:
  - Okta, Ping Identity, Auth0, etc.
  - SAML or OIDC federation
- **M&A Rationale**: Third-party IdPs complicate migration and may have contractual lock-in.

---

### 4.3 Microsoft Entra ID Module (Invoke-EntraID-Audit.ps1)

**Purpose**: Audit the cloud identity and security control plane.

**Required Modules**: `Microsoft.Graph` (with appropriate scopes)

**Required Permissions**: 
- `Directory.Read.All`
- `Policy.Read.All`
- `Application.Read.All`
- `RoleManagement.Read.All`
- `Device.Read.All`

#### Data Points to Collect:

##### 4.3.1 Tenant Information
- Tenant ID, tenant name
- Primary domain (*.onmicrosoft.com)
- Tenant region
- Tenant type (commercial, GCC, GCC High)
- Directory quota (user limit)
- **M&A Rationale**: Tenant region affects data residency. Tenant type affects migration path.

##### 4.3.2 Registered Domains
- All verified domains:
  - Domain name
  - Authentication type (Managed, Federated)
  - Default domain (yes/no)
  - Verification status
  - Federated domain federation metadata URL (if federated)
- **Unverified domains**: Domains added but not verified
- **M&A Rationale (CRITICAL)**: Domain verification required before migration. Federated domains require cutover planning.

##### 4.3.3 User Inventory (Cloud)
- All Entra ID users:
  - UserPrincipalName, DisplayName
  - UserType (Member, Guest)
  - AccountEnabled
  - OnPremisesSyncEnabled (synced from AD or cloud-only)
  - OnPremisesImmutableId (source anchor)
  - AssignedLicenses
  - CreatedDateTime, LastSignInDateTime
  - ProxyAddresses
  - MFA registration status
  - Authentication methods registered
- **Orphaned Cloud Users**: Cloud-only users with on-prem UPN domain
- **Guest User Analysis**: Guest users by external domain
- **M&A Rationale**: Cloud-only users must be handled separately from synced users. Guest access patterns reveal external collaboration needs.

##### 4.3.4 Enterprise Applications & App Registrations
- **Enterprise Applications** (service principals):
  - App name, App ID
  - App owner
  - Publisher (Microsoft, verified, unverified)
  - Enabled/Disabled
  - Sign-in activity (last used)
  - Assigned users/groups
  - API permissions granted (delegated, application)
  - Consent type (admin consent, user consent)
- **App Registrations**:
  - App name, App ID
  - Owner
  - Credential count (secrets, certificates)
  - Credential expiry dates
  - Reply URLs
  - API permissions requested
- **Expiring Credentials**: Apps with credentials expiring within 90 days
- **High-Risk Permissions**: Apps with permissions like `Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`
- **M&A Rationale (CRITICAL)**: Third-party apps may not support multi-tenant scenarios. Expiring credentials cause outages. Over-permissioned apps are security risks.

##### 4.3.5 License Inventory
- All subscribed SKUs:
  - SKU name (friendly name)
  - SKU part number
  - Total licenses, consumed licenses, available licenses
  - Service plans enabled/disabled within SKU
- **License Assignment**:
  - Direct vs. group-based assignment
  - Users with multiple E3/E5 licenses (waste)
  - Disabled users consuming licenses
- **Inactive License Detection**: Licensed users with no sign-in in 90+ days
- **M&A Rationale**: License reconciliation is critical for cost management. Group-based licensing simplifies management.

##### 4.3.6 Conditional Access Policies
- All Conditional Access policies:
  - Policy name, state (enabled, disabled, report-only)
  - Users/groups included, excluded
  - Cloud apps included, excluded
  - Conditions (sign-in risk, device platforms, locations, client apps)
  - Grant controls (MFA, compliant device, hybrid join, approved app)
  - Session controls
  - Policy last modified date
- **Policy Coverage Analysis**:
  - Users not covered by any CA policy
  - Policies targeting "All Users" (high impact)
  - Policies in report-only mode (not enforced)
- **M&A Rationale**: CA policies enforce security posture. Overly restrictive policies break apps. Missing CA policies indicate weak security.

##### 4.3.7 Privileged Role Membership
- All Entra ID directory roles:
  - Role name
  - Members (direct and PIM-eligible)
  - For each member:
    - Assignment type (permanent, PIM-eligible, PIM-active)
    - PIM activation duration (if applicable)
    - Assignment start/end date
    - MFA registration status
- **Privileged Roles to Inventory**:
  - Global Administrator
  - Privileged Role Administrator
  - User Administrator
  - Exchange Administrator
  - SharePoint Administrator
  - Security Administrator
  - Conditional Access Administrator
  - Application Administrator
  - Cloud Application Administrator
- **PIM Adoption Rate**: % of admin assignments using PIM vs. permanent
- **M&A Rationale**: Permanent Global Admins are security risks. PIM usage indicates mature security posture. Break-glass accounts should exist.

##### 4.3.8 Device Inventory
- All Entra ID devices:
  - Device name, device ID
  - Operating system, OS version
  - Join type (Entra ID Joined, Hybrid Joined, Entra ID Registered)
  - MDM enrollment (Intune, other, none)
  - Compliance status (compliant, non-compliant, unknown)
  - Last sign-in (approximate)
  - Ownership (corporate, personal)
  - Enabled/Disabled
- **Stale Device Detection**: Devices with no sign-in in 90+ days
- **Device Distribution**: Count by join type, OS, compliance status
- **M&A Rationale**: Hybrid joined devices depend on on-prem AD. Device join type affects migration approach. Intune enrollment indicates cloud management maturity.

##### 4.3.9 MFA and Authentication Methods
- MFA enforcement method (Conditional Access, per-user MFA, Security Defaults)
- Per-user MFA status (if used):
  - Users with MFA enforced, enabled, disabled
- Authentication methods registered:
  - Phone, SMS, Authenticator App, FIDO2, Windows Hello
  - Users with no MFA methods registered
- **M&A Rationale**: Per-user MFA is legacy and complicates migration. CA-based MFA is preferred. Users without MFA are security risks.

##### 4.3.10 Legacy Authentication
- Sign-in logs analysis (last 30 days if available):
  - Count of sign-ins using legacy protocols (IMAP, POP, SMTP AUTH, Basic Auth)
  - Users/apps still using legacy authentication
- **M&A Rationale**: Legacy authentication cannot use MFA. Microsoft is deprecating Basic Auth. Apps using legacy auth must be upgraded.

##### 4.3.11 Security Defaults
- Security Defaults enabled/disabled
- **M&A Rationale**: Security Defaults conflict with Conditional Access. If enabled, indicates small/immature tenant.

##### 4.3.12 Named Locations
- All named locations (IP ranges, countries):
  - Location name
  - IP ranges or countries
  - Trusted location flag
- **M&A Rationale**: Named locations used in CA policies. Incorrect locations can block users.

##### 4.3.13 External Collaboration Settings
- Guest user access restrictions
- Guest invite restrictions (who can invite guests)
- Collaboration restrictions (allowed/blocked domains)
- External Entra ID collaboration settings
- **M&A Rationale**: Guest access patterns reveal external collaboration needs. Blocked domains may conflict with acquiring company.

##### 4.3.14 Company Branding
- Custom branding configured (yes/no)
- Branded domains
- **M&A Rationale**: Branding must be updated post-acquisition.

---

### 4.4 Exchange Online Module (Invoke-Exchange-Audit.ps1)

**Purpose**: Scope the email migration workload and identify configuration dependencies.

**Required Modules**: `ExchangeOnlineManagement`

**Required Permissions**: `Exchange Administrator` (read-only) or `View-Only Configuration` role

#### Data Points to Collect:

##### 4.4.1 Mailbox Inventory
- All mailboxes by type:
  - **User Mailboxes**: Regular user email
  - **Shared Mailboxes**: Shared team mailboxes
  - **Resource Mailboxes**: Room and equipment
  - **Archive Mailboxes**: In-Place Archive status
  - **Litigation Hold Mailboxes**: Legal hold status
- For each mailbox:
  - PrimarySmtpAddress, UserPrincipalName, DisplayName
  - RecipientTypeDetails
  - LitigationHoldEnabled
  - InPlaceHolds (eDiscovery holds)
  - ArchiveStatus (Active, None)
  - ProhibitSendQuota, IssueWarningQuota
  - UseDatabaseQuotaDefaults
  - RetentionPolicy applied
  - Mailbox size (TotalItemSize, ItemCount)
  - DeletedItemSize (recoverable items)
  - ArchiveSize (if archive enabled)
  - LastLogonTime
  - ForwardingSMTPAddress, DeliverToMailboxAndForward
- **Inactive Mailboxes**: Mailboxes on hold after user deletion
- **M&A Rationale (CRITICAL)**: Mailbox count and size determine migration timeline. Litigation holds must be preserved. Forwarding to external domains is security risk.

##### 4.4.2 Mailbox Size Statistics & Volume Estimates
- Total mailbox count (by type)
- Total data volume (GB) across all mailboxes
- Total archive data volume (GB)
- Total recoverable items volume (GB) - often hidden
- Average mailbox size
- Top 100 largest mailboxes
- **Version history consideration**: Note that mailbox size doesn't include version history overhead
- **M&A Rationale**: Data volume determines migration timeline and network requirements. Hidden data (recoverable items, archive) can be 2-5x visible data.

##### 4.4.3 Distribution Groups & Mail-Enabled Security Groups
- All distribution lists:
  - Name, PrimarySmtpAddress
  - ManagedBy (owners)
  - MemberCount
  - RequireSenderAuthenticationEnabled (allow external senders)
  - HiddenFromAddressListsEnabled
  - MemberJoinRestriction, MemberDepartRestriction
- **Dynamic Distribution Groups**: Groups with LDAP filter membership
- **Mail-Enabled Security Groups**: Groups used for both email and permissions
- **M&A Rationale**: Distribution groups must be migrated or recreated. Dynamic groups require LDAP filter translation.

##### 4.4.4 Public Folder Inventory
- Public folder hierarchy
- Public folder count
- Total public folder size (GB)
- Mail-enabled public folders
- Public folder permissions
- Last access time per folder
- **M&A Rationale (CRITICAL BLOCKER)**: Public folders are complex to migrate. Microsoft recommends migrating to M365 Groups or SharePoint. Large public folder estates (>50GB) are major blockers.

##### 4.4.5 Mail Forwarding Rules
- User-level forwarding:
  - Users with ForwardingSMTPAddress set
  - Forward to external domains (security risk)
  - DeliverToMailboxAndForward setting
- Inbox rules with forwarding:
  - Rules forwarding to external addresses
- **M&A Rationale (CRITICAL SECURITY)**: Forwarding to personal accounts is data exfiltration risk. Must be reviewed before migration.

##### 4.4.6 Transport Rules (Mail Flow Rules)
- All transport rules:
  - Rule name, priority, state (enabled/disabled)
  - Conditions (sender, recipient, subject, attachment, etc.)
  - Actions (reject, redirect, modify, add disclaimer, encrypt)
  - Exceptions
  - Comments
- **Rules to Flag**:
  - Rules forwarding to external addresses
  - Rules modifying message headers
  - Rules with encryption/rights management
  - Rules with journaling
- **M&A Rationale**: Transport rules enforce compliance and security. Rules may break post-migration if they reference on-prem resources.

##### 4.4.7 Inbound/Outbound Connectors
- **Inbound Connectors**:
  - Connector name, enabled/disabled
  - Sender domains/IP ranges
  - RequireTLS, RestrictDomainsToCertificate
  - TreatMessagesAsInternal
- **Outbound Connectors**:
  - Connector name, enabled/disabled
  - Recipient domains
  - Smart host (relay server)
  - TLS settings
  - Authentication method
- **M&A Rationale (CRITICAL)**: Connectors to on-prem Exchange or third-party email security require reconfiguration. Break mail flow if misconfigured.

##### 4.4.8 Hybrid Exchange Configuration
- Hybrid configuration status (yes/no)
- Hybrid Configuration Wizard (HCW) version
- On-premises Exchange version
- Hybrid domains
- Organization relationship (to on-prem)
- Federation trust (to on-prem)
- **M&A Rationale (CRITICAL)**: Hybrid Exchange complicates migration. May need to maintain hybrid during migration.

##### 4.4.9 Retention Policies & Tags
- All retention policies:
  - Policy name
  - Retention tags included
  - Mailboxes assigned
- Retention tags:
  - Tag name, tag type (Delete, Archive, Personal)
  - Retention period
  - Retention action
- **M&A Rationale**: Retention policies enforce compliance. Must be preserved during migration.

##### 4.4.10 Journal Rules
- All journal rules:
  - Rule name, enabled/disabled
  - Scope (internal, external, global)
  - Journal recipient (mailbox or external address)
- **M&A Rationale**: Journaling for compliance must continue uninterrupted during migration.

##### 4.4.11 Accepted Domains
- All accepted domains:
  - Domain name
  - Domain type (Authoritative, Internal Relay, External Relay)
  - Default domain flag
- **M&A Rationale**: Accepted domains determine which email addresses Exchange accepts. Must be updated post-migration.

##### 4.4.12 Email Address Policies
- All email address policies:
  - Policy name, priority
  - Enabled/disabled
  - Recipient filter (which users get the policy)
  - Email address templates (SMTP addresses generated)
- **M&A Rationale**: Email address policies auto-generate proxy addresses. May generate incorrect addresses post-migration.

##### 4.4.13 Remote Domains
- All remote domains:
  - Domain name
  - Out-of-office replies allowed
  - Automatic replies allowed
  - Delivery reports allowed
- **M&A Rationale**: Remote domain settings control message formatting to external domains.

##### 4.4.14 Mobile Device Inventory
- ActiveSync devices:
  - Device type, device model
  - User, device ID
  - First sync time, last sync time
  - Status (allowed, blocked, quarantined)
- **M&A Rationale**: Mobile device wipe policies may apply during migration.

---

### 4.5 SharePoint, OneDrive, Teams Module (Invoke-SPO-Teams-Audit.ps1)

**Purpose**: Scope collaboration platform migration and data volume.

**Required Modules**: `PnP.PowerShell`, `MicrosoftTeams`

**Required Permissions**: SharePoint Administrator, Teams Administrator (read-only)

#### Data Points to Collect:

##### 4.5.1 SharePoint Site Inventory
- All SharePoint sites (SPO):
  - Site URL, title
  - Template (Team Site, Communication Site, Hub Site, Group Site, Classic)
  - Owner, created date, last modified date
  - Storage used (GB), storage quota
  - Sharing capability (Anyone, ExistingExternalUserSharingOnly, ExternalUserSharingOnly, Disabled)
  - Hub site association
  - Sensitivity label applied
  - Number of site collections
- **Hub Sites**: List of hub sites and associated sites
- **Classic Sites**: Sites using classic templates (migration candidates)
- **M&A Rationale**: Site count and storage determine migration timeline. Hub site topology must be preserved. Classic sites may need modernization.

##### 4.5.2 SharePoint Storage Analysis
- Total SharePoint storage used (GB)
- Total storage quota (GB)
- Storage by site template type
- Top 100 largest sites
- **Version History Size**: Estimate version history overhead (not directly queryable, note as limitation)
- **M&A Rationale**: Storage volume determines network requirements. Version history can be 5-10x visible file size.

##### 4.5.3 SharePoint Workflows
- **SharePoint 2010 Workflows**: (Deprecated, migration blocker)
- **SharePoint 2013 Workflows**: (Deprecated, migration blocker)
- **Power Automate Flows**: Modern replacement
- Per site: count of workflows by type
- **M&A Rationale (CRITICAL BLOCKER)**: Legacy workflows (2010/2013) are retired. Must be migrated to Power Automate before or during migration.

##### 4.5.4 SharePoint Custom Solutions & Add-ins
- SharePoint Framework (SPFx) solutions deployed
- SharePoint Add-ins (App Catalog)
- Custom site designs and site scripts
- Custom content types (tenant-level)
- **M&A Rationale**: Custom solutions may break during migration. Must inventory and test.

##### 4.5.5 SharePoint External Sharing
- Tenant-level sharing settings
- Per-site sharing settings
- **Anonymous sharing links**: Count of "Anyone" links
- **External user inventory**: Guests with site access
- Sharing links by type (view, edit, anonymous)
- **M&A Rationale (SECURITY RISK)**: Anonymous links persist after migration and may grant unintended access.

##### 4.5.6 OneDrive for Business Inventory
- All OneDrive sites:
  - Owner (UserPrincipalName)
  - OneDrive URL
  - Storage used (GB), storage quota
  - Last activity date
  - Sharing capability
- Total OneDrive storage used (GB)
- Average OneDrive size
- Inactive OneDrives (no activity in 90+ days)
- **M&A Rationale**: OneDrive data migrates per-user. Inactive OneDrives may not need migration.

##### 4.5.7 Teams Inventory
- All Teams:
  - Team display name, Team ID
  - Visibility (Public, Private)
  - Owner, created date
  - Member count (owners, members, guests)
  - Archived status
  - Group ID (associated M365 Group)
  - Channels count
- **Standard Channels**: Public channels
- **Private Channels**: Private channels (separate SharePoint site per channel)
- **Shared Channels**: Cross-tenant channels (migration blocker)
- **M&A Rationale (CRITICAL)**: Private channels have separate SharePoint sites. Shared channels cannot be migrated to another tenant (must be deleted/recreated).

##### 4.5.8 Teams Apps & Tabs
- Custom Teams apps deployed (tenant app catalog)
- Third-party Teams apps installed
- Tabs configured in channels (custom tabs may break)
- **M&A Rationale**: Custom apps and tabs may not work post-migration.

##### 4.5.9 Microsoft 365 Groups
- All M365 Groups:
  - Group name, email address
  - Visibility (Public, Private)
  - Owners, members count
  - Created date, last activity
  - Group expiration policy applied
  - Resources enabled (Team, SharePoint, Planner, Yammer)
- **Orphaned Groups**: Groups with no owners
- **Inactive Groups**: Groups with no activity in 90+ days
- **M&A Rationale**: M365 Groups are container objects. Deleting a group deletes Team, SharePoint site, Planner, etc.

---

### 4.6 Power Platform Module (Invoke-PowerPlatform-Audit.ps1)

**Purpose**: Inventory low-code applications and automation that may depend on current tenant.

**Required Modules**: `Microsoft.PowerApps.Administration.PowerShell`, `Microsoft.PowerApps.PowerShell`

**Required Permissions**: Power Platform Administrator

#### Data Points to Collect:

##### 4.6.1 Power Platform Environments
- All environments:
  - Environment name, environment ID
  - Environment type (Production, Sandbox, Trial, Default)
  - Region
  - Created by, created date
  - Dataverse database (yes/no)
  - Database size (GB) if Dataverse present
  - Security group assigned (if any)
  - DLP policies applied
- **M&A Rationale (CRITICAL)**: Environments cannot be migrated between tenants. Apps/flows must be exported and imported.

##### 4.6.2 Power Apps Inventory
- All Power Apps (Canvas and Model-Driven):
  - App name, app ID
  - App type (Canvas, Model-Driven)
  - Owner
  - Environment
  - Created date, last modified date
  - Last published date
  - Shared with (users/groups)
  - Connectors used
  - Premium connector usage (yes/no)
- **Premium Connector Detection**: Apps using premium connectors (requires per-app or per-user licenses)
- **On-Premises Data Gateway Usage**: Apps using on-prem gateways (migration blocker)
- **M&A Rationale (CRITICAL)**: Canvas apps can be exported/imported. Model-driven apps tied to Dataverse are complex. Premium connectors affect licensing costs.

##### 4.6.3 Power Automate (Flow) Inventory
- All Flows:
  - Flow name, flow ID
  - Flow type (Automated, Scheduled, Instant, Business Process Flow)
  - Owner
  - Environment
  - State (Started, Suspended, Stopped)
  - Created date, last modified date
  - Connectors used
  - Premium connector usage
  - Runs count (last 30 days)
  - Success rate
- **Flows using on-prem gateways**
- **Flows with SharePoint/Teams triggers**: May break during migration
- **M&A Rationale (CRITICAL)**: Flows must be exported/imported. Flows with hardcoded tenant-specific URLs will break. On-prem gateway flows are blockers.

##### 4.6.4 On-Premises Data Gateways
- All registered gateways:
  - Gateway name, gateway ID
  - Gateway type (Personal, Enterprise)
  - Gateway admin
  - Gateway region
  - Gateway version
  - Status (online/offline)
  - Data sources configured
- **M&A Rationale (CRITICAL BLOCKER)**: Gateways cannot be migrated. Apps/flows using gateways must be reconfigured post-migration.

##### 4.6.5 Custom Connectors
- All custom connectors:
  - Connector name, connector ID
  - Owner
  - Environment
  - Backend API endpoint
  - Authentication method
- **M&A Rationale**: Custom connectors must be recreated in new tenant.

##### 4.6.6 Dataverse (CDS) Inventory
- Environments with Dataverse:
  - Database size (GB)
  - Custom tables (entities) count
  - Custom fields count
  - Relationships count
  - Business rules count
  - Plugins/custom code
- **M&A Rationale (CRITICAL BLOCKER)**: Dataverse data must be migrated using specialized tools. Complex Dataverse solutions are major migration efforts.

##### 4.6.7 Power Platform DLP Policies
- All DLP policies:
  - Policy name
  - Environments applied to (all, specific)
  - Connector classification (Business, Non-Business, Blocked)
  - Default connector classification
- **M&A Rationale**: DLP policies enforce governance. Policies in acquiring tenant may conflict.

##### 4.6.8 Power BI Workspaces (Overview)
- Workspace count (classic vs. new workspaces)
- Workspace admins
- Premium capacity usage
- **M&A Rationale**: Power BI migration is complex. Note: Full Power BI audit is out of scope for this script, recommend separate Power BI Admin API audit.

---

### 4.7 Compliance and Security Module (Invoke-Compliance-Audit.ps1)

**Purpose**: Inventory compliance, data governance, and security configurations.

**Required Modules**: `ExchangeOnlineManagement`, `Microsoft.Graph` (Compliance scopes)

**Required Permissions**: `Compliance Administrator` (read-only), `Security Reader`

#### Data Points to Collect:

##### 4.7.1 Retention Policies (Microsoft 365)
- All retention policies:
  - Policy name
  - Locations (Exchange, SharePoint, OneDrive, Teams, Yammer)
  - Retention duration
  - Retention action (Delete, Retain, Retain then Delete)
  - Included/excluded sites or mailboxes
- **M&A Rationale (CRITICAL)**: Retention policies enforce compliance. Must be preserved or recreated to avoid data loss or compliance violations.

##### 4.7.2 Retention Labels
- All retention labels:
  - Label name
  - Retention settings
  - Label published to (locations)
  - Auto-apply conditions (if any)
  - Record label (yes/no)
- Items with retention labels applied (count)
- **M&A Rationale**: Labels applied to items must be preserved during migration.

##### 4.7.3 Data Loss Prevention (DLP) Policies
- All DLP policies:
  - Policy name, enabled/disabled
  - Locations (Exchange, SharePoint, OneDrive, Teams, Devices)
  - Sensitive info types detected
  - Actions (block, notify, allow with justification)
  - Policy mode (test, test with notifications, enforce)
  - Incident reports sent to
- **M&A Rationale**: DLP policies prevent data leaks. Policies may trigger false positives during migration.

##### 4.7.4 Sensitivity Labels (Information Protection)
- All sensitivity labels:
  - Label name, label ID
  - Parent label (if sub-label)
  - Protection settings (encryption, watermarks, access control)
  - Auto-labeling policies
  - Published to (users/groups)
- Items with sensitivity labels applied (count, if available)
- **M&A Rationale**: Sensitivity labels encrypt data. Encrypted items may not migrate cleanly.

##### 4.7.5 eDiscovery Cases
- All eDiscovery cases:
  - Case name, case type (Core, Advanced)
  - Case status (Active, Closed)
  - Case members (who has access)
  - Holds applied
  - Searches created
  - Exports performed
- **M&A Rationale (CRITICAL)**: Active eDiscovery cases indicate legal matters. Holds must be preserved.

##### 4.7.6 Communication Compliance (Insider Risk)
- Communication compliance policies:
  - Policy name
  - Supervised users
  - Conditions (keywords, sensitive info types)
- **M&A Rationale**: Insider risk monitoring may flag migration activities as suspicious.

##### 4.7.7 Information Barriers
- Information barrier policies:
  - Policy name
  - Segments defined
  - Users in each segment
  - Barrier rules (who can't communicate with whom)
- **M&A Rationale**: Information barriers restrict collaboration. May block migration tasks.

##### 4.7.8 Audit Logging
- Unified Audit Log status (enabled/disabled)
- Audit log retention period
- Mailbox auditing status (per-mailbox or tenant-default)
- **M&A Rationale**: Audit logs provide forensic trail during migration. Ensure enabled.

##### 4.7.9 Alert Policies
- All alert policies:
  - Policy name, category
  - Conditions (what triggers alert)
  - Recipients (who gets notified)
  - Severity (low, medium, high)
- **M&A Rationale**: Alerts may fire during migration (e.g., mass mailbox exports). Plan for alert fatigue.

---

### 4.8 Network and Infrastructure Module (Invoke-Network-Audit.ps1)

**Purpose**: Discover network dependencies and infrastructure services tied to AD.

**Required Modules**: `DnsServer`, `DhcpServer` (if available)

**Required Permissions**: Read access to DNS and DHCP servers

#### Data Points to Collect:

##### 4.8.1 DNS Configuration
- Covered in section 4.1.21 (AD module)

##### 4.8.2 DHCP Configuration
- Covered in section 4.1.22 (AD module)

##### 4.8.3 Network Policy Server (NPS) / RADIUS
- NPS server discovery:
  - Server name
  - Network policies configured
  - Connection request policies
  - RADIUS clients (network devices using NPS)
- **M&A Rationale**: NPS/RADIUS tied to AD for authentication. VPN and Wi-Fi may break if NPS not migrated.

##### 4.8.4 VPN Server Discovery
- RRAS (Routing and Remote Access) servers:
  - Server name
  - VPN protocols enabled (PPTP, L2TP, SSTP, IKEv2)
  - Authentication provider (RADIUS, Windows)
- **M&A Rationale**: VPN tied to AD accounts. VPN users must be migrated carefully.

---

## 5. Migration Gotchas and Common Blockers

This section documents known technical "gotchas" based on community best practices and Microsoft guidance.

### 5.1 Identity and Authentication Gotchas

| **Gotcha** | **Description** | **Impact** | **Mitigation** |
|------------|-----------------|------------|----------------|
| **ADFS to PHS/PTA Cutover** | Switching authentication method requires downtime | HIGH - Users cannot sign in during cutover | Plan for after-hours cutover window. Enable staged rollout. |
| **Immutable ID Mismatch** | Changing source anchor (immutable ID) breaks user sync | CRITICAL - Users duplicate in target tenant | Never change source anchor. Use same AD attribute (ObjectGUID). |
| **Duplicate Proxy Addresses** | Two users with same email alias cause sync errors | MEDIUM - Affected users don't sync | Clean up proxy address conflicts before migration. |
| **Hard-Matched Users** | Cloud user matches on-prem user by UPN/email, but wrong user | CRITICAL - Wrong user gets mailbox | Soft-match validation required. Delete cloud users before sync if needed. |
| **AdminSDHolder Permissions** | Users once in admin groups retain AdminSDHolder ACL | MEDIUM - Permissions inheritance broken | Run SDProp manually or wait for automatic cycle (60 min). |
| **SID History** | SID history required for resource access during migration | HIGH - Users lose access to file shares | Enable SID history in AD Connect. Requires domain trust. |
| **UPN != Email** | User UPN differs from primary email address | MEDIUM - User confusion, sign-in issues | Standardize UPN to match email before migration. |

### 5.2 Exchange Online Gotchas

| **Gotcha** | **Description** | **Impact** | **Mitigation** |
|------------|-----------------|------------|----------------|
| **Public Folder Migration Limit** | Public folders >50GB are slow to migrate | HIGH - Extended migration timeline | Archive or delete old public folder content. Migrate to M365 Groups. |
| **Litigation Hold** | Mailboxes on hold require special handling | CRITICAL - Compliance violation if mishandled | Document all holds. Preserve holds during migration. |
| **Forwarding to External** | Auto-forward to personal email is data leak | CRITICAL - Security risk | Disable external forwarding before migration. |
| **Recoverable Items** | Hidden "dumpster" can be 2x mailbox size | HIGH - Migration takes 3x longer than expected | Include recoverable items in size calculations. |
| **Hybrid Coexistence** | Hybrid Exchange required for staged migration | HIGH - Complex configuration | Deploy Hybrid Configuration Wizard. |
| **Mailbox Permissions** | SendAs, FullAccess, Send on Behalf permissions | MEDIUM - Users lose access to shared mailboxes | Export permissions before migration. Reapply in target. |
| **Shared Mailbox Licensing** | Shared mailboxes >50GB require license | MEDIUM - Unexpected licensing cost | Reduce shared mailbox size or assign license. |

### 5.3 SharePoint and Teams Gotchas

| **Gotcha** | **Description** | **Impact** | **Mitigation** |
|------------|-----------------|------------|----------------|
| **Private Channels** | Each private channel has separate SharePoint site | HIGH - Complex migration | Private channel sites must be migrated separately. |
| **Shared Channels** | Shared channels with external tenants can't migrate | CRITICAL BLOCKER - Must be recreated | Document shared channels. Delete before migration. Recreate after. |
| **SharePoint Workflows** | 2010/2013 workflows are retired | CRITICAL BLOCKER - Workflows stop working | Migrate to Power Automate before migration. |
| **Version History** | 50 versions x 10MB file = 500MB hidden data | HIGH - Storage estimate 5-10x low | Calculate version history overhead. Consider version trimming. |
| **Anonymous Sharing Links** | "Anyone" links persist after migration | CRITICAL - Security risk | Audit and delete anonymous links before migration. |
| **Custom SPFx Solutions** | Custom code may break in target tenant | MEDIUM - Business process disruption | Inventory custom solutions. Test in target tenant. |
| **Site Collection Admins** | Admins defined at site level, not inherited | MEDIUM - Loss of admin access | Export site collection admins. Reapply in target. |
| **Hub Site Topology** | Hub associations don't migrate automatically | MEDIUM - Loss of navigation structure | Document hub topology. Recreate in target. |

### 5.4 Power Platform Gotchas

| **Gotcha** | **Description** | **Impact** | **Mitigation** |
|------------|-----------------|------------|----------------|
| **On-Prem Data Gateways** | Gateways are tenant-specific, cannot migrate | CRITICAL BLOCKER - Apps/flows break | Deploy new gateways in target tenant. Reconfigure apps/flows. |
| **Hardcoded Tenant URLs** | Flows with hardcoded SharePoint URLs break | HIGH - Flows fail after migration | Find/replace tenant URLs during import. Use dynamic URLs. |
| **Dataverse Environments** | Dataverse databases cannot be migrated | CRITICAL BLOCKER - Data loss | Use Dataverse export/import or third-party tools. Complex. |
| **Premium Connectors** | Premium connectors require per-app or per-user licenses | MEDIUM - Licensing cost increase | Inventory premium connector usage. Budget for licenses. |
| **Solution Dependencies** | Complex solutions have dependency chains | HIGH - Import failures | Export as managed solution. Map dependencies. Import in order. |
| **Connection References** | Connections must be recreated by new owner | MEDIUM - Manual effort | Reassign connection ownership post-import. |
| **Environment Variables** | Environment-specific settings hardcoded | MEDIUM - Configuration drift | Use environment variables. Update post-migration. |

### 5.5 Licensing and PIM Gotchas

| **Gotcha** | **Description** | **Impact** | **Mitigation** |
|------------|-----------------|------------|----------------|
| **Group-Based Licensing** | License assignments via group membership | MEDIUM - Complex license mapping | Export group-based license assignments. Recreate in target. |
| **PIM Eligible Assignments** | PIM-eligible roles don't migrate | MEDIUM - Loss of JIT access | Document PIM assignments. Recreate in target tenant. |
| **Trial Licenses** | Trial licenses expire mid-migration | HIGH - Service disruption | Convert trials to paid before migration. |
| **Disabled Users with Licenses** | Disabled users consuming licenses | LOW - Wasted cost | Remove licenses from disabled users before migration. |

### 5.6 Device and Endpoint Gotchas

| **Gotcha** | **Description** | **Impact** | **Mitigation** |
|------------|-----------------|------------|----------------|
| **Hybrid Entra Join** | Devices joined to on-prem AD and Entra ID | HIGH - Devices lose cloud connectivity | Devices must be re-joined or migrated using migration tools. |
| **Intune Enrollment** | Device enrollment tied to tenant | HIGH - Devices unenrolled, lose policies | Devices must re-enroll in target tenant. May require device wipe. |
| **Autopilot** | Autopilot profiles tied to tenant | MEDIUM - Deployment process disrupted | Export Autopilot hardware hashes. Re-import in target. |
| **Conditional Access** | CA policies block unmanaged devices | HIGH - User lockout | Carefully migrate CA policies. Test with pilot users first. |

### 5.7 Compliance and Security Gotchas

| **Gotcha** | **Description** | **Impact** | **Mitigation** |
|------------|-----------------|------------|----------------|
| **Sensitivity Labels** | Labels encrypt data using tenant-specific keys | CRITICAL - Data unreadable post-migration | Decrypt before migration, or use double-key encryption. |
| **Retention Policies** | Retention locks can prevent deletion | HIGH - Cannot delete items for migration | Document retention policies. Ensure new tenant has matching policies. |
| **eDiscovery Holds** | Holds must be preserved for legal compliance | CRITICAL - Legal liability | Maintain holds through migration. Consult legal team. |
| **DLP Policies** | DLP may block bulk data export/import | HIGH - Migration tools blocked | Create DLP policy exceptions for migration accounts. |
| **Customer Key** | Customer-managed encryption keys | CRITICAL BLOCKER - Microsoft cannot migrate | Customer Key data cannot be migrated. Requires re-upload. |

---

## 6. Reporting and Output

### 6.1 Output Structure

The script will generate a timestamped folder with the following structure:

```
Output/
└── [Timestamp]_[CompanyName]/
    ├── Executive-Report.html          # High-level executive summary
    ├── Security-Findings.html         # Security issues and recommendations
    ├── Migration-Blockers.html        # Critical blockers with severity ratings
    ├── Data-Volume-Estimates.html     # Migration scope and timeline estimates
    ├── audit_metadata.json            # Audit execution metadata
    ├── RawData/
    │   ├── AD/
    │   │   ├── AD_Users.csv
    │   │   ├── AD_Computers.csv
    │   │   ├── AD_Groups.csv
    │   │   ├── AD_PrivilegedAccounts.csv
    │   │   ├── AD_DangerousACLs.csv
    │   │   ├── AD_GPOs.csv
    │   │   ├── AD_Trusts.csv
    │   │   ├── AD_ServiceAccounts.csv
    │   │   └── AD_PasswordPolicies.csv
    │   ├── Servers/
    │   │   ├── Server_Inventory_Summary.csv
    │   │   ├── Server_Hardware_Details.csv
    │   │   ├── Server_Storage_Details.csv
    │   │   ├── Server_Network_Adapters.csv
    │   │   ├── Server_Installed_Applications.csv
    │   │   ├── Server_Windows_Roles.csv
    │   │   ├── Server_Windows_Services.csv
    │   │   ├── Server_Event_Log_Critical.csv
    │   │   ├── Server_Event_Log_Errors.csv
    │   │   ├── Server_Current_Users.csv
    │   │   ├── Server_Logon_History.csv
    │   │   ├── Server_Logon_Failures.csv
    │   │   ├── Server_Application_Summary.csv
    │   │   └── Server_Unreachable.csv
    │   ├── SQL/
    │   │   ├── SQL_Instances.csv
    │   │   ├── SQL_Databases.csv
    │   │   ├── SQL_Database_Sizes.csv
    │   │   ├── SQL_Backup_Status.csv
    │   │   ├── SQL_Logins.csv
    │   │   ├── SQL_Agent_Jobs.csv
    │   │   ├── SQL_Job_Schedules.csv
    │   │   ├── SQL_Linked_Servers.csv
    │   │   ├── SQL_AlwaysOn_AGs.csv
    │   │   ├── SQL_Configuration_Issues.csv
    │   │   └── SQL_Azure_Assessment.csv
    │   ├── EntraID/
    │   │   ├── EntraID_Users.csv
    │   │   ├── EntraID_Devices.csv
    │   │   ├── EntraID_Apps.csv
    │   │   ├── EntraID_ConditionalAccess.csv
    │   │   └── EntraID_Licenses.csv
    │   ├── Exchange/
    │   │   ├── Exchange_Mailboxes.csv
    │   │   ├── Exchange_MailboxSizes.csv
    │   │   ├── Exchange_DistributionGroups.csv
    │   │   ├── Exchange_TransportRules.csv
    │   │   └── Exchange_Connectors.csv
    │   ├── SharePoint/
    │   │   ├── SPO_Sites.csv
    │   │   ├── SPO_OneDrive.csv
    │   │   ├── SPO_ExternalSharing.csv
    │   │   └── SPO_Workflows.csv
    │   ├── Teams/
    │   │   ├── Teams_Inventory.csv
    │   │   ├── Teams_PrivateChannels.csv
    │   │   └── Teams_SharedChannels.csv
    │   ├── PowerPlatform/
    │   │   ├── PowerApps.csv
    │   │   ├── PowerAutomate.csv
    │   │   ├── PowerPlatform_Environments.csv
    │   │   └── PowerPlatform_Gateways.csv
    │   └── Compliance/
    │       ├── Compliance_RetentionPolicies.csv
    │       ├── Compliance_DLP.csv
    │       ├── Compliance_SensitivityLabels.csv
    │       └── Compliance_eDiscovery.csv
    └── Logs/
        ├── execution.log              # Detailed execution log
        └── errors.log                 # Errors and warnings
```

### 6.2 Executive Report (HTML) - Key Metrics

The HTML executive report will include:

#### Overview Dashboard
- Audit execution date and time
- Audited by (user account)
- Target organization name
- Completion status (100% or partial with missing modules)
- Data quality score (0-100%)

#### Identity Summary
- Total on-prem AD users (enabled/disabled)
- Total Entra ID users (synced/cloud-only/guest)
- Total computers (workstations/servers/DCs)
- Total groups
- Privileged account count (admins)
- PIM adoption rate (% admin assignments using PIM)
- Authentication method (PHS/PTA/ADFS)

#### Infrastructure Summary
- Domain functional level
- Forest functional level
- Domain Controller count by OS version
- AD CS presence (yes/no)
- ADFS presence (yes/no)
- krbtgt password age (days)

#### Member Server Infrastructure Summary
- **Server Count**:
  - Total servers discovered in AD
  - Servers successfully audited (online, WinRM accessible)
  - Servers offline or unreachable
  - Servers by OS version (Server 2012 R2, 2016, 2019, 2022, etc.)
  - Physical vs. virtual servers (count and %)
- **Hardware Capacity Totals**:
  - Total CPU cores across all servers
  - Total memory (GB) across all servers
  - Total storage capacity (TB) across all servers
  - Total storage used (TB)
  - Average CPU per server
  - Average memory per server (GB)
  - Average storage per server (TB)
- **Server Age & Patch Status**:
  - Servers by OS support status (supported, extended support, end-of-life)
  - End-of-life OS count (Server 2012 R2 and older - critical)
  - Servers with patches >90 days old (count)
  - Servers with pending reboot (count)
  - Average uptime (days)
- **Top 10 Applications Installed** (by server count):
  - Application name
  - Version (most common)
  - Installed on X servers (count and %)
  - Total instances
  - Example: "SQL Server 2016 Standard - Installed on 12 servers (24%)"
- **Critical Applications Summary**:
  - SQL Server instances: [count] (list editions: Express, Standard, Enterprise)
  - IIS/Web Servers: [count]
  - On-premises Exchange: [count] (migration blocker)
  - On-premises SharePoint: [count] (migration blocker)
  - ADFS servers: [count]
  - Other key server roles (counts)
- **Server Roles Distribution**:
  - File Servers: [count]
  - Print Servers: [count]
  - DNS Servers: [count]
  - DHCP Servers: [count]
  - Hyper-V Hosts: [count]
  - Failover Clusters: [count]
- **Operational Health Indicators**:
  - Servers with >100 critical events (last 30 days): [count]
  - Servers with disk errors detected: [count]
  - Servers with unexpected shutdowns: [count]
  - Servers with high failed logon attempts (>100/day): [count]
- **Service Account Usage**:
  - Domain service accounts in use on servers: [count]
  - Servers with services using domain accounts: [count]
  - Unique service accounts detected: [list top 10]
- **Azure Migration Sizing Estimate**:
  - Recommended Azure VM SKUs (by server CPU/memory profile)
  - Estimated monthly Azure compute cost (ballpark)
  - Note: Actual sizing requires performance monitoring data

#### SQL Server Database Summary
- **SQL Server Instances**:
  - Total SQL Server instances: [count]
  - Instances by version (2012, 2014, 2016, 2017, 2019, 2022)
  - Instances by edition (Express, Standard, Enterprise)
  - End-of-life instances (SQL 2012 and older): [count] - **CRITICAL**
  - Total SQL Server cores (for licensing): [count]
- **Database Inventory**:
  - Total user databases: [count]
  - Total database storage: [TB]
  - Average database size: [GB]
  - Largest database: [name, size]
  - Databases in Always On Availability Groups: [count]
- **Backup & Recovery Status**:
  - Databases with no backup in 7+ days: [count] - **CRITICAL RISK**
  - Databases in FULL recovery without log backups: [count] - **HIGH RISK**
  - Databases in SUSPECT/EMERGENCY state: [count] - **CRITICAL**
- **SQL Server Logins & Security**:
  - Total SQL Server logins: [count]
  - SQL authentication logins: [count]
  - Logins with sysadmin: [count]
  - Orphaned logins: [count]
- **SQL Agent Jobs**:
  - Total SQL Agent jobs: [count]
  - Failed jobs (last run): [count]
  - Jobs calling external resources: [count] (may break post-migration)
- **Linked Servers**:
  - Total linked servers: [count]
  - Linked servers to external orgs: [count] - **MIGRATION BLOCKER**
- **Azure SQL Migration Estimate**:
  - Recommended for Azure SQL Database: [count] databases
  - Recommended for Azure SQL Managed Instance: [count] databases
  - Recommended for SQL Server on Azure VM: [count] instances
  - Estimated monthly Azure SQL cost: $[X],000 - $[Y],000
  - Potential Azure Hybrid Benefit savings: 40-50% with existing licenses

#### Security Findings
- **Critical**: Dangerous ACLs found (count)
- **High**: Accounts with unconstrained delegation (count)
- **High**: Privileged accounts without MFA (count)
- **Medium**: Users with password never expires (count)
- **Medium**: Stale accounts (count, >90 days)
- **Low**: Empty groups (count)

#### Migration Blockers (with severity)
- **Critical**: Public folders detected (size in GB)
- **Critical**: Shared Teams channels detected (count)
- **Critical**: SharePoint 2010/2013 workflows (count)
- **Critical**: Power Platform on-prem gateways (count)
- **High**: ADFS federation detected
- **High**: Dataverse environments (count, total size)
- **High**: Sensitivity labels with encryption (count)

#### Data Volume Estimates
- **Exchange**:
  - Total mailboxes: [count]
  - Total mailbox size: [GB]
  - Average mailbox size: [GB]
  - Estimated migration time: [days] (assuming 10GB/hour)
- **SharePoint**:
  - Total sites: [count]
  - Total storage: [GB]
  - Estimated migration time: [days]
- **OneDrive**:
  - Total OneDrive sites: [count]
  - Total storage: [GB]
  - Estimated migration time: [days]
- **Teams**:
  - Total teams: [count]
  - Standard channels: [count]
  - Private channels: [count]
- **Power Platform**:
  - Environments: [count]
  - Power Apps: [count]
  - Power Automate flows: [count]

#### Licensing Summary
- Total licensed users
- License SKUs (by type and count)
- Inactive licenses (licensed but no sign-in >90 days)
- Estimated monthly licensing cost

#### Compliance and Security
- Retention policies: [count]
- DLP policies: [count]
- Sensitivity labels: [count]
- Active eDiscovery cases: [count]
- Litigation holds: [count]

### 6.3 Validation and Quality Checks

The script will perform automatic validation:

| **Check** | **Validation Rule** | **Action if Failed** |
|-----------|---------------------|----------------------|
| User count | If AD users = 0 | Flag as ERROR, likely permission issue |
| Entra users vs. AD users | If Entra users < 50% of AD users | Flag as WARNING, sync issue possible |
| Mailbox count vs. Entra users | If mailboxes > Entra users | Flag as WARNING, shared mailboxes or data quality |
| Zero storage | If SPO storage = 0 GB | Flag as ERROR, permission or config issue |
| Module failures | If any module fails completely | Flag as ERROR, indicate affected areas |
| Execution time | If module takes >2x expected time | Flag as WARNING, possible throttling |

**Data Quality Score Calculation**:
- Start at 100%
- Deduct 10% for each module that fails completely
- Deduct 5% for each validation warning
- Deduct 15% for each validation error
- Display score prominently in report

---

## 7. Execution and Prerequisites

### 7.1 Platform Requirements
- **Operating System**: Windows 10/11, Windows Server 2016+
- **PowerShell Version**: Windows PowerShell 5.1 or PowerShell 7+
- **Execution Policy**: RemoteSigned or Unrestricted (for session only)

### 7.2 Required PowerShell Modules

| **Module** | **Minimum Version** | **Purpose** |
|------------|---------------------|-------------|
| ActiveDirectory | Built-in on DC/RSAT | AD discovery |
| GroupPolicy | Built-in on DC/RSAT | GPO inventory |
| DnsServer | Built-in on DC/RSAT | DNS inventory (optional) |
| DhcpServer | Built-in on DC/RSAT | DHCP inventory (optional) |
| Microsoft.Graph | 2.0+ | Entra ID, compliance |
| ExchangeOnlineManagement | 3.0+ | Exchange Online |
| PnP.PowerShell | 2.0+ | SharePoint, OneDrive |
| MicrosoftTeams | 5.0+ | Teams inventory |
| Microsoft.PowerApps.Administration.PowerShell | Latest | Power Platform |

### 7.3 Required Permissions

#### On-Premises Active Directory
- **Minimum**: Domain User (read-only) in target AD forest
- **Optional**: Read access to DNS/DHCP servers

#### Microsoft Entra ID (Graph API)
- Directory.Read.All
- Policy.Read.All
- Application.Read.All
- RoleManagement.Read.All
- Device.Read.All
- User.Read.All
- Group.Read.All
- Organization.Read.All

#### Exchange Online
- View-Only Configuration (role)
- Or Exchange Administrator (read-only)

#### SharePoint Online
- SharePoint Administrator (read-only)

#### Microsoft Teams
- Teams Administrator (read-only)

#### Power Platform
- Power Platform Administrator (read-only)

#### Security & Compliance
- Security Reader
- Compliance Administrator (read-only)

### 7.4 Execution Examples

#### Full Audit (All Modules)
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -ADCredential (Get-Credential) `
    -OutputFolder "C:\Audits\Contoso" `
    -Verbose
```

#### Full Audit with Custom Server Inventory Settings
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -ADCredential (Get-Credential) `
    -OutputFolder "C:\Audits\Contoso" `
    -ServerInventory `
    -ServerEventLogDays 30 `
    -ServerLogonHistoryDays 90 `
    -IncludeServerServices `
    -MaxParallelServers 10 `
    -Verbose
```

**Configuration Parameters** (Server Inventory):
- `-ServerInventory`: Enable detailed server hardware and application inventory (default: $true)
- `-ServerEventLogDays`: Number of days to query event logs (default: 30, options: 7/30/60/90)
- `-ServerLogonHistoryDays`: Number of days for logon history analysis (default: 90, options: 30/60/90/180/365)
- `-IncludeServerServices`: Include Windows services inventory (verbose, default: $false)
- `-MaxParallelServers`: Number of servers to query in parallel (default: 10, max: 50)
- `-ServerQueryTimeout`: Timeout in seconds per server (default: 300 = 5 minutes)
- `-SkipOfflineServers`: Skip servers that don't respond to ping (default: $true)
- `-SkipEventLogs`: Skip event log collection (faster, default: $false)
- `-SkipLogonHistory`: Skip logon history collection (faster, default: $false)

#### Cloud-Only Audit (No AD)
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -SkipAD `
    -OutputFolder "C:\Audits\Contoso" `
    -Verbose
```

#### AD and Server Inventory Only (Fast)
```powershell
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -ADCredential (Get-Credential) `
    -OutputFolder "C:\Audits\Contoso" `
    -OnlyAD `
    -ServerInventory `
    -Verbose
```

#### Single Module (Exchange Only)
```powershell
.\Modules\Invoke-Exchange-Audit.ps1 `
    -OutputFolder "C:\Audits\Contoso\Exchange" `
    -Verbose
```

### 7.5 Estimated Execution Times

| **Environment Size** | **User Count** | **Server Count** | **Estimated Time** | **Notes** |
|----------------------|----------------|------------------|--------------------|-----------| 
| Small | <500 | <25 | 30-60 minutes | Includes detailed server inventory |
| Medium | 500-5,000 | 25-100 | 2-4 hours | Server event log queries add 1-2 hours |
| Large | 5,000-25,000 | 100-500 | 6-10 hours | Parallel server processing recommended |
| Enterprise | 25,000+ | 500+ | 12-24 hours | May require multiple audit runs |

**Execution Time by Module** (approximate):

| **Module** | **Small** | **Medium** | **Large** | **Enterprise** |
|------------|-----------|------------|-----------|----------------|
| AD Audit (basic) | 5-10 min | 15-30 min | 30-60 min | 1-2 hours |
| Server Hardware Inventory | 10-20 min | 30-90 min | 2-4 hours | 6-10 hours |
| Server Event Logs & Logon History | 5-10 min | 30-60 min | 2-3 hours | 4-6 hours |
| Entra ID Audit | 5-10 min | 15-30 min | 30-60 min | 1-2 hours |
| Exchange Online | 5-10 min | 20-40 min | 1-2 hours | 3-5 hours |
| SharePoint/Teams | 5-10 min | 15-30 min | 1-2 hours | 2-4 hours |
| Power Platform | 2-5 min | 5-10 min | 10-20 min | 30-60 min |
| Compliance | 2-5 min | 5-10 min | 15-30 min | 30-60 min |

*Note: Times assume no API throttling and good network connectivity. Large tenants may experience throttling. Server inventory times assume WinRM is enabled and firewalls allow remote access.*

**Performance Factors**:
- **Server event log size**: Large Security logs (>1GB) significantly slow queries
- **Network latency**: Remote servers over WAN links take longer
- **WinRM configuration**: Servers with WinRM disabled cannot be audited remotely
- **Firewall rules**: Blocked WMI/WinRM ports prevent server inventory
- **Parallel processing**: Batching server queries in parallel reduces total time
- **API throttling**: Microsoft Graph may throttle large tenant queries

---

## 8. Risks and Mitigation

| **Risk** | **Impact** | **Mitigation** |
|----------|-----------|----------------|
| **Insufficient Permissions** | Script fails, incomplete data | Pre-flight permission checks. Clear error messages indicating missing permissions. |
| **API Throttling** | Script slows or fails | Exponential backoff retry logic. Batch API requests. Progress checkpoints for resume capability. |
| **Accidental Write Operations** | Data modification or deletion | All cmdlets are read-only (Get-*, Read-*). Code review enforces no Set-*, Remove-*, New-* cmdlets. |
| **Performance on Large Tenants** | Script takes 12+ hours | Parallel module execution. Stream large datasets to disk. Progress indicators. |
| **Data Security** | Sensitive data exposed | Encrypt output folder. Restrict folder permissions. Audit log of who ran script. |
| **Module Dependency Failures** | Missing modules break script | Graceful degradation. Optional modules don't halt execution. |
| **Network Interruptions** | Long-running script interrupted | Resume capability using checkpoint files. |
| **Shadow IT Discovery Failure** | Power Platform data inaccessible | Clearly indicate in report if Power Platform module failed due to permissions. |
| **Version Compatibility** | Script breaks on old PowerShell/modules | Check versions in pre-flight. Provide upgrade guidance. |
| **Customer Key Encryption** | Data cannot be read by script | Flag encrypted items in report. Note limitation. |

---

## 9. Manual Verification Checklist

This section lists critical discovery items that **cannot be reliably automated** and require direct inquiry with the target organization's IT team.

| **Check Item** | **Questions to Ask** | **M&A Rationale** |
|----------------|----------------------|-------------------|
| **AD Backup & Recovery** | What is the backup solution for AD? When was the last successful System State backup? When was the last recovery test (forest recovery drill)? | A poor answer indicates major operational risk. AD corruption during migration could be catastrophic without recent backups. |
| **Server Patch Status** | What is the patching solution (WSUS, SCCM, Intune, third-party)? Can you provide a patch compliance report for all Domain Controllers? What is the patch cadence (monthly, quarterly)? | Reveals patching discipline and security hygiene. Unpatched DCs are significant security risks and may be incompatible with new features. |
| **Internal Certificate Inventory** | Can you provide an inventory of internal SSL/TLS certificates (for IIS, ADFS, load balancers, etc.) and their expiry dates? What is the renewal process? | Expired certificates are a leading cause of service outages. Certificate-based authentication breaks if certs expire during migration. |
| **Physical Hardware & Virtualization** | What hypervisor is used (Hyper-V, VMware, cloud-hosted)? What is the age of the physical hosts? Are servers under warranty or maintenance contracts? Any plans to refresh hardware? | Identifies infrastructure-related technical debt. Aging hardware may fail during migration stress testing. |
| **Network Infrastructure** | Are there any hardware VPNs, RADIUS/NPS servers, or complex routing configurations tied to AD authentication? Any site-to-site VPNs between offices? | Discovers dependencies invisible from within AD itself. VPN/RADIUS tied to AD affects remote users during migration. |
| **Backup and DR for M365** | Is there a third-party M365 backup solution (Veeam, AvePoint, etc.)? What is the retention period? Can you restore individual items? | Microsoft's native retention is limited. Third-party backups may not be compatible with target tenant. |
| **Third-Party Security Tools** | What third-party security tools are integrated with Entra ID (Okta, Duo, RSA, CyberArk, etc.)? | Third-party MFA or PAM solutions may break during migration. |
| **Managed Service Providers** | Does an MSP manage part or all of the IT infrastructure? Do they have admin access? | MSP contracts may complicate access to systems. MSP may resist migration due to revenue loss. |
| **Compliance and Legal** | Are there any active legal holds, litigation, or regulatory audits in progress? Any industry-specific compliance requirements (HIPAA, PCI-DSS, FedRAMP)? | Active legal matters affect data handling. Compliance requirements may restrict migration methods. |
| **Network Bandwidth** | What is the available Internet bandwidth? Any WAN acceleration or caching appliances? Data egress costs? | Bandwidth limits migration speed. Cloud providers may charge for data egress. |
| **M365 Tenant History** | Has the tenant been involved in previous M&A activity (merged or split)? Are there any known tenant issues or support cases with Microsoft? | Previous migrations may have left configuration issues. Open support cases may indicate problems. |
| **Service Accounts Documentation** | Is there documentation of all service accounts, what they're used for, and who owns them? | Undocumented service accounts are a major blocker. Breaking service accounts stops business processes. |
| **Business-Critical Applications** | What are the top 10 business-critical applications? Which depend on AD, Entra ID, or M365? | Critical apps must be tested extensively before cutover. Downtime risk assessment. |
| **Scheduled Downtime Windows** | What are acceptable maintenance windows for infrastructure changes? Any blackout periods (fiscal year-end, busy season)? | Migration activities may require brief downtime. Business blackout periods extend project timeline. |

---

## 10. Future Enhancements (Out of Scope for v2.0)

The following items are identified as valuable but out of scope for the current version:

1. **Power BI Deep Audit**: Full Power BI workspace, dataset, and gateway inventory
2. **Intune/Endpoint Manager**: Full device configuration profile and compliance policy audit
3. **Azure Resource Audit**: Azure subscriptions, VMs, storage accounts tied to tenant
4. **Yammer/Viva Engage**: Community and conversation inventory
5. **Microsoft Defender**: Security alerts, threat detection policies
6. **Azure AD B2C**: External identity tenant audit
7. **Change Tracking**: Compare audit results over time to detect configuration drift
8. **Remediation Automation**: Auto-fix common hygiene issues (empty groups, stale accounts)
9. **Migration Planning**: Automated migration project plan generation
10. **Cost Estimation**: Detailed cost model for migration services and tools

---

## 11. Appendix

### 11.1 Glossary

- **ADFS**: Active Directory Federation Services - On-premises federation server
- **DFL**: Domain Functional Level - AD feature level for a single domain
- **FFL**: Forest Functional Level - AD feature level for entire forest
- **FGPP**: Fine-Grained Password Policy - Per-user/group password policies
- **FSMO**: Flexible Single Master Operation - Special DC roles in AD
- **PHS**: Password Hash Synchronization - Hybrid identity method syncing password hashes to cloud
- **PIM**: Privileged Identity Management - Just-in-time admin access
- **PTA**: Pass-Through Authentication - Hybrid identity method authenticating against on-prem AD
- **SPN**: Service Principal Name - Kerberos service identifier
- **UPN**: User Principal Name - User's logon name (user@domain.com format)

### 11.2 References

- [Microsoft Entra ID Documentation](https://learn.microsoft.com/en-us/entra/identity/)
- [Exchange Online Migration Guide](https://learn.microsoft.com/en-us/exchange/mailbox-migration/mailbox-migration)
- [SharePoint Migration Assessment Tool](https://learn.microsoft.com/en-us/sharepointmigration/overview-of-the-sharepoint-migration-assessment-tool)
- [Power Platform Migration Guide](https://learn.microsoft.com/en-us/power-platform/admin/move-environment-tenant)
- [AD CS Security Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ad-cs-security-guidance)

---

**Author**: Adrian Johnson <adrian207@gmail.com>  
**Document Version**: 2.0  
**Last Updated**: October 20, 2025  
**Status**: Design Complete - Ready for Implementation

