# AD-Audit PowerShell Module

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/AD-Audit.svg)](https://www.powershellgallery.com/packages/AD-Audit)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/AD-Audit.svg)](https://www.powershellgallery.com/packages/AD-Audit)
[![GitHub release](https://img.shields.io/github/release/yourusername/AD-Audit.svg)](https://github.com/yourusername/AD-Audit/releases)
[![GitHub license](https://img.shields.io/github/license/yourusername/AD-Audit.svg)](https://github.com/yourusername/AD-Audit/blob/main/LICENSE)

A comprehensive PowerShell module for Active Directory security auditing, remediation, and monitoring based on Microsoft's official security best practices and guidelines.

## 🚀 **Features**

### **8 Comprehensive Security Modules**

#### **1. Core Active Directory Auditing** (`Invoke-AD-Audit.ps1`)
- ✅ **User Account Analysis**: Stale accounts, password policies, group memberships
- ✅ **Computer Account Management**: Computer inventory, service accounts, stale computers
- ✅ **Group Policy Analysis**: GPO configuration, inheritance, security settings
- ✅ **Domain Controller Security**: DC configuration, replication, trust relationships
- ✅ **Server Inventory**: Hardware, software, services, event logs, logon history

#### **2. Credential Theft Prevention** (`Invoke-CredentialTheftPrevention.ps1`)
- ✅ **Permanently Privileged Account Detection**: Identifies accounts with permanent elevated privileges
- ✅ **VIP Account Protection**: Special monitoring for high-value accounts
- ✅ **Privileged Account Usage Monitoring**: Tracks privileged account logon patterns
- ✅ **Credential Exposure Detection**: Identifies potential credential exposure risks
- ✅ **Administrative Host Security**: Verifies security of administrative workstations

#### **3. Domain Controller Security** (`Invoke-DomainControllerSecurity.ps1`)
- ✅ **DC Hardening Verification**: Verifies domain controller security hardening
- ✅ **Physical Security Assessment**: Assesses physical security of domain controllers
- ✅ **Application Allowlist Verification**: Verifies application allowlisting
- ✅ **Configuration Baseline Compliance**: Verifies configuration baseline compliance
- ✅ **Security Configuration Analysis**: Analyzes security configuration settings

#### **4. Least Privilege Assessment** (`Invoke-LeastPrivilegeAssessment.ps1`)
- ✅ **RBAC Analysis**: Role-Based Access Control analysis
- ✅ **Privilege Escalation Detection**: Detects privilege escalation attempts
- ✅ **Cross-System Privilege Analysis**: Analyzes privileges across systems
- ✅ **Administrative Model Evaluation**: Evaluates administrative models
- ✅ **Access Control Review**: Reviews access control configurations

#### **5. Legacy System Management** (`Invoke-LegacySystemManagement.ps1`)
- ✅ **Legacy System Identification**: Identifies legacy systems and applications
- ✅ **Isolation Verification**: Verifies isolation of legacy systems
- ✅ **Decommissioning Planning**: Creates decommissioning plans
- ✅ **Risk Assessment**: Assesses risks associated with legacy systems
- ✅ **Migration Planning**: Plans migration from legacy systems

#### **6. Advanced Threat Detection** (`Invoke-AdvancedThreatDetection.ps1`)
- ✅ **Advanced Audit Policy Verification**: Verifies Advanced Audit Policy configuration
- ✅ **Compromise Indicators**: Detects compromise indicators
- ✅ **Lateral Movement Detection**: Detects lateral movement attempts
- ✅ **Persistence Detection**: Detects persistence mechanisms
- ✅ **Data Exfiltration Monitoring**: Monitors data theft attempts

#### **7. AD FS Security Audit** (`Invoke-ADFSSecurityAudit.ps1`)
- ✅ **Service Configuration Analysis**: AD FS farm, properties, and SSL certificate analysis
- ✅ **Authentication Configuration**: Authentication providers, MFA, and lockout protection
- ✅ **Authorization Configuration**: Access control policies and device authentication
- ✅ **RPT/CPT Configuration**: Relying Party Trusts and Claims Provider Trusts analysis
- ✅ **Sign-In Experience**: Web themes, SSO settings, and user experience configuration

#### **8. Event Monitoring** (`Invoke-EventMonitoring.ps1`)
- ✅ **High Criticality Events**: Immediate investigation required events (9 event types)
- ✅ **Medium Criticality Events**: Conditional investigation events (100+ event types)
- ✅ **Low Criticality Events**: Baseline monitoring events (13 event types)
- ✅ **Audit Policy Events**: Audit policy change monitoring
- ✅ **Compromise Indicator Events**: Security compromise detection events

#### **9. AD DS Auditing** (`Invoke-ADDSAuditing.ps1`)
- ✅ **Directory Service Access Events**: Event ID 4662 monitoring
- ✅ **Directory Service Changes Events**: Event IDs 5136-5141 with old/new value tracking
- ✅ **Directory Service Replication Events**: Event IDs 4928-4939 monitoring
- ✅ **SACL Analysis**: System Access Control List configuration analysis
- ✅ **Schema Auditing Configuration**: Schema attribute auditing analysis

### **Master Orchestration**
- ✅ **Unified Execution**: Single command execution across all modules
- ✅ **Priority-Based Processing**: Critical, High, Medium, Low priority processing
- ✅ **Dry-Run Mode**: Preview mode for safe testing
- ✅ **Comprehensive Reporting**: HTML reports, CSV exports, executive dashboards
- ✅ **Email Notifications**: Automated email alerts and reports

## 📋 **Prerequisites**

- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core)
- **Active Directory Module** (`RSAT-AD-PowerShell`)
- **Domain Admin Rights** (for comprehensive auditing)
- **SQLite Database** (for data storage)
- **Network Connectivity** (to domain controllers and servers)

## 🚀 **Installation**

### **From PowerShell Gallery**
```powershell
Install-Module -Name AD-Audit -Force
```

### **From GitHub**
```powershell
# Clone the repository
git clone https://github.com/yourusername/AD-Audit.git
cd AD-Audit

# Import the module
Import-Module .\AD-Audit.psd1
```

### **Manual Installation**
1. Download the latest release from [GitHub Releases](https://github.com/yourusername/AD-Audit/releases)
2. Extract to your PowerShell modules directory
3. Import the module: `Import-Module AD-Audit`

## 📖 **Quick Start**

### **Comprehensive Security Audit**
```powershell
# Execute all security modules
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "All"

# Execute specific security modules
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "CredentialTheft,DomainController,ADFS,EventMonitoring,ADDSAuditing" -Priority "Critical"

# Dry-run mode for testing
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "All" -DryRun
```

### **Individual Module Execution**
```powershell
# Core AD auditing
.\Invoke-AD-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# Credential theft prevention
.\Invoke-CredentialTheftPrevention.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# Domain controller security
.\Invoke-DomainControllerSecurity.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# Least privilege assessment
.\Invoke-LeastPrivilegeAssessment.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# Legacy system management
.\Invoke-LegacySystemManagement.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# Advanced threat detection
.\Invoke-AdvancedThreatDetection.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# AD FS security audit
.\Invoke-ADFSSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# Event monitoring
.\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# AD DS auditing
.\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll
```

## 📊 **Microsoft Compliance**

### **100% Coverage of Microsoft Recommendations**
- ✅ **Active Directory Security Best Practices**: Complete implementation
- ✅ **AD FS Operations**: Complete AD FS security auditing
- ✅ **Events to Monitor (Appendix L)**: Complete event monitoring
- ✅ **AD DS Auditing Step-by-Step Guide**: Complete AD DS auditing with value tracking

### **Security Standards Compliance**
- ✅ **NIST Cybersecurity Framework**: Comprehensive coverage
- ✅ **CIS Controls**: Critical security controls implementation
- ✅ **ISO 27001**: Information security management compliance
- ✅ **SOC 2**: Security and availability controls

## 📈 **Performance**

- **Parallel Processing**: Multi-threaded execution for large environments
- **Efficient Database Operations**: Optimized SQLite operations
- **Memory Management**: Optimized memory usage for large datasets
- **Progress Tracking**: Real-time progress indicators
- **Error Recovery**: Graceful error handling and recovery

## 🔧 **Configuration**

### **Database Configuration**
```powershell
# Create audit database
$DatabasePath = "C:\Audits\AuditData.db"
New-Item -Path (Split-Path $DatabasePath) -ItemType Directory -Force
```

### **Output Configuration**
```powershell
# Configure output paths
$OutputPath = "C:\Audits\Reports"
$LogPath = "C:\Audits\Logs"
```

### **Email Configuration**
```powershell
# Configure email notifications
$EmailConfig = @{
    SMTP Server = "smtp.company.com"
    Port = 587
    From = "ad-audit@company.com"
    To = "security@company.com"
    UseSSL = $true
}
```

## 📚 **Documentation**

- **[Installation Guide](docs/INSTALLATION.md)** - Complete installation instructions
- **[User Guide](docs/USER_GUIDE.md)** - Comprehensive user documentation
- **[Quick Start Guide](docs/QUICK_START.md)** - Quick start instructions
- **[Remediation Guide](docs/REMEDIATION_GUIDE.md)** - Remediation procedures
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Common issues and solutions

### **Module-Specific Documentation**
- **[Credential Theft Prevention Guide](docs/CREDENTIAL_THEFT_PREVENTION_GUIDE.md)**
- **[Domain Controller Security Guide](docs/DOMAIN_CONTROLLER_SECURITY_GUIDE.md)**
- **[Least Privilege Assessment Guide](docs/LEAST_PRIVILEGE_ASSESSMENT_GUIDE.md)**
- **[Legacy System Management Guide](docs/LEGACY_SYSTEM_MANAGEMENT_GUIDE.md)**
- **[Advanced Threat Detection Guide](docs/ADVANCED_THREAT_DETECTION_GUIDE.md)**
- **[AD FS Security Audit Guide](docs/ADFS_SECURITY_AUDIT_GUIDE.md)**
- **[Event Monitoring Guide](docs/EVENT_MONITORING_GUIDE.md)**
- **[AD DS Auditing Guide](docs/ADDS_AUDITING_GUIDE.md)**

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### **Development Setup**
```powershell
# Clone the repository
git clone https://github.com/yourusername/AD-Audit.git
cd AD-Audit

# Install dependencies
Install-Module -Name Pester -Force
Install-Module -Name PSScriptAnalyzer -Force

# Run tests
.\Tests\RunTests.ps1
```

## 🐛 **Bug Reports**

Please report bugs using our [Issue Template](ISSUE_TEMPLATE.md) or create an issue on GitHub.

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 **Authors**

- **Adrian Johnson** <adrian207@gmail.com> - *Lead Developer*

## 🙏 **Acknowledgments**

- Microsoft for providing comprehensive security guidance and best practices
- PowerShell community for excellent tools and resources
- Contributors and users for feedback and improvements

## 📞 **Support**

- **GitHub Issues**: [Create an issue](https://github.com/yourusername/AD-Audit/issues)
- **Email**: adrian207@gmail.com
- **Documentation**: [Full Documentation](docs/)

## 🔄 **Changelog**

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

---

**⭐ Star this repository if you find it useful!**

**🔔 Watch for updates and new features!**

**🤝 Contribute to make it even better!**