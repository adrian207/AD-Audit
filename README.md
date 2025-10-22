# M&A Technical Discovery Audit Tool

![Tests](https://github.com/adrian207/AD-Audit/workflows/Pester%20Tests/badge.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Version](https://img.shields.io/badge/version-2.3.0-green)
![License](https://img.shields.io/badge/license-MIT-blue)

**Author**: Adrian Johnson <adrian207@gmail.com>  
**Version**: 2.3.0 - With Advanced Analytics & Reporting

## Quick Start (3 Simple Steps)

### 1. Double-click to start:
```
Start-M&A-Audit-GUI.ps1
```

### 2. Fill in the form:
- Enter company name
- Choose where to save results
- Select what to audit (Active Directory, Servers, SQL)

### 3. Click "Start Audit"

That's it! The audit runs automatically and saves all results to your chosen folder.

---

## What You Get

**After 1-4 hours**, you'll have:

✅ **Executive Dashboard** (HTML report)
- Company infrastructure overview
- Migration blocker analysis  
- Security risk assessment
- Data volume estimates

✅ **60+ Detailed Reports** (CSV files)
- Server inventory with hardware specs
- SQL databases, logins, jobs, and backup status
- User and computer lists
- Security and configuration details

✅ **Encrypted & Secure**
- All results encrypted by default
- No passwords or sensitive data collected
- Read-only operations (no changes made)

---

## 🚀 New in v2.3.0 - Advanced Analytics & Reporting

### ✅ Complete Analytics Engine
Transform audit data into actionable intelligence:

**Baseline Comparison**: Track changes between audits
- User, computer, server, and privileged account growth
- SQL database size changes
- Percent change calculations

**Anomaly Detection**: Automatically discover 7 types of security risks
- Privileged account growth (>10%)
- Stale privileged accounts
- Service account password issues
- Kerberos unconstrained delegation
- Dangerous ACL permissions
- Database growth (>20%)
- Servers going offline

**Risk Scoring**: Quantify security posture (0-100 score)
- Low Risk (80-100) ✅
- Medium Risk (60-79) ⚠️
- High Risk (40-59) 🔴
- Critical Risk (0-39) 🚨

**Executive Dashboards**: Beautiful HTML reports
- Risk gauge with color-coded levels
- Animated metric cards
- Anomaly cards with recommendations
- Responsive design (mobile-friendly)
- Professional branding

**Alert System**: Proactive email notifications
- Configurable thresholds
- HTML-formatted emails
- Critical/High/Medium severity levels
- Automatic triggering

**Quick Start**:
```powershell
.\Start-M&A-Analytics.ps1 `
    -BaselineAuditPath "baseline.db" `
    -CurrentAuditPath "current.db" `
    -OutputFolder "C:\Analytics" `
    -CompanyName "Contoso" `
    -GenerateDashboard `
    -EnableAlerts `
    -AlertEmail "admin@contoso.com" `
    -SMTPServer "smtp.office365.com" `
    -FromEmail "audit@contoso.com"
```

**See**: `docs/ANALYTICS_GUIDE.md` for complete documentation

---

## 🎉 New in v2.1.0 - Advanced AD Security Components

### ✅ 9 New Security Analysis Functions
- **ACL Analysis**: Detects dangerous permissions on critical AD objects
- **Kerberos Delegation**: Identifies unconstrained/constrained delegation risks
- **DHCP Scope Analysis**: Inventory and utilization of DHCP scopes
- **GPO Inventory**: Comprehensive Group Policy Object analysis
- **Service Account Analysis**: Security posture of accounts with SPNs
- **AD Trust Relationships**: Trust configuration and security assessment
- **Password Policies**: Default + fine-grained password policy audit
- **DNS Zone Inventory**: DNS zone and record analysis
- **Certificate Services**: ADCS infrastructure inventory

**See**: `docs/AD_SECURITY_COMPONENTS.md` for complete documentation

### ✅ Quality Improvements
- **Zero linter errors**: All code meets PowerShell best practices
- **118+ tests**: Added 9 new tests for AD security components
- **~78% code coverage**: Improved test coverage
- **Complete documentation**: New dedicated AD security guide

---

## 🎊 Enterprise Features (v2.0.0)

### ✅ CI/CD Integration
- **GitHub Actions** workflow for automated testing
- **Azure DevOps** pipeline configuration
- Automated test execution on every commit
- Code coverage reporting (~75%)
- PowerShell Script Analyzer linting

### ✅ Professional Packaging
- **PowerShell module manifest** (`AD-Audit.psd1`)
- Installable via `Import-Module`
- Ready for PowerShell Gallery
- Versioned releases with semantic versioning

### ✅ Email Notifications
- **Automated email alerts** when audit completes
- Beautiful HTML email with audit summary
- Module success/failure breakdown
- Data quality score and metrics
- Next steps checklist

### ✅ Comprehensive Testing
- **110+ Pester tests** covering all components
- Integration tests for end-to-end workflows
- Performance tests for large datasets
- Complete test documentation

**See**: `docs/ENTERPRISE_FEATURES.md` for full details

---

## 📚 Complete Documentation

**All documentation is organized in the `docs/` directory:**

| Document | Purpose | Audience |
|----------|---------|----------|
| **[Quick Start Guide](docs/QUICK_START.md)** | Get running in 5 minutes | All Users |
| **[Installation Guide](docs/INSTALLATION.md)** | Setup and prerequisites | IT Administrators |
| **[User Guide](docs/USER_GUIDE.md)** | Complete usage instructions | Consultants, Auditors |
| **[Enterprise Features](docs/ENTERPRISE_FEATURES.md)** | CI/CD, Module, Email Notifications | DevOps, Enterprise |
| **[AD Security Components](docs/AD_SECURITY_COMPONENTS.md)** | Advanced AD security analysis | Security, Auditors |
| **[Testing Guide](Tests/TESTING_GUIDE.md)** | Pester testing framework | Developers, QA |
| **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** | Common issues and solutions | Support Teams |
| **[Module Reference](docs/MODULE_REFERENCE.md)** | Technical API documentation | Developers |
| **[Design Document](docs/DESIGN_DOCUMENT.md)** | Architecture and design | Architects |
| **[Development Progress](docs/DEVELOPMENT_PROGRESS.md)** | Build history and features | Stakeholders |

---

## System Requirements

- **Windows 10/11** or **Windows Server 2016+**
- **PowerShell 5.1** or newer (already installed on Windows)
- **Domain access** (for Active Directory audit)
- **Local Administrator** rights (for server inventory)

---

## What Gets Audited?

### ✅ Active Directory
- 5,000+ users: accounts, groups, privileged access
- Security risks: stale accounts, ACL misconfigurations
- Password policies and Kerberos delegation

### ✅ Servers (150+ servers)
- Hardware: CPU, memory, storage, network adapters
- Installed applications with versions
- Event logs: top 10 critical/error events (last 30 days)
- User logon history (last 90 days)

### ✅ SQL Server (25 instances, 85 databases)
- Database sizes and backup status
- SQL logins and server roles (sysadmin detection)
- SQL Agent jobs with schedules
- Linked servers and Always On Availability Groups
- Azure SQL migration assessment

### 🔜 Microsoft 365 (Coming Soon)
- Entra ID (Azure AD)
- Exchange Online mailboxes
- SharePoint sites and Teams
- Power Platform apps and flows

---

## Need Help?

**Quick Help**: Click the "Help" button in the GUI

**Full Documentation**: See `docs\README.md` for complete details

**Technical Design**: See `docs\DESIGN_DOCUMENT.md` for architecture

**Contact**: adrian207@gmail.com

---

## 🌐 Web-Based Query Builder (NEW!)

**Point-and-click database querying for your audit results**

### Quick Start
```powershell
Install-Module Pode -Scope CurrentUser
.\Start-M&A-QueryBuilder-Web.ps1
```
Then open: **http://localhost:5000**

### Features
- 📊 Visual query builder (no SQL needed)
- 🎯 8 pre-built templates
- 🌐 Multi-user access
- 📱 Mobile-friendly
- 💾 CSV export

**Full Guide**: See `QUERY_BUILDER_README.md`

---

## For Advanced Users

**Command-line version** (more options):
```powershell
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -Verbose
```

**Skip specific components**:
```powershell
.\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits" -SkipSQL -SkipEventLogs
```

---

## Security & Privacy

**What we collect**: Configuration data only—no emails, documents, or passwords

**How we protect it**: AES-256 encryption on all output files

**Read-only**: Zero modifications to your environment

**Chain of custody**: audit_metadata.json tracks who ran it, when, and from where

---

## Project Structure

```
AD-Audit/
├── Start-M&A-Audit-GUI.ps1    ← START HERE (Simple GUI)
├── Run-M&A-Audit.ps1           ← Command-line version
├── Modules/                    ← Audit modules
│   └── Invoke-AD-Audit.ps1
├── Libraries/                  ← Helper functions
├── docs/                       ← Documentation
│   ├── README.md              ← Full documentation
│   └── DESIGN_DOCUMENT.md     ← Technical specifications
└── Output/                     ← Results saved here (auto-created)
```

---

---

## 🚀 Enterprise Deployment

### Install as PowerShell Module
```powershell
# Import module
Import-Module .\AD-Audit.psd1

# Run audit with email notification
Start-MAAudit `
    -CompanyName "Acme Corp" `
    -OutputFolder "C:\Audits" `
    -NotificationEmail "admin@company.com" `
    -CreateDatabase
```

### CI/CD Integration
- **GitHub Actions**: Automatically enabled (see `.github/workflows/test.yml`)
- **Azure DevOps**: Import `azure-pipelines.yml` to your project
- **Automated Testing**: Runs 110+ tests on every commit
- **Code Quality**: PSScriptAnalyzer linting enforced

### Run Tests
```powershell
cd Tests
.\RunTests.ps1  # Run all tests (~2 minutes)
.\RunTests.ps1 -CodeCoverage  # With coverage report
```

---

**Version**: 2.1.0 (Enterprise Ready + Advanced AD Security)  
**Status**: Production ready with complete test coverage  
**Last Updated**: October 22, 2025  
**Test Coverage**: ~78% (118+ tests)

**License**: MIT
