# M&A Technical Discovery Audit Tool

**Author**: Adrian Johnson <adrian207@gmail.com>

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

## 📚 Complete Documentation

**All documentation is organized in the `docs/` directory:**

| Document | Purpose | Audience |
|----------|---------|----------|
| **[Quick Start Guide](docs/QUICK_START.md)** | Get running in 5 minutes | All Users |
| **[Installation Guide](docs/INSTALLATION.md)** | Setup and prerequisites | IT Administrators |
| **[User Guide](docs/USER_GUIDE.md)** | Complete usage instructions | Consultants, Auditors |
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

**Version**: 2.0  
**Status**: Active Directory & Server audit ready. M365 modules coming soon.  
**Last Updated**: October 20, 2025

**License**: [Specify your license]
