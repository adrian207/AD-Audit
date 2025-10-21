# Quick Start Guide

**Get the M&A Technical Discovery Script running in 5 minutes.**

---

## What You'll Get

A comprehensive audit of your Microsoft infrastructure in one command:
- **On-Premises**: Active Directory, servers, SQL databases
- **Microsoft 365**: Entra ID, Exchange, SharePoint, Teams, Power Platform, Compliance
- **Reports**: 5 HTML reports with executive dashboard
- **Database**: SQLite database for cross-dataset queries (optional)
- **Security**: AES-256 encrypted output

**Time**: 5 minutes setup + 30-90 minutes execution

---

## Prerequisites (2 minutes)

### Required:
- ✅ Windows 10/11 or Windows Server 2016+
- ✅ PowerShell 5.1 or later
- ✅ Domain-joined computer with network access to domain controllers
- ✅ **Domain Admin** permissions (on-premises audit)
- ✅ **Global Reader** role (Microsoft 365 audit)

### The Script Will Auto-Install:
- Microsoft Graph PowerShell modules
- Exchange Online Management module
- SharePoint Online Management Shell
- Microsoft Teams module
- Power Apps Administration modules

---

## Step 1: Download (30 seconds)

```powershell
# Clone the repository
git clone https://github.com/your-org/AD-Audit.git
cd AD-Audit
```

Or download the ZIP file and extract it.

---

## Step 2: Launch the GUI (30 seconds)

```powershell
# Right-click PowerShell and "Run as Administrator"
cd C:\Path\To\AD-Audit

# Launch the GUI
.\Start-M&A-Audit-GUI.ps1
```

**If you see an execution policy error:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Step 3: Configure the Audit (2 minutes)

Fill in the GUI form:

### **Basic Settings** (Required)
- **Company Name**: `Contoso` (used in report titles)
- **Output Folder**: `C:\Audits\Contoso` (where results will be saved)
- **Report Title**: `Contoso M&A Technical Discovery - Q4 2025`

### **What to Audit** (Choose)
- ☑ **Active Directory** (on-premises infrastructure)
- ☑ **Servers** (hardware, apps, SQL databases)
- ☑ **Microsoft 365** (Entra ID, Exchange, SharePoint, Teams, Power Platform, Compliance)

### **Audit Options** (Optional)
- **Stale Threshold**: `90 days` (accounts inactive for this long are flagged)
- **Event Log Days**: `30 days` (how far back to search event logs)

---

## Step 4: Run the Audit (1 minute)

Click **"Start Audit"** button.

A new PowerShell window will open showing progress:
```
============================================
   M&A Technical Discovery Script v1.0
   Author: Adrian Johnson
============================================

Execution Plan:
  - Active Directory Audit (Servers, SQL, Users, Groups)
  - Microsoft Entra ID
  - Exchange Online
  - SharePoint & Teams Audit
  - Power Platform Audit
  - Compliance & Security Audit

[12:00:00] Starting Active Directory audit...
[12:05:00] Collecting user inventory... 2,143 users found
[12:10:00] Collecting server inventory... 58 servers found
...
```

**⏱️ Execution Time Estimates:**
- **Small** (< 200 users, < 20 servers): 15-30 minutes
- **Medium** (200-1,000 users, 20-100 servers): 30-90 minutes
- **Large** (> 1,000 users, > 100 servers): 1-3 hours

---

## Step 5: Review the Reports (30 seconds)

When complete, the **Executive Summary** report will automatically open in your default browser.

### 📊 **Executive Summary** (Boardroom-Ready)
- Migration readiness score
- Key metrics (users, servers, mailboxes, Teams)
- Risk indicators (stale accounts, backup issues, privileged accounts)
- Top findings and recommendations

### 🔍 **Detailed Reports** (Technical Drill-Down)
Click the navigation menu for:
- **Active Directory**: Stale users, OS distribution, GPOs, trusts, DNS zones
- **Server Infrastructure**: Hardware inventory, storage, top applications
- **SQL Databases**: Instance details, backup issues, logins, failed jobs
- **Security Analysis**: Privileged accounts, service accounts, best practices

---

## Next Steps

### **Immediate (Day 1)**
1. ✅ Review Executive Summary with stakeholders
2. ✅ Identify high-priority risks (backup failures, privileged accounts)
3. ✅ Share reports with technical teams for validation

### **Short Term (Week 1)**
1. 📋 Deep-dive into raw CSV data files (`Output\RawData\`)
2. 🗄️ Query SQLite database for cross-dataset analysis (`AuditData.db`)
3. 🔍 Cross-reference findings with business requirements
4. 📊 Build migration project plan based on discovered infrastructure

### **Medium Term (Month 1)**
1. 🚀 Begin remediation of identified issues
2. 🔄 Re-run audit to validate improvements
3. 📈 Track metrics over time

---

## Common First-Run Issues

### ❌ **"Cannot be loaded because running scripts is disabled"**
**Solution**: Run PowerShell as Administrator and execute:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### ❌ **"Access Denied" when collecting server data**
**Solution**: Ensure you're running as a **Domain Admin** account.

### ❌ **Cloud modules fail to connect**
**Solution**: You'll be prompted to authenticate. Use an account with **Global Reader** role.

### ❌ **GUI doesn't launch**
**Solution**: You may be missing .NET Framework 4.5+. Install from Microsoft.

### ❌ **Execution is very slow**
**Solution**: Reduce parallelism in GUI: **Max Parallel Servers** = `5` (default is 10)

---

## Getting Help

- 📖 **Detailed instructions**: See [User Guide](USER_GUIDE.md)
- 🔧 **Installation issues**: See [Installation Guide](INSTALLATION.md)
- 🐛 **Errors and troubleshooting**: See [Troubleshooting Guide](TROUBLESHOOTING.md)
- 💻 **Technical deep-dive**: See [Module Reference](MODULE_REFERENCE.md)

---

## Security Note

🔐 **All audit data is encrypted by default using Windows EFS (Encrypting File System).**

Only the user who ran the audit (and SYSTEM) can decrypt the files. For enterprise scenarios, use the optional **Azure Key Vault** integration or **password-protected archive** options.

See [User Guide - Security](USER_GUIDE.md#security) for details.

---

**That's it! You're now running enterprise-grade M&A technical discovery in under 5 minutes.** 🎉

For more advanced usage, customization, and automation, continue to the [User Guide](USER_GUIDE.md).

