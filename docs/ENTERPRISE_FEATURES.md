# Enterprise Features Guide

> Executive summary: Ship AD-Audit like a product—use CI/CD, proper packaging, and notifications to operate reliably at scale.
>
> Key recommendations:
> - Automate tests (Pester) and linting in CI
> - Package modules for clean versioned distribution
> - Send HTML completion emails to stakeholders
>
> Supporting points:
> - Ready-made workflows and templates
> - Artifacts and coverage reporting patterns
> - Practical triggers and job breakdowns

**Version**: 2.0.0  
**Last Updated**: October 22, 2025  
**Author**: Adrian Johnson

---

## Overview

The M&A Audit Tool now includes enterprise-ready features for professional deployment:

1. ✅ **CI/CD Integration** - Automated testing pipelines
2. ✅ **PowerShell Module** - Professional packaging and distribution
3. ✅ **Email Notifications** - Automated completion alerts with HTML summaries

---

## 1. CI/CD Integration

### GitHub Actions

**File**: `.github/workflows/test.yml`

**Features**:
- Automated Pester test execution on push/PR
- Code coverage reporting (Codecov integration)
- PowerShell Script Analyzer linting
- Test result publishing with detailed reports
- Artifact uploads for test results and coverage

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Manual workflow dispatch

**Workflow Jobs**:

#### 1. Test Job
- Installs Pester 5.x
- Runs all 110+ tests
- Generates NUnit XML results
- Calculates code coverage (~75%)
- Publishes test results and coverage
- Fails build if tests fail

#### 2. Lint Job
- Installs PSScriptAnalyzer
- Scans all `.ps1` files
- Reports errors and warnings
- Fails build on errors

#### 3. Build Status
- Aggregates test + lint results
- Reports overall pass/fail

**Usage**:

```powershell
# Enable GitHub Actions
# 1. Push .github/workflows/test.yml to repository
# 2. Navigate to Actions tab in GitHub
# 3. Workflows run automatically on push/PR

# View results:
# - https://github.com/your-org/AD-Audit/actions
```

**Badge for README**:
```markdown
![Tests](https://github.com/adrian207/AD-Audit/workflows/Pester%20Tests/badge.svg)
```

### Azure DevOps Pipeline

**File**: `azure-pipelines.yml`

**Features**:
- Multi-stage pipeline (Test → Package → Notify)
- Pester test execution with NUnit reporting
- Code coverage with JaCoCo format
- PowerShell Script Analyzer integration
- Module packaging for deployment
- Artifact publication

**Stages**:

#### Stage 1: Test
- **Job 1 - Pester Tests**:
  - Runs all tests
  - Publishes test results
  - Publishes code coverage
  - Displays test summary

- **Job 2 - Script Analyzer**:
  - Lints all PowerShell files
  - Reports errors/warnings
  - Fails on errors

#### Stage 2: Package
- Runs only on `main` branch
- Creates module directory structure
- Copies all required files
- Publishes build artifact

#### Stage 3: Notify
- Sends build notifications
- Reports success/failure status

**Usage**:

```yaml
# Setup in Azure DevOps:
# 1. Create new pipeline
# 2. Select "Existing Azure Pipelines YAML file"
# 3. Choose /azure-pipelines.yml
# 4. Run pipeline

# View results:
# - Pipelines → Your Pipeline → Runs
```

**Integration with Release Pipeline**:
- Trigger releases on successful builds
- Deploy to staging/production
- Automated module distribution

---

## 2. PowerShell Module

### Module Manifest

**File**: `AD-Audit.psd1`

**Module Information**:
- **Name**: AD-Audit
- **Version**: 2.0.0
- **GUID**: `8f4e3d2c-1a5b-4c9e-8f3d-2a1b5c9e8f3d`
- **Author**: Adrian Johnson
- **Description**: M&A Technical Discovery Audit Tool

**Compatibility**:
- PowerShell 5.1+
- PowerShell Core 7.x+
- Windows only (requires AD module)

**Dependencies**:
- `ActiveDirectory` (Required)
- `Microsoft.Graph` (Optional - cloud audit)
- `ExchangeOnlineManagement` (Optional)
- `PnP.PowerShell` (Optional)
- `MicrosoftTeams` (Optional)
- `Microsoft.PowerApps.Administration.PowerShell` (Optional)

**Exported Functions**:

| Function | Purpose |
|----------|---------|
| `Start-MAAudit` | Main orchestration |
| `Invoke-ADAudit` | Active Directory audit |
| `Invoke-EntraIDAudit` | Entra ID audit |
| `Invoke-ExchangeAudit` | Exchange Online audit |
| `Invoke-SharePointTeamsAudit` | SharePoint/Teams audit |
| `Invoke-PowerPlatformAudit` | Power Platform audit |
| `Invoke-ComplianceAudit` | Compliance audit |
| `New-AuditReport` | Generate HTML reports |
| `Initialize-AuditDatabase` | Create SQLite database |
| `Invoke-AuditQuery` | Query audit database |
| `Decrypt-AuditData` | Decrypt audit archives |

### Installation

#### Option 1: Manual Install
```powershell
# Clone repository
git clone https://github.com/adrian207/AD-Audit.git
cd AD-Audit

# Import module
Import-Module .\AD-Audit.psd1

# Verify
Get-Module AD-Audit
```

#### Option 2: Copy to Modules Path
```powershell
# Find module path
$env:PSModulePath -split ';'

# Copy to user module path
$destination = "$HOME\Documents\PowerShell\Modules\AD-Audit"
Copy-Item -Path ".\AD-Audit" -Destination $destination -Recurse

# Import
Import-Module AD-Audit
```

#### Option 3: PowerShell Gallery (Future)
```powershell
# Install from PowerShell Gallery
Install-Module -Name AD-Audit -Scope CurrentUser

# Import
Import-Module AD-Audit
```

### Using the Module

```powershell
# Import module
Import-Module AD-Audit

# Run audit with notification
Start-MAAudit `
    -CompanyName "Acme Corp" `
    -OutputFolder "C:\Audits" `
    -NotificationEmail "admin@company.com" `
    -ServerInventory $true `
    -CreateDatabase

# List available commands
Get-Command -Module AD-Audit

# Get help
Get-Help Start-MAAudit -Full
```

---

## 3. Email Notifications

### Overview

Automatically sends HTML email notification when audit completes.

**Function**: `Send-AuditNotification`

**Features**:
- Modern HTML email with gradient styling
- Audit completion summary with metrics
- Module success/failure breakdown
- Output location and report links
- Next steps checklist
- Data quality score display

### Configuration

#### Basic Usage

```powershell
# Run audit with email notification
.\Run-M&A-Audit.ps1 `
    -CompanyName "Contoso" `
    -OutputFolder "C:\Audits" `
    -NotificationEmail "admin@contoso.com"
```

#### Custom SMTP Settings

```powershell
# Modify Send-AuditNotification function parameters:
$mailParams = @{
    SmtpServer = "smtp.gmail.com"  # Change SMTP server
    Port = 587                      # Change port
    UseSsl = $true
}

# Or use environment variables
$env:AUDIT_SMTP_SERVER = "smtp.company.com"
$env:AUDIT_SMTP_PORT = "25"
```

#### SMTP Authentication

For servers requiring authentication, modify the function to accept credentials:

```powershell
# In Run-M&A-Audit.ps1, add parameter:
[PSCredential]$SmtpCredential

# Pass to Send-AuditNotification:
Send-AuditNotification `
    -ToEmail $NotificationEmail `
    -SmtpServer "smtp.office365.com" `
    -SmtpPort 587 `
    -Credential $SmtpCredential
```

### Email Content

The notification email includes:

#### Header
- **Title**: "🎉 M&A Audit Complete"
- **Subtitle**: Company name
- **Status Badge**: Success/Warning indicator

#### Metrics Cards
- **Duration**: Execution time in minutes
- **Modules Completed**: Count of successful modules
- **Modules Failed**: Count of failed modules
- **Data Quality**: Percentage score (0-100%)

#### Sections
1. **Successful Modules**: ✓ List of completed modules
2. **Failed Modules**: ✗ List of failed modules (if any)
3. **Output Location**: File path to audit results
4. **Generated Reports**: List of HTML reports
5. **Next Steps**: Recommended actions checklist
6. **Footer**: Execution details and timestamp

### Email Styling

Professional HTML email with:
- Gradient header (purple/blue)
- Responsive grid layout
- Color-coded status badges (green/yellow/red)
- Modern Segoe UI font family
- Box shadows and border radius
- Hover effects on links

### SMTP Configuration Examples

#### Office 365 (Default)
```powershell
SmtpServer: smtp.office365.com
Port: 587
UseSsl: $true
Requires: Office 365 mailbox
```

#### Gmail
```powershell
SmtpServer: smtp.gmail.com
Port: 587
UseSsl: $true
Requires: App password or OAuth
```

#### Exchange On-Premises
```powershell
SmtpServer: mail.company.local
Port: 25
UseSsl: $false
Requires: Network access to Exchange
```

#### SendGrid
```powershell
SmtpServer: smtp.sendgrid.net
Port: 587
UseSsl: $true
Requires: SendGrid API key
```

### Troubleshooting

#### Email Not Sending

**Check 1**: Verify SMTP settings
```powershell
Test-NetConnection -ComputerName smtp.office365.com -Port 587
```

**Check 2**: Authentication
```powershell
# Test with Send-MailMessage
Send-MailMessage `
    -To "test@company.com" `
    -From "audit@company.com" `
    -Subject "Test" `
    -Body "Test" `
    -SmtpServer "smtp.office365.com" `
    -Port 587 `
    -UseSsl
```

**Check 3**: Firewall/Proxy
- Ensure outbound port 587/25 is open
- Configure proxy if required

**Check 4**: From Address
```powershell
# Ensure From address is valid
# Some servers require From to match authenticated account
```

#### Common Issues

| Issue | Solution |
|-------|----------|
| **"Mailbox unavailable"** | Check From address matches authenticated mailbox |
| **"Relay access denied"** | SMTP server requires authentication |
| **"Connection timeout"** | Check firewall, port availability |
| **"SSL/TLS error"** | Verify UseSsl setting matches server requirements |

---

## 4. Combined Enterprise Usage

### Complete Enterprise Workflow

```powershell
# 1. Install module
Import-Module AD-Audit

# 2. Run comprehensive audit with all features
Start-MAAudit `
    -CompanyName "Merger Target Corp" `
    -OutputFolder "D:\Audits" `
    -NotificationEmail "cfo@acquirer.com,cto@acquirer.com" `
    -ServerInventory $true `
    -ServerEventLogDays 30 `
    -ServerLogonHistoryDays 90 `
    -MaxParallelServers 20 `
    -CreateDatabase `
    -CreateEncryptedArchive `
    -ComplianceFocus "HIPAA,SOX" `
    -Verbose

# 3. CI/CD pipeline automatically:
#    - Runs tests
#    - Validates code quality
#    - Publishes artifacts

# 4. Email notification automatically sent to stakeholders

# 5. Review results
Start-Process "D:\Audits\*\index.html"
```

### Integration with Existing Tools

#### ServiceNow
```powershell
# Trigger audit from ServiceNow workflow
# Parse notification email for status
# Create incident if failures detected
```

#### Microsoft Teams
```powershell
# Post notification to Teams channel via webhook
$teamsWebhook = "https://outlook.office.com/webhook/..."
Invoke-RestMethod -Uri $teamsWebhook -Method Post -Body $jsonBody
```

#### Power BI
```powershell
# Import SQLite database to Power BI
# Create executive dashboard
# Schedule refresh after audit runs
```

---

## 5. Best Practices

### Security
- ✅ Use encrypted archive for sensitive data
- ✅ Restrict email distribution list
- ✅ Store SMTP credentials securely (Azure Key Vault)
- ✅ Enable EFS encryption on output folder

### Performance
- ✅ Run tests in CI/CD before deployment
- ✅ Monitor execution time (baseline: 30-90 min)
- ✅ Use parallel processing (10-20 servers)
- ✅ Schedule audits during off-hours

### Maintenance
- ✅ Review test results weekly
- ✅ Update module dependencies monthly
- ✅ Archive old audit results (retention: 1 year)
- ✅ Document custom configurations

### Deployment
- ✅ Test in dev environment first
- ✅ Use version control (Git)
- ✅ Document SMTP configuration
- ✅ Create runbook for troubleshooting

---

## 6. Support & Resources

### Documentation
- **User Guide**: `docs/USER_GUIDE.md`
- **Testing Guide**: `Tests/TESTING_GUIDE.md`
- **Installation**: `docs/INSTALLATION.md`
- **Troubleshooting**: `docs/TROUBLESHOOTING.md`

### Links
- **GitHub**: https://github.com/adrian207/AD-Audit
- **Issues**: https://github.com/adrian207/AD-Audit/issues
- **Releases**: https://github.com/adrian207/AD-Audit/releases

### Contact
- **Author**: Adrian Johnson
- **Email**: adrian207@gmail.com

---

**Ready for enterprise deployment!** 🚀

