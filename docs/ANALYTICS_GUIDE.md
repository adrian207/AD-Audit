# Advanced Analytics & Reporting Guide - v2.3.0

**Release Date**: October 22, 2025  
**Feature**: Option 4 - Advanced Analytics & Reporting  
**Author**: Adrian Johnson  

---

## 📊 Overview

The M&A Audit Advanced Analytics & Reporting system transforms raw audit data into actionable intelligence through:

- **Baseline Comparison** - Track changes between audits
- **Trend Analysis** - Identify patterns across multiple audits
- **Anomaly Detection** - Automatically discover security risks
- **Risk Scoring** - Quantify overall security posture
- **Executive Dashboards** - Beautiful HTML reports for stakeholders
- **Alert System** - Proactive notifications for threshold breaches

---

## 🚀 Quick Start

### Basic Usage
```powershell
.\Start-M&A-Analytics.ps1 `
    -BaselineAuditPath "C:\Audits\2024-01\AuditData.db" `
    -CurrentAuditPath "C:\Audits\2024-10\AuditData.db" `
    -OutputFolder "C:\Analytics" `
    -CompanyName "Contoso" `
    -GenerateDashboard
```

### With Alerts
```powershell
.\Start-M&A-Analytics.ps1 `
    -BaselineAuditPath "baseline.db" `
    -CurrentAuditPath "current.db" `
    -OutputFolder "C:\Analytics" `
    -CompanyName "Fabrikam" `
    -GenerateDashboard `
    -EnableAlerts `
    -AlertEmail "admin@fabrikam.com" `
    -SMTPServer "smtp.office365.com" `
    -FromEmail "audit@fabrikam.com"
```

---

## 🎯 Features

### 1. Baseline Comparison

Compares two audit databases to identify changes:

**Metrics Tracked**:
- Users (count, percent change)
- Computers (count, percent change)
- Servers (count, percent change)
- Groups (count, percent change)
- Privileged Accounts (count, percent change)
- Service Accounts (count, percent change)
- SQL Databases (count, size)

**Output**: `comparison_report.json`

### 2. Anomaly Detection

Automatically detects 7 types of security anomalies:

| Anomaly | Severity | Description |
|---------|----------|-------------|
| **Privileged Account Growth** | High | >10% increase in privileged accounts |
| **Stale Privileged Accounts** | Critical | Inactive accounts with elevated rights |
| **Service Account Password Issues** | High | Passwords >1 year old or never expire |
| **Kerberos Delegation Risks** | Critical | Unconstrained delegation detected |
| **Dangerous ACL Permissions** | High | Risky AD permission assignments |
| **Database Growth** | Medium | >20% growth in SQL databases |
| **Servers Going Offline** | Medium | Previously online servers now offline |

**Output**: `anomalies_report.csv`

### 3. Risk Scoring

Calculates comprehensive security risk score (0-100):

**Score Ranges**:
- **80-100**: Low Risk ✅
- **60-79**: Medium Risk ⚠️
- **40-59**: High Risk 🔴
- **0-39**: Critical Risk 🚨

**Risk Factors** (point deductions):
- Stale Privileged Accounts: -15 points
- Service Account Risks: -10 points
- Kerberos Delegation: -20 points
- Dangerous ACLs: -15 points
- Weak Password Policy: -10 points
- SQL Backup Risks: -10 points
- Untrusted Trusts: -10 points

**Output**: `risk_score_report.json`

### 4. Executive Dashboard

Beautiful HTML dashboard with:
- ✅ Risk gauge with color-coded levels
- ✅ Key metrics comparison (animated cards)
- ✅ Anomaly cards with severity badges
- ✅ Responsive design (mobile-friendly)
- ✅ Printable format
- ✅ Dark gradients and modern UI

**Output**: `[CompanyName]_Executive_Dashboard_[Date].html`

**Features**:
- Interactive hover effects
- Color-coded severity levels
- Executive summary section
- Professional branding

### 5. Alert System

Proactive email alerts when thresholds are breached:

**Default Thresholds**:
```powershell
@{
    RiskScoreBelow = 60              # Alert if risk score < 60
    CriticalAnomalies = 1            # Alert if ≥1 critical anomaly
    HighAnomalies = 3                # Alert if ≥3 high anomalies
    PrivilegedAccountGrowth = 10     # Alert if >10% growth
}
```

**Custom Thresholds**:
```powershell
$customThresholds = @{
    RiskScoreBelow = 70
    CriticalAnomalies = 0
    HighAnomalies = 2
    PrivilegedAccountGrowth = 5
}

.\Start-M&A-Analytics.ps1 ... -AlertThresholds $customThresholds
```

---

## 📁 Output Files

All analytics generate the following files in the output folder:

| File | Description | Format |
|------|-------------|--------|
| `comparison_report.json` | Baseline vs current comparison | JSON |
| `anomalies_report.csv` | Detected anomalies list | CSV |
| `risk_score_report.json` | Risk scoring details | JSON |
| `[Company]_Executive_Dashboard_[Date].html` | Executive dashboard | HTML |
| `analytics_log.txt` | Execution log | Text |

---

## 🔧 Advanced Usage

### Trend Analysis (Multiple Audits)

```powershell
# Load analytics module
Import-Module .\Modules\Invoke-Analytics-Engine.ps1

# Analyze trends across multiple audits
$auditPaths = @(
    "C:\Audits\2024-01\AuditData.db",
    "C:\Audits\2024-04\AuditData.db",
    "C:\Audits\2024-07\AuditData.db",
    "C:\Audits\2024-10\AuditData.db"
)

$trends = Get-TrendAnalysis -AuditPaths $auditPaths

# Display trends
$trends.UserGrowth | Format-Table
$trends.ServerGrowth | Format-Table
$trends.PrivilegedAccountGrowth | Format-Table
```

### Manual Dashboard Generation

```powershell
Import-Module .\Modules\New-ExecutiveDashboard.ps1

$comparison = Compare-AuditData -BaselinePath "baseline.db" -CurrentPath "current.db"
$anomalies = Find-Anomalies -BaselinePath "baseline.db" -CurrentPath "current.db"
$riskScore = Get-RiskScore -DatabasePath "current.db"

New-ExecutiveDashboard -CompanyName "Contoso" `
                      -Comparison $comparison `
                      -Anomalies $anomalies `
                      -RiskScore $riskScore `
                      -OutputPath "Dashboard.html"
```

### Alert Testing

```powershell
Import-Module .\Modules\Send-AnalyticsAlert.ps1

$alerts = Test-AlertThresholds -Anomalies $anomalies `
                               -RiskScore $riskScore `
                               -Comparison $comparison `
                               -Thresholds @{
                                   RiskScoreBelow = 60
                                   CriticalAnomalies = 1
                                   HighAnomalies = 3
                                   PrivilegedAccountGrowth = 10
                               }

$alerts | Format-Table Type, Severity, Message
```

---

## 📈 Use Cases

### 1. Monthly Security Review
```powershell
# Compare this month to last month
.\Start-M&A-Analytics.ps1 `
    -BaselineAuditPath "C:\Audits\September\AuditData.db" `
    -CurrentAuditPath "C:\Audits\October\AuditData.db" `
    -OutputFolder "C:\Reports\October" `
    -CompanyName "Contoso" `
    -GenerateDashboard `
    -EnableAlerts `
    -AlertEmail "security-team@contoso.com" `
    -SMTPServer "smtp.office365.com" `
    -FromEmail "audit@contoso.com"
```

### 2. Pre/Post M&A Comparison
```powershell
# Compare pre-merger to post-merger
.\Start-M&A-Analytics.ps1 `
    -BaselineAuditPath "C:\Audits\Pre-Merger\AuditData.db" `
    -CurrentAuditPath "C:\Audits\Post-Merger\AuditData.db" `
    -OutputFolder "C:\Reports\MergerAnalysis" `
    -CompanyName "Contoso + Fabrikam Merger" `
    -GenerateDashboard
```

### 3. Quarterly Board Report
```powershell
# Generate executive dashboard for board meeting
.\Start-M&A-Analytics.ps1 `
    -BaselineAuditPath "C:\Audits\Q3\AuditData.db" `
    -CurrentAuditPath "C:\Audits\Q4\AuditData.db" `
    -OutputFolder "C:\Reports\Q4-Board" `
    -CompanyName "Contoso Corp Q4 2024" `
    -GenerateDashboard
```

---

## 🎨 Dashboard Features

### Visual Elements

**Risk Gauge**:
- Animated circular gauge
- Color-coded by risk level
- Large score display

**Metric Cards**:
- Hover animations
- Change indicators (↑/↓/→)
- Percent change calculations

**Anomaly Cards**:
- Color-coded left border
- Severity badges
- Recommendation boxes with lightbulb icon

**Executive Summary**:
- Gradient background
- Bullet-point highlights
- Key metrics at a glance

### Responsive Design
- Desktop: Full 3-column layout
- Tablet: 2-column adaptive
- Mobile: Single column stack
- Print-friendly CSS

---

## ⚙️ Configuration

### Email Alert Setup

**Office 365**:
```powershell
-SMTPServer "smtp.office365.com"
-From "audit@company.com"
-AlertEmail "admin@company.com"
```

**Gmail** (App Password Required):
```powershell
-SMTPServer "smtp.gmail.com"
-From "audit@gmail.com"
-AlertEmail "admin@gmail.com"
```

**On-Premises Exchange**:
```powershell
-SMTPServer "mail.company.local"
-From "audit@company.local"
-AlertEmail "admin@company.local"
```

### Custom Thresholds

Modify thresholds based on your environment:

```powershell
$thresholds = @{
    # Alert if risk score drops below 70
    RiskScoreBelow = 70
    
    # Alert on ANY critical anomaly
    CriticalAnomalies = 0
    
    # Alert if 2 or more high anomalies
    HighAnomalies = 2
    
    # Alert if privileged accounts grow by >5%
    PrivilegedAccountGrowth = 5
}
```

---

## 🔒 Security Considerations

### Data Privacy
- Analytics runs locally on audit databases
- No external API calls
- No data sent to third parties
- Output files contain sensitive data - secure appropriately

### Access Control
- Restrict access to output folder
- Use encrypted file systems (EFS/BitLocker)
- Limit who can run analytics scripts
- Secure email alerts (TLS/SSL)

### Audit Trail
- All operations logged to `analytics_log.txt`
- Timestamps for all actions
- Error logging for troubleshooting

---

## 🐛 Troubleshooting

### Issue: "Database not found"
**Solution**: Verify paths are correct and databases exist
```powershell
Test-Path "C:\Audits\AuditData.db"
```

### Issue: "Failed to send alert email"
**Solution**: Check SMTP configuration and authentication
```powershell
# Test SMTP connectivity
Test-NetConnection smtp.office365.com -Port 587
```

### Issue: "No anomalies detected"
**Solution**: Ensure current audit has required tables (v2.1+ data)

### Issue: "Dashboard doesn't open"
**Solution**: Check file path and browser default association
```powershell
Start-Process "C:\Analytics\Dashboard.html"
```

---

## 📊 Performance

### Execution Times (Typical)
- Small Environment (<500 users): 10-20 seconds
- Medium Environment (500-2000 users): 30-60 seconds
- Large Environment (>2000 users): 60-120 seconds

### Resource Usage
- Memory: ~200MB during execution
- CPU: Moderate (mostly database queries)
- Disk I/O: Low (read-only on databases)

---

## 🔮 Future Enhancements

Planned for v2.4.0:
- [ ] Machine learning anomaly detection
- [ ] Predictive trend forecasting
- [ ] Multi-company portfolio dashboards
- [ ] Interactive Power BI integration
- [ ] Real-time monitoring mode
- [ ] Custom dashboard templates
- [ ] API for programmatic access
- [ ] Slack/Teams webhook alerts

---

## 📞 Support

For questions or issues:
- **Email**: adrian207@gmail.com
- **GitHub**: https://github.com/adrian207/AD-Audit/issues
- **Documentation**: See `/docs` folder

---

## 📄 License

MIT License - Same as main AD-Audit project

---

**Version**: 2.3.0  
**Release Date**: October 22, 2025  
**Status**: ✅ Production Ready  
**Dependencies**: System.Data.SQLite, PowerShell 5.1+

**🎉 Transform your audit data into actionable intelligence!**

