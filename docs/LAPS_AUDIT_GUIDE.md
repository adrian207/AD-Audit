# LAPS Audit Guide

**Complete guide to the Local Administrator Password Solution (LAPS) audit module**

**Author**: Adrian Johnson <adrian207@gmail.com>  
**Version**: 1.0.0  
**Module**: Invoke-LAPS-Audit.ps1

---

## 🎯 **Overview**

The LAPS (Local Administrator Password Solution) Audit module provides comprehensive auditing capabilities for monitoring and managing LAPS deployment across your Active Directory environment. This module helps ensure that local administrator passwords are properly managed, rotated, and compliant with security best practices.

---

## 📋 **What is LAPS?**

LAPS is a Microsoft solution that automatically manages unique, complex passwords for local administrator accounts on domain-joined computers. It stores these passwords securely in Active Directory and rotates them automatically based on configurable policies.

### **Why is LAPS Important?**
- **Eliminates shared passwords**: Each computer has a unique local administrator password
- **Automatic rotation**: Passwords are rotated automatically on a schedule
- **Secure storage**: Passwords are stored in AD with controlled access
- **Audit trail**: Tracks who accessed passwords and when
- **Compliance**: Meets CIS Controls and Microsoft security best practices

---

## 🚀 **Quick Start**

### **Basic Usage**
```powershell
# Run basic LAPS audit
.\Modules\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db"
```

### **Full Audit with Remediation**
```powershell
# Audit and remediate non-compliant systems (dry-run)
.\Modules\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -EnableRemediation -DryRun

# Actual remediation (no dry-run)
.\Modules\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -EnableRemediation
```

---

## 🔧 **Parameters**

### **Required Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `-DatabasePath` | String | Path to SQLite database for storing audit results |

### **Optional Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputPath` | String | `C:\Audits\LAPS` | Output directory for reports |
| `-IncludeAll` | Switch | `$true` | Run all LAPS checks |
| `-PasswordAgeThreshold` | Int | 30 | Days until password is considered stale |
| `-ExpirationThreshold` | Int | 90 | Days until password is considered expired |
| `-EnableRemediation` | Switch | `$false` | Enable password reset for non-compliant systems |
| `-DryRun` | Switch | `$false` | Preview mode - no actual password resets |
| `-EmailRecipients` | String[] | None | Email addresses for report delivery |
| `-SendEmail` | Switch | `$false` | Send email report |
| `-ReportFormat` | String[] | `HTML, CSV, JSON` | Report formats to generate |

---

## 📊 **What Gets Checked**

### **1. LAPS Installation Status**
- Detects if LAPS is installed and configured
- Checks for `ms-Mcs-AdmPwd` attribute (password storage)
- Checks for `ms-Mcs-AdmPwdExpirationTime` attribute (password expiration)

### **2. Password Age Analysis**
- Calculates password age in days
- Identifies stale passwords (>30 days by default)
- Identifies expired passwords (>90 days by default)

### **3. Compliance Status**
- Determines if each computer is LAPS compliant
- Calculates overall compliance percentage
- Assigns risk levels (Critical/High/Medium/Low)

### **4. Reporting**
- Generates multiple report formats
- Provides recommendations for remediation
- Tracks compliance over time

---

## 📈 **Compliance Metrics**

### **Risk Levels**

| Level | Description | Action Required |
|-------|-------------|-----------------|
| **Low** | 95%+ compliance | Monitor and maintain |
| **Medium** | 80-94% compliance | Address gaps |
| **High** | 60-79% compliance | Urgent action needed |
| **Critical** | <60% compliance | Immediate action required |

### **Compliance Scoring**

```
Compliance % = (Compliant Computers / Total Computers) × 100
```

Where a compliant computer has:
- LAPS installed
- Valid password (not expired)
- Password within acceptable age threshold

---

## 📑 **Report Formats**

### **1. HTML Report**
Professional dashboard with:
- Executive summary with compliance metrics
- Risk assessment and recommendations
- Detailed table of all computers
- Color-coded risk levels

**Output**: `LAPS_Compliance_Report_YYYYMMDD_HHMMSS.html`

### **2. CSV Reports**
Multiple CSV files for different categories:
- `LAPS_Status_All_*.csv` - All computers
- `LAPS_Non_Compliant_*.csv` - Non-compliant computers
- `LAPS_Expired_*.csv` - Expired passwords
- `LAPS_Missing_*.csv` - Missing LAPS installation

### **3. JSON Report**
Complete data export in JSON format for integration with other tools.

**Output**: `LAPS_Report_YYYYMMDD_HHMMSS.json`

### **4. XML Report**
Structured XML format for integration with enterprise systems.

**Output**: `LAPS_Report_YYYYMMDD_HHMMSS.xml`

### **5. Markdown Report**
Human-readable markdown format for documentation.

**Output**: `LAPS_Report_YYYYMMDD_HHMMSS.md`

---

## 🔄 **Password Reset Actions**

### **Force Password Reset**

The module can force LAPS to regenerate passwords by clearing the expiration timestamp. This triggers LAPS to rotate the password within approximately 15 minutes.

```powershell
# Dry-run to preview resets
.\Modules\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -EnableRemediation -DryRun

# Actual password reset
.\Modules\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -EnableRemediation
```

### **Bulk Operations**

The module supports parallel processing for efficient bulk password resets across multiple computers.

---

## 🎯 **Use Cases**

### **1. Security Compliance Audit**
Monitor LAPS deployment across the environment to ensure compliance with security standards.

```powershell
.\Modules\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -ReportFormat All
```

### **2. Incident Response**
Quickly identify and remediate systems with compromised local administrator passwords.

```powershell
.\Modules\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -EnableRemediation
```

### **3. Regular Monitoring**
Schedule regular LAPS audits to maintain security posture.

```powershell
# Weekly automated audit
Register-ScheduledJob -Name "LAPS-Audit-Weekly" -ScriptBlock {
    .\Modules\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -SendEmail
} -Trigger (New-JobTrigger -Weekly -DaysOfWeek Sunday -At 2AM)
```

---

## 🔒 **Security Best Practices**

### **Microsoft Recommendations**
- Enable LAPS on all domain-joined computers
- Rotate passwords every 30-60 days
- Grant read access to authorized personnel only
- Monitor password expiration and reset expired passwords promptly

### **CIS Controls**
- **CIS Control 4**: Secure Configuration of Enterprise Assets
- **CIS Control 6**: Access Control Management

---

## 📝 **Output Data Structure**

### **Computer Record**
```powershell
[PSCustomObject]@{
    ComputerName = "SERVER01"
    DNSHostName = "server01.domain.com"
    DistinguishedName = "CN=SERVER01,OU=Servers,DC=domain,DC=com"
    Enabled = $true
    OperatingSystem = "Windows Server 2019"
    IsServer = $true
    IsDomainController = $false
    LastLogonDate = "2025-01-15"
    LAPSInstalled = $true
    HasLAPSPassword = $true
    LAPSExpirationDate = "2025-02-15"
    LAPSPasswordAge = -30  # Negative = days until expiration
    IsExpired = $false
    IsStale = $false
    LAPSCompliant = $true
    RiskLevel = "Low"
    Recommendation = "LAPS is configured and compliant. Monitor regularly."
    AuditDate = "2025-01-20"
}
```

### **Compliance Metrics**
```powershell
[PSCustomObject]@{
    TotalComputers = 150
    LAPSInstalled = 120
    InstallationPercentage = 80
    LAPSCompliant = 115
    NonCompliant = 35
    CompliancePercentage = 76.67
    ExpiredPasswords = 5
    StalePasswords = 15
    RiskLevel = "High"
    AuditDate = "2025-01-20"
    Recommendation = "Urgent action needed. Address expired passwords..."
}
```

---

## 🐛 **Troubleshooting**

### **Issue: No computers found**
**Cause**: Incorrect domain or insufficient permissions  
**Solution**: Verify domain connectivity and run with domain admin rights

### **Issue: Password reset not working**
**Cause**: LAPS may not be properly installed or configured  
**Solution**: Verify LAPS installation and GPO configuration

### **Issue: Reports not generating**
**Cause**: Output path may not exist  
**Solution**: Module creates output path automatically, verify write permissions

---

## 📞 **Support**

- **GitHub Issues**: https://github.com/adrian207/AD-Audit/issues
- **Email**: adrian207@gmail.com
- **Documentation**: See README.md for complete documentation

---

**Happy Auditing!** 🔒
