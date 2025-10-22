# AD-Audit Framework Summary

## Overview

The AD-Audit framework is a comprehensive **Active Directory** security auditing and remediation solution designed to identify and automatically fix common AD security issues in on-premises environments.

## Core Focus: Active Directory Security

### **Primary Components**

#### **1. Active Directory Auditing**
- **User Account Security**: Stale accounts, privileged access, password policies
- **Computer Account Management**: Inactive computers, security configurations
- **Service Account Hygiene**: Password aging, delegation settings
- **Kerberos Security**: Delegation analysis, authentication protocols
- **ACL Permissions**: Dangerous permissions on critical AD objects
- **Group Management**: Empty groups, membership analysis

#### **2. Server Infrastructure Auditing**
- **Hardware Inventory**: Server specifications, hardware health
- **Operating System**: OS versions, patch levels, configurations
- **Service Management**: Unnecessary services, security hardening
- **Event Log Analysis**: Security events, SMB vulnerabilities
- **Storage Optimization**: Disk cleanup, space management
- **Application Security**: Unused applications, security patches

#### **3. Microsoft 365 Integration**
- **Exchange Online**: Mailbox management, forwarding rules
- **SharePoint**: Site cleanup, external sharing
- **Teams**: Archive inactive teams, compliance
- **Power Platform**: Environment management, security
- **Compliance Policies**: MFA enforcement, retention policies

### **Remediation Capabilities**

#### **Automated Security Hardening**
```powershell
# Disable stale user accounts
.\Invoke-ADRemediation.ps1 -IncludeStaleAccounts -DryRun:$false

# Remove stale privileged access
.\Invoke-ADRemediation.ps1 -IncludePrivilegedAccess -DryRun:$false

# Update service account passwords
.\Invoke-ADRemediation.ps1 -IncludeServiceAccounts -DryRun:$false
```

#### **Server Security Hardening**
```powershell
# Install missing patches
.\Invoke-ServerRemediation.ps1 -IncludePatchManagement -DryRun:$false

# Optimize services
.\Invoke-ServerRemediation.ps1 -IncludeServiceOptimization -DryRun:$false

# Apply security hardening
.\Invoke-ServerRemediation.ps1 -IncludeSecurityHardening -DryRun:$false
```

#### **M365 Configuration Management**
```powershell
# Manage user accounts
.\Invoke-M365Remediation.ps1 -IncludeUserManagement -DryRun:$false

# Optimize mailboxes
.\Invoke-M365Remediation.ps1 -IncludeMailboxOptimization -DryRun:$false

# Enforce compliance policies
.\Invoke-M365Remediation.ps1 -IncludeCompliancePolicies -DryRun:$false
```

### **Master Orchestration**

#### **Unified Audit Execution**
```powershell
# Run comprehensive AD audit
.\Invoke-MasterAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -ComprehensiveAudit

# Execute all remediations
.\Invoke-MasterRemediation.ps1 -Scope "All" -Priority "Critical,High" -DryRun:$false
```

#### **Incident Response Integration**
```powershell
# Respond to security incidents
.\Invoke-IncidentResponse.ps1 -IncidentType "PasswordSpray" -Severity "High" -AffectedUsers @("user1", "user2")
```

### **Security Focus Areas**

#### **Active Directory Security**
- **Account Security**: Stale account detection and remediation
- **Privileged Access**: Administrative account protection
- **Service Accounts**: Password rotation and security hardening
- **Kerberos Security**: Delegation vulnerability mitigation
- **ACL Security**: Dangerous permission remediation
- **Group Security**: Empty group cleanup and management

#### **Server Security**
- **Patch Management**: Critical security update deployment
- **Service Hardening**: Unnecessary service disabling
- **Event Log Security**: SMB vulnerability detection
- **Storage Security**: Disk cleanup and optimization
- **Application Security**: Unused application removal

#### **M365 Security**
- **User Management**: Inactive user account handling
- **Mailbox Security**: Oversized mailbox management
- **SharePoint Security**: Site cleanup and external sharing
- **Teams Security**: Inactive team archiving
- **Compliance Security**: Policy enforcement and MFA

### **Key Benefits**

#### **Automated Security Hardening**
- **Reduced Manual Effort**: Automated remediation of common issues
- **Consistent Security**: Standardized security configurations
- **Risk Reduction**: Proactive security issue resolution
- **Compliance**: Automated compliance policy enforcement

#### **Comprehensive Coverage**
- **Active Directory**: Complete AD security assessment
- **Server Infrastructure**: Hardware and OS security
- **Microsoft 365**: Cloud service security management
- **Incident Response**: Rapid threat containment

#### **Enterprise Ready**
- **Scalable Architecture**: Support for large AD environments
- **Database Integration**: SQLite-based audit data storage
- **Reporting**: Comprehensive HTML and CSV reports
- **Email Notifications**: Automated alert and report delivery

## Getting Started

### **Quick Start**
```powershell
# 1. Run comprehensive audit
.\Invoke-MasterAudit.ps1 -DatabasePath "C:\Audits\AuditData.db"

# 2. Review audit results
.\New-AuditReport.ps1 -DatabasePath "C:\Audits\AuditData.db" -OutputPath "C:\Reports\"

# 3. Execute remediations
.\Invoke-MasterRemediation.ps1 -Scope "All" -Priority "Critical" -DryRun:$false
```

### **Prerequisites**
- **PowerShell 5.1+**: Windows PowerShell or PowerShell Core
- **Active Directory Module**: RSAT tools installed
- **Local Administrator Rights**: Required for server auditing
- **SQLite**: For audit data storage
- **Email Configuration**: For notifications (optional)

## Documentation

- **Remediation Guide**: `docs/REMEDIATION_GUIDE.md`
- **SMB Security Audit**: `docs/SMB_SECURITY_AUDIT_GUIDE.md`
- **Module Documentation**: See individual module headers

## Support

- **Author**: Adrian Johnson <adrian207@gmail.com>
- **Repository**: AD-Audit PowerShell Module
- **Focus**: Active Directory security auditing and remediation

This framework provides comprehensive Active Directory security auditing and automated remediation capabilities, focusing on on-premises AD environments while providing integration with Microsoft 365 services for hybrid environments.
