# AD FS Security Audit Module Documentation

> Executive summary: Assess AD FS security posture quickly—focus on authentication, authorization, RPT/CPT configuration, and sign-in experience to reduce risk.
>
> Key recommendations:
> - Validate authentication providers and MFA/lockout configurations
> - Review access control policies and device authentication
> - Audit RPT/CPT trust settings and claim rules for least privilege
>
> Supporting points:
> - Captures SSL, database, and farm configurations
> - Surfaces encryption/signature algorithms and token settings
> - Provides targeted examples for common audit scenarios

## Overview

The AD FS Security Audit module (`Invoke-ADFSSecurityAudit.ps1`) provides comprehensive security auditing for Active Directory Federation Services (AD FS) based on the [Microsoft AD FS Operations documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-operations). While Microsoft recommends migrating to Microsoft Entra ID, many organizations still have AD FS deployments that require security auditing.

## Key Features

### **1. Service Configuration Analysis**
- **Farm Information**: AD FS farm configuration and settings
- **AD FS Properties**: Core AD FS configuration properties
- **SSL Certificate Analysis**: Certificate expiry and security validation
- **Database Configuration**: AD FS database connection settings

### **2. Authentication Configuration Analysis**
- **Authentication Providers**: Analysis of enabled authentication providers
- **Global Authentication Policy**: Global authentication policy settings
- **MFA Configuration**: Multi-factor authentication settings
- **Lockout Protection**: Extranet lockout protection settings

### **3. Authorization Configuration Analysis**
- **Access Control Policies**: AD FS access control policy analysis
- **Device Authentication Controls**: Device registration and authentication settings
- **Conditional Access**: Device-based conditional access policies

### **4. RPT/CPT Configuration Analysis**
- **Relying Party Trusts**: Analysis of RPT configurations and security settings
- **Claims Provider Trusts**: Analysis of CPT configurations
- **Claim Rules**: Analysis of claim rule definitions and security implications
- **Encryption Settings**: Claim encryption and signature algorithm analysis

### **5. Sign-In Experience Configuration**
- **Web Themes**: AD FS web theme customization analysis
- **Single Sign-On Settings**: SSO lifetime and configuration analysis
- **Password Expiry Claims**: Password expiry claim settings
- **User Experience**: Sign-in customization and user experience settings

## Usage Examples

### **Comprehensive AD FS Security Audit**
```powershell
# Execute all AD FS security assessments
.\Invoke-ADFSSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll
```

### **Specific Configuration Analysis**
```powershell
# Analyze authentication and authorization configurations
.\Invoke-ADFSSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAuthenticationConfig -IncludeAuthorizationConfig

# Analyze RPT/CPT configurations
.\Invoke-ADFSSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeRPTCPTConfig

# Analyze service configuration and sign-in experience
.\Invoke-ADFSSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeServiceConfiguration -IncludeSignInExperience
```

### **Master Orchestration Integration**
```powershell
# Execute AD FS security audit through master orchestration
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "ADFS"

# Execute all modules including AD FS
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "All"
```

## Security Analysis Categories

### **Critical Security Issues**
- **SSL Certificate Expiry**: Certificates expiring within 30 days
- **Unencrypted Claims**: RPTs with disabled claim encryption
- **Weak Signature Algorithms**: Use of SHA1 signature algorithms
- **Disabled Lockout Protection**: Extranet lockout protection disabled

### **High Security Issues**
- **Certificate Expiry**: Certificates expiring within 90 days
- **Authentication Provider Issues**: Misconfigured authentication providers
- **Access Control Policy Issues**: Insecure access control policies

### **Medium Security Issues**
- **Configuration Review Needed**: Standard configuration items requiring review
- **SSO Lifetime**: SSO lifetime settings requiring evaluation
- **Device Registration**: Device registration settings requiring review

### **Low Security Issues**
- **Informational Items**: Configuration items for monitoring
- **Best Practice Recommendations**: Recommendations for improvement

## Microsoft AD FS Operations Compliance

### **Service Configuration Compliance**
- ✅ **SSL Certificate Management**: Validates SSL certificate configuration and expiry
- ✅ **Farm Configuration**: Analyzes AD FS farm settings and configuration
- ✅ **Database Configuration**: Reviews database connection settings

### **Authentication Configuration Compliance**
- ✅ **Strong Authentication (MFA)**: Analyzes MFA configuration and settings
- ✅ **Lockout Protection**: Validates extranet lockout protection settings
- ✅ **Policy Configuration**: Reviews authentication policy configurations
- ✅ **Kerberos & Certificate Authentication**: Analyzes Kerberos and certificate authentication

### **Authorization Configuration Compliance**
- ✅ **Access Control Policies**: Analyzes access control policy configurations
- ✅ **Device-based Conditional Access**: Reviews device authentication controls

### **RPT & CPT Configuration Compliance**
- ✅ **Relying Party Trusts**: Analyzes RPT configurations and security settings
- ✅ **Claims Provider Trusts**: Reviews CPT configurations
- ✅ **Claim Rules**: Analyzes claim rule definitions and security implications

### **Sign-In Experience Configuration Compliance**
- ✅ **Single Sign-On Settings**: Analyzes SSO configuration and settings
- ✅ **User Sign-In Customization**: Reviews sign-in experience customization
- ✅ **Password Expiry Claims**: Analyzes password expiry claim settings

## Prerequisites

### **Required Components**
- **PowerShell 5.1+**: Windows PowerShell or PowerShell Core
- **AD FS PowerShell Module**: Required for AD FS configuration analysis
- **AD FS Admin Rights**: Administrative access to AD FS servers
- **SQLite Database**: For audit data storage
- **Network Connectivity**: Access to AD FS servers

### **Optional Components**
- **AD FS Management Console**: For manual configuration verification
- **Certificate Management Tools**: For certificate analysis
- **Event Log Access**: For additional security analysis

## Output and Reporting

### **CSV Export**
The module exports detailed results to CSV format including:
- Configuration Type
- Configuration Details
- Risk Level Assessment
- Security Recommendations
- Timestamp Information

### **Console Output**
Real-time console output includes:
- Progress indicators
- Risk level color coding
- Summary statistics
- Error and warning messages

### **Summary Statistics**
- Total configurations analyzed
- Risk level breakdown (Critical, High, Medium, Low)
- Configuration type breakdown
- Security recommendations count

## Integration with AD-Audit Framework

### **Master Orchestration**
- ✅ **Integrated with Master Remediation**: Available through `Invoke-MasterRemediation.ps1`
- ✅ **Consistent Logging**: Uses standardized logging functions
- ✅ **Database Integration**: Stores results in SQLite audit database
- ✅ **Error Handling**: Robust error handling and recovery

### **Reporting Integration**
- ✅ **Compatible with Existing Reports**: Works with `New-AuditReport.ps1`
- ✅ **Executive Dashboard Support**: Compatible with `New-ExecutiveDashboard.ps1`
- ✅ **CSV Export**: Standardized CSV output format
- ✅ **Summary Reporting**: Integrated summary statistics

## Security Recommendations

### **Immediate Actions (Critical)**
1. **Renew Expiring Certificates**: Replace SSL certificates expiring within 30 days
2. **Enable Claim Encryption**: Enable encryption for all sensitive RPTs
3. **Upgrade Signature Algorithms**: Replace SHA1 with SHA256 signature algorithms
4. **Enable Lockout Protection**: Enable extranet lockout protection

### **Short-term Actions (High)**
1. **Review Authentication Providers**: Audit and secure authentication provider configurations
2. **Analyze Access Control Policies**: Review and secure access control policies
3. **Monitor Certificate Expiry**: Implement certificate expiry monitoring

### **Long-term Actions (Medium/Low)**
1. **Optimize SSO Settings**: Review and optimize SSO lifetime settings
2. **Enhance Device Controls**: Review and enhance device authentication controls
3. **Improve User Experience**: Optimize sign-in experience while maintaining security

## Migration Considerations

### **Microsoft Entra ID Migration**
While this module provides comprehensive AD FS security auditing, Microsoft recommends migrating to Microsoft Entra ID for:
- **Enhanced Security**: Modern authentication and authorization capabilities
- **Reduced Complexity**: Simplified management and configuration
- **Better Integration**: Native integration with Microsoft 365 services
- **Advanced Features**: Conditional access, identity protection, and more

### **Hybrid Scenarios**
For organizations maintaining hybrid environments:
- **Use This Module**: For comprehensive AD FS security auditing
- **Plan Migration**: Develop migration strategy to Microsoft Entra ID
- **Maintain Security**: Ensure AD FS security while planning migration
- **Monitor Changes**: Track AD FS usage and plan migration timeline

## Troubleshooting

### **Common Issues**
1. **AD FS Module Not Available**: Install AD FS PowerShell module
2. **Access Denied**: Ensure AD FS administrative rights
3. **Network Connectivity**: Verify network access to AD FS servers
4. **Certificate Issues**: Check certificate validity and permissions

### **Error Handling**
The module includes comprehensive error handling:
- **Graceful Degradation**: Continues analysis when individual components fail
- **Detailed Logging**: Provides detailed error information
- **Recovery Options**: Attempts to recover from common errors
- **User Guidance**: Provides specific guidance for resolution

## Support and Resources

### **Documentation**
- [Microsoft AD FS Operations](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-operations)
- [AD FS Security Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-security-best-practices)
- [AD FS Migration to Microsoft Entra ID](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/migrate-from-federation-to-cloud-authentication)

### **Author**
- **Adrian Johnson** <adrian207@gmail.com>
- **Repository**: AD-Audit PowerShell Module
- **Focus**: Active Directory Federation Services security auditing

This module provides comprehensive AD FS security auditing capabilities while organizations plan their migration to Microsoft Entra ID, ensuring security is maintained throughout the transition process.
