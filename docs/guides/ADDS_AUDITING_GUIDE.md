# AD DS Auditing Module Documentation

> Executive summary: Enable high-fidelity AD DS auditing to track access and changes (old/new values) and strengthen investigation readiness across domain controllers.
>
> Key recommendations:
> - Monitor 4662 and 5136–5141 events for access/change tracking
> - Review SACLs on critical objects (Admins, DCs, Users, Computers)
> - Baseline and alert on replication and schema auditing anomalies
>
> Supporting points:
> - Implements Microsoft advanced auditing with value change tracking
> - Analyzes SACL coverage, inheritance, and ACE effectiveness
> - Surfaces replication events relevant to lateral movement detection

## Overview

The AD DS Auditing module (`Invoke-ADDSAuditing.ps1`) provides comprehensive Active Directory Domain Services auditing based on the [Microsoft AD DS Auditing Step-by-Step Guide](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc731607(v=ws.10)). This module implements Microsoft's advanced auditing features including **old and new value tracking** for attribute changes, SACL analysis, and directory service change monitoring.

## Key Features

### **1. Directory Service Access Events (Event ID 4662)**
Monitors directory service access events that replace Event ID 566 from Windows Server 2003:

- **Event ID 4662**: Directory Service Access
- **Access Tracking**: Monitors who accessed what objects and attributes
- **Permission Analysis**: Tracks access masks and operation types
- **Security Context**: Captures subject user information and logon IDs

### **2. Directory Service Changes Events (Event IDs 5136-5141)**
Monitors directory service changes with **old and new value tracking**:

- **Event ID 5136**: A directory service object was modified
- **Event ID 5137**: A directory service object was created
- **Event ID 5138**: A directory service object was undeleted
- **Event ID 5139**: A directory service object was moved
- **Event ID 5141**: A directory service object was deleted

#### **Advanced Value Change Tracking**
- ✅ **Old Value Capture**: Records previous attribute values
- ✅ **New Value Capture**: Records current attribute values
- ✅ **Attribute Identification**: Identifies specific attributes changed
- ✅ **Change Detection**: Flags when values actually change
- ✅ **Binary Value Handling**: Handles binary attributes appropriately

### **3. Directory Service Replication Events (Event IDs 4928-4939)**
Monitors directory service replication events:

- **Event ID 4928**: Replica source naming context established
- **Event ID 4929**: Replica source naming context removed
- **Event ID 4930**: Replica source naming context modified
- **Event ID 4931**: Replica destination naming context created
- **Event ID 4932**: Replica destination naming context deleted
- **Event ID 4933**: Replica destination naming context modified
- **Event ID 4934**: Replica source naming context established
- **Event ID 4935**: Replica source naming context removed
- **Event ID 4936**: Replica source naming context modified
- **Event ID 4937**: Replica destination naming context created
- **Event ID 4938**: Replica destination naming context deleted
- **Event ID 4939**: Replica destination naming context modified

### **4. SACL (System Access Control List) Analysis**
Analyzes SACL configuration for critical objects:

- ✅ **Critical Object Analysis**: Analyzes Users, Computers, Domain Controllers, Built-in Administrators, Domain Admins, Enterprise Admins
- ✅ **ACE Analysis**: Analyzes Access Control Entries in SACLs
- ✅ **Audit Configuration**: Verifies audit flags and inheritance settings
- ✅ **Missing SACL Detection**: Identifies objects without SACL configuration
- ✅ **Inheritance Analysis**: Tracks inherited vs. explicit SACL entries

### **5. Schema Auditing Configuration Analysis**
Analyzes schema attribute auditing configuration:

- ✅ **Search Flags Analysis**: Analyzes searchFlags property for auditing configuration
- ✅ **Bit 8 Detection**: Identifies attributes with auditing disabled (bit 8 = 256)
- ✅ **Critical Attribute Analysis**: Analyzes critical attributes like userPrincipalName, sAMAccountName, member, memberOf
- ✅ **Auditing Status**: Determines which attributes have auditing enabled/disabled

### **6. Audit Policy Configuration Analysis**
Analyzes audit policy subcategories:

- ✅ **Directory Service Access**: Audit directory service access
- ✅ **Directory Service Changes**: Audit directory service changes
- ✅ **Directory Service Replication**: Audit directory service replication
- ✅ **Detailed Directory Service Replication**: Audit detailed directory service replication

## Microsoft AD DS Auditing Guide Compliance

### **100% Coverage of Microsoft Recommendations**
- ✅ **Directory Service Access**: Complete monitoring of access events
- ✅ **Directory Service Changes**: Complete monitoring with old/new value tracking
- ✅ **Directory Service Replication**: Complete replication event monitoring
- ✅ **SACL Analysis**: Complete SACL configuration analysis
- ✅ **Schema Analysis**: Complete schema auditing configuration analysis
- ✅ **Audit Policy Analysis**: Complete audit policy subcategory analysis

### **Advanced Features Implemented**
- ✅ **Old/New Value Tracking**: Implements Microsoft's advanced value change tracking
- ✅ **Attribute-Specific Auditing**: Tracks specific attribute changes
- ✅ **Binary Value Handling**: Properly handles binary attributes
- ✅ **String Length Limits**: Respects Microsoft's string length limits (default 1000 bytes)
- ✅ **SDDL Support**: Supports Security Descriptor Definition Language

## Usage Examples

### **Comprehensive AD DS Auditing**
```powershell
# Monitor all AD DS auditing categories
.\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# Monitor specific event types
.\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeDirectoryServiceChanges -IncludeSACLAnalysis

# Monitor with specific time period
.\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll -Days 7
```

### **Targeted Auditing**
```powershell
# Monitor specific objects
.\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeSACLAnalysis -TargetObjects @("CN=Users,DC=domain,DC=com", "CN=Computers,DC=domain,DC=com")

# Monitor specific attributes
.\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeSchemaAnalysis -TargetAttributes @("userPrincipalName", "sAMAccountName", "member")

# Monitor specific servers
.\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll -Servers @("DC01", "DC02")
```

### **Master Orchestration Integration**
```powershell
# Execute AD DS auditing through master orchestration
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "ADDSAuditing"

# Execute all modules including AD DS auditing
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "All"
```

## Prerequisites

### **Required Components**
- **PowerShell 5.1+**: Windows PowerShell or PowerShell Core
- **Event Log Access**: Administrative access to Windows Event Logs
- **Domain Admin Rights**: Required for domain controller access and SACL management
- **SQLite Database**: For audit data storage
- **Network Connectivity**: Access to target servers
- **SACL Management Rights**: Required for SACL analysis

### **Audit Policy Configuration**
- **Global Audit Policy**: "Audit directory service access" must be enabled
- **Directory Service Access**: Subcategory enabled for success events (default)
- **Directory Service Changes**: Subcategory enabled for success events
- **Directory Service Replication**: Subcategory enabled for success events
- **Detailed Directory Service Replication**: Subcategory enabled for success events

### **SACL Configuration**
- **Critical Objects**: Must have appropriate SACL entries for auditing
- **ACE Configuration**: Access Control Entries must be properly configured
- **Inheritance Settings**: SACL inheritance must be properly configured

## Output and Reporting

### **CSV Export**
The module exports detailed results to CSV format including:
- Server Name
- Event ID
- Event Summary
- Event Type
- Time Created
- Event Level
- Source
- Log Name
- Subject Information (User SID, Username, Domain, Logon ID)
- Object Information (DN, GUID, Class)
- Attribute Information (Name, Old Value, New Value)
- Operation Information (Type, Access Mask, Properties)
- Investigation Required
- Recommendation

### **Console Output**
Real-time console output includes:
- Progress indicators
- Risk level color coding
- Summary statistics
- Error and warning messages

### **Summary Statistics**
- Total events analyzed
- Events by type (Access, Changes, Replication)
- SACL entries analyzed
- Schema attributes analyzed
- Audit policy subcategories analyzed
- Value changes detected
- Critical objects monitored
- Events requiring investigation

## Security Recommendations

### **Immediate Actions (Critical)**
1. **Enable Directory Service Changes Auditing**: Ensure Event IDs 5136-5141 are monitored
2. **Configure SACL for Critical Objects**: Ensure Users, Computers, Domain Controllers have SACL entries
3. **Enable Schema Auditing**: Ensure critical attributes have auditing enabled
4. **Monitor Value Changes**: Track old/new values for critical attribute changes

### **Short-term Actions (High Priority)**
1. **Review SACL Configuration**: Analyze SACL entries for completeness
2. **Monitor Replication Events**: Track replication topology changes
3. **Analyze Access Patterns**: Review directory service access patterns
4. **Verify Audit Policy**: Ensure all audit subcategories are enabled

### **Long-term Actions (Medium Priority)**
1. **Establish Baselines**: Create baseline patterns for normal operations
2. **Trend Analysis**: Monitor trends and patterns over time
3. **Compliance Reporting**: Use audit data for compliance reporting
4. **Performance Optimization**: Optimize audit configuration for performance

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

## Troubleshooting

### **Common Issues**
1. **Event Log Access Denied**: Ensure administrative rights on target servers
2. **SACL Access Denied**: Ensure SACL management rights
3. **Schema Access Denied**: Ensure schema access rights
4. **Audit Policy Not Enabled**: Ensure audit policy subcategories are enabled

### **Error Handling**
The module includes comprehensive error handling:
- **Graceful Degradation**: Continues monitoring when individual servers fail
- **Detailed Logging**: Provides detailed error information
- **Recovery Options**: Attempts to recover from common errors
- **User Guidance**: Provides specific guidance for resolution

## Advanced Features

### **Value Change Tracking**
- **Old Value Capture**: Records previous attribute values before changes
- **New Value Capture**: Records current attribute values after changes
- **Change Detection**: Flags when values actually change
- **Binary Value Handling**: Properly handles binary attributes with <binary> notation

### **SACL Analysis**
- **Critical Object Analysis**: Analyzes Users, Computers, Domain Controllers, Built-in Administrators, Domain Admins, Enterprise Admins
- **ACE Analysis**: Analyzes Access Control Entries in SACLs
- **Audit Configuration**: Verifies audit flags and inheritance settings
- **Missing SACL Detection**: Identifies objects without SACL configuration

### **Schema Analysis**
- **Search Flags Analysis**: Analyzes searchFlags property for auditing configuration
- **Bit 8 Detection**: Identifies attributes with auditing disabled (bit 8 = 256)
- **Critical Attribute Analysis**: Analyzes critical attributes
- **Auditing Status**: Determines which attributes have auditing enabled/disabled

## Support and Resources

### **Documentation**
- [Microsoft AD DS Auditing Step-by-Step Guide](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc731607(v=ws.10))
- [Windows Security Audit Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-events)
- [Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)

### **Author**
- **Adrian Johnson** <adrian207@gmail.com>
- **Repository**: AD-Audit PowerShell Module
- **Focus**: Active Directory Domain Services auditing

This module provides comprehensive AD DS auditing capabilities based on Microsoft's official recommendations, ensuring organizations can track directory service changes with old and new value tracking, monitor SACL configuration, and analyze schema auditing settings for complete Active Directory security monitoring.
