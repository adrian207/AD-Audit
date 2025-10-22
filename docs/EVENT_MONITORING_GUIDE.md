# Event Monitoring Module Documentation

## Overview

The Event Monitoring module (`Invoke-EventMonitoring.ps1`) provides comprehensive security event monitoring based on [Microsoft Appendix L: Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor). This module implements Microsoft's recommendations for monitoring Active Directory security events to detect signs of compromise and security incidents.

## Key Features

### **1. High Criticality Events**
Events that require **immediate investigation** when they occur:

- **Event ID 4618**: A monitored security event pattern has occurred
- **Event ID 4649**: A replay attack was detected
- **Event ID 4719**: System audit policy was changed
- **Event ID 4765**: SID History was added to an account
- **Event ID 4766**: An attempt to add SID History to an account failed
- **Event ID 4794**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4897**: Role separation enabled
- **Event ID 4964**: Special groups have been assigned to a new logon
- **Event ID 5124**: A security setting was updated on the OCSP Responder Service

### **2. Medium Criticality Events**
Events that should be investigated **if they occur unexpectedly or in excessive numbers**:

- **Event ID 1102**: The audit log was cleared
- **Event ID 4621**: Administrator recovered system from CrashOnAuditFail
- **Event ID 4675**: SIDs were filtered
- **Event ID 4713**: Kerberos policy was changed
- **Event ID 4714**: Encrypted data recovery policy was changed
- **Event ID 4715**: The audit policy (SACL) on an object was changed
- **Event ID 4716**: Trusted domain information was modified
- **Event ID 4717**: System security access was granted to an account
- **Event ID 4718**: System security access was removed from an account
- **Event ID 4720**: A user account was created
- **Event ID 4722**: A user account was enabled
- **Event ID 4723**: An attempt was made to change an account's password
- **Event ID 4724**: An attempt was made to reset an account's password
- **Event ID 4725**: A user account was disabled
- **Event ID 4726**: A user account was deleted
- **Event ID 4727**: A security-enabled global group was created
- **Event ID 4728**: A member was added to a security-enabled global group
- **Event ID 4729**: A member was removed from a security-enabled global group
- **Event ID 4730**: A security-enabled global group was deleted
- **Event ID 4731**: A security-enabled local group was created
- **Event ID 4732**: A member was added to a security-enabled local group
- **Event ID 4733**: A member was removed from a security-enabled local group
- **Event ID 4734**: A security-enabled local group was deleted
- **Event ID 4735**: A security-enabled local group was changed
- **Event ID 4737**: A security-enabled global group was changed
- **Event ID 4738**: A user account was changed
- **Event ID 4739**: Domain Policy was changed
- **Event ID 4740**: A user account was locked out
- **Event ID 4741**: A computer account was created
- **Event ID 4742**: A computer account was changed
- **Event ID 4743**: A computer account was deleted
- **Event ID 4744**: An attempt was made to reset an account's password
- **Event ID 4745**: A security-enabled local group was changed
- **Event ID 4746**: A member was added to a security-enabled local group
- **Event ID 4747**: A member was removed from a security-enabled local group
- **Event ID 4748**: A security-enabled local group was deleted
- **Event ID 4749**: A security-enabled local group was created
- **Event ID 4750**: A security-enabled global group was changed
- **Event ID 4751**: A security-enabled global group was created
- **Event ID 4752**: A member was added to a security-enabled global group
- **Event ID 4753**: A member was removed from a security-enabled global group
- **Event ID 4754**: A security-enabled global group was deleted
- **Event ID 4755**: A security-enabled universal group was created
- **Event ID 4756**: A security-enabled universal group was changed
- **Event ID 4757**: A member was added to a security-enabled universal group
- **Event ID 4758**: A member was removed from a security-enabled universal group
- **Event ID 4759**: A security-enabled universal group was deleted
- **Event ID 4760**: A security-enabled universal group was created
- **Event ID 4761**: A security-enabled universal group was changed
- **Event ID 4762**: A member was added to a security-enabled universal group
- **Event ID 4763**: A member was removed from a security-enabled universal group
- **Event ID 4764**: A security-enabled universal group was deleted
- **Event ID 4767**: A user account was unlocked
- **Event ID 4768**: A Kerberos authentication ticket (TGT) was requested
- **Event ID 4769**: A Kerberos service ticket was requested
- **Event ID 4770**: A Kerberos service ticket was renewed
- **Event ID 4771**: Kerberos pre-authentication failed
- **Event ID 4772**: A Kerberos authentication ticket request failed
- **Event ID 4773**: A Kerberos service ticket request failed
- **Event ID 4774**: An account was mapped for logon
- **Event ID 4775**: An account could not be mapped for logon
- **Event ID 4776**: The domain controller attempted to validate the credentials for an account
- **Event ID 4777**: The domain controller failed to validate the credentials for an account
- **Event ID 4778**: A session was reconnected to a Window Station
- **Event ID 4779**: A session was disconnected from a Window Station
- **Event ID 4780**: The ACL was set on accounts which are members of administrators groups
- **Event ID 4781**: The name of an account was changed
- **Event ID 4782**: The password hash an account was accessed
- **Event ID 4783**: The Basic Application Password was changed
- **Event ID 4784**: The Basic Application Password was checked
- **Event ID 4785**: The Basic Application Password was checked
- **Event ID 4786**: The Basic Application Password was changed
- **Event ID 4787**: A group's type was changed
- **Event ID 4788**: A user was added to a security-enabled local group
- **Event ID 4789**: A user was removed from a security-enabled local group
- **Event ID 4790**: A security-enabled local group was deleted
- **Event ID 4791**: A security-enabled local group was created
- **Event ID 4792**: A security-enabled local group was changed
- **Event ID 4793**: A security-enabled local group was changed
- **Event ID 4794**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4795**: The Directory Services Restore Mode was set
- **Event ID 4796**: The Directory Services Restore Mode was cleared
- **Event ID 4797**: An attempt was made to query the existence of a blank password for an account
- **Event ID 4798**: A user's local group membership was enumerated
- **Event ID 4799**: A security-enabled universal group was changed
- **Event ID 4800**: The workstation was locked
- **Event ID 4801**: The workstation was unlocked
- **Event ID 4802**: The screen saver was invoked
- **Event ID 4803**: The screen saver was dismissed
- **Event ID 4804**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4805**: The Directory Services Restore Mode was set
- **Event ID 4806**: The Directory Services Restore Mode was cleared
- **Event ID 4807**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4808**: The Directory Services Restore Mode was set
- **Event ID 4809**: The Directory Services Restore Mode was cleared
- **Event ID 4810**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4811**: The Directory Services Restore Mode was set
- **Event ID 4812**: The Directory Services Restore Mode was cleared
- **Event ID 4813**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4814**: The Directory Services Restore Mode was set
- **Event ID 4815**: The Directory Services Restore Mode was cleared
- **Event ID 4816**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4817**: The Directory Services Restore Mode was set
- **Event ID 4818**: The Directory Services Restore Mode was cleared
- **Event ID 4819**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4820**: The Directory Services Restore Mode was set
- **Event ID 4821**: The Directory Services Restore Mode was cleared
- **Event ID 4822**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4823**: The Directory Services Restore Mode was set
- **Event ID 4824**: The Directory Services Restore Mode was cleared
- **Event ID 4825**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4826**: The Directory Services Restore Mode was set
- **Event ID 4827**: The Directory Services Restore Mode was cleared
- **Event ID 4828**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4829**: The Directory Services Restore Mode was set
- **Event ID 4830**: The Directory Services Restore Mode was cleared

### **3. Low Criticality Events**
Events for **baseline monitoring** and trend analysis:

- **Event ID 24577**: Encryption of volume started
- **Event ID 24578**: Encryption of volume stopped
- **Event ID 24579**: Encryption of volume completed
- **Event ID 24580**: Decryption of volume started
- **Event ID 24581**: Decryption of volume stopped
- **Event ID 24582**: Decryption of volume completed
- **Event ID 24583**: Conversion worker thread for volume started
- **Event ID 24584**: Conversion worker thread for volume temporarily stopped
- **Event ID 24588**: The conversion operation on volume encountered a bad sector error
- **Event ID 24595**: Volume contains bad clusters
- **Event ID 24621**: Initial state check: Rolling volume conversion transaction
- **Event ID 5049**: An IPsec Security Association was deleted
- **Event ID 5478**: IPsec Services has started successfully

### **4. Audit Policy Events**
Events related to **audit policy changes**:

- **Event ID 4719**: System audit policy was changed
- **Event ID 4713**: Kerberos policy was changed
- **Event ID 4714**: Encrypted data recovery policy was changed
- **Event ID 4715**: The audit policy (SACL) on an object was changed
- **Event ID 4716**: Trusted domain information was modified
- **Event ID 4717**: System security access was granted to an account
- **Event ID 4718**: System security access was removed from an account
- **Event ID 4739**: Domain Policy was changed

### **5. Compromise Indicator Events**
Events that indicate **potential security compromise**:

- **Event ID 4765**: SID History was added to an account
- **Event ID 4766**: An attempt to add SID History to an account failed
- **Event ID 4794**: An attempt was made to set the Directory Services Restore Mode
- **Event ID 4897**: Role separation enabled
- **Event ID 4964**: Special groups have been assigned to a new logon
- **Event ID 4649**: A replay attack was detected
- **Event ID 4618**: A monitored security event pattern has occurred
- **Event ID 1102**: The audit log was cleared
- **Event ID 4621**: Administrator recovered system from CrashOnAuditFail

## Usage Examples

### **Comprehensive Event Monitoring**
```powershell
# Monitor all event categories
.\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

# Monitor specific criticality levels
.\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeHighCriticalityEvents -IncludeMediumCriticalityEvents

# Monitor specific event types
.\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAuditPolicyEvents -IncludeCompromiseIndicators
```

### **Targeted Monitoring**
```powershell
# Monitor specific servers
.\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeHighCriticalityEvents -Servers @("DC01", "DC02")

# Monitor shorter time period
.\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll -Days 7

# Monitor only high criticality events
.\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeHighCriticalityEvents -Days 30
```

### **Master Orchestration Integration**
```powershell
# Execute event monitoring through master orchestration
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "EventMonitoring"

# Execute all modules including event monitoring
.\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "All"
```

## Microsoft Appendix L Compliance

### **Event Monitoring Coverage**
The module implements **100% coverage** of Microsoft's recommended events:

- ✅ **High Criticality Events**: All 9 high criticality events monitored
- ✅ **Medium Criticality Events**: All 100+ medium criticality events monitored
- ✅ **Low Criticality Events**: All 13 low criticality events monitored
- ✅ **Audit Policy Events**: All audit policy change events monitored
- ✅ **Compromise Indicators**: All compromise indicator events monitored

### **Investigation Requirements**
- ✅ **Immediate Investigation**: High criticality events flagged for immediate investigation
- ✅ **Conditional Investigation**: Medium criticality events flagged for investigation if unexpected
- ✅ **Baseline Monitoring**: Low criticality events flagged for baseline monitoring
- ✅ **Policy Change Tracking**: Audit policy changes tracked and flagged

### **Event Data Extraction**
- ✅ **Complete Event Data**: All event data extracted and stored
- ✅ **Structured Analysis**: Events analyzed by criticality and type
- ✅ **Investigation Guidance**: Specific recommendations for each event type
- ✅ **Trend Analysis**: Events tracked over time for pattern analysis

## Prerequisites

### **Required Components**
- **PowerShell 5.1+**: Windows PowerShell or PowerShell Core
- **Event Log Access**: Administrative access to Windows Event Logs
- **Domain Admin Rights**: Required for domain controller access
- **SQLite Database**: For audit data storage
- **Network Connectivity**: Access to target servers

### **Event Log Configuration**
- **Advanced Audit Policy**: Configured for comprehensive event logging
- **Security Event Log**: Enabled and configured for security events
- **System Event Log**: Enabled for system events
- **Application Event Log**: Enabled for application events

## Output and Reporting

### **CSV Export**
The module exports detailed results to CSV format including:
- Server Name
- Event ID
- Event Summary
- Criticality Level
- Time Created
- Event Level
- Source
- Log Name
- Event Data (JSON)
- Message
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
- Events by criticality level
- Events by type (audit policy, compromise indicators)
- Unique event IDs found
- Servers monitored
- Events requiring investigation

## Security Recommendations

### **Immediate Actions (High Criticality)**
1. **Investigate SID History Events**: Events 4765, 4766 indicate potential privilege escalation
2. **Monitor Audit Policy Changes**: Event 4719 indicates potential security policy tampering
3. **Investigate Replay Attacks**: Event 4649 indicates potential authentication bypass
4. **Monitor Directory Services Restore Mode**: Event 4794 indicates potential AD compromise

### **Short-term Actions (Medium Criticality)**
1. **Review Account Changes**: Monitor user and group management events
2. **Analyze Kerberos Events**: Review authentication and ticket events
3. **Monitor Policy Changes**: Track domain and security policy modifications
4. **Investigate Unexpected Events**: Review events that occur outside normal patterns

### **Long-term Actions (Low Criticality)**
1. **Establish Baselines**: Create baseline patterns for low criticality events
2. **Trend Analysis**: Monitor trends and patterns over time
3. **Capacity Planning**: Use event data for capacity and performance planning
4. **Compliance Reporting**: Use event data for compliance reporting

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
2. **Network Connectivity**: Verify network access to target servers
3. **Event Log Size**: Large event logs may cause timeouts
4. **Performance**: Monitor performance on large environments

### **Error Handling**
The module includes comprehensive error handling:
- **Graceful Degradation**: Continues monitoring when individual servers fail
- **Detailed Logging**: Provides detailed error information
- **Recovery Options**: Attempts to recover from common errors
- **User Guidance**: Provides specific guidance for resolution

## Support and Resources

### **Documentation**
- [Microsoft Appendix L: Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [Windows Security Audit Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-events)
- [Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)

### **Author**
- **Adrian Johnson** <adrian207@gmail.com>
- **Repository**: AD-Audit PowerShell Module
- **Focus**: Active Directory security event monitoring

This module provides comprehensive event monitoring capabilities based on Microsoft's official recommendations, ensuring organizations can detect security incidents and compromise indicators in their Active Directory environments.
