# SMB Security Audit Module

> Executive summary: Detect and remediate missing SMB signing/encryption across clients and servers to close critical lateral-movement and tampering gaps.
>
> Key recommendations:
> - Require SMB signing where supported; enforce encryption on sensitive hosts
> - Scan event logs (1001–1003) and registry baselines across servers
> - Triage by severity and target high-risk servers first
>
> Supporting points:
> - Correlates config, event logs, and client identity
> - Exports CSV with severity to prioritize fixes
> - Works by server list or database inventory

## Overview

The `Invoke-SMBSecurityAudit.ps1` module provides comprehensive auditing capabilities to identify clients and servers that don't support SMB signing or encryption. This is critical for detecting security vulnerabilities and ensuring proper SMB security configuration across your environment.

## Features

### 🔍 **Event Log Analysis**
- **SMB Signing Failures** (Event ID 1001): Detects clients unable to negotiate SMB signing
- **SMB Encryption Failures** (Event ID 1002): Identifies clients unable to negotiate SMB encryption
- **Weak SMB Authentication** (Event ID 1003): Finds clients using weak authentication methods
- **System Log Analysis**: Scans System log for SMB-related errors

### ⚙️ **Configuration Auditing**
- **SMB Client Configuration**: Checks registry settings for SMB client signing requirements
- **SMB Server Configuration**: Verifies SMB server signing and encryption settings
- **Registry Analysis**: Examines HKLM registry keys for SMB security settings

### 📊 **Comprehensive Reporting**
- **CSV Export**: Detailed results exported to CSV format
- **Severity Classification**: Critical, High, Medium, Low risk levels
- **Summary Statistics**: Count of issues by severity and server
- **Client Identification**: IP addresses and hostnames of problematic clients

## Usage Examples

### Basic Usage
```powershell
# Audit specific servers
.\Invoke-SMBSecurityAudit.ps1 -Servers @("SERVER01", "SERVER02") -Days 30

# Audit all servers from database
.\Invoke-SMBSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -Days 7

# Custom output location
.\Invoke-SMBSecurityAudit.ps1 -Servers @("SERVER01") -OutputPath "C:\Reports\SMB-Audit.csv"
```

### Advanced Usage
```powershell
# Long-term analysis (90 days)
.\Invoke-SMBSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -Days 90 -OutputPath "C:\Reports\SMB-LongTerm.csv"

# Quick assessment (7 days)
.\Invoke-SMBSecurityAudit.ps1 -Servers @("DC01", "DC02", "FILE01") -Days 7
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `Servers` | String[] | No | - | Array of server names to audit |
| `DatabasePath` | String | No | - | Path to audit database for server list |
| `Days` | Int | No | 30 | Number of days to look back in event logs |
| `OutputPath` | String | No | `C:\Temp\SMBSecurityAudit.csv` | Path to save audit results |

## Event IDs Analyzed

### Microsoft-Windows-SMBServer/Security Log
- **1001**: SMB client unable to negotiate signing
- **1002**: SMB client unable to negotiate encryption  
- **1003**: SMB client using weak authentication

### System Log
- **1001-1004**: SMB-related system errors (filtered by message content)

## Registry Keys Checked

### SMB Client Settings
```
HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
- RequireSecuritySignature
```

### SMB Server Settings
```
HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
- RequireSecuritySignature
```

## Output Format

The audit generates a CSV file with the following columns:

| Column | Description |
|--------|-------------|
| `ServerName` | Name of the server being audited |
| `Type` | Type of finding (Event, ClientConfig, ServerConfig) |
| `Setting` | Specific SMB setting or event type |
| `Value` | Current value or event message |
| `ClientIP` | IP address of problematic client (if applicable) |
| `ClientName` | Hostname of problematic client (if applicable) |
| `Timestamp` | When the event occurred or config was checked |
| `Severity` | Risk level (Critical, High, Medium, Low) |
| `Recommendation` | Suggested remediation action |

## Severity Levels

### 🔴 **Critical**
- SMB encryption failures
- Clients unable to negotiate encryption

### 🟠 **High** 
- SMB signing failures
- Clients unable to negotiate signing
- SMB signing disabled in registry

### 🟡 **Medium**
- Weak SMB authentication
- SMB encryption not configured
- System log SMB errors

### 🟢 **Low**
- SMB signing properly configured
- No security issues found

## Prerequisites

### Required Permissions
- **Local Administrator** rights on target servers
- **Event Log Reader** permissions
- **Registry Read** access
- **PowerShell Remoting** enabled

### Required Modules
- **SQLite** (if using database integration)
- **Active Directory** module (if using AD integration)

## Troubleshooting

### Common Issues

#### 1. **Event Log Access Denied**
```
Error: Failed to analyze SMB events on SERVER01: Access denied
```
**Solution**: Ensure running as administrator and check event log permissions

#### 2. **PowerShell Remoting Failed**
```
Error: Failed to execute command on SERVER01: WinRM cannot process the request
```
**Solution**: Enable PowerShell remoting: `Enable-PSRemoting -Force`

#### 3. **Database Connection Failed**
```
Error: Failed to connect to database: Could not load file or assembly
```
**Solution**: Install SQLite assembly or use -Servers parameter instead

#### 4. **No SMB Events Found**
```
Info: No SMB security issues found on SERVER01
```
**Possible Causes**:
- SMB Server/Security log not enabled
- No SMB traffic in specified time period
- Events cleared or rotated

### Event Log Configuration

To ensure proper SMB event logging:

```powershell
# Enable SMB Server Security log
wevtutil sl Microsoft-Windows-SMBServer/Security /e:true

# Set log size and retention
wevtutil sl Microsoft-Windows-SMBServer/Security /ms:104857600 /rt:true
```

## Integration with AD-Audit

### Database Integration
```powershell
# Use existing audit database
.\Invoke-SMBSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -Days 30
```

### Remediation Integration
```powershell
# Run audit and remediation
$smbResults = .\Invoke-SMBSecurityAudit.ps1 -Servers @("SERVER01", "SERVER02")
.\Invoke-ServerRemediation.ps1 -Servers @("SERVER01", "SERVER02") -IncludeSMBSecurity
```

## Security Recommendations

### Immediate Actions
1. **Enable SMB Signing**: Configure Group Policy to require SMB signing
2. **Enable SMB Encryption**: Implement SMB encryption for sensitive data
3. **Update Clients**: Ensure all clients support modern SMB protocols
4. **Monitor Events**: Set up alerts for SMB security events

### Group Policy Settings
```
Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options

- Microsoft network client: Digitally sign communications (always)
- Microsoft network client: Digitally sign communications (if server agrees)
- Microsoft network server: Digitally sign communications (always)
- Microsoft network server: Digitally sign communications (if client agrees)
```

### Registry Settings
```powershell
# Enable SMB client signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# Enable SMB server signing  
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
```

## Performance Considerations

### Optimization Tips
- **Limit Time Range**: Use shorter time periods for faster execution
- **Targeted Servers**: Audit specific servers rather than entire environment
- **Parallel Processing**: Consider running multiple instances for large environments
- **Event Log Size**: Monitor event log sizes to prevent performance issues

### Resource Usage
- **Memory**: ~50MB per server during analysis
- **Network**: Minimal (only PowerShell remoting traffic)
- **CPU**: Low impact during execution
- **Disk**: Event log read operations

## Version History

### v1.0.0 (Current)
- Initial release
- Event log analysis for SMB signing/encryption failures
- Registry configuration auditing
- CSV export functionality
- Database integration support

## Support

For issues, questions, or feature requests:
- **Author**: Adrian Johnson <adrian207@gmail.com>
- **Repository**: AD-Audit PowerShell Module
- **Documentation**: See README.md for complete module documentation

## License

This module is part of the AD-Audit PowerShell Module suite. See the main module license for terms and conditions.
