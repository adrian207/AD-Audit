<#
.SYNOPSIS
    Master Remediation Orchestrator for AD-Audit

.DESCRIPTION
    Orchestrates comprehensive remediation across all infrastructure components:
    - Active Directory security and hygiene
    - Server infrastructure optimization
    - Microsoft 365 configuration cleanup
    - Automated scheduling and reporting
    - Risk-based prioritization

.PARAMETER DatabasePath
    Path to audit database for issue identification

.PARAMETER RemediationScope
    Scope of remediation (AD, Servers, M365, All)

.PARAMETER Priority
    Priority level for remediation (Critical, High, Medium, Low, All)

.PARAMETER DryRun
    Show what would be remediated without making changes

.PARAMETER Schedule
    Schedule remediation for later execution

.PARAMETER Credential
    Credentials for remediation operations

.PARAMETER LogPath
    Path to save remediation log

.PARAMETER EmailNotification
    Email address for remediation notifications

.EXAMPLE
    .\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -RemediationScope "All" -DryRun

.EXAMPLE
    .\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\AuditData.db" -Priority "Critical" -Credential $cred

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Requires: All remediation modules, appropriate permissions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('AD', 'Servers', 'M365', 'CredentialTheft', 'DomainController', 'LeastPrivilege', 'LegacySystems', 'ThreatDetection', 'ADFS', 'EventMonitoring', 'ADDSAuditing', 'All')]
    [string]$RemediationScope = 'All',
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'All')]
    [string]$Priority = 'All',
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [datetime]$Schedule,
    
    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Temp\MasterRemediation.log",
    
    [Parameter(Mandatory = $false)]
    [string]$EmailNotification
)

$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-RemediationLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Action','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Master-Remediation] [$Level] $Message"
    
    # Write to console
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Action'  { Write-Host $logMessage -ForegroundColor Cyan }
        'Critical' { Write-Host $logMessage -ForegroundColor Red -BackgroundColor Yellow }
        default   { Write-Verbose $logMessage }
    }
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

function Get-DatabaseConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath
    )
    
    try {
        Add-Type -Path "System.Data.SQLite.dll" -ErrorAction Stop
        $connectionString = "Data Source=$DatabasePath;Version=3;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()
        return $connection
    }
    catch {
        Write-RemediationLog "Failed to connect to database: $_" -Level Error
        throw
    }
}

function Invoke-DatabaseQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $true)]
        [string]$Query
    )
    
    try {
        $command = $Connection.CreateCommand()
        $command.CommandText = $Query
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet)
        return $dataSet.Tables[0]
    }
    catch {
        Write-RemediationLog "Database query failed: $_" -Level Error
        throw
    }
}

function Get-RiskAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection
    )
    
    Write-RemediationLog "Performing risk assessment..." -Level Info
    
    try {
        $risks = @{
            Critical = @()
            High = @()
            Medium = @()
            Low = @()
        }
        
        # Critical risks
        $criticalRisks = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 'StalePrivilegedAccounts' as RiskType, COUNT(*) as Count
FROM PrivilegedAccounts pa
LEFT JOIN Users u ON pa.MemberSamAccountName = u.SamAccountName
WHERE u.DaysSinceLastLogon > 90 OR u.Enabled = 0
UNION ALL
SELECT 'KerberosDelegation', COUNT(*)
FROM AD_Kerberos_Delegation
WHERE Severity = 'Critical'
UNION ALL
SELECT 'DangerousACLs', COUNT(*)
FROM AD_ACL_Issues
WHERE Severity = 'Critical'
"@
        
        foreach ($risk in $criticalRisks.Rows) {
            if ($risk.Count -gt 0) {
                $risks.Critical += [PSCustomObject]@{
                    Type = $risk.RiskType
                    Count = $risk.Count
                    Priority = 'Critical'
                }
            }
        }
        
        # High risks
        $highRisks = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 'ServiceAccountRisks' as RiskType, COUNT(*) as Count
FROM AD_Service_Accounts
WHERE SecurityRisk = 'High'
UNION ALL
SELECT 'WeakPasswordPolicy', 1
FROM AD_Password_Policy_Default
WHERE SecurityAssessment = 'Weak'
UNION ALL
SELECT 'InactiveUsers', COUNT(*)
FROM Users
WHERE DaysSinceLastLogon > 180 AND Enabled = 1
"@
        
        foreach ($risk in $highRisks.Rows) {
            if ($risk.Count -gt 0) {
                $risks.High += [PSCustomObject]@{
                    Type = $risk.RiskType
                    Count = $risk.Count
                    Priority = 'High'
                }
            }
        }
        
        # Medium risks
        $mediumRisks = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 'EmptyGroups' as RiskType, COUNT(*) as Count
FROM AD_Groups
WHERE MemberCount = 0
UNION ALL
SELECT 'OversizedMailboxes', COUNT(*)
FROM Exchange_Mailboxes
WHERE TotalItemSizeGB > 50
UNION ALL
SELECT 'InactiveTeams', COUNT(*)
FROM Teams_Teams
WHERE LastActivityDateTime < datetime('now', '-90 days')
"@
        
        foreach ($risk in $mediumRisks.Rows) {
            if ($risk.Count -gt 0) {
                $risks.Medium += [PSCustomObject]@{
                    Type = $risk.RiskType
                    Count = $risk.Count
                    Priority = 'Medium'
                }
            }
        }
        
        # Low risks
        $lowRisks = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 'UnusedApplications' as RiskType, COUNT(*) as Count
FROM Server_Installed_Applications
WHERE ApplicationName LIKE '%Java%' OR ApplicationName LIKE '%Flash%'
UNION ALL
SELECT 'LargeEventLogs', COUNT(*)
FROM Server_Event_Log_Critical
WHERE Count > 1000
"@
        
        foreach ($risk in $lowRisks.Rows) {
            if ($risk.Count -gt 0) {
                $risks.Low += [PSCustomObject]@{
                    Type = $risk.RiskType
                    Count = $risk.Count
                    Priority = 'Low'
                }
            }
        }
        
        Write-RemediationLog "Risk assessment complete" -Level Success
        return $risks
    }
    catch {
        Write-RemediationLog "Risk assessment failed: $_" -Level Error
        throw
    }
}

function Invoke-ADRemediation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath,
        
        [Parameter(Mandatory = $false)]
        [string]$Priority,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    
    Write-RemediationLog "Starting Active Directory remediation..." -Level Info
    
    try {
        $remediationTypes = @()
        
        # Determine remediation types based on priority
        switch ($Priority) {
            'Critical' {
                $remediationTypes = @('PrivilegedAccounts', 'KerberosDelegation', 'ACLIssues')
            }
            'High' {
                $remediationTypes = @('StaleAccounts', 'ServiceAccounts', 'PasswordPolicy')
            }
            'Medium' {
                $remediationTypes = @('GroupHygiene')
            }
            'All' {
                $remediationTypes = @('StaleAccounts', 'PrivilegedAccounts', 'ServiceAccounts', 'KerberosDelegation', 'ACLIssues', 'PasswordPolicy', 'GroupHygiene')
            }
        }
        
        $allActions = @()
        
        foreach ($type in $remediationTypes) {
            try {
                $params = @{
                    RemediationType = $type
                    DatabasePath = $DatabasePath
                    DryRun = $DryRun
                    LogPath = Join-Path (Split-Path $LogPath) "ADRemediation_$type.log"
                }
                
                if ($Credential) {
                    $params.Credential = $Credential
                }
                
                $result = & "$PSScriptRoot\Invoke-ADRemediation.ps1" @params
                $allActions += $result.Actions
                
                Write-RemediationLog "Completed AD remediation: $type ($($result.ActionsCount) actions)" -Level Success
            }
            catch {
                Write-RemediationLog "Failed AD remediation: $type - $_" -Level Error
            }
        }
        
        return $allActions
    }
    catch {
        Write-RemediationLog "Active Directory remediation failed: $_" -Level Error
        throw
    }
}

function Invoke-ServerRemediation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath,
        
        [Parameter(Mandatory = $false)]
        [string]$Priority,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    
    Write-RemediationLog "Starting server remediation..." -Level Info
    
    try {
        $remediationTypes = @()
        
        # Determine remediation types based on priority
        switch ($Priority) {
            'Critical' {
                $remediationTypes = @('Security', 'Patches')
            }
            'High' {
                $remediationTypes = @('Services', 'EventLogs')
            }
            'Medium' {
                $remediationTypes = @('Storage', 'Applications')
            }
            'All' {
                $remediationTypes = @('Patches', 'Services', 'EventLogs', 'Storage', 'Applications', 'Security')
            }
        }
        
        $allActions = @()
        
        foreach ($type in $remediationTypes) {
            try {
                $params = @{
                    RemediationType = $type
                    DatabasePath = $DatabasePath
                    DryRun = $DryRun
                    LogPath = Join-Path (Split-Path $LogPath) "ServerRemediation_$type.log"
                }
                
                if ($Credential) {
                    $params.Credential = $Credential
                }
                
                $result = & "$PSScriptRoot\Invoke-ServerRemediation.ps1" @params
                $allActions += $result.Actions
                
                Write-RemediationLog "Completed server remediation: $type ($($result.ActionsCount) actions)" -Level Success
            }
            catch {
                Write-RemediationLog "Failed server remediation: $type - $_" -Level Error
            }
        }
        
        return $allActions
    }
    catch {
        Write-RemediationLog "Server remediation failed: $_" -Level Error
        throw
    }
}

function Invoke-M365Remediation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath,
        
        [Parameter(Mandatory = $false)]
        [string]$Priority,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    
    Write-RemediationLog "Starting Microsoft 365 remediation..." -Level Info
    
    try {
        $remediationTypes = @()
        
        # Determine remediation types based on priority
        switch ($Priority) {
            'Critical' {
                $remediationTypes = @('Security', 'Compliance')
            }
            'High' {
                $remediationTypes = @('EntraID', 'Exchange')
            }
            'Medium' {
                $remediationTypes = @('SharePoint', 'Teams')
            }
            'All' {
                $remediationTypes = @('EntraID', 'Exchange', 'SharePoint', 'Teams', 'PowerPlatform', 'Compliance', 'Security')
            }
        }
        
        $allActions = @()
        
        foreach ($type in $remediationTypes) {
            try {
                $params = @{
                    RemediationType = $type
                    DatabasePath = $DatabasePath
                    DryRun = $DryRun
                    LogPath = Join-Path (Split-Path $LogPath) "M365Remediation_$type.log"
                }
                
                if ($Credential) {
                    $params.Credential = $Credential
                }
                
                $result = & "$PSScriptRoot\Invoke-M365Remediation.ps1" @params
                $allActions += $result.Actions
                
                Write-RemediationLog "Completed M365 remediation: $type ($($result.ActionsCount) actions)" -Level Success
            }
            catch {
                Write-RemediationLog "Failed M365 remediation: $type - $_" -Level Error
            }
        }
        
        return $allActions
    }
    catch {
        Write-RemediationLog "Microsoft 365 remediation failed: $_" -Level Error
        throw
    }
}

function Send-RemediationNotification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EmailAddress,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Summary
    )
    
    try {
        Write-RemediationLog "Sending remediation notification to: $EmailAddress" -Level Info
        
        $subject = "🔧 AD-Audit Remediation Complete - $($Summary.TotalActions) Actions"
        
        $body = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; text-align: center; }
        .content { padding: 30px; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 5px; text-align: center; min-width: 120px; }
        .metric-value { font-size: 24px; font-weight: bold; color: #667eea; }
        .metric-label { font-size: 12px; color: #666; text-transform: uppercase; }
        .section { margin: 20px 0; }
        .section h3 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 5px; }
        .action-item { background: #f8f9fa; padding: 10px; margin: 5px 0; border-left: 4px solid #667eea; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; border-radius: 0 0 8px 8px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 AD-Audit Remediation Complete</h1>
            <p>Automated remediation process finished successfully</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h3>📊 Summary</h3>
                <div class="metric">
                    <div class="metric-value">$($Summary.TotalActions)</div>
                    <div class="metric-label">Total Actions</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($Summary.CriticalActions)</div>
                    <div class="metric-label">Critical</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($Summary.HighActions)</div>
                    <div class="metric-label">High</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($Summary.MediumActions)</div>
                    <div class="metric-label">Medium</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($Summary.LowActions)</div>
                    <div class="metric-label">Low</div>
                </div>
            </div>
            
            <div class="section">
                <h3>🎯 Remediation Scope</h3>
                <p><strong>Scope:</strong> $($Summary.Scope)</p>
                <p><strong>Priority:</strong> $($Summary.Priority)</p>
                <p><strong>Dry Run:</strong> $($Summary.DryRun)</p>
                <p><strong>Duration:</strong> $($Summary.Duration)</p>
            </div>
            
            <div class="section">
                <h3>📋 Action Breakdown</h3>
                <p><strong>Active Directory:</strong> $($Summary.ADActions) actions</p>
                <p><strong>Servers:</strong> $($Summary.ServerActions) actions</p>
                <p><strong>Microsoft 365:</strong> $($Summary.M365Actions) actions</p>
            </div>
            
            <div class="section">
                <h3>📁 Output Files</h3>
                <p><strong>Log File:</strong> $($Summary.LogPath)</p>
                <p><strong>Summary CSV:</strong> $($Summary.SummaryPath)</p>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by AD-Audit Master Remediation Orchestrator</p>
            <p>Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
    </div>
</body>
</html>
"@
        
        $smtpServer = "smtp.office365.com"
        $smtpPort = 587
        
        $smtpClient = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
        $smtpClient.EnableSsl = $true
        
        $mailMessage = New-Object System.Net.Mail.MailMessage
        $mailMessage.From = "noreply@company.com"
        $mailMessage.To.Add($EmailAddress)
        $mailMessage.Subject = $subject
        $mailMessage.Body = $body
        $mailMessage.IsBodyHtml = $true
        
        $smtpClient.Send($mailMessage)
        
        Write-RemediationLog "Remediation notification sent successfully" -Level Success
    }
    catch {
        Write-RemediationLog "Failed to send remediation notification: $_" -Level Error
    }
}

#endregion

#region Main Execution

try {
    $startTime = Get-Date
    Write-RemediationLog "Starting Master Remediation Orchestrator..." -Level Info
    Write-RemediationLog "Database Path: $DatabasePath" -Level Info
    Write-RemediationLog "Remediation Scope: $RemediationScope" -Level Info
    Write-RemediationLog "Priority: $Priority" -Level Info
    Write-RemediationLog "Dry Run: $DryRun" -Level Info
    Write-RemediationLog "Log Path: $LogPath" -Level Info
    
    # Connect to database
    $connection = Get-DatabaseConnection -DatabasePath $DatabasePath
    Write-RemediationLog "Connected to audit database" -Level Success
    
    # Perform risk assessment
    $riskAssessment = Get-RiskAssessment -Connection $connection
    
    # Display risk summary
    Write-RemediationLog "Risk Assessment Summary:" -Level Info
    Write-RemediationLog "  Critical Risks: $($riskAssessment.Critical.Count)" -Level Critical
    Write-RemediationLog "  High Risks: $($riskAssessment.High.Count)" -Level Warning
    Write-RemediationLog "  Medium Risks: $($riskAssessment.Medium.Count)" -Level Info
    Write-RemediationLog "  Low Risks: $($riskAssessment.Low.Count)" -Level Info
    
    $allActions = @()
    $summary = @{
        TotalActions = 0
        CriticalActions = 0
        HighActions = 0
        MediumActions = 0
        LowActions = 0
        ADActions = 0
        ServerActions = 0
        M365Actions = 0
        CredentialTheftActions = 0
        DomainControllerActions = 0
        LeastPrivilegeActions = 0
        LegacySystemActions = 0
        ThreatDetectionActions = 0
        ADFSActions = 0
        EventMonitoringActions = 0
        ADDSAuditingActions = 0
        Scope = $RemediationScope
        Priority = $Priority
        DryRun = $DryRun
        LogPath = $LogPath
        SummaryPath = ""
    }
    
    # Execute remediation based on scope
    switch ($RemediationScope) {
        'AD' {
            $actions = Invoke-ADRemediation -DatabasePath $DatabasePath -Priority $Priority -DryRun:$DryRun -Credential $Credential
            $allActions += $actions
            $summary.ADActions = $actions.Count
        }
        'Servers' {
            $actions = Invoke-ServerRemediation -DatabasePath $DatabasePath -Priority $Priority -DryRun:$DryRun -Credential $Credential
            $allActions += $actions
            $summary.ServerActions = $actions.Count
        }
        'M365' {
            $actions = Invoke-M365Remediation -DatabasePath $DatabasePath -Priority $Priority -DryRun:$DryRun -Credential $Credential
            $allActions += $actions
            $summary.M365Actions = $actions.Count
        }
        'CredentialTheft' {
            Write-RemediationLog "Executing credential theft prevention remediation..." -Level Info
            $actions = Invoke-CredentialTheftPrevention -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.CredentialTheftActions = $actions.Count
        }
        'DomainController' {
            Write-RemediationLog "Executing domain controller security remediation..." -Level Info
            $actions = Invoke-DomainControllerSecurity -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.DomainControllerActions = $actions.Count
        }
        'LeastPrivilege' {
            Write-RemediationLog "Executing least privilege assessment remediation..." -Level Info
            $actions = Invoke-LeastPrivilegeAssessment -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.LeastPrivilegeActions = $actions.Count
        }
        'LegacySystems' {
            Write-RemediationLog "Executing legacy system management remediation..." -Level Info
            $actions = Invoke-LegacySystemManagement -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.LegacySystemActions = $actions.Count
        }
        'ThreatDetection' {
            Write-RemediationLog "Executing advanced threat detection remediation..." -Level Info
            $actions = Invoke-AdvancedThreatDetection -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.ThreatDetectionActions = $actions.Count
        }
        'ADFS' {
            Write-RemediationLog "Executing AD FS security audit..." -Level Info
            $actions = Invoke-ADFSSecurityAudit -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.ADFSActions = $actions.Count
        }
        'EventMonitoring' {
            Write-RemediationLog "Executing event monitoring..." -Level Info
            $actions = Invoke-EventMonitoring -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.EventMonitoringActions = $actions.Count
        }
        'ADDSAuditing' {
            Write-RemediationLog "Executing AD DS auditing..." -Level Info
            $actions = Invoke-ADDSAuditing -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.ADDSAuditingActions = $actions.Count
        }
        'All' {
            Write-RemediationLog "Executing comprehensive remediation across all components..." -Level Info
            
            $actions = Invoke-ADRemediation -DatabasePath $DatabasePath -Priority $Priority -DryRun:$DryRun -Credential $Credential
            $allActions += $actions
            $summary.ADActions = $actions.Count
            
            $actions = Invoke-ServerRemediation -DatabasePath $DatabasePath -Priority $Priority -DryRun:$DryRun -Credential $Credential
            $allActions += $actions
            $summary.ServerActions = $actions.Count
            
            $actions = Invoke-M365Remediation -DatabasePath $DatabasePath -Priority $Priority -DryRun:$DryRun -Credential $Credential
            $allActions += $actions
            $summary.M365Actions = $actions.Count
            
            # Execute new security modules
            Write-RemediationLog "Executing credential theft prevention..." -Level Info
            $actions = Invoke-CredentialTheftPrevention -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.CredentialTheftActions = $actions.Count
            
            Write-RemediationLog "Executing domain controller security..." -Level Info
            $actions = Invoke-DomainControllerSecurity -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.DomainControllerActions = $actions.Count
            
            Write-RemediationLog "Executing least privilege assessment..." -Level Info
            $actions = Invoke-LeastPrivilegeAssessment -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.LeastPrivilegeActions = $actions.Count
            
            Write-RemediationLog "Executing legacy system management..." -Level Info
            $actions = Invoke-LegacySystemManagement -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.LegacySystemActions = $actions.Count
            
            Write-RemediationLog "Executing advanced threat detection..." -Level Info
            $actions = Invoke-AdvancedThreatDetection -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.ThreatDetectionActions = $actions.Count
            
            Write-RemediationLog "Executing AD FS security audit..." -Level Info
            $actions = Invoke-ADFSSecurityAudit -DatabasePath $DatabasePath -IncludeAll -DryRun:$DryRun
            $allActions += $actions
            $summary.ADFSActions = $actions.Count
        }
    }
    
    # Calculate action counts by priority
    foreach ($action in $allActions) {
        if ($action.Priority -eq 'Critical') { $summary.CriticalActions++ }
        elseif ($action.Priority -eq 'High') { $summary.HighActions++ }
        elseif ($action.Priority -eq 'Medium') { $summary.MediumActions++ }
        elseif ($action.Priority -eq 'Low') { $summary.LowActions++ }
    }
    
    $summary.TotalActions = $allActions.Count
    
    # Calculate duration
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $summary.Duration = "$($duration.Hours)h $($duration.Minutes)m $($duration.Seconds)s"
    
    # Export comprehensive summary
    if ($allActions.Count -gt 0) {
        $summaryPath = Join-Path (Split-Path $LogPath) "MasterRemediationSummary.csv"
        $allActions | Export-Csv -Path $summaryPath -NoTypeInformation
        $summary.SummaryPath = $summaryPath
        Write-RemediationLog "Comprehensive summary exported to: $summaryPath" -Level Success
    }
    
    # Send notification if email provided
    if ($EmailNotification) {
        Send-RemediationNotification -EmailAddress $EmailNotification -Summary $summary
    }
    
    Write-RemediationLog "Master Remediation Orchestrator completed successfully" -Level Success
    Write-RemediationLog "Total actions: $($summary.TotalActions)" -Level Success
    Write-RemediationLog "Duration: $($summary.Duration)" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Actions = $allActions
        RiskAssessment = $riskAssessment
        Message = "Master remediation completed successfully"
    }
}
catch {
    Write-RemediationLog "Master Remediation Orchestrator failed: $_" -Level Error
    throw
}
finally {
    if ($connection) {
        $connection.Close()
        Write-RemediationLog "Database connection closed" -Level Info
    }
}

#endregion
