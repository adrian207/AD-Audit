<#
.SYNOPSIS
    Advanced Analytics Engine for M&A Audit Data
    
.DESCRIPTION
    Provides trend analysis, anomaly detection, risk scoring, executive dashboards,
    and alerting for audit data. Compares multiple audits over time to identify
    changes, risks, and opportunities.
    
.PARAMETER BaselineAuditPath
    Path to baseline audit database (older audit for comparison)
    
.PARAMETER CurrentAuditPath
    Path to current audit database
    
.PARAMETER OutputFolder
    Folder to save analytics reports
    
.PARAMETER CompanyName
    Company name for reports
    
.PARAMETER AlertThresholds
    Custom alert thresholds (hashtable)
    
.PARAMETER GenerateDashboard
    Generate executive dashboard HTML
    
.PARAMETER EnableAlerts
    Enable alerting system
    
.EXAMPLE
    .\Invoke-Analytics-Engine.ps1 -BaselineAuditPath "C:\Audits\Baseline\AuditData.db" `
                                   -CurrentAuditPath "C:\Audits\Current\AuditData.db" `
                                   -OutputFolder "C:\Analytics" `
                                   -CompanyName "Contoso"
    
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Requires: System.Data.SQLite, Pester (for testing)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BaselineAuditPath,
    
    [Parameter(Mandatory = $false)]
    [string]$CurrentAuditPath,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,
    
    [Parameter(Mandatory = $true)]
    [string]$CompanyName,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$AlertThresholds = @{},
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateDashboard,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableAlerts
)

#region Helper Functions

function Write-AnalyticsLog {
    <#
    .SYNOPSIS
        Writes log messages to console and file
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $colors = @{
        'Info' = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error' = 'Red'
    }
    
    Write-Host $logMessage -ForegroundColor $colors[$Level]
    
    # Log to file
    $logFile = Join-Path $OutputFolder "analytics_log.txt"
    $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8
}

function Get-DatabaseConnection {
    <#
    .SYNOPSIS
        Opens SQLite database connection
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath
    )
    
    if (-not (Test-Path $DatabasePath)) {
        throw "Database not found: $DatabasePath"
    }
    
    $connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$DatabasePath;Version=3;Read Only=True;")
    $connection.Open()
    return $connection
}

function Invoke-DatabaseQuery {
    <#
    .SYNOPSIS
        Executes SQL query and returns results
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $true)]
        [string]$Query
    )
    
    $command = $Connection.CreateCommand()
    $command.CommandText = $Query
    $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
    $dataSet = New-Object System.Data.DataSet
    [void]$adapter.Fill($dataSet)
    
    return $dataSet.Tables[0]
}

#endregion

#region Trend Analysis

function Compare-AuditData {
    <#
    .SYNOPSIS
        Compares baseline and current audit data
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselinePath,
        
        [Parameter(Mandatory = $true)]
        [string]$CurrentPath
    )
    
    Write-AnalyticsLog "Comparing audit data: Baseline vs Current" -Level Info
    
    $comparison = @{
        Users = @{}
        Computers = @{}
        Servers = @{}
        Groups = @{}
        PrivilegedAccounts = @{}
        ServiceAccounts = @{}
        SQLDatabases = @{}
        Summary = @{}
    }
    
    try {
        $baselineConn = Get-DatabaseConnection -DatabasePath $BaselinePath
        $currentConn = Get-DatabaseConnection -DatabasePath $CurrentPath
        
        # Compare Users
        $baselineUsers = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(*) as Count FROM Users"
        $currentUsers = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(*) as Count FROM Users"
        
        $comparison.Users = @{
            Baseline = $baselineUsers.Rows[0].Count
            Current = $currentUsers.Rows[0].Count
            Change = $currentUsers.Rows[0].Count - $baselineUsers.Rows[0].Count
            PercentChange = if ($baselineUsers.Rows[0].Count -gt 0) {
                [math]::Round((($currentUsers.Rows[0].Count - $baselineUsers.Rows[0].Count) / $baselineUsers.Rows[0].Count) * 100, 2)
            } else { 0 }
        }
        
        # Compare Computers
        $baselineComputers = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(*) as Count FROM Computers"
        $currentComputers = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(*) as Count FROM Computers"
        
        $comparison.Computers = @{
            Baseline = $baselineComputers.Rows[0].Count
            Current = $currentComputers.Rows[0].Count
            Change = $currentComputers.Rows[0].Count - $baselineComputers.Rows[0].Count
            PercentChange = if ($baselineComputers.Rows[0].Count -gt 0) {
                [math]::Round((($currentComputers.Rows[0].Count - $baselineComputers.Rows[0].Count) / $baselineComputers.Rows[0].Count) * 100, 2)
            } else { 0 }
        }
        
        # Compare Servers
        $baselineServers = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(*) as Count FROM Servers"
        $currentServers = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(*) as Count FROM Servers"
        
        $comparison.Servers = @{
            Baseline = $baselineServers.Rows[0].Count
            Current = $currentServers.Rows[0].Count
            Change = $currentServers.Rows[0].Count - $baselineServers.Rows[0].Count
            PercentChange = if ($baselineServers.Rows[0].Count -gt 0) {
                [math]::Round((($currentServers.Rows[0].Count - $baselineServers.Rows[0].Count) / $baselineServers.Rows[0].Count) * 100, 2)
            } else { 0 }
        }
        
        # Compare Groups
        $baselineGroups = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(*) as Count FROM Groups"
        $currentGroups = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(*) as Count FROM Groups"
        
        $comparison.Groups = @{
            Baseline = $baselineGroups.Rows[0].Count
            Current = $currentGroups.Rows[0].Count
            Change = $currentGroups.Rows[0].Count - $baselineGroups.Rows[0].Count
            PercentChange = if ($baselineGroups.Rows[0].Count -gt 0) {
                [math]::Round((($currentGroups.Rows[0].Count - $baselineGroups.Rows[0].Count) / $baselineGroups.Rows[0].Count) * 100, 2)
            } else { 0 }
        }
        
        # Compare Privileged Accounts
        $baselinePriv = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(DISTINCT MemberSamAccountName) as Count FROM PrivilegedAccounts"
        $currentPriv = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(DISTINCT MemberSamAccountName) as Count FROM PrivilegedAccounts"
        
        $comparison.PrivilegedAccounts = @{
            Baseline = $baselinePriv.Rows[0].Count
            Current = $currentPriv.Rows[0].Count
            Change = $currentPriv.Rows[0].Count - $baselinePriv.Rows[0].Count
            PercentChange = if ($baselinePriv.Rows[0].Count -gt 0) {
                [math]::Round((($currentPriv.Rows[0].Count - $baselinePriv.Rows[0].Count) / $baselinePriv.Rows[0].Count) * 100, 2)
            } else { 0 }
        }
        
        # Compare Service Accounts (if table exists)
        try {
            $baselineSvc = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(*) as Count FROM AD_Service_Accounts"
            $currentSvc = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(*) as Count FROM AD_Service_Accounts"
            
            $comparison.ServiceAccounts = @{
                Baseline = $baselineSvc.Rows[0].Count
                Current = $currentSvc.Rows[0].Count
                Change = $currentSvc.Rows[0].Count - $baselineSvc.Rows[0].Count
                PercentChange = if ($baselineSvc.Rows[0].Count -gt 0) {
                    [math]::Round((($currentSvc.Rows[0].Count - $baselineSvc.Rows[0].Count) / $baselineSvc.Rows[0].Count) * 100, 2)
                } else { 0 }
            }
        }
        catch {
            Write-AnalyticsLog "Service accounts table not found in one or both databases" -Level Warning
        }
        
        # Compare SQL Databases (if table exists)
        try {
            $baselineSQL = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(*) as Count, SUM(SizeGB) as TotalSizeGB FROM SQLDatabases"
            $currentSQL = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(*) as Count, SUM(SizeGB) as TotalSizeGB FROM SQLDatabases"
            
            $comparison.SQLDatabases = @{
                Baseline = $baselineSQL.Rows[0].Count
                Current = $currentSQL.Rows[0].Count
                Change = $currentSQL.Rows[0].Count - $baselineSQL.Rows[0].Count
                BaselineSizeGB = [math]::Round($baselineSQL.Rows[0].TotalSizeGB, 2)
                CurrentSizeGB = [math]::Round($currentSQL.Rows[0].TotalSizeGB, 2)
                SizeChangeGB = [math]::Round($currentSQL.Rows[0].TotalSizeGB - $baselineSQL.Rows[0].TotalSizeGB, 2)
            }
        }
        catch {
            Write-AnalyticsLog "SQL databases table not found in one or both databases" -Level Warning
        }
        
        Write-AnalyticsLog "Data comparison complete" -Level Success
        
        return $comparison
    }
    finally {
        if ($baselineConn) { $baselineConn.Close() }
        if ($currentConn) { $currentConn.Close() }
    }
}

function Get-TrendAnalysis {
    <#
    .SYNOPSIS
        Analyzes trends across multiple audits
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$AuditPaths
    )
    
    Write-AnalyticsLog "Analyzing trends across $($AuditPaths.Count) audits" -Level Info
    
    $trends = @{
        UserGrowth = @()
        ComputerGrowth = @()
        ServerGrowth = @()
        PrivilegedAccountGrowth = @()
        DataGrowth = @()
    }
    
    foreach ($auditPath in $AuditPaths) {
        try {
            $conn = Get-DatabaseConnection -DatabasePath $auditPath
            
            # Get audit timestamp from metadata or file
            $auditDate = (Get-Item $auditPath).LastWriteTime
            
            # Collect metrics
            $users = Invoke-DatabaseQuery -Connection $conn -Query "SELECT COUNT(*) as Count FROM Users"
            $computers = Invoke-DatabaseQuery -Connection $conn -Query "SELECT COUNT(*) as Count FROM Computers"
            $servers = Invoke-DatabaseQuery -Connection $conn -Query "SELECT COUNT(*) as Count FROM Servers"
            $privAccounts = Invoke-DatabaseQuery -Connection $conn -Query "SELECT COUNT(DISTINCT MemberSamAccountName) as Count FROM PrivilegedAccounts"
            
            $trends.UserGrowth += [PSCustomObject]@{
                Date = $auditDate
                Count = $users.Rows[0].Count
            }
            
            $trends.ComputerGrowth += [PSCustomObject]@{
                Date = $auditDate
                Count = $computers.Rows[0].Count
            }
            
            $trends.ServerGrowth += [PSCustomObject]@{
                Date = $auditDate
                Count = $servers.Rows[0].Count
            }
            
            $trends.PrivilegedAccountGrowth += [PSCustomObject]@{
                Date = $auditDate
                Count = $privAccounts.Rows[0].Count
            }
            
            $conn.Close()
        }
        catch {
            Write-AnalyticsLog "Failed to process audit: $auditPath - $_" -Level Warning
        }
    }
    
    Write-AnalyticsLog "Trend analysis complete" -Level Success
    return $trends
}

#endregion

#region Anomaly Detection

function Find-Anomalies {
    <#
    .SYNOPSIS
        Detects anomalies in audit data
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselinePath,
        
        [Parameter(Mandatory = $true)]
        [string]$CurrentPath
    )
    
    Write-AnalyticsLog "Detecting anomalies..." -Level Info
    
    $anomalies = @()
    
    try {
        $baselineConn = Get-DatabaseConnection -DatabasePath $BaselinePath
        $currentConn = Get-DatabaseConnection -DatabasePath $CurrentPath
        
        # Anomaly 1: Large increase in privileged accounts (>10%)
        $baselinePriv = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(DISTINCT MemberSamAccountName) as Count FROM PrivilegedAccounts"
        $currentPriv = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(DISTINCT MemberSamAccountName) as Count FROM PrivilegedAccounts"
        
        $privChange = (($currentPriv.Rows[0].Count - $baselinePriv.Rows[0].Count) / $baselinePriv.Rows[0].Count) * 100
        
        if ($privChange -gt 10) {
            $anomalies += [PSCustomObject]@{
                Category = "Security"
                Severity = "High"
                Title = "Significant increase in privileged accounts"
                Description = "Privileged account count increased by $([math]::Round($privChange, 2))% ($($baselinePriv.Rows[0].Count) → $($currentPriv.Rows[0].Count))"
                Recommendation = "Review recent privileged account additions for legitimacy"
            }
        }
        
        # Anomaly 2: Stale privileged accounts
        $stalePriv = Invoke-DatabaseQuery -Connection $currentConn -Query @"
SELECT COUNT(DISTINCT pa.MemberSamAccountName) as Count
FROM PrivilegedAccounts pa
LEFT JOIN Users u ON pa.MemberSamAccountName = u.SamAccountName
WHERE u.IsStale = 1 OR u.Enabled = 0
"@
        
        if ($stalePriv.Rows[0].Count -gt 0) {
            $anomalies += [PSCustomObject]@{
                Category = "Security"
                Severity = "Critical"
                Title = "Stale privileged accounts detected"
                Description = "$($stalePriv.Rows[0].Count) privileged accounts are stale or disabled but still have elevated rights"
                Recommendation = "Remove stale accounts from privileged groups immediately"
            }
        }
        
        # Anomaly 3: Service accounts with old passwords
        try {
            $oldPasswords = Invoke-DatabaseQuery -Connection $currentConn -Query @"
SELECT COUNT(*) as Count
FROM AD_Service_Accounts
WHERE PasswordAgeDays > 365 OR PasswordNeverExpires = 1
"@
            
            if ($oldPasswords.Rows[0].Count -gt 0) {
                $anomalies += [PSCustomObject]@{
                    Category = "Security"
                    Severity = "High"
                    Title = "Service accounts with password issues"
                    Description = "$($oldPasswords.Rows[0].Count) service accounts have passwords older than 1 year or never expire"
                    Recommendation = "Implement password rotation policy for service accounts"
                }
            }
        }
        catch {
            # Table might not exist
        }
        
        # Anomaly 4: Kerberos delegation risks
        try {
            $kerbRisks = Invoke-DatabaseQuery -Connection $currentConn -Query @"
SELECT COUNT(*) as Count
FROM AD_Kerberos_Delegation
WHERE Severity = 'Critical'
"@
            
            if ($kerbRisks.Rows[0].Count -gt 0) {
                $anomalies += [PSCustomObject]@{
                    Category = "Security"
                    Severity = "Critical"
                    Title = "Kerberos unconstrained delegation detected"
                    Description = "$($kerbRisks.Rows[0].Count) accounts have unconstrained delegation configured (high privilege escalation risk)"
                    Recommendation = "Review and remove unconstrained delegation or use constrained delegation instead"
                }
            }
        }
        catch {
            # Table might not exist
        }
        
        # Anomaly 5: Dangerous ACL permissions
        try {
            $aclIssues = Invoke-DatabaseQuery -Connection $currentConn -Query @"
SELECT COUNT(*) as Count
FROM AD_ACL_Issues
WHERE Severity IN ('Critical', 'High')
"@
            
            if ($aclIssues.Rows[0].Count -gt 0) {
                $anomalies += [PSCustomObject]@{
                    Category = "Security"
                    Severity = "High"
                    Title = "Dangerous AD permissions detected"
                    Description = "$($aclIssues.Rows[0].Count) critical/high severity ACL issues found in Active Directory"
                    Recommendation = "Review and remediate excessive permissions on AD objects"
                }
            }
        }
        catch {
            # Table might not exist
        }
        
        # Anomaly 6: Large database growth (>20%)
        try {
            $baselineDBSize = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT SUM(SizeGB) as TotalSize FROM SQLDatabases"
            $currentDBSize = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT SUM(SizeGB) as TotalSize FROM SQLDatabases"
            
            $dbGrowth = (($currentDBSize.Rows[0].TotalSize - $baselineDBSize.Rows[0].TotalSize) / $baselineDBSize.Rows[0].TotalSize) * 100
            
            if ($dbGrowth -gt 20) {
                $anomalies += [PSCustomObject]@{
                    Category = "Capacity"
                    Severity = "Medium"
                    Title = "Significant database growth"
                    Description = "SQL databases grew by $([math]::Round($dbGrowth, 2))% ($([math]::Round($baselineDBSize.Rows[0].TotalSize, 2))GB → $([math]::Round($currentDBSize.Rows[0].TotalSize, 2))GB)"
                    Recommendation = "Review database growth patterns and plan storage capacity accordingly"
                }
            }
        }
        catch {
            # Table might not exist
        }
        
        # Anomaly 7: Servers going offline
        $baselineOnline = Invoke-DatabaseQuery -Connection $baselineConn -Query "SELECT COUNT(*) as Count FROM Servers WHERE Online = 1"
        $currentOnline = Invoke-DatabaseQuery -Connection $currentConn -Query "SELECT COUNT(*) as Count FROM Servers WHERE Online = 1"
        
        $offlineChange = $baselineOnline.Rows[0].Count - $currentOnline.Rows[0].Count
        
        if ($offlineChange -gt 0) {
            $anomalies += [PSCustomObject]@{
                Category = "Availability"
                Severity = "Medium"
                Title = "Servers going offline"
                Description = "$offlineChange server(s) were online in baseline but are now offline"
                Recommendation = "Investigate server availability issues"
            }
        }
        
        Write-AnalyticsLog "Found $($anomalies.Count) anomalies" -Level Info
        
        return $anomalies
    }
    finally {
        if ($baselineConn) { $baselineConn.Close() }
        if ($currentConn) { $currentConn.Close() }
    }
}

#endregion

#region Risk Scoring

function Get-RiskScore {
    <#
    .SYNOPSIS
        Calculates comprehensive risk score
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath
    )
    
    Write-AnalyticsLog "Calculating risk score..." -Level Info
    
    $riskFactors = @{
        StalePrivilegedAccounts = 0
        ServiceAccountRisks = 0
        KerberosDelegation = 0
        DangerousACLs = 0
        WeakPasswordPolicy = 0
        BackupRisks = 0
        UntrustedTrusts = 0
    }
    
    $maxScore = 100
    $currentScore = $maxScore
    
    try {
        $conn = Get-DatabaseConnection -DatabasePath $DatabasePath
        
        # Risk Factor 1: Stale privileged accounts (-15 points)
        $stalePriv = Invoke-DatabaseQuery -Connection $conn -Query @"
SELECT COUNT(DISTINCT pa.MemberSamAccountName) as Count
FROM PrivilegedAccounts pa
LEFT JOIN Users u ON pa.MemberSamAccountName = u.SamAccountName
WHERE u.IsStale = 1 OR u.Enabled = 0
"@
        
        if ($stalePriv.Rows[0].Count -gt 0) {
            $riskFactors.StalePrivilegedAccounts = $stalePriv.Rows[0].Count
            $currentScore -= 15
        }
        
        # Risk Factor 2: Service account risks (-10 points)
        try {
            $svcRisks = Invoke-DatabaseQuery -Connection $conn -Query @"
SELECT COUNT(*) as Count
FROM AD_Service_Accounts
WHERE SecurityRisk = 'High'
"@
            
            if ($svcRisks.Rows[0].Count -gt 0) {
                $riskFactors.ServiceAccountRisks = $svcRisks.Rows[0].Count
                $currentScore -= 10
            }
        }
        catch {}
        
        # Risk Factor 3: Kerberos unconstrained delegation (-20 points)
        try {
            $kerbRisks = Invoke-DatabaseQuery -Connection $conn -Query @"
SELECT COUNT(*) as Count
FROM AD_Kerberos_Delegation
WHERE Severity = 'Critical'
"@
            
            if ($kerbRisks.Rows[0].Count -gt 0) {
                $riskFactors.KerberosDelegation = $kerbRisks.Rows[0].Count
                $currentScore -= 20
            }
        }
        catch {}
        
        # Risk Factor 4: Dangerous ACLs (-15 points)
        try {
            $aclRisks = Invoke-DatabaseQuery -Connection $conn -Query @"
SELECT COUNT(*) as Count
FROM AD_ACL_Issues
WHERE Severity = 'Critical'
"@
            
            if ($aclRisks.Rows[0].Count -gt 0) {
                $riskFactors.DangerousACLs = $aclRisks.Rows[0].Count
                $currentScore -= 15
            }
        }
        catch {}
        
        # Risk Factor 5: Weak password policy (-10 points)
        try {
            $pwdPolicy = Invoke-DatabaseQuery -Connection $conn -Query @"
SELECT SecurityAssessment
FROM AD_Password_Policy_Default
LIMIT 1
"@
            
            if ($pwdPolicy.Rows.Count -gt 0 -and $pwdPolicy.Rows[0].SecurityAssessment -eq 'Weak') {
                $riskFactors.WeakPasswordPolicy = 1
                $currentScore -= 10
            }
        }
        catch {}
        
        # Risk Factor 6: SQL backup risks (-10 points)
        try {
            $backupRisks = Invoke-DatabaseQuery -Connection $conn -Query @"
SELECT COUNT(*) as Count
FROM SQLDatabases
WHERE BackupIssue IS NOT NULL
"@
            
            if ($backupRisks.Rows[0].Count -gt 0) {
                $riskFactors.BackupRisks = $backupRisks.Rows[0].Count
                $currentScore -= 10
            }
        }
        catch {}
        
        # Risk Factor 7: Untrusted trusts (-10 points)
        try {
            $trustRisks = Invoke-DatabaseQuery -Connection $conn -Query @"
SELECT COUNT(*) as Count
FROM AD_Trusts
WHERE SecurityLevel = 'Review Required'
"@
            
            if ($trustRisks.Rows[0].Count -gt 0) {
                $riskFactors.UntrustedTrusts = $trustRisks.Rows[0].Count
                $currentScore -= 10
            }
        }
        catch {}
        
        # Ensure score doesn't go negative
        if ($currentScore -lt 0) { $currentScore = 0 }
        
        $riskLevel = switch ($currentScore) {
            { $_ -ge 80 } { "Low" }
            { $_ -ge 60 } { "Medium" }
            { $_ -ge 40 } { "High" }
            default { "Critical" }
        }
        
        Write-AnalyticsLog "Risk score calculated: $currentScore/100 ($riskLevel)" -Level Info
        
        return [PSCustomObject]@{
            Score = $currentScore
            MaxScore = $maxScore
            Level = $riskLevel
            Factors = $riskFactors
        }
    }
    finally {
        if ($conn) { $conn.Close() }
    }
}

#endregion

# Main execution
Write-AnalyticsLog "=== M&A Audit Analytics Engine Started ===" -Level Info
Write-AnalyticsLog "Company: $CompanyName" -Level Info
Write-AnalyticsLog "Output: $OutputFolder" -Level Info

# Create output folder
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

# Export functions for testing
Export-ModuleMember -Function @(
    'Compare-AuditData',
    'Get-TrendAnalysis',
    'Find-Anomalies',
    'Get-RiskScore',
    'Get-DatabaseConnection',
    'Invoke-DatabaseQuery'
)

Write-AnalyticsLog "Analytics Engine loaded successfully" -Level Success

