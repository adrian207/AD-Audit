<#
.SYNOPSIS
    Advanced audit reports using SQLite cross-dataset analysis
    
.DESCRIPTION
    Generates advanced HTML reports that correlate data across multiple audit domains.
    Demonstrates the power of in-memory database for M&A audit analysis.
    Author: Adrian Johnson <adrian207@gmail.com>
    
.PARAMETER OutputFolder
    Path to audit output folder containing audit.db
    
.PARAMETER CompanyName
    Name of audited company
    
.EXAMPLE
    .\New-AdvancedAuditReports.ps1 -OutputFolder "C:\Audits\Contoso\RawData" -CompanyName "Contoso"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,
    
    [Parameter(Mandatory = $true)]
    [string]$CompanyName,
    
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath
)

# Import SQLite helper module
$sqliteModule = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
. $sqliteModule

#region HTML Helpers

function Get-AdvancedReportHeader {
    param([string]$Title)
    
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f5f5; 
            color: #333;
            line-height: 1.6;
        }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        .header { 
            background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%);
            color: white; 
            padding: 40px 20px; 
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { font-size: 1.2em; opacity: 0.9; }
        .header .badge { 
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            margin-top: 10px;
            font-size: 0.9em;
        }
        .section { 
            background: white; 
            padding: 30px; 
            margin-bottom: 20px; 
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 { 
            color: #2563eb; 
            border-bottom: 3px solid #2563eb; 
            padding-bottom: 10px; 
            margin-bottom: 20px;
        }
        .section h3 {
            color: #7c3aed;
            margin-top: 25px;
            margin-bottom: 15px;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
            font-size: 0.9em;
        }
        th { 
            background: #2563eb; 
            color: white; 
            padding: 12px; 
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        td { 
            padding: 10px 12px; 
            border-bottom: 1px solid #e0e0e0;
        }
        tr:hover { background: #f8f8f8; }
        tr:nth-child(even) { background: #f9fafb; }
        tr:nth-child(even):hover { background: #f1f5f9; }
        .badge { 
            display: inline-block; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 0.85em;
            font-weight: 600;
            white-space: nowrap;
        }
        .badge-critical { background: #dc2626; color: white; }
        .badge-high { background: #ea580c; color: white; }
        .badge-medium { background: #f59e0b; color: white; }
        .badge-low { background: #10b981; color: white; }
        .badge-info { background: #3b82f6; color: white; }
        .alert { 
            padding: 15px; 
            border-radius: 8px; 
            margin: 15px 0;
            border-left: 4px solid;
        }
        .alert-critical { background: #fee2e2; border-color: #dc2626; color: #991b1b; }
        .alert-warning { background: #fef3c7; border-color: #f59e0b; color: #92400e; }
        .alert-info { background: #dbeafe; border-color: #3b82f6; color: #1e3a8a; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-box .number { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .stat-box .label { font-size: 0.9em; opacity: 0.9; }
        .query-info {
            background: #f3f4f6;
            border-left: 4px solid #6366f1;
            padding: 15px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            border-radius: 4px;
        }
        .risk-matrix {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .risk-card {
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            transition: transform 0.2s;
        }
        .risk-card:hover { transform: translateY(-3px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .risk-card.critical { border-color: #dc2626; background: #fef2f2; }
        .risk-card.high { border-color: #ea580c; background: #fff7ed; }
        .risk-card.medium { border-color: #f59e0b; background: #fffbeb; }
        .footer { text-align: center; padding: 20px; color: #666; margin-top: 40px; }
    </style>
</head>
<body>
"@
}

function Get-AdvancedReportFooter {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    return @"
    <div class="footer">
        <p><strong>Advanced Report Generated: $timestamp</strong></p>
        <p>M&A Technical Discovery Tool with SQLite Analytics</p>
        <p>Author: Adrian Johnson &lt;adrian207@gmail.com&gt;</p>
    </div>
</body>
</html>
"@
}

#endregion

#region Report 1: Privileged User Risk Analysis

function New-PrivilegedUserRiskReport {
    param(
        [System.Data.SQLite.SQLiteConnection]$Connection,
        [string]$CompanyName
    )
    
    Write-Host "Generating Privileged User Risk Analysis..." -ForegroundColor Cyan
    
    $html = Get-AdvancedReportHeader -Title "$CompanyName - Privileged User Risk Analysis"
    
    $html += @"
<div class="container">
    <div class="header">
        <h1>$CompanyName</h1>
        <div class="subtitle">Privileged User Risk Analysis</div>
        <div class="badge">🔒 Cross-Dataset Security Intelligence</div>
    </div>
"@
    
    # Query 1: Privileged users accessing SQL servers with backup issues
    $query1 = @"
SELECT DISTINCT
    pa.MemberSamAccountName,
    pa.GroupName,
    slh.ServerName,
    slh.LogonCount,
    slh.LastLogon,
    COUNT(DISTINCT sd.DatabaseName) AS DatabasesAtRisk,
    GROUP_CONCAT(DISTINCT sd.DatabaseName, ', ') AS DatabaseNames,
    MAX(sd.DaysSinceLastBackup) AS MaxDaysNoBackup
FROM PrivilegedAccounts pa
INNER JOIN ServerLogonHistory slh ON pa.MemberSamAccountName = slh.UserName
INNER JOIN SQLInstances si ON slh.ServerName = si.ServerName
INNER JOIN SQLDatabases sd ON si.ConnectionString = sd.ConnectionString
WHERE sd.BackupIssue != 'OK'
GROUP BY pa.MemberSamAccountName, pa.GroupName, slh.ServerName
ORDER BY MaxDaysNoBackup DESC, DatabasesAtRisk DESC
LIMIT 50;
"@
    
    $criticalAccess = Invoke-AuditQuery -Connection $Connection -Query $query1
    
    $html += @"
    <div class="section">
        <h2>🚨 Critical Finding: Privileged Users Accessing At-Risk SQL Servers</h2>
        <div class="alert alert-critical">
            <strong>Security Risk:</strong> $($criticalAccess.Count) privileged accounts have accessed servers hosting SQL databases with backup issues.
            This combination creates significant data loss and security risks.
        </div>
        
        <div class="query-info">
            <strong>SQL Query Used:</strong><br>
            Cross-joins PrivilegedAccounts → ServerLogonHistory → SQLInstances → SQLDatabases<br>
            Filtered on: BackupIssue != 'OK'
        </div>
"@
    
    if ($criticalAccess.Count -gt 0) {
        $html += @"
        <table>
            <tr>
                <th>Privileged User</th>
                <th>Admin Group</th>
                <th>SQL Server</th>
                <th>Logon Count</th>
                <th>Last Access</th>
                <th>At-Risk DBs</th>
                <th>Max Days No Backup</th>
            </tr>
"@
        foreach ($row in $criticalAccess) {
            $badgeClass = if ($row.MaxDaysNoBackup -gt 30) { 'critical' } 
                         elseif ($row.MaxDaysNoBackup -gt 14) { 'high' } 
                         else { 'medium' }
            
            $html += @"
            <tr>
                <td><strong>$($row.MemberSamAccountName)</strong></td>
                <td><span class="badge badge-critical">$($row.GroupName)</span></td>
                <td>$($row.ServerName)</td>
                <td>$($row.LogonCount)</td>
                <td>$($row.LastLogon)</td>
                <td>$($row.DatabasesAtRisk)</td>
                <td><span class="badge badge-$badgeClass">$($row.MaxDaysNoBackup) days</span></td>
            </tr>
"@
        }
        $html += "</table>"
    } else {
        $html += "<p>✅ No privileged users found accessing servers with backup issues.</p>"
    }
    
    $html += "</div>"
    
    # Query 2: Stale privileged accounts
    $query2 = @"
SELECT 
    pa.MemberSamAccountName,
    pa.GroupName,
    pa.MemberType,
    u.LastLogonDate,
    u.DaysSinceLastLogon,
    u.PasswordLastSet,
    u.Enabled,
    COALESCE(slh.ServerCount, 0) AS RecentServerAccess
FROM PrivilegedAccounts pa
INNER JOIN Users u ON pa.MemberSamAccountName = u.SamAccountName
LEFT JOIN (
    SELECT UserName, COUNT(DISTINCT ServerName) AS ServerCount
    FROM ServerLogonHistory
    GROUP BY UserName
) slh ON u.SamAccountName = slh.UserName
WHERE u.DaysSinceLastLogon > 90 OR u.Enabled = 0
ORDER BY u.DaysSinceLastLogon DESC;
"@
    
    $stalePriv = Invoke-AuditQuery -Connection $Connection -Query $query2
    
    $html += @"
    <div class="section">
        <h2>⚠️ Stale Privileged Accounts</h2>
        <div class="alert alert-warning">
            <strong>$($stalePriv.Count) privileged accounts are stale or disabled</strong> but still retain elevated permissions.
            These should be removed from privileged groups immediately.
        </div>
        
        <table>
            <tr>
                <th>Account</th>
                <th>Privileged Group</th>
                <th>Last Logon</th>
                <th>Days Inactive</th>
                <th>Enabled</th>
                <th>Server Access Count</th>
            </tr>
"@
    
    foreach ($row in $stalePriv) {
        $daysInactive = if ($row.DaysSinceLastLogon -eq 'Never') { '999+' } else { $row.DaysSinceLastLogon }
        $badgeClass = if ($daysInactive -gt 180) { 'critical' } elseif ($daysInactive -gt 90) { 'high' } else { 'medium' }
        
        $html += @"
            <tr>
                <td><strong>$($row.MemberSamAccountName)</strong></td>
                <td><span class="badge badge-critical">$($row.GroupName)</span></td>
                <td>$($row.LastLogonDate)</td>
                <td><span class="badge badge-$badgeClass">$daysInactive</span></td>
                <td><span class="badge badge-$(if($row.Enabled -eq 1){'info'}else{'critical'})">$(if($row.Enabled -eq 1){'Yes'}else{'No'})</span></td>
                <td>$($row.RecentServerAccess)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
"@
    
    # Query 3: Privileged account activity summary
    $query3 = @"
SELECT 
    pa.GroupName,
    COUNT(DISTINCT pa.MemberSamAccountName) AS MemberCount,
    COUNT(DISTINCT slh.ServerName) AS ServersAccessed,
    SUM(slh.LogonCount) AS TotalLogons,
    COUNT(DISTINCT CASE WHEN u.DaysSinceLastLogon > 90 THEN pa.MemberSamAccountName END) AS StaleMembers
FROM PrivilegedAccounts pa
LEFT JOIN Users u ON pa.MemberSamAccountName = u.SamAccountName
LEFT JOIN ServerLogonHistory slh ON pa.MemberSamAccountName = slh.UserName
GROUP BY pa.GroupName
ORDER BY MemberCount DESC;
"@
    
    $groupStats = Invoke-AuditQuery -Connection $Connection -Query $query3
    
    $html += @"
    <div class="section">
        <h2>📊 Privileged Group Activity Summary</h2>
        <table>
            <tr>
                <th>Privileged Group</th>
                <th>Members</th>
                <th>Servers Accessed</th>
                <th>Total Logons</th>
                <th>Stale Members</th>
            </tr>
"@
    
    foreach ($row in $groupStats) {
        $stalePercent = if ($row.MemberCount -gt 0) { [math]::Round(($row.StaleMembers / $row.MemberCount) * 100) } else { 0 }
        $staleBadge = if ($stalePercent -gt 30) { 'critical' } elseif ($stalePercent -gt 10) { 'high' } else { 'low' }
        
        $html += @"
            <tr>
                <td><strong>$($row.GroupName)</strong></td>
                <td>$($row.MemberCount)</td>
                <td>$($row.ServersAccessed)</td>
                <td>$($row.TotalLogons)</td>
                <td><span class="badge badge-$staleBadge">$($row.StaleMembers) ($stalePercent%)</span></td>
            </tr>
"@
    }
    
    $html += "</table></div>"
    
    $html += "</div>"
    $html += Get-AdvancedReportFooter
    
    return $html
}

#endregion

#region Report 2: Service Account Dependency Analysis

function New-ServiceAccountDependencyReport {
    param(
        [System.Data.SQLite.SQLiteConnection]$Connection,
        [string]$CompanyName
    )
    
    Write-Host "Generating Service Account Dependency Analysis..." -ForegroundColor Cyan
    
    $html = Get-AdvancedReportHeader -Title "$CompanyName - Service Account Dependency Analysis"
    
    $html += @"
<div class="container">
    <div class="header">
        <h1>$CompanyName</h1>
        <div class="subtitle">Service Account Dependency & Impact Analysis</div>
        <div class="badge">🔧 Cross-System Dependency Mapping</div>
    </div>
"@
    
    # Query: Service account comprehensive impact
    $query = @"
SELECT 
    sa.SamAccountName,
    sa.DisplayName,
    sa.SPNCount,
    sa.DetectionReason,
    -- Server access
    COALESCE(server_access.ServerCount, 0) AS ServersAccessed,
    COALESCE(server_access.TotalLogons, 0) AS TotalServerLogons,
    server_access.ServerList,
    -- SQL access
    COALESCE(sql_access.SQLInstanceCount, 0) AS SQLInstancesUsing,
    COALESCE(sql_access.IsSysAdmin, 0) AS HasSysAdminRights,
    sql_access.SQLInstances,
    -- Application presence
    COALESCE(app_presence.AppCount, 0) AS RelatedApplications,
    app_presence.Applications,
    -- SQL jobs
    COALESCE(job_owner.JobCount, 0) AS SQLJobsOwned,
    job_owner.Jobs,
    -- Risk scoring
    CASE
        WHEN COALESCE(sql_access.IsSysAdmin, 0) > 0 THEN 'CRITICAL'
        WHEN COALESCE(server_access.ServerCount, 0) > 10 THEN 'HIGH'
        WHEN COALESCE(sql_access.SQLInstanceCount, 0) > 0 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS ImpactLevel
FROM ServiceAccounts sa
-- Server logon history
LEFT JOIN (
    SELECT 
        UserName,
        COUNT(DISTINCT ServerName) AS ServerCount,
        SUM(LogonCount) AS TotalLogons,
        GROUP_CONCAT(DISTINCT ServerName, ', ') AS ServerList
    FROM ServerLogonHistory
    GROUP BY UserName
) server_access ON sa.SamAccountName = server_access.UserName
-- SQL logins
LEFT JOIN (
    SELECT 
        LoginName,
        COUNT(DISTINCT ConnectionString) AS SQLInstanceCount,
        SUM(IsSysAdmin) AS IsSysAdmin,
        GROUP_CONCAT(DISTINCT ConnectionString, ', ') AS SQLInstances
    FROM SQLLogins
    GROUP BY LoginName
) sql_access ON sa.SamAccountName = sql_access.LoginName
-- Applications mentioning service account
LEFT JOIN (
    SELECT 
        SUBSTR(ApplicationName, INSTR(ApplicationName, SamAccountName)) AS AccountRef,
        COUNT(DISTINCT ApplicationName) AS AppCount,
        GROUP_CONCAT(DISTINCT ApplicationName, '; ') AS Applications
    FROM ServerApplications, ServiceAccounts
    WHERE ApplicationName LIKE '%' || SamAccountName || '%'
    GROUP BY AccountRef
) app_presence ON sa.SamAccountName = app_presence.AccountRef
-- SQL jobs owned
LEFT JOIN (
    SELECT 
        Owner,
        COUNT(*) AS JobCount,
        GROUP_CONCAT(JobName, '; ') AS Jobs
    FROM SQLJobs
    GROUP BY Owner
) job_owner ON sa.SamAccountName = job_owner.Owner
ORDER BY 
    CASE ImpactLevel
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END,
    ServersAccessed DESC;
"@
    
    $serviceAccounts = Invoke-AuditQuery -Connection $Connection -Query $query
    
    # Summary stats
    $criticalCount = ($serviceAccounts | Where-Object { $_.ImpactLevel -eq 'CRITICAL' }).Count
    $highCount = ($serviceAccounts | Where-Object { $_.ImpactLevel -eq 'HIGH' }).Count
    $mediumCount = ($serviceAccounts | Where-Object { $_.ImpactLevel -eq 'MEDIUM' }).Count
    $lowCount = ($serviceAccounts | Where-Object { $_.ImpactLevel -eq 'LOW' }).Count
    
    $html += @"
    <div class="section">
        <h2>📊 Service Account Impact Overview</h2>
        <div class="stats-grid">
            <div class="stat-box" style="background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);">
                <div class="number">$criticalCount</div>
                <div class="label">Critical Impact</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #ea580c 0%, #c2410c 100%);">
                <div class="number">$highCount</div>
                <div class="label">High Impact</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);">
                <div class="number">$mediumCount</div>
                <div class="label">Medium Impact</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">
                <div class="number">$lowCount</div>
                <div class="label">Low Impact</div>
            </div>
        </div>
        
        <div class="alert alert-info">
            <strong>💡 What This Means:</strong> This report shows the blast radius if each service account is disabled or compromised.
            Critical and High impact accounts require immediate documentation and migration planning.
        </div>
    </div>
"@
    
    # Critical service accounts
    $criticalAccounts = $serviceAccounts | Where-Object { $_.ImpactLevel -eq 'CRITICAL' -or $_.ImpactLevel -eq 'HIGH' }
    
    if ($criticalAccounts.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>🚨 Critical & High Impact Service Accounts</h2>
        <div class="alert alert-critical">
            <strong>Immediate Attention Required:</strong> These $($criticalAccounts.Count) service accounts have elevated permissions or wide-reaching dependencies.
            Disabling these accounts could cause significant service outages.
        </div>
"@
        
        foreach ($acc in $criticalAccounts) {
            $badgeColor = if ($acc.ImpactLevel -eq 'CRITICAL') { 'critical' } else { 'high' }
            
            $html += @"
        <div class="risk-card $($acc.ImpactLevel.ToLower())">
            <h3>🔧 $($acc.SamAccountName)</h3>
            <p><strong>Display Name:</strong> $($acc.DisplayName)</p>
            <p><strong>Impact Level:</strong> <span class="badge badge-$badgeColor">$($acc.ImpactLevel)</span></p>
            <p><strong>Detection Method:</strong> $($acc.DetectionReason)</p>
            <hr style="margin: 15px 0; border: none; border-top: 1px solid #e5e7eb;">
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <div>
                    <strong>Server Access:</strong><br>
                    $($acc.ServersAccessed) servers ($($acc.TotalServerLogons) logons)
                </div>
                <div>
                    <strong>SQL Instances:</strong><br>
                    $($acc.SQLInstancesUsing) instances
                    $(if($acc.HasSysAdminRights -gt 0){"<span class='badge badge-critical'>SYSADMIN</span>"}else{""})
                </div>
                <div>
                    <strong>SQL Jobs Owned:</strong><br>
                    $($acc.SQLJobsOwned) jobs
                </div>
                <div>
                    <strong>SPNs Registered:</strong><br>
                    $($acc.SPNCount) SPNs
                </div>
            </div>
            
            $(if($acc.ServerList){"<p style='margin-top:10px;'><strong>Servers:</strong> $($acc.ServerList)</p>"}else{""})
            $(if($acc.SQLInstances){"<p><strong>SQL Instances:</strong> $($acc.SQLInstances)</p>"}else{""})
            $(if($acc.Jobs){"<p><strong>SQL Jobs:</strong> $($acc.Jobs)</p>"}else{""})
        </div>
"@
        }
        
        $html += "</div>"
    }
    
    # Full table
    $html += @"
    <div class="section">
        <h2>📋 Complete Service Account Inventory</h2>
        <table>
            <tr>
                <th>Service Account</th>
                <th>Impact</th>
                <th>Servers</th>
                <th>SQL Instances</th>
                <th>SysAdmin</th>
                <th>SQL Jobs</th>
                <th>SPNs</th>
            </tr>
"@
    
    foreach ($acc in $serviceAccounts) {
        $badgeClass = switch ($acc.ImpactLevel) {
            'CRITICAL' { 'critical' }
            'HIGH' { 'high' }
            'MEDIUM' { 'medium' }
            default { 'low' }
        }
        
        $html += @"
            <tr>
                <td><strong>$($acc.SamAccountName)</strong><br><small>$($acc.DisplayName)</small></td>
                <td><span class="badge badge-$badgeClass">$($acc.ImpactLevel)</span></td>
                <td>$($acc.ServersAccessed)</td>
                <td>$($acc.SQLInstancesUsing)</td>
                <td>$(if($acc.HasSysAdminRights -gt 0){"<span class='badge badge-critical'>YES</span>"}else{"No"})</td>
                <td>$($acc.SQLJobsOwned)</td>
                <td>$($acc.SPNCount)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
"@
    
    $html += "</div>"
    $html += Get-AdvancedReportFooter
    
    return $html
}

#endregion

#region Report 3: Migration Complexity Scoring

function New-MigrationComplexityReport {
    param(
        [System.Data.SQLite.SQLiteConnection]$Connection,
        [string]$CompanyName
    )
    
    Write-Host "Generating Migration Complexity Analysis..." -ForegroundColor Cyan
    
    $html = Get-AdvancedReportHeader -Title "$CompanyName - Migration Complexity Analysis"
    
    $html += @"
<div class="container">
    <div class="header">
        <h1>$CompanyName</h1>
        <div class="subtitle">Server Migration Complexity & Risk Scoring</div>
        <div class="badge">📊 Multi-Factor Analysis</div>
    </div>
"@
    
    # Complex migration scoring query
    $query = @"
SELECT 
    s.ServerName,
    s.IsVirtual,
    s.CPUCores,
    s.MemoryGB,
    s.OSName,
    s.UptimeDays,
    -- Database factor
    COALESCE(db_count.DatabaseCount, 0) AS DatabaseCount,
    COALESCE(db_count.TotalDBSizeGB, 0) AS TotalDBSizeGB,
    COALESCE(db_count.BackupIssues, 0) AS DatabaseBackupIssues,
    -- User activity factor
    COALESCE(user_activity.UniqueUsers, 0) AS UniqueUsersAccess,
    COALESCE(user_activity.TotalLogons, 0) AS TotalLogons,
    COALESCE(user_activity.PrivilegedUsers, 0) AS PrivilegedUsersAccess,
    -- Application factor
    COALESCE(apps.ApplicationCount, 0) AS ApplicationCount,
    COALESCE(apps.CustomApps, 0) AS CustomApplications,
    -- SQL dependencies
    COALESCE(sql_deps.LinkedServerCount, 0) AS LinkedServerCount,
    COALESCE(sql_deps.JobCount, 0) AS SQLJobCount,
    -- Storage factor
    COALESCE(storage.TotalStorageGB, 0) AS TotalStorageGB,
    COALESCE(storage.LowSpaceVolumes, 0) AS LowSpaceVolumes,
    -- Calculate complexity score (0-100, higher = more complex)
    (
        -- Physical servers are harder to migrate
        CASE WHEN s.IsVirtual = 0 THEN 25 ELSE 0 END +
        -- Database presence adds complexity
        CASE 
            WHEN COALESCE(db_count.DatabaseCount, 0) = 0 THEN 0
            WHEN COALESCE(db_count.DatabaseCount, 0) <= 5 THEN 15
            WHEN COALESCE(db_count.DatabaseCount, 0) <= 15 THEN 25
            ELSE 35
        END +
        -- Large databases are complex
        CASE 
            WHEN COALESCE(db_count.TotalDBSizeGB, 0) > 500 THEN 15
            WHEN COALESCE(db_count.TotalDBSizeGB, 0) > 100 THEN 10
            ELSE 0
        END +
        -- Backup issues add risk
        CASE WHEN COALESCE(db_count.BackupIssues, 0) > 0 THEN 10 ELSE 0 END +
        -- High user activity means more testing needed
        CASE 
            WHEN COALESCE(user_activity.UniqueUsers, 0) > 50 THEN 10
            WHEN COALESCE(user_activity.UniqueUsers, 0) > 20 THEN 5
            ELSE 0
        END +
        -- Privileged access requires extra security planning
        CASE WHEN COALESCE(user_activity.PrivilegedUsers, 0) > 0 THEN 5 ELSE 0 END +
        -- Many applications = complex dependencies
        CASE 
            WHEN COALESCE(apps.ApplicationCount, 0) > 30 THEN 10
            WHEN COALESCE(apps.ApplicationCount, 0) > 10 THEN 5
            ELSE 0
        END +
        -- Custom apps are hard to re-install
        COALESCE(apps.CustomApps, 0) * 3 +
        -- Linked servers create dependencies
        COALESCE(sql_deps.LinkedServerCount, 0) * 5 +
        -- SQL jobs need to be migrated
        CASE WHEN COALESCE(sql_deps.JobCount, 0) > 10 THEN 10
             WHEN COALESCE(sql_deps.JobCount, 0) > 0 THEN 5
             ELSE 0 
        END
    ) AS ComplexityScore,
    -- Risk factors
    CASE 
        WHEN s.UptimeDays > 365 THEN 'High - Long uptime, untested failover'
        WHEN COALESCE(db_count.BackupIssues, 0) > 0 THEN 'High - Backup issues present'
        WHEN s.IsVirtual = 0 AND COALESCE(db_count.DatabaseCount, 0) > 0 THEN 'High - Physical + Database'
        WHEN COALESCE(sql_deps.LinkedServerCount, 0) > 2 THEN 'Medium - Multiple dependencies'
        ELSE 'Low'
    END AS RiskLevel
FROM Servers s
-- Database metrics
LEFT JOIN (
    SELECT 
        si.ServerName,
        COUNT(DISTINCT sd.DatabaseName) AS DatabaseCount,
        SUM(sd.SizeGB) AS TotalDBSizeGB,
        COUNT(DISTINCT CASE WHEN sd.BackupIssue != 'OK' THEN sd.DatabaseName END) AS BackupIssues
    FROM SQLInstances si
    INNER JOIN SQLDatabases sd ON si.ConnectionString = sd.ConnectionString
    GROUP BY si.ServerName
) db_count ON s.ServerName = db_count.ServerName
-- User activity
LEFT JOIN (
    SELECT 
        slh.ServerName,
        COUNT(DISTINCT slh.UserName) AS UniqueUsers,
        SUM(slh.LogonCount) AS TotalLogons,
        COUNT(DISTINCT CASE WHEN pa.MemberSamAccountName IS NOT NULL THEN slh.UserName END) AS PrivilegedUsers
    FROM ServerLogonHistory slh
    LEFT JOIN PrivilegedAccounts pa ON slh.UserName = pa.MemberSamAccountName
    GROUP BY slh.ServerName
) user_activity ON s.ServerName = user_activity.ServerName
-- Applications
LEFT JOIN (
    SELECT 
        ServerName,
        COUNT(*) AS ApplicationCount,
        COUNT(CASE WHEN ApplicationName LIKE '%Custom%' OR Publisher LIKE '%Internal%' THEN 1 END) AS CustomApps
    FROM ServerApplications
    GROUP BY ServerName
) apps ON s.ServerName = apps.ServerName
-- SQL dependencies
LEFT JOIN (
    SELECT 
        si.ServerName,
        COUNT(DISTINCT ls.LinkedServerName) AS LinkedServerCount,
        COUNT(DISTINCT sj.JobName) AS JobCount
    FROM SQLInstances si
    LEFT JOIN LinkedServers ls ON si.ConnectionString = ls.ConnectionString
    LEFT JOIN SQLJobs sj ON si.ConnectionString = sj.ConnectionString
    GROUP BY si.ServerName
) sql_deps ON s.ServerName = sql_deps.ServerName
-- Storage
LEFT JOIN (
    SELECT 
        ServerName,
        SUM(SizeGB) AS TotalStorageGB,
        COUNT(CASE WHEN PercentFree < 15 THEN 1 END) AS LowSpaceVolumes
    FROM ServerStorage
    GROUP BY ServerName
) storage ON s.ServerName = storage.ServerName
WHERE s.Status = 'Success'
ORDER BY ComplexityScore DESC, DatabaseCount DESC;
"@
    
    $servers = Invoke-AuditQuery -Connection $Connection -Query $query
    
    # Calculate overall statistics
    $avgComplexity = ($servers | Measure-Object -Property ComplexityScore -Average).Average
    $highComplexity = ($servers | Where-Object { $_.ComplexityScore -gt 60 }).Count
    $mediumComplexity = ($servers | Where-Object { $_.ComplexityScore -gt 30 -and $_.ComplexityScore -le 60 }).Count
    $lowComplexity = ($servers | Where-Object { $_.ComplexityScore -le 30 }).Count
    
    $html += @"
    <div class="section">
        <h2>📊 Overall Migration Complexity</h2>
        <div class="stats-grid">
            <div class="stat-box" style="background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);">
                <div class="number">$highComplexity</div>
                <div class="label">High Complexity (60+)</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);">
                <div class="number">$mediumComplexity</div>
                <div class="label">Medium Complexity (30-60)</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">
                <div class="number">$lowComplexity</div>
                <div class="label">Low Complexity (<30)</div>
            </div>
            <div class="stat-box" style="background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);">
                <div class="number">$([math]::Round($avgComplexity, 1))</div>
                <div class="label">Average Score</div>
            </div>
        </div>
        
        <div class="query-info">
            <strong>Complexity Scoring Factors:</strong><br>
            • Physical vs Virtual (25 pts) • Database Count (15-35 pts) • Database Size (0-15 pts)<br>
            • Backup Issues (10 pts) • User Activity (0-10 pts) • Application Count (0-10 pts)<br>
            • Custom Apps (3 pts each) • Linked Servers (5 pts each) • SQL Jobs (5-10 pts)
        </div>
    </div>
"@
    
    # Top 20 most complex servers
    $topComplex = $servers | Select-Object -First 20
    
    $html += @"
    <div class="section">
        <h2>🎯 Top 20 Most Complex Servers (Migration Planning Priority)</h2>
        <div class="alert alert-warning">
            <strong>Strategic Planning Required:</strong> These servers have the highest migration complexity.
            Start planning these migrations early and allocate additional resources and testing time.
        </div>
        
        <table>
            <tr>
                <th>Server</th>
                <th>Complexity<br>Score</th>
                <th>Virtual</th>
                <th>DBs</th>
                <th>DB Size</th>
                <th>Users</th>
                <th>Apps</th>
                <th>SQL Jobs</th>
                <th>Risk Factors</th>
            </tr>
"@
    
    foreach ($srv in $topComplex) {
        $scoreClass = if ($srv.ComplexityScore -gt 60) { 'critical' }
                     elseif ($srv.ComplexityScore -gt 40) { 'high' }
                     elseif ($srv.ComplexityScore -gt 20) { 'medium' }
                     else { 'low' }
        
        $html += @"
            <tr>
                <td><strong>$($srv.ServerName)</strong></td>
                <td><span class="badge badge-$scoreClass">$($srv.ComplexityScore)</span></td>
                <td>$(if($srv.IsVirtual -eq 1){'✅'}else{'❌ Physical'})</td>
                <td>$($srv.DatabaseCount)</td>
                <td>$([math]::Round($srv.TotalDBSizeGB, 1)) GB</td>
                <td>$($srv.UniqueUsersAccess)$(if($srv.PrivilegedUsersAccess -gt 0){" <span class='badge badge-critical'>+$($srv.PrivilegedUsersAccess) Admin</span>"})</td>
                <td>$($srv.ApplicationCount)$(if($srv.CustomApplications -gt 0){" ($($srv.CustomApplications) custom)"})</td>
                <td>$($srv.SQLJobCount)</td>
                <td><small>$($srv.RiskLevel)</small></td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
"@
    
    $html += "</div>"
    $html += Get-AdvancedReportFooter
    
    return $html
}

#endregion

#region Main Execution

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Advanced Audit Report Generator" -ForegroundColor Cyan
    Write-Host "Using SQLite Cross-Dataset Analysis" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Determine database path
    if (-not $DatabasePath) {
        $DatabasePath = Join-Path $OutputFolder "audit.db"
    }
    
    # Check if database exists, if not create and import
    if (-not (Test-Path $DatabasePath)) {
        Write-Host "Database not found. Creating and importing CSV data..." -ForegroundColor Yellow
        
        $connection = Initialize-AuditDatabase -DatabasePath $DatabasePath
        Import-AuditCSVsToDatabase -Connection $connection -RawDataFolder $OutputFolder
        
        Write-Host "✅ Database created and populated" -ForegroundColor Green
    } else {
        Write-Host "Loading existing database: $DatabasePath" -ForegroundColor Green
        $connectionString = "Data Source=$DatabasePath;Version=3;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()
    }
    
    # Generate reports
    $reportPath = Split-Path $OutputFolder -Parent
    
    Write-Host "`nGenerating advanced reports..." -ForegroundColor Cyan
    
    # Report 1: Privileged User Risk Analysis
    $report1Html = New-PrivilegedUserRiskReport -Connection $connection -CompanyName $CompanyName
    $report1Path = Join-Path $reportPath "advanced-privileged-user-risk.html"
    $report1Html | Out-File -FilePath $report1Path -Encoding UTF8
    Write-Host "✅ Report 1: $report1Path" -ForegroundColor Green
    
    # Report 2: Service Account Dependencies
    $report2Html = New-ServiceAccountDependencyReport -Connection $connection -CompanyName $CompanyName
    $report2Path = Join-Path $reportPath "advanced-service-account-dependencies.html"
    $report2Html | Out-File -FilePath $report2Path -Encoding UTF8
    Write-Host "✅ Report 2: $report2Path" -ForegroundColor Green
    
    # Report 3: Migration Complexity
    $report3Html = New-MigrationComplexityReport -Connection $connection -CompanyName $CompanyName
    $report3Path = Join-Path $reportPath "advanced-migration-complexity.html"
    $report3Html | Out-File -FilePath $report3Path -Encoding UTF8
    Write-Host "✅ Report 3: $report3Path" -ForegroundColor Green
    
    $connection.Close()
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "✅ Advanced Reports Generated!" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
    
    Write-Host "Reports saved to:" -ForegroundColor Cyan
    Write-Host "  1. Privileged User Risk Analysis" -ForegroundColor White
    Write-Host "  2. Service Account Dependencies" -ForegroundColor White
    Write-Host "  3. Migration Complexity Scoring" -ForegroundColor White
    Write-Host ""
    
    # Open first report
    Start-Process $report1Path
}
catch {
    Write-Host "`n❌ Error generating advanced reports: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    throw
}

#endregion

