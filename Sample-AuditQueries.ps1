<#
.SYNOPSIS
    Sample ad-hoc queries demonstrating SQLite audit database capabilities
    
.DESCRIPTION
    Collection of useful queries for analyzing audit data.
    Copy these queries or use as templates for your own analysis.
    
    Author: Adrian Johnson <adrian207@gmail.com>
    
.PARAMETER DatabasePath
    Path to audit.db file
    
.EXAMPLE
    .\Sample-AuditQueries.ps1 -DatabasePath "C:\Audits\TestCo\RawData\audit.db"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath
)

# Import SQLite helper
$sqliteModule = Join-Path $PSScriptRoot "Libraries\SQLite-AuditDB.ps1"
. $sqliteModule

# Connect to database
if (-not (Test-Path $DatabasePath)) {
    Write-Host "❌ Database not found: $DatabasePath" -ForegroundColor Red
    exit 1
}

Write-Host "📊 Connecting to audit database..." -ForegroundColor Cyan
$connectionString = "Data Source=$DatabasePath;Version=3;"
$connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
$connection.Open()

Write-Host "✅ Connected successfully!`n" -ForegroundColor Green

#region Sample Queries

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sample Query 1: Privileged Users with SQL Access" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$query1 = @"
SELECT DISTINCT
    pa.MemberSamAccountName AS PrivilegedUser,
    pa.GroupName AS AdminGroup,
    sl.ConnectionString AS SQLInstance,
    sl.IsSysAdmin,
    sl.ServerRoles
FROM PrivilegedAccounts pa
INNER JOIN SQLLogins sl ON pa.MemberSamAccountName = sl.LoginName
WHERE sl.IsDisabled = 0
ORDER BY sl.IsSysAdmin DESC, pa.GroupName;
"@

Write-Host "Query:" -ForegroundColor Yellow
Write-Host $query1 -ForegroundColor Gray
Write-Host ""

$results1 = Invoke-AuditQuery -Connection $connection -Query $query1
Write-Host "Results: $($results1.Count) rows`n" -ForegroundColor Green

if ($results1.Count -gt 0) {
    $results1 | Select-Object -First 10 | Format-Table -AutoSize
    if ($results1.Count -gt 10) {
        Write-Host "... showing first 10 of $($results1.Count) results`n" -ForegroundColor Gray
    }
}

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host

#---

Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sample Query 2: Servers Without Recent Backups" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$query2 = @"
SELECT 
    si.ServerName,
    si.InstanceName,
    sd.DatabaseName,
    sd.SizeGB,
    sd.RecoveryModel,
    sd.DaysSinceLastBackup,
    sd.LastFullBackup,
    CASE 
        WHEN sd.DaysSinceLastBackup > 30 THEN 'CRITICAL'
        WHEN sd.DaysSinceLastBackup > 14 THEN 'HIGH'
        WHEN sd.DaysSinceLastBackup > 7 THEN 'MEDIUM'
        ELSE 'OK'
    END AS RiskLevel
FROM SQLInstances si
INNER JOIN SQLDatabases sd ON si.ConnectionString = sd.ConnectionString
WHERE sd.BackupIssue != 'OK'
ORDER BY sd.DaysSinceLastBackup DESC, sd.SizeGB DESC
LIMIT 20;
"@

Write-Host "Query:" -ForegroundColor Yellow
Write-Host $query2 -ForegroundColor Gray
Write-Host ""

$results2 = Invoke-AuditQuery -Connection $connection -Query $query2
Write-Host "Results: $($results2.Count) rows`n" -ForegroundColor Green

if ($results2.Count -gt 0) {
    $results2 | Format-Table -AutoSize
} else {
    Write-Host "✅ No backup issues found!" -ForegroundColor Green
}

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host

#---

Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sample Query 3: Service Account Footprint" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$query3 = @"
SELECT 
    sa.SamAccountName,
    sa.SPNCount,
    -- Server access
    COUNT(DISTINCT slh.ServerName) AS ServersAccessed,
    SUM(slh.LogonCount) AS TotalLogons,
    -- SQL presence
    COUNT(DISTINCT sl.ConnectionString) AS SQLInstances,
    SUM(sl.IsSysAdmin) AS SysAdminInstances,
    -- Jobs owned
    COUNT(DISTINCT sj.JobName) AS JobsOwned
FROM ServiceAccounts sa
LEFT JOIN ServerLogonHistory slh ON sa.SamAccountName = slh.UserName
LEFT JOIN SQLLogins sl ON sa.SamAccountName = sl.LoginName
LEFT JOIN SQLJobs sj ON sa.SamAccountName = sj.Owner
GROUP BY sa.SamAccountName
ORDER BY SysAdminInstances DESC, ServersAccessed DESC
LIMIT 15;
"@

Write-Host "Query:" -ForegroundColor Yellow
Write-Host $query3 -ForegroundColor Gray
Write-Host ""

$results3 = Invoke-AuditQuery -Connection $connection -Query $query3
Write-Host "Results: $($results3.Count) rows`n" -ForegroundColor Green

if ($results3.Count -gt 0) {
    $results3 | Format-Table -AutoSize
}

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host

#---

Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sample Query 4: Stale Accounts with Recent Activity" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$query4 = @"
SELECT 
    u.SamAccountName,
    u.DisplayName,
    u.Department,
    u.DaysSinceLastLogon AS ADInactiveDays,
    slh.LastLogon AS RecentServerLogon,
    slh.ServerName,
    slh.LogonCount
FROM Users u
INNER JOIN ServerLogonHistory slh ON u.SamAccountName = slh.UserName
WHERE u.IsStale = 1  -- Marked stale in AD (90+ days)
  AND julianday('now') - julianday(slh.LastLogon) < 30  -- But recent server access
ORDER BY u.DaysSinceLastLogon DESC;
"@

Write-Host "Query:" -ForegroundColor Yellow
Write-Host $query4 -ForegroundColor Gray
Write-Host ""

$results4 = Invoke-AuditQuery -Connection $connection -Query $query4
Write-Host "Results: $($results4.Count) rows`n" -ForegroundColor Green

if ($results4.Count -gt 0) {
    Write-Host "⚠️  Found accounts marked stale in AD but actively used!" -ForegroundColor Yellow
    $results4 | Format-Table -AutoSize
} else {
    Write-Host "✅ No discrepancies found" -ForegroundColor Green
}

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host

#---

Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sample Query 5: Application Version Sprawl" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$query5 = @"
SELECT 
    ApplicationName,
    COUNT(DISTINCT Version) AS VersionCount,
    COUNT(DISTINCT ServerName) AS ServerCount,
    GROUP_CONCAT(DISTINCT Version, ', ') AS Versions,
    CASE 
        WHEN COUNT(DISTINCT Version) > 5 THEN 'HIGH SPRAWL'
        WHEN COUNT(DISTINCT Version) > 2 THEN 'MEDIUM SPRAWL'
        ELSE 'STANDARDIZED'
    END AS SprawlRisk
FROM ServerApplications
WHERE ApplicationName NOT LIKE 'Microsoft%'
  AND ApplicationName NOT LIKE 'Update for%'
GROUP BY ApplicationName
HAVING ServerCount >= 5 AND VersionCount > 1
ORDER BY VersionCount DESC, ServerCount DESC
LIMIT 20;
"@

Write-Host "Query:" -ForegroundColor Yellow
Write-Host $query5 -ForegroundColor Gray
Write-Host ""

$results5 = Invoke-AuditQuery -Connection $connection -Query $query5
Write-Host "Results: $($results5.Count) rows`n" -ForegroundColor Green

if ($results5.Count -gt 0) {
    $results5 | Format-Table -AutoSize
}

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host

#---

Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sample Query 6: SQL Databases by Size Category" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$query6 = @"
SELECT 
    CASE 
        WHEN SizeGB < 1 THEN '< 1 GB'
        WHEN SizeGB < 10 THEN '1-10 GB'
        WHEN SizeGB < 50 THEN '10-50 GB'
        WHEN SizeGB < 100 THEN '50-100 GB'
        WHEN SizeGB < 500 THEN '100-500 GB'
        ELSE '> 500 GB'
    END AS SizeCategory,
    COUNT(*) AS DatabaseCount,
    ROUND(SUM(SizeGB), 2) AS TotalSizeGB,
    ROUND(AVG(SizeGB), 2) AS AvgSizeGB,
    COUNT(CASE WHEN BackupIssue != 'OK' THEN 1 END) AS WithBackupIssues
FROM SQLDatabases
GROUP BY SizeCategory
ORDER BY MIN(SizeGB);
"@

Write-Host "Query:" -ForegroundColor Yellow
Write-Host $query6 -ForegroundColor Gray
Write-Host ""

$results6 = Invoke-AuditQuery -Connection $connection -Query $query6
Write-Host "Results: $($results6.Count) rows`n" -ForegroundColor Green

if ($results6.Count -gt 0) {
    $results6 | Format-Table -AutoSize
}

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host

#---

Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sample Query 7: Linked Server Dependencies" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$query7 = @"
SELECT 
    si.ServerName AS SourceServer,
    si.InstanceName,
    ls.LinkedServerName,
    ls.Product,
    ls.DataSource,
    -- Count databases on source
    (SELECT COUNT(*) 
     FROM SQLDatabases sd 
     WHERE sd.ConnectionString = si.ConnectionString) AS DatabaseCount,
    -- Count jobs using linked server
    (SELECT COUNT(*) 
     FROM SQLJobs sj 
     WHERE sj.ConnectionString = si.ConnectionString) AS JobCount
FROM SQLInstances si
INNER JOIN LinkedServers ls ON si.ConnectionString = ls.ConnectionString
ORDER BY JobCount DESC, DatabaseCount DESC;
"@

Write-Host "Query:" -ForegroundColor Yellow
Write-Host $query7 -ForegroundColor Gray
Write-Host ""

$results7 = Invoke-AuditQuery -Connection $connection -Query $query7
Write-Host "Results: $($results7.Count) rows`n" -ForegroundColor Green

if ($results7.Count -gt 0) {
    $results7 | Format-Table -AutoSize
} else {
    Write-Host "ℹ️  No linked servers found" -ForegroundColor Gray
}

Write-Host "Press Enter to continue..." -ForegroundColor Yellow
Read-Host

#---

Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Sample Query 8: Custom Query Prompt" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "Available tables:" -ForegroundColor Yellow
$tables = Invoke-AuditQuery -Connection $connection -Query "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
$tables | ForEach-Object { Write-Host "  - $($_.name)" -ForegroundColor White }
Write-Host ""

Write-Host "Enter your custom SQL query (or press Enter to skip):" -ForegroundColor Cyan
Write-Host "Example: SELECT * FROM Users WHERE Department = 'IT' LIMIT 10" -ForegroundColor Gray
$customQuery = Read-Host

if ($customQuery) {
    try {
        $customResults = Invoke-AuditQuery -Connection $connection -Query $customQuery
        Write-Host "`nResults: $($customResults.Count) rows`n" -ForegroundColor Green
        
        if ($customResults.Count -gt 0) {
            $customResults | Select-Object -First 20 | Format-Table -AutoSize
            if ($customResults.Count -gt 20) {
                Write-Host "... showing first 20 of $($customResults.Count) results" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "❌ Query failed: $_" -ForegroundColor Red
    }
}

#endregion

# Cleanup
$connection.Close()

Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "✅ Query Demo Complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════`n" -ForegroundColor Green

Write-Host "💡 Key Takeaways:" -ForegroundColor Yellow
Write-Host "  1. Complex multi-table joins are EASY with SQL" -ForegroundColor White
Write-Host "  2. Results return in milliseconds, not minutes" -ForegroundColor White
Write-Host "  3. You can answer any ad-hoc question instantly" -ForegroundColor White
Write-Host "  4. No need to re-run the audit for new insights" -ForegroundColor White
Write-Host ""

Write-Host "📚 Next Steps:" -ForegroundColor Cyan
Write-Host "  • Copy these queries to build your own reports" -ForegroundColor White
Write-Host "  • Modify queries to answer your specific questions" -ForegroundColor White
Write-Host "  • Use DB Browser for SQLite for visual query building" -ForegroundColor White
Write-Host "  • See docs/SQLITE_POC_GUIDE.md for more examples" -ForegroundColor White
Write-Host ""

