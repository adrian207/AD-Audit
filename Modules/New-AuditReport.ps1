<#
.SYNOPSIS
    Generates HTML reports from M&A audit CSV data

.DESCRIPTION
    Creates executive summary and detailed HTML reports from audit CSV files
    Author: Adrian Johnson <adrian207@gmail.com>
    
.PARAMETER OutputFolder
    Path to audit output folder containing CSV files

.PARAMETER CompanyName
    Name of audited company

.EXAMPLE
    .\New-AuditReport.ps1 -OutputFolder "C:\Audits\Contoso" -CompanyName "Contoso"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,
    
    [Parameter(Mandatory = $true)]
    [string]$CompanyName,
    
    [Parameter(Mandatory = $false)]
    [string]$ReportTitle
)

#region Helper Functions

function Write-ReportLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        default { 'White' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-HTMLHeader {
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
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 40px 20px; 
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .nav { 
            background: white; 
            padding: 15px; 
            border-radius: 8px; 
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .nav a { 
            color: #667eea; 
            text-decoration: none; 
            padding: 8px 16px;
            border-radius: 5px;
            transition: all 0.3s;
        }
        .nav a:hover { 
            background: #667eea; 
            color: white; 
        }
        .section { 
            background: white; 
            padding: 30px; 
            margin-bottom: 20px; 
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 { 
            color: #667eea; 
            border-bottom: 3px solid #667eea; 
            padding-bottom: 10px; 
            margin-bottom: 20px;
        }
        .metrics { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin: 20px 0;
        }
        .metric-card { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 25px; 
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .metric-card:hover { transform: translateY(-5px); }
        .metric-card h3 { font-size: 2.5em; margin-bottom: 5px; }
        .metric-card p { font-size: 1em; opacity: 0.9; }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
            background: white;
        }
        th { 
            background: #667eea; 
            color: white; 
            padding: 12px; 
            text-align: left;
            font-weight: 600;
        }
        td { 
            padding: 10px 12px; 
            border-bottom: 1px solid #e0e0e0;
        }
        tr:hover { background: #f8f8f8; }
        .badge { 
            display: inline-block; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-success { background: #10b981; color: white; }
        .badge-warning { background: #f59e0b; color: white; }
        .badge-danger { background: #ef4444; color: white; }
        .badge-info { background: #3b82f6; color: white; }
        .alert { 
            padding: 15px; 
            border-radius: 8px; 
            margin: 15px 0;
            border-left: 4px solid;
        }
        .alert-warning { background: #fef3c7; border-color: #f59e0b; color: #92400e; }
        .alert-danger { background: #fee2e2; border-color: #ef4444; color: #991b1b; }
        .alert-info { background: #dbeafe; border-color: #3b82f6; color: #1e3a8a; }
        .progress-bar {
            background: #e0e0e0;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            height: 100%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.85em;
            font-weight: 600;
        }
        .footer { 
            text-align: center; 
            padding: 20px; 
            color: #666; 
            margin-top: 40px;
        }
        .chart { 
            margin: 20px 0; 
            padding: 20px; 
            background: #f9f9f9; 
            border-radius: 8px;
        }
    </style>
</head>
<body>
"@
}

function Get-HTMLFooter {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    return @"
    <div class="footer">
        <p>Generated on $timestamp by M&A Technical Discovery Tool</p>
        <p>Author: Adrian Johnson &lt;adrian207@gmail.com&gt;</p>
    </div>
</body>
</html>
"@
}

function Import-CSVSafe {
    param([string]$Path)
    
    if (Test-Path $Path) {
        try {
            return Import-Csv -Path $Path
        }
        catch {
            Write-ReportLog "Failed to import $Path : $_" -Level Warning
            return @()
        }
    }
    return @()
}

function Format-Number {
    param([long]$Number)
    
    if ($Number -ge 1TB) {
        return "{0:N2} TB" -f ($Number / 1TB)
    }
    elseif ($Number -ge 1GB) {
        return "{0:N2} GB" -f ($Number / 1GB)
    }
    elseif ($Number -ge 1MB) {
        return "{0:N2} MB" -f ($Number / 1MB)
    }
    else {
        return "{0:N0} KB" -f ($Number / 1KB)
    }
}

#endregion

#region Executive Summary Report

function New-ExecutiveSummaryReport {
    param(
        [string]$OutputFolder,
        [string]$CompanyName,
        [string]$ReportTitle
    )
    
    Write-ReportLog "Generating executive summary report..." -Level Info
    
    $title = if ($ReportTitle) { $ReportTitle } else { "$CompanyName - M&A Technical Discovery Executive Summary" }
    $html = Get-HTMLHeader -Title $title
    
    # Container and header
    $html += @"
<div class="container">
    <div class="header">
        <h1>$CompanyName</h1>
        <p>M&A Technical Discovery - Executive Summary</p>
    </div>
    
    <div class="nav">
        <a href="executive-summary.html">Executive Summary</a>
        <a href="active-directory.html">Active Directory</a>
        <a href="servers.html">Server Infrastructure</a>
        <a href="sql-databases.html">SQL Databases</a>
        <a href="security.html">Security Analysis</a>
    </div>
"@
    
    # Load data
    $adPath = Join-Path $OutputFolder "AD"
    $serverPath = Join-Path $OutputFolder "Servers"
    $sqlPath = Join-Path $OutputFolder "SQL"
    
    $users = Import-CSVSafe (Join-Path $adPath "AD_Users.csv")
    $computers = Import-CSVSafe (Join-Path $adPath "AD_Computers.csv")
    $groups = Import-CSVSafe (Join-Path $adPath "AD_Groups.csv")
    $gpos = Import-CSVSafe (Join-Path $adPath "AD_GPOs.csv")
    $servers = Import-CSVSafe (Join-Path $serverPath "Server_Hardware.csv")
    $sqlInstances = Import-CSVSafe (Join-Path $sqlPath "SQL_Instances.csv")
    $sqlDatabases = Import-CSVSafe (Join-Path $sqlPath "SQL_Databases.csv")
    
    # Key metrics
    $html += @"
    <div class="section">
        <h2>📊 Key Metrics at a Glance</h2>
        <div class="metrics">
            <div class="metric-card">
                <h3>$($users.Count)</h3>
                <p>Total Users</p>
            </div>
            <div class="metric-card">
                <h3>$($computers.Count)</h3>
                <p>Total Computers</p>
            </div>
            <div class="metric-card">
                <h3>$($servers.Count)</h3>
                <p>Member Servers</p>
            </div>
            <div class="metric-card">
                <h3>$($sqlInstances.Count)</h3>
                <p>SQL Instances</p>
            </div>
            <div class="metric-card">
                <h3>$($sqlDatabases.Count)</h3>
                <p>SQL Databases</p>
            </div>
            <div class="metric-card">
                <h3>$($groups.Count)</h3>
                <p>AD Groups</p>
            </div>
            <div class="metric-card">
                <h3>$($gpos.Count)</h3>
                <p>Group Policies</p>
            </div>
        </div>
    </div>
"@
    
    # Identity summary
    $enabledUsers = ($users | Where-Object {$_.Enabled -eq 'True'}).Count
    $staleUsers = ($users | Where-Object {$_.IsStale -eq 'True'}).Count
    $stalePercent = if ($users.Count -gt 0) { [math]::Round(($staleUsers / $users.Count) * 100, 1) } else { 0 }
    
    $html += @"
    <div class="section">
        <h2>👥 Identity & Access Summary</h2>
        <p><strong>Total Users:</strong> $($users.Count) ($enabledUsers enabled)</p>
        <p><strong>Stale Accounts:</strong> $staleUsers ($stalePercent% of total) - <span class="badge badge-warning">Cleanup Recommended</span></p>
        <p><strong>Total Groups:</strong> $($groups.Count)</p>
        <p><strong>Total Computers:</strong> $($computers.Count)</p>
"@
    
    if ($staleUsers -gt ($users.Count * 0.1)) {
        $html += @"
        <div class="alert alert-warning">
            <strong>⚠️ High Stale Account Count:</strong> $stalePercent% of accounts are stale (inactive for 90+ days). Recommend account cleanup before migration.
        </div>
"@
    }
    
    $html += "</div>"
    
    # Server infrastructure summary
    if ($servers.Count -gt 0) {
        $totalCPU = ($servers | Measure-Object -Property CPUCores -Sum).Sum
        $totalMemoryGB = ($servers | Measure-Object -Property MemoryGB -Sum).Sum
        $vmServers = ($servers | Where-Object {$_.IsVirtual -eq 'True'}).Count
        $physicalServers = $servers.Count - $vmServers
        $vmPercent = if ($servers.Count -gt 0) { [math]::Round(($vmServers / $servers.Count) * 100, 1) } else { 0 }
        $physicalPercent = 100 - $vmPercent
        
        $html += @"
    <div class="section">
        <h2>🖥️ Server Infrastructure Summary</h2>
        <p><strong>Total Servers:</strong> $($servers.Count) ($vmServers virtual, $physicalServers physical)</p>
        <p><strong>Virtualization Rate:</strong> $vmPercent%</p>
        <p><strong>Total CPU Cores:</strong> $totalCPU cores</p>
        <p><strong>Total Memory:</strong> $([math]::Round($totalMemoryGB, 0)) GB</p>
        
        <h3>Server Distribution</h3>
        <div class="progress-bar">
            <div class="progress-fill" style="width: $vmPercent%">Virtual: $vmPercent%</div>
        </div>
        <div class="progress-bar">
            <div class="progress-fill" style="width: $physicalPercent%">Physical: $physicalPercent%</div>
        </div>
"@
        
        if ($vmPercent -lt 50) {
            $html += @"
        <div class="alert alert-info">
            <strong>💡 Cloud Migration Opportunity:</strong> Only $vmPercent% of servers are virtualized. Significant cloud migration opportunity exists.
        </div>
"@
        }
        
        $html += "</div>"
    }
    
    # SQL Database summary
    if ($sqlDatabases.Count -gt 0) {
        $totalSizeGB = ($sqlDatabases | Measure-Object -Property SizeGB -Sum).Sum
        $backupIssues = ($sqlDatabases | Where-Object {$_.BackupIssue -ne 'OK'}).Count
        $backupIssuePercent = if ($sqlDatabases.Count -gt 0) { [math]::Round(($backupIssues / $sqlDatabases.Count) * 100, 1) } else { 0 }
        
        $html += @"
    <div class="section">
        <h2>🗄️ SQL Database Summary</h2>
        <p><strong>SQL Instances:</strong> $($sqlInstances.Count)</p>
        <p><strong>Total Databases:</strong> $($sqlDatabases.Count)</p>
        <p><strong>Total Database Size:</strong> $([math]::Round($totalSizeGB, 2)) GB</p>
        <p><strong>Backup Issues:</strong> $backupIssues databases ($backupIssuePercent%) - <span class="badge badge-$(if($backupIssues -gt 0){'danger'}else{'success'})">$(if($backupIssues -gt 0){'Action Required'}else{'Healthy'})</span></p>
"@
        
        if ($backupIssues -gt 0) {
            $html += @"
        <div class="alert alert-danger">
            <strong>🚨 Backup Issues Detected:</strong> $backupIssues databases have backup issues (no recent backup or missing log backups). Immediate attention required.
        </div>
"@
        }
        
        $html += "</div>"
    }
    
    # Security findings
    $privilegedAccounts = Import-CSVSafe (Join-Path $adPath "AD_PrivilegedAccounts.csv")
    $serviceAccounts = Import-CSVSafe (Join-Path $adPath "AD_ServiceAccounts.csv")
    $trusts = Import-CSVSafe (Join-Path $adPath "AD_Trusts.csv")
    
    $html += @"
    <div class="section">
        <h2>🔒 Security Highlights</h2>
        <p><strong>Privileged Accounts:</strong> $($privilegedAccounts.Count) - <span class="badge badge-info">Review Required</span></p>
        <p><strong>Service Accounts:</strong> $($serviceAccounts.Count) detected</p>
        <p><strong>AD Trusts:</strong> $($trusts.Count)</p>
        <p><strong>Group Policies:</strong> $($gpos.Count)</p>
        
        <div class="alert alert-info">
            <strong>📋 Recommendation:</strong> Review all privileged accounts and service accounts before migration. Implement least privilege principles.
        </div>
    </div>
"@
    
    # Migration readiness assessment
    $readinessScore = 100
    if ($stalePercent -gt 20) { $readinessScore -= 15 }
    if ($backupIssues -gt 0) { $readinessScore -= 20 }
    if ($vmPercent -lt 50) { $readinessScore -= 10 }
    if ($privilegedAccounts.Count -gt 50) { $readinessScore -= 10 }
    
    $readinessLevel = if ($readinessScore -ge 80) { "High" } elseif ($readinessScore -ge 60) { "Medium" } else { "Low" }
    $badgeClass = if ($readinessScore -ge 80) { "success" } elseif ($readinessScore -ge 60) { "warning" } else { "danger" }
    
    $html += @"
    <div class="section">
        <h2>✅ Migration Readiness Assessment</h2>
        <div class="metric-card" style="max-width: 400px;">
            <h3>$readinessScore / 100</h3>
            <p>Readiness Score: <span class="badge badge-$badgeClass">$readinessLevel</span></p>
        </div>
        
        <h3>Key Findings</h3>
        <ul style="line-height: 2;">
            <li>$(if($stalePercent -lt 10){'✅'}else{'⚠️'}) Account hygiene: $stalePercent% stale accounts</li>
            <li>$(if($backupIssues -eq 0){'✅'}else{'🚨'}) SQL backup status: $backupIssues issues</li>
            <li>$(if($vmPercent -gt 70){'✅'}else{'💡'}) Virtualization rate: $vmPercent%</li>
            <li>$(if($privilegedAccounts.Count -lt 30){'✅'}else{'⚠️'}) Privileged accounts: $($privilegedAccounts.Count)</li>
        </ul>
    </div>
"@
    
    $html += "</div>" # Close container
    $html += Get-HTMLFooter
    
    # Save report
    $reportPath = Join-Path $OutputFolder "executive-summary.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    
    Write-ReportLog "Executive summary saved to: $reportPath" -Level Success
    return $reportPath
}

#endregion

#region Main Execution

try {
    Write-ReportLog "Starting HTML report generation..." -Level Info
    Write-ReportLog "Output folder: $OutputFolder" -Level Info
    
    # Generate executive summary
    $execReport = New-ExecutiveSummaryReport -OutputFolder $OutputFolder -CompanyName $CompanyName -ReportTitle $ReportTitle
    
    Write-ReportLog "Report generation complete!" -Level Success
    Write-ReportLog "Open report: $execReport" -Level Info
    
    # Open report in default browser
    Start-Process $execReport
}
catch {
    Write-ReportLog "Report generation failed: $_" -Level Error
    throw
}

#endregion

