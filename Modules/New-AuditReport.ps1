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

#region Active Directory Detailed Report

function New-ADDetailedReport {
    param(
        [string]$OutputFolder,
        [string]$CompanyName
    )
    
    Write-ReportLog "Generating Active Directory detailed report..." -Level Info
    
    $title = "$CompanyName - Active Directory Details"
    $html = Get-HTMLHeader -Title $title
    
    $adPath = Join-Path $OutputFolder "AD"
    
    # Load data
    $users = Import-CSVSafe (Join-Path $adPath "AD_Users.csv")
    $computers = Import-CSVSafe (Join-Path $adPath "AD_Computers.csv")
    $groups = Import-CSVSafe (Join-Path $adPath "AD_Groups.csv")
    $gpos = Import-CSVSafe (Join-Path $adPath "AD_GPOs.csv")
    $gposUnlinked = Import-CSVSafe (Join-Path $adPath "AD_GPOs_Unlinked.csv")
    $trusts = Import-CSVSafe (Join-Path $adPath "AD_Trusts.csv")
    $passwordPolicies = Import-CSVSafe (Join-Path $adPath "AD_PasswordPolicies.csv")
    $dnsZones = Import-CSVSafe (Join-Path $adPath "AD_DNS_Zones.csv")
    
    $html += @"
<div class="container">
    <div class="header">
        <h1>$CompanyName</h1>
        <p>Active Directory - Detailed Analysis</p>
    </div>
    
    <div class="nav">
        <a href="executive-summary.html">Executive Summary</a>
        <a href="active-directory.html">Active Directory</a>
        <a href="servers.html">Server Infrastructure</a>
        <a href="sql-databases.html">SQL Databases</a>
        <a href="security.html">Security Analysis</a>
    </div>
    
    <!-- User Statistics -->
    <div class="section">
        <h2>👥 User Accounts</h2>
        <p><strong>Total Users:</strong> $($users.Count)</p>
        <p><strong>Enabled:</strong> $(($users | Where-Object {$_.Enabled -eq 'True'}).Count)</p>
        <p><strong>Disabled:</strong> $(($users | Where-Object {$_.Enabled -eq 'False'}).Count)</p>
        <p><strong>Stale Accounts (90+ days):</strong> $(($users | Where-Object {$_.IsStale -eq 'True'}).Count)</p>
        
        <h3>Top 20 Stale User Accounts</h3>
        <table>
            <tr>
                <th>Username</th>
                <th>Display Name</th>
                <th>Last Logon</th>
                <th>Password Last Set</th>
                <th>Enabled</th>
            </tr>
"@
    
    $staleUsers = $users | Where-Object {$_.IsStale -eq 'True'} | Select-Object -First 20
    foreach ($user in $staleUsers) {
        $html += @"
            <tr>
                <td>$($user.SamAccountName)</td>
                <td>$($user.DisplayName)</td>
                <td>$($user.LastLogonDate)</td>
                <td>$($user.PasswordLastSet)</td>
                <td><span class="badge badge-$(if($user.Enabled -eq 'True'){'success'}else{'danger'})">$($user.Enabled)</span></td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
    
    <!-- Computer Statistics -->
    <div class="section">
        <h2>💻 Computer Accounts</h2>
        <p><strong>Total Computers:</strong> $($computers.Count)</p>
        <p><strong>Servers:</strong> $(($computers | Where-Object {$_.OperatingSystem -like '*Server*'}).Count)</p>
        <p><strong>Workstations:</strong> $(($computers | Where-Object {$_.OperatingSystem -notlike '*Server*'}).Count)</p>
        <p><strong>Stale Computers (90+ days):</strong> $(($computers | Where-Object {$_.IsStale -eq 'True'}).Count)</p>
        
        <h3>Operating System Distribution</h3>
        <table>
            <tr>
                <th>Operating System</th>
                <th>Count</th>
            </tr>
"@
    
    $osGroups = $computers | Group-Object OperatingSystem | Sort-Object Count -Descending
    foreach ($osGroup in $osGroups) {
        $html += @"
            <tr>
                <td>$($osGroup.Name)</td>
                <td>$($osGroup.Count)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
    
    <!-- Group Statistics -->
    <div class="section">
        <h2>👥 Groups</h2>
        <p><strong>Total Groups:</strong> $($groups.Count)</p>
        <p><strong>Security Groups:</strong> $(($groups | Where-Object {$_.GroupCategory -eq 'Security'}).Count)</p>
        <p><strong>Distribution Groups:</strong> $(($groups | Where-Object {$_.GroupCategory -eq 'Distribution'}).Count)</p>
        <p><strong>Empty Groups:</strong> $(($groups | Where-Object {$_.MemberCount -eq 0}).Count)</p>
        
        <h3>Largest Groups (Top 15)</h3>
        <table>
            <tr>
                <th>Group Name</th>
                <th>Scope</th>
                <th>Category</th>
                <th>Members</th>
            </tr>
"@
    
    $largestGroups = $groups | Sort-Object {[int]$_.MemberCount} -Descending | Select-Object -First 15
    foreach ($group in $largestGroups) {
        $html += @"
            <tr>
                <td>$($group.Name)</td>
                <td>$($group.GroupScope)</td>
                <td>$($group.GroupCategory)</td>
                <td>$($group.MemberCount)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
    
    <!-- GPO Summary -->
    <div class="section">
        <h2>📋 Group Policy Objects</h2>
        <p><strong>Total GPOs:</strong> $($gpos.Count)</p>
        <p><strong>Unlinked GPOs:</strong> $($gposUnlinked.Count) - <span class="badge badge-warning">Cleanup Candidates</span></p>
"@
    
    if ($gposUnlinked.Count -gt 0) {
        $html += @"
        
        <h3>Unlinked GPOs</h3>
        <table>
            <tr>
                <th>GPO Name</th>
                <th>Owner</th>
                <th>Created</th>
                <th>Modified</th>
            </tr>
"@
        foreach ($gpo in $gposUnlinked) {
            $html += @"
            <tr>
                <td>$($gpo.DisplayName)</td>
                <td>$($gpo.Owner)</td>
                <td>$($gpo.CreationTime)</td>
                <td>$($gpo.ModificationTime)</td>
            </tr>
"@
        }
        $html += "</table>"
    }
    
    $html += "</div>"
    
    # Trusts
    if ($trusts.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>🔗 AD Trusts</h2>
        <table>
            <tr>
                <th>Source Domain</th>
                <th>Target Domain</th>
                <th>Trust Type</th>
                <th>Direction</th>
            </tr>
"@
        foreach ($trust in $trusts) {
            $html += @"
            <tr>
                <td>$($trust.SourceName)</td>
                <td>$($trust.TargetName)</td>
                <td>$($trust.TrustType)</td>
                <td>$($trust.TrustDirection)</td>
            </tr>
"@
        }
        $html += "</table></div>"
    }
    
    # Password Policies
    if ($passwordPolicies.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>🔐 Password Policies</h2>
        <table>
            <tr>
                <th>Policy Name</th>
                <th>Min Length</th>
                <th>Max Age (Days)</th>
                <th>Complexity</th>
                <th>Lockout Threshold</th>
                <th>Applies To</th>
            </tr>
"@
        foreach ($policy in $passwordPolicies) {
            $html += @"
            <tr>
                <td>$($policy.Name)</td>
                <td>$($policy.MinPasswordLength)</td>
                <td>$($policy.MaxPasswordAge)</td>
                <td><span class="badge badge-$(if($policy.ComplexityEnabled -eq 'True'){'success'}else{'danger'})">$($policy.ComplexityEnabled)</span></td>
                <td>$($policy.LockoutThreshold)</td>
                <td>$($policy.AppliesTo)</td>
            </tr>
"@
        }
        $html += "</table></div>"
    }
    
    # DNS Zones
    if ($dnsZones.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>🌐 DNS Zones</h2>
        <table>
            <tr>
                <th>Zone Name</th>
                <th>Type</th>
                <th>Dynamic Update</th>
                <th>AD Integrated</th>
                <th>Reverse Lookup</th>
            </tr>
"@
        foreach ($zone in $dnsZones) {
            $html += @"
            <tr>
                <td>$($zone.ZoneName)</td>
                <td>$($zone.ZoneType)</td>
                <td>$($zone.DynamicUpdate)</td>
                <td><span class="badge badge-$(if($zone.IsDsIntegrated -eq 'True'){'success'}else{'warning'})">$($zone.IsDsIntegrated)</span></td>
                <td>$($zone.IsReverseLookupZone)</td>
            </tr>
"@
        }
        $html += "</table></div>"
    }
    
    $html += "</div>"
    $html += Get-HTMLFooter
    
    $reportPath = Join-Path $OutputFolder "active-directory.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-ReportLog "AD detailed report saved to: $reportPath" -Level Success
}

#endregion

#region Server Infrastructure Detailed Report

function New-ServerDetailedReport {
    param(
        [string]$OutputFolder,
        [string]$CompanyName
    )
    
    Write-ReportLog "Generating server infrastructure detailed report..." -Level Info
    
    $title = "$CompanyName - Server Infrastructure Details"
    $html = Get-HTMLHeader -Title $title
    
    $serverPath = Join-Path $OutputFolder "Servers"
    
    # Load data
    $servers = Import-CSVSafe (Join-Path $serverPath "Server_Hardware.csv")
    $storage = Import-CSVSafe (Join-Path $serverPath "Server_Storage_Details.csv")
    $appSummary = Import-CSVSafe (Join-Path $serverPath "Server_Application_Summary.csv")
    
    $html += @"
<div class="container">
    <div class="header">
        <h1>$CompanyName</h1>
        <p>Server Infrastructure - Detailed Analysis</p>
    </div>
    
    <div class="nav">
        <a href="executive-summary.html">Executive Summary</a>
        <a href="active-directory.html">Active Directory</a>
        <a href="servers.html">Server Infrastructure</a>
        <a href="sql-databases.html">SQL Databases</a>
        <a href="security.html">Security Analysis</a>
    </div>
    
    <!-- Server Hardware -->
    <div class="section">
        <h2>🖥️ Server Hardware Inventory</h2>
        <p><strong>Total Servers:</strong> $($servers.Count)</p>
        <table>
            <tr>
                <th>Server Name</th>
                <th>OS</th>
                <th>CPU Cores</th>
                <th>Memory (GB)</th>
                <th>Virtual</th>
                <th>Uptime (Days)</th>
            </tr>
"@
    
    foreach ($server in $servers) {
        $html += @"
            <tr>
                <td>$($server.ServerName)</td>
                <td>$($server.OperatingSystem)</td>
                <td>$($server.CPUCores)</td>
                <td>$($server.MemoryGB)</td>
                <td><span class="badge badge-$(if($server.IsVirtual -eq 'True'){'info'}else{'warning'})">$($server.IsVirtual)</span></td>
                <td>$($server.UptimeDays)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
    
    <!-- Storage Summary -->
    <div class="section">
        <h2>💾 Storage Overview</h2>
"@
    
    if ($storage.Count -gt 0) {
        $totalSizeGB = ($storage | Measure-Object -Property SizeGB -Sum).Sum
        $totalFreeGB = ($storage | Measure-Object -Property FreeSpaceGB -Sum).Sum
        $totalUsedGB = $totalSizeGB - $totalFreeGB
        
        $html += @"
        <p><strong>Total Capacity:</strong> $([math]::Round($totalSizeGB, 2)) GB</p>
        <p><strong>Used Space:</strong> $([math]::Round($totalUsedGB, 2)) GB</p>
        <p><strong>Free Space:</strong> $([math]::Round($totalFreeGB, 2)) GB</p>
        <p><strong>Average Utilization:</strong> $([math]::Round(($totalUsedGB / $totalSizeGB) * 100, 1))%</p>
        
        <h3>Top 10 Largest Volumes</h3>
        <table>
            <tr>
                <th>Server</th>
                <th>Drive</th>
                <th>Size (GB)</th>
                <th>Used (GB)</th>
                <th>Free (%)</th>
            </tr>
"@
        $topVolumes = $storage | Sort-Object {[double]$_.SizeGB} -Descending | Select-Object -First 10
        foreach ($vol in $topVolumes) {
            $usedGB = [double]$vol.SizeGB - [double]$vol.FreeSpaceGB
            $freePercent = [math]::Round([double]$vol.FreePercent, 1)
            $badgeClass = if ($freePercent -lt 10) { 'danger' } elseif ($freePercent -lt 20) { 'warning' } else { 'success' }
            
            $html += @"
            <tr>
                <td>$($vol.ServerName)</td>
                <td>$($vol.Drive)</td>
                <td>$([math]::Round([double]$vol.SizeGB, 2))</td>
                <td>$([math]::Round($usedGB, 2))</td>
                <td><span class="badge badge-$badgeClass">$freePercent%</span></td>
            </tr>
"@
        }
        $html += "</table>"
    }
    
    $html += @"
    </div>
    
    <!-- Application Summary -->
    <div class="section">
        <h2>📦 Installed Applications</h2>
"@
    
    if ($appSummary.Count -gt 0) {
        $html += @"
        <p><strong>Unique Applications:</strong> $($appSummary.Count)</p>
        
        <h3>Top 20 Most Common Applications</h3>
        <table>
            <tr>
                <th>Application</th>
                <th>Server Count</th>
                <th>Common Version</th>
            </tr>
"@
        $topApps = $appSummary | Sort-Object {[int]$_.ServerCount} -Descending | Select-Object -First 20
        foreach ($app in $topApps) {
            $html += @"
            <tr>
                <td>$($app.ApplicationName)</td>
                <td>$($app.ServerCount)</td>
                <td>$($app.MostCommonVersion)</td>
            </tr>
"@
        }
        $html += "</table>"
    }
    
    $html += @"
    </div>
</div>
"@
    
    $html += Get-HTMLFooter
    
    $reportPath = Join-Path $OutputFolder "servers.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-ReportLog "Server detailed report saved to: $reportPath" -Level Success
}

#endregion

#region SQL Database Detailed Report

function New-SQLDetailedReport {
    param(
        [string]$OutputFolder,
        [string]$CompanyName
    )
    
    Write-ReportLog "Generating SQL database detailed report..." -Level Info
    
    $title = "$CompanyName - SQL Database Details"
    $html = Get-HTMLHeader -Title $title
    
    $sqlPath = Join-Path $OutputFolder "SQL"
    
    # Load data
    $instances = Import-CSVSafe (Join-Path $sqlPath "SQL_Instance_Details.csv")
    $databases = Import-CSVSafe (Join-Path $sqlPath "SQL_Databases.csv")
    $backupIssues = Import-CSVSafe (Join-Path $sqlPath "SQL_Backup_Issues.csv")
    $logins = Import-CSVSafe (Join-Path $sqlPath "SQL_Logins.csv")
    $sysadmins = Import-CSVSafe (Join-Path $sqlPath "SQL_Logins_SysAdmin.csv")
    $jobs = Import-CSVSafe (Join-Path $sqlPath "SQL_Agent_Jobs.csv")
    $linkedServers = Import-CSVSafe (Join-Path $sqlPath "SQL_Linked_Servers.csv")
    
    $html += @"
<div class="container">
    <div class="header">
        <h1>$CompanyName</h1>
        <p>SQL Server - Detailed Analysis</p>
    </div>
    
    <div class="nav">
        <a href="executive-summary.html">Executive Summary</a>
        <a href="active-directory.html">Active Directory</a>
        <a href="servers.html">Server Infrastructure</a>
        <a href="sql-databases.html">SQL Databases</a>
        <a href="security.html">Security Analysis</a>
    </div>
    
    <!-- SQL Instances -->
    <div class="section">
        <h2>🗄️ SQL Server Instances</h2>
        <p><strong>Total Instances:</strong> $($instances.Count)</p>
        <table>
            <tr>
                <th>Instance</th>
                <th>Version</th>
                <th>Edition</th>
                <th>Service Pack</th>
                <th>Clustered</th>
                <th>AlwaysOn</th>
            </tr>
"@
    
    foreach ($instance in $instances) {
        $html += @"
            <tr>
                <td>$($instance.ConnectionString)</td>
                <td>$($instance.ProductVersion)</td>
                <td>$($instance.Edition)</td>
                <td>$($instance.ProductLevel)</td>
                <td><span class="badge badge-$(if($instance.IsClustered -eq 'True'){'success'}else{'info'})">$($instance.IsClustered)</span></td>
                <td><span class="badge badge-$(if($instance.IsHadrEnabled -eq 'True'){'success'}else{'info'})">$($instance.IsHadrEnabled)</span></td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
    
    <!-- Databases -->
    <div class="section">
        <h2>💾 Databases</h2>
        <p><strong>Total Databases:</strong> $($databases.Count)</p>
        <p><strong>Total Size:</strong> $([math]::Round(($databases | Measure-Object -Property SizeGB -Sum).Sum, 2)) GB</p>
        
        <h3>Top 20 Largest Databases</h3>
        <table>
            <tr>
                <th>Database Name</th>
                <th>Instance</th>
                <th>Size (GB)</th>
                <th>Recovery Model</th>
                <th>Last Backup</th>
                <th>Status</th>
            </tr>
"@
    
    $topDBs = $databases | Sort-Object {[double]$_.SizeGB} -Descending | Select-Object -First 20
    foreach ($db in $topDBs) {
        $daysSince = [int]$db.DaysSinceLastBackup
        $badgeClass = if ($daysSince -gt 7) { 'danger' } elseif ($daysSince -gt 3) { 'warning' } else { 'success' }
        
        $html += @"
            <tr>
                <td>$($db.DatabaseName)</td>
                <td>$($db.ConnectionString)</td>
                <td>$($db.SizeGB)</td>
                <td>$($db.RecoveryModel)</td>
                <td>$($db.LastFullBackup)</td>
                <td><span class="badge badge-$badgeClass">$daysSince days ago</span></td>
            </tr>
"@
    }
    
    $html += "</table></div>"
    
    # Backup Issues
    if ($backupIssues.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>🚨 Backup Issues</h2>
        <div class="alert alert-danger">
            <strong>$($backupIssues.Count) databases have backup issues!</strong>
        </div>
        <table>
            <tr>
                <th>Database</th>
                <th>Instance</th>
                <th>Issue</th>
                <th>Days Since Backup</th>
            </tr>
"@
        foreach ($issue in $backupIssues) {
            $html += @"
            <tr>
                <td>$($issue.DatabaseName)</td>
                <td>$($issue.ConnectionString)</td>
                <td>$($issue.BackupIssue)</td>
                <td>$($issue.DaysSinceLastBackup)</td>
            </tr>
"@
        }
        $html += "</table></div>"
    }
    
    # Sysadmin Logins
    if ($sysadmins.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>👑 Sysadmin Accounts</h2>
        <p><strong>Total Sysadmin Logins:</strong> $($sysadmins.Count)</p>
        <table>
            <tr>
                <th>Login Name</th>
                <th>Instance</th>
                <th>Type</th>
                <th>Disabled</th>
                <th>Created</th>
            </tr>
"@
        foreach ($login in $sysadmins) {
            $html += @"
            <tr>
                <td>$($login.LoginName)</td>
                <td>$($login.ConnectionString)</td>
                <td>$($login.LoginType)</td>
                <td><span class="badge badge-$(if($login.IsDisabled -eq 'True'){'success'}else{'warning'})">$($login.IsDisabled)</span></td>
                <td>$($login.CreateDate)</td>
            </tr>
"@
        }
        $html += "</table></div>"
    }
    
    # SQL Agent Jobs
    if ($jobs.Count -gt 0) {
        $failedJobs = $jobs | Where-Object {$_.LastRunStatus -eq 'Failed'}
        $html += @"
    <div class="section">
        <h2>⚙️ SQL Agent Jobs</h2>
        <p><strong>Total Jobs:</strong> $($jobs.Count)</p>
        <p><strong>Failed Jobs:</strong> $($failedJobs.Count)</p>
"@
        if ($failedJobs.Count -gt 0) {
            $html += @"
        
        <h3>Recently Failed Jobs</h3>
        <table>
            <tr>
                <th>Job Name</th>
                <th>Instance</th>
                <th>Owner</th>
                <th>Last Run</th>
                <th>Status</th>
            </tr>
"@
            foreach ($job in $failedJobs) {
                $html += @"
            <tr>
                <td>$($job.JobName)</td>
                <td>$($job.ConnectionString)</td>
                <td>$($job.Owner)</td>
                <td>$($job.LastRunDate)</td>
                <td><span class="badge badge-danger">$($job.LastRunStatus)</span></td>
            </tr>
"@
            }
            $html += "</table>"
        }
        $html += "</div>"
    }
    
    # Linked Servers
    if ($linkedServers.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>🔗 Linked Servers</h2>
        <p><strong>Total Linked Servers:</strong> $($linkedServers.Count)</p>
        <table>
            <tr>
                <th>Linked Server</th>
                <th>Source Instance</th>
                <th>Product</th>
                <th>Data Source</th>
            </tr>
"@
        foreach ($linked in $linkedServers) {
            $html += @"
            <tr>
                <td>$($linked.LinkedServerName)</td>
                <td>$($linked.ConnectionString)</td>
                <td>$($linked.Product)</td>
                <td>$($linked.DataSource)</td>
            </tr>
"@
        }
        $html += "</table></div>"
    }
    
    $html += "</div>"
    $html += Get-HTMLFooter
    
    $reportPath = Join-Path $OutputFolder "sql-databases.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-ReportLog "SQL detailed report saved to: $reportPath" -Level Success
}

#endregion

#region Security Analysis Detailed Report

function New-SecurityDetailedReport {
    param(
        [string]$OutputFolder,
        [string]$CompanyName
    )
    
    Write-ReportLog "Generating security analysis detailed report..." -Level Info
    
    $title = "$CompanyName - Security Analysis"
    $html = Get-HTMLHeader -Title $title
    
    $adPath = Join-Path $OutputFolder "AD"
    
    # Load data
    $privilegedAccounts = Import-CSVSafe (Join-Path $adPath "AD_PrivilegedAccounts.csv")
    $serviceAccounts = Import-CSVSafe (Join-Path $adPath "AD_ServiceAccounts.csv")
    
    $html += @"
<div class="container">
    <div class="header">
        <h1>$CompanyName</h1>
        <p>Security Analysis - Detailed Report</p>
    </div>
    
    <div class="nav">
        <a href="executive-summary.html">Executive Summary</a>
        <a href="active-directory.html">Active Directory</a>
        <a href="servers.html">Server Infrastructure</a>
        <a href="sql-databases.html">SQL Databases</a>
        <a href="security.html">Security Analysis</a>
    </div>
    
    <!-- Privileged Accounts -->
    <div class="section">
        <h2>👑 Privileged Accounts</h2>
        <p><strong>Total Privileged Accounts:</strong> $($privilegedAccounts.Count)</p>
        <table>
            <tr>
                <th>Username</th>
                <th>Display Name</th>
                <th>Group Membership</th>
                <th>Enabled</th>
            </tr>
"@
    
    foreach ($account in $privilegedAccounts) {
        $html += @"
            <tr>
                <td>$($account.MemberSamAccountName)</td>
                <td>$($account.MemberDisplayName)</td>
                <td><span class="badge badge-danger">$($account.GroupName)</span></td>
                <td><span class="badge badge-$(if($account.Enabled -eq 'True'){'warning'}else{'success'})">$($account.Enabled)</span></td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <div class="alert alert-warning">
            <strong>⚠️ Security Recommendation:</strong> Review all privileged accounts. Implement least privilege principles and use separate admin accounts for administrative tasks.
        </div>
    </div>
    
    <!-- Service Accounts -->
    <div class="section">
        <h2>🔧 Service Accounts</h2>
        <p><strong>Detected Service Accounts:</strong> $($serviceAccounts.Count)</p>
        <table>
            <tr>
                <th>Account Name</th>
                <th>Display Name</th>
                <th>SPNs</th>
                <th>Password Age (Days)</th>
                <th>Detection Method</th>
            </tr>
"@
    
    foreach ($account in $serviceAccounts) {
        $passwordAge = if ($account.PasswordLastSet) { 
            [math]::Round(((Get-Date) - [datetime]$account.PasswordLastSet).TotalDays, 0)
        } else { 
            "N/A" 
        }
        
        $html += @"
            <tr>
                <td>$($account.SamAccountName)</td>
                <td>$($account.DisplayName)</td>
                <td>$($account.SPNCount)</td>
                <td>$passwordAge</td>
                <td><span class="badge badge-info">$($account.DetectionReason)</span></td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <div class="alert alert-info">
            <strong>💡 Service Account Best Practices:</strong>
            <ul>
                <li>Use Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA) where possible</li>
                <li>Implement strong password policies for service accounts</li>
                <li>Regular password rotation (90-180 days)</li>
                <li>Audit service account permissions regularly</li>
            </ul>
        </div>
    </div>
</div>
"@
    
    $html += Get-HTMLFooter
    
    $reportPath = Join-Path $OutputFolder "security.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-ReportLog "Security detailed report saved to: $reportPath" -Level Success
}

#endregion

#region Main Execution

try {
    Write-ReportLog "Starting HTML report generation..." -Level Info
    Write-ReportLog "Output folder: $OutputFolder" -Level Info
    
    # Generate executive summary
    $execReport = New-ExecutiveSummaryReport -OutputFolder $OutputFolder -CompanyName $CompanyName -ReportTitle $ReportTitle
    
    # Generate detailed reports
    Write-ReportLog "Generating detailed reports..." -Level Info
    
    New-ADDetailedReport -OutputFolder $OutputFolder -CompanyName $CompanyName
    New-ServerDetailedReport -OutputFolder $OutputFolder -CompanyName $CompanyName
    New-SQLDetailedReport -OutputFolder $OutputFolder -CompanyName $CompanyName
    New-SecurityDetailedReport -OutputFolder $OutputFolder -CompanyName $CompanyName
    
    Write-ReportLog "Report generation complete! Generated 5 HTML reports." -Level Success
    Write-ReportLog "Executive summary: $execReport" -Level Info
    
    # Open executive summary in default browser
    Start-Process $execReport
}
catch {
    Write-ReportLog "Report generation failed: $_" -Level Error
    throw
}

#endregion

