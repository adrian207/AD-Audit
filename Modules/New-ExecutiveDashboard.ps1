<#
.SYNOPSIS
    Generates executive-level dashboard reports from audit analytics
    
.DESCRIPTION
    Creates professional HTML dashboards with charts, metrics, and insights
    for C-level executives and stakeholders.
    
.PARAMETER CompanyName
    Company name for the dashboard
    
.PARAMETER Comparison
    Comparison data from Compare-AuditData
    
.PARAMETER Anomalies
    Anomaly detection results
    
.PARAMETER RiskScore
    Risk scoring results
    
.PARAMETER OutputPath
    Path to save the HTML dashboard
    
.EXAMPLE
    $comparison = Compare-AuditData -BaselinePath "baseline.db" -CurrentPath "current.db"
    $anomalies = Find-Anomalies -BaselinePath "baseline.db" -CurrentPath "current.db"
    $riskScore = Get-RiskScore -DatabasePath "current.db"
    
    New-ExecutiveDashboard -CompanyName "Contoso" `
                          -Comparison $comparison `
                          -Anomalies $anomalies `
                          -RiskScore $riskScore `
                          -OutputPath "C:\Analytics\Dashboard.html"
    
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CompanyName,
    
    [Parameter(Mandatory = $true)]
    [hashtable]$Comparison,
    
    [Parameter(Mandatory = $true)]
    [array]$Anomalies,
    
    [Parameter(Mandatory = $true)]
    [PSCustomObject]$RiskScore,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$dashboardHTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$CompanyName - M&A Audit Executive Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .header .date {
            margin-top: 10px;
            font-size: 0.9rem;
            opacity: 0.8;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section-title {
            font-size: 1.8rem;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            font-weight: 600;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }
        
        .metric-card .label {
            font-size: 0.9rem;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .metric-card .value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        
        .metric-card .change {
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .change.positive { color: #28a745; }
        .change.negative { color: #dc3545; }
        .change.neutral { color: #6c757d; }
        
        .change-icon {
            font-size: 1.2rem;
            font-weight: bold;
        }
        
        .risk-score-container {
            background: #f8f9fa;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .risk-score {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .risk-gauge {
            flex: 1;
            min-width: 250px;
        }
        
        .gauge-circle {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin: 0 auto;
            border: 10px solid;
            position: relative;
            animation: fadeInScale 0.6s ease;
        }
        
        @keyframes fadeInScale {
            from {
                opacity: 0;
                transform: scale(0.8);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }
        
        .gauge-circle.low { border-color: #28a745; background: rgba(40, 167, 69, 0.1); }
        .gauge-circle.medium { border-color: #ffc107; background: rgba(255, 193, 7, 0.1); }
        .gauge-circle.high { border-color: #ff6b6b; background: rgba(255, 107, 107, 0.1); }
        .gauge-circle.critical { border-color: #dc3545; background: rgba(220, 53, 69, 0.1); }
        
        .gauge-score {
            font-size: 3.5rem;
            font-weight: bold;
            color: #333;
        }
        
        .gauge-label {
            font-size: 1.2rem;
            color: #666;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        .risk-factors {
            flex: 2;
            min-width: 300px;
        }
        
        .risk-factor {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            margin-bottom: 10px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .risk-factor-name {
            font-weight: 500;
            color: #333;
        }
        
        .risk-factor-count {
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
        }
        
        .anomalies {
            display: grid;
            gap: 15px;
        }
        
        .anomaly-card {
            background: white;
            border-left: 5px solid;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s ease;
        }
        
        .anomaly-card:hover {
            transform: translateX(5px);
        }
        
        .anomaly-card.critical { border-left-color: #dc3545; }
        .anomaly-card.high { border-left-color: #ff6b6b; }
        .anomaly-card.medium { border-left-color: #ffc107; }
        .anomaly-card.low { border-left-color: #28a745; }
        
        .anomaly-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .anomaly-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: #333;
        }
        
        .anomaly-severity {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }
        
        .severity-critical { background: #dc3545; }
        .severity-high { background: #ff6b6b; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; }
        
        .anomaly-description {
            color: #666;
            margin-bottom: 10px;
            line-height: 1.6;
        }
        
        .anomaly-recommendation {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 5px;
            font-size: 0.95rem;
            color: #333;
            border-left: 3px solid #667eea;
        }
        
        .anomaly-recommendation::before {
            content: "💡 Recommendation: ";
            font-weight: bold;
            color: #667eea;
        }
        
        .summary-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-top: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .summary-box h3 {
            font-size: 1.5rem;
            margin-bottom: 15px;
        }
        
        .summary-box ul {
            list-style: none;
            padding-left: 0;
        }
        
        .summary-box li {
            padding: 10px 0;
            padding-left: 30px;
            position: relative;
            line-height: 1.6;
        }
        
        .summary-box li::before {
            content: "✓";
            position: absolute;
            left: 0;
            font-weight: bold;
            font-size: 1.2rem;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px 40px;
            text-align: center;
            color: #666;
            font-size: 0.9rem;
            border-top: 1px solid #e9ecef;
        }
        
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
            .anomaly-card, .metric-card { page-break-inside: avoid; }
        }
        
        @media (max-width: 768px) {
            .header h1 { font-size: 1.8rem; }
            .content { padding: 20px; }
            .section-title { font-size: 1.4rem; }
            .metric-card .value { font-size: 2rem; }
            .gauge-circle { width: 150px; height: 150px; }
            .gauge-score { font-size: 2.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$CompanyName</h1>
            <div class="subtitle">M&A Audit Executive Dashboard</div>
            <div class="date">Generated: $(Get-Date -Format "MMMM dd, yyyy HH:mm")</div>
        </div>
        
        <div class="content">
            <!-- Risk Score Section -->
            <section class="section">
                <h2 class="section-title">Overall Security Posture</h2>
                <div class="risk-score-container">
                    <div class="risk-score">
                        <div class="risk-gauge">
                            <div class="gauge-circle $($RiskScore.Level.ToLower())">
                                <div class="gauge-score">$($RiskScore.Score)</div>
                                <div class="gauge-label">$($RiskScore.Level) Risk</div>
                            </div>
                        </div>
                        <div class="risk-factors">
                            <h3 style="margin-bottom: 15px; color: #333;">Risk Factors Detected</h3>
$(
    $factorsList = @()
    if ($RiskScore.Factors.StalePrivilegedAccounts -gt 0) {
        $factorsList += "                            <div class='risk-factor'><span class='risk-factor-name'>Stale Privileged Accounts</span><span class='risk-factor-count'>$($RiskScore.Factors.StalePrivilegedAccounts)</span></div>"
    }
    if ($RiskScore.Factors.ServiceAccountRisks -gt 0) {
        $factorsList += "                            <div class='risk-factor'><span class='risk-factor-name'>Service Account Risks</span><span class='risk-factor-count'>$($RiskScore.Factors.ServiceAccountRisks)</span></div>"
    }
    if ($RiskScore.Factors.KerberosDelegation -gt 0) {
        $factorsList += "                            <div class='risk-factor'><span class='risk-factor-name'>Kerberos Delegation Issues</span><span class='risk-factor-count'>$($RiskScore.Factors.KerberosDelegation)</span></div>"
    }
    if ($RiskScore.Factors.DangerousACLs -gt 0) {
        $factorsList += "                            <div class='risk-factor'><span class='risk-factor-name'>Dangerous ACL Permissions</span><span class='risk-factor-count'>$($RiskScore.Factors.DangerousACLs)</span></div>"
    }
    if ($RiskScore.Factors.WeakPasswordPolicy -gt 0) {
        $factorsList += "                            <div class='risk-factor'><span class='risk-factor-name'>Weak Password Policy</span><span class='risk-factor-count'>Yes</span></div>"
    }
    if ($RiskScore.Factors.BackupRisks -gt 0) {
        $factorsList += "                            <div class='risk-factor'><span class='risk-factor-name'>Database Backup Issues</span><span class='risk-factor-count'>$($RiskScore.Factors.BackupRisks)</span></div>"
    }
    if ($RiskScore.Factors.UntrustedTrusts -gt 0) {
        $factorsList += "                            <div class='risk-factor'><span class='risk-factor-name'>Untrusted AD Trusts</span><span class='risk-factor-count'>$($RiskScore.Factors.UntrustedTrusts)</span></div>"
    }
    if ($factorsList.Count -eq 0) {
        "                            <div class='risk-factor'><span class='risk-factor-name'>No significant risk factors detected</span><span class='risk-factor-count' style='background:#28a745;'>✓</span></div>"
    } else {
        $factorsList -join "`n"
    }
)
                        </div>
                    </div>
                </div>
            </section>
            
            <!-- Key Metrics Section -->
            <section class="section">
                <h2 class="section-title">Key Metrics Comparison</h2>
                <div class="metrics-grid">
$(
    function Get-ChangeHTML($baseline, $current, $change, $percentChange) {
        $changeClass = if ($change -gt 0) { "positive" } elseif ($change -lt 0) { "negative" } else { "neutral" }
        $icon = if ($change -gt 0) { "↑" } elseif ($change -lt 0) { "↓" } else { "→" }
        return "<div class='change $changeClass'><span class='change-icon'>$icon</span><span>$change ($percentChange%)</span></div>"
    }
    
    $metricsHTML = @"
                    <div class="metric-card">
                        <div class="label">Users</div>
                        <div class="value">$($Comparison.Users.Current)</div>
                        $(Get-ChangeHTML $Comparison.Users.Baseline $Comparison.Users.Current $Comparison.Users.Change $Comparison.Users.PercentChange)
                    </div>
                    <div class="metric-card">
                        <div class="label">Computers</div>
                        <div class="value">$($Comparison.Computers.Current)</div>
                        $(Get-ChangeHTML $Comparison.Computers.Baseline $Comparison.Computers.Current $Comparison.Computers.Change $Comparison.Computers.PercentChange)
                    </div>
                    <div class="metric-card">
                        <div class="label">Servers</div>
                        <div class="value">$($Comparison.Servers.Current)</div>
                        $(Get-ChangeHTML $Comparison.Servers.Baseline $Comparison.Servers.Current $Comparison.Servers.Change $Comparison.Servers.PercentChange)
                    </div>
                    <div class="metric-card">
                        <div class="label">Groups</div>
                        <div class="value">$($Comparison.Groups.Current)</div>
                        $(Get-ChangeHTML $Comparison.Groups.Baseline $Comparison.Groups.Current $Comparison.Groups.Change $Comparison.Groups.PercentChange)
                    </div>
                    <div class="metric-card">
                        <div class="label">Privileged Accounts</div>
                        <div class="value">$($Comparison.PrivilegedAccounts.Current)</div>
                        $(Get-ChangeHTML $Comparison.PrivilegedAccounts.Baseline $Comparison.PrivilegedAccounts.Current $Comparison.PrivilegedAccounts.Change $Comparison.PrivilegedAccounts.PercentChange)
                    </div>
"@
    if ($Comparison.ServiceAccounts -and $Comparison.ServiceAccounts.Current) {
        $metricsHTML += @"

                    <div class="metric-card">
                        <div class="label">Service Accounts</div>
                        <div class="value">$($Comparison.ServiceAccounts.Current)</div>
                        $(Get-ChangeHTML $Comparison.ServiceAccounts.Baseline $Comparison.ServiceAccounts.Current $Comparison.ServiceAccounts.Change $Comparison.ServiceAccounts.PercentChange)
                    </div>
"@
    }
    $metricsHTML
)
                </div>
            </section>
            
            <!-- Anomalies Section -->
            <section class="section">
                <h2 class="section-title">Critical Findings ($($Anomalies.Count) Anomalies Detected)</h2>
                <div class="anomalies">
$(
    if ($Anomalies.Count -eq 0) {
        "                    <div class='anomaly-card low'><div class='anomaly-title'>No anomalies detected - Environment appears healthy</div></div>"
    } else {
        $Anomalies | ForEach-Object {
            $severityClass = $_.Severity.ToLower()
            @"
                    <div class="anomaly-card $severityClass">
                        <div class="anomaly-header">
                            <div class="anomaly-title">$($_.Title)</div>
                            <span class="anomaly-severity severity-$severityClass">$($_.Severity)</span>
                        </div>
                        <div class="anomaly-description">$($_.Description)</div>
                        <div class="anomaly-recommendation">$($_.Recommendation)</div>
                    </div>
"@
        } | Out-String
    }
)
                </div>
            </section>
            
            <!-- Executive Summary -->
            <div class="summary-box">
                <h3>Executive Summary</h3>
                <ul>
                    <li>Overall Security Risk Level: <strong>$($RiskScore.Level)</strong> (Score: $($RiskScore.Score)/100)</li>
                    <li>Total Anomalies Detected: <strong>$($Anomalies.Count)</strong> findings requiring attention</li>
                    <li>Critical Issues: <strong>$(($Anomalies | Where-Object Severity -eq 'Critical').Count)</strong></li>
                    <li>High Priority Items: <strong>$(($Anomalies | Where-Object Severity -eq 'High').Count)</strong></li>
                    <li>Privileged Accounts Changed by: <strong>$($Comparison.PrivilegedAccounts.Change) ($($Comparison.PrivilegedAccounts.PercentChange)%)</strong></li>
                    <li>User Base Changed by: <strong>$($Comparison.Users.Change) ($($Comparison.Users.PercentChange)%)</strong></li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            Generated by M&A Audit Tool v2.3.0 | © $(Get-Date -Format yyyy) | Confidential
        </div>
    </div>
</body>
</html>
"@

# Save dashboard
$dashboardHTML | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "✅ Executive dashboard generated: $OutputPath" -ForegroundColor Green

# Return path for confirmation
return $OutputPath

