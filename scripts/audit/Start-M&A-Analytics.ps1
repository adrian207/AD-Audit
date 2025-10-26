<#
.SYNOPSIS
    M&A Audit Advanced Analytics & Reporting Tool
    
.DESCRIPTION
    Orchestrates the complete analytics workflow:
    - Baseline vs Current comparison
    - Trend analysis across multiple audits
    - Anomaly detection
    - Risk scoring
    - Executive dashboard generation
    - Alert system with thresholds
    
.PARAMETER BaselineAuditPath
    Path to baseline (older) audit database
    
.PARAMETER CurrentAuditPath
    Path to current (newer) audit database
    
.PARAMETER OutputFolder
    Folder to save all analytics outputs
    
.PARAMETER CompanyName
    Company name for reports
    
.PARAMETER GenerateDashboard
    Generate executive HTML dashboard
    
.PARAMETER EnableAlerts
    Enable email alerting system
    
.PARAMETER AlertEmail
    Email address for alerts
    
.PARAMETER SMTPServer
    SMTP server for email alerts
    
.PARAMETER FromEmail
    From email address for alerts
    
.PARAMETER AlertThresholds
    Custom alert thresholds (hashtable)
    
.EXAMPLE
    .\Start-M&A-Analytics.ps1 -BaselineAuditPath "C:\Audits\2024-01\AuditData.db" `
                               -CurrentAuditPath "C:\Audits\2024-10\AuditData.db" `
                               -OutputFolder "C:\Analytics\Report" `
                               -CompanyName "Contoso" `
                               -GenerateDashboard
    
.EXAMPLE
    # With alerts enabled
    .\Start-M&A-Analytics.ps1 -BaselineAuditPath "baseline.db" `
                               -CurrentAuditPath "current.db" `
                               -OutputFolder "C:\Analytics" `
                               -CompanyName "Fabrikam" `
                               -GenerateDashboard `
                               -EnableAlerts `
                               -AlertEmail "admin@fabrikam.com" `
                               -SMTPServer "smtp.office365.com" `
                               -FromEmail "audit@fabrikam.com"
    
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 2.3.0
    Requires: System.Data.SQLite, Modules/Invoke-Analytics-Engine.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaselineAuditPath,
    
    [Parameter(Mandatory = $true)]
    [string]$CurrentAuditPath,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,
    
    [Parameter(Mandatory = $true)]
    [string]$CompanyName,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateDashboard,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableAlerts,
    
    [Parameter(Mandatory = $false)]
    [string]$AlertEmail,
    
    [Parameter(Mandatory = $false)]
    [string]$SMTPServer,
    
    [Parameter(Mandatory = $false)]
    [string]$FromEmail,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$AlertThresholds = @{
        RiskScoreBelow = 60
        CriticalAnomalies = 1
        HighAnomalies = 3
        PrivilegedAccountGrowth = 10
    }
)

#region Initialize

$ErrorActionPreference = 'Stop'
$startTime = Get-Date

Write-Host "
╔══════════════════════════════════════════════════════════════╗
║   M&A AUDIT ADVANCED ANALYTICS & REPORTING v2.3.0           ║
║   Company: $($CompanyName.PadRight(48))║
╚══════════════════════════════════════════════════════════════╝
" -ForegroundColor Cyan

# Validate inputs
if (-not (Test-Path $BaselineAuditPath)) {
    throw "Baseline audit database not found: $BaselineAuditPath"
}

if (-not (Test-Path $CurrentAuditPath)) {
    throw "Current audit database not found: $CurrentAuditPath"
}

# Create output folder
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    Write-Host "✓ Created output folder: $OutputFolder" -ForegroundColor Green
}

# Load required modules
$modulePath = Join-Path $PSScriptRoot "Modules"
Import-Module (Join-Path $modulePath "Invoke-Analytics-Engine.ps1") -Force
Import-Module (Join-Path $modulePath "New-ExecutiveDashboard.ps1") -Force
Import-Module (Join-Path $modulePath "Send-AnalyticsAlert.ps1") -Force

Write-Host "✓ Modules loaded successfully" -ForegroundColor Green

#endregion

#region Step 1: Baseline Comparison

Write-Host "`n[Step 1/5] Comparing Baseline vs Current Audit Data..." -ForegroundColor Cyan
Write-Host "  Baseline: $BaselineAuditPath"
Write-Host "  Current:  $CurrentAuditPath"

$comparison = Compare-AuditData -BaselinePath $BaselineAuditPath -CurrentPath $CurrentAuditPath

Write-Host "✓ Comparison complete" -ForegroundColor Green
Write-Host "  Users: $($comparison.Users.Baseline) → $($comparison.Users.Current) ($($comparison.Users.Change) / $($comparison.Users.PercentChange)%)" -ForegroundColor White
Write-Host "  Computers: $($comparison.Computers.Baseline) → $($comparison.Computers.Current) ($($comparison.Computers.Change) / $($comparison.Computers.PercentChange)%)" -ForegroundColor White
Write-Host "  Servers: $($comparison.Servers.Baseline) → $($comparison.Servers.Current) ($($comparison.Servers.Change) / $($comparison.Servers.PercentChange)%)" -ForegroundColor White
Write-Host "  Privileged Accounts: $($comparison.PrivilegedAccounts.Baseline) → $($comparison.PrivilegedAccounts.Current) ($($comparison.PrivilegedAccounts.Change) / $($comparison.PrivilegedAccounts.PercentChange)%)" -ForegroundColor White

# Export comparison
$comparisonReport = Join-Path $OutputFolder "comparison_report.json"
$comparison | ConvertTo-Json -Depth 10 | Out-File $comparisonReport -Encoding UTF8
Write-Host "  Report saved: $comparisonReport" -ForegroundColor Gray

#endregion

#region Step 2: Anomaly Detection

Write-Host "`n[Step 2/5] Detecting Anomalies..." -ForegroundColor Cyan

$anomalies = Find-Anomalies -BaselinePath $BaselineAuditPath -CurrentPath $CurrentAuditPath

$criticalCount = ($anomalies | Where-Object Severity -eq 'Critical').Count
$highCount = ($anomalies | Where-Object Severity -eq 'High').Count
$mediumCount = ($anomalies | Where-Object Severity -eq 'Medium').Count

Write-Host "✓ Anomaly detection complete" -ForegroundColor Green
Write-Host "  Total Anomalies: $($anomalies.Count)" -ForegroundColor White
Write-Host "  Critical: $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  High: $highCount" -ForegroundColor $(if ($highCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Medium: $mediumCount" -ForegroundColor $(if ($mediumCount -gt 0) { 'Yellow' } else { 'Green' })

if ($anomalies.Count -gt 0) {
    # Export anomalies
    $anomaliesReport = Join-Path $OutputFolder "anomalies_report.csv"
    $anomalies | Export-Csv -Path $anomaliesReport -NoTypeInformation -Encoding UTF8
    Write-Host "  Report saved: $anomaliesReport" -ForegroundColor Gray
    
    # Display top 3 anomalies
    Write-Host "`n  Top Anomalies:" -ForegroundColor Yellow
    $anomalies | Select-Object -First 3 | ForEach-Object {
        Write-Host "    [$($_.Severity)] $($_.Title)" -ForegroundColor $(if ($_.Severity -eq 'Critical') { 'Red' } else { 'Yellow' })
    }
}

#endregion

#region Step 3: Risk Scoring

Write-Host "`n[Step 3/5] Calculating Risk Score..." -ForegroundColor Cyan

$riskScore = Get-RiskScore -DatabasePath $CurrentAuditPath

$riskColor = switch ($riskScore.Level) {
    "Low" { "Green" }
    "Medium" { "Yellow" }
    "High" { "Red" }
    "Critical" { "Red" }
}

Write-Host "✓ Risk score calculated" -ForegroundColor Green
Write-Host "  Score: $($riskScore.Score)/100" -ForegroundColor White
Write-Host "  Risk Level: $($riskScore.Level)" -ForegroundColor $riskColor

# Display risk factors
if ($riskScore.Factors) {
    Write-Host "`n  Active Risk Factors:" -ForegroundColor Yellow
    $riskScore.Factors.GetEnumerator() | Where-Object { $_.Value -gt 0 } | ForEach-Object {
        Write-Host "    • $($_.Key): $($_.Value)" -ForegroundColor White
    }
}

# Export risk score
$riskReport = Join-Path $OutputFolder "risk_score_report.json"
$riskScore | ConvertTo-Json -Depth 10 | Out-File $riskReport -Encoding UTF8
Write-Host "  Report saved: $riskReport" -ForegroundColor Gray

#endregion

#region Step 4: Executive Dashboard

if ($GenerateDashboard) {
    Write-Host "`n[Step 4/5] Generating Executive Dashboard..." -ForegroundColor Cyan
    
    $dashboardPath = Join-Path $OutputFolder "$CompanyName`_Executive_Dashboard_$(Get-Date -Format 'yyyy-MM-dd').html"
    
    New-ExecutiveDashboard -CompanyName $CompanyName `
                          -Comparison $comparison `
                          -Anomalies $anomalies `
                          -RiskScore $riskScore `
                          -OutputPath $dashboardPath | Out-Null
    
    Write-Host "✓ Dashboard generated" -ForegroundColor Green
    Write-Host "  Location: $dashboardPath" -ForegroundColor White
    Write-Host "  Opening in browser..." -ForegroundColor Gray
    
    # Open in default browser
    Start-Process $dashboardPath
}
else {
    Write-Host "`n[Step 4/5] Dashboard generation skipped (use -GenerateDashboard to enable)" -ForegroundColor Gray
}

#endregion

#region Step 5: Alert System

if ($EnableAlerts) {
    Write-Host "`n[Step 5/5] Checking Alert Thresholds..." -ForegroundColor Cyan
    
    if (-not $AlertEmail -or -not $SMTPServer -or -not $FromEmail) {
        Write-Host "⚠️  Alert email configuration incomplete. Skipping email alerts." -ForegroundColor Yellow
    }
    else {
        # Run alert system
        $alertScript = Join-Path $modulePath "Send-AnalyticsAlert.ps1"
        $alerts = & $alertScript -Anomalies $anomalies `
                                 -RiskScore $riskScore `
                                 -Comparison $comparison `
                                 -AlertEmail $AlertEmail `
                                 -SMTPServer $SMTPServer `
                                 -From $FromEmail `
                                 -Thresholds $AlertThresholds
        
        if ($alerts) {
            Write-Host "✓ Alert system triggered - email sent" -ForegroundColor Yellow
        }
        else {
            Write-Host "✓ No alerts triggered - all within thresholds" -ForegroundColor Green
        }
    }
}
else {
    Write-Host "`n[Step 5/5] Alert system disabled (use -EnableAlerts to enable)" -ForegroundColor Gray
}

#endregion

#region Summary

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "
╔══════════════════════════════════════════════════════════════╗
║                    ANALYTICS COMPLETE                        ║
╚══════════════════════════════════════════════════════════════╝
" -ForegroundColor Green

Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Company: $CompanyName" -ForegroundColor White
Write-Host "  Risk Score: $($riskScore.Score)/100 ($($riskScore.Level))" -ForegroundColor $riskColor
Write-Host "  Anomalies: $($anomalies.Count) ($criticalCount critical, $highCount high)" -ForegroundColor White
Write-Host "  User Change: $($comparison.Users.Change) ($($comparison.Users.PercentChange)%)" -ForegroundColor White
Write-Host "  Privileged Account Change: $($comparison.PrivilegedAccounts.Change) ($($comparison.PrivilegedAccounts.PercentChange)%)" -ForegroundColor White
Write-Host "  Duration: $([math]::Round($duration.TotalSeconds, 2)) seconds" -ForegroundColor White
Write-Host "  Output: $OutputFolder" -ForegroundColor White

Write-Host "`nGenerated Reports:" -ForegroundColor Cyan
Get-ChildItem $OutputFolder | ForEach-Object {
    Write-Host "  • $($_.Name)" -ForegroundColor Gray
}

Write-Host "`n✓ Analytics workflow complete!" -ForegroundColor Green

#endregion

# Return summary object
return [PSCustomObject]@{
    Company = $CompanyName
    Comparison = $comparison
    Anomalies = $anomalies
    RiskScore = $riskScore
    OutputFolder = $OutputFolder
    Duration = $duration
}

