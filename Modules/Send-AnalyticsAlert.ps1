<#
.SYNOPSIS
    Sends alerts based on analytics thresholds
    
.DESCRIPTION
    Monitors audit analytics and sends email alerts when thresholds are breached.
    Supports custom thresholds and multiple notification methods.
    
.PARAMETER Anomalies
    Array of anomalies from Find-Anomalies
    
.PARAMETER RiskScore
    Risk score object from Get-RiskScore
    
.PARAMETER Comparison
    Comparison data from Compare-AuditData
    
.PARAMETER AlertEmail
    Email address to send alerts to
    
.PARAMETER SMTPServer
    SMTP server for sending emails
    
.PARAMETER From
    From email address
    
.PARAMETER Thresholds
    Custom alert thresholds
    
.EXAMPLE
    Send-AnalyticsAlert -Anomalies $anomalies `
                        -RiskScore $riskScore `
                        -Comparison $comparison `
                        -AlertEmail "admin@contoso.com" `
                        -SMTPServer "smtp.office365.com" `
                        -From "audit@contoso.com"
    
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [array]$Anomalies,
    
    [Parameter(Mandatory = $true)]
    [PSCustomObject]$RiskScore,
    
    [Parameter(Mandatory = $true)]
    [hashtable]$Comparison,
    
    [Parameter(Mandatory = $true)]
    [string]$AlertEmail,
    
    [Parameter(Mandatory = $true)]
    [string]$SMTPServer,
    
    [Parameter(Mandatory = $true)]
    [string]$From,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$Thresholds = @{
        RiskScoreBelow = 60
        CriticalAnomalies = 1
        HighAnomalies = 3
        PrivilegedAccountGrowth = 10 # percent
    }
)

function Test-AlertThresholds {
    <#
    .SYNOPSIS
        Tests if any alert thresholds have been breached
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Anomalies,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RiskScore,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Comparison,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Thresholds
    )
    
    $alerts = @()
    
    # Alert 1: Risk score below threshold
    if ($RiskScore.Score -lt $Thresholds.RiskScoreBelow) {
        $alerts += [PSCustomObject]@{
            Type = "RiskScore"
            Severity = "High"
            Message = "Overall risk score ($($RiskScore.Score)/100) is below threshold ($($Thresholds.RiskScoreBelow)). Current risk level: $($RiskScore.Level)"
            Action = "Review risk factors and implement remediation plan"
        }
    }
    
    # Alert 2: Critical anomalies detected
    $criticalCount = ($Anomalies | Where-Object Severity -eq 'Critical').Count
    if ($criticalCount -ge $Thresholds.CriticalAnomalies) {
        $alerts += [PSCustomObject]@{
            Type = "CriticalAnomalies"
            Severity = "Critical"
            Message = "$criticalCount critical anomalies detected (threshold: $($Thresholds.CriticalAnomalies))"
            Action = "Immediate remediation required for critical security issues"
        }
    }
    
    # Alert 3: High priority anomalies
    $highCount = ($Anomalies | Where-Object Severity -eq 'High').Count
    if ($highCount -ge $Thresholds.HighAnomalies) {
        $alerts += [PSCustomObject]@{
            Type = "HighAnomalies"
            Severity = "High"
            Message = "$highCount high priority anomalies detected (threshold: $($Thresholds.HighAnomalies))"
            Action = "Schedule remediation for high priority issues within 48 hours"
        }
    }
    
    # Alert 4: Privileged account growth
    if ($Comparison.PrivilegedAccounts.PercentChange -gt $Thresholds.PrivilegedAccountGrowth) {
        $alerts += [PSCustomObject]@{
            Type = "PrivilegedAccountGrowth"
            Severity = "Medium"
            Message = "Privileged accounts increased by $($Comparison.PrivilegedAccounts.PercentChange)% (threshold: $($Thresholds.PrivilegedAccountGrowth)%)"
            Action = "Review recent privileged account additions for justification"
        }
    }
    
    # Alert 5: Stale privileged accounts
    if ($RiskScore.Factors.StalePrivilegedAccounts -gt 0) {
        $alerts += [PSCustomObject]@{
            Type = "StalePrivilegedAccounts"
            Severity = "Critical"
            Message = "$($RiskScore.Factors.StalePrivilegedAccounts) stale or disabled accounts still have privileged access"
            Action = "Remove privileged access from inactive accounts immediately"
        }
    }
    
    # Alert 6: Kerberos delegation risks
    if ($RiskScore.Factors.KerberosDelegation -gt 0) {
        $alerts += [PSCustomObject]@{
            Type = "KerberosDelegation"
            Severity = "Critical"
            Message = "$($RiskScore.Factors.KerberosDelegation) accounts with unconstrained Kerberos delegation detected"
            Action = "Remove unconstrained delegation or switch to constrained delegation"
        }
    }
    
    return $alerts
}

function Send-AlertEmail {
    <#
    .SYNOPSIS
        Sends alert email with HTML formatting
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Alerts,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RiskScore,
        
        [Parameter(Mandatory = $true)]
        [string]$To,
        
        [Parameter(Mandatory = $true)]
        [string]$From,
        
        [Parameter(Mandatory = $true)]
        [string]$SMTPServer
    )
    
    $subject = "🚨 M&A Audit Alert: $($Alerts.Count) Threshold(s) Breached - Risk Level: $($RiskScore.Level)"
    
    $body = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }
        .container { background: white; border-radius: 10px; padding: 30px; max-width: 800px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #dc3545 0%, #ff6b6b 100%); color: white; padding: 20px; border-radius: 10px 10px 0 0; margin: -30px -30px 20px -30px; }
        .header h1 { margin: 0; font-size: 1.8rem; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .risk-badge { display: inline-block; padding: 10px 20px; border-radius: 25px; font-weight: bold; font-size: 1.2rem; }
        .risk-critical { background: #dc3545; color: white; }
        .risk-high { background: #ff6b6b; color: white; }
        .risk-medium { background: #ffc107; color: #333; }
        .risk-low { background: #28a745; color: white; }
        .alert-card { background: #f8f9fa; border-left: 5px solid; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
        .alert-card.critical { border-left-color: #dc3545; }
        .alert-card.high { border-left-color: #ff6b6b; }
        .alert-card.medium { border-left-color: #ffc107; }
        .alert-title { font-size: 1.1rem; font-weight: bold; margin-bottom: 8px; color: #333; }
        .alert-message { color: #666; margin-bottom: 8px; }
        .alert-action { background: white; padding: 10px; border-radius: 5px; font-size: 0.9rem; color: #333; }
        .severity-badge { padding: 3px 10px; border-radius: 15px; font-size: 0.8rem; font-weight: bold; color: white; }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #ff6b6b; }
        .severity-medium { background: #ffc107; color: #333; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #666; font-size: 0.9rem; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 M&A Audit Alert</h1>
            <p>$(Get-Date -Format "MMMM dd, yyyy HH:mm")</p>
        </div>
        
        <h2 style="color: #333; margin-bottom: 15px;">Alert Summary</h2>
        <p style="font-size: 1.1rem; margin-bottom: 20px;">
            Current Risk Level: <span class="risk-badge risk-$($RiskScore.Level.ToLower())">$($RiskScore.Level.ToUpper())</span>
        </p>
        <p style="color: #666; margin-bottom: 30px;">
            <strong>$($Alerts.Count)</strong> alert threshold(s) have been breached and require immediate attention.
        </p>
        
        <h3 style="color: #333; margin-bottom: 15px;">Triggered Alerts</h3>
$(
    $Alerts | ForEach-Object {
        $severityClass = $_.Severity.ToLower()
        @"
        <div class="alert-card $severityClass">
            <div class="alert-title">
                $($_.Type) <span class="severity-badge severity-$severityClass">$($_.Severity)</span>
            </div>
            <div class="alert-message">$($_.Message)</div>
            <div class="alert-action"><strong>Action Required:</strong> $($_.Action)</div>
        </div>
"@
    } | Out-String
)
        
        <div class="footer">
            <p><strong>This is an automated alert from the M&A Audit Analytics Engine.</strong></p>
            <p>Review the detailed analytics dashboard for complete information.</p>
            <p>Generated by M&A Audit Tool v2.3.0</p>
        </div>
    </div>
</body>
</html>
"@
    
    try {
        Send-MailMessage -To $To `
                        -From $From `
                        -Subject $subject `
                        -Body $body `
                        -BodyAsHtml `
                        -SmtpServer $SMTPServer `
                        -Priority High
        
        Write-Host "✅ Alert email sent to $To" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "❌ Failed to send alert email: $_" -ForegroundColor Red
        return $false
    }
}

# Main execution
Write-Host "`n=== Analytics Alert System ===" -ForegroundColor Cyan
Write-Host "Testing alert thresholds..." -ForegroundColor Cyan

$triggeredAlerts = Test-AlertThresholds -Anomalies $Anomalies `
                                        -RiskScore $RiskScore `
                                        -Comparison $Comparison `
                                        -Thresholds $Thresholds

if ($triggeredAlerts.Count -eq 0) {
    Write-Host "✅ No alert thresholds breached - Environment within acceptable parameters" -ForegroundColor Green
    return $null
}
else {
    Write-Host "⚠️  $($triggeredAlerts.Count) alert(s) triggered" -ForegroundColor Yellow
    
    # Display alerts
    $triggeredAlerts | ForEach-Object {
        Write-Host "`n[$($_.Severity)] $($_.Type)" -ForegroundColor Red
        Write-Host "  Message: $($_.Message)" -ForegroundColor White
        Write-Host "  Action: $($_.Action)" -ForegroundColor Yellow
    }
    
    # Send email if configured
    if ($AlertEmail) {
        Write-Host "`nSending alert email to $AlertEmail..." -ForegroundColor Cyan
        Send-AlertEmail -Alerts $triggeredAlerts `
                       -RiskScore $RiskScore `
                       -To $AlertEmail `
                       -From $From `
                       -SMTPServer $SMTPServer | Out-Null
    }
    
    return $triggeredAlerts
}

# Export functions
Export-ModuleMember -Function @('Test-AlertThresholds', 'Send-AlertEmail')

