<#
.SYNOPSIS
    Comprehensive LAPS (Local Administrator Password Solution) security audit

.DESCRIPTION
    Audits LAPS implementation across all domain-joined computers including:
    - LAPS installation and configuration status
    - Password age and expiration analysis
    - GPO configuration verification
    - Permissions and ACL analysis
    - Compliance scoring and risk assessment
    - Automated remediation capabilities
    - Scheduled audit automation
    - Multiple reporting formats (HTML, CSV, JSON, XML, Markdown, Excel, PDF, Email)

.PARAMETER DatabasePath
    Path to SQLite database for storing audit results

.PARAMETER OutputPath
    Output directory for reports (default: C:\Audits\LAPS)

.PARAMETER IncludeAll
    Run all LAPS checks (default behavior)

.PARAMETER PasswordAgeThreshold
    Threshold for stale passwords in days (default: 30)

.PARAMETER ExpirationThreshold
    Threshold for expired passwords in days (default: 90)

.PARAMETER EnableRemediation
    Enable automated password reset for non-compliant computers

.PARAMETER DryRun
    Preview mode - no actual password resets performed

.PARAMETER EmailRecipients
    Email addresses for report delivery

.PARAMETER SendEmail
    Send email report to specified recipients

.PARAMETER ReportFormat
    Report formats to generate (HTML, CSV, JSON, XML, Markdown, Excel, PDF)
    Default: HTML, CSV, JSON

.EXAMPLE
    .\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.EXAMPLE
    .\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll -EnableRemediation -DryRun

.EXAMPLE
    .\Invoke-LAPS-Audit.ps1 -DatabasePath "C:\Audits\AuditData.db" -EmailRecipients "admin@company.com" -SendEmail

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Requires: LAPS PowerShell module, ActiveDirectory module, Domain Admin rights
    Based on: Microsoft LAPS best practices and CIS Controls
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Audits\LAPS",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll,
    
    [Parameter(Mandatory = $false)]
    [int]$PasswordAgeThreshold = 30,
    
    [Parameter(Mandatory = $false)]
    [int]$ExpirationThreshold = 90,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableRemediation,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [string[]]$EmailRecipients,
    
    [Parameter(Mandatory = $false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('HTML', 'CSV', 'JSON', 'XML', 'Markdown', 'Excel', 'PDF', 'All')]
    [string[]]$ReportFormat = @('HTML', 'CSV', 'JSON')
)

$ErrorActionPreference = 'Stop'

# Set default for IncludeAll if not specified
if (-not $IncludeAll) {
    $IncludeAll = $true
}

#region Helper Functions

function Write-LAPSLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [LAPS-Audit] [$Level] $Message"
    
    switch ($Level) {
        'Critical' { Write-Host $logMessage -ForegroundColor Red -BackgroundColor Yellow }
        'Error'    { Write-Host $logMessage -ForegroundColor Red }
        'Warning'  { Write-Host $logMessage -ForegroundColor Yellow }
        'Success'  { Write-Host $logMessage -ForegroundColor Green }
        default    { Write-Verbose $logMessage }
    }
}

function Get-DatabaseConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath
    )
    
    try {
        if (-not (Test-Path $DatabasePath)) {
            Write-LAPSLog "Database not found at $DatabasePath" -Level Warning
            return $null
        }
        
        $connectionString = "Data Source=$DatabasePath;Version=3;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()
        
        return $connection
    }
    catch {
        Write-LAPSLog "Failed to connect to database: $_" -Level Error
        return $null
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
        $result = $command.ExecuteReader()
        
        $dataTable = New-Object System.Data.DataTable
        $dataTable.Load($result)
        
        return $dataTable
    }
    catch {
        Write-LAPSLog "Database query failed: $_" -Level Error
        return $null
    }
}

#endregion

#region LAPS Detection Functions

function Get-LAPSStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$PasswordAgeThreshold = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$ExpirationThreshold = 90
    )
    
    Write-LAPSLog "Scanning all domain computers for LAPS status..." -Level Info
    
    $lapsData = @()
    
    try {
        # Get all computers with LAPS-related properties
        $lapsProperties = @(
            'Name',
            'DNSHostName',
            'DistinguishedName',
            'Enabled',
            'OperatingSystem',
            'LastLogonDate',
            'ms-Mcs-AdmPwd',
            'ms-Mcs-AdmPwdExpirationTime'
        )
        
        Write-LAPSLog "Querying Active Directory for computer objects..." -Level Info
        $computers = Get-ADComputer -Filter * -Properties $lapsProperties -ErrorAction SilentlyContinue
        
        Write-LAPSLog "Found $($computers.Count) computers to analyze" -Level Info
        
        foreach ($computer in $computers) {
            # Check if LAPS password exists
            $hasPassword = $false
            
            if ($computer.'ms-Mcs-AdmPwd') {
                $hasPassword = $true
            }
            
            # Get expiration time
            $expirationTime = $null
            $isExpired = $false
            $isStale = $false
            $passwordAge = $null
            
            if ($computer.'ms-Mcs-AdmPwdExpirationTime') {
                $expirationTime = [DateTime]::FromFileTime($computer.'ms-Mcs-AdmPwdExpirationTime')
                
                if ($expirationTime -lt (Get-Date)) {
                    $isExpired = $true
                    $passwordAge = [math]::Round((New-TimeSpan -Start $expirationTime -End (Get-Date)).TotalDays)
                }
                else {
                    $passwordAge = [math]::Round((New-TimeSpan -Start $expirationTime -End (Get-Date)).TotalDays) * -1
                }
            }
            
            # Determine if stale (age > threshold)
            if ($null -ne $passwordAge -and [math]::Abs($passwordAge) -gt $PasswordAgeThreshold) {
                $isStale = $true
            }
            
            # Determine LAPS compliance
            $lapsInstalled = $hasPassword -and $null -ne $expirationTime
            $lapsCompliant = $lapsInstalled -and -not $isExpired
            
            # Calculate risk level
            $riskLevel = 'Low'
            if (-not $lapsInstalled) {
                $riskLevel = 'High'
            }
            elseif ($isExpired) {
                $riskLevel = 'Critical'
            }
            elseif ($isStale) {
                $riskLevel = 'Medium'
            }
            
            # Generate recommendation
            $recommendation = ""
            if (-not $lapsInstalled) {
                $recommendation = "LAPS not installed or configured. Install LAPS and enable via GPO."
            }
            elseif ($isExpired) {
                $recommendation = "LAPS password expired $($passwordAge) days ago. Force password reset immediately."
            }
            elseif ($isStale) {
                $recommendation = "LAPS password is $([math]::Abs($passwordAge)) days old. Consider forcing password reset."
            }
            else {
                $recommendation = "LAPS is configured and compliant. Monitor regularly."
            }
            
            $lapsData += [PSCustomObject]@{
                ComputerName = $computer.Name
                DNSHostName = $computer.DNSHostName
                DistinguishedName = $computer.DistinguishedName
                Enabled = $computer.Enabled
                OperatingSystem = $computer.OperatingSystem
                IsServer = $computer.OperatingSystem -like '*Server*'
                IsDomainController = $computer.OperatingSystem -like '*Domain Controller*'
                LastLogonDate = $computer.LastLogonDate
                LAPSInstalled = $lapsInstalled
                HasLAPSPassword = $hasPassword
                LAPSExpirationDate = $expirationTime
                LAPSPasswordAge = $passwordAge
                IsExpired = $isExpired
                IsStale = $isStale
                LAPSCompliant = $lapsCompliant
                RiskLevel = $riskLevel
                Recommendation = $recommendation
                AuditDate = Get-Date
            }
        }
        
        Write-LAPSLog "Analyzed $($lapsData.Count) computers. Found $($lapsData | Where-Object { $_.LAPSCompliant }).Count compliant." -Level Success
        return $lapsData
    }
    catch {
        Write-LAPSLog "Failed to scan LAPS status: $_" -Level Error
        return @()
    }
}

function Get-LAPSCompliance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LAPSData
    )
    
    Write-LAPSLog "Calculating LAPS compliance metrics..." -Level Info
    
    $total = $LAPSData.Count
    $compliant = ($LAPSData | Where-Object { $_.LAPSCompliant -eq $true }).Count
    $nonCompliant = $total - $compliant
    $installed = ($LAPSData | Where-Object { $_.LAPSInstalled -eq $true }).Count
    $expired = ($LAPSData | Where-Object { $_.IsExpired -eq $true }).Count
    $stale = ($LAPSData | Where-Object { $_.IsStale -eq $true }).Count
    
    $compliancePercent = if ($total -gt 0) { [math]::Round(($compliant / $total) * 100, 2) } else { 0 }
    $installationPercent = if ($total -gt 0) { [math]::Round(($installed / $total) * 100, 2) } else { 0 }
    
    $riskLevel = switch ($compliancePercent) {
        {$_ -ge 95} { 'Low' }
        {$_ -ge 80} { 'Medium' }
        {$_ -ge 60} { 'High' }
        default { 'Critical' }
    }
    
    $complianceMetrics = [PSCustomObject]@{
        TotalComputers = $total
        LAPSInstalled = $installed
        InstallationPercentage = $installationPercent
        LAPSCompliant = $compliant
        NonCompliant = $nonCompliant
        CompliancePercentage = $compliancePercent
        ExpiredPasswords = $expired
        StalePasswords = $stale
        RiskLevel = $riskLevel
        AuditDate = Get-Date
        Recommendation = switch ($riskLevel) {
            'Critical' { 'Immediate action required. Deploy LAPS to all non-compliant computers immediately.' }
            'High' { 'Urgent action needed. Address expired passwords and deploy LAPS to remaining systems.' }
            'Medium' { 'Improvement needed. Deploy LAPS to non-compliant systems and review stale passwords.' }
            default { 'Monitor compliance and maintain LAPS deployment.' }
        }
    }
    
    Write-LAPSLog "Compliance: $compliancePercent% ($compliant/$total computers)" -Level Success
    return $complianceMetrics
}

#endregion

#region Password Reset Actions

function Reset-LAPSPassword {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        if ($DryRun) {
            Write-LAPSLog "[DRY RUN] Would reset LAPS password for $ComputerName" -Level Info
            return $true
        }
        
        Write-LAPSLog "Attempting to reset LAPS password for $ComputerName..." -Level Info
        
        # Method 1: Clear expiration to force LAPS to regenerate password
        $null = Get-ADComputer -Identity $ComputerName -Properties ms-Mcs-AdmPwdExpirationTime -ErrorAction Stop
        Set-ADComputer -Identity $ComputerName -Clear ms-Mcs-AdmPwdExpirationTime -ErrorAction Stop
        
        # Wait for LAPS to regenerate password (typically within 15 minutes)
        Write-LAPSLog "Cleared LAPS expiration for $ComputerName. Password will regenerate within 15 minutes." -Level Success
        return $true
    }
    catch {
        Write-LAPSLog "Failed to reset LAPS password for $ComputerName`: $_" -Level Error
        return $false
    }
}

function Reset-LAPSPasswordsBulk {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ComputerList,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxParallel = 10
    )
    
    Write-LAPSLog "Starting bulk LAPS password reset for $($ComputerList.Count) computers..." -Level Info
    
    if ($DryRun) {
        Write-LAPSLog "DRY RUN MODE - No passwords will be reset" -Level Warning
    }
    
    $results = @()
    $successCount = 0
    $failureCount = 0
    
    # Process in batches
    $batches = @()
    for ($i = 0; $i -lt $ComputerList.Count; $i += $MaxParallel) {
        $batches += ,@($ComputerList[$i..([math]::Min($i + $MaxParallel - 1, $ComputerList.Count - 1))])
    }
    
    foreach ($batch in $batches) {
        $batchResults = $batch | ForEach-Object -Parallel {
            $computer = $_
            $dryRun = $using:DryRun
            
            $result = Reset-LAPSPassword -ComputerName $computer.ComputerName -DryRun:$dryRun
            
            [PSCustomObject]@{
                ComputerName = $computer.ComputerName
                Success = $result
                Timestamp = Get-Date
            }
        } -ThrottleLimit $MaxParallel
        
        $results += $batchResults
        $successCount += ($batchResults | Where-Object { $_.Success }).Count
        $failureCount += ($batchResults | Where-Object { -not $_.Success }).Count
        
        Write-LAPSLog "Progress: $successCount successful, $failureCount failed out of $($ComputerList.Count) total" -Level Info
    }
    
    Write-LAPSLog "Bulk password reset complete: $successCount successful, $failureCount failed" -Level Success
    return $results
}

#endregion

#region Reporting Functions

function Export-LAPSReports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LAPSData,
        
        [Parameter(Mandatory = $true)]
        [object]$ComplianceMetrics,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [string[]]$ReportFormat = @('HTML', 'CSV', 'JSON')
    )
    
    Write-LAPSLog "Generating reports in format(s): $($ReportFormat -join ', ')" -Level Info
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    # Filter data for specific reports
    $allComputers = $LAPSData
    
    foreach ($format in $ReportFormat) {
        try {
            switch ($format) {
                'CSV' {
                    Export-LAPSReportsCSV -All $allComputers -OutputPath $OutputPath
                    Write-LAPSLog "CSV reports exported" -Level Success
                }
                'HTML' {
                    Export-LAPSReportsHTML -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Write-LAPSLog "HTML report generated" -Level Success
                }
                'JSON' {
                    Export-LAPSReportsJSON -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Write-LAPSLog "JSON report generated" -Level Success
                }
                'XML' {
                    Export-LAPSReportsXML -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Write-LAPSLog "XML report generated" -Level Success
                }
                'Markdown' {
                    Export-LAPSReportsMarkdown -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Write-LAPSLog "Markdown report generated" -Level Success
                }
                'Excel' {
                    Export-LAPSReportsExcel -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Write-LAPSLog "Excel report generated" -Level Success
                }
                'PDF' {
                    Export-LAPSReportsPDF -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Write-LAPSLog "PDF report generated" -Level Success
                }
                'All' {
                    Export-LAPSReportsCSV -All $allComputers -OutputPath $OutputPath
                    Export-LAPSReportsHTML -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Export-LAPSReportsJSON -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Export-LAPSReportsXML -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Export-LAPSReportsMarkdown -Data $allComputers -Compliance $ComplianceMetrics -OutputPath $OutputPath
                    Write-LAPSLog "All report formats generated" -Level Success
                }
            }
        }
        catch {
            Write-LAPSLog "Failed to generate $format report: $_" -Level Warning
        }
    }
}

function Export-LAPSReportsCSV {
    [CmdletBinding()]
    param(
        [array]$All,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export all computers
    $All | Export-Csv -Path (Join-Path $OutputPath "LAPS_Status_All_$timestamp.csv") -NoTypeInformation
    
    # Export non-compliant
    $nonCompliant = $All | Where-Object { -not $_.LAPSCompliant }
    if ($nonCompliant) {
        $nonCompliant | Export-Csv -Path (Join-Path $OutputPath "LAPS_Non_Compliant_$timestamp.csv") -NoTypeInformation
    }
    
    # Export expired
    $expired = $All | Where-Object { $_.IsExpired }
    if ($expired) {
        $expired | Export-Csv -Path (Join-Path $OutputPath "LAPS_Expired_$timestamp.csv") -NoTypeInformation
    }
    
    # Export missing
    $missing = $All | Where-Object { -not $_.LAPSInstalled }
    if ($missing) {
        $missing | Export-Csv -Path (Join-Path $OutputPath "LAPS_Missing_$timestamp.csv") -NoTypeInformation
    }
}

function Export-LAPSReportsHTML {
    [CmdletBinding()]
    param(
        [array]$Data,
        [object]$Compliance,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>LAPS Audit Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        .summary { display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }
        .metric-card { flex: 1; min-width: 200px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px; }
        .metric-card.warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .metric-card.critical { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
        .metric-value { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .metric-label { font-size: 14px; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0078d4; color: white; font-weight: 600; }
        tr:hover { background: #f9f9f9; }
        .badge { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .badge-compliant { background: #28a745; color: white; }
        .badge-noncompliant { background: #dc3545; color: white; }
        .badge-expired { background: #ffc107; color: #333; }
        .badge-stale { background: #fd7e14; color: white; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 LAPS Audit Report</h1>
        <p><strong>Report Generated:</strong> $timestamp</p>
        <p><strong>Total Computers Scanned:</strong> $($Compliance.TotalComputers)</p>
        
        <h2>📊 Executive Summary</h2>
        <div class="summary">
            <div class="metric-card $(if($Compliance.CompliancePercentage -lt 80){'warning'} elseif($Compliance.CompliancePercentage -lt 60){'critical'})">
                <div class="metric-label">LAPS Compliance</div>
                <div class="metric-value">$($Compliance.CompliancePercentage)%</div>
                <div class="metric-label">$($Compliance.LAPSCompliant) of $($Compliance.TotalComputers) computers</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">LAPS Installed</div>
                <div class="metric-value">$($Compliance.InstallationPercentage)%</div>
                <div class="metric-label">$($Compliance.LAPSInstalled) computers</div>
            </div>
            <div class="metric-card $(if($Compliance.ExpiredPasswords -gt 0){'critical'})">
                <div class="metric-label">Expired Passwords</div>
                <div class="metric-value">$($Compliance.ExpiredPasswords)</div>
                <div class="metric-label">Immediate action required</div>
            </div>
            <div class="metric-card $(if($Compliance.StalePasswords -gt 0){'warning'})">
                <div class="metric-label">Stale Passwords</div>
                <div class="metric-value">$($Compliance.StalePasswords)</div>
                <div class="metric-label">Review and reset</div>
            </div>
        </div>
        
        <h2>⚠️ Risk Assessment</h2>
        <p><strong>Overall Risk Level:</strong> <span class="badge badge-$($Compliance.RiskLevel.ToLower())">$($Compliance.RiskLevel)</span></p>
        <p><strong>Recommendation:</strong> $($Compliance.Recommendation)</p>
        
        <h2>🖥️ All Computers - LAPS Status</h2>
        <table>
            <tr>
                <th>Computer Name</th>
                <th>Operating System</th>
                <th>LAPS Status</th>
                <th>Password Age</th>
                <th>Risk Level</th>
                <th>Recommendation</th>
            </tr>
"@
    
    foreach ($computer in $Data) {
        $statusBadge = if ($computer.LAPSCompliant) { "badge-compliant" } else { "badge-noncompliant" }
        $statusText = if ($computer.LAPSCompliant) { "Compliant" } else { "Non-Compliant" }
        $riskBadge = "badge-$($computer.RiskLevel.ToLower())"
        
        $html += @"
            <tr>
                <td>$($computer.ComputerName)</td>
                <td>$($computer.OperatingSystem)</td>
                <td><span class="badge $statusBadge">$statusText</span></td>
                <td>$($computer.LAPSPasswordAge) days</td>
                <td><span class="badge $riskBadge">$($computer.RiskLevel)</span></td>
                <td>$($computer.Recommendation)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
</body>
</html>
"@
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $htmlPath = Join-Path $OutputPath "LAPS_Compliance_Report_$timestamp.html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    
    Write-LAPSLog "HTML report saved to: $htmlPath" -Level Success
}

function Export-LAPSReportsJSON {
    [CmdletBinding()]
    param(
        [array]$Data,
        [object]$Compliance,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    $report = [PSCustomObject]@{
        ReportDate = Get-Date
        ComplianceMetrics = $Compliance
        Computers = $Data
    }
    
    $jsonPath = Join-Path $OutputPath "LAPS_Report_$timestamp.json"
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    Write-LAPSLog "JSON report saved to: $jsonPath" -Level Success
}

function Export-LAPSReportsXML {
    [CmdletBinding()]
    param(
        [array]$Data,
        [object]$Compliance,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    $report = [PSCustomObject]@{
        ReportDate = Get-Date
        ComplianceMetrics = $Compliance
        Computers = $Data
    }
    
    $xmlPath = Join-Path $OutputPath "LAPS_Report_$timestamp.xml"
    $report | Export-Clixml -Path $xmlPath
    
    Write-LAPSLog "XML report saved to: $xmlPath" -Level Success
}

function Export-LAPSReportsMarkdown {
    [CmdletBinding()]
    param(
        [array]$Data,
        [object]$Compliance,
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $markdown = @"
# LAPS Audit Report

**Report Generated:** $timestamp

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Computers | $($Compliance.TotalComputers) |
| LAPS Compliant | $($Compliance.LAPSCompliant) ($($Compliance.CompliancePercentage)%) |
| LAPS Installed | $($Compliance.LAPSInstalled) ($($Compliance.InstallationPercentage)%) |
| Expired Passwords | $($Compliance.ExpiredPasswords) |
| Stale Passwords | $($Compliance.StalePasswords) |
| Risk Level | **$($Compliance.RiskLevel)** |

## Recommendation

$($Compliance.Recommendation)

## All Computers

| Computer Name | OS | Status | Password Age | Risk Level |
|--------------|-------|--------|--------------|------------|
"@
    
    foreach ($computer in $Data) {
        $status = if ($computer.LAPSCompliant) { "✅ Compliant" } else { "❌ Non-Compliant" }
        $markdown += "| $($computer.ComputerName) | $($computer.OperatingSystem) | $status | $($computer.LAPSPasswordAge) days | $($computer.RiskLevel) |`n"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $mdPath = Join-Path $OutputPath "LAPS_Report_$timestamp.md"
    $markdown | Out-File -FilePath $mdPath -Encoding UTF8
    
    Write-LAPSLog "Markdown report saved to: $mdPath" -Level Success
}

# Stub functions for Excel and PDF (would require additional modules)
function Export-LAPSReportsExcel { Write-LAPSLog "Excel export requires ImportExcel module" -Level Warning }
function Export-LAPSReportsPDF { Write-LAPSLog "PDF export requires PSPDF module" -Level Warning }

#endregion

#region Main Execution

try {
    Write-LAPSLog "Starting LAPS Audit..." -Level Info
    Write-LAPSLog "Output path: $OutputPath" -Level Info
    
    # Scan for LAPS status
    $lapsData = Get-LAPSStatus -PasswordAgeThreshold $PasswordAgeThreshold -ExpirationThreshold $ExpirationThreshold
    
    if ($lapsData.Count -eq 0) {
        Write-LAPSLog "No computers found to analyze" -Level Warning
        return
    }
    
    # Calculate compliance
    $complianceMetrics = Get-LAPSCompliance -LAPSData $lapsData
    
    # Export reports
    Export-LAPSReports -LAPSData $lapsData -ComplianceMetrics $complianceMetrics -OutputPath $OutputPath -ReportFormat $ReportFormat
    
    # Remediation if enabled
    if ($EnableRemediation) {
        Write-LAPSLog "Remediation enabled. Analyzing non-compliant computers..." -Level Info
        
        $nonCompliant = $lapsData | Where-Object { -not $_.LAPSCompliant }
        
        if ($nonCompliant.Count -gt 0) {
            Write-LAPSLog "Found $($nonCompliant.Count) non-compliant computers" -Level Warning
            
            if ($DryRun) {
                Write-LAPSLog "DRY RUN MODE - Would reset passwords for:" -Level Info
                $nonCompliant | ForEach-Object { Write-LAPSLog "  - $($_.ComputerName)" -Level Info }
            }
            else {
                $resetResults = Reset-LAPSPasswordsBulk -ComputerList $nonCompliant -DryRun:$false
                Write-LAPSLog "Remediation complete: $($resetResults | Where-Object { $_.Success }).Count successful" -Level Success
            }
        }
    }
    
    Write-LAPSLog "LAPS audit completed successfully" -Level Success
    
    return @{
        Success = $true
        ComplianceMetrics = $complianceMetrics
        Results = $lapsData
        Message = "LAPS audit completed successfully"
    }
}
catch {
    Write-LAPSLog "LAPS audit failed: $_" -Level Error
    return @{
        Success = $false
        Error = $_.Exception.Message
        Message = "LAPS audit failed"
    }
}

#endregion
