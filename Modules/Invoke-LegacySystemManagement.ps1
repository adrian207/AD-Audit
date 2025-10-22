<#
.SYNOPSIS
    Active Directory Legacy System Management Module

.DESCRIPTION
    Comprehensive legacy system identification and management based on Microsoft's Active Directory
    security best practices. Identifies outdated systems, applications, and implements isolation
    recommendations.

.PARAMETER DatabasePath
    Path to audit database for storing results

.PARAMETER OutputPath
    Path to save CSV results

.PARAMETER IncludeLegacySystems
    Include legacy system identification

.PARAMETER IncludeLegacyApplications
    Include legacy application analysis

.PARAMETER IncludeLegacyIsolation
    Include legacy system isolation verification

.PARAMETER IncludeLegacyDecommissioning
    Include legacy system decommissioning tracking

.PARAMETER IncludeAll
    Include all legacy system assessments

.EXAMPLE
    .\Invoke-LegacySystemManagement.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.EXAMPLE
    .\Invoke-LegacySystemManagement.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeLegacySystems -IncludeLegacyApplications

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Based on: Microsoft Active Directory Security Best Practices
    Requires: ActiveDirectory module, domain admin rights
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Temp\LegacySystemManagement.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLegacySystems,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLegacyApplications,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLegacyIsolation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLegacyDecommissioning,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll
)

$ErrorActionPreference = 'Stop'

# Set flags based on IncludeAll parameter
if ($IncludeAll) {
    $IncludeLegacySystems = $true
    $IncludeLegacyApplications = $true
    $IncludeLegacyIsolation = $true
    $IncludeLegacyDecommissioning = $true
}

#region Helper Functions

function Write-LegacySystemLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Legacy-System-Management] [$Level] $Message"
    
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
        Add-Type -Path "System.Data.SQLite.dll" -ErrorAction Stop
        $connectionString = "Data Source=$DatabasePath;Version=3;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()
        return $connection
    }
    catch {
        Write-LegacySystemLog "Failed to connect to database: $_" -Level Error
        throw
    }
}

#endregion

#region Legacy System Management Functions

function Get-LegacySystemInventory {
    [CmdletBinding()]
    param()
    
    Write-LegacySystemLog "Identifying legacy systems..." -Level Info
    
    $legacySystems = @()
    
    try {
        # Get all computers
        $allComputers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled -ErrorAction SilentlyContinue
        
        foreach ($computer in $allComputers) {
            $isLegacy = $false
            $legacyReason = ""
            $riskLevel = 'Low'
            
            # Check operating system version
            $osVersion = $computer.OperatingSystemVersion
            if ($osVersion) {
                # Check for unsupported Windows versions
                if ($osVersion -match "Windows Server 2003|Windows Server 2008|Windows Server 2008 R2|Windows XP|Windows Vista|Windows 7") {
                    $isLegacy = $true
                    $legacyReason = "Unsupported OS: $($computer.OperatingSystem)"
                    $riskLevel = 'Critical'
                }
                elseif ($osVersion -match "Windows Server 2012|Windows Server 2012 R2|Windows 8|Windows 8.1") {
                    $isLegacy = $true
                    $legacyReason = "Legacy OS: $($computer.OperatingSystem)"
                    $riskLevel = 'High'
                }
                elseif ($osVersion -match "Windows Server 2016") {
                    $isLegacy = $true
                    $legacyReason = "Older OS: $($computer.OperatingSystem)"
                    $riskLevel = 'Medium'
                }
            }
            
            # Check for computers that haven't logged on recently
            if ($computer.LastLogonDate) {
                $daysSinceLogon = (Get-Date) - $computer.LastLogonDate
                if ($daysSinceLogon.Days -gt 365) {
                    $isLegacy = $true
                    $legacyReason += if ($legacyReason) { "; " } else { "" }
                    $legacyReason += "No logon for $($daysSinceLogon.Days) days"
                    $riskLevel = 'High'
                }
            }
            else {
                $isLegacy = $true
                $legacyReason += if ($legacyReason) { "; " } else { "" }
                $legacyReason += "Never logged on"
                $riskLevel = 'Medium'
            }
            
            # Check for disabled computers
            if (-not $computer.Enabled) {
                $isLegacy = $true
                $legacyReason += if ($legacyReason) { "; " } else { "" }
                $legacyReason += "Disabled account"
                $riskLevel = 'Low'
            }
            
            if ($isLegacy) {
                $legacySystems += [PSCustomObject]@{
                    ComputerName = $computer.Name
                    SamAccountName = $computer.SamAccountName
                    OperatingSystem = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    LastLogonDate = $computer.LastLogonDate
                    DaysSinceLogon = if ($computer.LastLogonDate) { ((Get-Date) - $computer.LastLogonDate).Days } else { 'Never' }
                    Enabled = $computer.Enabled
                    LegacyReason = $legacyReason
                    RiskLevel = $riskLevel
                    LegacyType = switch ($osVersion) {
                        { $_ -match "Windows Server 2003|Windows Server 2008|Windows XP|Windows Vista" } { 'Unsupported' }
                        { $_ -match "Windows Server 2012|Windows 8" } { 'Legacy' }
                        { $_ -match "Windows Server 2016|Windows 10" } { 'Older' }
                        default { 'Unknown' }
                    }
                    Recommendation = switch ($riskLevel) {
                        'Critical' { 'Immediate decommissioning required' }
                        'High' { 'Plan for decommissioning within 6 months' }
                        'Medium' { 'Plan for decommissioning within 12 months' }
                        'Low' { 'Monitor and consider decommissioning' }
                    }
                    LastModified = $computer.Modified
                }
            }
        }
        
        Write-LegacySystemLog "Identified $($legacySystems.Count) legacy systems" -Level Success
        return $legacySystems
    }
    catch {
        Write-LegacySystemLog "Failed to identify legacy systems: $_" -Level Error
        return @()
    }
}

function Get-LegacyApplicationAnalysis {
    [CmdletBinding()]
    param()
    
    Write-LegacySystemLog "Analyzing legacy applications..." -Level Info
    
    $legacyApplications = @()
    
    try {
        # Get all computers for application analysis
        $allComputers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion -ErrorAction SilentlyContinue
        
        foreach ($computer in $allComputers) {
            # Check for legacy applications based on OS version
            $osVersion = $computer.OperatingSystemVersion
            $legacyApps = @()
            
            if ($osVersion) {
                # Check for legacy OS that likely has legacy applications
                if ($osVersion -match "Windows Server 2003|Windows Server 2008|Windows XP|Windows Vista") {
                    $legacyApps += "Legacy OS likely has unsupported applications"
                }
                elseif ($osVersion -match "Windows Server 2012|Windows 8") {
                    $legacyApps += "Legacy OS may have outdated applications"
                }
                
                # Check for specific legacy application patterns
                if ($computer.Name -like "*sql*" -or $computer.Name -like "*exchange*" -or $computer.Name -like "*sharepoint*") {
                    $legacyApps += "Legacy server role detected"
                }
            }
            
            if ($legacyApps.Count -gt 0) {
                $legacyApplications += [PSCustomObject]@{
                    ComputerName = $computer.Name
                    SamAccountName = $computer.SamAccountName
                    OperatingSystem = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    LegacyApplications = $legacyApps -join '; '
                    RiskLevel = switch ($osVersion) {
                        { $_ -match "Windows Server 2003|Windows Server 2008|Windows XP|Windows Vista" } { 'Critical' }
                        { $_ -match "Windows Server 2012|Windows 8" } { 'High' }
                        default { 'Medium' }
                    }
                    ApplicationType = switch ($computer.Name) {
                        { $_ -like "*sql*" } { 'Database Server' }
                        { $_ -like "*exchange*" } { 'Mail Server' }
                        { $_ -like "*sharepoint*" } { 'Collaboration Server' }
                        default { 'General Server' }
                    }
                    Recommendation = 'Identify and migrate legacy applications to supported platforms'
                    LastModified = $computer.Modified
                }
            }
        }
        
        Write-LegacySystemLog "Analyzed $($legacyApplications.Count) legacy applications" -Level Success
        return $legacyApplications
    }
    catch {
        Write-LegacySystemLog "Failed to analyze legacy applications: $_" -Level Error
        return @()
    }
}

function Test-LegacySystemIsolation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LegacySystems
    )
    
    Write-LegacySystemLog "Verifying legacy system isolation..." -Level Info
    
    $isolationAnalysis = @()
    
    foreach ($legacySystem in $LegacySystems) {
        try {
            # Check if legacy system is accessible
            $isAccessible = Test-Connection -ComputerName $legacySystem.ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            if ($isAccessible) {
                $isolationAnalysis += [PSCustomObject]@{
                    ComputerName = $legacySystem.ComputerName
                    SamAccountName = $legacySystem.SamAccountName
                    OperatingSystem = $legacySystem.OperatingSystem
                    LegacyReason = $legacySystem.LegacyReason
                    RiskLevel = $legacySystem.RiskLevel
                    IsAccessible = $isAccessible
                    NetworkIsolation = 'Cannot verify remotely'
                    FirewallRules = 'Cannot verify remotely'
                    NetworkSegmentation = 'Cannot verify remotely'
                    AccessControl = 'Cannot verify remotely'
                    IsolationAssessment = 'Legacy system is accessible - requires isolation'
                    IsolationRecommendation = 'Implement network isolation and access controls'
                    LastChecked = Get-Date
                }
            }
            else {
                $isolationAnalysis += [PSCustomObject]@{
                    ComputerName = $legacySystem.ComputerName
                    SamAccountName = $legacySystem.SamAccountName
                    OperatingSystem = $legacySystem.OperatingSystem
                    LegacyReason = $legacySystem.LegacyReason
                    RiskLevel = $legacySystem.RiskLevel
                    IsAccessible = $false
                    NetworkIsolation = 'Unknown'
                    FirewallRules = 'Unknown'
                    NetworkSegmentation = 'Unknown'
                    AccessControl = 'Unknown'
                    IsolationAssessment = 'Legacy system is not accessible - may be isolated'
                    IsolationRecommendation = 'Verify isolation is intentional and secure'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-LegacySystemLog "Failed to analyze isolation for $($legacySystem.ComputerName): $_" -Level Warning
        }
    }
    
    Write-LegacySystemLog "Isolation analysis completed for $($isolationAnalysis.Count) legacy systems" -Level Success
    return $isolationAnalysis
}

function Get-LegacySystemDecommissioning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$LegacySystems
    )
    
    Write-LegacySystemLog "Tracking legacy system decommissioning..." -Level Info
    
    $decommissioningPlan = @()
    
    foreach ($legacySystem in $LegacySystems) {
        # Create decommissioning plan based on risk level
        $decommissioningTimeline = switch ($legacySystem.RiskLevel) {
            'Critical' { 'Immediate (0-30 days)' }
            'High' { 'Short-term (1-6 months)' }
            'Medium' { 'Medium-term (6-12 months)' }
            'Low' { 'Long-term (12+ months)' }
        }
        
        $decommissioningSteps = @()
        switch ($legacySystem.RiskLevel) {
            'Critical' {
                $decommissioningSteps += "1. Immediate network isolation"
                $decommissioningSteps += "2. Data migration (if applicable)"
                $decommissioningSteps += "3. Application migration (if applicable)"
                $decommissioningSteps += "4. Remove from domain"
                $decommissioningSteps += "5. Physical decommissioning"
            }
            'High' {
                $decommissioningSteps += "1. Plan data migration"
                $decommissioningSteps += "2. Plan application migration"
                $decommissioningSteps += "3. Implement network isolation"
                $decommissioningSteps += "4. Remove from domain"
                $decommissioningSteps += "5. Physical decommissioning"
            }
            'Medium' {
                $decommissioningSteps += "1. Assess migration requirements"
                $decommissioningSteps += "2. Plan migration timeline"
                $decommissioningSteps += "3. Implement network isolation"
                $decommissioningSteps += "4. Remove from domain"
                $decommissioningSteps += "5. Physical decommissioning"
            }
            'Low' {
                $decommissioningSteps += "1. Monitor usage"
                $decommissioningSteps += "2. Plan migration timeline"
                $decommissioningSteps += "3. Implement network isolation"
                $decommissioningSteps += "4. Remove from domain"
                $decommissioningSteps += "5. Physical decommissioning"
            }
        }
        
        $decommissioningPlan += [PSCustomObject]@{
            ComputerName = $legacySystem.ComputerName
            SamAccountName = $legacySystem.SamAccountName
            OperatingSystem = $legacySystem.OperatingSystem
            LegacyReason = $legacySystem.LegacyReason
            RiskLevel = $legacySystem.RiskLevel
            DecommissioningTimeline = $decommissioningTimeline
            DecommissioningSteps = $decommissioningSteps -join '; '
            Priority = switch ($legacySystem.RiskLevel) {
                'Critical' { 1 }
                'High' { 2 }
                'Medium' { 3 }
                'Low' { 4 }
            }
            EstimatedEffort = switch ($legacySystem.RiskLevel) {
                'Critical' { 'High' }
                'High' { 'High' }
                'Medium' { 'Medium' }
                'Low' { 'Low' }
            }
            Dependencies = 'Assess data and application dependencies'
            LastUpdated = Get-Date
        }
    }
    
    # Sort by priority
    $decommissioningPlan = $decommissioningPlan | Sort-Object Priority
    
    Write-LegacySystemLog "Decommissioning plan created for $($decommissioningPlan.Count) legacy systems" -Level Success
    return $decommissioningPlan
}

function Get-LegacySystemSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllResults
    )
    
    Write-LegacySystemLog "Generating legacy system summary..." -Level Info
    
    $summary = @{
        TotalLegacySystems = 0
        CriticalLegacySystems = 0
        HighLegacySystems = 0
        MediumLegacySystems = 0
        LowLegacySystems = 0
        UnsupportedOS = 0
        LegacyOS = 0
        OlderOS = 0
        InactiveSystems = 0
        DisabledSystems = 0
        LegacyApplications = 0
        IsolationRequired = 0
        DecommissioningRequired = 0
    }
    
    foreach ($result in $AllResults) {
        $summary.TotalLegacySystems++
        
        # Count by risk level
        switch ($result.RiskLevel) {
            'Critical' { $summary.CriticalLegacySystems++ }
            'High' { $summary.HighLegacySystems++ }
            'Medium' { $summary.MediumLegacySystems++ }
            'Low' { $summary.LowLegacySystems++ }
        }
        
        # Count by legacy type
        if ($result.LegacyType) {
            switch ($result.LegacyType) {
                'Unsupported' { $summary.UnsupportedOS++ }
                'Legacy' { $summary.LegacyOS++ }
                'Older' { $summary.OlderOS++ }
            }
        }
        
        # Count inactive systems
        if ($result.DaysSinceLogon -eq 'Never' -or $result.DaysSinceLogon -gt 365) {
            $summary.InactiveSystems++
        }
        
        # Count disabled systems
        if (-not $result.Enabled) {
            $summary.DisabledSystems++
        }
        
        # Count legacy applications
        if ($result.LegacyApplications) {
            $summary.LegacyApplications++
        }
        
        # Count systems requiring isolation
        if ($result.IsolationAssessment -like "*requires isolation*") {
            $summary.IsolationRequired++
        }
        
        # Count systems requiring decommissioning
        if ($result.DecommissioningTimeline) {
            $summary.DecommissioningRequired++
        }
    }
    
    return $summary
}

#endregion

#region Main Execution

try {
    Write-LegacySystemLog "Starting Legacy System Management Analysis..." -Level Info
    Write-LegacySystemLog "Database path: $DatabasePath" -Level Info
    Write-LegacySystemLog "Output path: $OutputPath" -Level Info
    
    $allResults = @()
    
    # Always perform legacy system identification (core requirement)
    Write-LegacySystemLog "Identifying legacy systems..." -Level Info
    $legacySystems = Get-LegacySystemInventory
    $allResults += $legacySystems
    
    # Optional analyses based on parameters
    if ($IncludeLegacyApplications) {
        Write-LegacySystemLog "Analyzing legacy applications..." -Level Info
        $legacyApplications = Get-LegacyApplicationAnalysis
        $allResults += $legacyApplications
    }
    
    if ($IncludeLegacyIsolation -and $legacySystems.Count -gt 0) {
        Write-LegacySystemLog "Verifying legacy system isolation..." -Level Info
        $isolationAnalysis = Test-LegacySystemIsolation -LegacySystems $legacySystems
        $allResults += $isolationAnalysis
    }
    
    if ($IncludeLegacyDecommissioning -and $legacySystems.Count -gt 0) {
        Write-LegacySystemLog "Creating decommissioning plan..." -Level Info
        $decommissioningPlan = Get-LegacySystemDecommissioning -LegacySystems $legacySystems
        $allResults += $decommissioningPlan
    }
    
    # Generate summary
    $summary = Get-LegacySystemSummary -AllResults $allResults
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-LegacySystemLog "Legacy system management results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-LegacySystemLog "Legacy System Management Summary:" -Level Info
    Write-LegacySystemLog "  Total Legacy Systems: $($summary.TotalLegacySystems)" -Level Info
    Write-LegacySystemLog "  Critical Legacy Systems: $($summary.CriticalLegacySystems)" -Level Error
    Write-LegacySystemLog "  High Legacy Systems: $($summary.HighLegacySystems)" -Level Warning
    Write-LegacySystemLog "  Medium Legacy Systems: $($summary.MediumLegacySystems)" -Level Info
    Write-LegacySystemLog "  Low Legacy Systems: $($summary.LowLegacySystems)" -Level Info
    Write-LegacySystemLog "  Unsupported OS: $($summary.UnsupportedOS)" -Level Error
    Write-LegacySystemLog "  Legacy OS: $($summary.LegacyOS)" -Level Warning
    Write-LegacySystemLog "  Older OS: $($summary.OlderOS)" -Level Info
    Write-LegacySystemLog "  Inactive Systems: $($summary.InactiveSystems)" -Level Warning
    Write-LegacySystemLog "  Disabled Systems: $($summary.DisabledSystems)" -Level Info
    Write-LegacySystemLog "  Legacy Applications: $($summary.LegacyApplications)" -Level Warning
    Write-LegacySystemLog "  Isolation Required: $($summary.IsolationRequired)" -Level Warning
    Write-LegacySystemLog "  Decommissioning Required: $($summary.DecommissioningRequired)" -Level Warning
    
    Write-LegacySystemLog "Legacy system management analysis completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allResults
        Message = "Legacy system management analysis completed successfully"
    }
}
catch {
    Write-LegacySystemLog "Legacy system management analysis failed: $_" -Level Error
    throw
}

#endregion
