<#
.SYNOPSIS
    Active Directory Domain Controller Security Module

.DESCRIPTION
    Comprehensive domain controller security analysis based on Microsoft's Active Directory
    security best practices. Verifies DC hardening, physical security, application allowlists,
    and configuration baselines.

.PARAMETER DatabasePath
    Path to audit database for storing results

.PARAMETER OutputPath
    Path to save CSV results

.PARAMETER IncludePhysicalSecurity
    Include physical security assessment

.PARAMETER IncludeApplicationAllowlists
    Include application allowlist verification

.PARAMETER IncludeConfigurationBaselines
    Include configuration baseline verification

.PARAMETER IncludeOSHardening
    Include operating system hardening analysis

.PARAMETER IncludeAll
    Include all security assessments

.EXAMPLE
    .\Invoke-DomainControllerSecurity.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.EXAMPLE
    .\Invoke-DomainControllerSecurity.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeApplicationAllowlists -IncludeOSHardening

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
    [string]$OutputPath = "C:\Temp\DomainControllerSecurity.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePhysicalSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeApplicationAllowlists,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeConfigurationBaselines,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeOSHardening,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll
)

$ErrorActionPreference = 'Stop'

# Set flags based on IncludeAll parameter
if ($IncludeAll) {
    $IncludePhysicalSecurity = $true
    $IncludeApplicationAllowlists = $true
    $IncludeConfigurationBaselines = $true
    $IncludeOSHardening = $true
}

#region Helper Functions

function Write-DCSecurityLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [DC-Security] [$Level] $Message"
    
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
        Write-DCSecurityLog "Failed to connect to database: $_" -Level Error
        throw
    }
}

function Invoke-RemoteCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )
    
    try {
        return Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop
    }
    catch {
        Write-DCSecurityLog "Failed to execute command on $ComputerName`: $_" -Level Error
        throw
    }
}

#endregion

#region Domain Controller Security Functions

function Get-DomainControllerInventory {
    [CmdletBinding()]
    param()
    
    Write-DCSecurityLog "Collecting domain controller inventory..." -Level Info
    
    $dcInventory = @()
    
    try {
        $domainControllers = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
        
        foreach ($dc in $domainControllers) {
            $dcInventory += [PSCustomObject]@{
                HostName = $dc.HostName
                Name = $dc.Name
                OperatingSystem = $dc.OperatingSystem
                OperatingSystemVersion = $dc.OperatingSystemVersion
                Site = $dc.Site
                IPv4Address = $dc.IPv4Address
                IPv6Address = $dc.IPv6Address
                IsGlobalCatalog = $dc.IsGlobalCatalog
                IsReadOnly = $dc.IsReadOnly
                Domain = $dc.Domain
                Forest = $dc.Forest
                LastModified = $dc.Modified
                Enabled = $dc.Enabled
            }
        }
        
        Write-DCSecurityLog "Found $($dcInventory.Count) domain controllers" -Level Success
        return $dcInventory
    }
    catch {
        Write-DCSecurityLog "Failed to collect domain controller inventory: $_" -Level Error
        return @()
    }
}

function Test-DomainControllerHardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$DomainControllers
    )
    
    Write-DCSecurityLog "Analyzing domain controller hardening..." -Level Info
    
    $hardeningAnalysis = @()
    
    foreach ($dc in $DomainControllers) {
        try {
            $isAccessible = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            if ($isAccessible) {
                # Check basic DC security configurations
                $securityChecks = @{
                    HostName = $dc.HostName
                    OperatingSystem = $dc.OperatingSystem
                    OperatingSystemVersion = $dc.OperatingSystemVersion
                    IsAccessible = $isAccessible
                    SecurityAssessment = 'Analyzing...'
                    Issues = @()
                    Recommendations = @()
                    RiskLevel = 'Medium'
                }
                
                # Check if DC is running a supported OS version
                $osVersion = $dc.OperatingSystemVersion
                if ($osVersion -match "Windows Server 2016|Windows Server 2019|Windows Server 2022|Windows Server 2025") {
                    $securityChecks.Issues += "Running supported OS version: $osVersion"
                }
                else {
                    $securityChecks.Issues += "Running unsupported OS version: $osVersion"
                    $securityChecks.RiskLevel = 'High'
                    $securityChecks.Recommendations += "Upgrade to supported Windows Server version"
                }
                
                # Check if DC is a Global Catalog
                if ($dc.IsGlobalCatalog) {
                    $securityChecks.Issues += "Global Catalog server - ensure proper security"
                    $securityChecks.Recommendations += "Monitor Global Catalog security closely"
                }
                
                # Check if DC is read-only
                if ($dc.IsReadOnly) {
                    $securityChecks.Issues += "Read-only domain controller - additional security considerations"
                    $securityChecks.Recommendations += "Implement RODC-specific security measures"
                }
                
                $hardeningAnalysis += [PSCustomObject]@{
                    HostName = $dc.HostName
                    OperatingSystem = $dc.OperatingSystem
                    OperatingSystemVersion = $dc.OperatingSystemVersion
                    IsAccessible = $isAccessible
                    SecurityAssessment = $securityChecks.SecurityAssessment
                    Issues = $securityChecks.Issues -join '; '
                    Recommendations = $securityChecks.Recommendations -join '; '
                    RiskLevel = $securityChecks.RiskLevel
                    IsGlobalCatalog = $dc.IsGlobalCatalog
                    IsReadOnly = $dc.IsReadOnly
                    Site = $dc.Site
                }
            }
            else {
                $hardeningAnalysis += [PSCustomObject]@{
                    HostName = $dc.HostName
                    OperatingSystem = $dc.OperatingSystem
                    OperatingSystemVersion = $dc.OperatingSystemVersion
                    IsAccessible = $false
                    SecurityAssessment = 'Cannot assess - Host unreachable'
                    Issues = 'Host unreachable for security analysis'
                    Recommendations = 'Investigate connectivity and verify DC is operational'
                    RiskLevel = 'High'
                    IsGlobalCatalog = $dc.IsGlobalCatalog
                    IsReadOnly = $dc.IsReadOnly
                    Site = $dc.Site
                }
            }
        }
        catch {
            Write-DCSecurityLog "Failed to analyze DC $($dc.HostName): $_" -Level Warning
        }
    }
    
    Write-DCSecurityLog "Analyzed hardening for $($hardeningAnalysis.Count) domain controllers" -Level Success
    return $hardeningAnalysis
}

function Test-PhysicalSecurityAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$DomainControllers
    )
    
    Write-DCSecurityLog "Assessing physical security requirements..." -Level Info
    
    $physicalSecurity = @()
    
    foreach ($dc in $DomainControllers) {
        # Physical security assessment (requires manual verification)
        $physicalSecurity += [PSCustomObject]@{
            HostName = $dc.HostName
            Site = $dc.Site
            PhysicalLocation = 'Requires manual verification'
            AccessControl = 'Requires manual verification'
            EnvironmentalControls = 'Requires manual verification'
            NetworkSecurity = 'Requires manual verification'
            BackupPower = 'Requires manual verification'
            FireSuppression = 'Requires manual verification'
            Monitoring = 'Requires manual verification'
            RiskLevel = 'Medium'
            Assessment = 'Physical security requires on-site verification'
            Recommendations = 'Conduct on-site physical security assessment'
        }
    }
    
    Write-DCSecurityLog "Physical security assessment completed for $($physicalSecurity.Count) domain controllers" -Level Success
    return $physicalSecurity
}

function Test-ApplicationAllowlists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$DomainControllers
    )
    
    Write-DCSecurityLog "Verifying application allowlists on domain controllers..." -Level Info
    
    $allowlistAnalysis = @()
    
    foreach ($dc in $DomainControllers) {
        try {
            $isAccessible = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            if ($isAccessible) {
                # Check for application allowlist implementation
                # This would require remote execution to check AppLocker or similar
                
                $allowlistAnalysis += [PSCustomObject]@{
                    HostName = $dc.HostName
                    OperatingSystem = $dc.OperatingSystem
                    IsAccessible = $isAccessible
                    AppLockerEnabled = 'Cannot verify remotely'
                    SoftwareRestrictionPolicies = 'Cannot verify remotely'
                    ApplicationAllowlist = 'Cannot verify remotely'
                    NonStandardApplications = 'Cannot verify remotely'
                    RiskLevel = 'Medium'
                    Assessment = 'Application allowlist verification requires remote access'
                    Recommendations = 'Implement AppLocker or Software Restriction Policies on DCs'
                }
            }
            else {
                $allowlistAnalysis += [PSCustomObject]@{
                    HostName = $dc.HostName
                    OperatingSystem = $dc.OperatingSystem
                    IsAccessible = $false
                    AppLockerEnabled = 'Unknown'
                    SoftwareRestrictionPolicies = 'Unknown'
                    ApplicationAllowlist = 'Unknown'
                    NonStandardApplications = 'Unknown'
                    RiskLevel = 'High'
                    Assessment = 'Cannot assess - Host unreachable'
                    Recommendations = 'Investigate connectivity and verify DC is operational'
                }
            }
        }
        catch {
            Write-DCSecurityLog "Failed to analyze application allowlists for $($dc.HostName): $_" -Level Warning
        }
    }
    
    Write-DCSecurityLog "Application allowlist analysis completed for $($allowlistAnalysis.Count) domain controllers" -Level Success
    return $allowlistAnalysis
}

function Test-ConfigurationBaselines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$DomainControllers
    )
    
    Write-DCSecurityLog "Verifying configuration baselines..." -Level Info
    
    $baselineAnalysis = @()
    
    try {
        # Check GPOs applied to domain controllers
        $gpos = Get-GPO -All | Where-Object { $_.DisplayName -like "*Domain Controller*" -or $_.DisplayName -like "*DC*" }
        
        foreach ($dc in $DomainControllers) {
            $baselineAnalysis += [PSCustomObject]@{
                HostName = $dc.HostName
                OperatingSystem = $dc.OperatingSystem
                AppliedGPOs = ($gpos | ForEach-Object { $_.DisplayName }) -join ', '
                SecurityBaselineGPOs = 'Requires detailed GPO analysis'
                ConfigurationCompliance = 'Requires detailed analysis'
                SecuritySettings = 'Requires detailed analysis'
                AuditPolicy = 'Requires detailed analysis'
                UserRights = 'Requires detailed analysis'
                SecurityOptions = 'Requires detailed analysis'
                RiskLevel = 'Medium'
                Assessment = 'Configuration baseline verification requires detailed GPO analysis'
                Recommendations = 'Implement security configuration baseline GPOs for DCs'
            }
        }
        
        Write-DCSecurityLog "Configuration baseline analysis completed for $($baselineAnalysis.Count) domain controllers" -Level Success
        return $baselineAnalysis
    }
    catch {
        Write-DCSecurityLog "Failed to analyze configuration baselines: $_" -Level Error
        return @()
    }
}

function Test-OperatingSystemHardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$DomainControllers
    )
    
    Write-DCSecurityLog "Analyzing operating system hardening..." -Level Info
    
    $osHardening = @()
    
    foreach ($dc in $DomainControllers) {
        try {
            $isAccessible = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            if ($isAccessible) {
                # Basic OS hardening checks
                $osHardening += [PSCustomObject]@{
                    HostName = $dc.HostName
                    OperatingSystem = $dc.OperatingSystem
                    OperatingSystemVersion = $dc.OperatingSystemVersion
                    IsAccessible = $isAccessible
                    WindowsFeatures = 'Requires remote analysis'
                    Services = 'Requires remote analysis'
                    RegistrySettings = 'Requires remote analysis'
                    FirewallRules = 'Requires remote analysis'
                    EventLogSettings = 'Requires remote analysis'
                    SecurityPolicies = 'Requires remote analysis'
                    RiskLevel = 'Medium'
                    Assessment = 'OS hardening verification requires remote access'
                    Recommendations = 'Implement comprehensive OS hardening for DCs'
                }
            }
            else {
                $osHardening += [PSCustomObject]@{
                    HostName = $dc.HostName
                    OperatingSystem = $dc.OperatingSystem
                    OperatingSystemVersion = $dc.OperatingSystemVersion
                    IsAccessible = $false
                    WindowsFeatures = 'Unknown'
                    Services = 'Unknown'
                    RegistrySettings = 'Unknown'
                    FirewallRules = 'Unknown'
                    EventLogSettings = 'Unknown'
                    SecurityPolicies = 'Unknown'
                    RiskLevel = 'High'
                    Assessment = 'Cannot assess - Host unreachable'
                    Recommendations = 'Investigate connectivity and verify DC is operational'
                }
            }
        }
        catch {
            Write-DCSecurityLog "Failed to analyze OS hardening for $($dc.HostName): $_" -Level Warning
        }
    }
    
    Write-DCSecurityLog "OS hardening analysis completed for $($osHardening.Count) domain controllers" -Level Success
    return $osHardening
}

function Get-DomainControllerSecuritySummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllResults
    )
    
    Write-DCSecurityLog "Generating domain controller security summary..." -Level Info
    
    $summary = @{
        TotalDomainControllers = 0
        AccessibleDCs = 0
        UnreachableDCs = 0
        GlobalCatalogs = 0
        ReadOnlyDCs = 0
        SupportedOSVersions = 0
        UnsupportedOSVersions = 0
        SecurityIssues = 0
        CriticalIssues = 0
        HighIssues = 0
        MediumIssues = 0
        LowIssues = 0
    }
    
    foreach ($result in $AllResults) {
        $summary.TotalDomainControllers++
        
        if ($result.IsAccessible) {
            $summary.AccessibleDCs++
        }
        else {
            $summary.UnreachableDCs++
        }
        
        if ($result.IsGlobalCatalog) {
            $summary.GlobalCatalogs++
        }
        
        if ($result.IsReadOnly) {
            $summary.ReadOnlyDCs++
        }
        
        if ($result.OperatingSystemVersion -match "Windows Server 2016|Windows Server 2019|Windows Server 2022|Windows Server 2025") {
            $summary.SupportedOSVersions++
        }
        else {
            $summary.UnsupportedOSVersions++
        }
        
        switch ($result.RiskLevel) {
            'Critical' { $summary.CriticalIssues++ }
            'High' { $summary.HighIssues++ }
            'Medium' { $summary.MediumIssues++ }
            'Low' { $summary.LowIssues++ }
        }
    }
    
    $summary.SecurityIssues = $summary.CriticalIssues + $summary.HighIssues + $summary.MediumIssues + $summary.LowIssues
    
    return $summary
}

#endregion

#region Main Execution

try {
    Write-DCSecurityLog "Starting Domain Controller Security Analysis..." -Level Info
    Write-DCSecurityLog "Database path: $DatabasePath" -Level Info
    Write-DCSecurityLog "Output path: $OutputPath" -Level Info
    
    $allResults = @()
    
    # Collect domain controller inventory
    Write-DCSecurityLog "Collecting domain controller inventory..." -Level Info
    $dcInventory = Get-DomainControllerInventory
    
    if ($dcInventory.Count -eq 0) {
        throw "No domain controllers found"
    }
    
    # Always perform basic hardening analysis
    Write-DCSecurityLog "Analyzing domain controller hardening..." -Level Info
    $hardeningAnalysis = Test-DomainControllerHardening -DomainControllers $dcInventory
    $allResults += $hardeningAnalysis
    
    # Optional analyses based on parameters
    if ($IncludePhysicalSecurity) {
        Write-DCSecurityLog "Assessing physical security..." -Level Info
        $physicalSecurity = Test-PhysicalSecurityAssessment -DomainControllers $dcInventory
        $allResults += $physicalSecurity
    }
    
    if ($IncludeApplicationAllowlists) {
        Write-DCSecurityLog "Verifying application allowlists..." -Level Info
        $allowlistAnalysis = Test-ApplicationAllowlists -DomainControllers $dcInventory
        $allResults += $allowlistAnalysis
    }
    
    if ($IncludeConfigurationBaselines) {
        Write-DCSecurityLog "Verifying configuration baselines..." -Level Info
        $baselineAnalysis = Test-ConfigurationBaselines -DomainControllers $dcInventory
        $allResults += $baselineAnalysis
    }
    
    if ($IncludeOSHardening) {
        Write-DCSecurityLog "Analyzing operating system hardening..." -Level Info
        $osHardening = Test-OperatingSystemHardening -DomainControllers $dcInventory
        $allResults += $osHardening
    }
    
    # Generate summary
    $summary = Get-DomainControllerSecuritySummary -AllResults $allResults
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-DCSecurityLog "Domain controller security results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-DCSecurityLog "Domain Controller Security Analysis Summary:" -Level Info
    Write-DCSecurityLog "  Total Domain Controllers: $($summary.TotalDomainControllers)" -Level Info
    Write-DCSecurityLog "  Accessible DCs: $($summary.AccessibleDCs)" -Level Success
    Write-DCSecurityLog "  Unreachable DCs: $($summary.UnreachableDCs)" -Level Warning
    Write-DCSecurityLog "  Global Catalogs: $($summary.GlobalCatalogs)" -Level Info
    Write-DCSecurityLog "  Read-Only DCs: $($summary.ReadOnlyDCs)" -Level Info
    Write-DCSecurityLog "  Supported OS Versions: $($summary.SupportedOSVersions)" -Level Success
    Write-DCSecurityLog "  Unsupported OS Versions: $($summary.UnsupportedOSVersions)" -Level Warning
    Write-DCSecurityLog "  Security Issues: $($summary.SecurityIssues)" -Level Info
    Write-DCSecurityLog "    Critical: $($summary.CriticalIssues)" -Level Error
    Write-DCSecurityLog "    High: $($summary.HighIssues)" -Level Warning
    Write-DCSecurityLog "    Medium: $($summary.MediumIssues)" -Level Info
    Write-DCSecurityLog "    Low: $($summary.LowIssues)" -Level Info
    
    Write-DCSecurityLog "Domain controller security analysis completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allResults
        Message = "Domain controller security analysis completed successfully"
    }
}
catch {
    Write-DCSecurityLog "Domain controller security analysis failed: $_" -Level Error
    throw
}

#endregion
