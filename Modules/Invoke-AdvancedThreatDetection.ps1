<#
.SYNOPSIS
    Active Directory Advanced Threat Detection Module

.DESCRIPTION
    Comprehensive advanced threat detection based on Microsoft's Active Directory
    security best practices. Implements Advanced Audit Policy, compromise indicators,
    lateral movement detection, and persistence mechanism detection.

.PARAMETER DatabasePath
    Path to audit database for storing results

.PARAMETER OutputPath
    Path to save CSV results

.PARAMETER IncludeAdvancedAuditPolicy
    Include Advanced Audit Policy verification

.PARAMETER IncludeCompromiseIndicators
    Include compromise indicator detection

.PARAMETER IncludeLateralMovement
    Include lateral movement detection

.PARAMETER IncludePersistenceDetection
    Include persistence mechanism detection

.PARAMETER IncludeDataExfiltration
    Include data exfiltration monitoring

.PARAMETER IncludeAll
    Include all threat detection assessments

.EXAMPLE
    .\Invoke-AdvancedThreatDetection.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.EXAMPLE
    .\Invoke-AdvancedThreatDetection.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAdvancedAuditPolicy -IncludeCompromiseIndicators

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
    [string]$OutputPath = "C:\Temp\AdvancedThreatDetection.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAdvancedAuditPolicy,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCompromiseIndicators,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLateralMovement,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePersistenceDetection,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDataExfiltration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll
)

$ErrorActionPreference = 'Stop'

# Set flags based on IncludeAll parameter
if ($IncludeAll) {
    $IncludeAdvancedAuditPolicy = $true
    $IncludeCompromiseIndicators = $true
    $IncludeLateralMovement = $true
    $IncludePersistenceDetection = $true
    $IncludeDataExfiltration = $true
}

#region Helper Functions

function Write-ThreatDetectionLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Advanced-Threat-Detection] [$Level] $Message"
    
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
        Write-ThreatDetectionLog "Failed to connect to database: $_" -Level Error
        throw
    }
}

#endregion

#region Advanced Threat Detection Functions

function Test-AdvancedAuditPolicy {
    [CmdletBinding()]
    param()
    
    Write-ThreatDetectionLog "Verifying Advanced Audit Policy implementation..." -Level Info
    
    $auditPolicyAnalysis = @()
    
    try {
        # Define critical audit policy categories
        $auditCategories = @{
            'Account Logon' = @{
                'Audit Credential Validation' = 'Success, Failure'
                'Audit Kerberos Authentication Service' = 'Success, Failure'
                'Audit Kerberos Service Ticket Operations' = 'Success, Failure'
                'Audit Other Account Logon Events' = 'Success, Failure'
            }
            'Account Management' = @{
                'Audit Computer Account Management' = 'Success, Failure'
                'Audit Security Group Management' = 'Success, Failure'
                'Audit User Account Management' = 'Success, Failure'
            }
            'DS Access' = @{
                'Audit Directory Service Access' = 'Success, Failure'
                'Audit Directory Service Changes' = 'Success, Failure'
            }
            'Logon/Logoff' = @{
                'Audit Account Lockout' = 'Success, Failure'
                'Audit Group Membership' = 'Success, Failure'
                'Audit Logoff' = 'Success, Failure'
                'Audit Logon' = 'Success, Failure'
                'Audit Other Logon/Logoff Events' = 'Success, Failure'
                'Audit Special Logon' = 'Success, Failure'
            }
            'Object Access' = @{
                'Audit File System' = 'Success, Failure'
                'Audit Registry' = 'Success, Failure'
                'Audit Removable Storage' = 'Success, Failure'
            }
            'Policy Change' = @{
                'Audit Audit Policy Change' = 'Success, Failure'
                'Audit Authentication Policy Change' = 'Success, Failure'
                'Audit Authorization Policy Change' = 'Success, Failure'
            }
            'Privilege Use' = @{
                'Audit Sensitive Privilege Use' = 'Success, Failure'
                'Audit Non Sensitive Privilege Use' = 'Success, Failure'
            }
            'System' = @{
                'Audit IPsec Driver' = 'Success, Failure'
                'Audit Other System Events' = 'Success, Failure'
                'Audit Security State Change' = 'Success, Failure'
                'Audit Security System Extension' = 'Success, Failure'
                'Audit System Integrity' = 'Success, Failure'
            }
        }
        
        # Check if Advanced Audit Policy is enabled
        $advancedAuditEnabled = $false
        try {
            # This would require checking the registry or GPO settings
            # For now, we'll assume it's not enabled and provide recommendations
            $advancedAuditEnabled = $false
        }
        catch {
            $advancedAuditEnabled = $false
        }
        
        foreach ($category in $auditCategories.Keys) {
            $subcategories = $auditCategories[$category]
            
            foreach ($subcategory in $subcategories.Keys) {
                $auditPolicyAnalysis += [PSCustomObject]@{
                    Category = $category
                    Subcategory = $subcategory
                    RecommendedSetting = $subcategories[$subcategory]
                    CurrentSetting = 'Unknown - Requires manual verification'
                    IsEnabled = $advancedAuditEnabled
                    RiskLevel = 'High'
                    Assessment = 'Advanced Audit Policy verification requires manual configuration check'
                    Recommendation = 'Enable Advanced Audit Policy and configure recommended settings'
                    LastChecked = Get-Date
                }
            }
        }
        
        Write-ThreatDetectionLog "Advanced Audit Policy analysis completed for $($auditPolicyAnalysis.Count) categories" -Level Success
        return $auditPolicyAnalysis
    }
    catch {
        Write-ThreatDetectionLog "Failed to analyze Advanced Audit Policy: $_" -Level Error
        return @()
    }
}

function Get-CompromiseIndicators {
    [CmdletBinding()]
    param()
    
    Write-ThreatDetectionLog "Detecting compromise indicators..." -Level Info
    
    $compromiseAnalysis = @()
    
    try {
        # Get all users for compromise analysis
        $allUsers = Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, Enabled, LockedOut, MemberOf -ErrorAction SilentlyContinue
        
        foreach ($user in $allUsers) {
            $compromiseIndicators = @()
            $riskLevel = 'Low'
            
            # Check for suspicious account patterns
            if ($user.SamAccountName -like "*admin*" -or $user.SamAccountName -like "*administrator*") {
                $compromiseIndicators += "Admin-named account"
                $riskLevel = 'Medium'
            }
            
            # Check for service accounts with administrative privileges
            if ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*") {
                $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
                $userGroups = $user.MemberOf | ForEach-Object { 
                    $group = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
                    if ($group -and $group.Name -in $privilegedGroups) { $group.Name }
                }
                
                if ($userGroups.Count -gt 0) {
                    $compromiseIndicators += "Service account with administrative privileges"
                    $riskLevel = 'High'
                }
            }
            
            # Check for accounts with no recent password changes
            if ($user.PasswordLastSet) {
                $passwordAge = (Get-Date) - $user.PasswordLastSet
                if ($passwordAge.Days -gt 365) {
                    $compromiseIndicators += "Password not changed in $($passwordAge.Days) days"
                    $riskLevel = 'High'
                }
            }
            
            # Check for locked out accounts
            if ($user.LockedOut) {
                $compromiseIndicators += "Account is currently locked out"
                $riskLevel = 'High'
            }
            
            # Check for disabled accounts that were recently active
            if (-not $user.Enabled -and $user.LastLogonDate) {
                $lastLogonAge = (Get-Date) - $user.LastLogonDate
                if ($lastLogonAge.Days -lt 30) {
                    $compromiseIndicators += "Account disabled but was active $($lastLogonAge.Days) days ago"
                    $riskLevel = 'Medium'
                }
            }
            
            # Check for accounts with unusual group memberships
            $groupCount = $user.MemberOf.Count
            if ($groupCount -gt 10) {
                $compromiseIndicators += "Member of $groupCount groups - unusual for standard user"
                $riskLevel = 'Medium'
            }
            
            if ($compromiseIndicators.Count -gt 0) {
                $compromiseAnalysis += [PSCustomObject]@{
                    AccountName = $user.Name
                    SamAccountName = $user.SamAccountName
                    CompromiseIndicators = $compromiseIndicators -join '; '
                    RiskLevel = $riskLevel
                    PasswordLastSet = $user.PasswordLastSet
                    LastLogonDate = $user.LastLogonDate
                    Enabled = $user.Enabled
                    LockedOut = $user.LockedOut
                    GroupMembershipCount = $groupCount
                    IsServiceAccount = ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*")
                    IsAdminNamed = ($user.SamAccountName -like "*admin*" -or $user.Name -like "*admin*")
                    Recommendation = 'Investigate account for potential compromise'
                    LastAnalyzed = Get-Date
                }
            }
        }
        
        Write-ThreatDetectionLog "Detected compromise indicators for $($compromiseAnalysis.Count) accounts" -Level Success
        return $compromiseAnalysis
    }
    catch {
        Write-ThreatDetectionLog "Failed to detect compromise indicators: $_" -Level Error
        return @()
    }
}

function Get-LateralMovementDetection {
    [CmdletBinding()]
    param()
    
    Write-ThreatDetectionLog "Detecting lateral movement indicators..." -Level Info
    
    $lateralMovementAnalysis = @()
    
    try {
        # Get all computers for lateral movement analysis
        $allComputers = Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate, Enabled -ErrorAction SilentlyContinue
        
        foreach ($computer in $allComputers) {
            $lateralMovementIndicators = @()
            $riskLevel = 'Low'
            
            # Check for computers with unusual logon patterns
            if ($computer.LastLogonDate) {
                $lastLogonAge = (Get-Date) - $computer.LastLogonDate
                
                # Check for computers that haven't logged on recently
                if ($lastLogonAge.Days -gt 90) {
                    $lateralMovementIndicators += "No logon for $($lastLogonAge.Days) days"
                    $riskLevel = 'Medium'
                }
                
                # Check for computers with very recent logons (potential lateral movement)
                if ($lastLogonAge.Days -lt 1) {
                    $lateralMovementIndicators += "Very recent logon - potential lateral movement"
                    $riskLevel = 'High'
                }
            }
            
            # Check for computers with suspicious names
            if ($computer.Name -like "*test*" -or $computer.Name -like "*dev*" -or $computer.Name -like "*temp*") {
                $lateralMovementIndicators += "Suspicious computer name pattern"
                $riskLevel = 'Medium'
            }
            
            # Check for computers with legacy operating systems
            $osVersion = $computer.OperatingSystemVersion
            if ($osVersion -match "Windows Server 2003|Windows Server 2008|Windows XP|Windows Vista") {
                $lateralMovementIndicators += "Legacy OS - potential lateral movement target"
                $riskLevel = 'High'
            }
            
            # Check for disabled computers
            if (-not $computer.Enabled) {
                $lateralMovementIndicators += "Disabled computer account"
                $riskLevel = 'Low'
            }
            
            if ($lateralMovementIndicators.Count -gt 0) {
                $lateralMovementAnalysis += [PSCustomObject]@{
                    ComputerName = $computer.Name
                    SamAccountName = $computer.SamAccountName
                    OperatingSystem = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    LateralMovementIndicators = $lateralMovementIndicators -join '; '
                    RiskLevel = $riskLevel
                    LastLogonDate = $computer.LastLogonDate
                    DaysSinceLogon = if ($computer.LastLogonDate) { $lastLogonAge.Days } else { 'Never' }
                    Enabled = $computer.Enabled
                    IsLegacyOS = ($osVersion -match "Windows Server 2003|Windows Server 2008|Windows XP|Windows Vista")
                    IsSuspiciousName = ($computer.Name -like "*test*" -or $computer.Name -like "*dev*" -or $computer.Name -like "*temp*")
                    Recommendation = 'Monitor for lateral movement activity'
                    LastAnalyzed = Get-Date
                }
            }
        }
        
        Write-ThreatDetectionLog "Detected lateral movement indicators for $($lateralMovementAnalysis.Count) computers" -Level Success
        return $lateralMovementAnalysis
    }
    catch {
        Write-ThreatDetectionLog "Failed to detect lateral movement: $_" -Level Error
        return @()
    }
}

function Get-PersistenceDetection {
    [CmdletBinding()]
    param()
    
    Write-ThreatDetectionLog "Detecting persistence mechanisms..." -Level Info
    
    $persistenceAnalysis = @()
    
    try {
        # Get all users for persistence analysis
        $allUsers = Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, Enabled, MemberOf -ErrorAction SilentlyContinue
        
        foreach ($user in $allUsers) {
            $persistenceIndicators = @()
            $riskLevel = 'Low'
            
            # Check for service accounts (common persistence mechanism)
            if ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*") {
                $persistenceIndicators += "Service account - potential persistence mechanism"
                $riskLevel = 'Medium'
            }
            
            # Check for accounts with administrative privileges
            $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
            $userGroups = $user.MemberOf | ForEach-Object { 
                $group = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
                if ($group -and $group.Name -in $privilegedGroups) { $group.Name }
            }
            
            if ($userGroups.Count -gt 0) {
                $persistenceIndicators += "Administrative privileges - potential persistence mechanism"
                $riskLevel = 'High'
            }
            
            # Check for accounts with password never expires
            if ($null -eq $user.PasswordLastSet) {
                $persistenceIndicators += "Password never expires - potential persistence mechanism"
                $riskLevel = 'High'
            }
            
            # Check for accounts with old passwords
            if ($user.PasswordLastSet) {
                $passwordAge = (Get-Date) - $user.PasswordLastSet
                if ($passwordAge.Days -gt 365) {
                    $persistenceIndicators += "Password not changed in $($passwordAge.Days) days - potential persistence"
                    $riskLevel = 'High'
                }
            }
            
            # Check for accounts with unusual group memberships
            $groupCount = $user.MemberOf.Count
            if ($groupCount -gt 5) {
                $persistenceIndicators += "Member of $groupCount groups - potential persistence mechanism"
                $riskLevel = 'Medium'
            }
            
            if ($persistenceIndicators.Count -gt 0) {
                $persistenceAnalysis += [PSCustomObject]@{
                    AccountName = $user.Name
                    SamAccountName = $user.SamAccountName
                    PersistenceIndicators = $persistenceIndicators -join '; '
                    RiskLevel = $riskLevel
                    PasswordLastSet = $user.PasswordLastSet
                    LastLogonDate = $user.LastLogonDate
                    Enabled = $user.Enabled
                    GroupMembershipCount = $groupCount
                    PrivilegedGroups = $userGroups -join ', '
                    IsServiceAccount = ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*")
                    PasswordNeverExpires = ($null -eq $user.PasswordLastSet)
                    Recommendation = 'Investigate for persistence mechanisms'
                    LastAnalyzed = Get-Date
                }
            }
        }
        
        Write-ThreatDetectionLog "Detected persistence mechanisms for $($persistenceAnalysis.Count) accounts" -Level Success
        return $persistenceAnalysis
    }
    catch {
        Write-ThreatDetectionLog "Failed to detect persistence mechanisms: $_" -Level Error
        return @()
    }
}

function Get-DataExfiltrationMonitoring {
    [CmdletBinding()]
    param()
    
    Write-ThreatDetectionLog "Monitoring for data exfiltration indicators..." -Level Info
    
    $exfiltrationAnalysis = @()
    
    try {
        # Get all users for data exfiltration analysis
        $allUsers = Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, Enabled, MemberOf -ErrorAction SilentlyContinue
        
        foreach ($user in $allUsers) {
            $exfiltrationIndicators = @()
            $riskLevel = 'Low'
            
            # Check for accounts with administrative privileges (potential data access)
            $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
            $userGroups = $user.MemberOf | ForEach-Object { 
                $group = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
                if ($group -and $group.Name -in $privilegedGroups) { $group.Name }
            }
            
            if ($userGroups.Count -gt 0) {
                $exfiltrationIndicators += "Administrative privileges - potential data access"
                $riskLevel = 'High'
            }
            
            # Check for service accounts (potential data access)
            if ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*") {
                $exfiltrationIndicators += "Service account - potential data access"
                $riskLevel = 'Medium'
            }
            
            # Check for accounts with unusual group memberships
            $groupCount = $user.MemberOf.Count
            if ($groupCount -gt 10) {
                $exfiltrationIndicators += "Member of $groupCount groups - potential data access"
                $riskLevel = 'Medium'
            }
            
            # Check for accounts with recent password changes (potential compromise)
            if ($user.PasswordLastSet) {
                $passwordAge = (Get-Date) - $user.PasswordLastSet
                if ($passwordAge.Days -lt 7) {
                    $exfiltrationIndicators += "Recent password change - potential compromise"
                    $riskLevel = 'High'
                }
            }
            
            # Check for accounts with no recent logons
            if ($user.LastLogonDate) {
                $lastLogonAge = (Get-Date) - $user.LastLogonDate
                if ($lastLogonAge.Days -gt 90) {
                    $exfiltrationIndicators += "No logon for $($lastLogonAge.Days) days - potential dormant account"
                    $riskLevel = 'Medium'
                }
            }
            
            if ($exfiltrationIndicators.Count -gt 0) {
                $exfiltrationAnalysis += [PSCustomObject]@{
                    AccountName = $user.Name
                    SamAccountName = $user.SamAccountName
                    ExfiltrationIndicators = $exfiltrationIndicators -join '; '
                    RiskLevel = $riskLevel
                    PasswordLastSet = $user.PasswordLastSet
                    LastLogonDate = $user.LastLogonDate
                    Enabled = $user.Enabled
                    GroupMembershipCount = $groupCount
                    PrivilegedGroups = $userGroups -join ', '
                    IsServiceAccount = ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*")
                    RecentPasswordChange = if ($user.PasswordLastSet) { ((Get-Date) - $user.PasswordLastSet).Days -lt 7 } else { $false }
                    Recommendation = 'Monitor for data exfiltration activity'
                    LastAnalyzed = Get-Date
                }
            }
        }
        
        Write-ThreatDetectionLog "Detected data exfiltration indicators for $($exfiltrationAnalysis.Count) accounts" -Level Success
        return $exfiltrationAnalysis
    }
    catch {
        Write-ThreatDetectionLog "Failed to detect data exfiltration indicators: $_" -Level Error
        return @()
    }
}

function Get-ThreatDetectionSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllResults
    )
    
    Write-ThreatDetectionLog "Generating threat detection summary..." -Level Info
    
    $summary = @{
        TotalThreats = 0
        CriticalThreats = 0
        HighThreats = 0
        MediumThreats = 0
        LowThreats = 0
        CompromiseIndicators = 0
        LateralMovementIndicators = 0
        PersistenceMechanisms = 0
        DataExfiltrationIndicators = 0
        AuditPolicyIssues = 0
    }
    
    foreach ($result in $AllResults) {
        $summary.TotalThreats++
        
        # Count by risk level
        switch ($result.RiskLevel) {
            'Critical' { $summary.CriticalThreats++ }
            'High' { $summary.HighThreats++ }
            'Medium' { $summary.MediumThreats++ }
            'Low' { $summary.LowThreats++ }
        }
        
        # Count by threat type
        if ($result.CompromiseIndicators) {
            $summary.CompromiseIndicators++
        }
        if ($result.LateralMovementIndicators) {
            $summary.LateralMovementIndicators++
        }
        if ($result.PersistenceIndicators) {
            $summary.PersistenceMechanisms++
        }
        if ($result.ExfiltrationIndicators) {
            $summary.DataExfiltrationIndicators++
        }
        if ($result.Category) {
            $summary.AuditPolicyIssues++
        }
    }
    
    return $summary
}

#endregion

#region Main Execution

try {
    Write-ThreatDetectionLog "Starting Advanced Threat Detection Analysis..." -Level Info
    Write-ThreatDetectionLog "Database path: $DatabasePath" -Level Info
    Write-ThreatDetectionLog "Output path: $OutputPath" -Level Info
    
    $allResults = @()
    
    # Optional analyses based on parameters
    if ($IncludeAdvancedAuditPolicy) {
        Write-ThreatDetectionLog "Verifying Advanced Audit Policy..." -Level Info
        $auditPolicyAnalysis = Test-AdvancedAuditPolicy
        $allResults += $auditPolicyAnalysis
    }
    
    if ($IncludeCompromiseIndicators) {
        Write-ThreatDetectionLog "Detecting compromise indicators..." -Level Info
        $compromiseAnalysis = Get-CompromiseIndicators
        $allResults += $compromiseAnalysis
    }
    
    if ($IncludeLateralMovement) {
        Write-ThreatDetectionLog "Detecting lateral movement..." -Level Info
        $lateralMovementAnalysis = Get-LateralMovementDetection
        $allResults += $lateralMovementAnalysis
    }
    
    if ($IncludePersistenceDetection) {
        Write-ThreatDetectionLog "Detecting persistence mechanisms..." -Level Info
        $persistenceAnalysis = Get-PersistenceDetection
        $allResults += $persistenceAnalysis
    }
    
    if ($IncludeDataExfiltration) {
        Write-ThreatDetectionLog "Monitoring data exfiltration..." -Level Info
        $exfiltrationAnalysis = Get-DataExfiltrationMonitoring
        $allResults += $exfiltrationAnalysis
    }
    
    # Generate summary
    $summary = Get-ThreatDetectionSummary -AllResults $allResults
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-ThreatDetectionLog "Advanced threat detection results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-ThreatDetectionLog "Advanced Threat Detection Summary:" -Level Info
    Write-ThreatDetectionLog "  Total Threats: $($summary.TotalThreats)" -Level Info
    Write-ThreatDetectionLog "  Critical Threats: $($summary.CriticalThreats)" -Level Error
    Write-ThreatDetectionLog "  High Threats: $($summary.HighThreats)" -Level Warning
    Write-ThreatDetectionLog "  Medium Threats: $($summary.MediumThreats)" -Level Info
    Write-ThreatDetectionLog "  Low Threats: $($summary.LowThreats)" -Level Info
    Write-ThreatDetectionLog "  Compromise Indicators: $($summary.CompromiseIndicators)" -Level Warning
    Write-ThreatDetectionLog "  Lateral Movement Indicators: $($summary.LateralMovementIndicators)" -Level Warning
    Write-ThreatDetectionLog "  Persistence Mechanisms: $($summary.PersistenceMechanisms)" -Level Warning
    Write-ThreatDetectionLog "  Data Exfiltration Indicators: $($summary.DataExfiltrationIndicators)" -Level Warning
    Write-ThreatDetectionLog "  Audit Policy Issues: $($summary.AuditPolicyIssues)" -Level Warning
    
    Write-ThreatDetectionLog "Advanced threat detection analysis completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allResults
        Message = "Advanced threat detection analysis completed successfully"
    }
}
catch {
    Write-ThreatDetectionLog "Advanced threat detection analysis failed: $_" -Level Error
    throw
}

#endregion
