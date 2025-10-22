<#
.SYNOPSIS
    Active Directory Least Privilege Assessment Module

.DESCRIPTION
    Comprehensive least privilege assessment based on Microsoft's Active Directory
    security best practices. Analyzes RBAC implementation, privilege escalation
    detection, and administrative model evaluation.

.PARAMETER DatabasePath
    Path to audit database for storing results

.PARAMETER OutputPath
    Path to save CSV results

.PARAMETER IncludeRBACAnalysis
    Include role-based access control analysis

.PARAMETER IncludePrivilegeEscalation
    Include privilege escalation detection

.PARAMETER IncludeAdministrativeModel
    Include administrative model evaluation

.PARAMETER IncludeCrossSystemPrivileges
    Include cross-system privilege analysis

.PARAMETER IncludeAll
    Include all privilege assessments

.EXAMPLE
    .\Invoke-LeastPrivilegeAssessment.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.EXAMPLE
    .\Invoke-LeastPrivilegeAssessment.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeRBACAnalysis -IncludePrivilegeEscalation

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
    [string]$OutputPath = "C:\Temp\LeastPrivilegeAssessment.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeRBACAnalysis,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePrivilegeEscalation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAdministrativeModel,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCrossSystemPrivileges,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll
)

$ErrorActionPreference = 'Stop'

# Set flags based on IncludeAll parameter
if ($IncludeAll) {
    $IncludeRBACAnalysis = $true
    $IncludePrivilegeEscalation = $true
    $IncludeAdministrativeModel = $true
    $IncludeCrossSystemPrivileges = $true
}

#region Helper Functions

function Write-LeastPrivilegeLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Least-Privilege-Assessment] [$Level] $Message"
    
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
        Write-LeastPrivilegeLog "Failed to connect to database: $_" -Level Error
        throw
    }
}

#endregion

#region Least Privilege Assessment Functions

function Test-RoleBasedAccessControl {
    [CmdletBinding()]
    param()
    
    Write-LeastPrivilegeLog "Analyzing role-based access control implementation..." -Level Info
    
    $rbacAnalysis = @()
    
    try {
        # Define standard RBAC roles
        $standardRoles = @{
            'Domain Admins' = 'Full domain administrative access'
            'Enterprise Admins' = 'Full forest administrative access'
            'Schema Admins' = 'Schema modification access'
            'Account Operators' = 'User and group management'
            'Backup Operators' = 'Backup and restore operations'
            'Server Operators' = 'Server management'
            'Print Operators' = 'Print server management'
            'DnsAdmins' = 'DNS server management'
            'Cert Publishers' = 'Certificate management'
            'Group Policy Creator Owners' = 'GPO creation and management'
        }
        
        # Analyze each role
        foreach ($roleName in $standardRoles.Keys) {
            try {
                $role = Get-ADGroup -Identity $roleName -ErrorAction SilentlyContinue
                if ($role) {
                    $members = Get-ADGroupMember -Identity $roleName -ErrorAction SilentlyContinue
                    
                    $rbacAnalysis += [PSCustomObject]@{
                        RoleName = $roleName
                        RoleDescription = $standardRoles[$roleName]
                        MemberCount = $members.Count
                        Members = ($members | ForEach-Object { $_.SamAccountName }) -join ', '
                        RoleSID = $role.SID.Value
                        IsBuiltIn = $true
                        RiskLevel = switch ($roleName) {
                            'Domain Admins' { 'Critical' }
                            'Enterprise Admins' { 'Critical' }
                            'Schema Admins' { 'Critical' }
                            default { 'High' }
                        }
                        RBACCompliance = if ($members.Count -eq 0) { 'Compliant - No members' } else { 'Non-Compliant - Has members' }
                        Recommendation = 'Implement least privilege - remove unnecessary members'
                        LastModified = $role.Modified
                    }
                }
            }
            catch {
                Write-LeastPrivilegeLog "Failed to analyze role $roleName`: $_" -Level Warning
            }
        }
        
        # Check for custom roles
        $customRoles = Get-ADGroup -Filter { Name -notlike "*$($standardRoles.Keys -join '*' -replace '\*', '*')*" } -ErrorAction SilentlyContinue
        
        foreach ($customRole in $customRoles) {
            $members = Get-ADGroupMember -Identity $customRole.SamAccountName -ErrorAction SilentlyContinue
            
            $rbacAnalysis += [PSCustomObject]@{
                RoleName = $customRole.Name
                RoleDescription = 'Custom role - requires review'
                MemberCount = $members.Count
                Members = ($members | ForEach-Object { $_.SamAccountName }) -join ', '
                RoleSID = $customRole.SID.Value
                IsBuiltIn = $false
                RiskLevel = 'Medium'
                RBACCompliance = 'Requires review'
                Recommendation = 'Review custom role necessity and member assignments'
                LastModified = $customRole.Modified
            }
        }
        
        Write-LeastPrivilegeLog "Analyzed $($rbacAnalysis.Count) roles for RBAC compliance" -Level Success
        return $rbacAnalysis
    }
    catch {
        Write-LeastPrivilegeLog "Failed to analyze RBAC: $_" -Level Error
        return @()
    }
}

function Test-PrivilegeEscalationDetection {
    [CmdletBinding()]
    param()
    
    Write-LeastPrivilegeLog "Detecting privilege escalation indicators..." -Level Info
    
    $escalationAnalysis = @()
    
    try {
        # Get all users with group memberships
        $allUsers = Get-ADUser -Filter * -Properties MemberOf -ErrorAction SilentlyContinue
        
        foreach ($user in $allUsers) {
            $escalationIndicators = @()
            $riskLevel = 'Low'
            
            # Check for multiple privileged group memberships
            $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
            $userPrivilegedGroups = $user.MemberOf | ForEach-Object { 
                $group = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
                if ($group -and $group.Name -in $privilegedGroups) { $group.Name }
            }
            
            if ($userPrivilegedGroups.Count -gt 1) {
                $escalationIndicators += "Member of multiple privileged groups: $($userPrivilegedGroups -join ', ')"
                $riskLevel = 'High'
            }
            
            # Check for nested group memberships that could lead to privilege escalation
            $nestedGroups = @()
            foreach ($groupDN in $user.MemberOf) {
                $group = Get-ADGroup -Identity $groupDN -ErrorAction SilentlyContinue
                if ($group) {
                    $parentGroups = Get-ADGroup -Filter { Members -eq $group.SID } -ErrorAction SilentlyContinue
                    foreach ($parentGroup in $parentGroups) {
                        if ($parentGroup.Name -in $privilegedGroups) {
                            $nestedGroups += "$($group.Name) -> $($parentGroup.Name)"
                        }
                    }
                }
            }
            
            if ($nestedGroups.Count -gt 0) {
                $escalationIndicators += "Nested group privilege escalation: $($nestedGroups -join '; ')"
                $riskLevel = 'Critical'
            }
            
            # Check for service accounts with administrative privileges
            if ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*") {
                if ($userPrivilegedGroups.Count -gt 0) {
                    $escalationIndicators += "Service account with administrative privileges"
                    $riskLevel = 'High'
                }
            }
            
            # Check for accounts with "Admin" in the name
            if ($user.SamAccountName -like "*admin*" -or $user.Name -like "*admin*") {
                if ($userPrivilegedGroups.Count -gt 0) {
                    $escalationIndicators += "Admin-named account with administrative privileges"
                    $riskLevel = 'Medium'
                }
            }
            
            if ($escalationIndicators.Count -gt 0) {
                $escalationAnalysis += [PSCustomObject]@{
                    AccountName = $user.Name
                    SamAccountName = $user.SamAccountName
                    EscalationIndicators = $escalationIndicators -join '; '
                    RiskLevel = $riskLevel
                    PrivilegedGroups = $userPrivilegedGroups -join ', '
                    NestedGroups = $nestedGroups -join '; '
                    IsServiceAccount = ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*")
                    IsAdminNamed = ($user.SamAccountName -like "*admin*" -or $user.Name -like "*admin*")
                    LastLogonDate = $user.LastLogonDate
                    Enabled = $user.Enabled
                    Recommendation = 'Review privilege assignments and implement least privilege'
                }
            }
        }
        
        Write-LeastPrivilegeLog "Detected privilege escalation indicators for $($escalationAnalysis.Count) accounts" -Level Success
        return $escalationAnalysis
    }
    catch {
        Write-LeastPrivilegeLog "Failed to detect privilege escalation: $_" -Level Error
        return @()
    }
}

function Test-AdministrativeModelEvaluation {
    [CmdletBinding()]
    param()
    
    Write-LeastPrivilegeLog "Evaluating administrative model..." -Level Info
    
    $adminModelAnalysis = @()
    
    try {
        # Analyze administrative model components
        $adminModelComponents = @{
            'Domain Controllers' = (Get-ADDomainController -Filter *).Count
            'Administrative Groups' = (Get-ADGroup -Filter { Name -like "*Admin*" }).Count
            'Service Accounts' = (Get-ADUser -Filter { SamAccountName -like "*service*" -or SamAccountName -like "*svc*" }).Count
            'Privileged Users' = 0
            'Custom Administrative Roles' = 0
        }
        
        # Count privileged users
        $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
        foreach ($groupName in $privilegedGroups) {
            $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
            if ($group) {
                $members = Get-ADGroupMember -Identity $groupName -ErrorAction SilentlyContinue
                $adminModelComponents['Privileged Users'] += $members.Count
            }
        }
        
        # Count custom administrative roles
        $customRoles = Get-ADGroup -Filter { Name -like "*Admin*" -and Name -notlike "Domain Admins" -and Name -notlike "Enterprise Admins" -and Name -notlike "Schema Admins" -and Name -notlike "Administrators" }
        $adminModelComponents['Custom Administrative Roles'] = $customRoles.Count
        
        # Evaluate administrative model
        $modelAssessment = switch ($adminModelComponents['Privileged Users']) {
            { $_ -eq 0 } { 'Excellent - No permanently privileged users' }
            { $_ -le 2 } { 'Good - Minimal privileged users' }
            { $_ -le 5 } { 'Fair - Moderate privileged users' }
            { $_ -le 10 } { 'Poor - Many privileged users' }
            default { 'Critical - Excessive privileged users' }
        }
        
        $riskLevel = switch ($adminModelComponents['Privileged Users']) {
            { $_ -eq 0 } { 'Low' }
            { $_ -le 2 } { 'Low' }
            { $_ -le 5 } { 'Medium' }
            { $_ -le 10 } { 'High' }
            default { 'Critical' }
        }
        
        $adminModelAnalysis += [PSCustomObject]@{
            Component = 'Administrative Model Overview'
            DomainControllers = $adminModelComponents['Domain Controllers']
            AdministrativeGroups = $adminModelComponents['Administrative Groups']
            ServiceAccounts = $adminModelComponents['Service Accounts']
            PrivilegedUsers = $adminModelComponents['Privileged Users']
            CustomAdministrativeRoles = $adminModelComponents['Custom Administrative Roles']
            ModelAssessment = $modelAssessment
            RiskLevel = $riskLevel
            Recommendation = 'Implement least privilege administrative model'
            LastAnalyzed = Get-Date
        }
        
        Write-LeastPrivilegeLog "Administrative model evaluation completed" -Level Success
        return $adminModelAnalysis
    }
    catch {
        Write-LeastPrivilegeLog "Failed to evaluate administrative model: $_" -Level Error
        return @()
    }
}

function Test-CrossSystemPrivilegeAnalysis {
    [CmdletBinding()]
    param()
    
    Write-LeastPrivilegeLog "Analyzing cross-system privileges..." -Level Info
    
    $crossSystemAnalysis = @()
    
    try {
        # Get all users with administrative privileges
        $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
        $privilegedUsers = @()
        
        foreach ($groupName in $privilegedGroups) {
            $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
            if ($group) {
                $members = Get-ADGroupMember -Identity $groupName -ErrorAction SilentlyContinue
                foreach ($member in $members) {
                    if ($member.ObjectClass -eq 'user') {
                        $privilegedUsers += $member.SamAccountName
                    }
                }
            }
        }
        
        # Analyze each privileged user
        foreach ($userSamAccount in ($privilegedUsers | Sort-Object -Unique)) {
            try {
                $user = Get-ADUser -Identity $userSamAccount -Properties MemberOf, Title, Department -ErrorAction SilentlyContinue
                
                if ($user) {
                    # Check for cross-system access patterns
                    $crossSystemIndicators = @()
                    $riskLevel = 'Low'
                    
                    # Check for multiple system access patterns
                    if ($user.Title -like "*Admin*" -or $user.Title -like "*Manager*") {
                        $crossSystemIndicators += "Administrative title suggests cross-system access"
                        $riskLevel = 'Medium'
                    }
                    
                    # Check for service account patterns
                    if ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*") {
                        $crossSystemIndicators += "Service account with administrative privileges"
                        $riskLevel = 'High'
                    }
                    
                    # Check for generic administrative accounts
                    if ($user.SamAccountName -like "*admin*" -or $user.SamAccountName -like "*administrator*") {
                        $crossSystemIndicators += "Generic administrative account"
                        $riskLevel = 'High'
                    }
                    
                    # Check for accounts with multiple group memberships
                    $groupCount = $user.MemberOf.Count
                    if ($groupCount -gt 5) {
                        $crossSystemIndicators += "Member of $groupCount groups - potential cross-system access"
                        $riskLevel = 'Medium'
                    }
                    
                    if ($crossSystemIndicators.Count -gt 0) {
                        $crossSystemAnalysis += [PSCustomObject]@{
                            AccountName = $user.Name
                            SamAccountName = $user.SamAccountName
                            Title = $user.Title
                            Department = $user.Department
                            CrossSystemIndicators = $crossSystemIndicators -join '; '
                            RiskLevel = $riskLevel
                            GroupMembershipCount = $groupCount
                            IsServiceAccount = ($user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*")
                            IsGenericAdmin = ($user.SamAccountName -like "*admin*" -or $user.SamAccountName -like "*administrator*")
                            LastLogonDate = $user.LastLogonDate
                            Enabled = $user.Enabled
                            Recommendation = 'Review cross-system access and implement least privilege'
                        }
                    }
                }
            }
            catch {
                Write-LeastPrivilegeLog "Failed to analyze cross-system privileges for $userSamAccount`: $_" -Level Warning
            }
        }
        
        Write-LeastPrivilegeLog "Cross-system privilege analysis completed for $($crossSystemAnalysis.Count) accounts" -Level Success
        return $crossSystemAnalysis
    }
    catch {
        Write-LeastPrivilegeLog "Failed to analyze cross-system privileges: $_" -Level Error
        return @()
    }
}

function Get-LeastPrivilegeComplianceScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllResults
    )
    
    Write-LeastPrivilegeLog "Calculating least privilege compliance score..." -Level Info
    
    $totalIssues = $AllResults.Count
    $criticalIssues = ($AllResults | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $highIssues = ($AllResults | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumIssues = ($AllResults | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    $lowIssues = ($AllResults | Where-Object { $_.RiskLevel -eq 'Low' }).Count
    
    # Calculate compliance score (100 - penalty points)
    $penaltyPoints = ($criticalIssues * 20) + ($highIssues * 10) + ($mediumIssues * 5) + ($lowIssues * 2)
    $complianceScore = [Math]::Max(0, 100 - $penaltyPoints)
    
    $complianceLevel = switch ($complianceScore) {
        { $_ -ge 90 } { 'Excellent' }
        { $_ -ge 80 } { 'Good' }
        { $_ -ge 70 } { 'Fair' }
        { $_ -ge 60 } { 'Poor' }
        default { 'Critical' }
    }
    
    return @{
        ComplianceScore = $complianceScore
        ComplianceLevel = $complianceLevel
        TotalIssues = $totalIssues
        CriticalIssues = $criticalIssues
        HighIssues = $highIssues
        MediumIssues = $mediumIssues
        LowIssues = $lowIssues
        PenaltyPoints = $penaltyPoints
    }
}

#endregion

#region Main Execution

try {
    Write-LeastPrivilegeLog "Starting Least Privilege Assessment..." -Level Info
    Write-LeastPrivilegeLog "Database path: $DatabasePath" -Level Info
    Write-LeastPrivilegeLog "Output path: $OutputPath" -Level Info
    
    $allResults = @()
    
    # Always perform RBAC analysis (core requirement)
    Write-LeastPrivilegeLog "Analyzing role-based access control..." -Level Info
    $rbacAnalysis = Test-RoleBasedAccessControl
    $allResults += $rbacAnalysis
    
    # Optional analyses based on parameters
    if ($IncludePrivilegeEscalation) {
        Write-LeastPrivilegeLog "Detecting privilege escalation..." -Level Info
        $escalationAnalysis = Test-PrivilegeEscalationDetection
        $allResults += $escalationAnalysis
    }
    
    if ($IncludeAdministrativeModel) {
        Write-LeastPrivilegeLog "Evaluating administrative model..." -Level Info
        $adminModelAnalysis = Test-AdministrativeModelEvaluation
        $allResults += $adminModelAnalysis
    }
    
    if ($IncludeCrossSystemPrivileges) {
        Write-LeastPrivilegeLog "Analyzing cross-system privileges..." -Level Info
        $crossSystemAnalysis = Test-CrossSystemPrivilegeAnalysis
        $allResults += $crossSystemAnalysis
    }
    
    # Calculate compliance score
    $complianceScore = Get-LeastPrivilegeComplianceScore -AllResults $allResults
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-LeastPrivilegeLog "Least privilege assessment results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-LeastPrivilegeLog "Least Privilege Assessment Summary:" -Level Info
    Write-LeastPrivilegeLog "  Compliance Score: $($complianceScore.ComplianceScore)/100 ($($complianceScore.ComplianceLevel))" -Level Info
    Write-LeastPrivilegeLog "  Total Issues: $($complianceScore.TotalIssues)" -Level Info
    Write-LeastPrivilegeLog "  Critical Issues: $($complianceScore.CriticalIssues)" -Level Error
    Write-LeastPrivilegeLog "  High Issues: $($complianceScore.HighIssues)" -Level Warning
    Write-LeastPrivilegeLog "  Medium Issues: $($complianceScore.MediumIssues)" -Level Info
    Write-LeastPrivilegeLog "  Low Issues: $($complianceScore.LowIssues)" -Level Info
    Write-LeastPrivilegeLog "  Penalty Points: $($complianceScore.PenaltyPoints)" -Level Info
    
    Write-LeastPrivilegeLog "Least privilege assessment completed successfully" -Level Success
    
    return @{
        Success = $true
        ComplianceScore = $complianceScore
        Results = $allResults
        Message = "Least privilege assessment completed successfully"
    }
}
catch {
    Write-LeastPrivilegeLog "Least privilege assessment failed: $_" -Level Error
    throw
}

#endregion
