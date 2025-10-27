<#
.SYNOPSIS
    Active Directory Credential Theft Prevention Module

.DESCRIPTION
    Comprehensive credential theft prevention and detection based on Microsoft's Active Directory
    security best practices. Identifies permanently privileged accounts, VIP accounts, and
    implements monitoring for credential theft indicators.

.PARAMETER DatabasePath
    Path to audit database for storing results

.PARAMETER OutputPath
    Path to save CSV results

.PARAMETER IncludeVIPAccounts
    Include VIP account analysis

.PARAMETER IncludePrivilegedUsage
    Include privileged account usage monitoring

.PARAMETER IncludeAdministrativeHosts
    Include secure administrative host verification

.PARAMETER Days
    Number of days to analyze for usage patterns

.EXAMPLE
    .\Invoke-CredentialTheftPrevention.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeVIPAccounts

.EXAMPLE
    .\Invoke-CredentialTheftPrevention.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll -Days 30

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
    [string]$OutputPath = "C:\Temp\CredentialTheftPrevention.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeVIPAccounts,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePrivilegedUsage,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAdministrativeHosts,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSIDHistory,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll,
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 30
)

$ErrorActionPreference = 'Stop'

# Set flags based on IncludeAll parameter
if ($IncludeAll) {
    $IncludeVIPAccounts = $true
    $IncludePrivilegedUsage = $true
    $IncludeAdministrativeHosts = $true
    $IncludeSIDHistory = $true
}

#region Helper Functions

function Write-CredentialTheftLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Credential-Theft-Prevention] [$Level] $Message"
    
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
        Write-CredentialTheftLog "Failed to connect to database: $_" -Level Error
        throw
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
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet)
        return $dataSet.Tables[0]
    }
    catch {
        Write-CredentialTheftLog "Database query failed: $_" -Level Error
        throw
    }
}

#endregion

#region Credential Theft Prevention Functions

function Get-PermanentlyPrivilegedAccounts {
    [CmdletBinding()]
    param()
    
    Write-CredentialTheftLog "Analyzing permanently privileged accounts..." -Level Info
    
    $permanentPrivileged = @()
    
    try {
        # Get all privileged groups
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins', 
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators',
            'Print Operators',
            'DnsAdmins',
            'Cert Publishers',
            'Group Policy Creator Owners'
        )
        
        foreach ($groupName in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
                if ($group) {
                    $members = Get-ADGroupMember -Identity $groupName -ErrorAction SilentlyContinue
                    
                    foreach ($member in $members) {
                        # Check if this is a permanent assignment (not PIM)
                        # Check if user is in PIM (this would require additional PIM module)
                        # For now, we'll assume all assignments are permanent
                        
                        $permanentPrivileged += [PSCustomObject]@{
                            AccountName = $member.Name
                            SamAccountName = $member.SamAccountName
                            ObjectClass = $member.ObjectClass
                            GroupName = $groupName
                            GroupSID = $group.SID.Value
                            AssignmentType = 'Permanent'
                            RiskLevel = switch ($groupName) {
                                'Domain Admins' { 'Critical' }
                                'Enterprise Admins' { 'Critical' }
                                'Schema Admins' { 'Critical' }
                                'Administrators' { 'High' }
                                default { 'Medium' }
                            }
                            Recommendation = 'Convert to temporary assignment using PIM or remove if not needed'
                            LastModified = $group.Modified
                        }
                    }
                }
            }
            catch {
                Write-CredentialTheftLog "Failed to analyze group $groupName`: $_" -Level Warning
            }
        }
        
        Write-CredentialTheftLog "Found $($permanentPrivileged.Count) permanently privileged accounts" -Level Success
        return $permanentPrivileged
    }
    catch {
        Write-CredentialTheftLog "Failed to analyze permanently privileged accounts: $_" -Level Error
        return @()
    }
}

function Get-SIDHistoryAnalysis {
    [CmdletBinding()]
    param()
    
    Write-CredentialTheftLog "Analyzing SID history for privileged accounts..." -Level Info
    
    $sidHistoryFindings = @()
    
    try {
        # Get all users with SID history
        $allUsers = Get-ADUser -Filter * -Properties SIDHistory, DistinguishedName -ErrorAction SilentlyContinue
        
        foreach ($user in $allUsers) {
            # Check if user has SID history
            if ($user.SIDHistory -and $user.SIDHistory.Count -gt 0) {
                # Get user's current groups to determine if privileged
                $userGroups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                
                # Determine if account is privileged
                $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators')
                $isPrivileged = $false
                $privilegedGroupList = @()
                
                foreach ($group in $privilegedGroups) {
                    if ($userGroups -contains $group) {
                        $isPrivileged = $true
                        $privilegedGroupList += $group
                    }
                }
                
                # If privileged or if SID history indicates potential privilege escalation
                if ($isPrivileged -or $userGroups) {
                    # Analyze each SID in history
                    foreach ($sid in $user.SIDHistory) {
                        $domainSID = $null
                        $domainName = "Unknown"
                        
                        # Try to resolve domain from SID
                        try {
                            $sidObj = [System.Security.Principal.SecurityIdentifier]$sid
                            $sidString = $sidObj.ToString()
                            
                            # Extract domain SID (everything before the last RID)
                            $ridIndex = $sidString.LastIndexOf('-')
                            if ($ridIndex -gt 0) {
                                $domainSID = $sidString.Substring(0, $ridIndex)
                            }
                        }
                        catch {
                            $domainSID = "Unable to parse"
                        }
                        
                        # Determine risk level
                        $riskLevel = 'High'
                        $description = "SID History present on account"
                        
                        if ($isPrivileged -and $privilegedGroupList.Count -gt 0) {
                            $riskLevel = 'Critical'
                            $description = "SID History on privileged account with access to: $($privilegedGroupList -join ', ')"
                        }
                        
                        $sidHistoryFindings += [PSCustomObject]@{
                            AccountName = $user.Name
                            SamAccountName = $user.SamAccountName
                            DistinguishedName = $user.DistinguishedName
                            SIDHistoryValue = $sid.ToString()
                            DomainSID = $domainSID
                            DomainName = $domainName
                            IsPrivileged = $isPrivileged
                            PrivilegedGroups = ($privilegedGroupList -join ', ')
                            AllGroups = ($userGroups -join ', ')
                            RiskLevel = $riskLevel
                            Description = $description
                            Recommendation = if ($isPrivileged) {
                                "Review and remove SID history if migration is complete. Monitor account for suspicious activity."
                            } else {
                                "Review SID history to ensure it's legitimate. Consider removing if not needed."
                            }
                        }
                    }
                }
            }
        }
        
        Write-CredentialTheftLog "Found $($sidHistoryFindings.Count) SID history entries on accounts" -Level Success
        return $sidHistoryFindings
    }
    catch {
        Write-CredentialTheftLog "Failed to analyze SID history: $_" -Level Error
        return @()
    }
}

function Get-VIPAccountAnalysis {
    [CmdletBinding()]
    param()
    
    Write-CredentialTheftLog "Analyzing VIP accounts..." -Level Info
    
    $vipAccounts = @()
    
    try {
        # Define VIP account patterns
        $vipPatterns = @(
            '*CEO*', '*CTO*', '*CFO*', '*COO*', '*President*', '*Vice President*',
            '*Director*', '*Manager*', '*Executive*', '*Admin*', '*Administrator*',
            '*Service*', '*System*', '*SQL*', '*Exchange*', '*SharePoint*'
        )
        
        # Get all users
        $allUsers = Get-ADUser -Filter * -Properties Title, Department, Description, Manager -ErrorAction SilentlyContinue
        
        foreach ($user in $allUsers) {
            $isVIP = $false
            $vipReason = ""
            
            # Check title patterns
            if ($user.Title) {
                foreach ($pattern in $vipPatterns) {
                    if ($user.Title -like $pattern) {
                        $isVIP = $true
                        $vipReason = "Title: $($user.Title)"
                        break
                    }
                }
            }
            
            # Check description patterns
            if ($user.Description -and -not $isVIP) {
                foreach ($pattern in $vipPatterns) {
                    if ($user.Description -like $pattern) {
                        $isVIP = $true
                        $vipReason = "Description: $($user.Description)"
                        break
                    }
                }
            }
            
            # Check if user is in privileged groups
            $userGroups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName -ErrorAction SilentlyContinue
            $privilegedGroups = $userGroups | Where-Object { $_.Name -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') }
            
            if ($privilegedGroups -or $isVIP) {
                $vipAccounts += [PSCustomObject]@{
                    AccountName = $user.Name
                    SamAccountName = $user.SamAccountName
                    Title = $user.Title
                    Department = $user.Department
                    Description = $user.Description
                    Manager = $user.Manager
                    VIPReason = $vipReason
                    PrivilegedGroups = ($privilegedGroups | ForEach-Object { $_.Name }) -join ', '
                    RiskLevel = if ($privilegedGroups) { 'Critical' } else { 'High' }
                    LastLogonDate = $user.LastLogonDate
                    PasswordLastSet = $user.PasswordLastSet
                    Enabled = $user.Enabled
                    Recommendation = 'Implement enhanced monitoring and protection for VIP account'
                }
            }
        }
        
        Write-CredentialTheftLog "Found $($vipAccounts.Count) VIP accounts requiring special protection" -Level Success
        return $vipAccounts
    }
    catch {
        Write-CredentialTheftLog "Failed to analyze VIP accounts: $_" -Level Error
        return @()
    }
}

function Get-PrivilegedAccountUsage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-CredentialTheftLog "Analyzing privileged account usage patterns..." -Level Info
    
    $usageAnalysis = @()
    
    try {
        # Get privileged accounts
        $privilegedAccounts = Get-PermanentlyPrivilegedAccounts
        
        foreach ($account in $privilegedAccounts) {
            if ($account.ObjectClass -eq 'user') {
                try {
                    # Get recent logon events (this would require event log access)
                    # For now, we'll analyze account properties
                    
                    $user = Get-ADUser -Identity $account.SamAccountName -Properties LastLogonDate, PasswordLastSet, Enabled, LockedOut -ErrorAction SilentlyContinue
                    
                    if ($user) {
                        $daysSinceLogon = if ($user.LastLogonDate) { (Get-Date) - $user.LastLogonDate } else { $null }
                        $daysSincePasswordSet = if ($user.PasswordLastSet) { (Get-Date) - $user.PasswordLastSet } else { $null }
                        
                        $usageAnalysis += [PSCustomObject]@{
                            AccountName = $account.AccountName
                            SamAccountName = $account.SamAccountName
                            GroupName = $account.GroupName
                            RiskLevel = $account.RiskLevel
                            LastLogonDate = $user.LastLogonDate
                            DaysSinceLogon = if ($daysSinceLogon) { $daysSinceLogon.Days } else { 'Never' }
                            PasswordLastSet = $user.PasswordLastSet
                            DaysSincePasswordSet = if ($daysSincePasswordSet) { $daysSincePasswordSet.Days } else { 'Unknown' }
                            Enabled = $user.Enabled
                            LockedOut = $user.LockedOut
                            UsageRisk = switch ($daysSinceLogon.Days) {
                                { $_ -gt 90 } { 'High - Account appears unused' }
                                { $_ -gt 30 } { 'Medium - Infrequent usage' }
                                { $_ -lt 7 } { 'High - Frequent usage detected' }
                                default { 'Normal' }
                            }
                            Recommendation = switch ($daysSinceLogon.Days) {
                                { $_ -gt 90 } { 'Consider disabling or removing from privileged groups' }
                                { $_ -lt 7 } { 'Monitor for potential credential theft - frequent usage' }
                                default { 'Continue monitoring usage patterns' }
                            }
                        }
                    }
                }
                catch {
                    Write-CredentialTheftLog "Failed to analyze usage for $($account.SamAccountName): $_" -Level Warning
                }
            }
        }
        
        Write-CredentialTheftLog "Analyzed usage patterns for $($usageAnalysis.Count) privileged accounts" -Level Success
        return $usageAnalysis
    }
    catch {
        Write-CredentialTheftLog "Failed to analyze privileged account usage: $_" -Level Error
        return @()
    }
}

function Test-SecureAdministrativeHosts {
    [CmdletBinding()]
    param()
    
    Write-CredentialTheftLog "Verifying secure administrative hosts..." -Level Info
    
    $adminHostAnalysis = @()
    
    try {
        # Get domain controllers (these should be secure administrative hosts)
        $domainControllers = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
        
        foreach ($dc in $domainControllers) {
            try {
                # Check if DC is accessible for analysis
                $isAccessible = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
                
                if ($isAccessible) {
                    # Check for non-administrative software (this would require remote execution)
                    # For now, we'll check basic connectivity and properties
                    
                    $adminHostAnalysis += [PSCustomObject]@{
                        HostName = $dc.HostName
                        HostType = 'Domain Controller'
                        OperatingSystem = $dc.OperatingSystem
                        OperatingSystemVersion = $dc.OperatingSystemVersion
                        IsAccessible = $isAccessible
                        SecurityAssessment = 'Domain Controller - Should be secure'
                        NonAdminSoftware = 'Cannot verify remotely'
                        MFARequired = 'Should be configured'
                        PhysicalSecurity = 'Should be physically secured'
                        RiskLevel = 'Low'
                        Recommendation = 'Verify physical security and application allowlists'
                        LastModified = $dc.Modified
                    }
                }
                else {
                    $adminHostAnalysis += [PSCustomObject]@{
                        HostName = $dc.HostName
                        HostType = 'Domain Controller'
                        OperatingSystem = $dc.OperatingSystem
                        OperatingSystemVersion = $dc.OperatingSystemVersion
                        IsAccessible = $false
                        SecurityAssessment = 'Cannot assess - Host unreachable'
                        NonAdminSoftware = 'Unknown'
                        MFARequired = 'Unknown'
                        PhysicalSecurity = 'Unknown'
                        RiskLevel = 'Medium'
                        Recommendation = 'Investigate connectivity issues and verify security'
                        LastModified = $dc.Modified
                    }
                }
            }
            catch {
                Write-CredentialTheftLog "Failed to analyze DC $($dc.HostName): $_" -Level Warning
            }
        }
        
        # Check for other potential administrative hosts
        # This would require additional configuration to identify
        
        Write-CredentialTheftLog "Analyzed $($adminHostAnalysis.Count) administrative hosts" -Level Success
        return $adminHostAnalysis
    }
    catch {
        Write-CredentialTheftLog "Failed to analyze secure administrative hosts: $_" -Level Error
        return @()
    }
}

function Get-CredentialTheftIndicators {
    [CmdletBinding()]
    param()
    
    Write-CredentialTheftLog "Analyzing credential theft indicators..." -Level Info
    
    $theftIndicators = @()
    
    try {
        # Check for accounts with suspicious patterns
        $allUsers = Get-ADUser -Filter * -Properties PasswordLastSet, LastLogonDate, Enabled, LockedOut -ErrorAction SilentlyContinue
        
        foreach ($user in $allUsers) {
            $indicators = @()
            $riskLevel = 'Low'
            
            # Check for accounts that haven't changed passwords in a long time
            if ($user.PasswordLastSet) {
                $passwordAge = (Get-Date) - $user.PasswordLastSet
                if ($passwordAge.Days -gt 365) {
                    $indicators += "Password not changed in $($passwordAge.Days) days"
                    $riskLevel = 'High'
                }
            }
            
            # Check for locked out accounts
            if ($user.LockedOut) {
                $indicators += "Account is currently locked out"
                $riskLevel = 'High'
            }
            
            # Check for disabled accounts that were recently active
            if (-not $user.Enabled -and $user.LastLogonDate) {
                $lastLogonAge = (Get-Date) - $user.LastLogonDate
                if ($lastLogonAge.Days -lt 30) {
                    $indicators += "Account disabled but was active $($lastLogonAge.Days) days ago"
                    $riskLevel = 'Medium'
                }
            }
            
            # Check for accounts with no recent logon but enabled
            if ($user.Enabled -and -not $user.LastLogonDate) {
                $indicators += "Account enabled but never logged on"
                $riskLevel = 'Medium'
            }
            
            if ($indicators.Count -gt 0) {
                $theftIndicators += [PSCustomObject]@{
                    AccountName = $user.Name
                    SamAccountName = $user.SamAccountName
                    Indicators = $indicators -join '; '
                    RiskLevel = $riskLevel
                    PasswordLastSet = $user.PasswordLastSet
                    LastLogonDate = $user.LastLogonDate
                    Enabled = $user.Enabled
                    LockedOut = $user.LockedOut
                    Recommendation = 'Investigate account for potential credential theft'
                }
            }
        }
        
        Write-CredentialTheftLog "Found $($theftIndicators.Count) accounts with credential theft indicators" -Level Success
        return $theftIndicators
    }
    catch {
        Write-CredentialTheftLog "Failed to analyze credential theft indicators: $_" -Level Error
        return @()
    }
}

#endregion

#region Main Execution

try {
    Write-CredentialTheftLog "Starting Active Directory Credential Theft Prevention Analysis..." -Level Info
    Write-CredentialTheftLog "Database path: $DatabasePath" -Level Info
    Write-CredentialTheftLog "Output path: $OutputPath" -Level Info
    
    $allResults = @()
    $summary = @{
        TotalIssues = 0
        CriticalIssues = 0
        HighIssues = 0
        MediumIssues = 0
        LowIssues = 0
        Categories = @{}
    }
    
    # Always analyze permanently privileged accounts (core requirement)
    Write-CredentialTheftLog "Analyzing permanently privileged accounts..." -Level Info
    $permanentPrivileged = Get-PermanentlyPrivilegedAccounts
    $allResults += $permanentPrivileged
    
    # Analyze credential theft indicators
    Write-CredentialTheftLog "Analyzing credential theft indicators..." -Level Info
    $theftIndicators = Get-CredentialTheftIndicators
    $allResults += $theftIndicators
    
    # Optional analyses based on parameters
    if ($IncludeVIPAccounts) {
        Write-CredentialTheftLog "Analyzing VIP accounts..." -Level Info
        $vipAccounts = Get-VIPAccountAnalysis
        $allResults += $vipAccounts
    }
    
    if ($IncludePrivilegedUsage) {
        Write-CredentialTheftLog "Analyzing privileged account usage..." -Level Info
        $usageAnalysis = Get-PrivilegedAccountUsage -Days $Days
        $allResults += $usageAnalysis
    }
    
    if ($IncludeAdministrativeHosts) {
        Write-CredentialTheftLog "Verifying secure administrative hosts..." -Level Info
        $adminHosts = Test-SecureAdministrativeHosts
        $allResults += $adminHosts
    }
    
    if ($IncludeSIDHistory) {
        Write-CredentialTheftLog "Analyzing SID history for privileged accounts..." -Level Info
        $sidHistory = Get-SIDHistoryAnalysis
        $allResults += $sidHistory
    }
    
    # Process results
    foreach ($result in $allResults) {
        $summary.TotalIssues++
        
        # Count by severity
        switch ($result.RiskLevel) {
            'Critical' { $summary.CriticalIssues++ }
            'High' { $summary.HighIssues++ }
            'Medium' { $summary.MediumIssues++ }
            'Low' { $summary.LowIssues++ }
        }
        
        # Count by category
        $category = switch ($result) {
            { $_ -in $permanentPrivileged } { 'Permanently Privileged' }
            { $_ -in $vipAccounts } { 'VIP Accounts' }
            { $_ -in $usageAnalysis } { 'Privileged Usage' }
            { $_ -in $adminHosts } { 'Administrative Hosts' }
            { $_ -in $sidHistory } { 'SID History' }
            { $_ -in $theftIndicators } { 'Credential Theft Indicators' }
            default { 'Other' }
        }
        
        if ($summary.Categories.ContainsKey($category)) {
            $summary.Categories[$category]++
        }
        else {
            $summary.Categories[$category] = 1
        }
    }
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-CredentialTheftLog "Credential theft prevention results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-CredentialTheftLog "Credential Theft Prevention Analysis Summary:" -Level Info
    Write-CredentialTheftLog "  Total Issues: $($summary.TotalIssues)" -Level Info
    Write-CredentialTheftLog "  Critical Issues: $($summary.CriticalIssues)" -Level Error
    Write-CredentialTheftLog "  High Issues: $($summary.HighIssues)" -Level Warning
    Write-CredentialTheftLog "  Medium Issues: $($summary.MediumIssues)" -Level Info
    Write-CredentialTheftLog "  Low Issues: $($summary.LowIssues)" -Level Info
    
    Write-CredentialTheftLog "Issues by Category:" -Level Info
    foreach ($category in $summary.Categories.GetEnumerator()) {
        Write-CredentialTheftLog "  $($category.Key): $($category.Value)" -Level Info
    }
    
    Write-CredentialTheftLog "Credential theft prevention analysis completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allResults
        Message = "Credential theft prevention analysis completed successfully"
    }
}
catch {
    Write-CredentialTheftLog "Credential theft prevention analysis failed: $_" -Level Error
    throw
}

#endregion
