<#
.SYNOPSIS
    Active Directory Remediation Scripts for Common Security Issues

.DESCRIPTION
    Provides automated remediation for common AD security issues identified during audits:
    - Stale user and computer accounts
    - Privileged account cleanup
    - Service account password rotation
    - Kerberos delegation remediation
    - ACL permission cleanup
    - Password policy enforcement
    - Group hygiene (empty groups, nested groups)

.PARAMETER RemediationType
    Type of remediation to perform (StaleAccounts, PrivilegedAccounts, ServiceAccounts, KerberosDelegation, ACLIssues, PasswordPolicy, GroupHygiene, All)

.PARAMETER DatabasePath
    Path to audit database for issue identification

.PARAMETER DryRun
    Show what would be remediated without making changes

.PARAMETER Credential
    AD credentials for remediation operations

.PARAMETER LogPath
    Path to save remediation log

.EXAMPLE
    .\Invoke-ADRemediation.ps1 -RemediationType "StaleAccounts" -DatabasePath "C:\Audits\AuditData.db" -DryRun

.EXAMPLE
    .\Invoke-ADRemediation.ps1 -RemediationType "All" -DatabasePath "C:\Audits\AuditData.db" -Credential $cred

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Requires: ActiveDirectory module, domain admin rights
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('StaleAccounts', 'PrivilegedAccounts', 'ServiceAccounts', 'KerberosDelegation', 'ACLIssues', 'PasswordPolicy', 'GroupHygiene', 'All')]
    [string]$RemediationType,
    
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Temp\ADRemediation.log"
)

$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-RemediationLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Action')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [AD-Remediation] [$Level] $Message"
    
    # Write to console
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Action'  { Write-Host $logMessage -ForegroundColor Cyan }
        default   { Write-Verbose $logMessage }
    }
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
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
        Write-RemediationLog "Failed to connect to database: $_" -Level Error
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
        Write-RemediationLog "Database query failed: $_" -Level Error
        throw
    }
}

#endregion

#region Stale Account Remediation

function Remove-StaleAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting stale account remediation..." -Level Info
    
    try {
        # Get stale users (90+ days inactive)
        $staleUsers = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT SamAccountName, DisplayName, LastLogonDate, DaysSinceLastLogon, Enabled, DistinguishedName
FROM Users 
WHERE DaysSinceLastLogon > 90 AND Enabled = 1
ORDER BY DaysSinceLastLogon DESC
"@
        
        # Get stale computers (90+ days inactive)
        $staleComputers = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT Name, DNSHostName, LastLogonDate, DaysSinceLastLogon, Enabled, DistinguishedName
FROM Computers 
WHERE DaysSinceLastLogon > 90 AND Enabled = 1 AND IsServer = 0
ORDER BY DaysSinceLastLogon DESC
"@
        
        $actions = @()
        
        # Process stale users
        ForEach-Object -InputObject $staleUsers.Rows -Process {
            $user = $_
            $action = [PSCustomObject]@{
                Type = "User"
                Name = $user.SamAccountName
                DisplayName = $user.DisplayName
                LastLogon = $user.LastLogonDate
                DaysInactive = $user.DaysSinceLastLogon
                Action = "Disable"
                DistinguishedName = $user.DistinguishedName
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    Set-ADUser -Identity $user.SamAccountName -Enabled $false -ErrorAction Stop
                    Write-RemediationLog "Disabled stale user: $($user.SamAccountName) ($($user.DaysSinceLastLogon) days inactive)" -Level Action
                }
                catch {
                    Write-RemediationLog "Failed to disable user $($user.SamAccountName): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would disable user $($user.SamAccountName) ($($user.DaysSinceLastLogon) days inactive)" -Level Action
            }
        }
        
        # Process stale computers
        ForEach-Object -InputObject $staleComputers.Rows -Process {
            $computer = $_
            $action = [PSCustomObject]@{
                Type = "Computer"
                Name = $computer.Name
                DNSHostName = $computer.DNSHostName
                LastLogon = $computer.LastLogonDate
                DaysInactive = $computer.DaysSinceLastLogon
                Action = "Disable"
                DistinguishedName = $computer.DistinguishedName
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    Set-ADComputer -Identity $computer.Name -Enabled $false -ErrorAction Stop
                    Write-RemediationLog "Disabled stale computer: $($computer.Name) ($($computer.DaysSinceLastLogon) days inactive)" -Level Action
                }
                catch {
                    Write-RemediationLog "Failed to disable computer $($computer.Name): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would disable computer $($computer.Name) ($($computer.DaysSinceLastLogon) days inactive)" -Level Action
            }
        }
        
        Write-RemediationLog "Stale account remediation complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Stale account remediation failed: $_" -Level Error
        throw
    }
}

#endregion

#region Privileged Account Remediation

function Remove-StalePrivilegedAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting stale privileged account remediation..." -Level Info
    
    try {
        # Get stale privileged accounts
        $stalePrivileged = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT DISTINCT 
    pa.MemberSamAccountName,
    pa.GroupName,
    u.DisplayName,
    u.LastLogonDate,
    u.DaysSinceLastLogon,
    u.Enabled,
    pa.DistinguishedName
FROM PrivilegedAccounts pa
LEFT JOIN Users u ON pa.MemberSamAccountName = u.SamAccountName
WHERE (u.DaysSinceLastLogon > 90 OR u.Enabled = 0) 
    AND pa.GroupName IN ('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
ORDER BY u.DaysSinceLastLogon DESC
"@
        
        $actions = @()
        
        ForEach-Object -InputObject $stalePrivileged.Rows -Process {
            $account = $_
            $action = [PSCustomObject]@{
                Account = $account.MemberSamAccountName
                Group = $account.GroupName
                DisplayName = $account.DisplayName
                LastLogon = $account.LastLogonDate
                DaysInactive = $account.DaysSinceLastLogon
                Enabled = $account.Enabled
                Action = "Remove from privileged group"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    Remove-ADGroupMember -Identity $account.GroupName -Members $account.MemberSamAccountName -Confirm:$false -ErrorAction Stop
                    Write-RemediationLog "Removed stale account from privileged group: $($account.MemberSamAccountName) from $($account.GroupName)" -Level Action
                }
                catch {
                    Write-RemediationLog "Failed to remove $($account.MemberSamAccountName) from $($account.GroupName): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would remove $($account.MemberSamAccountName) from $($account.GroupName)" -Level Action
            }
        }
        
        Write-RemediationLog "Stale privileged account remediation complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Stale privileged account remediation failed: $_" -Level Error
        throw
    }
}

#endregion

#region Service Account Remediation

function Update-ServiceAccountPasswords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting service account password remediation..." -Level Info
    
    try {
        # Get service accounts with password issues
        $serviceAccounts = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    SAMAccountName,
    Name,
    PasswordLastSet,
    PasswordAgeDays,
    PasswordNeverExpires,
    SecurityRisk,
    DistinguishedName
FROM AD_Service_Accounts
WHERE PasswordAgeDays > 365 OR PasswordNeverExpires = 1
ORDER BY PasswordAgeDays DESC
"@
        
        $actions = @()
        
        ForEach-Object -InputObject $serviceAccounts.Rows -Process {
            $account = $_
            $action = [PSCustomObject]@{
                Account = $account.SAMAccountName
                Name = $account.Name
                PasswordAge = $account.PasswordAgeDays
                NeverExpires = $account.PasswordNeverExpires
                SecurityRisk = $account.SecurityRisk
                Action = "Update password policy"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    # Set password to expire (if it was set to never expire)
                    if ($account.PasswordNeverExpires -eq 1) {
                        Set-ADUser -Identity $account.SAMAccountName -PasswordNeverExpires $false -ErrorAction Stop
                        Write-RemediationLog "Enabled password expiration for service account: $($account.SAMAccountName)" -Level Action
                    }
                    
                    # Generate new password
                    $newPassword = -join ((1..16) | ForEach-Object {Get-Random -InputObject ([char[]]([char]'A'..[char]'Z') + [char[]]([char]'a'..[char]'z') + [char[]]([char]'0'..[char]'9') + [char[]]'!@#$%^&*')})
                    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                    
                    Set-ADAccountPassword -Identity $account.SAMAccountName -NewPassword $securePassword -ErrorAction Stop
                    Write-RemediationLog "Updated password for service account: $($account.SAMAccountName)" -Level Action
                    
                    # Log password to secure file (for service restart)
                    $passwordLog = Join-Path (Split-Path $LogPath) "ServiceAccountPasswords.txt"
                    Add-Content -Path $passwordLog -Value "$($account.SAMAccountName):$newPassword" -ErrorAction SilentlyContinue
                }
                catch {
                    Write-RemediationLog "Failed to update service account $($account.SAMAccountName): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would update password for service account $($account.SAMAccountName)" -Level Action
            }
        }
        
        Write-RemediationLog "Service account password remediation complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Service account password remediation failed: $_" -Level Error
        throw
    }
}

#endregion

#region Kerberos Delegation Remediation

function Remove-UnconstrainedKerberosDelegation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting Kerberos delegation remediation..." -Level Info
    
    try {
        # Get accounts with unconstrained delegation
        $delegationAccounts = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    Name,
    SAMAccountName,
    ObjectType,
    DelegationType,
    Severity,
    DistinguishedName
FROM AD_Kerberos_Delegation
WHERE Severity = 'Critical' AND DelegationType = 'Unconstrained'
ORDER BY ObjectType, Name
"@
        
        $actions = @()
        
        ForEach-Object -InputObject $delegationAccounts.Rows -Process {
            $account = $_
            $action = [PSCustomObject]@{
                Account = $account.SAMAccountName
                Name = $account.Name
                ObjectType = $account.ObjectType
                DelegationType = $account.DelegationType
                Severity = $account.Severity
                Action = "Remove unconstrained delegation"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    if ($account.ObjectType -eq "Computer") {
                        Set-ADComputer -Identity $account.SAMAccountName -TrustedForDelegation $false -ErrorAction Stop
                        Write-RemediationLog "Removed unconstrained delegation from computer: $($account.SAMAccountName)" -Level Action
                    }
                    elseif ($account.ObjectType -eq "User") {
                        Set-ADUser -Identity $account.SAMAccountName -TrustedForDelegation $false -ErrorAction Stop
                        Write-RemediationLog "Removed unconstrained delegation from user: $($account.SAMAccountName)" -Level Action
                    }
                }
                catch {
                    Write-RemediationLog "Failed to remove delegation from $($account.SAMAccountName): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would remove unconstrained delegation from $($account.SAMAccountName)" -Level Action
            }
        }
        
        Write-RemediationLog "Kerberos delegation remediation complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Kerberos delegation remediation failed: $_" -Level Error
        throw
    }
}

#endregion

#region ACL Remediation

function Repair-DangerousACLPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting ACL remediation..." -Level Info
    
    try {
        # Get dangerous ACL issues
        $aclIssues = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    Path,
    Identity,
    Rights,
    AccessControlType,
    IsInherited,
    Reason,
    Severity
FROM AD_ACL_Issues
WHERE Severity IN ('Critical', 'High')
ORDER BY Severity DESC, Path
"@
        
        $actions = @()
        
        ForEach-Object -InputObject $aclIssues.Rows -Process {
            $issue = $_
            $action = [PSCustomObject]@{
                Path = $issue.Path
                Identity = $issue.Identity
                Rights = $issue.Rights
                AccessControlType = $issue.AccessControlType
                IsInherited = $issue.IsInherited
                Reason = $issue.Reason
                Severity = $issue.Severity
                Action = "Review and remove dangerous permission"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    # This is a complex operation that requires careful review
                    # For now, we'll log the issue for manual review
                    Write-RemediationLog "CRITICAL ACL ISSUE REQUIRES MANUAL REVIEW: $($issue.Path) - $($issue.Identity) has $($issue.Rights)" -Level Warning
                    Write-RemediationLog "Reason: $($issue.Reason)" -Level Warning
                }
                catch {
                    Write-RemediationLog "Failed to process ACL issue for $($issue.Path): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would review ACL issue: $($issue.Path) - $($issue.Identity)" -Level Action
            }
        }
        
        Write-RemediationLog "ACL remediation review complete: $($actions.Count) issues require manual review" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "ACL remediation failed: $_" -Level Error
        throw
    }
}

#endregion

#region Password Policy Remediation

function Set-PasswordPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting password policy enforcement..." -Level Info
    
    try {
        # Get current password policy
        $passwordPolicy = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    PolicyType,
    ComplexityEnabled,
    MinPasswordLength,
    MaxPasswordAge,
    MinPasswordAge,
    PasswordHistoryCount,
    SecurityAssessment
FROM AD_Password_Policy_Default
LIMIT 1
"@
        
        $actions = @()
        
        if ($passwordPolicy.Rows.Count -gt 0) {
            $policy = $passwordPolicy.Rows[0]
            
            # Check if policy needs strengthening
            $needsUpdate = $false
            $updates = @()
            
            if ($policy.MinPasswordLength -lt 12) {
                $needsUpdate = $true
                $updates += "MinPasswordLength: $($policy.MinPasswordLength) -> 12"
            }
            
            if ($policy.ComplexityEnabled -eq 0) {
                $needsUpdate = $true
                $updates += "ComplexityEnabled: False -> True"
            }
            
            if ($policy.MaxPasswordAge -gt 90) {
                $needsUpdate = $true
                $updates += "MaxPasswordAge: $($policy.MaxPasswordAge) -> 90"
            }
            
            if ($needsUpdate) {
                $action = [PSCustomObject]@{
                    PolicyType = $policy.PolicyType
                    CurrentSettings = "Length: $($policy.MinPasswordLength), Complex: $($policy.ComplexityEnabled), MaxAge: $($policy.MaxPasswordAge)"
                    RecommendedUpdates = ($updates -join "; ")
                    Action = "Update password policy"
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        # Update password policy
                        Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 12 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -ErrorAction Stop
                        Write-RemediationLog "Updated password policy: $($updates -join ', ')" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to update password policy: $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would update password policy: $($updates -join ', ')" -Level Action
                }
            }
            else {
                Write-RemediationLog "Password policy is already compliant" -Level Success
            }
        }
        
        Write-RemediationLog "Password policy enforcement complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Password policy enforcement failed: $_" -Level Error
        throw
    }
}

#endregion

#region Group Hygiene Remediation

function Remove-EmptyGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting group hygiene remediation..." -Level Info
    
    try {
        # Get empty groups
        $emptyGroups = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    Name,
    GroupScope,
    GroupCategory,
    Description,
    MemberCount,
    DistinguishedName
FROM AD_Groups
WHERE MemberCount = 0
ORDER BY GroupScope, Name
"@
        
        $actions = @()
        
        ForEach-Object -InputObject $emptyGroups.Rows -Process {
            $group = $_
            # Skip built-in groups
            $builtInGroups = @('Domain Users', 'Domain Computers', 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Users', 'Guests')
            
            if ($group.Name -notin $builtInGroups) {
                $action = [PSCustomObject]@{
                    GroupName = $group.Name
                    GroupScope = $group.GroupScope
                    GroupCategory = $group.GroupCategory
                    Description = $group.Description
                    MemberCount = $group.MemberCount
                    Action = "Delete empty group"
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        Remove-ADGroup -Identity $group.Name -Confirm:$false -ErrorAction Stop
                        Write-RemediationLog "Deleted empty group: $($group.Name)" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to delete group $($group.Name): $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would delete empty group: $($group.Name)" -Level Action
                }
            }
        }
        
        Write-RemediationLog "Group hygiene remediation complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Group hygiene remediation failed: $_" -Level Error
        throw
    }
}

#endregion

#region Main Execution

try {
    Write-RemediationLog "Starting AD remediation process..." -Level Info
    Write-RemediationLog "Remediation Type: $RemediationType" -Level Info
    Write-RemediationLog "Database Path: $DatabasePath" -Level Info
    Write-RemediationLog "Dry Run: $DryRun" -Level Info
    Write-RemediationLog "Log Path: $LogPath" -Level Info
    
    # Import ActiveDirectory module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-RemediationLog "ActiveDirectory module imported successfully" -Level Success
    }
    catch {
        throw "Failed to import ActiveDirectory module: $_. Install RSAT tools."
    }
    
    # Connect to database
    $connection = Get-DatabaseConnection -DatabasePath $DatabasePath
    Write-RemediationLog "Connected to audit database" -Level Success
    
    $allActions = @()
    
    # Execute remediation based on type
    switch ($RemediationType) {
        'StaleAccounts' {
            $actions = Remove-StaleAccounts -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'PrivilegedAccounts' {
            $actions = Remove-StalePrivilegedAccounts -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'ServiceAccounts' {
            $actions = Update-ServiceAccountPasswords -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'KerberosDelegation' {
            $actions = Remove-UnconstrainedKerberosDelegation -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'ACLIssues' {
            $actions = Fix-DangerousACLPermissions -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'PasswordPolicy' {
            $actions = Enforce-PasswordPolicy -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'GroupHygiene' {
            $actions = Clean-EmptyGroups -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'All' {
            Write-RemediationLog "Executing all remediation types..." -Level Info
            
            $actions = Remove-StaleAccounts -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Remove-StalePrivilegedAccounts -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Update-ServiceAccountPasswords -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Remove-UnconstrainedKerberosDelegation -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Fix-DangerousACLPermissions -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Enforce-PasswordPolicy -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Clean-EmptyGroups -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
    }
    
    # Export actions summary
    if ($allActions.Count -gt 0) {
        $summaryPath = Join-Path (Split-Path $LogPath) "RemediationSummary.csv"
        $allActions | Export-Csv -Path $summaryPath -NoTypeInformation
        Write-RemediationLog "Actions summary exported to: $summaryPath" -Level Success
    }
    
    Write-RemediationLog "AD remediation process completed successfully" -Level Success
    Write-RemediationLog "Total actions: $($allActions.Count)" -Level Success
    
    return @{
        Success = $true
        ActionsCount = $allActions.Count
        Actions = $allActions
        Message = "Remediation completed successfully"
    }
}
catch {
    Write-RemediationLog "AD remediation process failed: $_" -Level Error
    throw
}
finally {
    if ($connection) {
        $connection.Close()
        Write-RemediationLog "Database connection closed" -Level Info
    }
}

#endregion
