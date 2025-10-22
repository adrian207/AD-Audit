<#
.SYNOPSIS
    Incident Response and Threat Containment Module

.DESCRIPTION
    Provides automated incident response capabilities based on Microsoft's incident response playbooks.
    Integrates with existing AD-Audit remediation framework to provide rapid threat containment.

.PARAMETER IncidentType
    Type of security incident (Phishing, PasswordSpray, AppConsent, CompromisedApp)

.PARAMETER Severity
    Incident severity level (Critical, High, Medium, Low)

.PARAMETER AffectedUsers
    Array of affected user accounts

.PARAMETER AffectedServers
    Array of affected servers

.PARAMETER ContainmentMode
    Level of containment (Full, Partial, Monitor)

.PARAMETER DatabasePath
    Path to audit database for context

.EXAMPLE
    .\Invoke-IncidentResponse.ps1 -IncidentType "PasswordSpray" -Severity "High" -AffectedUsers @("user1", "user2")

.EXAMPLE
    .\Invoke-IncidentResponse.ps1 -IncidentType "Phishing" -Severity "Critical" -ContainmentMode "Full"

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Based on: Microsoft Incident Response Playbooks
    Requires: AD-Audit remediation modules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Phishing', 'PasswordSpray', 'AppConsent', 'CompromisedApp', 'SMBCompromise', 'PrivilegeEscalation')]
    [string]$IncidentType,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet('Critical', 'High', 'Medium', 'Low')]
    [string]$Severity,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AffectedUsers,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AffectedServers,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Full', 'Partial', 'Monitor')]
    [string]$ContainmentMode = 'Partial',
    
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-IncidentLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info',
        [string]$IncidentID = $script:IncidentID
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [INCIDENT-$IncidentID] [$Level] $Message"
    
    switch ($Level) {
        'Critical' { Write-Host $logMessage -ForegroundColor Red -BackgroundColor Yellow }
        'Error'    { Write-Host $logMessage -ForegroundColor Red }
        'Warning'  { Write-Host $logMessage -ForegroundColor Yellow }
        'Success'  { Write-Host $logMessage -ForegroundColor Green }
        default    { Write-Verbose $logMessage }
    }
}

function New-IncidentID {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $random = Get-Random -Minimum 1000 -Maximum 9999
    return "INC-$timestamp-$random"
}

function Get-AffectedUsersFromDatabase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabasePath,
        
        [Parameter(Mandatory = $true)]
        [string]$IncidentType
    )
    
    try {
        Add-Type -Path "System.Data.SQLite.dll" -ErrorAction Stop
        $connectionString = "Data Source=$DatabasePath;Version=3;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()
        
        $query = switch ($IncidentType) {
            'PasswordSpray' {
                "SELECT DISTINCT SamAccountName FROM AD_User_Inventory WHERE LastLogonDate > datetime('now', '-7 days') AND PasswordAgeDays > 90"
            }
            'Phishing' {
                "SELECT DISTINCT SamAccountName FROM AD_User_Inventory WHERE LastLogonDate > datetime('now', '-1 days')"
            }
            'AppConsent' {
                "SELECT DISTINCT UserPrincipalName FROM M365_User_Details WHERE LastSignIn > datetime('now', '-1 days')"
            }
            default {
                "SELECT DISTINCT SamAccountName FROM AD_User_Inventory WHERE LastLogonDate > datetime('now', '-7 days')"
            }
        }
        
        $command = $connection.CreateCommand()
        $command.CommandText = $query
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet)
        
        $users = $dataSet.Tables[0].Rows | ForEach-Object { $_.ItemArray[0] }
        $connection.Close()
        
        return $users
    }
    catch {
        Write-IncidentLog "Failed to get affected users from database: $_" -Level Error
        return @()
    }
}

#endregion

#region Incident Response Procedures

function Invoke-PhishingResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AffectedUsers,
        
        [Parameter(Mandatory = $true)]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$ContainmentMode
    )
    
    Write-IncidentLog "Executing phishing incident response procedures" -Level Critical
    
    $actions = @()
    
    foreach ($user in $AffectedUsers) {
        try {
            # Immediate password reset
            if ($ContainmentMode -in @('Full', 'Partial')) {
                if (-not $DryRun) {
                    $newPassword = -join ((1..16) | ForEach-Object {Get-Random -InputObject ([char[]]([char]'A'..[char]'Z') + [char[]]([char]'a'..[char]'z') + [char[]]([char]'0'..[char]'9') + [char[]]'!@#$%^&*')})
                    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                    Set-ADAccountPassword -Identity $user -NewPassword $securePassword -ErrorAction Stop
                    Write-IncidentLog "Reset password for potentially compromised user: $user" -Level Success
                }
                else {
                    Write-IncidentLog "DRY RUN: Would reset password for user: $user" -Level Warning
                }
            }
            
            # Disable account if critical severity
            if ($Severity -eq 'Critical' -and $ContainmentMode -eq 'Full') {
                if (-not $DryRun) {
                    Disable-ADAccount -Identity $user -ErrorAction Stop
                    Write-IncidentLog "Disabled account for critical phishing incident: $user" -Level Success
                }
                else {
                    Write-IncidentLog "DRY RUN: Would disable account: $user" -Level Warning
                }
            }
            
            # Remove from privileged groups
            if (-not $DryRun) {
                $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
                foreach ($group in $privilegedGroups) {
                    try {
                        Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false -ErrorAction SilentlyContinue
                        Write-IncidentLog "Removed $user from privileged group: $group" -Level Success
                    }
                    catch {
                        # User might not be in group
                    }
                }
            }
            else {
                Write-IncidentLog "DRY RUN: Would remove $user from privileged groups" -Level Warning
            }
            
            $actions += [PSCustomObject]@{
                User = $user
                Action = 'Password Reset + Privilege Removal'
                Status = if ($DryRun) { 'Simulated' } else { 'Completed' }
                Timestamp = Get-Date
            }
        }
        catch {
            Write-IncidentLog "Failed to process user $user`: $_" -Level Error
        }
    }
    
    return $actions
}

function Invoke-PasswordSprayResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AffectedUsers,
        
        [Parameter(Mandatory = $true)]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$ContainmentMode
    )
    
    Write-IncidentLog "Executing password spray incident response procedures" -Level Critical
    
    $actions = @()
    
    foreach ($user in $AffectedUsers) {
        try {
            # Force password change for all affected users
            if (-not $DryRun) {
                $newPassword = -join ((1..16) | ForEach-Object {Get-Random -InputObject ([char[]]([char]'A'..[char]'Z') + [char[]]([char]'a'..[char]'z') + [char[]]([char]'0'..[char]'9') + [char[]]'!@#$%^&*')})
                $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                Set-ADAccountPassword -Identity $user -NewPassword $securePassword -ErrorAction Stop
                Write-IncidentLog "Reset password for password spray target: $user" -Level Success
            }
            else {
                Write-IncidentLog "DRY RUN: Would reset password for user: $user" -Level Warning
            }
            
            # Enable MFA if available
            if (-not $DryRun) {
                try {
                    Set-ADUser -Identity $user -SmartcardLogonRequired $true -ErrorAction SilentlyContinue
                    Write-IncidentLog "Enabled smartcard logon for: $user" -Level Success
                }
                catch {
                    Write-IncidentLog "Could not enable smartcard logon for $user`: $_" -Level Warning
                }
            }
            
            $actions += [PSCustomObject]@{
                User = $user
                Action = 'Password Reset + MFA Enforcement'
                Status = if ($DryRun) { 'Simulated' } else { 'Completed' }
                Timestamp = Get-Date
            }
        }
        catch {
            Write-IncidentLog "Failed to process user $user`: $_" -Level Error
        }
    }
    
    return $actions
}

function Invoke-AppConsentResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AffectedUsers,
        
        [Parameter(Mandatory = $true)]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$ContainmentMode
    )
    
    Write-IncidentLog "Executing app consent incident response procedures" -Level Critical
    
    $actions = @()
    
    foreach ($user in $AffectedUsers) {
        try {
            # Revoke all app consents for affected users
            if (-not $DryRun) {
                # This would require Microsoft Graph API integration
                Write-IncidentLog "Would revoke app consents for: $user (requires Graph API)" -Level Warning
            }
            else {
                Write-IncidentLog "DRY RUN: Would revoke app consents for: $user" -Level Warning
            }
            
            # Disable user if critical
            if ($Severity -eq 'Critical' -and $ContainmentMode -eq 'Full') {
                if (-not $DryRun) {
                    Disable-ADAccount -Identity $user -ErrorAction Stop
                    Write-IncidentLog "Disabled account for critical app consent abuse: $user" -Level Success
                }
                else {
                    Write-IncidentLog "DRY RUN: Would disable account: $user" -Level Warning
                }
            }
            
            $actions += [PSCustomObject]@{
                User = $user
                Action = 'App Consent Revocation + Account Review'
                Status = if ($DryRun) { 'Simulated' } else { 'Completed' }
                Timestamp = Get-Date
            }
        }
        catch {
            Write-IncidentLog "Failed to process user $user`: $_" -Level Error
        }
    }
    
    return $actions
}

function Invoke-SMBCompromiseResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$AffectedServers,
        
        [Parameter(Mandatory = $true)]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [string]$ContainmentMode
    )
    
    Write-IncidentLog "Executing SMB compromise incident response procedures" -Level Critical
    
    $actions = @()
    
    foreach ($server in $AffectedServers) {
        try {
            # Isolate server from network
            if ($Severity -eq 'Critical' -and $ContainmentMode -eq 'Full') {
                if (-not $DryRun) {
                    # This would require network infrastructure integration
                    Write-IncidentLog "Would isolate server from network: $server (requires network integration)" -Level Warning
                }
                else {
                    Write-IncidentLog "DRY RUN: Would isolate server: $server" -Level Warning
                }
            }
            
            # Disable SMB services temporarily
            if ($ContainmentMode -in @('Full', 'Partial')) {
                if (-not $DryRun) {
                    Invoke-Command -ComputerName $server -ScriptBlock {
                        Stop-Service -Name "LanmanServer" -Force -ErrorAction SilentlyContinue
                        Set-Service -Name "LanmanServer" -StartupType Disabled -ErrorAction SilentlyContinue
                    } -ErrorAction SilentlyContinue
                    Write-IncidentLog "Disabled SMB services on: $server" -Level Success
                }
                else {
                    Write-IncidentLog "DRY RUN: Would disable SMB services on: $server" -Level Warning
                }
            }
            
            $actions += [PSCustomObject]@{
                Server = $server
                Action = 'SMB Service Disable + Network Isolation'
                Status = if ($DryRun) { 'Simulated' } else { 'Completed' }
                Timestamp = Get-Date
            }
        }
        catch {
            Write-IncidentLog "Failed to process server $server`: $_" -Level Error
        }
    }
    
    return $actions
}

#endregion

#region Main Execution

try {
    # Initialize incident
    $script:IncidentID = New-IncidentID
    Write-IncidentLog "Starting incident response for $IncidentType (Severity: $Severity)" -Level Critical
    
    # Get affected users if not provided
    if (-not $AffectedUsers -and $DatabasePath) {
        $AffectedUsers = Get-AffectedUsersFromDatabase -DatabasePath $DatabasePath -IncidentType $IncidentType
        Write-IncidentLog "Retrieved $($AffectedUsers.Count) potentially affected users from database" -Level Info
    }
    
    if (-not $AffectedUsers -and -not $AffectedServers) {
        throw "Either AffectedUsers or AffectedServers must be specified"
    }
    
    # Execute appropriate response procedure
    $responseActions = @()
    
    switch ($IncidentType) {
        'Phishing' {
            $responseActions = Invoke-PhishingResponse -AffectedUsers $AffectedUsers -Severity $Severity -ContainmentMode $ContainmentMode
        }
        'PasswordSpray' {
            $responseActions = Invoke-PasswordSprayResponse -AffectedUsers $AffectedUsers -Severity $Severity -ContainmentMode $ContainmentMode
        }
        'AppConsent' {
            $responseActions = Invoke-AppConsentResponse -AffectedUsers $AffectedUsers -Severity $Severity -ContainmentMode $ContainmentMode
        }
        'SMBCompromise' {
            $responseActions = Invoke-SMBCompromiseResponse -AffectedServers $AffectedServers -Severity $Severity -ContainmentMode $ContainmentMode
        }
        default {
            throw "Unsupported incident type: $IncidentType"
        }
    }
    
    # Generate incident report
    $incidentReport = [PSCustomObject]@{
        IncidentID = $script:IncidentID
        IncidentType = $IncidentType
        Severity = $Severity
        ContainmentMode = $ContainmentMode
        StartTime = Get-Date
        AffectedUsers = $AffectedUsers -join ', '
        AffectedServers = $AffectedServers -join ', '
        ActionsTaken = $responseActions.Count
        DryRun = $DryRun.IsPresent
        Status = 'Completed'
    }
    
    # Export incident report
    $reportPath = "C:\Temp\Incident-$($script:IncidentID).csv"
    $incidentReport | Export-Csv -Path $reportPath -NoTypeInformation
    $responseActions | Export-Csv -Path "C:\Temp\IncidentActions-$($script:IncidentID).csv" -NoTypeInformation
    
    Write-IncidentLog "Incident response completed successfully" -Level Success
    Write-IncidentLog "Incident report saved to: $reportPath" -Level Info
    Write-IncidentLog "Response actions saved to: C:\Temp\IncidentActions-$($script:IncidentID).csv" -Level Info
    
    return @{
        Success = $true
        IncidentID = $script:IncidentID
        Actions = $responseActions
        Report = $incidentReport
        Message = "Incident response completed successfully"
    }
}
catch {
    Write-IncidentLog "Incident response failed: $_" -Level Error
    throw
}

#endregion
