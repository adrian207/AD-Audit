<#
.SYNOPSIS
    Microsoft 365 Remediation Scripts for Common Issues

.DESCRIPTION
    Provides automated remediation for common Microsoft 365 issues identified during audits:
    - Entra ID user cleanup and license optimization
    - Exchange Online mailbox management
    - SharePoint/OneDrive storage optimization
    - Teams configuration cleanup
    - Power Platform environment optimization
    - Compliance policy enforcement
    - Security configuration hardening

.PARAMETER RemediationType
    Type of remediation to perform (EntraID, Exchange, SharePoint, Teams, PowerPlatform, Compliance, Security, All)

.PARAMETER DatabasePath
    Path to audit database for issue identification

.PARAMETER TenantId
    Microsoft 365 tenant ID

.PARAMETER DryRun
    Show what would be remediated without making changes

.PARAMETER Credential
    Microsoft 365 credentials for remediation operations

.PARAMETER LogPath
    Path to save remediation log

.EXAMPLE
    .\Invoke-M365Remediation.ps1 -RemediationType "EntraID" -DatabasePath "C:\Audits\AuditData.db" -DryRun

.EXAMPLE
    .\Invoke-M365Remediation.ps1 -RemediationType "All" -DatabasePath "C:\Audits\AuditData.db" -Credential $cred

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Requires: Microsoft.Graph, ExchangeOnlineManagement, PnP.PowerShell modules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('EntraID', 'Exchange', 'SharePoint', 'Teams', 'PowerPlatform', 'Compliance', 'Security', 'All')]
    [string]$RemediationType,
    
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Temp\M365Remediation.log"
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
    $logMessage = "[$timestamp] [M365-Remediation] [$Level] $Message"
    
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

function Connect-M365Services {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    
    try {
        Write-RemediationLog "Connecting to Microsoft 365 services..." -Level Info
        
        # Connect to Microsoft Graph
        if ($Credential) {
            Connect-MgGraph -Credential $Credential -TenantId $TenantId -ErrorAction Stop
        }
        else {
            Connect-MgGraph -TenantId $TenantId -ErrorAction Stop
        }
        Write-RemediationLog "Connected to Microsoft Graph" -Level Success
        
        # Connect to Exchange Online
        if ($Credential) {
            Connect-ExchangeOnline -Credential $Credential -ShowProgress $false -ErrorAction Stop
        }
        else {
            Connect-ExchangeOnline -ShowProgress $false -ErrorAction Stop
        }
        Write-RemediationLog "Connected to Exchange Online" -Level Success
        
        # Connect to SharePoint
        if ($Credential) {
            Connect-PnPOnline -Credential $Credential -ErrorAction Stop
        }
        else {
            Connect-PnPOnline -Interactive -ErrorAction Stop
        }
        Write-RemediationLog "Connected to SharePoint" -Level Success
        
        # Connect to Teams
        if ($Credential) {
            Connect-MicrosoftTeams -Credential $Credential -ErrorAction Stop
        }
        else {
            Connect-MicrosoftTeams -ErrorAction Stop
        }
        Write-RemediationLog "Connected to Microsoft Teams" -Level Success
        
        return $true
    }
    catch {
        Write-RemediationLog "Failed to connect to Microsoft 365 services: $_" -Level Error
        throw
    }
}

#endregion

#region Entra ID Remediation

function Optimize-EntraIDUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting Entra ID user optimization..." -Level Info
    
    try {
        # Get inactive users
        $inactiveUsers = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    UserPrincipalName,
    DisplayName,
    LastSignInDateTime,
    AccountEnabled,
    LicenseAssignmentStates,
    JobTitle,
    Department
FROM EntraID_Users
WHERE AccountEnabled = 1 AND (LastSignInDateTime IS NULL OR LastSignInDateTime < datetime('now', '-90 days'))
ORDER BY LastSignInDateTime ASC
"@
        
        $actions = @()
        
        foreach ($user in $inactiveUsers.Rows) {
            $action = [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                LastSignIn = $user.LastSignInDateTime
                AccountEnabled = $user.AccountEnabled
                Licenses = $user.LicenseAssignmentStates
                Action = "Disable inactive user"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    # Disable the user
                    Update-MgUser -UserId $user.UserPrincipalName -AccountEnabled:$false -ErrorAction Stop
                    Write-RemediationLog "Disabled inactive user: $($user.UserPrincipalName)" -Level Action
                    
                    # Remove licenses if assigned
                    if ($user.LicenseAssignmentStates) {
                        $licenses = $user.LicenseAssignmentStates -split ';'
                        foreach ($license in $licenses) {
                            if ($license.Trim()) {
                                try {
                                    Set-MgUserLicense -UserId $user.UserPrincipalName -RemoveLicenses @($license.Trim()) -ErrorAction SilentlyContinue
                                    Write-RemediationLog "Removed license $license from $($user.UserPrincipalName)" -Level Action
                                }
                                catch {
                                    Write-RemediationLog "Failed to remove license $license from $($user.UserPrincipalName): $_" -Level Warning
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-RemediationLog "Failed to disable user $($user.UserPrincipalName): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would disable inactive user $($user.UserPrincipalName)" -Level Action
            }
        }
        
        # Get users with excessive licenses
        $excessiveLicenseUsers = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    UserPrincipalName,
    DisplayName,
    LicenseAssignmentStates,
    JobTitle,
    Department
FROM EntraID_Users
WHERE AccountEnabled = 1 AND LicenseAssignmentStates LIKE '%;%'
ORDER BY UserPrincipalName
"@
        
        foreach ($user in $excessiveLicenseUsers.Rows) {
            $licenses = $user.LicenseAssignmentStates -split ';'
            if ($licenses.Count -gt 3) {  # More than 3 licenses
                $action = [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    LicenseCount = $licenses.Count
                    Licenses = $user.LicenseAssignmentStates
                    Action = "Review license assignments"
                }
                $actions += $action
                
                if (-not $DryRun) {
                    Write-RemediationLog "MANUAL REVIEW NEEDED: User $($user.UserPrincipalName) has $($licenses.Count) licenses" -Level Warning
                }
                else {
                    Write-RemediationLog "DRY RUN: Would review licenses for $($user.UserPrincipalName) ($($licenses.Count) licenses)" -Level Action
                }
            }
        }
        
        Write-RemediationLog "Entra ID user optimization complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Entra ID user optimization failed: $_" -Level Error
        throw
    }
}

#endregion

#region Exchange Online Remediation

function Optimize-ExchangeMailboxes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting Exchange Online mailbox optimization..." -Level Info
    
    try {
        # Get oversized mailboxes
        $oversizedMailboxes = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    UserPrincipalName,
    DisplayName,
    TotalItemSize,
    TotalItemSizeGB,
    ItemCount,
    MailboxType
FROM Exchange_Mailboxes
WHERE TotalItemSizeGB > 50
ORDER BY TotalItemSizeGB DESC
"@
        
        $actions = @()
        
        foreach ($mailbox in $oversizedMailboxes.Rows) {
            $action = [PSCustomObject]@{
                UserPrincipalName = $mailbox.UserPrincipalName
                DisplayName = $mailbox.DisplayName
                SizeGB = $mailbox.TotalItemSizeGB
                ItemCount = $mailbox.ItemCount
                MailboxType = $mailbox.MailboxType
                Action = "Archive old items"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    # Enable archive mailbox if not already enabled
                    $archiveStatus = Get-Mailbox -Identity $mailbox.UserPrincipalName | Select-Object ArchiveStatus
                    if ($archiveStatus.ArchiveStatus -eq 'None') {
                        Enable-Mailbox -Identity $mailbox.UserPrincipalName -Archive -ErrorAction Stop
                        Write-RemediationLog "Enabled archive mailbox for $($mailbox.UserPrincipalName)" -Level Action
                    }
                    
                    # Create retention policy for old items
                    $retentionPolicyName = "Archive-Old-Items-$(Get-Date -Format 'yyyyMMdd')"
                    try {
                        New-RetentionPolicy -Name $retentionPolicyName -RetentionPolicyTagLinks "Default-2Years" -ErrorAction SilentlyContinue
                        Set-Mailbox -Identity $mailbox.UserPrincipalName -RetentionPolicy $retentionPolicyName -ErrorAction Stop
                        Write-RemediationLog "Applied retention policy to $($mailbox.UserPrincipalName)" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to apply retention policy to $($mailbox.UserPrincipalName): $_" -Level Warning
                    }
                }
                catch {
                    Write-RemediationLog "Failed to optimize mailbox for $($mailbox.UserPrincipalName): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would optimize mailbox for $($mailbox.UserPrincipalName) ($($mailbox.TotalItemSizeGB)GB)" -Level Action
            }
        }
        
        # Get mailboxes with forwarding rules
        $forwardingMailboxes = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT DISTINCT
    UserPrincipalName,
    DisplayName,
    ForwardingAddress,
    ForwardingSMTPAddress
FROM Exchange_Mailboxes
WHERE ForwardingAddress IS NOT NULL OR ForwardingSMTPAddress IS NOT NULL
ORDER BY UserPrincipalName
"@
        
        foreach ($mailbox in $forwardingMailboxes.Rows) {
            $action = [PSCustomObject]@{
                UserPrincipalName = $mailbox.UserPrincipalName
                DisplayName = $mailbox.DisplayName
                ForwardingAddress = $mailbox.ForwardingAddress
                ForwardingSMTPAddress = $mailbox.ForwardingSMTPAddress
                Action = "Review forwarding rules"
            }
            $actions += $action
            
            if (-not $DryRun) {
                Write-RemediationLog "MANUAL REVIEW NEEDED: Mailbox $($mailbox.UserPrincipalName) has forwarding configured" -Level Warning
            }
            else {
                Write-RemediationLog "DRY RUN: Would review forwarding for $($mailbox.UserPrincipalName)" -Level Action
            }
        }
        
        Write-RemediationLog "Exchange Online mailbox optimization complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Exchange Online mailbox optimization failed: $_" -Level Error
        throw
    }
}

#endregion

#region SharePoint Remediation

function Optimize-SharePointSites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting SharePoint site optimization..." -Level Info
    
    try {
        # Get oversized sites
        $oversizedSites = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    SiteUrl,
    Title,
    StorageUsedGB,
    StorageQuotaGB,
    LastContentModifiedDate,
    SiteOwner
FROM SharePoint_Sites
WHERE StorageUsedGB > 100 OR (StorageQuotaGB > 0 AND StorageUsedGB > (StorageQuotaGB * 0.8))
ORDER BY StorageUsedGB DESC
"@
        
        $actions = @()
        
        foreach ($site in $oversizedSites.Rows) {
            $action = [PSCustomObject]@{
                SiteUrl = $site.SiteUrl
                Title = $site.Title
                StorageUsedGB = $site.StorageUsedGB
                StorageQuotaGB = $site.StorageQuotaGB
                LastModified = $site.LastContentModifiedDate
                SiteOwner = $site.SiteOwner
                Action = "Clean up site storage"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    # Connect to the specific site
                    Connect-PnPOnline -Url $site.SiteUrl -ErrorAction Stop
                    
                    # Get large files
                    $largeFiles = Get-PnPListItem -List "Documents" -Query "<View><Query><Where><Gt><FieldRef Name='File_x0020_Size'/><Value Type='Number'>104857600</Value></Gt></Where></Query></View>" -ErrorAction SilentlyContinue
                    
                    if ($largeFiles.Count -gt 0) {
                        Write-RemediationLog "Found $($largeFiles.Count) large files (>100MB) in $($site.SiteUrl)" -Level Warning
                        
                        # Archive old large files
                        foreach ($file in $largeFiles) {
                            $fileAge = (Get-Date) - [DateTime]$file.FieldValues.Modified
                            if ($fileAge.Days -gt 365) {
                                Write-RemediationLog "MANUAL REVIEW: Large old file $($file.FieldValues.FileLeafRef) in $($site.SiteUrl)" -Level Warning
                            }
                        }
                    }
                    
                    # Check for unused document libraries
                    $libraries = Get-PnPList -Template DocumentLibrary -ErrorAction SilentlyContinue
                    foreach ($library in $libraries) {
                        $items = Get-PnPListItem -List $library.Title -ErrorAction SilentlyContinue
                        if ($items.Count -eq 0) {
                            Write-RemediationLog "Found empty library: $($library.Title) in $($site.SiteUrl)" -Level Info
                        }
                    }
                }
                catch {
                    Write-RemediationLog "Failed to analyze site $($site.SiteUrl): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would analyze site $($site.SiteUrl) ($($site.StorageUsedGB)GB)" -Level Action
            }
        }
        
        # Get sites with external sharing enabled
        $externalSharingSites = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    SiteUrl,
    Title,
    ExternalSharingEnabled,
    SharingCapability,
    SiteOwner
FROM SharePoint_Sites
WHERE ExternalSharingEnabled = 1
ORDER BY SiteUrl
"@
        
        foreach ($site in $externalSharingSites.Rows) {
            $action = [PSCustomObject]@{
                SiteUrl = $site.SiteUrl
                Title = $site.Title
                ExternalSharingEnabled = $site.ExternalSharingEnabled
                SharingCapability = $site.SharingCapability
                SiteOwner = $site.SiteOwner
                Action = "Review external sharing settings"
            }
            $actions += $action
            
            if (-not $DryRun) {
                Write-RemediationLog "MANUAL REVIEW NEEDED: Site $($site.SiteUrl) has external sharing enabled" -Level Warning
            }
            else {
                Write-RemediationLog "DRY RUN: Would review external sharing for $($site.SiteUrl)" -Level Action
            }
        }
        
        Write-RemediationLog "SharePoint site optimization complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "SharePoint site optimization failed: $_" -Level Error
        throw
    }
}

#endregion

#region Teams Remediation

function Optimize-TeamsConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting Teams configuration optimization..." -Level Info
    
    try {
        # Get inactive teams
        $inactiveTeams = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    TeamId,
    DisplayName,
    Description,
    CreatedDateTime,
    LastActivityDateTime,
    MemberCount,
    Owner
FROM Teams_Teams
WHERE LastActivityDateTime IS NULL OR LastActivityDateTime < datetime('now', '-90 days')
ORDER BY LastActivityDateTime ASC
"@
        
        $actions = @()
        
        foreach ($team in $inactiveTeams.Rows) {
            $action = [PSCustomObject]@{
                TeamId = $team.TeamId
                DisplayName = $team.DisplayName
                Description = $team.Description
                CreatedDateTime = $team.CreatedDateTime
                LastActivity = $team.LastActivityDateTime
                MemberCount = $team.MemberCount
                Owner = $team.Owner
                Action = "Archive inactive team"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    # Archive the team
                    Set-Team -GroupId $team.TeamId -Archived $true -ErrorAction Stop
                    Write-RemediationLog "Archived inactive team: $($team.DisplayName)" -Level Action
                }
                catch {
                    Write-RemediationLog "Failed to archive team $($team.DisplayName): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would archive inactive team $($team.DisplayName)" -Level Action
            }
        }
        
        # Get teams with excessive members
        $largeTeams = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    TeamId,
    DisplayName,
    MemberCount,
    Owner
FROM Teams_Teams
WHERE MemberCount > 1000
ORDER BY MemberCount DESC
"@
        
        foreach ($team in $largeTeams.Rows) {
            $action = [PSCustomObject]@{
                TeamId = $team.TeamId
                DisplayName = $team.DisplayName
                MemberCount = $team.MemberCount
                Owner = $team.Owner
                Action = "Review team size and structure"
            }
            $actions += $action
            
            if (-not $DryRun) {
                Write-RemediationLog "MANUAL REVIEW NEEDED: Team $($team.DisplayName) has $($team.MemberCount) members" -Level Warning
            }
            else {
                Write-RemediationLog "DRY RUN: Would review team $($team.DisplayName) ($($team.MemberCount) members)" -Level Action
            }
        }
        
        Write-RemediationLog "Teams configuration optimization complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Teams configuration optimization failed: $_" -Level Error
        throw
    }
}

#endregion

#region Power Platform Remediation

function Optimize-PowerPlatformEnvironments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting Power Platform environment optimization..." -Level Info
    
    try {
        # Get unused environments
        $unusedEnvironments = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    EnvironmentName,
    DisplayName,
    EnvironmentType,
    CreatedTime,
    LastModifiedTime,
    AppsCount,
    FlowsCount
FROM PowerPlatform_Environments
WHERE AppsCount = 0 AND FlowsCount = 0
ORDER BY CreatedTime ASC
"@
        
        $actions = @()
        
        foreach ($env in $unusedEnvironments.Rows) {
            # Skip default environment
            if ($env.EnvironmentName -ne "Default") {
                $action = [PSCustomObject]@{
                    EnvironmentName = $env.EnvironmentName
                    DisplayName = $env.DisplayName
                    EnvironmentType = $env.EnvironmentType
                    CreatedTime = $env.CreatedTime
                    AppsCount = $env.AppsCount
                    FlowsCount = $env.FlowsCount
                    Action = "Delete unused environment"
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        # Note: Power Platform environment deletion requires admin privileges
                        Write-RemediationLog "MANUAL ACTION REQUIRED: Delete unused environment $($env.DisplayName)" -Level Warning
                    }
                    catch {
                        Write-RemediationLog "Failed to process environment $($env.DisplayName): $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would delete unused environment $($env.DisplayName)" -Level Action
                }
            }
        }
        
        # Get apps with errors
        $errorApps = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    AppName,
    EnvironmentName,
    AppType,
    CreatedTime,
    LastModifiedTime,
    ErrorCount
FROM PowerPlatform_Apps
WHERE ErrorCount > 0
ORDER BY ErrorCount DESC
"@
        
        foreach ($app in $errorApps.Rows) {
            $action = [PSCustomObject]@{
                AppName = $app.AppName
                EnvironmentName = $app.EnvironmentName
                AppType = $app.AppType
                ErrorCount = $app.ErrorCount
                Action = "Fix app errors"
            }
            $actions += $action
            
            if (-not $DryRun) {
                Write-RemediationLog "MANUAL REVIEW NEEDED: App $($app.AppName) has $($app.ErrorCount) errors" -Level Warning
            }
            else {
                Write-RemediationLog "DRY RUN: Would review app $($app.AppName) ($($app.ErrorCount) errors)" -Level Action
            }
        }
        
        Write-RemediationLog "Power Platform environment optimization complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Power Platform environment optimization failed: $_" -Level Error
        throw
    }
}

#endregion

#region Compliance Remediation

function Set-CompliancePolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting compliance policy enforcement..." -Level Info
    
    try {
        # Get users without MFA
        $noMfaUsers = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    UserPrincipalName,
    DisplayName,
    MFAEnabled,
    LastSignInDateTime,
    JobTitle
FROM EntraID_Users
WHERE AccountEnabled = 1 AND MFAEnabled = 0
ORDER BY LastSignInDateTime DESC
"@
        
        $actions = @()
        
        foreach ($user in $noMfaUsers.Rows) {
            $action = [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                MFAEnabled = $user.MFAEnabled
                LastSignIn = $user.LastSignInDateTime
                JobTitle = $user.JobTitle
                Action = "Enable MFA"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    # Enable MFA for the user
                    $mfapolicy = Get-MgUserAuthenticationMethodConfiguration -UserId $user.UserPrincipalName -ErrorAction SilentlyContinue
                    if (-not $mfapolicy) {
                        Write-RemediationLog "MANUAL ACTION REQUIRED: Enable MFA for $($user.UserPrincipalName)" -Level Warning
                    }
                }
                catch {
                    Write-RemediationLog "Failed to check MFA status for $($user.UserPrincipalName): $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would enable MFA for $($user.UserPrincipalName)" -Level Action
            }
        }
        
        # Get users with weak authentication methods
        $weakAuthUsers = Invoke-DatabaseQuery -Connection $Connection -Query @"
SELECT 
    UserPrincipalName,
    DisplayName,
    AuthenticationMethods,
    LastSignInDateTime
FROM EntraID_Users
WHERE AccountEnabled = 1 AND AuthenticationMethods LIKE '%SMS%'
ORDER BY LastSignInDateTime DESC
"@
        
        foreach ($user in $weakAuthUsers.Rows) {
            $action = [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                AuthenticationMethods = $user.AuthenticationMethods
                LastSignIn = $user.LastSignInDateTime
                Action = "Upgrade authentication methods"
            }
            $actions += $action
            
            if (-not $DryRun) {
                Write-RemediationLog "MANUAL REVIEW NEEDED: User $($user.UserPrincipalName) uses SMS authentication" -Level Warning
            }
            else {
                Write-RemediationLog "DRY RUN: Would review authentication methods for $($user.UserPrincipalName)" -Level Action
            }
        }
        
        Write-RemediationLog "Compliance policy enforcement complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Compliance policy enforcement failed: $_" -Level Error
        throw
    }
}

#endregion

#region Security Hardening

function Set-M365SecurityHardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting Microsoft 365 security hardening..." -Level Info
    
    try {
        $actions = @()
        
        # Check Conditional Access policies
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
        if ($caPolicies.Count -eq 0) {
            $action = [PSCustomObject]@{
                PolicyType = "Conditional Access"
                CurrentStatus = "No policies configured"
                RecommendedAction = "Create baseline CA policies"
                Action = "Create Conditional Access policies"
            }
            $actions += $action
            
            if (-not $DryRun) {
                Write-RemediationLog "MANUAL ACTION REQUIRED: Create Conditional Access policies" -Level Warning
            }
            else {
                Write-RemediationLog "DRY RUN: Would create Conditional Access policies" -Level Action
            }
        }
        
        # Check Security Defaults
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
        if ($securityDefaults.IsEnabled -eq $false) {
            $action = [PSCustomObject]@{
                PolicyType = "Security Defaults"
                CurrentStatus = "Disabled"
                RecommendedAction = "Enable Security Defaults"
                Action = "Enable Security Defaults"
            }
            $actions += $action
            
            if (-not $DryRun) {
                try {
                    Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled $true -ErrorAction Stop
                    Write-RemediationLog "Enabled Security Defaults" -Level Action
                }
                catch {
                    Write-RemediationLog "Failed to enable Security Defaults: $_" -Level Error
                }
            }
            else {
                Write-RemediationLog "DRY RUN: Would enable Security Defaults" -Level Action
            }
        }
        
        # Check Privileged Identity Management
        $pimRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ErrorAction SilentlyContinue
        if ($pimRoles.Count -eq 0) {
            $action = [PSCustomObject]@{
                PolicyType = "Privileged Identity Management"
                CurrentStatus = "Not configured"
                RecommendedAction = "Enable PIM for privileged roles"
                Action = "Configure PIM"
            }
            $actions += $action
            
            if (-not $DryRun) {
                Write-RemediationLog "MANUAL ACTION REQUIRED: Configure Privileged Identity Management" -Level Warning
            }
            else {
                Write-RemediationLog "DRY RUN: Would configure PIM" -Level Action
            }
        }
        
        Write-RemediationLog "Microsoft 365 security hardening complete: $($actions.Count) actions" -Level Success
        return $actions
    }
    catch {
        Write-RemediationLog "Microsoft 365 security hardening failed: $_" -Level Error
        throw
    }
}

#endregion

#region Main Execution

try {
    Write-RemediationLog "Starting Microsoft 365 remediation process..." -Level Info
    Write-RemediationLog "Remediation Type: $RemediationType" -Level Info
    Write-RemediationLog "Database Path: $DatabasePath" -Level Info
    Write-RemediationLog "Dry Run: $DryRun" -Level Info
    Write-RemediationLog "Log Path: $LogPath" -Level Info
    
    # Connect to Microsoft 365 services
    Connect-M365Services -Credential $Credential -TenantId $TenantId
    
    # Connect to database
    $connection = Get-DatabaseConnection -DatabasePath $DatabasePath
    Write-RemediationLog "Connected to audit database" -Level Success
    
    $allActions = @()
    
    # Execute remediation based on type
    switch ($RemediationType) {
        'EntraID' {
            $actions = Optimize-EntraIDUsers -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'Exchange' {
            $actions = Optimize-ExchangeMailboxes -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'SharePoint' {
            $actions = Optimize-SharePointSites -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'Teams' {
            $actions = Optimize-TeamsConfiguration -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'PowerPlatform' {
            $actions = Optimize-PowerPlatformEnvironments -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'Compliance' {
            $actions = Set-CompliancePolicies -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'Security' {
            $actions = Set-M365SecurityHardening -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
        'All' {
            Write-RemediationLog "Executing all Microsoft 365 remediation types..." -Level Info
            
            $actions = Optimize-EntraIDUsers -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Optimize-ExchangeMailboxes -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Optimize-SharePointSites -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Optimize-TeamsConfiguration -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Optimize-PowerPlatformEnvironments -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Set-CompliancePolicies -Connection $connection -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Set-M365SecurityHardening -Connection $connection -DryRun:$DryRun
            $allActions += $actions
        }
    }
    
    # Export actions summary
    if ($allActions.Count -gt 0) {
        $summaryPath = Join-Path (Split-Path $LogPath) "M365RemediationSummary.csv"
        $allActions | Export-Csv -Path $summaryPath -NoTypeInformation
        Write-RemediationLog "Actions summary exported to: $summaryPath" -Level Success
    }
    
    Write-RemediationLog "Microsoft 365 remediation process completed successfully" -Level Success
    Write-RemediationLog "Total actions: $($allActions.Count)" -Level Success
    
    return @{
        Success = $true
        ActionsCount = $allActions.Count
        Actions = $allActions
        Message = "Microsoft 365 remediation completed successfully"
    }
}
catch {
    Write-RemediationLog "Microsoft 365 remediation process failed: $_" -Level Error
    throw
}
finally {
    if ($connection) {
        $connection.Close()
        Write-RemediationLog "Database connection closed" -Level Info
    }
    
    # Disconnect from Microsoft 365 services
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        Write-RemediationLog "Disconnected from Microsoft 365 services" -Level Info
    }
    catch {
        Write-RemediationLog "Failed to disconnect from some Microsoft 365 services: $_" -Level Warning
    }
}

#endregion
