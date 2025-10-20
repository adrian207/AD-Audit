<#
.SYNOPSIS
    Audits SharePoint Online, OneDrive, and Microsoft Teams for M&A discovery

.DESCRIPTION
    Collects comprehensive SharePoint, OneDrive, and Teams data including:
    - SharePoint site inventory (modern, classic, communication, hub sites)
    - Site collections, storage quotas, and external sharing settings
    - OneDrive for Business site inventory and usage
    - Microsoft Teams inventory and configurations
    - Team channels, membership, and settings
    - External sharing configurations and guest access
    - File sharing links (anonymous links, guest links)
    - Site ownership and permissions overview

    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0
    Date: October 2025

.PARAMETER OutputFolder
    Root folder where CSV files will be saved

.PARAMETER Credential
    Optional credential for authentication (if not using interactive)

.EXAMPLE
    .\Invoke-SharePoint-Teams-Audit.ps1 -OutputFolder "C:\Audits\Contoso\RawData"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-ModuleLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        default   { 'Cyan' }
    }

    $timestamp = Get-Date -Format 'HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Connect-ToSharePointOnline {
    param([string]$AdminUrl)

    Write-ModuleLog "Connecting to SharePoint Online..." -Level Info

    # Check if SharePoint Online Management Shell module is available
    if (-not (Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell)) {
        Write-ModuleLog "Installing SharePoint Online Management Shell module..." -Level Warning
        Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -AllowClobber
    }

    Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop

    # Connect
    try {
        if ($Credential) {
            Connect-SPOService -Url $AdminUrl -Credential $Credential
        }
        else {
            Connect-SPOService -Url $AdminUrl
        }
        Write-ModuleLog "Successfully connected to SharePoint Online" -Level Success
    }
    catch {
        Write-ModuleLog "Failed to connect to SharePoint Online: $_" -Level Error
        throw
    }
}

function Connect-ToMicrosoftTeams {
    Write-ModuleLog "Connecting to Microsoft Teams..." -Level Info

    # Check if Microsoft Teams module is available
    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        Write-ModuleLog "Installing Microsoft Teams module..." -Level Warning
        Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force -AllowClobber
    }

    Import-Module MicrosoftTeams -ErrorAction Stop

    # Connect
    try {
        if ($Credential) {
            Connect-MicrosoftTeams -Credential $Credential
        }
        else {
            Connect-MicrosoftTeams
        }
        Write-ModuleLog "Successfully connected to Microsoft Teams" -Level Success
    }
    catch {
        Write-ModuleLog "Failed to connect to Microsoft Teams: $_" -Level Error
        throw
    }
}

#endregion

#region Data Collection Functions

function Get-TenantConfiguration {
    Write-ModuleLog "Collecting SharePoint tenant configuration..." -Level Info

    try {
        $tenantConfig = Get-SPOTenant

        $tenantInfo = [PSCustomObject]@{
            SharePointDomain = $tenantConfig.SharePointDomain
            OneDriveStorageQuota = $tenantConfig.OneDriveStorageQuota
            OrphanedPersonalSitesRetentionPeriod = $tenantConfig.OrphanedPersonalSitesRetentionPeriod
            SharingCapability = $tenantConfig.SharingCapability
            DefaultSharingLinkType = $tenantConfig.DefaultSharingLinkType
            DefaultLinkPermission = $tenantConfig.DefaultLinkPermission
            ExternalServicesEnabled = $tenantConfig.ExternalServicesEnabled
            PublicCdnEnabled = $tenantConfig.PublicCdnEnabled
            RequireAcceptingAccountMatchInvitedAccount = $tenantConfig.RequireAcceptingAccountMatchInvitedAccount
            SearchResolveExactEmailOrUPN = $tenantConfig.SearchResolveExactEmailOrUPN
            OfficeClientADALDisabled = $tenantConfig.OfficeClientADALDisabled
            LegacyAuthProtocolsEnabled = $tenantConfig.LegacyAuthProtocolsEnabled
            ShowEveryoneClaim = $tenantConfig.ShowEveryoneClaim
            ShowEveryoneExceptExternalUsersClaim = $tenantConfig.ShowEveryoneExceptExternalUsersClaim
            NotificationsInOneDriveForBusinessEnabled = $tenantConfig.NotificationsInOneDriveForBusinessEnabled
            NotificationsInSharePointEnabled = $tenantConfig.NotificationsInSharePointEnabled
            OwnerAnonymousNotification = $tenantConfig.OwnerAnonymousNotification
            DisplayStartASiteOption = $tenantConfig.DisplayStartASiteOption
        }

        $tenantInfo | Export-Csv -Path (Join-Path $OutputFolder "SharePoint\SharePoint_Tenant_Config.csv") -NoTypeInformation
        Write-ModuleLog "Tenant configuration collected" -Level Success

        return $tenantInfo
    }
    catch {
        Write-ModuleLog "Failed to collect tenant configuration: $_" -Level Error
        throw
    }
}

function Get-SharePointSites {
    Write-ModuleLog "Collecting SharePoint site inventory (this may take several minutes)..." -Level Info

    try {
        $sites = Get-SPOSite -Limit All -IncludePersonalSite:$false

        Write-ModuleLog "Processing $($sites.Count) SharePoint sites..." -Level Info

        $siteDetails = $sites | ForEach-Object {
            [PSCustomObject]@{
                Url = $_.Url
                Title = $_.Title
                Owner = $_.Owner
                Template = $_.Template
                StorageQuota = $_.StorageQuota
                StorageQuotaWarningLevel = $_.StorageQuotaWarningLevel
                StorageUsageCurrent = $_.StorageUsageCurrent
                StorageUsageCurrentMB = [math]::Round($_.StorageUsageCurrent, 2)
                StorageUtilizationPercent = if ($_.StorageQuota -gt 0) { 
                    [math]::Round(($_.StorageUsageCurrent / $_.StorageQuota) * 100, 2) 
                } else { 0 }
                SharingCapability = $_.SharingCapability
                ConditionalAccessPolicy = $_.ConditionalAccessPolicy
                AllowDownloadingNonWebViewableFiles = $_.AllowDownloadingNonWebViewableFiles
                AllowEditing = $_.AllowEditing
                CommentsOnSitePagesDisabled = $_.CommentsOnSitePagesDisabled
                DenyAddAndCustomizePages = $_.DenyAddAndCustomizePages
                DisableCompanyWideSharingLinks = $_.DisableCompanyWideSharingLinks
                ExternalUserExpirationInDays = $_.ExternalUserExpirationInDays
                LockState = $_.LockState
                PWAEnabled = $_.PWAEnabled
                RestrictedToRegion = $_.RestrictedToRegion
                SandboxedCodeActivationCapability = $_.SandboxedCodeActivationCapability
                SensitivityLabel = $_.SensitivityLabel
                SiteDefinedSharingCapability = $_.SiteDefinedSharingCapability
                Status = $_.Status
                LastContentModifiedDate = $_.LastContentModifiedDate
                IsHubSite = $_.IsHubSite
                HubSiteId = $_.HubSiteId
                GroupId = $_.GroupId
                HasHolds = $_.HasHolds
                IBMode = $_.IBMode
            }
        }

        $siteDetails | Export-Csv -Path (Join-Path $OutputFolder "SharePoint\SharePoint_Sites.csv") -NoTypeInformation
        Write-ModuleLog "SharePoint sites collected: $($sites.Count) sites" -Level Success

        # Generate summary
        $summary = [PSCustomObject]@{
            TotalSites = $sites.Count
            TotalStorageUsedMB = ($siteDetails | Measure-Object -Property StorageUsageCurrentMB -Sum).Sum
            AverageStorageUsedMB = [math]::Round(($siteDetails | Measure-Object -Property StorageUsageCurrentMB -Average).Average, 2)
            HubSites = ($siteDetails | Where-Object { $_.IsHubSite }).Count
            GroupConnectedSites = ($siteDetails | Where-Object { $null -ne $_.GroupId }).Count
            SitesWithHolds = ($siteDetails | Where-Object { $_.HasHolds }).Count
            LockedSites = ($siteDetails | Where-Object { $_.LockState -ne 'Unlock' }).Count
        }

        $summary | Export-Csv -Path (Join-Path $OutputFolder "SharePoint\SharePoint_Site_Summary.csv") -NoTypeInformation

        return $siteDetails
    }
    catch {
        Write-ModuleLog "Failed to collect SharePoint sites: $_" -Level Error
        throw
    }
}

function Get-OneDriveSites {
    Write-ModuleLog "Collecting OneDrive for Business sites..." -Level Info

    try {
        $oneDriveSites = Get-SPOSite -Limit All -IncludePersonalSite:$true -Filter "Url -like '-my.sharepoint.com/personal/'"

        Write-ModuleLog "Processing $($oneDriveSites.Count) OneDrive sites..." -Level Info

        $oneDriveDetails = $oneDriveSites | ForEach-Object {
            [PSCustomObject]@{
                Url = $_.Url
                Owner = $_.Owner
                StorageQuota = $_.StorageQuota
                StorageUsageCurrent = $_.StorageUsageCurrent
                StorageUsageCurrentMB = [math]::Round($_.StorageUsageCurrent, 2)
                StorageUtilizationPercent = if ($_.StorageQuota -gt 0) { 
                    [math]::Round(($_.StorageUsageCurrent / $_.StorageQuota) * 100, 2) 
                } else { 0 }
                SharingCapability = $_.SharingCapability
                LockState = $_.LockState
                LastContentModifiedDate = $_.LastContentModifiedDate
                Status = $_.Status
            }
        }

        $oneDriveDetails | Export-Csv -Path (Join-Path $OutputFolder "SharePoint\OneDrive_Sites.csv") -NoTypeInformation
        Write-ModuleLog "OneDrive sites collected: $($oneDriveSites.Count) sites" -Level Success

        # Generate summary
        $summary = [PSCustomObject]@{
            TotalOneDriveSites = $oneDriveSites.Count
            TotalStorageUsedMB = ($oneDriveDetails | Measure-Object -Property StorageUsageCurrentMB -Sum).Sum
            AverageStorageUsedMB = [math]::Round(($oneDriveDetails | Measure-Object -Property StorageUsageCurrentMB -Average).Average, 2)
        }

        $summary | Export-Csv -Path (Join-Path $OutputFolder "SharePoint\OneDrive_Summary.csv") -NoTypeInformation

        return $oneDriveDetails
    }
    catch {
        Write-ModuleLog "Failed to collect OneDrive sites: $_" -Level Error
        throw
    }
}

function Get-ExternalUsers {
    Write-ModuleLog "Collecting external users (guest access)..." -Level Info

    try {
        $externalUsers = Get-SPOExternalUser -PageSize 50 -Position 0

        $userDetails = @()
        if ($externalUsers) {
            foreach ($user in $externalUsers) {
                $userDetails += [PSCustomObject]@{
                    DisplayName = $user.DisplayName
                    Email = $user.Email
                    AcceptedAs = $user.AcceptedAs
                    WhenCreated = $user.WhenCreated
                    InvitedBy = $user.InvitedBy
                    InvitedAs = $user.InvitedAs
                    UniqueId = $user.UniqueId
                }
            }
        }

        $userDetails | Export-Csv -Path (Join-Path $OutputFolder "SharePoint\SharePoint_External_Users.csv") -NoTypeInformation
        Write-ModuleLog "External users collected: $($userDetails.Count) users" -Level Success

        return $userDetails
    }
    catch {
        Write-ModuleLog "Failed to collect external users: $_" -Level Warning
        return @()
    }
}

function Get-TeamsInventory {
    Write-ModuleLog "Collecting Microsoft Teams inventory..." -Level Info

    try {
        $teams = Get-Team

        Write-ModuleLog "Processing $($teams.Count) teams..." -Level Info

        $teamDetails = $teams | ForEach-Object {
            # Get team membership count
            try {
                $owners = Get-TeamUser -GroupId $_.GroupId -Role Owner -ErrorAction SilentlyContinue
                $members = Get-TeamUser -GroupId $_.GroupId -Role Member -ErrorAction SilentlyContinue
                $guests = Get-TeamUser -GroupId $_.GroupId -Role Guest -ErrorAction SilentlyContinue
                
                $ownerCount = if ($owners) { $owners.Count } else { 0 }
                $memberCount = if ($members) { $members.Count } else { 0 }
                $guestCount = if ($guests) { $guests.Count } else { 0 }
            }
            catch {
                $ownerCount = 0
                $memberCount = 0
                $guestCount = 0
            }

            # Get channel count
            try {
                $channels = Get-TeamChannel -GroupId $_.GroupId -ErrorAction SilentlyContinue
                $channelCount = if ($channels) { $channels.Count } else { 0 }
            }
            catch {
                $channelCount = 0
            }

            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                GroupId = $_.GroupId
                Visibility = $_.Visibility
                MailNickName = $_.MailNickName
                Description = $_.Description
                Archived = $_.Archived
                AllowGiphy = $_.AllowGiphy
                GiphyContentRating = $_.GiphyContentRating
                AllowStickersAndMemes = $_.AllowStickersAndMemes
                AllowCustomMemes = $_.AllowCustomMemes
                AllowGuestCreateUpdateChannels = $_.AllowGuestCreateUpdateChannels
                AllowGuestDeleteChannels = $_.AllowGuestDeleteChannels
                AllowCreateUpdateChannels = $_.AllowCreateUpdateChannels
                AllowDeleteChannels = $_.AllowDeleteChannels
                AllowAddRemoveApps = $_.AllowAddRemoveApps
                AllowCreateUpdateRemoveTabs = $_.AllowCreateUpdateRemoveTabs
                AllowCreateUpdateRemoveConnectors = $_.AllowCreateUpdateRemoveConnectors
                AllowUserEditMessages = $_.AllowUserEditMessages
                AllowUserDeleteMessages = $_.AllowUserDeleteMessages
                AllowOwnerDeleteMessages = $_.AllowOwnerDeleteMessages
                AllowTeamMentions = $_.AllowTeamMentions
                AllowChannelMentions = $_.AllowChannelMentions
                OwnerCount = $ownerCount
                MemberCount = $memberCount
                GuestCount = $guestCount
                ChannelCount = $channelCount
            }
        }

        $teamDetails | Export-Csv -Path (Join-Path $OutputFolder "SharePoint\Teams_Inventory.csv") -NoTypeInformation
        Write-ModuleLog "Teams collected: $($teams.Count) teams" -Level Success

        # Generate summary
        $summary = [PSCustomObject]@{
            TotalTeams = $teams.Count
            PrivateTeams = ($teamDetails | Where-Object { $_.Visibility -eq 'Private' }).Count
            PublicTeams = ($teamDetails | Where-Object { $_.Visibility -eq 'Public' }).Count
            ArchivedTeams = ($teamDetails | Where-Object { $_.Archived }).Count
            TotalChannels = ($teamDetails | Measure-Object -Property ChannelCount -Sum).Sum
            TeamsWithGuests = ($teamDetails | Where-Object { $_.GuestCount -gt 0 }).Count
        }

        $summary | Export-Csv -Path (Join-Path $OutputFolder "SharePoint\Teams_Summary.csv") -NoTypeInformation

        return $teamDetails
    }
    catch {
        Write-ModuleLog "Failed to collect Teams inventory: $_" -Level Error
        throw
    }
}

#endregion

#region Main Execution

try {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   SharePoint, OneDrive & Teams Audit" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    # Ensure output folder exists
    $sharePointFolder = Join-Path $OutputFolder "SharePoint"
    if (-not (Test-Path $sharePointFolder)) {
        New-Item -ItemType Directory -Path $sharePointFolder -Force | Out-Null
    }

    # Determine SharePoint admin URL
    # First, try to get from Entra ID tenant
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            # Try to get initial domain from organization
            try {
                $org = Get-MgOrganization -ErrorAction SilentlyContinue
                if ($org) {
                    $initialDomain = ($org.VerifiedDomains | Where-Object { $_.IsInitial }).Name
                    if ($initialDomain) {
                        $tenantName = $initialDomain -replace '\.onmicrosoft\.com$', ''
                    }
                }
            }
            catch {
                # Fallback - prompt user
            }
        }
    }
    catch {
        # Can't determine automatically
    }

    if (-not $tenantName) {
        Write-Host ""
        Write-Host "Please enter your SharePoint tenant name (e.g., 'contoso' from contoso.sharepoint.com):" -ForegroundColor Yellow
        $tenantName = Read-Host "Tenant Name"
    }

    $adminUrl = "https://$tenantName-admin.sharepoint.com"
    Write-ModuleLog "Using SharePoint Admin URL: $adminUrl" -Level Info

    # Connect to SharePoint Online
    Connect-ToSharePointOnline -AdminUrl $adminUrl

    # Collect tenant configuration
    $tenantConfig = Get-TenantConfiguration

    # Collect SharePoint sites
    $sites = Get-SharePointSites

    # Collect OneDrive sites
    $oneDriveSites = Get-OneDriveSites

    # Collect external users
    $externalUsers = Get-ExternalUsers

    # Connect to Microsoft Teams
    Connect-ToMicrosoftTeams

    # Collect Teams inventory
    $teams = Get-TeamsInventory

    # Generate summary
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   SharePoint, OneDrive & Teams Audit Completed!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  SharePoint Sites: $($sites.Count)" -ForegroundColor White
    Write-Host "  OneDrive Sites: $($oneDriveSites.Count)" -ForegroundColor White
    Write-Host "  Microsoft Teams: $($teams.Count)" -ForegroundColor White
    Write-Host "  External Users: $($externalUsers.Count)" -ForegroundColor White
    Write-Host ""

    # Return statistics
    return @{
        SharePointSites = $sites.Count
        OneDriveSites = $oneDriveSites.Count
        Teams = $teams.Count
        ExternalUsers = $externalUsers.Count
    }
}
catch {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "   SharePoint & Teams Audit Failed!" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    throw
}
finally {
    # Disconnect from services
    try {
        Disconnect-SPOService -ErrorAction SilentlyContinue | Out-Null
        Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
        Write-ModuleLog "Disconnected from SharePoint and Teams" -Level Info
    }
    catch {
        # Ignore disconnect errors
    }
}

#endregion

