<#
.SYNOPSIS
    Audits Exchange Online configuration for M&A discovery

.DESCRIPTION
    Collects comprehensive Exchange Online data including:
    - Mailbox inventory (user, shared, room, equipment)
    - Mailbox sizes and quotas
    - Forwarding rules and inbox rules
    - Transport rules (mail flow rules)
    - Connectors (inbound/outbound)
    - Distribution groups and Microsoft 365 groups
    - Public folders
    - Email address policies
    - Mobile devices
    - Hybrid configuration (if present)

    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0
    Date: October 2025

.PARAMETER OutputFolder
    Root folder where CSV files will be saved

.PARAMETER Credential
    Optional credential for authentication (if not using interactive)

.EXAMPLE
    .\Invoke-Exchange-Audit.ps1 -OutputFolder "C:\Audits\Contoso\RawData"
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

function Connect-ToExchangeOnline {
    Write-ModuleLog "Connecting to Exchange Online..." -Level Info

    # Check if ExchangeOnlineManagement module is available
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-ModuleLog "Installing ExchangeOnlineManagement module..." -Level Warning
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    # Check if already connected
    try {
        $null = Get-OrganizationConfig -ErrorAction Stop
        Write-ModuleLog "Already connected to Exchange Online" -Level Success
        return
    }
    catch {
        # Not connected, proceed with connection
    }

    # Connect
    try {
        if ($Credential) {
            Connect-ExchangeOnline -Credential $Credential -ShowBanner:$false
        }
        else {
            Connect-ExchangeOnline -ShowBanner:$false
        }
        Write-ModuleLog "Successfully connected to Exchange Online" -Level Success
    }
    catch {
        Write-ModuleLog "Failed to connect to Exchange Online: $_" -Level Error
        throw
    }
}

#endregion

#region Data Collection Functions

function Get-OrganizationInformation {
    Write-ModuleLog "Collecting organization configuration..." -Level Info

    try {
        $orgConfig = Get-OrganizationConfig

        $orgInfo = [PSCustomObject]@{
            Name = $orgConfig.Name
            DisplayName = $orgConfig.DisplayName
            Identity = $orgConfig.Identity
            DefaultDomain = $orgConfig.DefaultDomain
            IsHybrid = $orgConfig.IsHybridConfigurationEnabled
            IsDehydrated = $orgConfig.IsDehydrated
            IsUpgradingOrganization = $orgConfig.IsUpgradingOrganization
            IsUpdatingServicePlan = $orgConfig.IsUpdatingServicePlan
            ActivityBasedAuthenticationTimeoutEnabled = $orgConfig.ActivityBasedAuthenticationTimeoutEnabled
            ActivityBasedAuthenticationTimeoutInterval = $orgConfig.ActivityBasedAuthenticationTimeoutInterval
            ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled = $orgConfig.ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled
            AppsForOfficeEnabled = $orgConfig.AppsForOfficeEnabled
            AsyncSendEnabled = $orgConfig.AsyncSendEnabled
            AuditDisabled = $orgConfig.AuditDisabled
            AutoExpandingArchiveEnabled = $orgConfig.AutoExpandingArchive
            CustomerFeedbackEnabled = $orgConfig.CustomerFeedbackEnabled
            OAuth2ClientProfileEnabled = $orgConfig.OAuth2ClientProfileEnabled
        }

        $orgInfo | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Organization_Config.csv") -NoTypeInformation
        Write-ModuleLog "Organization configuration collected" -Level Success

        return $orgInfo
    }
    catch {
        Write-ModuleLog "Failed to collect organization config: $_" -Level Error
        throw
    }
}

function Get-MailboxInventory {
    Write-ModuleLog "Collecting mailbox inventory (this may take several minutes)..." -Level Info

    try {
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties DisplayName,UserPrincipalName,PrimarySmtpAddress,
            RecipientTypeDetails,WhenCreated,WhenMailboxCreated,ArchiveStatus,LitigationHoldEnabled,InPlaceHolds,
            ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward,HiddenFromAddressListsEnabled

        Write-ModuleLog "Processing $($mailboxes.Count) mailboxes..." -Level Info

        $mailboxDetails = $mailboxes | ForEach-Object {
            # Get mailbox statistics
            try {
                $stats = Get-EXOMailboxStatistics -Identity $_.UserPrincipalName -ErrorAction SilentlyContinue
                $itemCount = $stats.ItemCount
                $totalItemSizeMB = if ($stats.TotalItemSize) {
                    [math]::Round(($stats.TotalItemSize.Value.ToString() -replace '.*\(| bytes\)', '') / 1MB, 2)
                } else { 0 }
                $lastLogonTime = $stats.LastLogonTime
            }
            catch {
                $itemCount = 0
                $totalItemSizeMB = 0
                $lastLogonTime = $null
            }

            # Get mailbox quota
            $quota = if ($_.UseDatabaseQuotaDefaults) { 'Default' } else { $_.ProhibitSendReceiveQuota }

            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                UserPrincipalName = $_.UserPrincipalName
                PrimarySmtpAddress = $_.PrimarySmtpAddress
                RecipientTypeDetails = $_.RecipientTypeDetails
                ItemCount = $itemCount
                TotalItemSizeMB = $totalItemSizeMB
                ProhibitSendReceiveQuota = $quota
                ArchiveStatus = $_.ArchiveStatus
                ArchiveState = $_.ArchiveState
                LitigationHoldEnabled = $_.LitigationHoldEnabled
                InPlaceHolds = ($_.InPlaceHolds -join ';')
                HasForwarding = (-not [string]::IsNullOrEmpty($_.ForwardingAddress) -or -not [string]::IsNullOrEmpty($_.ForwardingSmtpAddress))
                ForwardingAddress = $_.ForwardingAddress
                ForwardingSmtpAddress = $_.ForwardingSmtpAddress
                DeliverToMailboxAndForward = $_.DeliverToMailboxAndForward
                HiddenFromAddressListsEnabled = $_.HiddenFromAddressListsEnabled
                WhenCreated = $_.WhenCreated
                WhenMailboxCreated = $_.WhenMailboxCreated
                LastLogonTime = $lastLogonTime
                Identity = $_.Identity
            }
        }

        $mailboxDetails | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Mailboxes.csv") -NoTypeInformation
        Write-ModuleLog "Mailbox inventory collected: $($mailboxes.Count) mailboxes" -Level Success

        # Generate summary
        $summary = [PSCustomObject]@{
            TotalMailboxes = $mailboxes.Count
            UserMailboxes = ($mailboxDetails | Where-Object { $_.RecipientTypeDetails -eq 'UserMailbox' }).Count
            SharedMailboxes = ($mailboxDetails | Where-Object { $_.RecipientTypeDetails -eq 'SharedMailbox' }).Count
            RoomMailboxes = ($mailboxDetails | Where-Object { $_.RecipientTypeDetails -eq 'RoomMailbox' }).Count
            EquipmentMailboxes = ($mailboxDetails | Where-Object { $_.RecipientTypeDetails -eq 'EquipmentMailbox' }).Count
            TotalSizeMB = ($mailboxDetails | Measure-Object -Property TotalItemSizeMB -Sum).Sum
            AverageSizeMB = [math]::Round(($mailboxDetails | Measure-Object -Property TotalItemSizeMB -Average).Average, 2)
            MailboxesWithArchive = ($mailboxDetails | Where-Object { $_.ArchiveStatus -eq 'Active' }).Count
            MailboxesWithLitigationHold = ($mailboxDetails | Where-Object { $_.LitigationHoldEnabled }).Count
            MailboxesWithForwarding = ($mailboxDetails | Where-Object { $_.HasForwarding }).Count
        }

        $summary | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Mailbox_Summary.csv") -NoTypeInformation

        return $mailboxDetails
    }
    catch {
        Write-ModuleLog "Failed to collect mailbox inventory: $_" -Level Error
        throw
    }
}

function Get-InboxRules {
    Write-ModuleLog "Collecting inbox rules..." -Level Info

    try {
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox
        $allRules = @()

        $counter = 0
        foreach ($mailbox in $mailboxes) {
            $counter++
            if ($counter % 50 -eq 0) {
                Write-Progress -Activity "Collecting inbox rules" -Status "$counter of $($mailboxes.Count)" -PercentComplete (($counter / $mailboxes.Count) * 100)
            }

            try {
                $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction SilentlyContinue

                foreach ($rule in $rules) {
                    $allRules += [PSCustomObject]@{
                        Mailbox = $mailbox.UserPrincipalName
                        RuleName = $rule.Name
                        Enabled = $rule.Enabled
                        Description = $rule.Description
                        ForwardTo = ($rule.ForwardTo -join ';')
                        ForwardAsAttachmentTo = ($rule.ForwardAsAttachmentTo -join ';')
                        RedirectTo = ($rule.RedirectTo -join ';')
                        DeleteMessage = $rule.DeleteMessage
                        MoveToFolder = $rule.MoveToFolder
                        Priority = $rule.Priority
                    }
                }
            }
            catch {
                Write-Verbose "Failed to get rules for $($mailbox.UserPrincipalName): $_"
            }
        }

        Write-Progress -Activity "Collecting inbox rules" -Completed

        $allRules | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Inbox_Rules.csv") -NoTypeInformation
        Write-ModuleLog "Inbox rules collected: $($allRules.Count) rules" -Level Success

        return $allRules
    }
    catch {
        Write-ModuleLog "Failed to collect inbox rules: $_" -Level Error
        throw
    }
}

function Get-TransportRules {
    Write-ModuleLog "Collecting transport rules (mail flow rules)..." -Level Info

    try {
        $transportRules = Get-TransportRule

        $ruleDetails = $transportRules | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                State = $_.State
                Mode = $_.Mode
                Priority = $_.Priority
                Description = $_.Description
                Comments = $_.Comments
                SentTo = ($_.SentTo -join ';')
                SentToScope = $_.SentToScope
                From = ($_.From -join ';')
                FromScope = $_.FromScope
                SubjectContainsWords = ($_.SubjectContainsWords -join ';')
                SubjectMatchesPatterns = ($_.SubjectMatchesPatterns -join ';')
                AttachmentNameMatchesPatterns = ($_.AttachmentNameMatchesPatterns -join ';')
                SetSCL = $_.SetSCL
                Quarantine = $_.Quarantine
                RejectMessageReasonText = $_.RejectMessageReasonText
                DeleteMessage = $_.DeleteMessage
                BlindCopyTo = ($_.BlindCopyTo -join ';')
                RedirectMessageTo = ($_.RedirectMessageTo -join ';')
                ModerateMessageByUser = ($_.ModerateMessageByUser -join ';')
                WhenChanged = $_.WhenChanged
            }
        }

        $ruleDetails | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Transport_Rules.csv") -NoTypeInformation
        Write-ModuleLog "Transport rules collected: $($transportRules.Count) rules" -Level Success

        return $ruleDetails
    }
    catch {
        Write-ModuleLog "Failed to collect transport rules: $_" -Level Error
        throw
    }
}

function Get-Connectors {
    Write-ModuleLog "Collecting inbound and outbound connectors..." -Level Info

    try {
        $inboundConnectors = Get-InboundConnector
        $outboundConnectors = Get-OutboundConnector

        # Inbound connectors
        $inboundDetails = $inboundConnectors | ForEach-Object {
            [PSCustomObject]@{
                Direction = 'Inbound'
                Name = $_.Name
                Enabled = $_.Enabled
                ConnectorType = $_.ConnectorType
                SenderDomains = ($_.SenderDomains -join ';')
                TlsSenderCertificateName = $_.TlsSenderCertificateName
                RequireTls = $_.RequireTls
                RestrictDomainsToIPAddresses = $_.RestrictDomainsToIPAddresses
                RestrictedIPAddresses = ($_.RestrictedIPAddresses -join ';')
                WhenChanged = $_.WhenChanged
            }
        }

        # Outbound connectors
        $outboundDetails = $outboundConnectors | ForEach-Object {
            [PSCustomObject]@{
                Direction = 'Outbound'
                Name = $_.Name
                Enabled = $_.Enabled
                ConnectorType = $_.ConnectorType
                RecipientDomains = ($_.RecipientDomains -join ';')
                SmartHosts = ($_.SmartHosts -join ';')
                TlsSettings = $_.TlsSettings
                TlsDomain = $_.TlsDomain
                IsTransportRuleScoped = $_.IsTransportRuleScoped
                RouteAllMessagesViaOnPremises = $_.RouteAllMessagesViaOnPremises
                WhenChanged = $_.WhenChanged
            }
        }

        $allConnectors = $inboundDetails + $outboundDetails
        $allConnectors | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Connectors.csv") -NoTypeInformation
        Write-ModuleLog "Connectors collected: $($inboundConnectors.Count) inbound, $($outboundConnectors.Count) outbound" -Level Success

        return $allConnectors
    }
    catch {
        Write-ModuleLog "Failed to collect connectors: $_" -Level Error
        throw
    }
}

function Get-DistributionGroups {
    Write-ModuleLog "Collecting distribution groups..." -Level Info

    try {
        $distGroups = Get-DistributionGroup -ResultSize Unlimited

        $groupDetails = $distGroups | ForEach-Object {
            # Get member count
            try {
                $members = Get-DistributionGroupMember -Identity $_.Identity -ResultSize Unlimited -ErrorAction SilentlyContinue
                $memberCount = if ($members) { $members.Count } else { 0 }
            }
            catch {
                $memberCount = 0
            }

            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                PrimarySmtpAddress = $_.PrimarySmtpAddress
                GroupType = $_.GroupType
                RecipientTypeDetails = $_.RecipientTypeDetails
                MemberCount = $memberCount
                ManagedBy = ($_.ManagedBy -join ';')
                RequireSenderAuthenticationEnabled = $_.RequireSenderAuthenticationEnabled
                ModerationEnabled = $_.ModerationEnabled
                HiddenFromAddressListsEnabled = $_.HiddenFromAddressListsEnabled
                WhenCreated = $_.WhenCreated
                EmailAddresses = ($_.EmailAddresses -join ';')
                Identity = $_.Identity
            }
        }

        $groupDetails | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Distribution_Groups.csv") -NoTypeInformation
        Write-ModuleLog "Distribution groups collected: $($distGroups.Count) groups" -Level Success

        return $groupDetails
    }
    catch {
        Write-ModuleLog "Failed to collect distribution groups: $_" -Level Error
        throw
    }
}

function Get-PublicFolders {
    Write-ModuleLog "Collecting public folders..." -Level Info

    try {
        $publicFolders = Get-PublicFolder -Recurse -ResultSize Unlimited -ErrorAction SilentlyContinue

        if ($publicFolders) {
            $folderDetails = $publicFolders | ForEach-Object {
                # Get statistics
                try {
                    $stats = Get-PublicFolderStatistics -Identity $_.Identity -ErrorAction SilentlyContinue
                    $itemCount = $stats.ItemCount
                    $totalItemSizeMB = if ($stats.TotalItemSize) {
                        [math]::Round(($stats.TotalItemSize.Value.ToString() -replace '.*\(| bytes\)', '') / 1MB, 2)
                    } else { 0 }
                }
                catch {
                    $itemCount = 0
                    $totalItemSizeMB = 0
                }

                [PSCustomObject]@{
                    Name = $_.Name
                    Identity = $_.Identity
                    FolderPath = $_.FolderPath
                    MailEnabled = $_.MailEnabled
                    ItemCount = $itemCount
                    TotalItemSizeMB = $totalItemSizeMB
                    WhenCreated = $_.WhenCreated
                }
            }

            $folderDetails | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Public_Folders.csv") -NoTypeInformation
            Write-ModuleLog "Public folders collected: $($publicFolders.Count) folders" -Level Success

            return $folderDetails
        }
        else {
            Write-ModuleLog "No public folders found or access denied" -Level Warning
            return @()
        }
    }
    catch {
        Write-ModuleLog "Failed to collect public folders (may not be configured): $_" -Level Warning
        return @()
    }
}

function Get-MobileDevices {
    Write-ModuleLog "Collecting mobile device partnerships..." -Level Info

    try {
        $mobileDevices = Get-MobileDevice -ResultSize Unlimited

        $deviceDetails = $mobileDevices | ForEach-Object {
            [PSCustomObject]@{
                DeviceId = $_.DeviceId
                DeviceModel = $_.DeviceModel
                DeviceOS = $_.DeviceOS
                DeviceType = $_.DeviceType
                DeviceName = $_.FriendlyName
                UserDisplayName = $_.UserDisplayName
                FirstSyncTime = $_.FirstSyncTime
                WhenCreated = $_.WhenCreated
                DeviceAccessState = $_.DeviceAccessState
                DeviceAccessStateReason = $_.DeviceAccessStateReason
                Identity = $_.Identity
            }
        }

        $deviceDetails | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Mobile_Devices.csv") -NoTypeInformation
        Write-ModuleLog "Mobile devices collected: $($mobileDevices.Count) devices" -Level Success

        return $deviceDetails
    }
    catch {
        Write-ModuleLog "Failed to collect mobile devices: $_" -Level Error
        throw
    }
}

function Get-AcceptedDomains {
    Write-ModuleLog "Collecting accepted domains..." -Level Info

    try {
        $domains = Get-AcceptedDomain

        $domainDetails = $domains | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                DomainName = $_.DomainName
                DomainType = $_.DomainType
                Default = $_.Default
                MatchSubDomains = $_.MatchSubDomains
                OutboundOnly = $_.OutboundOnly
                WhenCreated = $_.WhenCreated
            }
        }

        $domainDetails | Export-Csv -Path (Join-Path $OutputFolder "Exchange\Exchange_Accepted_Domains.csv") -NoTypeInformation
        Write-ModuleLog "Accepted domains collected: $($domains.Count) domains" -Level Success

        return $domainDetails
    }
    catch {
        Write-ModuleLog "Failed to collect accepted domains: $_" -Level Error
        throw
    }
}

#endregion

#region Main Execution

try {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Exchange Online Audit Module" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    # Ensure output folder exists
    $exchangeFolder = Join-Path $OutputFolder "Exchange"
    if (-not (Test-Path $exchangeFolder)) {
        New-Item -ItemType Directory -Path $exchangeFolder -Force | Out-Null
    }

    # Connect to Exchange Online
    Connect-ToExchangeOnline

    # Collect organization configuration
    $orgInfo = Get-OrganizationInformation

    # Collect accepted domains
    $domains = Get-AcceptedDomains

    # Collect mailbox inventory
    $mailboxes = Get-MailboxInventory

    # Collect inbox rules
    $inboxRules = Get-InboxRules

    # Collect transport rules
    $transportRules = Get-TransportRules

    # Collect connectors
    $connectors = Get-Connectors

    # Collect distribution groups
    $distGroups = Get-DistributionGroups

    # Collect public folders
    $publicFolders = Get-PublicFolders

    # Collect mobile devices
    $mobileDevices = Get-MobileDevices

    # Generate summary
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   Exchange Online Audit Completed!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Organization: $($orgInfo.DisplayName)" -ForegroundColor White
    Write-Host "  Mailboxes: $($mailboxes.Count)" -ForegroundColor White
    Write-Host "  Distribution Groups: $($distGroups.Count)" -ForegroundColor White
    Write-Host "  Inbox Rules: $($inboxRules.Count)" -ForegroundColor White
    Write-Host "  Transport Rules: $($transportRules.Count)" -ForegroundColor White
    Write-Host "  Connectors: $($connectors.Count)" -ForegroundColor White
    Write-Host "  Mobile Devices: $($mobileDevices.Count)" -ForegroundColor White
    Write-Host "  Public Folders: $($publicFolders.Count)" -ForegroundColor White
    Write-Host "  Accepted Domains: $($domains.Count)" -ForegroundColor White
    Write-Host ""

    # Return statistics
    return @{
        Organization = $orgInfo.DisplayName
        Mailboxes = $mailboxes.Count
        DistributionGroups = $distGroups.Count
        InboxRules = $inboxRules.Count
        TransportRules = $transportRules.Count
        Connectors = $connectors.Count
        MobileDevices = $mobileDevices.Count
        PublicFolders = $publicFolders.Count
        AcceptedDomains = $domains.Count
    }
}
catch {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "   Exchange Online Audit Failed!" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    throw
}
finally {
    # Disconnect from Exchange Online
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-ModuleLog "Disconnected from Exchange Online" -Level Info
    }
    catch {
        # Ignore disconnect errors
    }
}

#endregion

