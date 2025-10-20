<#
.SYNOPSIS
    Audits Microsoft Entra ID (Azure AD) configuration for M&A discovery

.DESCRIPTION
    Collects comprehensive Entra ID/Azure AD data including:
    - Tenant information and registered domains
    - User inventory (cloud-only, synced, guest, MFA status)
    - Privileged role assignments
    - Conditional Access policies
    - Enterprise applications and service principals
    - OAuth grants and permissions
    - Device inventory
    - License assignments
    - Authentication methods
    - Security defaults and legacy authentication

    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0
    Date: October 2025

.PARAMETER OutputFolder
    Root folder where CSV files will be saved

.PARAMETER Credential
    Optional credential for authentication (if not using interactive)

.EXAMPLE
    .\Invoke-EntraID-Audit.ps1 -OutputFolder "C:\Audits\Contoso\RawData"
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

function Test-EntraIDConnection {
    try {
        $context = Get-MgContext
        if ($context) {
            Write-ModuleLog "Connected to tenant: $($context.TenantId)" -Level Success
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Connect-ToEntraID {
    Write-ModuleLog "Connecting to Microsoft Entra ID (Azure AD)..." -Level Info

    # Check if Microsoft.Graph module is available
    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Applications',
        'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.DeviceManagement')

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-ModuleLog "Installing module: $module" -Level Warning
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
        }
    }

    # Import modules
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module Microsoft.Graph.Groups -ErrorAction Stop
    Import-Module Microsoft.Graph.Applications -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
    Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue

    # Connect with required permissions
    $scopes = @(
        'User.Read.All', 'Group.Read.All', 'Directory.Read.All',
        'Application.Read.All', 'RoleManagement.Read.All',
        'Policy.Read.All', 'Organization.Read.All',
        'UserAuthenticationMethod.Read.All', 'AuditLog.Read.All'
    )

    try {
        if (Test-EntraIDConnection) {
            Write-ModuleLog "Already connected to Entra ID" -Level Success
        }
        else {
            Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
            Write-ModuleLog "Successfully connected to Entra ID" -Level Success
        }
    }
    catch {
        Write-ModuleLog "Failed to connect to Entra ID: $_" -Level Error
        throw
    }
}

#endregion

#region Data Collection Functions

function Get-TenantInformation {
    Write-ModuleLog "Collecting tenant information..." -Level Info

    try {
        $org = Get-MgOrganization
        $domains = Get-MgDomain

        $tenantInfo = [PSCustomObject]@{
            TenantId = $org.Id
            DisplayName = $org.DisplayName
            TenantType = $org.TenantType
            InitialDomain = ($domains | Where-Object { $_.IsInitial }).Id
            DefaultDomain = ($domains | Where-Object { $_.IsDefault }).Id
            VerifiedDomainsCount = ($domains | Where-Object { $_.IsVerified }).Count
            CreatedDateTime = $org.CreatedDateTime
            Country = $org.Country
            CountryLetterCode = $org.CountryLetterCode
            PreferredLanguage = $org.PreferredLanguage
            SecurityDefaults = $org.SecurityComplianceNotificationMails -join ';'
            TechnicalNotificationMails = $org.TechnicalNotificationMails -join ';'
            OnPremisesSyncEnabled = $org.OnPremisesSyncEnabled
            OnPremisesLastSyncDateTime = $org.OnPremisesLastSyncDateTime
            DirectorySizeQuota = $org.DirectoryQuota.Total
            DirectorySizeUsed = $org.DirectoryQuota.Used
        }

        $tenantInfo | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Tenant_Info.csv") -NoTypeInformation
        Write-ModuleLog "Tenant information collected" -Level Success

        # Export domains separately
        $domainDetails = $domains | Select-Object Id, AuthenticationType, IsVerified, IsDefault, IsInitial,
            IsAdminManaged, IsRoot, SupportedServices, @{N='Capabilities';E={$_.SupportedServices -join ';'}}

        $domainDetails | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Domains.csv") -NoTypeInformation
        Write-ModuleLog "Domain information collected: $($domains.Count) domains" -Level Success

        return $tenantInfo
    }
    catch {
        Write-ModuleLog "Failed to collect tenant information: $_" -Level Error
        throw
    }
}

function Get-UserInventory {
    Write-ModuleLog "Collecting user inventory (this may take several minutes)..." -Level Info

    try {
        $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,Mail,AccountEnabled,
            UserType,CreatedDateTime,SignInActivity,OnPremisesSyncEnabled,AssignedLicenses,
            PasswordPolicies,LastPasswordChangeDateTime,Department,JobTitle,CompanyName

        Write-ModuleLog "Processing $($users.Count) users..." -Level Info

        $userDetails = $users | ForEach-Object {
            $licenseNames = ($_.AssignedLicenses | ForEach-Object { $_.SkuId }) -join ';'
            $lastSignIn = $_.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = if ($lastSignIn) { [math]::Round(((Get-Date) - $lastSignIn).TotalDays) } else { 9999 }

            [PSCustomObject]@{
                UserPrincipalName = $_.UserPrincipalName
                DisplayName = $_.DisplayName
                Mail = $_.Mail
                AccountEnabled = $_.AccountEnabled
                UserType = $_.UserType
                IsGuest = ($_.UserType -eq 'Guest')
                CreatedDateTime = $_.CreatedDateTime
                LastSignInDateTime = $lastSignIn
                DaysSinceLastSignIn = $daysSinceSignIn
                IsStale = ($daysSinceSignIn -gt 90)
                OnPremisesSyncEnabled = $_.OnPremisesSyncEnabled
                IsSynced = ($null -ne $_.OnPremisesSyncEnabled -and $_.OnPremisesSyncEnabled)
                IsCloudOnly = ($null -eq $_.OnPremisesSyncEnabled -or -not $_.OnPremisesSyncEnabled)
                LicenseCount = $_.AssignedLicenses.Count
                LicenseSkuIds = $licenseNames
                Department = $_.Department
                JobTitle = $_.JobTitle
                CompanyName = $_.CompanyName
                PasswordNeverExpires = ($_.PasswordPolicies -like '*DisablePasswordExpiration*')
                LastPasswordChangeDateTime = $_.LastPasswordChangeDateTime
                ObjectId = $_.Id
            }
        }

        $userDetails | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Users.csv") -NoTypeInformation
        Write-ModuleLog "User inventory collected: $($users.Count) users" -Level Success

        # Generate user summary
        $summary = [PSCustomObject]@{
            TotalUsers = $users.Count
            EnabledUsers = ($userDetails | Where-Object { $_.AccountEnabled }).Count
            DisabledUsers = ($userDetails | Where-Object { -not $_.AccountEnabled }).Count
            CloudOnlyUsers = ($userDetails | Where-Object { $_.IsCloudOnly }).Count
            SyncedUsers = ($userDetails | Where-Object { $_.IsSynced }).Count
            GuestUsers = ($userDetails | Where-Object { $_.IsGuest }).Count
            LicensedUsers = ($userDetails | Where-Object { $_.LicenseCount -gt 0 }).Count
            StaleUsers = ($userDetails | Where-Object { $_.IsStale }).Count
            PasswordNeverExpires = ($userDetails | Where-Object { $_.PasswordNeverExpires }).Count
        }

        $summary | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_User_Summary.csv") -NoTypeInformation

        return $userDetails
    }
    catch {
        Write-ModuleLog "Failed to collect user inventory: $_" -Level Error
        throw
    }
}

function Get-PrivilegedRoleAssignments {
    Write-ModuleLog "Collecting privileged role assignments..." -Level Info

    try {
        # Get all directory roles
        $roles = Get-MgDirectoryRole -All

        $privilegedRoles = @(
            'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
            'Exchange Administrator', 'SharePoint Administrator', 'User Administrator',
            'Billing Administrator', 'Password Administrator', 'Helpdesk Administrator',
            'Application Administrator', 'Cloud Application Administrator',
            'Authentication Administrator', 'Privileged Authentication Administrator',
            'Conditional Access Administrator', 'Intune Administrator', 'Global Reader'
        )

        $roleAssignments = @()

        foreach ($role in $roles) {
            if ($role.DisplayName -in $privilegedRoles) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All

                foreach ($member in $members) {
                    $roleAssignments += [PSCustomObject]@{
                        RoleName = $role.DisplayName
                        RoleId = $role.Id
                        MemberId = $member.Id
                        MemberType = $member.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
                        AssignmentType = 'Direct'
                    }
                }

                Write-Verbose "$($role.DisplayName): $($members.Count) members"
            }
        }

        $roleAssignments | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Privileged_Role_Assignments.csv") -NoTypeInformation
        Write-ModuleLog "Privileged role assignments collected: $($roleAssignments.Count) assignments" -Level Success

        return $roleAssignments
    }
    catch {
        Write-ModuleLog "Failed to collect role assignments: $_" -Level Error
        throw
    }
}

function Get-ConditionalAccessPolicies {
    Write-ModuleLog "Collecting Conditional Access policies..." -Level Info

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All

        $policyDetails = $policies | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                State = $_.State
                Id = $_.Id
                CreatedDateTime = $_.CreatedDateTime
                ModifiedDateTime = $_.ModifiedDateTime
                IncludeUsers = $_.Conditions.Users.IncludeUsers -join ';'
                ExcludeUsers = $_.Conditions.Users.ExcludeUsers -join ';'
                IncludeGroups = $_.Conditions.Users.IncludeGroups -join ';'
                ExcludeGroups = $_.Conditions.Users.ExcludeGroups -join ';'
                IncludeApplications = $_.Conditions.Applications.IncludeApplications -join ';'
                ExcludeApplications = $_.Conditions.Applications.ExcludeApplications -join ';'
                ClientAppTypes = $_.Conditions.ClientAppTypes -join ';'
                IncludeLocations = $_.Conditions.Locations.IncludeLocations -join ';'
                ExcludeLocations = $_.Conditions.Locations.ExcludeLocations -join ';'
                IncludePlatforms = $_.Conditions.Platforms.IncludePlatforms -join ';'
                ExcludePlatforms = $_.Conditions.Platforms.ExcludePlatforms -join ';'
                GrantControls = $_.GrantControls.BuiltInControls -join ';'
                GrantOperator = $_.GrantControls.Operator
                SessionControls = if ($_.SessionControls) { 'Yes' } else { 'No' }
            }
        }

        $policyDetails | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Conditional_Access_Policies.csv") -NoTypeInformation
        Write-ModuleLog "Conditional Access policies collected: $($policies.Count) policies" -Level Success

        return $policyDetails
    }
    catch {
        Write-ModuleLog "Failed to collect Conditional Access policies: $_" -Level Error
        throw
    }
}

function Get-EnterpriseApplications {
    Write-ModuleLog "Collecting enterprise applications and service principals..." -Level Info

    try {
        $servicePrincipals = Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,AppDisplayName,
            ServicePrincipalType,AccountEnabled,SignInAudience,CreatedDateTime,Tags,AppOwnerOrganizationId

        $spDetails = $servicePrincipals | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                AppDisplayName = $_.AppDisplayName
                AppId = $_.AppId
                ServicePrincipalType = $_.ServicePrincipalType
                AccountEnabled = $_.AccountEnabled
                SignInAudience = $_.SignInAudience
                CreatedDateTime = $_.CreatedDateTime
                IsMicrosoftApp = ($_.AppOwnerOrganizationId -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a')
                Tags = $_.Tags -join ';'
                ObjectId = $_.Id
            }
        }

        $spDetails | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Service_Principals.csv") -NoTypeInformation
        Write-ModuleLog "Service principals collected: $($servicePrincipals.Count) applications" -Level Success

        return $spDetails
    }
    catch {
        Write-ModuleLog "Failed to collect service principals: $_" -Level Error
        throw
    }
}

function Get-ApplicationRegistrations {
    Write-ModuleLog "Collecting application registrations..." -Level Info

    try {
        $apps = Get-MgApplication -All -Property Id,AppId,DisplayName,CreatedDateTime,SignInAudience,
            PublisherDomain,PasswordCredentials,KeyCredentials,RequiredResourceAccess

        $appDetails = $apps | ForEach-Object {
            $secretCount = if ($_.PasswordCredentials) { $_.PasswordCredentials.Count } else { 0 }
            $certCount = if ($_.KeyCredentials) { $_.KeyCredentials.Count } else { 0 }
            $oldestSecret = if ($_.PasswordCredentials) { 
                ($_.PasswordCredentials | Sort-Object StartDateTime | Select-Object -First 1).StartDateTime 
            } else { $null }
            $expiringSoon = if ($_.PasswordCredentials) {
                ($_.PasswordCredentials | Where-Object { $_.EndDateTime -lt (Get-Date).AddDays(30) }).Count
            } else { 0 }

            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                AppId = $_.AppId
                SignInAudience = $_.SignInAudience
                PublisherDomain = $_.PublisherDomain
                CreatedDateTime = $_.CreatedDateTime
                SecretCount = $secretCount
                CertificateCount = $certCount
                OldestSecretDate = $oldestSecret
                SecretsExpiringSoon = $expiringSoon
                APIPermissionsCount = if ($_.RequiredResourceAccess) { $_.RequiredResourceAccess.Count } else { 0 }
                ObjectId = $_.Id
            }
        }

        $appDetails | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_App_Registrations.csv") -NoTypeInformation
        Write-ModuleLog "Application registrations collected: $($apps.Count) apps" -Level Success

        return $appDetails
    }
    catch {
        Write-ModuleLog "Failed to collect application registrations: $_" -Level Error
        throw
    }
}

function Get-DeviceInventory {
    Write-ModuleLog "Collecting device inventory..." -Level Info

    try {
        $devices = Get-MgDevice -All -Property Id,DisplayName,DeviceId,OperatingSystem,OperatingSystemVersion,
            AccountEnabled,TrustType,ApproximateLastSignInDateTime,RegistrationDateTime,IsCompliant,IsManaged

        $deviceDetails = $devices | ForEach-Object {
            $lastSignIn = $_.ApproximateLastSignInDateTime
            $daysSinceSignIn = if ($lastSignIn) { [math]::Round(((Get-Date) - $lastSignIn).TotalDays) } else { 9999 }

            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                DeviceId = $_.DeviceId
                OperatingSystem = $_.OperatingSystem
                OperatingSystemVersion = $_.OperatingSystemVersion
                AccountEnabled = $_.AccountEnabled
                TrustType = $_.TrustType
                IsCompliant = $_.IsCompliant
                IsManaged = $_.IsManaged
                RegistrationDateTime = $_.RegistrationDateTime
                ApproximateLastSignInDateTime = $lastSignIn
                DaysSinceLastSignIn = $daysSinceSignIn
                IsStale = ($daysSinceSignIn -gt 90)
                ObjectId = $_.Id
            }
        }

        $deviceDetails | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Devices.csv") -NoTypeInformation
        Write-ModuleLog "Device inventory collected: $($devices.Count) devices" -Level Success

        # Generate device summary
        $summary = [PSCustomObject]@{
            TotalDevices = $devices.Count
            EnabledDevices = ($deviceDetails | Where-Object { $_.AccountEnabled }).Count
            DisabledDevices = ($deviceDetails | Where-Object { -not $_.AccountEnabled }).Count
            CompliantDevices = ($deviceDetails | Where-Object { $_.IsCompliant }).Count
            ManagedDevices = ($deviceDetails | Where-Object { $_.IsManaged }).Count
            StaleDevices = ($deviceDetails | Where-Object { $_.IsStale }).Count
            WindowsDevices = ($deviceDetails | Where-Object { $_.OperatingSystem -like 'Windows*' }).Count
            MacDevices = ($deviceDetails | Where-Object { $_.OperatingSystem -like 'Mac*' }).Count
            LinuxDevices = ($deviceDetails | Where-Object { $_.OperatingSystem -like 'Linux*' }).Count
            AndroidDevices = ($deviceDetails | Where-Object { $_.OperatingSystem -like 'Android*' }).Count
            iOSDevices = ($deviceDetails | Where-Object { $_.OperatingSystem -like 'iOS*' }).Count
        }

        $summary | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Device_Summary.csv") -NoTypeInformation

        return $deviceDetails
    }
    catch {
        Write-ModuleLog "Failed to collect device inventory: $_" -Level Error
        throw
    }
}

function Get-LicenseInventory {
    Write-ModuleLog "Collecting license inventory..." -Level Info

    try {
        $subscribedSkus = Get-MgSubscribedSku -All

        $licenseDetails = $subscribedSkus | ForEach-Object {
            [PSCustomObject]@{
                SkuId = $_.SkuId
                SkuPartNumber = $_.SkuPartNumber
                ProductName = $_.SkuPartNumber
                Enabled = $_.PrepaidUnits.Enabled
                Suspended = $_.PrepaidUnits.Suspended
                Warning = $_.PrepaidUnits.Warning
                ConsumedUnits = $_.ConsumedUnits
                AvailableUnits = $_.PrepaidUnits.Enabled - $_.ConsumedUnits
                UtilizationPercent = if ($_.PrepaidUnits.Enabled -gt 0) { 
                    [math]::Round(($_.ConsumedUnits / $_.PrepaidUnits.Enabled) * 100, 2) 
                } else { 0 }
                CapabilityStatus = $_.CapabilityStatus
                AppliesTo = $_.AppliesTo
            }
        }

        $licenseDetails | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Licenses.csv") -NoTypeInformation
        Write-ModuleLog "License inventory collected: $($subscribedSkus.Count) SKUs" -Level Success

        return $licenseDetails
    }
    catch {
        Write-ModuleLog "Failed to collect license inventory: $_" -Level Error
        throw
    }
}

function Get-GroupInventory {
    Write-ModuleLog "Collecting group inventory..." -Level Info

    try {
        $groups = Get-MgGroup -All -Property Id,DisplayName,GroupTypes,MailEnabled,SecurityEnabled,
            Visibility,CreatedDateTime,MembershipRule,MembershipRuleProcessingState

        Write-ModuleLog "Processing $($groups.Count) groups..." -Level Info

        $groupDetails = $groups | ForEach-Object {
            # Get member count
            try {
                $members = Get-MgGroupMember -GroupId $_.Id -All -ErrorAction SilentlyContinue
                $memberCount = if ($members) { $members.Count } else { 0 }
            }
            catch {
                $memberCount = 0
            }

            $isM365Group = $_.GroupTypes -contains 'Unified'
            $isDynamicGroup = $_.GroupTypes -contains 'DynamicMembership'

            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                GroupType = if ($isM365Group) { 'Microsoft 365' } elseif ($isDynamicGroup) { 'Dynamic' } else { 'Security' }
                MailEnabled = $_.MailEnabled
                SecurityEnabled = $_.SecurityEnabled
                Visibility = $_.Visibility
                MemberCount = $memberCount
                CreatedDateTime = $_.CreatedDateTime
                IsDynamic = $isDynamicGroup
                MembershipRule = $_.MembershipRule
                MembershipRuleProcessingState = $_.MembershipRuleProcessingState
                ObjectId = $_.Id
            }
        }

        $groupDetails | Export-Csv -Path (Join-Path $OutputFolder "EntraID\EntraID_Groups.csv") -NoTypeInformation
        Write-ModuleLog "Group inventory collected: $($groups.Count) groups" -Level Success

        return $groupDetails
    }
    catch {
        Write-ModuleLog "Failed to collect group inventory: $_" -Level Error
        throw
    }
}

#endregion

#region Main Execution

try {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Microsoft Entra ID Audit Module" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    # Ensure output folder exists
    $entraIDFolder = Join-Path $OutputFolder "EntraID"
    if (-not (Test-Path $entraIDFolder)) {
        New-Item -ItemType Directory -Path $entraIDFolder -Force | Out-Null
    }

    # Connect to Entra ID
    Connect-ToEntraID

    # Collect tenant information
    $tenantInfo = Get-TenantInformation

    # Collect user inventory
    $users = Get-UserInventory

    # Collect privileged roles
    $roles = Get-PrivilegedRoleAssignments

    # Collect Conditional Access
    $caPolicies = Get-ConditionalAccessPolicies

    # Collect applications
    $servicePrincipals = Get-EnterpriseApplications
    $appRegistrations = Get-ApplicationRegistrations

    # Collect devices
    $devices = Get-DeviceInventory

    # Collect licenses
    $licenses = Get-LicenseInventory

    # Collect groups
    $groups = Get-GroupInventory

    # Generate summary
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   Entra ID Audit Completed!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Tenant: $($tenantInfo.DisplayName)" -ForegroundColor White
    Write-Host "  Users: $($users.Count)" -ForegroundColor White
    Write-Host "  Groups: $($groups.Count)" -ForegroundColor White
    Write-Host "  Devices: $($devices.Count)" -ForegroundColor White
    Write-Host "  Service Principals: $($servicePrincipals.Count)" -ForegroundColor White
    Write-Host "  App Registrations: $($appRegistrations.Count)" -ForegroundColor White
    Write-Host "  Conditional Access Policies: $($caPolicies.Count)" -ForegroundColor White
    Write-Host "  License SKUs: $($licenses.Count)" -ForegroundColor White
    Write-Host "  Privileged Role Assignments: $($roles.Count)" -ForegroundColor White
    Write-Host ""

    # Return statistics
    return @{
        TenantId = $tenantInfo.TenantId
        TenantName = $tenantInfo.DisplayName
        Users = $users.Count
        Groups = $groups.Count
        Devices = $devices.Count
        ServicePrincipals = $servicePrincipals.Count
        AppRegistrations = $appRegistrations.Count
        ConditionalAccessPolicies = $caPolicies.Count
        Licenses = $licenses.Count
        PrivilegedRoles = $roles.Count
    }
}
catch {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "   Entra ID Audit Failed!" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    throw
}
finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-ModuleLog "Disconnected from Microsoft Graph" -Level Info
    }
    catch {
        # Ignore disconnect errors
    }
}

#endregion

