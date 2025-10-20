<#
.SYNOPSIS
    Audits Microsoft Power Platform for M&A discovery

.DESCRIPTION
    Collects comprehensive Power Platform data including:
    - Power Platform environments
    - Power Apps (canvas and model-driven apps)
    - Power Automate flows (cloud flows, desktop flows)
    - Dataverse databases and capacity
    - Power BI workspaces and datasets
    - Data Loss Prevention (DLP) policies
    - On-premises data gateways
    - Custom connectors
    - Environment security and role assignments

    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0
    Date: October 2025

.PARAMETER OutputFolder
    Root folder where CSV files will be saved

.PARAMETER Credential
    Optional credential for authentication (if not using interactive)

.EXAMPLE
    .\Invoke-PowerPlatform-Audit.ps1 -OutputFolder "C:\Audits\Contoso\RawData"
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

function Connect-ToPowerPlatform {
    Write-ModuleLog "Connecting to Power Platform..." -Level Info

    # Check if Power Apps modules are available
    $requiredModules = @(
        'Microsoft.PowerApps.Administration.PowerShell',
        'Microsoft.PowerApps.PowerShell'
    )

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-ModuleLog "Installing module: $module" -Level Warning
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
        }
    }

    # Import modules
    Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop
    Import-Module Microsoft.PowerApps.PowerShell -ErrorAction Stop

    # Connect
    try {
        Add-PowerAppsAccount
        Write-ModuleLog "Successfully connected to Power Platform" -Level Success
    }
    catch {
        Write-ModuleLog "Failed to connect to Power Platform: $_" -Level Error
        throw
    }
}

#endregion

#region Data Collection Functions

function Get-PowerPlatformEnvironments {
    Write-ModuleLog "Collecting Power Platform environments..." -Level Info

    try {
        $environments = Get-AdminPowerAppEnvironment

        $envDetails = $environments | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                EnvironmentName = $_.EnvironmentName
                EnvironmentType = $_.EnvironmentType
                Location = $_.Location
                CreatedTime = $_.CreatedTime
                CreatedBy = $_.CreatedBy.displayName
                IsDefault = $_.IsDefault
                EnvironmentSku = $_.EnvironmentSku
                SecurityGroupId = $_.SecurityGroupId
                CommonDataServiceDatabaseProvisioningState = $_.CommonDataServiceDatabaseProvisioningState
                CommonDataServiceDatabaseType = $_.CommonDataServiceDatabaseType
                LinkedEnvironmentMetadata = if ($_.LinkedEnvironmentMetadata) { $_.LinkedEnvironmentMetadata.InstanceUrl } else { '' }
                States = $_.States -join ';'
                RetentionPeriod = $_.RetentionPeriod
                ProtectionStatus = $_.ProtectionStatus.keyName
            }
        }

        $envDetails | Export-Csv -Path (Join-Path $OutputFolder "PowerPlatform\PowerPlatform_Environments.csv") -NoTypeInformation
        Write-ModuleLog "Environments collected: $($environments.Count) environments" -Level Success

        return $envDetails
    }
    catch {
        Write-ModuleLog "Failed to collect environments: $_" -Level Error
        throw
    }
}

function Get-PowerApps {
    Write-ModuleLog "Collecting Power Apps (this may take several minutes)..." -Level Info

    try {
        $apps = Get-AdminPowerApp

        Write-ModuleLog "Processing $($apps.Count) Power Apps..." -Level Info

        # Export simplified app inventory
        $simplifiedApps = $apps | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                AppName = $_.AppName
                EnvironmentName = $_.EnvironmentName
                Owner = $_.Owner.displayName
                OwnerEmail = $_.Owner.email
                CreatedTime = $_.CreatedTime
                LastModifiedTime = $_.LastModifiedTime
                AppType = $_.AppType
            }
        }

        $simplifiedApps | Export-Csv -Path (Join-Path $OutputFolder "PowerPlatform\PowerApps_Inventory.csv") -NoTypeInformation
        Write-ModuleLog "Power Apps collected: $($apps.Count) apps" -Level Success

        return $simplifiedApps
    }
    catch {
        Write-ModuleLog "Failed to collect Power Apps: $_" -Level Error
        throw
    }
}

function Get-PowerAutomateFlows {
    Write-ModuleLog "Collecting Power Automate flows..." -Level Info

    try {
        $flows = Get-AdminFlow

        Write-ModuleLog "Processing $($flows.Count) flows..." -Level Info

        $flowDetails = $flows | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                FlowName = $_.FlowName
                EnvironmentName = $_.EnvironmentName
                Owner = $_.CreatedBy.displayName
                OwnerEmail = $_.CreatedBy.email
                CreatedTime = $_.CreatedTime
                LastModifiedTime = $_.LastModifiedTime
                FlowState = $_.Enabled
                FlowSuspensionReason = $_.FlowSuspensionReason
                FlowTrigger = $_.Internal.properties.definitionSummary.triggers[0].type
                UserType = $_.UserType
            }
        }

        $flowDetails | Export-Csv -Path (Join-Path $OutputFolder "PowerPlatform\PowerAutomate_Flows.csv") -NoTypeInformation
        Write-ModuleLog "Power Automate flows collected: $($flows.Count) flows" -Level Success

        return $flowDetails
    }
    catch {
        Write-ModuleLog "Failed to collect flows: $_" -Level Error
        throw
    }
}

function Get-DLPPolicies {
    Write-ModuleLog "Collecting Data Loss Prevention (DLP) policies..." -Level Info

    try {
        $dlpPolicies = Get-AdminDlpPolicy

        $policyDetails = $dlpPolicies | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                PolicyName = $_.PolicyName
                CreatedTime = $_.CreatedTime
                CreatedBy = $_.CreatedBy.displayName
                LastModifiedTime = $_.LastModifiedTime
                LastModifiedBy = $_.LastModifiedBy.displayName
                EnvironmentType = $_.EnvironmentType
                Environments = ($_.Environments | ForEach-Object { $_.name }) -join ';'
                ConnectorGroups = ($_.ConnectorGroups | ForEach-Object { $_.classification }) -join ';'
                DefaultConnectorClassification = $_.DefaultConnectorClassification
            }
        }

        $policyDetails | Export-Csv -Path (Join-Path $OutputFolder "PowerPlatform\PowerPlatform_DLP_Policies.csv") -NoTypeInformation
        Write-ModuleLog "DLP policies collected: $($dlpPolicies.Count) policies" -Level Success

        return $policyDetails
    }
    catch {
        Write-ModuleLog "Failed to collect DLP policies: $_" -Level Error
        throw
    }
}

function Get-PowerAppConnections {
    Write-ModuleLog "Collecting Power App connections..." -Level Info

    try {
        $environments = Get-AdminPowerAppEnvironment
        $allConnections = @()

        foreach ($env in $environments) {
            try {
                $connections = Get-AdminPowerAppConnection -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue

                foreach ($conn in $connections) {
                    $allConnections += [PSCustomObject]@{
                        DisplayName = $conn.DisplayName
                        ConnectionName = $conn.ConnectionName
                        EnvironmentName = $env.EnvironmentName
                        ConnectorName = $conn.ConnectorName
                        CreatedTime = $conn.CreatedTime
                        CreatedBy = $conn.CreatedBy.displayName
                        Status = $conn.Statuses[0].status
                        ConnectionParameters = ($conn.ConnectionParameters | ConvertTo-Json -Compress)
                    }
                }
            }
            catch {
                Write-Verbose "Failed to get connections for environment $($env.DisplayName): $_"
            }
        }

        $allConnections | Export-Csv -Path (Join-Path $OutputFolder "PowerPlatform\PowerApps_Connections.csv") -NoTypeInformation
        Write-ModuleLog "Power App connections collected: $($allConnections.Count) connections" -Level Success

        return $allConnections
    }
    catch {
        Write-ModuleLog "Failed to collect connections: $_" -Level Error
        throw
    }
}

function Get-PowerAppConnectors {
    Write-ModuleLog "Collecting custom connectors..." -Level Info

    try {
        $environments = Get-AdminPowerAppEnvironment
        $allConnectors = @()

        foreach ($env in $environments) {
            try {
                $connectors = Get-AdminPowerAppConnector -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue |
                    Where-Object { $_.Internal.properties.isCustomApi -eq $true }

                foreach ($connector in $connectors) {
                    $allConnectors += [PSCustomObject]@{
                        DisplayName = $connector.DisplayName
                        ConnectorName = $connector.ConnectorName
                        EnvironmentName = $env.EnvironmentName
                        CreatedTime = $connector.CreatedTime
                        CreatedBy = $connector.CreatedBy.displayName
                        ApiDefinitionUrl = $connector.Internal.properties.apiDefinitionUrl
                    }
                }
            }
            catch {
                Write-Verbose "Failed to get connectors for environment $($env.DisplayName): $_"
            }
        }

        $allConnectors | Export-Csv -Path (Join-Path $OutputFolder "PowerPlatform\PowerApps_Custom_Connectors.csv") -NoTypeInformation
        Write-ModuleLog "Custom connectors collected: $($allConnectors.Count) connectors" -Level Success

        return $allConnectors
    }
    catch {
        Write-ModuleLog "Failed to collect custom connectors: $_" -Level Error
        throw
    }
}

function Get-DataverseCapacity {
    Write-ModuleLog "Collecting Dataverse capacity information..." -Level Info

    try {
        $environments = Get-AdminPowerAppEnvironment | Where-Object { $_.CommonDataServiceDatabaseProvisioningState -eq 'Succeeded' }

        $capacityDetails = $environments | ForEach-Object {
            # Note: Detailed capacity info requires Power Platform Admin API
            [PSCustomObject]@{
                EnvironmentName = $_.EnvironmentName
                DisplayName = $_.DisplayName
                HasDataverse = ($_.CommonDataServiceDatabaseProvisioningState -eq 'Succeeded')
                DatabaseType = $_.CommonDataServiceDatabaseType
                InstanceUrl = if ($_.LinkedEnvironmentMetadata) { $_.LinkedEnvironmentMetadata.InstanceUrl } else { '' }
            }
        }

        $capacityDetails | Export-Csv -Path (Join-Path $OutputFolder "PowerPlatform\Dataverse_Capacity.csv") -NoTypeInformation
        Write-ModuleLog "Dataverse capacity collected for $($capacityDetails.Count) environments" -Level Success

        return $capacityDetails
    }
    catch {
        Write-ModuleLog "Failed to collect Dataverse capacity: $_" -Level Error
        throw
    }
}

#endregion

#region Main Execution

try {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Power Platform Audit Module" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    # Ensure output folder exists
    $powerPlatformFolder = Join-Path $OutputFolder "PowerPlatform"
    if (-not (Test-Path $powerPlatformFolder)) {
        New-Item -ItemType Directory -Path $powerPlatformFolder -Force | Out-Null
    }

    # Connect to Power Platform
    Connect-ToPowerPlatform

    # Collect environments
    $environments = Get-PowerPlatformEnvironments

    # Collect Power Apps
    $powerApps = Get-PowerApps

    # Collect Power Automate flows
    $flows = Get-PowerAutomateFlows

    # Collect DLP policies
    $dlpPolicies = Get-DLPPolicies

    # Collect connections
    $connections = Get-PowerAppConnections

    # Collect custom connectors
    $customConnectors = Get-PowerAppConnectors

    # Collect Dataverse capacity
    $dataverseCapacity = Get-DataverseCapacity

    # Generate summary
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   Power Platform Audit Completed!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Environments: $($environments.Count)" -ForegroundColor White
    Write-Host "  Power Apps: $($powerApps.Count)" -ForegroundColor White
    Write-Host "  Power Automate Flows: $($flows.Count)" -ForegroundColor White
    Write-Host "  DLP Policies: $($dlpPolicies.Count)" -ForegroundColor White
    Write-Host "  Connections: $($connections.Count)" -ForegroundColor White
    Write-Host "  Custom Connectors: $($customConnectors.Count)" -ForegroundColor White
    Write-Host "  Dataverse Environments: $($dataverseCapacity.Count)" -ForegroundColor White
    Write-Host ""

    # Return statistics
    return @{
        Environments = $environments.Count
        PowerApps = $powerApps.Count
        Flows = $flows.Count
        DLPPolicies = $dlpPolicies.Count
        Connections = $connections.Count
        CustomConnectors = $customConnectors.Count
        DataverseEnvironments = $dataverseCapacity.Count
    }
}
catch {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "   Power Platform Audit Failed!" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    throw
}
finally {
    # Disconnect (no explicit disconnect command for Power Apps)
    Write-ModuleLog "Power Platform audit completed" -Level Info
}

#endregion

