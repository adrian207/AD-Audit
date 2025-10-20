<#
.SYNOPSIS
    Audits Microsoft 365 Compliance and Security for M&A discovery

.DESCRIPTION
    Collects comprehensive compliance and security data including:
    - Retention policies and labels
    - Data Loss Prevention (DLP) policies
    - Sensitivity labels and label policies
    - eDiscovery cases and holds
    - Information barriers
    - Audit log configuration
    - Compliance alerts and incidents
    - Communication compliance policies
    - Insider risk management settings
    - Records management configuration

    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0
    Date: October 2025

.PARAMETER OutputFolder
    Root folder where CSV files will be saved

.PARAMETER Credential
    Optional credential for authentication (if not using interactive)

.EXAMPLE
    .\Invoke-Compliance-Audit.ps1 -OutputFolder "C:\Audits\Contoso\RawData"
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

function Connect-ToComplianceCenter {
    Write-ModuleLog "Connecting to Security & Compliance Center..." -Level Info

    # Check if Exchange Online Management module is available (also provides Compliance cmdlets)
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-ModuleLog "Installing ExchangeOnlineManagement module..." -Level Warning
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    # Connect to Security & Compliance Center
    try {
        if ($Credential) {
            Connect-IPPSSession -Credential $Credential -ShowBanner:$false
        }
        else {
            Connect-IPPSSession -ShowBanner:$false
        }
        Write-ModuleLog "Successfully connected to Security & Compliance Center" -Level Success
    }
    catch {
        Write-ModuleLog "Failed to connect to Security & Compliance Center: $_" -Level Error
        throw
    }
}

#endregion

#region Data Collection Functions

function Get-RetentionPolicies {
    Write-ModuleLog "Collecting retention policies..." -Level Info

    try {
        $retentionPolicies = Get-RetentionCompliancePolicy

        $policyDetails = $retentionPolicies | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Guid = $_.Guid
                Enabled = $_.Enabled
                Mode = $_.Mode
                Comment = $_.Comment
                Workload = ($_.Workload -join ';')
                ExchangeLocation = ($_.ExchangeLocation -join ';')
                SharePointLocation = ($_.SharePointLocation -join ';')
                OneDriveLocation = ($_.OneDriveLocation -join ';')
                TeamsChannelLocation = ($_.TeamsChannelLocation -join ';')
                TeamsChatLocation = ($_.TeamsChatLocation -join ';')
                WhenCreated = $_.WhenCreated
                WhenChanged = $_.WhenChanged
                CreatedBy = $_.CreatedBy
                ModifiedBy = $_.LastModifiedBy
            }
        }

        $policyDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_Retention_Policies.csv") -NoTypeInformation
        Write-ModuleLog "Retention policies collected: $($retentionPolicies.Count) policies" -Level Success

        return $policyDetails
    }
    catch {
        Write-ModuleLog "Failed to collect retention policies: $_" -Level Error
        throw
    }
}

function Get-RetentionLabels {
    Write-ModuleLog "Collecting retention labels..." -Level Info

    try {
        $retentionLabels = Get-ComplianceTag

        $labelDetails = $retentionLabels | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Guid = $_.Guid
                Comment = $_.Comment
                RetentionAction = $_.RetentionAction
                RetentionDuration = $_.RetentionDuration
                RetentionType = $_.RetentionType
                IsRecordLabel = $_.IsRecordLabel
                RegulatoryRecord = $_.RegulatoryRecord
                EventType = $_.EventType
                WhenCreated = $_.WhenCreated
                WhenChanged = $_.WhenChanged
            }
        }

        $labelDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_Retention_Labels.csv") -NoTypeInformation
        Write-ModuleLog "Retention labels collected: $($retentionLabels.Count) labels" -Level Success

        return $labelDetails
    }
    catch {
        Write-ModuleLog "Failed to collect retention labels: $_" -Level Error
        throw
    }
}

function Get-DLPPoliciesCompliance {
    Write-ModuleLog "Collecting DLP policies..." -Level Info

    try {
        $dlpPolicies = Get-DlpCompliancePolicy

        $policyDetails = $dlpPolicies | ForEach-Object {
            # Get associated rules
            try {
                $rules = Get-DlpComplianceRule -Policy $_.Name -ErrorAction SilentlyContinue
                $ruleCount = if ($rules) { $rules.Count } else { 0 }
            }
            catch {
                $ruleCount = 0
            }

            [PSCustomObject]@{
                Name = $_.Name
                Guid = $_.Guid
                Enabled = $_.Enabled
                Mode = $_.Mode
                Comment = $_.Comment
                Workload = ($_.Workload -join ';')
                ExchangeLocation = ($_.ExchangeLocation -join ';')
                SharePointLocation = ($_.SharePointLocation -join ';')
                OneDriveLocation = ($_.OneDriveLocation -join ';')
                RuleCount = $ruleCount
                WhenCreated = $_.WhenCreated
                WhenChanged = $_.WhenChanged
                CreatedBy = $_.CreatedBy
                ModifiedBy = $_.LastModifiedBy
            }
        }

        $policyDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_DLP_Policies.csv") -NoTypeInformation
        Write-ModuleLog "DLP policies collected: $($dlpPolicies.Count) policies" -Level Success

        return $policyDetails
    }
    catch {
        Write-ModuleLog "Failed to collect DLP policies: $_" -Level Error
        throw
    }
}

function Get-SensitivityLabels {
    Write-ModuleLog "Collecting sensitivity labels..." -Level Info

    try {
        $sensitivityLabels = Get-Label

        $labelDetails = $sensitivityLabels | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Guid = $_.Guid
                DisplayName = $_.DisplayName
                Comment = $_.Comment
                Tooltip = $_.Tooltip
                Disabled = $_.Disabled
                Priority = $_.Priority
                ParentId = $_.ParentId
                EncryptionEnabled = $_.EncryptionEnabled
                EncryptionProtectionType = $_.EncryptionProtectionType
                ContentType = ($_.ContentType -join ';')
                ApplyContentMarkingFooterEnabled = $_.ApplyContentMarkingFooterEnabled
                ApplyContentMarkingHeaderEnabled = $_.ApplyContentMarkingHeaderEnabled
                ApplyWaterMarkingEnabled = $_.ApplyWaterMarkingEnabled
                WhenCreated = $_.WhenCreated
                WhenChanged = $_.WhenChanged
            }
        }

        $labelDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_Sensitivity_Labels.csv") -NoTypeInformation
        Write-ModuleLog "Sensitivity labels collected: $($sensitivityLabels.Count) labels" -Level Success

        return $labelDetails
    }
    catch {
        Write-ModuleLog "Failed to collect sensitivity labels: $_" -Level Error
        throw
    }
}

function Get-SensitivityLabelPolicies {
    Write-ModuleLog "Collecting sensitivity label policies..." -Level Info

    try {
        $labelPolicies = Get-LabelPolicy

        $policyDetails = $labelPolicies | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Guid = $_.Guid
                Comment = $_.Comment
                Enabled = $_.Enabled
                Mode = $_.Mode
                Labels = ($_.Labels -join ';')
                ExchangeLocation = ($_.ExchangeLocation -join ';')
                SharePointLocation = ($_.SharePointLocation -join ';')
                OneDriveLocation = ($_.OneDriveLocation -join ';')
                WhenCreated = $_.WhenCreated
                WhenChanged = $_.WhenChanged
            }
        }

        $policyDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_Sensitivity_Label_Policies.csv") -NoTypeInformation
        Write-ModuleLog "Sensitivity label policies collected: $($labelPolicies.Count) policies" -Level Success

        return $policyDetails
    }
    catch {
        Write-ModuleLog "Failed to collect sensitivity label policies: $_" -Level Error
        throw
    }
}

function Get-eDiscoveryCases {
    Write-ModuleLog "Collecting eDiscovery cases..." -Level Info

    try {
        # Core eDiscovery cases
        $coreEDCases = Get-ComplianceCase

        $caseDetails = $coreEDCases | ForEach-Object {
            # Get holds for this case
            try {
                $holds = Get-CaseHoldPolicy -Case $_.Name -ErrorAction SilentlyContinue
                $holdCount = if ($holds) { $holds.Count } else { 0 }
            }
            catch {
                $holdCount = 0
            }

            [PSCustomObject]@{
                Name = $_.Name
                Identity = $_.Identity
                Status = $_.Status
                CaseType = $_.CaseType
                Description = $_.Description
                HoldCount = $holdCount
                CreatedDateTime = $_.CreatedDateTime
                ClosedDateTime = $_.ClosedDateTime
                CreatedBy = $_.CreatedBy
            }
        }

        $caseDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_eDiscovery_Cases.csv") -NoTypeInformation
        Write-ModuleLog "eDiscovery cases collected: $($coreEDCases.Count) cases" -Level Success

        return $caseDetails
    }
    catch {
        Write-ModuleLog "Failed to collect eDiscovery cases: $_" -Level Error
        throw
    }
}

function Get-AuditLogConfiguration {
    Write-ModuleLog "Collecting audit log configuration..." -Level Info

    try {
        $auditConfig = Get-AdminAuditLogConfig

        $auditDetails = [PSCustomObject]@{
            UnifiedAuditLogIngestionEnabled = $auditConfig.UnifiedAuditLogIngestionEnabled
            LogLevel = $auditConfig.LogLevel
            TestCmdletLoggingEnabled = $auditConfig.TestCmdletLoggingEnabled
            AdminAuditLogEnabled = $auditConfig.AdminAuditLogEnabled
            AdminAuditLogCmdlets = ($auditConfig.AdminAuditLogCmdlets -join ';')
            AdminAuditLogParameters = ($auditConfig.AdminAuditLogParameters -join ';')
            AdminAuditLogExcludedCmdlets = ($auditConfig.AdminAuditLogExcludedCmdlets -join ';')
            AdminAuditLogAgeLimit = $auditConfig.AdminAuditLogAgeLimit
        }

        $auditDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_Audit_Config.csv") -NoTypeInformation
        Write-ModuleLog "Audit log configuration collected" -Level Success

        return $auditDetails
    }
    catch {
        Write-ModuleLog "Failed to collect audit log configuration: $_" -Level Warning
        return @{}
    }
}

function Get-InformationBarriers {
    Write-ModuleLog "Collecting information barriers..." -Level Info

    try {
        $ibPolicies = Get-InformationBarrierPolicy -ErrorAction SilentlyContinue

        if ($ibPolicies) {
            $policyDetails = $ibPolicies | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    Guid = $_.Guid
                    State = $_.State
                    AssignedSegment = $_.AssignedSegment
                    SegmentsAllowed = ($_.SegmentsAllowed -join ';')
                    SegmentsBlocked = ($_.SegmentsBlocked -join ';')
                    WhenCreated = $_.WhenCreated
                    WhenChanged = $_.WhenChanged
                }
            }

            $policyDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_Information_Barriers.csv") -NoTypeInformation
            Write-ModuleLog "Information barrier policies collected: $($ibPolicies.Count) policies" -Level Success

            return $policyDetails
        }
        else {
            Write-ModuleLog "No information barrier policies found or feature not enabled" -Level Warning
            return @()
        }
    }
    catch {
        Write-ModuleLog "Failed to collect information barriers (may not be enabled): $_" -Level Warning
        return @()
    }
}

function Get-ComplianceAlerts {
    Write-ModuleLog "Collecting compliance alerts..." -Level Info

    try {
        $alerts = Get-ProtectionAlert

        $alertDetails = $alerts | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                AlertBy = $_.AlertBy -join ';'
                AlertFor = $_.AlertFor -join ';'
                Category = $_.Category
                Comment = $_.Comment
                Disabled = $_.Disabled
                NotifyUser = ($_.NotifyUser -join ';')
                Operation = ($_.Operation -join ';')
                Severity = $_.Severity
                ThreatType = $_.ThreatType
                WhenCreated = $_.WhenCreated
                WhenChanged = $_.WhenChanged
            }
        }

        $alertDetails | Export-Csv -Path (Join-Path $OutputFolder "Compliance\Compliance_Alerts.csv") -NoTypeInformation
        Write-ModuleLog "Compliance alerts collected: $($alerts.Count) alerts" -Level Success

        return $alertDetails
    }
    catch {
        Write-ModuleLog "Failed to collect compliance alerts: $_" -Level Error
        throw
    }
}

#endregion

#region Main Execution

try {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   Compliance & Security Audit Module" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    # Ensure output folder exists
    $complianceFolder = Join-Path $OutputFolder "Compliance"
    if (-not (Test-Path $complianceFolder)) {
        New-Item -ItemType Directory -Path $complianceFolder -Force | Out-Null
    }

    # Connect to Security & Compliance Center
    Connect-ToComplianceCenter

    # Collect retention policies
    $retentionPolicies = Get-RetentionPolicies

    # Collect retention labels
    $retentionLabels = Get-RetentionLabels

    # Collect DLP policies
    $dlpPolicies = Get-DLPPoliciesCompliance

    # Collect sensitivity labels
    $sensitivityLabels = Get-SensitivityLabels

    # Collect sensitivity label policies
    $sensitivityLabelPolicies = Get-SensitivityLabelPolicies

    # Collect eDiscovery cases
    $eDiscoveryCases = Get-eDiscoveryCases

    # Collect audit log configuration
    $auditConfig = Get-AuditLogConfiguration

    # Collect information barriers
    $informationBarriers = Get-InformationBarriers

    # Collect compliance alerts
    $complianceAlerts = Get-ComplianceAlerts

    # Generate summary
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   Compliance & Security Audit Completed!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Retention Policies: $($retentionPolicies.Count)" -ForegroundColor White
    Write-Host "  Retention Labels: $($retentionLabels.Count)" -ForegroundColor White
    Write-Host "  DLP Policies: $($dlpPolicies.Count)" -ForegroundColor White
    Write-Host "  Sensitivity Labels: $($sensitivityLabels.Count)" -ForegroundColor White
    Write-Host "  Sensitivity Label Policies: $($sensitivityLabelPolicies.Count)" -ForegroundColor White
    Write-Host "  eDiscovery Cases: $($eDiscoveryCases.Count)" -ForegroundColor White
    Write-Host "  Information Barrier Policies: $($informationBarriers.Count)" -ForegroundColor White
    Write-Host "  Compliance Alerts: $($complianceAlerts.Count)" -ForegroundColor White
    Write-Host ""

    # Return statistics
    return @{
        RetentionPolicies = $retentionPolicies.Count
        RetentionLabels = $retentionLabels.Count
        DLPPolicies = $dlpPolicies.Count
        SensitivityLabels = $sensitivityLabels.Count
        SensitivityLabelPolicies = $sensitivityLabelPolicies.Count
        eDiscoveryCases = $eDiscoveryCases.Count
        InformationBarriers = $informationBarriers.Count
        ComplianceAlerts = $complianceAlerts.Count
    }
}
catch {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "   Compliance & Security Audit Failed!" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    throw
}
finally {
    # Disconnect from Security & Compliance Center
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-ModuleLog "Disconnected from Security & Compliance Center" -Level Info
    }
    catch {
        # Ignore disconnect errors
    }
}

#endregion

