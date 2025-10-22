<#
.SYNOPSIS
    Active Directory Federation Services (AD FS) Security Audit Module

.DESCRIPTION
    Comprehensive AD FS security audit based on Microsoft's AD FS Operations documentation.
    Audits AD FS configuration, authentication policies, authorization settings, and security
    configurations for hybrid identity environments.

.PARAMETER DatabasePath
    Path to audit database for storing results

.PARAMETER OutputPath
    Path to save CSV results

.PARAMETER IncludeServiceConfiguration
    Include AD FS service configuration analysis

.PARAMETER IncludeAuthenticationConfig
    Include authentication configuration analysis

.PARAMETER IncludeAuthorizationConfig
    Include authorization configuration analysis

.PARAMETER IncludeRPTCPTConfig
    Include Relying Party Trust and Claims Provider Trust analysis

.PARAMETER IncludeSignInExperience
    Include sign-in experience configuration analysis

.PARAMETER IncludeAll
    Include all AD FS security assessments

.EXAMPLE
    .\Invoke-ADFSSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.EXAMPLE
    .\Invoke-ADFSSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAuthenticationConfig -IncludeAuthorizationConfig

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Based on: Microsoft AD FS Operations Documentation
    Requires: AD FS PowerShell module, AD FS admin rights
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Temp\ADFSSecurityAudit.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeServiceConfiguration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAuthenticationConfig,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAuthorizationConfig,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeRPTCPTConfig,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSignInExperience,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll
)

$ErrorActionPreference = 'Stop'

# Set flags based on IncludeAll parameter
if ($IncludeAll) {
    $IncludeServiceConfiguration = $true
    $IncludeAuthenticationConfig = $true
    $IncludeAuthorizationConfig = $true
    $IncludeRPTCPTConfig = $true
    $IncludeSignInExperience = $true
}

#region Helper Functions

function Write-ADFSLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [ADFS-Security-Audit] [$Level] $Message"
    
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
        Write-ADFSLog "Failed to connect to database: $_" -Level Error
        throw
    }
}

function Test-ADFSModule {
    [CmdletBinding()]
    param()
    
    try {
        Import-Module ADFS -ErrorAction Stop
        Write-ADFSLog "AD FS PowerShell module loaded successfully" -Level Success
        return $true
    }
    catch {
        Write-ADFSLog "AD FS PowerShell module not available: $_" -Level Warning
        return $false
    }
}

#endregion

#region AD FS Security Audit Functions

function Get-ADFSServiceConfiguration {
    [CmdletBinding()]
    param()
    
    Write-ADFSLog "Analyzing AD FS service configuration..." -Level Info
    
    $serviceConfigAnalysis = @()
    
    try {
        if (-not (Test-ADFSModule)) {
            Write-ADFSLog "AD FS module not available - cannot analyze service configuration" -Level Warning
            return $serviceConfigAnalysis
        }
        
        # Get AD FS farm information
        try {
            $farmInfo = Get-AdfsFarmInformation -ErrorAction SilentlyContinue
            
            if ($farmInfo) {
                $serviceConfigAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Farm Information'
                    FarmName = $farmInfo.FarmName
                    FarmMode = $farmInfo.FarmMode
                    ServiceAccount = $farmInfo.ServiceAccount
                    CertificateThumbprint = $farmInfo.CertificateThumbprint
                    DatabaseConnectionString = $farmInfo.DatabaseConnectionString
                    IsPrimaryComputer = $farmInfo.IsPrimaryComputer
                    RiskLevel = 'Low'
                    Assessment = 'AD FS farm configuration retrieved'
                    Recommendation = 'Verify farm configuration is secure'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get farm information: $_" -Level Warning
        }
        
        # Get AD FS properties
        try {
            $adfsProperties = Get-AdfsProperties -ErrorAction SilentlyContinue
            
            if ($adfsProperties) {
                $serviceConfigAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'AD FS Properties'
                    HostName = $adfsProperties.HostName
                    HttpsPort = $adfsProperties.HttpsPort
                    HttpPort = $adfsProperties.HttpPort
                    SslCertificateThumbprint = $adfsProperties.SslCertificateThumbprint
                    SigningCertificateThumbprint = $adfsProperties.SigningCertificateThumbprint
                    TokenSigningCertificateThumbprint = $adfsProperties.TokenSigningCertificateThumbprint
                    RiskLevel = 'Medium'
                    Assessment = 'AD FS properties configuration analyzed'
                    Recommendation = 'Verify SSL and signing certificates are valid and secure'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get AD FS properties: $_" -Level Warning
        }
        
        # Check for SSL certificate issues
        try {
            $sslCert = Get-AdfsSslCertificate -ErrorAction SilentlyContinue
            
            if ($sslCert) {
                $certExpiry = $sslCert.NotAfter
                $daysUntilExpiry = ($certExpiry - (Get-Date)).Days
                
                $riskLevel = switch ($daysUntilExpiry) {
                    { $_ -lt 30 } { 'Critical' }
                    { $_ -lt 90 } { 'High' }
                    { $_ -lt 180 } { 'Medium' }
                    default { 'Low' }
                }
                
                $serviceConfigAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'SSL Certificate'
                    CertificateThumbprint = $sslCert.Thumbprint
                    Subject = $sslCert.Subject
                    NotAfter = $sslCert.NotAfter
                    DaysUntilExpiry = $daysUntilExpiry
                    RiskLevel = $riskLevel
                    Assessment = "SSL certificate expires in $daysUntilExpiry days"
                    Recommendation = if ($daysUntilExpiry -lt 90) { 'Renew SSL certificate immediately' } else { 'Monitor certificate expiry' }
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get SSL certificate information: $_" -Level Warning
        }
        
        Write-ADFSLog "AD FS service configuration analysis completed for $($serviceConfigAnalysis.Count) configurations" -Level Success
        return $serviceConfigAnalysis
    }
    catch {
        Write-ADFSLog "Failed to analyze AD FS service configuration: $_" -Level Error
        return @()
    }
}

function Get-ADFSAuthenticationConfiguration {
    [CmdletBinding()]
    param()
    
    Write-ADFSLog "Analyzing AD FS authentication configuration..." -Level Info
    
    $authConfigAnalysis = @()
    
    try {
        if (-not (Test-ADFSModule)) {
            Write-ADFSLog "AD FS module not available - cannot analyze authentication configuration" -Level Warning
            return $authConfigAnalysis
        }
        
        # Get authentication policies
        try {
            $authPolicies = Get-AdfsAuthenticationProvider -ErrorAction SilentlyContinue
            
            foreach ($policy in $authPolicies) {
                $authConfigAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Authentication Provider'
                    Name = $policy.Name
                    TypeName = $policy.TypeName
                    IsEnabled = $policy.IsEnabled
                    IsBuiltIn = $policy.IsBuiltIn
                    RiskLevel = if ($policy.IsEnabled) { 'Medium' } else { 'Low' }
                    Assessment = "Authentication provider: $($policy.Name)"
                    Recommendation = 'Verify authentication provider configuration is secure'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get authentication policies: $_" -Level Warning
        }
        
        # Get global authentication policy
        try {
            $globalAuthPolicy = Get-AdfsGlobalAuthenticationPolicy -ErrorAction SilentlyContinue
            
            if ($globalAuthPolicy) {
                $authConfigAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Global Authentication Policy'
                    AdditionalAuthenticationRules = $globalAuthPolicy.AdditionalAuthenticationRules
                    AllowAdditionalAuthenticationAsPrimary = $globalAuthPolicy.AllowAdditionalAuthenticationAsPrimary
                    RiskLevel = 'Medium'
                    Assessment = 'Global authentication policy configuration'
                    Recommendation = 'Review authentication policy rules for security'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get global authentication policy: $_" -Level Warning
        }
        
        # Check for MFA configuration
        try {
            $mfaProviders = Get-AdfsAdditionalAuthenticationRule -ErrorAction SilentlyContinue
            
            if ($mfaProviders) {
                foreach ($mfaProvider in $mfaProviders) {
                    $authConfigAnalysis += [PSCustomObject]@{
                        ConfigurationType = 'MFA Configuration'
                        RuleName = $mfaProvider.Name
                        RuleDefinition = $mfaProvider.AdditionalAuthenticationRules
                        RiskLevel = 'Low'
                        Assessment = 'MFA configuration found'
                        Recommendation = 'Verify MFA rules are properly configured'
                        LastChecked = Get-Date
                    }
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get MFA configuration: $_" -Level Warning
        }
        
        # Check for lockout protection
        try {
            $lockoutPolicy = Get-AdfsProperties | Select-Object ExtranetLockoutEnabled, ExtranetLockoutThreshold, ExtranetLockoutObservationWindow -ErrorAction SilentlyContinue
            
            if ($lockoutPolicy) {
                $riskLevel = if ($lockoutPolicy.ExtranetLockoutEnabled) { 'Low' } else { 'High' }
                
                $authConfigAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Lockout Protection'
                    ExtranetLockoutEnabled = $lockoutPolicy.ExtranetLockoutEnabled
                    ExtranetLockoutThreshold = $lockoutPolicy.ExtranetLockoutThreshold
                    ExtranetLockoutObservationWindow = $lockoutPolicy.ExtranetLockoutObservationWindow
                    RiskLevel = $riskLevel
                    Assessment = if ($lockoutPolicy.ExtranetLockoutEnabled) { 'Lockout protection enabled' } else { 'Lockout protection disabled' }
                    Recommendation = if ($lockoutPolicy.ExtranetLockoutEnabled) { 'Monitor lockout settings' } else { 'Enable lockout protection' }
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get lockout policy: $_" -Level Warning
        }
        
        Write-ADFSLog "AD FS authentication configuration analysis completed for $($authConfigAnalysis.Count) configurations" -Level Success
        return $authConfigAnalysis
    }
    catch {
        Write-ADFSLog "Failed to analyze AD FS authentication configuration: $_" -Level Error
        return @()
    }
}

function Get-ADFSAuthorizationConfiguration {
    [CmdletBinding()]
    param()
    
    Write-ADFSLog "Analyzing AD FS authorization configuration..." -Level Info
    
    $authzConfigAnalysis = @()
    
    try {
        if (-not (Test-ADFSModule)) {
            Write-ADFSLog "AD FS module not available - cannot analyze authorization configuration" -Level Warning
            return $authzConfigAnalysis
        }
        
        # Get access control policies
        try {
            $accessControlPolicies = Get-AdfsAccessControlPolicy -ErrorAction SilentlyContinue
            
            foreach ($policy in $accessControlPolicies) {
                $authzConfigAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Access Control Policy'
                    PolicyName = $policy.Name
                    PolicyDescription = $policy.Description
                    PolicyDefinition = $policy.PolicyDefinition
                    RiskLevel = 'Medium'
                    Assessment = "Access control policy: $($policy.Name)"
                    Recommendation = 'Review access control policy for security implications'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get access control policies: $_" -Level Warning
        }
        
        # Get device authentication controls
        try {
            $deviceAuthControls = Get-AdfsDeviceRegistration -ErrorAction SilentlyContinue
            
            if ($deviceAuthControls) {
                $authzConfigAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Device Registration'
                    DeviceRegistrationEnabled = $deviceAuthControls.Enabled
                    RiskLevel = if ($deviceAuthControls.Enabled) { 'Medium' } else { 'Low' }
                    Assessment = if ($deviceAuthControls.Enabled) { 'Device registration enabled' } else { 'Device registration disabled' }
                    Recommendation = 'Review device registration security implications'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get device authentication controls: $_" -Level Warning
        }
        
        Write-ADFSLog "AD FS authorization configuration analysis completed for $($authzConfigAnalysis.Count) configurations" -Level Success
        return $authzConfigAnalysis
    }
    catch {
        Write-ADFSLog "Failed to analyze AD FS authorization configuration: $_" -Level Error
        return @()
    }
}

function Get-ADFSRPTCPTConfiguration {
    [CmdletBinding()]
    param()
    
    Write-ADFSLog "Analyzing AD FS RPT and CPT configuration..." -Level Info
    
    $rptCptAnalysis = @()
    
    try {
        if (-not (Test-ADFSModule)) {
            Write-ADFSLog "AD FS module not available - cannot analyze RPT/CPT configuration" -Level Warning
            return $rptCptAnalysis
        }
        
        # Get Relying Party Trusts
        try {
            $relyingPartyTrusts = Get-AdfsRelyingPartyTrust -ErrorAction SilentlyContinue
            
            foreach ($rpt in $relyingPartyTrusts) {
                $riskLevel = 'Medium'
                $assessment = "Relying Party Trust: $($rpt.Name)"
                $recommendation = 'Review RPT configuration for security'
                
                # Check for high-risk configurations
                if ($rpt.EncryptClaims -eq $false) {
                    $riskLevel = 'High'
                    $recommendation = 'Enable claim encryption for sensitive applications'
                }
                
                if ($rpt.SignatureAlgorithm -eq 'SHA1') {
                    $riskLevel = 'High'
                    $recommendation = 'Upgrade to SHA256 signature algorithm'
                }
                
                $rptCptAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Relying Party Trust'
                    Name = $rpt.Name
                    Identifier = $rpt.Identifier
                    EncryptClaims = $rpt.EncryptClaims
                    SignatureAlgorithm = $rpt.SignatureAlgorithm
                    TokenLifetime = $rpt.TokenLifetime
                    RiskLevel = $riskLevel
                    Assessment = $assessment
                    Recommendation = $recommendation
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get Relying Party Trusts: $_" -Level Warning
        }
        
        # Get Claims Provider Trusts
        try {
            $claimsProviderTrusts = Get-AdfsClaimsProviderTrust -ErrorAction SilentlyContinue
            
            foreach ($cpt in $claimsProviderTrusts) {
                $rptCptAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Claims Provider Trust'
                    Name = $cpt.Name
                    Identifier = $cpt.Identifier
                    EncryptClaims = $cpt.EncryptClaims
                    SignatureAlgorithm = $cpt.SignatureAlgorithm
                    RiskLevel = 'Medium'
                    Assessment = "Claims Provider Trust: $($cpt.Name)"
                    Recommendation = 'Review CPT configuration for security'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get Claims Provider Trusts: $_" -Level Warning
        }
        
        # Get Claim Rules
        try {
            $claimRules = Get-AdfsClaimRule -ErrorAction SilentlyContinue
            
            foreach ($rule in $claimRules) {
                $rptCptAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Claim Rule'
                    RuleName = $rule.Name
                    RuleDefinition = $rule.RuleDefinition
                    RiskLevel = 'Low'
                    Assessment = "Claim rule: $($rule.Name)"
                    Recommendation = 'Review claim rule for security implications'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get claim rules: $_" -Level Warning
        }
        
        Write-ADFSLog "AD FS RPT/CPT configuration analysis completed for $($rptCptAnalysis.Count) configurations" -Level Success
        return $rptCptAnalysis
    }
    catch {
        Write-ADFSLog "Failed to analyze AD FS RPT/CPT configuration: $_" -Level Error
        return @()
    }
}

function Get-ADFSSignInExperienceConfiguration {
    [CmdletBinding()]
    param()
    
    Write-ADFSLog "Analyzing AD FS sign-in experience configuration..." -Level Info
    
    $signInAnalysis = @()
    
    try {
        if (-not (Test-ADFSModule)) {
            Write-ADFSLog "AD FS module not available - cannot analyze sign-in experience configuration" -Level Warning
            return $signInAnalysis
        }
        
        # Get sign-in customization
        try {
            $signInCustomization = Get-AdfsWebTheme -ErrorAction SilentlyContinue
            
            foreach ($theme in $signInCustomization) {
                $signInAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Web Theme'
                    Name = $theme.Name
                    IsDefault = $theme.IsDefault
                    RiskLevel = 'Low'
                    Assessment = "Web theme: $($theme.Name)"
                    Recommendation = 'Verify web theme customization is secure'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get web themes: $_" -Level Warning
        }
        
        # Get single sign-on settings
        try {
            $ssoSettings = Get-AdfsProperties | Select-Object SsoLifetime -ErrorAction SilentlyContinue
            
            if ($ssoSettings) {
                $signInAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Single Sign-On Settings'
                    SsoLifetime = $ssoSettings.SsoLifetime
                    RiskLevel = 'Medium'
                    Assessment = "SSO lifetime: $($ssoSettings.SsoLifetime) minutes"
                    Recommendation = 'Review SSO lifetime for security balance'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get SSO settings: $_" -Level Warning
        }
        
        # Check for password expiry claims
        try {
            $passwordExpiryClaims = Get-AdfsProperties | Select-Object SendPasswordExpiryClaims -ErrorAction SilentlyContinue
            
            if ($passwordExpiryClaims) {
                $signInAnalysis += [PSCustomObject]@{
                    ConfigurationType = 'Password Expiry Claims'
                    SendPasswordExpiryClaims = $passwordExpiryClaims.SendPasswordExpiryClaims
                    RiskLevel = 'Low'
                    Assessment = if ($passwordExpiryClaims.SendPasswordExpiryClaims) { 'Password expiry claims enabled' } else { 'Password expiry claims disabled' }
                    Recommendation = 'Consider enabling password expiry claims for user experience'
                    LastChecked = Get-Date
                }
            }
        }
        catch {
            Write-ADFSLog "Failed to get password expiry claims settings: $_" -Level Warning
        }
        
        Write-ADFSLog "AD FS sign-in experience configuration analysis completed for $($signInAnalysis.Count) configurations" -Level Success
        return $signInAnalysis
    }
    catch {
        Write-ADFSLog "Failed to analyze AD FS sign-in experience configuration: $_" -Level Error
        return @()
    }
}

function Get-ADFSSecuritySummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllResults
    )
    
    Write-ADFSLog "Generating AD FS security summary..." -Level Info
    
    $summary = @{
        TotalConfigurations = 0
        CriticalConfigurations = 0
        HighConfigurations = 0
        MediumConfigurations = 0
        LowConfigurations = 0
        ServiceConfigurations = 0
        AuthenticationConfigurations = 0
        AuthorizationConfigurations = 0
        RPTCPTConfigurations = 0
        SignInConfigurations = 0
    }
    
    foreach ($result in $AllResults) {
        $summary.TotalConfigurations++
        
        # Count by risk level
        switch ($result.RiskLevel) {
            'Critical' { $summary.CriticalConfigurations++ }
            'High' { $summary.HighConfigurations++ }
            'Medium' { $summary.MediumConfigurations++ }
            'Low' { $summary.LowConfigurations++ }
        }
        
        # Count by configuration type
        switch ($result.ConfigurationType) {
            { $_ -like "*Farm*" -or $_ -like "*Properties*" -or $_ -like "*Certificate*" } { $summary.ServiceConfigurations++ }
            { $_ -like "*Authentication*" -or $_ -like "*MFA*" -or $_ -like "*Lockout*" } { $summary.AuthenticationConfigurations++ }
            { $_ -like "*Access Control*" -or $_ -like "*Device*" } { $summary.AuthorizationConfigurations++ }
            { $_ -like "*RPT*" -or $_ -like "*CPT*" -or $_ -like "*Claim*" } { $summary.RPTCPTConfigurations++ }
            { $_ -like "*Web Theme*" -or $_ -like "*SSO*" -or $_ -like "*Password*" } { $summary.SignInConfigurations++ }
        }
    }
    
    return $summary
}

#endregion

#region Main Execution

try {
    Write-ADFSLog "Starting AD FS Security Audit Analysis..." -Level Info
    Write-ADFSLog "Database path: $DatabasePath" -Level Info
    Write-ADFSLog "Output path: $OutputPath" -Level Info
    
    $allResults = @()
    
    # Check if AD FS module is available
    if (-not (Test-ADFSModule)) {
        Write-ADFSLog "AD FS PowerShell module not available - limited analysis possible" -Level Warning
    }
    
    # Optional analyses based on parameters
    if ($IncludeServiceConfiguration) {
        Write-ADFSLog "Analyzing service configuration..." -Level Info
        $serviceConfigAnalysis = Get-ADFSServiceConfiguration
        $allResults += $serviceConfigAnalysis
    }
    
    if ($IncludeAuthenticationConfig) {
        Write-ADFSLog "Analyzing authentication configuration..." -Level Info
        $authConfigAnalysis = Get-ADFSAuthenticationConfiguration
        $allResults += $authConfigAnalysis
    }
    
    if ($IncludeAuthorizationConfig) {
        Write-ADFSLog "Analyzing authorization configuration..." -Level Info
        $authzConfigAnalysis = Get-ADFSAuthorizationConfiguration
        $allResults += $authzConfigAnalysis
    }
    
    if ($IncludeRPTCPTConfig) {
        Write-ADFSLog "Analyzing RPT/CPT configuration..." -Level Info
        $rptCptAnalysis = Get-ADFSRPTCPTConfiguration
        $allResults += $rptCptAnalysis
    }
    
    if ($IncludeSignInExperience) {
        Write-ADFSLog "Analyzing sign-in experience configuration..." -Level Info
        $signInAnalysis = Get-ADFSSignInExperienceConfiguration
        $allResults += $signInAnalysis
    }
    
    # Generate summary
    $summary = Get-ADFSSecuritySummary -AllResults $allResults
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-ADFSLog "AD FS security audit results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-ADFSLog "AD FS Security Audit Summary:" -Level Info
    Write-ADFSLog "  Total Configurations: $($summary.TotalConfigurations)" -Level Info
    Write-ADFSLog "  Critical Configurations: $($summary.CriticalConfigurations)" -Level Error
    Write-ADFSLog "  High Configurations: $($summary.HighConfigurations)" -Level Warning
    Write-ADFSLog "  Medium Configurations: $($summary.MediumConfigurations)" -Level Info
    Write-ADFSLog "  Low Configurations: $($summary.LowConfigurations)" -Level Info
    Write-ADFSLog "  Service Configurations: $($summary.ServiceConfigurations)" -Level Info
    Write-ADFSLog "  Authentication Configurations: $($summary.AuthenticationConfigurations)" -Level Info
    Write-ADFSLog "  Authorization Configurations: $($summary.AuthorizationConfigurations)" -Level Info
    Write-ADFSLog "  RPT/CPT Configurations: $($summary.RPTCPTConfigurations)" -Level Info
    Write-ADFSLog "  Sign-In Configurations: $($summary.SignInConfigurations)" -Level Info
    
    Write-ADFSLog "AD FS security audit analysis completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allResults
        Message = "AD FS security audit analysis completed successfully"
    }
}
catch {
    Write-ADFSLog "AD FS security audit analysis failed: $_" -Level Error
    throw
}

#endregion
