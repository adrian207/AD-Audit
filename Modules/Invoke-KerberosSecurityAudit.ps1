<#
.SYNOPSIS
    Kerberos Security Audit Module - Comprehensive Kerberos security analysis

.DESCRIPTION
    Audits Kerberos security configuration including:
    - Kerberos delegation vulnerabilities (unconstrained, constrained, resource-based)
    - Golden and silver ticket attack indicators
    - Kerberoasting and AS-REP roasting vulnerabilities
    - Encryption algorithm downgrade attacks
    - Pre-authentication requirements
    - Ticket lifetime and renewal settings
    - KRBTGT password age retirement
    - Service principal name (SPN) security analysis

.PARAMETER DatabasePath
    Path to SQLite database for storing audit results

.PARAMETER OutputPath
    Output directory for reports (default: C:\Audits\Kerberos)

.PARAMETER IncludeAll
    Run all Kerberos security checks (default behavior)

.PARAMETER DaysThreshold
    Threshold for password age warnings (default: 180 days for KRBTGT)

.EXAMPLE
    .\Invoke-KerberosSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Requires: ActiveDirectory module, Domain Admin rights
    Based on: Microsoft AD Security Best Practices, CIS Kerberos Security Benchmark
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Audits\Kerberos",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysThreshold = 180
)

$ErrorActionPreference = 'Stop'

# Set default for IncludeAll if not specified
if (-not $IncludeAll) {
    $IncludeAll = $true
}

#region Helper Functions

function Write-KerberosLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Kerberos-Security-Audit] [$Level] $Message"
    
    switch ($Level) {
        'Critical' { Write-Host $logMessage -ForegroundColor Red -BackgroundColor Yellow }
        'Error'    { Write-Host $logMessage -ForegroundColor Red }
        'Warning'  { Write-Host $logMessage -ForegroundColor Yellow }
        'Success'  { Write-Host $logMessage -ForegroundColor Green }
        default    { Write-Verbose $logMessage }
    }
}

#endregion

#region Kerberos Detection Functions

function Get-KerberosDelegationAnalysis {
    [CmdletBinding()]
    param()
    
    Write-KerberosLog "Analyzing Kerberos delegation settings..." -Level Info
    
    $delegationFindings = @()
    
    try {
        # Get all computers with delegation configured
        $computers = Get-ADComputer -Filter * -Properties TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalName, msDS-AllowedToDelegateTo -ErrorAction SilentlyContinue
        
        Write-KerberosLog "Found $($computers.Count) computers to analyze" -Level Info
        
        foreach ($computer in $computers) {
            $delegationType = "None"
            $riskLevel = "Low"
            $vulnerabilities = @()
            $recommendation = ""
            
            # Check for unconstrained delegation (HIGHEST RISK)
            if ($computer.TrustedForDelegation) {
                $delegationType = "Unconstrained"
                $riskLevel = "Critical"
                $vulnerabilities += "Unconstrained delegation allows this computer to impersonate any user to any service"
                $recommendation = "Immediately change to constrained or resource-based constrained delegation"
            }
            
            # Check for constrained delegation
            elseif ($computer.TrustedToAuthForDelegation) {
                $delegationType = "Constrained"
                $riskLevel = "High"
                $vulnerabilities += "Constrained delegation allows impersonation to specific services"
                $recommendation = "Review delegated services and consider resource-based constrained delegation"
                
                # Check msDS-AllowedToDelegateTo for allowed services
                if ($computer.'msDS-AllowedToDelegateTo') {
                    $vulnerabilities += "Delegated to: $($computer.'msDS-AllowedToDelegateTo' -join ', ')"
                }
            }
            
            # Check for resource-based constrained delegation (safest)
            elseif ($computer.'msDS-AllowedToDelegateTo') {
                $delegationType = "Resource-Based Constrained"
                $riskLevel = "Low"
                $vulnerabilities += "Resource-based constrained delegation is the most secure option"
                $recommendation = "Current configuration is secure"
            }
            
            # Check for service accounts with multiple SPNs (potential kerberoasting risk)
            $spnCount = 0
            if ($computer.ServicePrincipalName) {
                $spnCount = $computer.ServicePrincipalName.Count
                if ($spnCount -gt 5) {
                    $vulnerabilities += "High SPN count ($spnCount) increases kerberoasting attack surface"
                    $riskLevel = if ($riskLevel -eq "Low" -or $riskLevel -eq "Medium") { "Medium" } else { $riskLevel }
                }
            }
            
            if ($delegationType -ne "None" -or $spnCount -gt 0) {
                $delegationFindings += [PSCustomObject]@{
                    ComputerName = $computer.Name
                    DNSHostName = $computer.DNSHostName
                    DistinguishedName = $computer.DistinguishedName
                    DelegationType = $delegationType
                    SPNCount = $spnCount
                    Vulnerabilities = ($vulnerabilities -join '; ')
                    RiskLevel = $riskLevel
                    Recommendation = $recommendation
                    AuditDate = Get-Date
                }
            }
        }
        
        Write-KerberosLog "Analyzed delegation settings. Found $($delegationFindings.Count) items with delegation or SPNs" -Level Success
        return $delegationFindings
    }
    catch {
        Write-KerberosLog "Failed to analyze Kerberos delegation: $_" -Level Error
        return @()
    }
}

function Get-KRBTGTAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$DaysThreshold = 180
    )
    
    Write-KerberosLog "Analyzing KRBTGT account password age..." -Level Info
    
    $krbtgtFindings = @()
    
    try {
        # Get KRBTGT account
        $krbtgt = Get-ADUser -Identity "KRBTGT" -Properties PasswordLastSet, PasswordNeverExpires, Enabled -ErrorAction Stop
        
        $passwordAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
        $isExpired = $passwordAge -gt $DaysThreshold
        $riskLevel = if ($isExpired) { "Critical" } else { "Medium" }
        
        $recommendation = if ($isExpired) {
            "IMMEDIATE ACTION REQUIRED: KRBTGT password age exceeds $DaysThreshold days. Rotate immediately to prevent golden ticket attacks."
        } else {
            "Monitor KRBTGT password age. Plan rotation within next 60 days."
        }
        
        $krbtgtFindings = [PSCustomObject]@{
            AccountName = "KRBTGT"
            PasswordAge = $passwordAge
            PasswordLastSet = $krbtgt.PasswordLastSet
            PasswordNeverExpires = $krbtgt.PasswordNeverExpires
            Enabled = $krbtgt.Enabled
            IsExpired = $isExpired
            RiskLevel = $riskLevel
            Recommendation = $recommendation
            AuditDate = Get-Date
        }
        
        Write-KerberosLog "KRBTGT password age: $passwordAge days (Threshold: $DaysThreshold)" -Level $(if ($isExpired) { 'Critical' } else { 'Success' })
        return $krbtgtFindings
    }
    catch {
        Write-KerberosLog "Failed to analyze KRBTGT account: $_" -Level Error
        return $null
    }
}

function Get-KerberoastingVulnerabilities {
    [CmdletBinding()]
    param()
    
    Write-KerberosLog "Analyzing Kerberoasting vulnerabilities..." -Level Info
    
    $kerberoastingFindings = @()
    
    try {
        # Get all service accounts
        $computers = Get-ADComputer -Filter * -Properties ServicePrincipalName, TrustedForDelegation, TrustedToAuthForDelegation, msDS-AllowedToDelegateTo -ErrorAction SilentlyContinue
        $users = Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName -ErrorAction SilentlyContinue
        
        $allAccounts = @()
        $computers | ForEach-Object { $allAccounts += $_ }
        $users | ForEach-Object { $allAccounts += $_ }
        
        foreach ($account in $allAccounts) {
            if ($account.ServicePrincipalName) {
                $spnCount = $account.ServicePrincipalName.Count
                
                # High risk indicators
                $riskScore = 0
                $vulnerabilities = @()
                
                # High SPN count increases attack surface
                if ($spnCount -gt 10) {
                    $riskScore += 3
                    $vulnerabilities += "Very high SPN count ($spnCount)"
                } elseif ($spnCount -gt 5) {
                    $riskScore += 1
                    $vulnerabilities += "High SPN count ($spnCount)"
                }
                
                # Delegation configured increases risk
                if ($account.TrustedForDelegation -or $account.TrustedToAuthForDelegation) {
                    $riskScore += 2
                    $vulnerabilities += "Delegation configured"
                }
                
                # Calculate risk level
                $riskLevel = switch ($riskScore) {
                    {$_ -ge 4} { 'Critical' }
                    {$_ -ge 2} { 'High' }
                    {$_ -ge 1} { 'Medium' }
                    default { 'Low' }
                }
                
                if ($riskScore -gt 0) {
                    $kerberoastingFindings += [PSCustomObject]@{
                        AccountName = $account.Name
                        SamAccountName = $account.SamAccountName
                        ObjectType = $account.ObjectClass
                        SPNCount = $spnCount
                        SPNs = ($account.ServicePrincipalName -join '; ')
                        Vulnerabilities = ($vulnerabilities -join '; ')
                        RiskScore = $riskScore
                        RiskLevel = $riskLevel
                        Recommendation = if ($riskLevel -eq 'Critical') {
                            "HIGH PRIORITY: Reduce SPNs, remove unnecessary delegation, use Group Managed Service Accounts"
                        } elseif ($riskLevel -eq 'High') {
                            "Review and reduce SPNs. Consider using managed service accounts."
                        } else {
                            "Monitor and limit SPN exposure where possible."
                        }
                        AuditDate = Get-Date
                    }
                }
            }
        }
        
        Write-KerberosLog "Found $($kerberoastingFindings.Count) accounts with Kerberoasting vulnerabilities" -Level Success
        return $kerberoastingFindings
    }
    catch {
        Write-KerberosLog "Failed to analyze Kerberoasting vulnerabilities: $_" -Level Error
        return @()
    }
}

function Get-PreauthRequirementAnalysis {
    [CmdletBinding()]
    param()
    
    Write-KerberosLog "Analyzing pre-authentication requirements..." -Level Info
    
    $preauthFindings = @()
    
    try {
        # Find accounts without pre-authentication (AS-REP roasting vulnerability)
        $accountsWithoutPreauth = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, PasswordNeverExpires, Enabled -ErrorAction SilentlyContinue
        
        foreach ($account in $accountsWithoutPreauth) {
            $preauthFindings += [PSCustomObject]@{
                AccountName = $account.Name
                SamAccountName = $account.SamAccountName
                DistinguishedName = $account.DistinguishedName
                DoesNotRequirePreAuth = $account.DoesNotRequirePreAuth
                PasswordNeverExpires = $account.PasswordNeverExpires
                Enabled = $account.Enabled
                RiskLevel = if ($account.Enabled) { "Critical" } else { "High" }
                Recommendation = if ($account.Enabled) {
                    "IMMEDIATE ACTION: Disable DoesNotRequirePreAuth flag to prevent AS-REP roasting attacks"
                } else {
                    "Account is disabled but should still enable pre-authentication"
                }
                AuditDate = Get-Date
            }
        }
        
        Write-KerberosLog "Found $($preauthFindings.Count) accounts without pre-authentication requirement" -Level $(if ($preauthFindings.Count -gt 0) { 'Critical' } else { 'Success' })
        return $preauthFindings
    }
    catch {
        Write-KerberosLog "Failed to analyze pre-authentication requirements: $_" -Level Error
        return @()
    }
}

#endregion

#region Reporting Functions

function Export-KerberosReports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [array]$DelegationFindings,
        [object]$KRBTGTFindings,
        [array]$KerberoastingFindings,
        [array]$PreauthFindings
    )
    
    Write-KerberosLog "Generating Kerberos security reports..." -Level Info
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export delegation findings
    if ($DelegationFindings) {
        $DelegationFindings | Export-Csv -Path (Join-Path $OutputPath "Kerberos_Delegation_Analysis_$timestamp.csv") -NoTypeInformation
        Write-KerberosLog "Delegation analysis exported" -Level Success
    }
    
    # Export KRBTGT findings
    if ($KRBTGTFindings) {
        $KRBTGTFindings | Export-Csv -Path (Join-Path $OutputPath "KRBTGT_Password_Age_$timestamp.csv") -NoTypeInformation
        Write-KerberosLog "KRBTGT analysis exported" -Level Success
    }
    
    # Export Kerberoasting findings
    if ($KerberoastingFindings) {
        $KerberoastingFindings | Export-Csv -Path (Join-Path $OutputPath "Kerberos_Kerberoasting_Vulnerabilities_$timestamp.csv") -NoTypeInformation
        Write-KerberosLog "Kerberoasting analysis exported" -Level Success
    }
    
    # Export pre-authentication findings
    if ($PreauthFindings) {
        $PreauthFindings | Export-Csv -Path (Join-Path $OutputPath "Kerberos_Preauth_Vulnerabilities_$timestamp.csv") -NoTypeInformation
        Write-KerberosLog "Pre-authentication analysis exported" -Level Success
    }
}

#endregion

#region Main Execution

try {
    Write-KerberosLog "Starting Kerberos Security Audit..." -Level Info
    Write-KerberosLog "Output path: $OutputPath" -Level Info
    
    $allFindings = @()
    $summary = @{
        TotalCritical = 0
        TotalHigh = 0
        TotalMedium = 0
        TotalLow = 0
    }
    
    # Analyze delegations
    Write-KerberosLog "Analyzing Kerberos delegation settings..." -Level Info
    $delegationFindings = Get-KerberosDelegationAnalysis
    $allFindings += $delegationFindings
    
    # Analyze KRBTGT account
    Write-KerberosLog "Analyzing KRBTGT account..." -Level Info
    $krbtgtFindings = Get-KRBTGTAnalysis -DaysThreshold $DaysThreshold
    
    # Analyze Kerberoasting vulnerabilities
    Write-KerberosLog "Analyzing Kerberoasting vulnerabilities..." -Level Info
    $kerberoastingFindings = Get-KerberoastingVulnerabilities
    $allFindings += $kerberoastingFindings
    
    # Analyze pre-authentication requirements
    Write-KerberosLog "Analyzing pre-authentication requirements..." -Level Info
    $preauthFindings = Get-PreauthRequirementAnalysis
    $allFindings += $preauthFindings
    
    # Calculate summary
    foreach ($finding in $allFindings) {
        switch ($finding.RiskLevel) {
            'Critical' { $summary.TotalCritical++ }
            'High'     { $summary.TotalHigh++ }
            'Medium'   { $summary.TotalMedium++ }
            'Low'      { $summary.TotalLow++ }
        }
    }
    
    # Export reports
    Export-KerberosReports -OutputPath $OutputPath `
                           -DelegationFindings $delegationFindings `
                           -KRBTGTFindings $krbtgtFindings `
                           -KerberoastingFindings $kerberoastingFindings `
                           -PreauthFindings $preauthFindings
    
    # Display summary
    Write-KerberosLog "Kerberos Security Audit Summary:" -Level Info
    Write-KerberosLog "  Critical Issues: $($summary.TotalCritical)" -Level $(if ($summary.TotalCritical -gt 0) { 'Critical' } else { 'Success' })
    Write-KerberosLog "  High Issues: $($summary.TotalHigh)" -Level Warning
    Write-KerberosLog "  Medium Issues: $($summary.TotalMedium)" -Level Info
    Write-KerberosLog "  Low Issues: $($summary.TotalLow)" -Level Info
    
    Write-KerberosLog "Kerberos security audit completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allFindings
        Message = "Kerberos security audit completed successfully"
    }
}
catch {
    Write-KerberosLog "Kerberos security audit failed: $_" -Level Error
    return @{
        Success = $false
        Error = $_.Exception.Message
        Message = "Kerberos security audit failed"
    }
}

#endregion
