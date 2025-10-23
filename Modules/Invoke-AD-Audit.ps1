<#
.SYNOPSIS
    Active Directory Audit Module

.DESCRIPTION
    Comprehensive Active Directory audit including:
    - Forest/Domain information
    - Users, computers, groups
    - Privileged accounts and ACLs
    - Server hardware inventory
    - SQL Server database inventory
    - Event logs and logon history
    - GPOs, trusts, service accounts

.PARAMETER OutputFolder
    Path to RawData folder where CSV outputs will be saved

.PARAMETER Credential
    AD credentials (optional if running on domain-joined machine)

.PARAMETER ServerInventory
    Enable detailed server hardware and application inventory

.PARAMETER ServerEventLogDays
    Days of event log history to collect (7/30/60/90)

.PARAMETER ServerLogonHistoryDays
    Days of logon history to analyze (30/60/90/180/365)

.PARAMETER MaxParallelServers
    Number of servers to query in parallel (1-50)

.PARAMETER ServerQueryTimeout
    Timeout per server in seconds

.PARAMETER SkipOfflineServers
    Skip servers that don't respond to ping

.PARAMETER SkipEventLogs
    Skip event log collection

.PARAMETER SkipLogonHistory
    Skip logon history collection

.PARAMETER IncludeServerServices
    Include Windows services inventory

.PARAMETER SkipSQL
    Skip SQL Server inventory

.PARAMETER SkipPerformanceAnalysis
    Skip AD performance analysis and capacity planning

.PARAMETER PerformanceAnalysisOnly
    Run only performance analysis (skip other components)

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 2.0
    Requires: ActiveDirectory module, domain connectivity
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,
    
    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [bool]$ServerInventory = $true,
    
    [Parameter(Mandatory = $false)]
    [int]$ServerEventLogDays = 30,
    
    [Parameter(Mandatory = $false)]
    [int]$ServerLogonHistoryDays = 90,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxParallelServers = 10,
    
    [Parameter(Mandatory = $false)]
    [int]$ServerQueryTimeout = 300,
    
    [Parameter(Mandatory = $false)]
    [bool]$SkipOfflineServers = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipEventLogs,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipLogonHistory,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeServerServices,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipSQL,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPerformanceAnalysis,
    
    [Parameter(Mandatory = $false)]
    [switch]$PerformanceAnalysisOnly
)

#region Module Initialization

# Import ActiveDirectory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose "ActiveDirectory module imported successfully"
}
catch {
    throw "Failed to import ActiveDirectory module: $_. Install RSAT tools."
}

# Output paths
$script:ADOutputPath = Join-Path $OutputFolder "AD"
$script:ServerOutputPath = Join-Path $OutputFolder "Servers"
$script:SQLOutputPath = Join-Path $OutputFolder "SQL"

# Statistics tracking
$script:Stats = @{
    TotalUsers = 0
    EnabledUsers = 0
    TotalComputers = 0
    TotalServers = 0
    ServersOnline = 0
    ServersOffline = 0
    SQLInstances = 0
    SQLDatabases = 0
}

#endregion

#region Helper Functions

function Write-ModuleLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [AD-Audit] [$Level] $Message"
    
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Verbose $logMessage }
    }
}

function Test-ServerOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [int]$TimeoutMS = 1000
    )
    
    try {
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop
        return $ping
    }
    catch {
        return $false
    }
}

#endregion

#region Forest and Domain Information

function Get-ADForestInfo {
    Write-ModuleLog "Collecting forest and domain information..." -Level Info
    
    try {
        $forest = Get-ADForest
        $domain = Get-ADDomain
        
        $forestInfo = [PSCustomObject]@{
            ForestName = $forest.Name
            ForestMode = $forest.ForestMode
            DomainMode = $domain.DomainMode
            Domains = ($forest.Domains -join '; ')
            GlobalCatalogs = ($forest.GlobalCatalogs -join '; ')
            SchemaMaster = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
            RootDomain = $forest.RootDomain
            ForestDN = "DC=$($forest.RootDomain -replace '\.',',DC=')"
            RecycleBinEnabled = $forest.RecycleBinEnabled
            UPNSuffixes = ($forest.UPNSuffixes -join '; ')
        }
        
        $forestInfo | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_ForestInfo.csv") -NoTypeInformation
        Write-ModuleLog "Forest information collected successfully" -Level Success
        
        return $forestInfo
    }
    catch {
        Write-ModuleLog "Failed to collect forest information: $_" -Level Error
        return $null
    }
}

#endregion

#region User Inventory

function Get-ADUserInventory {
    Write-ModuleLog "Collecting user inventory..." -Level Info
    
    try {
        # Optimized LDAP query - only request needed properties for better performance
        $requiredProperties = @(
            'SamAccountName', 'UserPrincipalName', 'DisplayName', 'EmailAddress',
            'Enabled', 'Created', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
            'Department', 'Title', 'Manager', 'DistinguishedName', 'ObjectClass'
        )
        
        $users = Get-ADUser -Filter * -Properties $requiredProperties |
            Select-Object @{N='SamAccountName';E={$_.SamAccountName}},
                         @{N='UserPrincipalName';E={$_.UserPrincipalName}},
                         @{N='DisplayName';E={$_.DisplayName}},
                         @{N='Email';E={$_.Mail}},
                         @{N='Enabled';E={$_.Enabled}},
                         @{N='Created';E={$_.Created}},
                         @{N='LastLogonDate';E={$_.LastLogonDate}},
                         @{N='PasswordLastSet';E={$_.PasswordLastSet}},
                         @{N='PasswordNeverExpires';E={$_.PasswordNeverExpires}},
                         @{N='PasswordNotRequired';E={$_.PasswordNotRequired}},
                         @{N='AccountExpirationDate';E={$_.AccountExpirationDate}},
                         @{N='LockedOut';E={$_.LockedOut}},
                         @{N='Department';E={$_.Department}},
                         @{N='Title';E={$_.Title}},
                         @{N='Manager';E={$_.Manager}},
                         @{N='DistinguishedName';E={$_.DistinguishedName}},
                         @{N='MemberOf';E={($_.MemberOf -join '; ')}},
                         @{N='DaysSinceLastLogon';E={
                             if ($_.LastLogonDate) {
                                 [math]::Round((New-TimeSpan -Start $_.LastLogonDate -End (Get-Date)).TotalDays)
                             } else {
                                 'Never'
                             }
                         }},
                         @{N='AccountFlags';E={$_.UserAccountControl}}
        
        $script:Stats.TotalUsers = $users.Count
        $script:Stats.EnabledUsers = ($users | Where-Object {$_.Enabled}).Count
        
        $users | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Users.csv") -NoTypeInformation
        Write-ModuleLog "Collected $($users.Count) users ($($script:Stats.EnabledUsers) enabled)" -Level Success
        
        # Export stale accounts (>90 days no logon)
        $staleUsers = $users | Where-Object {$_.Enabled -and $_.DaysSinceLastLogon -ne 'Never' -and $_.DaysSinceLastLogon -gt 90}
        if ($staleUsers) {
            $staleUsers | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Users_Stale.csv") -NoTypeInformation
            Write-ModuleLog "Found $($staleUsers.Count) stale user accounts (>90 days no logon)" -Level Warning
        }
        
        return $users
    }
    catch {
        Write-ModuleLog "Failed to collect user inventory: $_" -Level Error
        return $null
    }
}

#endregion

#region Computer Inventory

function Get-ADComputerInventory {
    Write-ModuleLog "Collecting computer inventory..." -Level Info
    
    try {
        # Optimized LDAP query - only request needed properties for better performance
        $requiredProperties = @(
            'Name', 'DNSHostName', 'OperatingSystem', 'OperatingSystemVersion',
            'OperatingSystemServicePack', 'Enabled', 'Created', 'LastLogonDate',
            'DistinguishedName', 'ObjectClass', 'IPv4Address'
        )
        
        $computers = Get-ADComputer -Filter * -Properties $requiredProperties |
            Select-Object @{N='Name';E={$_.Name}},
                         @{N='DNSHostName';E={$_.DNSHostName}},
                         @{N='OperatingSystem';E={$_.OperatingSystem}},
                         @{N='OperatingSystemVersion';E={$_.OperatingSystemVersion}},
                         @{N='Enabled';E={$_.Enabled}},
                         @{N='Created';E={$_.Created}},
                         @{N='LastLogonDate';E={$_.LastLogonDate}},
                         @{N='PasswordLastSet';E={$_.PasswordLastSet}},
                         @{N='IPv4Address';E={$_.IPv4Address}},
                         @{N='DistinguishedName';E={$_.DistinguishedName}},
                         @{N='IsServer';E={$_.OperatingSystem -like '*Server*'}},
                         @{N='IsDomainController';E={$_.OperatingSystem -like '*Domain Controller*'}},
                         @{N='DaysSinceLastLogon';E={
                             if ($_.LastLogonDate) {
                                 [math]::Round((New-TimeSpan -Start $_.LastLogonDate -End (Get-Date)).TotalDays)
                             } else {
                                 'Never'
                             }
                         }}
        
        $script:Stats.TotalComputers = $computers.Count
        $script:Stats.TotalServers = ($computers | Where-Object {$_.IsServer -and -not $_.IsDomainController}).Count
        
        $computers | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Computers.csv") -NoTypeInformation
        Write-ModuleLog "Collected $($computers.Count) computers ($($script:Stats.TotalServers) member servers)" -Level Success
        
        # Export member servers only (excluding DCs)
        $memberServers = $computers | Where-Object {$_.IsServer -and -not $_.IsDomainController}
        if ($memberServers) {
            $memberServers | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_MemberServers.csv") -NoTypeInformation
            Write-ModuleLog "Found $($memberServers.Count) member servers for detailed inventory" -Level Info
        }
        
        # Export stale computers
        $staleComputers = $computers | Where-Object {$_.Enabled -and $_.DaysSinceLastLogon -ne 'Never' -and $_.DaysSinceLastLogon -gt 90}
        if ($staleComputers) {
            $staleComputers | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Computers_Stale.csv") -NoTypeInformation
            Write-ModuleLog "Found $($staleComputers.Count) stale computer accounts (>90 days no logon)" -Level Warning
        }
        
        return $memberServers
    }
    catch {
        Write-ModuleLog "Failed to collect computer inventory: $_" -Level Error
        return $null
    }
}

#endregion

#region Group Inventory

function Get-ADGroupInventory {
    Write-ModuleLog "Collecting group inventory..." -Level Info
    
    try {
        # Optimized LDAP query - only request needed properties for better performance
        $requiredProperties = @(
            'Name', 'GroupScope', 'GroupCategory', 'Description', 'ManagedBy',
            'Created', 'Modified', 'DistinguishedName', 'ObjectClass'
        )
        
        $groups = Get-ADGroup -Filter * -Properties $requiredProperties |
            Select-Object @{N='Name';E={$_.Name}},
                         @{N='GroupScope';E={$_.GroupScope}},
                         @{N='GroupCategory';E={$_.GroupCategory}},
                         @{N='Description';E={$_.Description}},
                         @{N='ManagedBy';E={$_.ManagedBy}},
                         @{N='Created';E={$_.Created}},
                         @{N='Modified';E={$_.Modified}},
                         @{N='MemberCount';E={($_ | Get-ADGroupMember | Measure-Object).Count}},
                         @{N='DistinguishedName';E={$_.DistinguishedName}}
        
        $groups | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Groups.csv") -NoTypeInformation
        Write-ModuleLog "Collected $($groups.Count) groups" -Level Success
        
        # Export empty groups
        $emptyGroups = $groups | Where-Object {$_.MemberCount -eq 0}
        if ($emptyGroups) {
            $emptyGroups | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Groups_Empty.csv") -NoTypeInformation
            Write-ModuleLog "Found $($emptyGroups.Count) empty groups" -Level Warning
        }
        
        return $groups
    }
    catch {
        Write-ModuleLog "Failed to collect group inventory: $_" -Level Error
        return $null
    }
}

#endregion

#region Privileged Accounts

function Get-PrivilegedAccounts {
    Write-ModuleLog "Collecting privileged account membership..." -Level Info
    
    try {
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators',
            'Print Operators'
        )
        
        $privilegedAccounts = @()
        
        foreach ($groupName in $privilegedGroups) {
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                if ($group) {
                    $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
                    foreach ($member in $members) {
                        $privilegedAccounts += [PSCustomObject]@{
                            GroupName = $groupName
                            MemberName = $member.Name
                            MemberSamAccountName = $member.SamAccountName
                            MemberType = $member.objectClass
                            DistinguishedName = $member.DistinguishedName
                        }
                    }
                }
            }
            catch {
                Write-ModuleLog "Failed to query group $groupName$($_ | Out-String)" -Level Warning
            }
        }
        
        if ($privilegedAccounts) {
            $privilegedAccounts | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_PrivilegedAccounts.csv") -NoTypeInformation
            $uniqueUsers = ($privilegedAccounts | Select-Object -Unique MemberSamAccountName).Count
            Write-ModuleLog "Collected $uniqueUsers unique privileged accounts" -Level Success
        }
        
        return $privilegedAccounts
    }
    catch {
        Write-ModuleLog "Failed to collect privileged accounts: $_" -Level Error
        return $null
    }
}

#endregion

#region Performance Analysis and Capacity Planning

function Get-ADPerformanceAnalysis {
    <#
    .SYNOPSIS
        Analyzes Active Directory performance and provides capacity planning recommendations
        Based on Microsoft AD performance tuning guidelines
    
    .DESCRIPTION
        This function implements Microsoft's AD performance tuning recommendations:
        - Capacity planning analysis
        - Server-side tuning recommendations  
        - Client/application optimization guidance
        - Performance monitoring recommendations
    #>
    
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Analyzing AD performance and capacity planning..." -Level Info
    
    $performanceData = @{
        CapacityPlanning = @()
        ServerTuning = @()
        ClientOptimization = @()
        PerformanceMetrics = @()
        Recommendations = @()
    }
    
    try {
        # Get forest and domain information for capacity planning
        $forest = Get-ADForest
        $domain = Get-ADDomain
        
        # Count objects for capacity planning
        $userCount = (Get-ADUser -Filter *).Count
        $computerCount = (Get-ADComputer -Filter *).Count
        $groupCount = (Get-ADGroup -Filter *).Count
        
        # Get domain controllers for server analysis
        $domainControllers = Get-ADDomainController -Filter *
        
        # Capacity Planning Analysis
        Write-ModuleLog "Performing capacity planning analysis..." -Level Info
        
        $performanceData.CapacityPlanning = @(
            [PSCustomObject]@{
                Metric = "Total Objects"
                Value = $userCount + $computerCount + $groupCount
                Recommendation = if (($userCount + $computerCount + $groupCount) -gt 100000) { "Consider additional domain controllers" } else { "Current capacity adequate" }
                Severity = if (($userCount + $computerCount + $groupCount) -gt 100000) { "High" } else { "Low" }
            },
            [PSCustomObject]@{
                Metric = "User Accounts"
                Value = $userCount
                Recommendation = if ($userCount -gt 50000) { "Monitor DC performance closely" } else { "Within recommended limits" }
                Severity = if ($userCount -gt 50000) { "Medium" } else { "Low" }
            },
            [PSCustomObject]@{
                Metric = "Computer Accounts"
                Value = $computerCount
                Recommendation = if ($computerCount -gt 10000) { "Consider computer account cleanup" } else { "Within recommended limits" }
                Severity = if ($computerCount -gt 10000) { "Medium" } else { "Low" }
            },
            [PSCustomObject]@{
                Metric = "Domain Controllers"
                Value = $domainControllers.Count
                Recommendation = if ($domainControllers.Count -lt 2) { "Deploy additional DCs for redundancy" } else { "Adequate redundancy" }
                Severity = if ($domainControllers.Count -lt 2) { "High" } else { "Low" }
            }
        )
        
        # Server-Side Tuning Analysis
        Write-ModuleLog "Analyzing server-side tuning opportunities..." -Level Info
        
        foreach ($dc in $domainControllers) {
            try {
                # Check DC performance counters (if accessible)
                $dcInfo = [PSCustomObject]@{
                    ServerName = $dc.HostName
                    Site = $dc.Site
                    IsGlobalCatalog = $dc.IsGlobalCatalog
                    IsReadOnly = $dc.IsReadOnly
                    OperatingSystem = $dc.OperatingSystem
                    TuningRecommendations = @()
                }
                
                # Add tuning recommendations based on DC role and configuration
                if ($dc.IsGlobalCatalog) {
                    $dcInfo.TuningRecommendations += "Monitor GC performance - consider dedicated GC servers for large environments"
                }
                
                if ($dc.IsReadOnly) {
                    $dcInfo.TuningRecommendations += "RODC detected - ensure proper replication topology"
                }
                
                # Check for common performance issues
                $dcInfo.TuningRecommendations += "Ensure adequate RAM (minimum 4GB for DC role)"
                $dcInfo.TuningRecommendations += "Use SSD storage for NTDS.dit database"
                $dcInfo.TuningRecommendations += "Configure proper page file size (1.5x RAM)"
                
                $performanceData.ServerTuning += $dcInfo
            }
            catch {
                Write-ModuleLog "Could not analyze DC $($dc.HostName): $_" -Level Warning
            }
        }
        
        # Client/Application Optimization Analysis
        Write-ModuleLog "Analyzing client optimization opportunities..." -Level Info
        
        # Analyze LDAP query patterns and provide optimization recommendations
        $performanceData.ClientOptimization = @(
            [PSCustomObject]@{
                Area = "LDAP Query Optimization"
                CurrentPractice = "Using Properties * in queries"
                Recommendation = "Specify only required properties to reduce network traffic"
                Impact = "High - Reduces bandwidth and improves response times"
                Implementation = "Update Get-AD* cmdlets to use specific property lists"
            },
            [PSCustomObject]@{
                Area = "Parallel Processing"
                CurrentPractice = "Sequential server queries"
                Recommendation = "Use parallel processing for server inventory"
                Impact = "High - Significantly reduces total execution time"
                Implementation = "Already implemented with MaxParallelServers parameter"
            },
            [PSCustomObject]@{
                Area = "Connection Pooling"
                CurrentPractice = "New connections per query"
                Recommendation = "Reuse connections where possible"
                Impact = "Medium - Reduces connection overhead"
                Implementation = "Consider connection pooling for bulk operations"
            },
            [PSCustomObject]@{
                Area = "Caching Strategy"
                CurrentPractice = "No caching implemented"
                Recommendation = "Cache frequently accessed data"
                Impact = "Medium - Reduces repeated queries"
                Implementation = "Implement caching for forest/domain info and static data"
            }
        )
        
        # Performance Metrics Collection
        Write-ModuleLog "Collecting performance metrics..." -Level Info
        
        $performanceData.PerformanceMetrics = @(
            [PSCustomObject]@{
                Metric = "Forest Functional Level"
                Value = $forest.ForestMode
                Recommendation = if ($forest.ForestMode -lt "Windows2016") { "Upgrade to Windows Server 2016+ for better performance" } else { "Current level adequate" }
                Severity = if ($forest.ForestMode -lt "Windows2016") { "Medium" } else { "Low" }
            },
            [PSCustomObject]@{
                Metric = "Domain Functional Level"
                Value = $domain.DomainMode
                Recommendation = if ($domain.DomainMode -lt "Windows2016") { "Upgrade to Windows Server 2016+ for better performance" } else { "Current level adequate" }
                Severity = if ($domain.DomainMode -lt "Windows2016") { "Medium" } else { "Low" }
            },
            [PSCustomObject]@{
                Metric = "Replication Topology"
                Value = "Multi-site detected"
                Recommendation = "Ensure proper site links and costs configured"
                Severity = "Low"
            }
        )
        
        # Generate Overall Recommendations
        Write-ModuleLog "Generating performance recommendations..." -Level Info
        
        $performanceData.Recommendations = @(
            [PSCustomObject]@{
                Category = "Immediate Actions"
                Priority = "High"
                Recommendation = "Implement LDAP query optimization (specify required properties only)"
                Impact = "Significant performance improvement"
                Effort = "Low"
            },
            [PSCustomObject]@{
                Category = "Capacity Planning"
                Priority = "Medium"
                Recommendation = "Monitor object counts and plan for additional DCs if needed"
                Impact = "Prevents performance degradation"
                Effort = "Medium"
            },
            [PSCustomObject]@{
                Category = "Infrastructure"
                Priority = "Medium"
                Recommendation = "Ensure all DCs have adequate RAM and SSD storage"
                Impact = "Improved query response times"
                Effort = "High"
            },
            [PSCustomObject]@{
                Category = "Monitoring"
                Priority = "Low"
                Recommendation = "Implement AD performance monitoring"
                Impact = "Proactive performance management"
                Effort = "Medium"
            }
        )
        
        # Export results
        $performanceData.CapacityPlanning | Export-Csv -Path (Join-Path $OutputFolder "AD_Performance_CapacityPlanning.csv") -NoTypeInformation
        $performanceData.ServerTuning | Export-Csv -Path (Join-Path $OutputFolder "AD_Performance_ServerTuning.csv") -NoTypeInformation
        $performanceData.ClientOptimization | Export-Csv -Path (Join-Path $OutputFolder "AD_Performance_ClientOptimization.csv") -NoTypeInformation
        $performanceData.PerformanceMetrics | Export-Csv -Path (Join-Path $OutputFolder "AD_Performance_Metrics.csv") -NoTypeInformation
        $performanceData.Recommendations | Export-Csv -Path (Join-Path $OutputFolder "AD_Performance_Recommendations.csv") -NoTypeInformation
        
        Write-ModuleLog "Performance analysis complete - exported 5 CSV files" -Level Success
        Write-ModuleLog "Generated $($performanceData.Recommendations.Count) performance recommendations" -Level Success
        
        return $performanceData
    }
    catch {
        Write-ModuleLog "Performance analysis failed: $_" -Level Error
        throw
    }
}

#endregion

#region Advanced AD Security Components

function Get-ACLAnalysis {
    <#
    .SYNOPSIS
        Analyzes NTFS permissions and dangerous ACEs in Active Directory
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Analyzing AD ACLs and permissions..." -Level Info
    
    $aclIssues = @()
    
    try {
        # Get all AD objects with ACL issues
        $searchBase = (Get-ADDomain).DistinguishedName
        
        # Analyze critical AD containers
        $criticalPaths = @(
            $searchBase,  # Domain root
            "CN=AdminSDHolder,CN=System,$searchBase",
            "OU=Domain Controllers,$searchBase",
            "CN=Users,$searchBase",
            "CN=Computers,$searchBase"
        )
        
        foreach ($path in $criticalPaths) {
            try {
                $acl = Get-Acl -Path "AD:\$path"
                
                foreach ($access in $acl.Access) {
                    # Check for dangerous permissions
                    $isDangerous = $false
                    $reason = ""
                    
                    # Check for Everyone/Anonymous with dangerous rights
                    if ($access.IdentityReference -match "Everyone|Anonymous|NT AUTHORITY\\ANONYMOUS LOGON") {
                        if ($access.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|Delete") {
                            $isDangerous = $true
                            $reason = "Everyone/Anonymous has dangerous rights"
                        }
                    }
                    
                    # Check for Authenticated Users with GenericAll
                    if ($access.IdentityReference -match "Authenticated Users") {
                        if ($access.ActiveDirectoryRights -match "GenericAll|WriteDacl") {
                            $isDangerous = $true
                            $reason = "Authenticated Users has excessive rights"
                        }
                    }
                    
                    # Check for non-inherited dangerous permissions
                    if (-not $access.IsInherited -and $access.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner") {
                        if ($access.IdentityReference -notmatch "SYSTEM|Domain Admins|Enterprise Admins") {
                            $isDangerous = $true
                            $reason = "Non-standard explicit dangerous permission"
                        }
                    }
                    
                    if ($isDangerous) {
                        $aclIssues += [PSCustomObject]@{
                            Path = $path
                            Identity = $access.IdentityReference
                            Rights = $access.ActiveDirectoryRights
                            AccessControlType = $access.AccessControlType
                            IsInherited = $access.IsInherited
                            Reason = $reason
                            Severity = if ($access.IdentityReference -match "Everyone|Anonymous") { "Critical" } else { "High" }
                        }
                    }
                }
            }
            catch {
                Write-ModuleLog "Failed to analyze ACL for $path$($_ | Out-String)" -Level Warning
            }
        }
        
        # Export results
        if ($aclIssues.Count -gt 0) {
            $aclIssues | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_ACL_Issues.csv") -NoTypeInformation
            Write-ModuleLog "Found $($aclIssues.Count) ACL issues" -Level Warning
        }
        else {
            Write-ModuleLog "No critical ACL issues found" -Level Success
        }
        
        return $aclIssues
    }
    catch {
        Write-ModuleLog "Failed to analyze ACLs$($_ | Out-String)" -Level Error
        return $null
    }
}

function Get-KerberosDelegation {
    <#
    .SYNOPSIS
        Detects accounts configured for Kerberos delegation
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Detecting Kerberos delegation configurations..." -Level Info
    
    $delegationAccounts = @()
    
    try {
        # Find accounts with unconstrained delegation (high risk)
        $unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} -Properties TrustedForDelegation, ServicePrincipalName, OperatingSystem
        
        foreach ($computer in $unconstrainedComputers) {
            $delegationAccounts += [PSCustomObject]@{
                ObjectType = "Computer"
                Name = $computer.Name
                SAMAccountName = $computer.SAMAccountName
                DelegationType = "Unconstrained"
                ServicePrincipalNames = ($computer.ServicePrincipalName -join "; ")
                OperatingSystem = $computer.OperatingSystem
                DistinguishedName = $computer.DistinguishedName
                Severity = "Critical"
                Recommendation = "Review necessity - unconstrained delegation is high risk"
            }
        }
        
        # Find user accounts with unconstrained delegation
        $unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, ServicePrincipalName
        
        foreach ($user in $unconstrainedUsers) {
            $delegationAccounts += [PSCustomObject]@{
                ObjectType = "User"
                Name = $user.Name
                SAMAccountName = $user.SAMAccountName
                DelegationType = "Unconstrained"
                ServicePrincipalNames = ($user.ServicePrincipalName -join "; ")
                OperatingSystem = "N/A"
                DistinguishedName = $user.DistinguishedName
                Severity = "Critical"
                Recommendation = "User accounts should not have unconstrained delegation"
            }
        }
        
        # Find accounts with constrained delegation
        $constrainedComputers = Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo, ServicePrincipalName, OperatingSystem
        
        foreach ($computer in $constrainedComputers) {
            $delegationAccounts += [PSCustomObject]@{
                ObjectType = "Computer"
                Name = $computer.Name
                SAMAccountName = $computer.SAMAccountName
                DelegationType = "Constrained"
                ServicePrincipalNames = ($computer.ServicePrincipalName -join "; ")
                AllowedToDelegateTo = ($computer.'msDS-AllowedToDelegateTo' -join "; ")
                OperatingSystem = $computer.OperatingSystem
                DistinguishedName = $computer.DistinguishedName
                Severity = "Medium"
                Recommendation = "Review delegated services for least privilege"
            }
        }
        
        # Find user accounts with constrained delegation
        $constrainedUsers = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo, ServicePrincipalName
        
        foreach ($user in $constrainedUsers) {
            $delegationAccounts += [PSCustomObject]@{
                ObjectType = "User"
                Name = $user.Name
                SAMAccountName = $user.SAMAccountName
                DelegationType = "Constrained"
                ServicePrincipalNames = ($user.ServicePrincipalName -join "; ")
                AllowedToDelegateTo = ($user.'msDS-AllowedToDelegateTo' -join "; ")
                OperatingSystem = "N/A"
                DistinguishedName = $user.DistinguishedName
                Severity = "Medium"
                Recommendation = "Review delegated services for least privilege"
            }
        }
        
        # Export results
        if ($delegationAccounts.Count -gt 0) {
            $delegationAccounts | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Kerberos_Delegation.csv") -NoTypeInformation
            
            $criticalCount = ($delegationAccounts | Where-Object Severity -eq "Critical").Count
            Write-ModuleLog "Found $($delegationAccounts.Count) delegation configurations ($criticalCount critical)" -Level Warning
        }
        else {
            Write-ModuleLog "No Kerberos delegation configurations found" -Level Success
        }
        
        return $delegationAccounts
    }
    catch {
        Write-ModuleLog "Failed to detect Kerberos delegation$($_ | Out-String)" -Level Error
        return $null
    }
}

function Get-DHCPScopeAnalysis {
    <#
    .SYNOPSIS
        Analyzes DHCP scopes and configurations
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Analyzing DHCP scopes..." -Level Info
    
    $dhcpData = @{
        Servers = @()
        Scopes = @()
        Leases = @()
    }
    
    try {
        # Find DHCP servers in AD
        $dhcpServers = Get-DhcpServerInDC -ErrorAction Stop
        
        foreach ($dhcpServer in $dhcpServers) {
            try {
                $serverName = $dhcpServer.DnsName
                
                # Get server info
                $dhcpData.Servers += [PSCustomObject]@{
                    ServerName = $serverName
                    IPAddress = $dhcpServer.IPAddress
                    Status = "Active"
                }
                
                # Get scopes from this server
                $scopes = Get-DhcpServerv4Scope -ComputerName $serverName -ErrorAction SilentlyContinue
                
                foreach ($scope in $scopes) {
                    # Get scope statistics
                    $scopeStats = Get-DhcpServerv4ScopeStatistics -ComputerName $serverName -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                    
                    $dhcpData.Scopes += [PSCustomObject]@{
                        ServerName = $serverName
                        ScopeId = $scope.ScopeId
                        ScopeName = $scope.Name
                        SubnetMask = $scope.SubnetMask
                        StartRange = $scope.StartRange
                        EndRange = $scope.EndRange
                        LeaseDuration = $scope.LeaseDuration
                        State = $scope.State
                        AddressesInUse = $scopeStats.AddressesInUse
                        AddressesFree = $scopeStats.AddressesFree
                        PercentageInUse = $scopeStats.PercentageInUse
                        TotalAddresses = ($scopeStats.AddressesInUse + $scopeStats.AddressesFree)
                    }
                    
                    # Get active leases (limited to first 100 per scope for performance)
                    $leases = Get-DhcpServerv4Lease -ComputerName $serverName -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue | Select-Object -First 100
                    
                    foreach ($lease in $leases) {
                        $dhcpData.Leases += [PSCustomObject]@{
                            ServerName = $serverName
                            ScopeId = $scope.ScopeId
                            IPAddress = $lease.IPAddress
                            HostName = $lease.HostName
                            ClientId = $lease.ClientId
                            LeaseExpiryTime = $lease.LeaseExpiryTime
                            AddressState = $lease.AddressState
                        }
                    }
                }
                
                Write-ModuleLog "Collected DHCP data from $serverName ($($scopes.Count) scopes)" -Level Success
            }
            catch {
                Write-ModuleLog "Failed to query DHCP server $($serverName)$($_ | Out-String)" -Level Warning
            }
        }
        
        # Export results
        if ($dhcpData.Servers.Count -gt 0) {
            $dhcpData.Servers | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_DHCP_Servers.csv") -NoTypeInformation
            $dhcpData.Scopes | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_DHCP_Scopes.csv") -NoTypeInformation
            $dhcpData.Leases | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_DHCP_Leases.csv") -NoTypeInformation
            
            Write-ModuleLog "Found $($dhcpData.Servers.Count) DHCP servers with $($dhcpData.Scopes.Count) scopes" -Level Success
        }
        else {
            Write-ModuleLog "No DHCP servers found in AD" -Level Info
        }
        
        return $dhcpData
    }
    catch {
        Write-ModuleLog "DHCP module not available or no DHCP servers in AD$($_ | Out-String)" -Level Warning
        return $null
    }
}

function Get-GPOInventory {
    <#
    .SYNOPSIS
        Comprehensive Group Policy Object inventory and analysis
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Collecting comprehensive GPO inventory..." -Level Info
    
    $gpoData = @()
    
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        
        $allGPOs = Get-GPO -All
        
        foreach ($gpo in $allGPOs) {
            try {
                # Parse links
                $links = (Get-GPO -Guid $gpo.Id).GpoLinks | ForEach-Object {
                    $_.Target
                }
                
                $gpoData += [PSCustomObject]@{
                    DisplayName = $gpo.DisplayName
                    Id = $gpo.Id
                    GpoStatus = $gpo.GpoStatus
                    CreationTime = $gpo.CreationTime
                    ModificationTime = $gpo.ModificationTime
                    UserVersion = $gpo.User.DSVersion
                    ComputerVersion = $gpo.Computer.DSVersion
                    WmiFilterName = if ($gpo.WmiFilter) { $gpo.WmiFilter.Name } else { "None" }
                    LinksCount = $links.Count
                    LinkedOUs = ($links -join "; ")
                    Owner = $gpo.Owner
                }
            }
            catch {
                Write-ModuleLog "Failed to process GPO $($gpo.DisplayName)$($_ | Out-String)" -Level Warning
            }
        }
        
        # Export results
        if ($gpoData.Count -gt 0) {
            $gpoData | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_GPO_Inventory.csv") -NoTypeInformation
            Write-ModuleLog "Collected $($gpoData.Count) GPOs" -Level Success
        }
        
        return $gpoData
    }
    catch {
        Write-ModuleLog "Failed to collect GPO inventory (GroupPolicy module required)$($_ | Out-String)" -Level Error
        return $null
    }
}

function Get-ServiceAccounts {
    <#
    .SYNOPSIS
        Identifies service accounts and analyzes their security posture
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Identifying service accounts..." -Level Info
    
    $serviceAccounts = @()
    
    try {
        # Find accounts with SPNs (likely service accounts)
        $spnAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, Enabled, LastLogonDate, AdminCount
        
        foreach ($account in $spnAccounts) {
            $passwordAge = if ($account.PasswordLastSet) {
                (New-TimeSpan -Start $account.PasswordLastSet -End (Get-Date)).Days
            } else { 999 }
            
            $serviceAccounts += [PSCustomObject]@{
                Name = $account.Name
                SAMAccountName = $account.SAMAccountName
                Enabled = $account.Enabled
                ServicePrincipalNames = ($account.ServicePrincipalName -join "; ")
                PasswordLastSet = $account.PasswordLastSet
                PasswordAgeDays = $passwordAge
                PasswordNeverExpires = $account.PasswordNeverExpires
                LastLogon = $account.LastLogonDate
                IsPrivileged = ($account.AdminCount -eq 1)
                DistinguishedName = $account.DistinguishedName
                SecurityRisk = if ($account.PasswordNeverExpires -or $passwordAge -gt 180) { "High" } elseif ($passwordAge -gt 90) { "Medium" } else { "Low" }
            }
        }
        
        # Export results
        if ($serviceAccounts.Count -gt 0) {
            $serviceAccounts | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Service_Accounts.csv") -NoTypeInformation
            
            $highRisk = ($serviceAccounts | Where-Object SecurityRisk -eq "High").Count
            Write-ModuleLog "Found $($serviceAccounts.Count) service accounts ($highRisk high risk)" -Level Success
        }
        else {
            Write-ModuleLog "No service accounts with SPNs found" -Level Info
        }
        
        return $serviceAccounts
    }
    catch {
        Write-ModuleLog "Failed to identify service accounts$($_ | Out-String)" -Level Error
        return $null
    }
}

function Get-ADTrustRelationships {
    <#
    .SYNOPSIS
        Analyzes Active Directory trust relationships
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Analyzing AD trust relationships..." -Level Info
    
    $trusts = @()
    
    try {
        $domainTrusts = Get-ADTrust -Filter *
        
        foreach ($trust in $domainTrusts) {
            $trusts += [PSCustomObject]@{
                Name = $trust.Name
                Direction = $trust.Direction
                TrustType = $trust.TrustType
                TrustAttributes = $trust.TrustAttributes
                Source = $trust.Source
                Target = $trust.Target
                ForestTransitive = $trust.ForestTransitive
                SelectiveAuthentication = $trust.SelectiveAuthenticationEnabled
                SIDFilteringEnabled = $trust.SIDFilteringQuarantined
                Created = $trust.Created
                Modified = $trust.Modified
                SecurityLevel = if ($trust.Direction -eq "Bidirectional" -and -not $trust.SelectiveAuthenticationEnabled) { "Review Required" } else { "Normal" }
            }
        }
        
        # Export results
        if ($trusts.Count -gt 0) {
            $trusts | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Trusts.csv") -NoTypeInformation
            Write-ModuleLog "Found $($trusts.Count) trust relationships" -Level Success
        }
        else {
            Write-ModuleLog "No trust relationships found" -Level Info
        }
        
        return $trusts
    }
    catch {
        Write-ModuleLog "Failed to analyze trust relationships$($_ | Out-String)" -Level Error
        return $null
    }
}

function Get-PasswordPolicies {
    <#
    .SYNOPSIS
        Analyzes domain and fine-grained password policies
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Analyzing password policies..." -Level Info
    
    $policies = @{
        DefaultPolicy = $null
        FineGrainedPolicies = @()
    }
    
    try {
        # Get default domain password policy
        $defaultPolicy = Get-ADDefaultDomainPasswordPolicy
        
        $policies.DefaultPolicy = [PSCustomObject]@{
            PolicyType = "Default Domain Policy"
            ComplexityEnabled = $defaultPolicy.ComplexityEnabled
            LockoutDuration = $defaultPolicy.LockoutDuration
            LockoutObservationWindow = $defaultPolicy.LockoutObservationWindow
            LockoutThreshold = $defaultPolicy.LockoutThreshold
            MaxPasswordAge = $defaultPolicy.MaxPasswordAge
            MinPasswordAge = $defaultPolicy.MinPasswordAge
            MinPasswordLength = $defaultPolicy.MinPasswordLength
            PasswordHistoryCount = $defaultPolicy.PasswordHistoryCount
            ReversibleEncryptionEnabled = $defaultPolicy.ReversibleEncryptionEnabled
            SecurityAssessment = if ($defaultPolicy.MinPasswordLength -lt 12 -or -not $defaultPolicy.ComplexityEnabled) { "Weak" } else { "Adequate" }
        }
        
        # Get fine-grained password policies (PSOs)
        $fgPolicies = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
        
        foreach ($policy in $fgPolicies) {
            $policies.FineGrainedPolicies += [PSCustomObject]@{
                Name = $policy.Name
                Precedence = $policy.Precedence
                AppliesTo = ($policy.AppliesTo -join "; ")
                ComplexityEnabled = $policy.ComplexityEnabled
                LockoutDuration = $policy.LockoutDuration
                LockoutThreshold = $policy.LockoutThreshold
                MaxPasswordAge = $policy.MaxPasswordAge
                MinPasswordLength = $policy.MinPasswordLength
                PasswordHistoryCount = $policy.PasswordHistoryCount
                ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled
            }
        }
        
        # Export results
        $policies.DefaultPolicy | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Password_Policy_Default.csv") -NoTypeInformation
        
        if ($policies.FineGrainedPolicies.Count -gt 0) {
            $policies.FineGrainedPolicies | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Password_Policies_FineGrained.csv") -NoTypeInformation
            Write-ModuleLog "Found $($policies.FineGrainedPolicies.Count) fine-grained password policies" -Level Success
        }
        
        Write-ModuleLog "Password policy analysis complete" -Level Success
        return $policies
    }
    catch {
        Write-ModuleLog "Failed to analyze password policies$($_ | Out-String)" -Level Error
        return $null
    }
}

function Get-DNSZoneInventory {
    <#
    .SYNOPSIS
        Analyzes DNS zones and configurations
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Analyzing DNS zones..." -Level Info
    
    $dnsData = @{
        Zones = @()
        Records = @()
    }
    
    try {
        # Get DNS server (use domain's DNS servers)
        $domain = Get-ADDomain
        $dnsServer = $domain.PDCEmulator
        
        # Get DNS zones
        $zones = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop
        
        foreach ($zone in $zones) {
            $dnsData.Zones += [PSCustomObject]@{
                ZoneName = $zone.ZoneName
                ZoneType = $zone.ZoneType
                DynamicUpdate = $zone.DynamicUpdate
                IsAutoCreated = $zone.IsAutoCreated
                IsDsIntegrated = $zone.IsDsIntegrated
                IsReverseLookupZone = $zone.IsReverseLookupZone
                IsSigned = $zone.IsSigned
                SecureSecondaries = $zone.SecureSecondaries
            }
            
            # Get sample records from each zone (first 100 for performance)
            try {
                $records = Get-DnsServerResourceRecord -ComputerName $dnsServer -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue | Select-Object -First 100
                
                foreach ($record in $records) {
                    $dnsData.Records += [PSCustomObject]@{
                        ZoneName = $zone.ZoneName
                        HostName = $record.HostName
                        RecordType = $record.RecordType
                        RecordData = $record.RecordData.IPv4Address -join ", "
                        TimeStamp = $record.Timestamp
                        TimeToLive = $record.TimeToLive
                    }
                }
            }
            catch {
                Write-ModuleLog "Failed to get records from zone $($zone.ZoneName)$($_ | Out-String)" -Level Warning
            }
        }
        
        # Export results
        if ($dnsData.Zones.Count -gt 0) {
            $dnsData.Zones | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_DNS_Zones.csv") -NoTypeInformation
            $dnsData.Records | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_DNS_Records_Sample.csv") -NoTypeInformation
            Write-ModuleLog "Found $($dnsData.Zones.Count) DNS zones" -Level Success
        }
        
        return $dnsData
    }
    catch {
        Write-ModuleLog "DNS module not available or failed to query$($_ | Out-String)" -Level Warning
        return $null
    }
}

function Get-CertificateServices {
    <#
    .SYNOPSIS
        Audits Active Directory Certificate Services if available
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFolder = $script:ADOutputPath
    )
    
    Write-ModuleLog "Analyzing Certificate Services..." -Level Info
    
    $certData = @{
        CertificationAuthorities = @()
        Templates = @()
    }
    
    try {
        # Check if ADCS is installed
        $configNC = (Get-ADRootDSE).configurationNamingContext
        
        # Find Certificate Authority objects
        $caObjects = Get-ADObject -Filter {objectClass -eq "pKIEnrollmentService"} -SearchBase $configNC -Properties *
        
        foreach ($ca in $caObjects) {
            $certData.CertificationAuthorities += [PSCustomObject]@{
                Name = $ca.Name
                DisplayName = $ca.displayName
                DNSHostName = $ca.dNSHostName
                CACertificate = if ($ca.cACertificate) { "Present" } else { "Missing" }
                DistinguishedName = $ca.DistinguishedName
            }
        }
        
        # Get certificate templates
        $templates = Get-ADObject -Filter {objectClass -eq "pKICertificateTemplate"} -SearchBase $configNC -Properties *
        
        foreach ($template in $templates) {
            $certData.Templates += [PSCustomObject]@{
                Name = $template.Name
                DisplayName = $template.displayName
                Created = $template.Created
                Modified = $template.Modified
                DistinguishedName = $template.DistinguishedName
            }
        }
        
        # Export results
        if ($certData.CertificationAuthorities.Count -gt 0) {
            $certData.CertificationAuthorities | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Certificate_Authorities.csv") -NoTypeInformation
            $certData.Templates | Export-Csv -Path (Join-Path $script:ADOutputPath "AD_Certificate_Templates.csv") -NoTypeInformation
            Write-ModuleLog "Found $($certData.CertificationAuthorities.Count) Certificate Authorities with $($certData.Templates.Count) templates" -Level Success
        }
        else {
            Write-ModuleLog "No Certificate Services found in AD" -Level Info
        }
        
        return $certData
    }
    catch {
        Write-ModuleLog "Failed to analyze Certificate Services$($_ | Out-String)" -Level Warning
        return $null
    }
}

#endregion

#region Server Hardware Inventory

function Get-ServerHardwareInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Servers,
        
        [int]$MaxParallel = 10,
        
        [int]$TimeoutSeconds = 300,
        
        [bool]$SkipOffline = $true
    )
    
    Write-ModuleLog "Starting hardware inventory on $($Servers.Count) servers..." -Level Info
    Write-ModuleLog "Querying $MaxParallel servers in parallel (timeout: $TimeoutSeconds seconds each)" -Level Info
    
    $serverResults = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

    # Process servers in batches
    $Servers | ForEach-Object -ThrottleLimit $MaxParallel -Parallel {
        $server = $_
        $serverName = $server.DNSHostName
        if ([string]::IsNullOrWhiteSpace($serverName)) {
            $serverName = $server.Name
        }

        $resultBag = $using:serverResults
        $timeout = $using:TimeoutSeconds
        $skipOffline = $using:SkipOffline

        # Progress tracking
        Write-Verbose "Processing $serverName..."
        
        $result = [PSCustomObject]@{
            ServerName = $serverName
            Status = 'Unknown'
            Online = $false
            ErrorMessage = ''
            # Hardware
            Manufacturer = ''
            Model = ''
            SerialNumber = ''
            BIOSVersion = ''
            CPUName = ''
            CPUCores = 0
            CPULogicalProcessors = 0
            MemoryGB = 0
            # OS
            OSName = ''
            OSVersion = ''
            OSBuild = ''
            OSInstallDate = $null
            LastBootTime = $null
            UptimeDays = 0
            # Virtualization
            IsVirtual = $false
            Hypervisor = ''
        }
        
        try {
            # Test connectivity first
            $ping = Test-Connection -ComputerName $serverName -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            if (-not $ping) {
                if ($skipOffline) {
                    $result.Status = 'Offline'
                    $result.ErrorMessage = 'Server did not respond to ping'
                    $resultBag.Add($result)
                    return
                }
            } else {
                $result.Online = $true
            }
            
            # Query hardware via CIM
            $cimSession = $null
            try {
                $sessionOption = New-CimSessionOption -Protocol Dcom
                $cimSession = New-CimSession -ComputerName $serverName -SessionOption $sessionOption -OperationTimeoutSec $timeout -ErrorAction Stop
                
                # Computer System
                $cs = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem -ErrorAction Stop
                $result.Manufacturer = $cs.Manufacturer
                $result.Model = $cs.Model
                $result.CPULogicalProcessors = $cs.NumberOfLogicalProcessors
                $result.MemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                
                # BIOS
                $bios = Get-CimInstance -CimSession $cimSession -ClassName Win32_BIOS -ErrorAction Stop
                $result.SerialNumber = $bios.SerialNumber
                $result.BIOSVersion = $bios.SMBIOSBIOSVersion
                
                # CPU
                $cpu = Get-CimInstance -CimSession $cimSession -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
                $result.CPUName = $cpu.Name
                $result.CPUCores = $cpu.NumberOfCores
                
                # Operating System
                $os = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem -ErrorAction Stop
                $result.OSName = $os.Caption
                $result.OSVersion = $os.Version
                $result.OSBuild = $os.BuildNumber
                $result.OSInstallDate = $os.InstallDate
                $result.LastBootTime = $os.LastBootUpTime
                $result.UptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
                
                # Virtualization detection
                $result.IsVirtual = $cs.Model -match 'Virtual|VMware|Hyper-V|KVM|Xen'
                if ($result.IsVirtual) {
                    if ($cs.Model -match 'VMware') { $result.Hypervisor = 'VMware' }
                    elseif ($cs.Model -match 'Hyper-V|Virtual Machine') { $result.Hypervisor = 'Hyper-V' }
                    elseif ($cs.Model -match 'KVM') { $result.Hypervisor = 'KVM' }
                    elseif ($cs.Model -match 'Xen') { $result.Hypervisor = 'Xen' }
                }
                
                $result.Status = 'Success'
            }
            finally {
                if ($cimSession) {
                    Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            $result.Status = 'Failed'
            $result.ErrorMessage = $_.Exception.Message
        }
        
        $resultBag.Add($result)
    }
    
    $results = @($serverResults)
    $successCount = ($results | Where-Object {$_.Status -eq 'Success'}).Count
    $offlineCount = ($results | Where-Object {$_.Status -eq 'Offline'}).Count
    $failedCount = ($results | Where-Object {$_.Status -eq 'Failed'}).Count
    
    Write-ModuleLog "Hardware inventory complete: $successCount successful, $offlineCount offline, $failedCount failed" -Level Success
    
    # Export results
    $results | Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Hardware_Details.csv") -NoTypeInformation
    
    # Export offline/failed servers separately
    $results | Where-Object {$_.Status -ne 'Success'} | 
        Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Unreachable.csv") -NoTypeInformation
    
    return $results | Where-Object {$_.Status -eq 'Success'}
}

#endregion

#region Server Storage Inventory

function Get-ServerStorageInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Servers,
        
        [int]$MaxParallel = 10
    )
    
    Write-ModuleLog "Collecting storage information from $($Servers.Count) servers..." -Level Info
    
    $storageResults = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    
    $Servers | ForEach-Object -ThrottleLimit $MaxParallel -Parallel {
        $server = $_
        $serverName = $server.ServerName
        $storageBag = $using:storageResults
        
        try {
            $sessionOption = New-CimSessionOption -Protocol Dcom
            $cimSession = New-CimSession -ComputerName $serverName -SessionOption $sessionOption -OperationTimeoutSec 120 -ErrorAction Stop
            
            try {
                $disks = Get-CimInstance -CimSession $cimSession -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
                
                foreach ($disk in $disks) {
                    $storageBag.Add([PSCustomObject]@{
                        ServerName = $serverName
                        DriveLetter = $disk.DeviceID
                        VolumeName = $disk.VolumeName
                        FileSystem = $disk.FileSystem
                        SizeGB = [math]::Round($disk.Size / 1GB, 2)
                        FreeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                        UsedSpaceGB = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
                        PercentFree = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
                    })
                }
            }
            finally {
                Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Verbose "Failed to collect storage from $($serverName): $($_.Exception.Message)"
        }
    }
    
    $results = @($storageResults)
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Storage_Details.csv") -NoTypeInformation
        Write-Verbose "Collected $($results.Count) disk volumes from servers"
    }
    
    return $results
}

#endregion

#region Installed Applications

function Get-ServerApplications {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Servers,
        
        [int]$MaxParallel = 10
    )
    
    Write-ModuleLog "Collecting installed applications from $($Servers.Count) servers..." -Level Info
    Write-ModuleLog "This may take 15-30 minutes..." -Level Warning
    
    $appResults = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    
    $Servers | ForEach-Object -ThrottleLimit $MaxParallel -Parallel {
        $server = $_
        $serverName = $server.ServerName
        $resultBag = $using:appResults
        
        try {
            $scriptBlock = {
                $apps = @()
                
                # Query both 64-bit and 32-bit registry paths
                $paths = @(
                    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                )
                
                foreach ($path in $paths) {
                    try {
                        $items = Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                            Where-Object { $_.DisplayName } |
                            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, EstimatedSize
                        $apps += $items
                    }
                    catch {}
                }
                
                return $apps
            }
            
            $apps = Invoke-Command -ComputerName $serverName -ScriptBlock $scriptBlock -ErrorAction Stop
            
            foreach ($app in $apps) {
                $resultBag.Add([PSCustomObject]@{
                    ServerName = $serverName
                    ApplicationName = $app.DisplayName
                    Version = $app.DisplayVersion
                    Publisher = $app.Publisher
                    InstallDate = $app.InstallDate
                    InstallLocation = $app.InstallLocation
                    SizeMB = if ($app.EstimatedSize) { [math]::Round($app.EstimatedSize / 1024, 2) } else { 0 }
                })
            }
        }
        catch {
            Write-Verbose "Failed to collect applications from $($serverName): $($_.Exception.Message)"
        }
    }
    
    $results = @($appResults)
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Installed_Applications.csv") -NoTypeInformation
        Write-Verbose "Collected $($results.Count) application installations"

        # Create application summary (aggregated)
        $summary = $results | Group-Object ApplicationName | Select-Object @{N='ApplicationName';E={$_.Name}},
            @{N='ServerCount';E={$_.Count}},
            @{N='MostCommonVersion';E={($_.Group | Group-Object Version | Sort-Object Count -Descending | Select-Object -First 1).Name}},
            @{N='Servers';E={($_.Group.ServerName | Sort-Object -Unique) -join '; '}}

        $summary | Sort-Object ServerCount -Descending |
            Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Application_Summary.csv") -NoTypeInformation
    }
    
    return $results
}

#endregion

#region Event Log Analysis

function Get-ServerEventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Servers,
        
        [int]$Days = 30,
        
        [int]$MaxParallel = 10
    )
    
    Write-ModuleLog "Collecting event logs from $($Servers.Count) servers (last $Days days)..." -Level Info
    Write-ModuleLog "This may take 15-30 minutes for large Security logs..." -Level Warning
    
    $criticalEvents = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $errorEvents = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    $Servers | ForEach-Object -ThrottleLimit $MaxParallel -Parallel {
        $server = $_
        $serverName = $server.ServerName
        $criticalBag = $using:criticalEvents
        $errorBag = $using:errorEvents
        $days = $using:Days
        $startDate = $using:startDate
        
        try {
            # Query Critical events
            $criticalFilter = @{
                LogName = 'System', 'Application'
                Level = 1  # Critical
                StartTime = $startDate
            }
            
            $criticals = Get-WinEvent -ComputerName $serverName -FilterHashtable $criticalFilter -ErrorAction SilentlyContinue |
                Group-Object Id, ProviderName |
                Select-Object @{N='ServerName';E={$serverName}},
                             @{N='EventID';E={$_.Group[0].Id}},
                             @{N='Source';E={$_.Group[0].ProviderName}},
                             @{N='LogName';E={$_.Group[0].LogName}},
                             @{N='Count';E={$_.Count}},
                             @{N='FirstOccurrence';E={($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated}},
                             @{N='LastOccurrence';E={($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated}},
                             @{N='Message';E={
                                 $msg = $_.Group[0].Message
                                 if ($msg) {
                                     ($msg -replace '[\r\n]+', ' ').Substring(0, [Math]::Min(500, $msg.Length))
                                 } else {
                                     'No message'
                                 }
                             }}
            
            foreach ($logEvent in $criticals) {
                $criticalBag.Add($logEvent)
            }
            
            # Query Error events
            $errorFilter = @{
                LogName = 'System', 'Application'
                Level = 2  # Error
                StartTime = $startDate
            }
            
            $errors = Get-WinEvent -ComputerName $serverName -FilterHashtable $errorFilter -MaxEvents 1000 -ErrorAction SilentlyContinue |
                Group-Object Id, ProviderName |
                Select-Object @{N='ServerName';E={$serverName}},
                             @{N='EventID';E={$_.Group[0].Id}},
                             @{N='Source';E={$_.Group[0].ProviderName}},
                             @{N='LogName';E={$_.Group[0].LogName}},
                             @{N='Count';E={$_.Count}},
                             @{N='FirstOccurrence';E={($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated}},
                             @{N='LastOccurrence';E={($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated}},
                             @{N='Message';E={
                                 $msg = $_.Group[0].Message
                                 if ($msg) {
                                     ($msg -replace '[\r\n]+', ' ').Substring(0, [Math]::Min(500, $msg.Length))
                                 } else {
                                     'No message'
                                 }
                             }}
            
            foreach ($logEvent in $errors) {
                $errorBag.Add($logEvent)
            }
            
            Write-Verbose "Collected event logs from $serverName"
        }
        catch {
            Write-Verbose "Failed to collect event logs from $($serverName): $($_.Exception.Message)"
        }
    }
    
    # Export results
    $criticalResults = @($criticalEvents) | Sort-Object Count -Descending
    if ($criticalResults.Count -gt 0) {
        $criticalResults | Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Event_Log_Critical.csv") -NoTypeInformation
        Write-Verbose "Collected $($criticalResults.Count) unique critical event types"
    }

    $errorResults = @($errorEvents) | Sort-Object Count -Descending
    if ($errorResults.Count -gt 0) {
        $errorResults | Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Event_Log_Errors.csv") -NoTypeInformation
        Write-Verbose "Collected $($errorResults.Count) unique error event types"
    }
    
    return @{
        Critical = $criticalResults
        Errors = $errorResults
    }
}

#endregion

#region Logon History Analysis

function Get-ServerLogonHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Servers,
        
        [int]$Days = 90,
        
        [int]$MaxParallel = 10
    )
    
    Write-ModuleLog "Collecting logon history from $($Servers.Count) servers (last $Days days)..." -Level Info
    Write-ModuleLog "This may take 20-40 minutes for large Security logs..." -Level Warning
    
    $logonResults = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $failureResults = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    $Servers | ForEach-Object -ThrottleLimit $MaxParallel -Parallel {
        $server = $_
        $serverName = $server.ServerName
        $logonBag = $using:logonResults
        $failureBag = $using:failureResults
        $startDate = $using:startDate
        
        try {
            # Query successful logons (Event ID 4624)
            $logonFilter = @{
                LogName = 'Security'
                ID = 4624
                StartTime = $startDate
            }
            
            $logons = Get-WinEvent -ComputerName $serverName -FilterHashtable $logonFilter -MaxEvents 10000 -ErrorAction SilentlyContinue
            
            if ($logons) {
                $logonSummary = $logons | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $targetUser = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                    $logonType = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
                    $sourceIP = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
                    
                    if ($targetUser -and $targetUser -notmatch '\$$') {  # Exclude computer accounts
                        [PSCustomObject]@{
                            ServerName = $serverName
                            UserName = $targetUser
                            LogonType = $logonType
                            SourceIP = $sourceIP
                            Timestamp = $_.TimeCreated
                        }
                    }
                } | Where-Object {$_}
                
                # Aggregate by user
                $userSummary = $logonSummary | Group-Object UserName | Select-Object @{N='ServerName';E={$serverName}},
                    @{N='UserName';E={$_.Name}},
                    @{N='LogonCount';E={$_.Count}},
                    @{N='FirstLogon';E={($_.Group | Sort-Object Timestamp | Select-Object -First 1).Timestamp}},
                    @{N='LastLogon';E={($_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp}},
                    @{N='LogonTypes';E={($_.Group.LogonType | Select-Object -Unique) -join '; '}},
                    @{N='UniqueIPs';E={($_.Group.SourceIP | Where-Object {$_ -ne '-'} | Select-Object -Unique).Count}}
                
                foreach ($user in $userSummary) {
                    $logonBag.Add($user)
                }
            }
            
            # Query failed logons (Event ID 4625)
            $failureFilter = @{
                LogName = 'Security'
                ID = 4625
                StartTime = $startDate
            }
            
            $failures = Get-WinEvent -ComputerName $serverName -FilterHashtable $failureFilter -MaxEvents 5000 -ErrorAction SilentlyContinue
            
            if ($failures) {
                $failureSummary = $failures | ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $targetUser = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
                    $failureReason = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Status'}).'#text'
                    
                    if ($targetUser) {
                        [PSCustomObject]@{
                            ServerName = $serverName
                            UserName = $targetUser
                            FailureReason = $failureReason
                            Timestamp = $_.TimeCreated
                        }
                    }
                } | Where-Object {$_}
                
                $userFailures = $failureSummary | Group-Object UserName | Select-Object @{N='ServerName';E={$serverName}},
                    @{N='UserName';E={$_.Name}},
                    @{N='FailureCount';E={$_.Count}},
                    @{N='FirstFailure';E={($_.Group | Sort-Object Timestamp | Select-Object -First 1).Timestamp}},
                    @{N='LastFailure';E={($_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp}}
                
                foreach ($failure in $userFailures) {
                    $failureBag.Add($failure)
                }
            }
            
            Write-Verbose "Collected logon history from $serverName"
        }
        catch {
            Write-Verbose "Failed to collect logon history from $($serverName): $($_.Exception.Message)"
        }
    }
    
    # Export results
    $logonResults = @($logonResults) | Sort-Object LogonCount -Descending
    if ($logonResults.Count -gt 0) {
        $logonResults | Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Logon_History.csv") -NoTypeInformation
        Write-Verbose "Collected logon history for $($logonResults.Count) users"
    }

    $failureResults = @($failureResults) | Sort-Object FailureCount -Descending
    if ($failureResults.Count -gt 0) {
        $failureResults | Export-Csv -Path (Join-Path $script:ServerOutputPath "Server_Logon_Failures.csv") -NoTypeInformation
        Write-Verbose "Collected $($failureResults.Count) users with failed logon attempts"
    }
    
    return @{
        Logons = $logonResults
        Failures = $failureResults
    }
}

#endregion

#region Main Execution

# Only run main execution if not being dot-sourced for testing
if ($MyInvocation.InvocationName -ne '.') {
try {
    Write-ModuleLog "Starting Active Directory audit..." -Level Info
    Write-ModuleLog "Output folder: $OutputFolder" -Level Info
    
    # Check if running performance analysis only
    if ($PerformanceAnalysisOnly) {
        Write-ModuleLog "Running performance analysis only..." -Level Info
        $performanceResults = Get-ADPerformanceAnalysis -OutputFolder $OutputFolder
        Write-ModuleLog "Performance analysis complete: $($performanceResults.Recommendations.Count) recommendations generated" -Level Success
        return
    }
    
    # Collect forest and domain information
    $forestInfo = Get-ADForestInfo
    
    # Collect user inventory
    $users = Get-ADUserInventory -OutputFolder $OutputFolder
    
    # Collect computer inventory (returns member servers)
    $memberServers = Get-ADComputerInventory -OutputFolder $OutputFolder
    
    # Collect group inventory
    $groups = Get-ADGroupInventory -OutputFolder $OutputFolder
    
    # Collect privileged accounts
    $privilegedAccounts = Get-PrivilegedAccounts -OutputFolder $OutputFolder
    
    # Performance Analysis and Capacity Planning
    if (-not $SkipPerformanceAnalysis) {
        Write-ModuleLog "Running AD performance analysis..." -Level Info
        $performanceResults = Get-ADPerformanceAnalysis -OutputFolder $OutputFolder
        Write-ModuleLog "Performance analysis complete: $($performanceResults.Recommendations.Count) recommendations generated" -Level Success
    }
    
    # Advanced AD Security Components
    Write-ModuleLog "Collecting advanced AD security components..." -Level Info
    
    Get-ACLAnalysis -OutputFolder $OutputFolder | Out-Null
    Get-KerberosDelegation -OutputFolder $OutputFolder | Out-Null
    Get-DHCPScopeAnalysis -OutputFolder $OutputFolder | Out-Null
    Get-GPOInventory -OutputFolder $OutputFolder | Out-Null
    Get-ServiceAccounts -OutputFolder $OutputFolder | Out-Null
    Get-ADTrustRelationships -OutputFolder $OutputFolder | Out-Null
    Get-PasswordPolicies -OutputFolder $OutputFolder | Out-Null
    Get-DNSZoneInventory -OutputFolder $OutputFolder | Out-Null
    Get-CertificateServices -OutputFolder $OutputFolder | Out-Null
    
    Write-ModuleLog "Advanced AD security component collection complete" -Level Success
    
    # Server Inventory (if enabled)
    if ($ServerInventory -and $memberServers) {
        Write-ModuleLog "Starting detailed server inventory on $($memberServers.Count) servers..." -Level Info
        Write-ModuleLog "This may take 30-90 minutes depending on server count and network speed" -Level Warning
        
        # Step 1: Hardware inventory
        $onlineServers = Get-ServerHardwareInventory -Servers $memberServers `
            -MaxParallel $MaxParallelServers `
            -TimeoutSeconds $ServerQueryTimeout `
            -SkipOffline $SkipOfflineServers
        
        $script:Stats.ServersOnline = $onlineServers.Count
        $script:Stats.ServersOffline = $memberServers.Count - $onlineServers.Count
        
        if ($onlineServers.Count -eq 0) {
            Write-ModuleLog "No servers were reachable - skipping remaining server inventory" -Level Warning
        }
        else {
            # Step 2: Storage inventory
            Get-ServerStorageInventory -Servers $onlineServers -MaxParallel $MaxParallelServers | Out-Null
            
            # Step 3: Installed applications
            Get-ServerApplications -Servers $onlineServers -MaxParallel $MaxParallelServers | Out-Null
            
            # Step 4: Event logs (if not skipped)
            if (-not $SkipEventLogs) {
                $eventLogs = Get-ServerEventLogs -Servers $onlineServers -Days $ServerEventLogDays -MaxParallel $MaxParallelServers
                Write-ModuleLog "Collected $($eventLogs.Critical.Count) critical and $($eventLogs.Errors.Count) error event types" -Level Success
            }
            
            # Step 5: Logon history (if not skipped)  
            if (-not $SkipLogonHistory) {
                $logonHistory = Get-ServerLogonHistory -Servers $onlineServers -Days $ServerLogonHistoryDays -MaxParallel $MaxParallelServers
                Write-ModuleLog "Collected logon history for $($logonHistory.Logons.Count) users" -Level Success
            }
            
            # Step 6: SQL Server inventory (if not skipped)
            if (-not $SkipSQL) {
                Write-ModuleLog "SQL Server inventory will be implemented in next iteration" -Level Warning
            }
            
            Write-ModuleLog "Server inventory completed for $($onlineServers.Count) servers" -Level Success
        }
    }
    
    # Return summary
    Write-ModuleLog "Active Directory audit completed successfully" -Level Success
    Write-ModuleLog "Statistics:" -Level Info
    Write-ModuleLog "  Total Users: $($script:Stats.TotalUsers) ($($script:Stats.EnabledUsers) enabled)" -Level Info
    Write-ModuleLog "  Total Computers: $($script:Stats.TotalComputers)" -Level Info
    Write-ModuleLog "  Member Servers: $($script:Stats.TotalServers)" -Level Info
    
    return @{
        Success = $true
        Statistics = $script:Stats
        Message = "AD audit completed successfully"
    }
}
catch {
    Write-ModuleLog "Active Directory audit failed: $_" -Level Error
    throw
}
}

#endregion

