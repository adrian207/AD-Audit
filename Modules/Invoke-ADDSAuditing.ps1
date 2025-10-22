<#
.SYNOPSIS
    Active Directory Domain Services Auditing Module

.DESCRIPTION
    Comprehensive AD DS auditing based on Microsoft's AD DS Auditing Step-by-Step Guide.
    Implements advanced auditing features including old/new value tracking for attribute changes,
    SACL analysis, and directory service change monitoring as recommended by Microsoft.

.PARAMETER DatabasePath
    Path to audit database for storing results

.PARAMETER OutputPath
    Path to save CSV results

.PARAMETER IncludeDirectoryServiceAccess
    Include Directory Service Access events (Event ID 4662)

.PARAMETER IncludeDirectoryServiceChanges
    Include Directory Service Changes events (Event IDs 5136-5141)

.PARAMETER IncludeDirectoryServiceReplication
    Include Directory Service Replication events

.PARAMETER IncludeDetailedReplication
    Include Detailed Directory Service Replication events

.PARAMETER IncludeSACLAnalysis
    Include SACL (System Access Control List) analysis

.PARAMETER IncludeSchemaAnalysis
    Include schema attribute auditing configuration analysis

.PARAMETER IncludeAll
    Include all AD DS auditing categories

.PARAMETER Days
    Number of days to analyze (default: 30)

.PARAMETER Servers
    Array of servers to monitor (default: all domain controllers)

.PARAMETER TargetObjects
    Array of specific objects to audit (default: all objects)

.PARAMETER TargetAttributes
    Array of specific attributes to audit (default: all attributes)

.EXAMPLE
    .\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.EXAMPLE
    .\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeDirectoryServiceChanges -Days 7

.EXAMPLE
    .\Invoke-ADDSAuditing.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeSACLAnalysis -TargetObjects @("CN=Users,DC=domain,DC=com")

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Based on: Microsoft AD DS Auditing Step-by-Step Guide
    Requires: Domain admin rights, event log access, SACL management rights
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Temp\ADDSAuditing.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDirectoryServiceAccess,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDirectoryServiceChanges,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDirectoryServiceReplication,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDetailedReplication,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSACLAnalysis,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSchemaAnalysis,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll,
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 30,
    
    [Parameter(Mandatory = $false)]
    [array]$Servers,
    
    [Parameter(Mandatory = $false)]
    [array]$TargetObjects,
    
    [Parameter(Mandatory = $false)]
    [array]$TargetAttributes
)

$ErrorActionPreference = 'Stop'

# Set flags based on IncludeAll parameter
if ($IncludeAll) {
    $IncludeDirectoryServiceAccess = $true
    $IncludeDirectoryServiceChanges = $true
    $IncludeDirectoryServiceReplication = $true
    $IncludeDetailedReplication = $true
    $IncludeSACLAnalysis = $true
    $IncludeSchemaAnalysis = $true
}

#region Helper Functions

function Write-ADDSAuditingLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [AD-DS-Auditing] [$Level] $Message"
    
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
        Write-ADDSAuditingLog "Failed to connect to database: $_" -Level Error
        throw
    }
}

function Get-DomainControllers {
    [CmdletBinding()]
    param()
    
    try {
        $domainControllers = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
        return $domainControllers.HostName
    }
    catch {
        Write-ADDSAuditingLog "Failed to get domain controllers: $_" -Level Warning
        return @()
    }
}

#endregion

#region AD DS Auditing Functions

function Get-DirectoryServiceAccessEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-ADDSAuditingLog "Monitoring Directory Service Access events (Event ID 4662)..." -Level Info
    
    $directoryServiceAccessEvents = @()
    
    # Event ID 4662: Directory Service Access (replaces Event ID 566 from Windows Server 2003)
    $startDate = (Get-Date).AddDays(-$Days)
    
    foreach ($server in $TargetServers) {
        try {
            $filter = @{
                LogName = 'Security'
                ID = 4662
                StartTime = $startDate
            }
            
            $events = Get-WinEvent -ComputerName $server -FilterHashtable $filter -MaxEvents 1000 -ErrorAction SilentlyContinue
            
            if ($events) {
                foreach ($eventRecord in $events) {
                    $xml = [xml]$eventRecord.ToXml()
                    $eventData = @{}
                    
                    # Extract event data
                    foreach ($data in $xml.Event.EventData.Data) {
                        $eventData[$data.Name] = $data.'#text'
                    }
                    
                    $directoryServiceAccessEvents += [PSCustomObject]@{
                        ServerName = $server
                        EventID = 4662
                        EventSummary = "Directory Service Access"
                        EventType = "Directory Service Access"
                        TimeCreated = $eventRecord.TimeCreated
                        Level = $eventRecord.LevelDisplayName
                        Source = $eventRecord.ProviderName
                        LogName = $eventRecord.LogName
                        SubjectUserSid = $eventData.SubjectUserSid
                        SubjectUserName = $eventData.SubjectUserName
                        SubjectDomainName = $eventData.SubjectDomainName
                        SubjectLogonId = $eventData.SubjectLogonId
                        ObjectServer = $eventData.ObjectServer
                        ObjectType = $eventData.ObjectType
                        ObjectName = $eventData.ObjectName
                        HandleId = $eventData.HandleId
                        OperationType = $eventData.OperationType
                        Accesses = $eventData.Accesses
                        AccessMask = $eventData.AccessMask
                        Properties = $eventData.Properties
                        EventData = ($eventData | ConvertTo-Json -Compress)
                        Message = $eventRecord.Message
                        InvestigationRequired = 'If unexpected access patterns'
                        Recommendation = 'Review access patterns and verify legitimate access'
                    }
                }
            }
        }
        catch {
            Write-ADDSAuditingLog "Failed to query Directory Service Access events on $server`: $_" -Level Warning
        }
    }
    
    Write-ADDSAuditingLog "Found $($directoryServiceAccessEvents.Count) Directory Service Access events" -Level Success
    return $directoryServiceAccessEvents
}

function Get-DirectoryServiceChangeEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-ADDSAuditingLog "Monitoring Directory Service Changes events (Event IDs 5136-5141)..." -Level Info
    
    $directoryServiceChangeEvents = @()
    
    # Define Directory Service Changes event IDs based on Microsoft guide
    $directoryServiceChangeEventIDs = @{
        5136 = "A directory service object was modified"
        5137 = "A directory service object was created"
        5138 = "A directory service object was undeleted"
        5139 = "A directory service object was moved"
        5141 = "A directory service object was deleted"
    }
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    foreach ($server in $TargetServers) {
        try {
            foreach ($eventID in $directoryServiceChangeEventIDs.Keys) {
                try {
                    $filter = @{
                        LogName = 'Security'
                        ID = $eventID
                        StartTime = $startDate
                    }
                    
                    $events = Get-WinEvent -ComputerName $server -FilterHashtable $filter -MaxEvents 1000 -ErrorAction SilentlyContinue
                    
                    if ($events) {
                        foreach ($eventRecord in $events) {
                            $xml = [xml]$eventRecord.ToXml()
                            $eventData = @{}
                            
                            # Extract event data
                            foreach ($data in $xml.Event.EventData.Data) {
                                $eventData[$data.Name] = $data.'#text'
                            }
                            
                            # Extract old and new values for attribute changes
                            $oldValue = $eventData.OldValue
                            $newValue = $eventData.NewValue
                            $attributeName = $eventData.AttributeLDAPDisplayName
                            
                            $directoryServiceChangeEvents += [PSCustomObject]@{
                                ServerName = $server
                                EventID = $eventID
                                EventSummary = $directoryServiceChangeEventIDs[$eventID]
                                EventType = "Directory Service Changes"
                                TimeCreated = $eventRecord.TimeCreated
                                Level = $eventRecord.LevelDisplayName
                                Source = $eventRecord.ProviderName
                                LogName = $eventRecord.LogName
                                SubjectUserSid = $eventData.SubjectUserSid
                                SubjectUserName = $eventData.SubjectUserName
                                SubjectDomainName = $eventData.SubjectDomainName
                                SubjectLogonId = $eventData.SubjectLogonId
                                ObjectDN = $eventData.DSName
                                ObjectGUID = $eventData.DSGuid
                                ObjectClass = $eventData.DSClass
                                AttributeName = $attributeName
                                OldValue = $oldValue
                                NewValue = $newValue
                                OperationType = $eventData.DSOperation
                                TreeDelete = $eventData.DSTreeDelete
                                EventData = ($eventData | ConvertTo-Json -Compress)
                                Message = $eventRecord.Message
                                InvestigationRequired = 'Immediate for critical objects'
                                Recommendation = 'Review object changes and verify legitimate modifications'
                                ValueChangeDetected = ($oldValue -ne $newValue)
                            }
                        }
                    }
                }
                catch {
                    Write-ADDSAuditingLog "Failed to query event $eventID on $server`: $_" -Level Warning
                }
            }
        }
        catch {
            Write-ADDSAuditingLog "Failed to connect to $server`: $_" -Level Warning
        }
    }
    
    Write-ADDSAuditingLog "Found $($directoryServiceChangeEvents.Count) Directory Service Changes events" -Level Success
    return $directoryServiceChangeEvents
}

function Get-DirectoryServiceReplicationEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-ADDSAuditingLog "Monitoring Directory Service Replication events..." -Level Info
    
    $directoryServiceReplicationEvents = @()
    
    # Define Directory Service Replication event IDs
    $directoryServiceReplicationEventIDs = @{
        4928 = "An Active Directory replica source naming context was established"
        4929 = "An Active Directory replica source naming context was removed"
        4930 = "An Active Directory replica source naming context was modified"
        4931 = "An Active Directory replica destination naming context was created"
        4932 = "An Active Directory replica destination naming context was deleted"
        4933 = "An Active Directory replica destination naming context was modified"
        4934 = "An Active Directory replica source naming context was established"
        4935 = "An Active Directory replica source naming context was removed"
        4936 = "An Active Directory replica source naming context was modified"
        4937 = "An Active Directory replica destination naming context was created"
        4938 = "An Active Directory replica destination naming context was deleted"
        4939 = "An Active Directory replica destination naming context was modified"
    }
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    foreach ($server in $TargetServers) {
        try {
            foreach ($eventID in $directoryServiceReplicationEventIDs.Keys) {
                try {
                    $filter = @{
                        LogName = 'Security'
                        ID = $eventID
                        StartTime = $startDate
                    }
                    
                    $events = Get-WinEvent -ComputerName $server -FilterHashtable $filter -MaxEvents 1000 -ErrorAction SilentlyContinue
                    
                    if ($events) {
                        foreach ($eventRecord in $events) {
                            $xml = [xml]$eventRecord.ToXml()
                            $eventData = @{}
                            
                            # Extract event data
                            foreach ($data in $xml.Event.EventData.Data) {
                                $eventData[$data.Name] = $data.'#text'
                            }
                            
                            $directoryServiceReplicationEvents += [PSCustomObject]@{
                                ServerName = $server
                                EventID = $eventID
                                EventSummary = $directoryServiceReplicationEventIDs[$eventID]
                                EventType = "Directory Service Replication"
                                TimeCreated = $eventRecord.TimeCreated
                                Level = $eventRecord.LevelDisplayName
                                Source = $eventRecord.ProviderName
                                LogName = $eventRecord.LogName
                                SubjectUserSid = $eventData.SubjectUserSid
                                SubjectUserName = $eventData.SubjectUserName
                                SubjectDomainName = $eventData.SubjectDomainName
                                SubjectLogonId = $eventData.SubjectLogonId
                                NamingContext = $eventData.NamingContext
                                SourceServer = $eventData.SourceServer
                                DestinationServer = $eventData.DestinationServer
                                EventData = ($eventData | ConvertTo-Json -Compress)
                                Message = $eventRecord.Message
                                InvestigationRequired = 'If unexpected replication changes'
                                Recommendation = 'Review replication topology changes and verify legitimate modifications'
                            }
                        }
                    }
                }
                catch {
                    Write-ADDSAuditingLog "Failed to query event $eventID on $server`: $_" -Level Warning
                }
            }
        }
        catch {
            Write-ADDSAuditingLog "Failed to connect to $server`: $_" -Level Warning
        }
    }
    
    Write-ADDSAuditingLog "Found $($directoryServiceReplicationEvents.Count) Directory Service Replication events" -Level Success
    return $directoryServiceReplicationEvents
}

function Get-SACLAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$TargetObjects
    )
    
    Write-ADDSAuditingLog "Analyzing SACL (System Access Control List) configuration..." -Level Info
    
    $saclAnalysis = @()
    
    try {
        # If no specific objects provided, analyze common critical objects
        if (-not $TargetObjects) {
            $TargetObjects = @(
                "CN=Users,DC=$((Get-ADDomain).DistinguishedName)",
                "CN=Computers,DC=$((Get-ADDomain).DistinguishedName)",
                "CN=Domain Controllers,DC=$((Get-ADDomain).DistinguishedName)",
                "CN=Administrators,CN=Builtin,DC=$((Get-ADDomain).DistinguishedName)",
                "CN=Domain Admins,CN=Users,DC=$((Get-ADDomain).DistinguishedName)",
                "CN=Enterprise Admins,CN=Users,DC=$((Get-ADDomain).DistinguishedName)"
            )
        }
        
        foreach ($objectDN in $TargetObjects) {
            try {
                $object = Get-ADObject -Identity $objectDN -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
                
                if ($object) {
                    $securityDescriptor = $object.nTSecurityDescriptor
                    $sacl = $securityDescriptor.SystemAcl
                    
                    if ($sacl) {
                        foreach ($ace in $sacl) {
                            $saclAnalysis += [PSCustomObject]@{
                                ObjectDN = $objectDN
                                ObjectClass = $object.ObjectClass
                                ACEType = $ace.AceType
                                Trustee = $ace.SecurityIdentifier
                                AccessMask = $ace.AccessMask
                                AuditFlags = $ace.AuditFlags
                                InheritanceFlags = $ace.InheritanceFlags
                                PropagationFlags = $ace.PropagationFlags
                                IsInherited = $ace.IsInherited
                                AuditEnabled = ($ace.AuditFlags -ne 'None')
                                InvestigationRequired = 'Review SACL configuration'
                                Recommendation = 'Ensure critical objects have appropriate SACL entries for auditing'
                            }
                        }
                    }
                    else {
                        $saclAnalysis += [PSCustomObject]@{
                            ObjectDN = $objectDN
                            ObjectClass = $object.ObjectClass
                            ACEType = 'None'
                            Trustee = 'None'
                            AccessMask = 'None'
                            AuditFlags = 'None'
                            InheritanceFlags = 'None'
                            PropagationFlags = 'None'
                            IsInherited = $false
                            AuditEnabled = $false
                            InvestigationRequired = 'Critical - No SACL configured'
                            Recommendation = 'Configure SACL for critical objects to enable auditing'
                        }
                    }
                }
            }
            catch {
                Write-ADDSAuditingLog "Failed to analyze SACL for $objectDN`: $_" -Level Warning
            }
        }
    }
    catch {
        Write-ADDSAuditingLog "Failed to perform SACL analysis: $_" -Level Error
    }
    
    Write-ADDSAuditingLog "Analyzed SACL configuration for $($saclAnalysis.Count) objects" -Level Success
    return $saclAnalysis
}

function Get-SchemaAuditingConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$TargetAttributes
    )
    
    Write-ADDSAuditingLog "Analyzing schema auditing configuration..." -Level Info
    
    $schemaAnalysis = @()
    
    try {
        # Get schema partition
        $schemaDN = (Get-ADRootDSE).schemaNamingContext
        
        # If no specific attributes provided, analyze common critical attributes
        if (-not $TargetAttributes) {
            $TargetAttributes = @(
                'userPrincipalName',
                'sAMAccountName',
                'member',
                'memberOf',
                'userAccountControl',
                'pwdLastSet',
                'lastLogon',
                'lastLogonTimestamp',
                'servicePrincipalName',
                'msDS-AllowedToDelegateTo',
                'msDS-AllowedToActOnBehalfOfOtherIdentity'
            )
        }
        
        foreach ($attributeName in $TargetAttributes) {
            try {
                $attribute = Get-ADObject -SearchBase $schemaDN -Filter "lDAPDisplayName -eq '$attributeName'" -Properties searchFlags -ErrorAction SilentlyContinue
                
                if ($attribute) {
                    $searchFlags = $attribute.searchFlags
                    $auditingDisabled = ($searchFlags -band 256) -eq 256  # Bit 8 (value 256) disables auditing
                    
                    $schemaAnalysis += [PSCustomObject]@{
                        AttributeName = $attributeName
                        LDAPDisplayName = $attribute.lDAPDisplayName
                        SearchFlags = $searchFlags
                        AuditingDisabled = $auditingDisabled
                        AuditingEnabled = -not $auditingDisabled
                        InvestigationRequired = if ($auditingDisabled) { 'Critical - Auditing disabled' } else { 'Review auditing configuration' }
                        Recommendation = if ($auditingDisabled) { 'Enable auditing for critical attributes' } else { 'Verify auditing configuration is appropriate' }
                    }
                }
            }
            catch {
                Write-ADDSAuditingLog "Failed to analyze schema for attribute $attributeName`: $_" -Level Warning
            }
        }
    }
    catch {
        Write-ADDSAuditingLog "Failed to perform schema analysis: $_" -Level Error
    }
    
    Write-ADDSAuditingLog "Analyzed schema configuration for $($schemaAnalysis.Count) attributes" -Level Success
    return $schemaAnalysis
}

function Get-AuditPolicyConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers
    )
    
    Write-ADDSAuditingLog "Analyzing audit policy configuration..." -Level Info
    
    $auditPolicyAnalysis = @()
    
    # Define AD DS audit policy subcategories
    $auditSubcategories = @{
        'Directory Service Access' = 'Audit directory service access'
        'Directory Service Changes' = 'Audit directory service changes'
        'Directory Service Replication' = 'Audit directory service replication'
        'Detailed Directory Service Replication' = 'Audit detailed directory service replication'
    }
    
    foreach ($server in $TargetServers) {
        try {
            foreach ($subcategory in $auditSubcategories.Keys) {
                try {
                    # Use auditpol.exe to check audit policy
                    $auditResult = Invoke-Command -ComputerName $server -ScriptBlock {
                        param($subcategory)
                        try {
                            $result = auditpol.exe /get /subcategory:"$subcategory" 2>$null
                            return $result
                        }
                        catch {
                            return "Error: $_"
                        }
                    } -ArgumentList $subcategory -ErrorAction SilentlyContinue
                    
                    if ($auditResult) {
                        $auditPolicyAnalysis += [PSCustomObject]@{
                            ServerName = $server
                            Subcategory = $subcategory
                            PolicyName = $auditSubcategories[$subcategory]
                            Configuration = $auditResult
                            InvestigationRequired = 'Review audit policy configuration'
                            Recommendation = 'Ensure appropriate audit policy is configured for AD DS auditing'
                        }
                    }
                }
                catch {
                    Write-ADDSAuditingLog "Failed to check audit policy for $subcategory on $server`: $_" -Level Warning
                }
            }
        }
        catch {
            Write-ADDSAuditingLog "Failed to connect to $server`: $_" -Level Warning
        }
    }
    
    Write-ADDSAuditingLog "Analyzed audit policy configuration for $($auditPolicyAnalysis.Count) subcategories" -Level Success
    return $auditPolicyAnalysis
}

function Get-ADDSAuditingSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllResults
    )
    
    Write-ADDSAuditingLog "Generating AD DS auditing summary..." -Level Info
    
    $summary = @{
        TotalEvents = 0
        DirectoryServiceAccessEvents = 0
        DirectoryServiceChangeEvents = 0
        DirectoryServiceReplicationEvents = 0
        SACLEntries = 0
        SchemaAttributes = 0
        AuditPolicySubcategories = 0
        ValueChangesDetected = 0
        CriticalObjectsMonitored = 0
        InvestigationRequired = 0
    }
    
    foreach ($result in $AllResults) {
        $summary.TotalEvents++
        
        # Count by event type
        switch ($result.EventType) {
            'Directory Service Access' { $summary.DirectoryServiceAccessEvents++ }
            'Directory Service Changes' { $summary.DirectoryServiceChangeEvents++ }
            'Directory Service Replication' { $summary.DirectoryServiceReplicationEvents++ }
        }
        
        # Count SACL entries
        if ($result.ObjectDN) {
            $summary.SACLEntries++
        }
        
        # Count schema attributes
        if ($result.AttributeName) {
            $summary.SchemaAttributes++
        }
        
        # Count audit policy subcategories
        if ($result.Subcategory) {
            $summary.AuditPolicySubcategories++
        }
        
        # Count value changes
        if ($result.ValueChangeDetected) {
            $summary.ValueChangesDetected++
        }
        
        # Count critical objects
        if ($result.ObjectDN -and $result.ObjectDN -match '(Users|Computers|Domain Controllers|Administrators|Domain Admins|Enterprise Admins)') {
            $summary.CriticalObjectsMonitored++
        }
        
        # Count investigation required
        if ($result.InvestigationRequired -match 'Critical|Immediate') {
            $summary.InvestigationRequired++
        }
    }
    
    return $summary
}

#endregion

#region Main Execution

try {
    Write-ADDSAuditingLog "Starting AD DS Auditing Analysis..." -Level Info
    Write-ADDSAuditingLog "Database path: $DatabasePath" -Level Info
    Write-ADDSAuditingLog "Output path: $OutputPath" -Level Info
    Write-ADDSAuditingLog "Analysis period: $Days days" -Level Info
    
    $allResults = @()
    
    # Determine target servers
    if ($Servers) {
        $targetServers = $Servers
    }
    else {
        $targetServers = Get-DomainControllers
    }
    
    if ($targetServers.Count -eq 0) {
        throw "No target servers available for monitoring"
    }
    
    Write-ADDSAuditingLog "Monitoring $($targetServers.Count) servers: $($targetServers -join ', ')" -Level Info
    
    # Optional analyses based on parameters
    if ($IncludeDirectoryServiceAccess) {
        Write-ADDSAuditingLog "Monitoring Directory Service Access events..." -Level Info
        $directoryServiceAccessEvents = Get-DirectoryServiceAccessEvents -TargetServers $targetServers -Days $Days
        $allResults += $directoryServiceAccessEvents
    }
    
    if ($IncludeDirectoryServiceChanges) {
        Write-ADDSAuditingLog "Monitoring Directory Service Changes events..." -Level Info
        $directoryServiceChangeEvents = Get-DirectoryServiceChangeEvents -TargetServers $targetServers -Days $Days
        $allResults += $directoryServiceChangeEvents
    }
    
    if ($IncludeDirectoryServiceReplication) {
        Write-ADDSAuditingLog "Monitoring Directory Service Replication events..." -Level Info
        $directoryServiceReplicationEvents = Get-DirectoryServiceReplicationEvents -TargetServers $targetServers -Days $Days
        $allResults += $directoryServiceReplicationEvents
    }
    
    if ($IncludeSACLAnalysis) {
        Write-ADDSAuditingLog "Analyzing SACL configuration..." -Level Info
        $saclAnalysis = Get-SACLAnalysis -TargetObjects $TargetObjects
        $allResults += $saclAnalysis
    }
    
    if ($IncludeSchemaAnalysis) {
        Write-ADDSAuditingLog "Analyzing schema auditing configuration..." -Level Info
        $schemaAnalysis = Get-SchemaAuditingConfiguration -TargetAttributes $TargetAttributes
        $allResults += $schemaAnalysis
    }
    
    # Always include audit policy configuration
    Write-ADDSAuditingLog "Analyzing audit policy configuration..." -Level Info
    $auditPolicyAnalysis = Get-AuditPolicyConfiguration -TargetServers $targetServers
    $allResults += $auditPolicyAnalysis
    
    # Generate summary
    $summary = Get-ADDSAuditingSummary -AllResults $allResults
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-ADDSAuditingLog "AD DS auditing results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-ADDSAuditingLog "AD DS Auditing Summary:" -Level Info
    Write-ADDSAuditingLog "  Total Events: $($summary.TotalEvents)" -Level Info
    Write-ADDSAuditingLog "  Directory Service Access Events: $($summary.DirectoryServiceAccessEvents)" -Level Info
    Write-ADDSAuditingLog "  Directory Service Changes Events: $($summary.DirectoryServiceChangeEvents)" -Level Warning
    Write-ADDSAuditingLog "  Directory Service Replication Events: $($summary.DirectoryServiceReplicationEvents)" -Level Info
    Write-ADDSAuditingLog "  SACL Entries: $($summary.SACLEntries)" -Level Info
    Write-ADDSAuditingLog "  Schema Attributes: $($summary.SchemaAttributes)" -Level Info
    Write-ADDSAuditingLog "  Audit Policy Subcategories: $($summary.AuditPolicySubcategories)" -Level Info
    Write-ADDSAuditingLog "  Value Changes Detected: $($summary.ValueChangesDetected)" -Level Warning
    Write-ADDSAuditingLog "  Critical Objects Monitored: $($summary.CriticalObjectsMonitored)" -Level Info
    Write-ADDSAuditingLog "  Events Requiring Investigation: $($summary.InvestigationRequired)" -Level Error
    
    Write-ADDSAuditingLog "AD DS auditing analysis completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allResults
        Message = "AD DS auditing analysis completed successfully"
    }
}
catch {
    Write-ADDSAuditingLog "AD DS auditing analysis failed: $_" -Level Error
    throw
}

#endregion
