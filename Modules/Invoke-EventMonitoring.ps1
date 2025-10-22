<#
.SYNOPSIS
    Active Directory Event Monitoring Module

.DESCRIPTION
    Comprehensive event monitoring based on Microsoft's Appendix L: Events to Monitor.
    Monitors critical security events, audit policy changes, and compromise indicators
    as recommended by Microsoft for Active Directory security monitoring.

.PARAMETER DatabasePath
    Path to audit database for storing results

.PARAMETER OutputPath
    Path to save CSV results

.PARAMETER IncludeHighCriticalityEvents
    Include high criticality events (immediate investigation required)

.PARAMETER IncludeMediumCriticalityEvents
    Include medium criticality events (investigate if unexpected)

.PARAMETER IncludeLowCriticalityEvents
    Include low criticality events (baseline monitoring)

.PARAMETER IncludeAuditPolicyEvents
    Include audit policy change events

.PARAMETER IncludeCompromiseIndicators
    Include compromise indicator events

.PARAMETER IncludeAll
    Include all event monitoring categories

.PARAMETER Days
    Number of days to analyze (default: 30)

.PARAMETER Servers
    Array of servers to monitor (default: all domain controllers)

.EXAMPLE
    .\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeAll

.EXAMPLE
    .\Invoke-EventMonitoring.ps1 -DatabasePath "C:\Audits\AuditData.db" -IncludeHighCriticalityEvents -Days 7

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Based on: Microsoft Appendix L: Events to Monitor
    Requires: Domain admin rights, event log access
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Temp\EventMonitoring.csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHighCriticalityEvents,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMediumCriticalityEvents,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLowCriticalityEvents,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAuditPolicyEvents,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCompromiseIndicators,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAll,
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 30,
    
    [Parameter(Mandatory = $false)]
    [array]$Servers
)

$ErrorActionPreference = 'Stop'

# Set flags based on IncludeAll parameter
if ($IncludeAll) {
    $IncludeHighCriticalityEvents = $true
    $IncludeMediumCriticalityEvents = $true
    $IncludeLowCriticalityEvents = $true
    $IncludeAuditPolicyEvents = $true
    $IncludeCompromiseIndicators = $true
}

#region Helper Functions

function Write-EventMonitoringLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Critical')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Event-Monitoring] [$Level] $Message"
    
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
        Write-EventMonitoringLog "Failed to connect to database: $_" -Level Error
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
        Write-EventMonitoringLog "Failed to get domain controllers: $_" -Level Warning
        return @()
    }
}

#endregion

#region Event Monitoring Functions

function Get-HighCriticalityEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-EventMonitoringLog "Monitoring high criticality events..." -Level Info
    
    $highCriticalityEvents = @()
    
    # Define high criticality event IDs based on Microsoft Appendix L
    $highCriticalityEventIDs = @{
        4618 = "A monitored security event pattern has occurred"
        4649 = "A replay attack was detected"
        4719 = "System audit policy was changed"
        4765 = "SID History was added to an account"
        4766 = "An attempt to add SID History to an account failed"
        4794 = "An attempt was made to set the Directory Services Restore Mode"
        4897 = "Role separation enabled"
        4964 = "Special groups have been assigned to a new logon"
        5124 = "A security setting was updated on the OCSP Responder Service"
    }
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    foreach ($server in $TargetServers) {
        try {
            foreach ($eventID in $highCriticalityEventIDs.Keys) {
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
                            
                            $highCriticalityEvents += [PSCustomObject]@{
                                ServerName = $server
                                EventID = $eventID
                                EventSummary = $highCriticalityEventIDs[$eventID]
                                Criticality = 'High'
                                TimeCreated = $eventRecord.TimeCreated
                                Level = $eventRecord.LevelDisplayName
                                Source = $eventRecord.ProviderName
                                LogName = $eventRecord.LogName
                                EventData = ($eventData | ConvertTo-Json -Compress)
                                Message = $eventRecord.Message
                                InvestigationRequired = 'Immediate'
                                Recommendation = 'Investigate immediately - high criticality event'
                            }
                        }
                    }
                }
                catch {
                    Write-EventMonitoringLog "Failed to query event $eventID on $server`: $_" -Level Warning
                }
            }
        }
        catch {
            Write-EventMonitoringLog "Failed to connect to $server`: $_" -Level Warning
        }
    }
    
    Write-EventMonitoringLog "Found $($highCriticalityEvents.Count) high criticality events" -Level Success
    return $highCriticalityEvents
}

function Get-MediumCriticalityEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-EventMonitoringLog "Monitoring medium criticality events..." -Level Info
    
    $mediumCriticalityEvents = @()
    
    # Define medium criticality event IDs based on Microsoft Appendix L
    $mediumCriticalityEventIDs = @{
        1102 = "The audit log was cleared"
        4621 = "Administrator recovered system from CrashOnAuditFail"
        4675 = "SIDs were filtered"
        4713 = "Kerberos policy was changed"
        4714 = "Encrypted data recovery policy was changed"
        4715 = "The audit policy (SACL) on an object was changed"
        4716 = "Trusted domain information was modified"
        4717 = "System security access was granted to an account"
        4718 = "System security access was removed from an account"
        4720 = "A user account was created"
        4722 = "A user account was enabled"
        4723 = "An attempt was made to change an account's password"
        4724 = "An attempt was made to reset an account's password"
        4725 = "A user account was disabled"
        4726 = "A user account was deleted"
        4727 = "A security-enabled global group was created"
        4728 = "A member was added to a security-enabled global group"
        4729 = "A member was removed from a security-enabled global group"
        4730 = "A security-enabled global group was deleted"
        4731 = "A security-enabled local group was created"
        4732 = "A member was added to a security-enabled local group"
        4733 = "A member was removed from a security-enabled local group"
        4734 = "A security-enabled local group was deleted"
        4735 = "A security-enabled local group was changed"
        4737 = "A security-enabled global group was changed"
        4738 = "A user account was changed"
        4739 = "Domain Policy was changed"
        4740 = "A user account was locked out"
        4741 = "A computer account was created"
        4742 = "A computer account was changed"
        4743 = "A computer account was deleted"
        4744 = "An attempt was made to reset an account's password"
        4745 = "A security-enabled local group was changed"
        4746 = "A member was added to a security-enabled local group"
        4747 = "A member was removed from a security-enabled local group"
        4748 = "A security-enabled local group was deleted"
        4749 = "A security-enabled local group was created"
        4750 = "A security-enabled global group was changed"
        4751 = "A security-enabled global group was created"
        4752 = "A member was added to a security-enabled global group"
        4753 = "A member was removed from a security-enabled global group"
        4754 = "A security-enabled global group was deleted"
        4755 = "A security-enabled universal group was created"
        4756 = "A security-enabled universal group was changed"
        4757 = "A member was added to a security-enabled universal group"
        4758 = "A member was removed from a security-enabled universal group"
        4759 = "A security-enabled universal group was deleted"
        4760 = "A security-enabled universal group was created"
        4761 = "A security-enabled universal group was changed"
        4762 = "A member was added to a security-enabled universal group"
        4763 = "A member was removed from a security-enabled universal group"
        4764 = "A security-enabled universal group was deleted"
        4767 = "A user account was unlocked"
        4768 = "A Kerberos authentication ticket (TGT) was requested"
        4769 = "A Kerberos service ticket was requested"
        4770 = "A Kerberos service ticket was renewed"
        4771 = "Kerberos pre-authentication failed"
        4772 = "A Kerberos authentication ticket request failed"
        4773 = "A Kerberos service ticket request failed"
        4774 = "An account was mapped for logon"
        4775 = "An account could not be mapped for logon"
        4776 = "The domain controller attempted to validate the credentials for an account"
        4777 = "The domain controller failed to validate the credentials for an account"
        4778 = "A session was reconnected to a Window Station"
        4779 = "A session was disconnected from a Window Station"
        4780 = "The ACL was set on accounts which are members of administrators groups"
        4781 = "The name of an account was changed"
        4782 = "The password hash an account was accessed"
        4783 = "The Basic Application Password was changed"
        4784 = "The Basic Application Password was checked"
        4785 = "The Basic Application Password was checked"
        4786 = "The Basic Application Password was changed"
        4787 = "A group's type was changed"
        4788 = "A user was added to a security-enabled local group"
        4789 = "A user was removed from a security-enabled local group"
        4790 = "A security-enabled local group was deleted"
        4791 = "A security-enabled local group was created"
        4792 = "A security-enabled local group was changed"
        4793 = "A security-enabled local group was changed"
        4794 = "An attempt was made to set the Directory Services Restore Mode"
        4795 = "The Directory Services Restore Mode was set"
        4796 = "The Directory Services Restore Mode was cleared"
        4797 = "An attempt was made to query the existence of a blank password for an account"
        4798 = "A user's local group membership was enumerated"
        4799 = "A security-enabled universal group was changed"
        4800 = "The workstation was locked"
        4801 = "The workstation was unlocked"
        4802 = "The screen saver was invoked"
        4803 = "The screen saver was dismissed"
        4804 = "An attempt was made to set the Directory Services Restore Mode"
        4805 = "The Directory Services Restore Mode was set"
        4806 = "The Directory Services Restore Mode was cleared"
        4807 = "An attempt was made to set the Directory Services Restore Mode"
        4808 = "The Directory Services Restore Mode was set"
        4809 = "The Directory Services Restore Mode was cleared"
        4810 = "An attempt was made to set the Directory Services Restore Mode"
        4811 = "The Directory Services Restore Mode was set"
        4812 = "The Directory Services Restore Mode was cleared"
        4813 = "An attempt was made to set the Directory Services Restore Mode"
        4814 = "The Directory Services Restore Mode was set"
        4815 = "The Directory Services Restore Mode was cleared"
        4816 = "An attempt was made to set the Directory Services Restore Mode"
        4817 = "The Directory Services Restore Mode was set"
        4818 = "The Directory Services Restore Mode was cleared"
        4819 = "An attempt was made to set the Directory Services Restore Mode"
        4820 = "The Directory Services Restore Mode was set"
        4821 = "The Directory Services Restore Mode was cleared"
        4822 = "An attempt was made to set the Directory Services Restore Mode"
        4823 = "The Directory Services Restore Mode was set"
        4824 = "The Directory Services Restore Mode was cleared"
        4825 = "An attempt was made to set the Directory Services Restore Mode"
        4826 = "The Directory Services Restore Mode was set"
        4827 = "The Directory Services Restore Mode was cleared"
        4828 = "An attempt was made to set the Directory Services Restore Mode"
        4829 = "The Directory Services Restore Mode was set"
        4830 = "The Directory Services Restore Mode was cleared"
    }
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    foreach ($server in $TargetServers) {
        try {
            foreach ($eventID in $mediumCriticalityEventIDs.Keys) {
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
                            
                            $mediumCriticalityEvents += [PSCustomObject]@{
                                ServerName = $server
                                EventID = $eventID
                                EventSummary = $mediumCriticalityEventIDs[$eventID]
                                Criticality = 'Medium'
                                TimeCreated = $eventRecord.TimeCreated
                                Level = $eventRecord.LevelDisplayName
                                Source = $eventRecord.ProviderName
                                LogName = $eventRecord.LogName
                                EventData = ($eventData | ConvertTo-Json -Compress)
                                Message = $eventRecord.Message
                                InvestigationRequired = 'If unexpected or excessive'
                                Recommendation = 'Investigate if this event is unexpected or occurs in excessive numbers'
                            }
                        }
                    }
                }
                catch {
                    Write-EventMonitoringLog "Failed to query event $eventID on $server`: $_" -Level Warning
                }
            }
        }
        catch {
            Write-EventMonitoringLog "Failed to connect to $server`: $_" -Level Warning
        }
    }
    
    Write-EventMonitoringLog "Found $($mediumCriticalityEvents.Count) medium criticality events" -Level Success
    return $mediumCriticalityEvents
}

function Get-LowCriticalityEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-EventMonitoringLog "Monitoring low criticality events..." -Level Info
    
    $lowCriticalityEvents = @()
    
    # Define low criticality event IDs based on Microsoft Appendix L
    $lowCriticalityEventIDs = @{
        24577 = "Encryption of volume started"
        24578 = "Encryption of volume stopped"
        24579 = "Encryption of volume completed"
        24580 = "Decryption of volume started"
        24581 = "Decryption of volume stopped"
        24582 = "Decryption of volume completed"
        24583 = "Conversion worker thread for volume started"
        24584 = "Conversion worker thread for volume temporarily stopped"
        24588 = "The conversion operation on volume encountered a bad sector error"
        24595 = "Volume contains bad clusters"
        24621 = "Initial state check: Rolling volume conversion transaction"
        5049 = "An IPsec Security Association was deleted"
        5478 = "IPsec Services has started successfully"
    }
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    foreach ($server in $TargetServers) {
        try {
            foreach ($eventID in $lowCriticalityEventIDs.Keys) {
                try {
                    $filter = @{
                        LogName = 'System', 'Application'
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
                            
                            $lowCriticalityEvents += [PSCustomObject]@{
                                ServerName = $server
                                EventID = $eventID
                                EventSummary = $lowCriticalityEventIDs[$eventID]
                                Criticality = 'Low'
                                TimeCreated = $eventRecord.TimeCreated
                                Level = $eventRecord.LevelDisplayName
                                Source = $eventRecord.ProviderName
                                LogName = $eventRecord.LogName
                                EventData = ($eventData | ConvertTo-Json -Compress)
                                Message = $eventRecord.Message
                                InvestigationRequired = 'Baseline monitoring'
                                Recommendation = 'Monitor for baseline patterns and trends'
                            }
                        }
                    }
                }
                catch {
                    Write-EventMonitoringLog "Failed to query event $eventID on $server`: $_" -Level Warning
                }
            }
        }
        catch {
            Write-EventMonitoringLog "Failed to connect to $server`: $_" -Level Warning
        }
    }
    
    Write-EventMonitoringLog "Found $($lowCriticalityEvents.Count) low criticality events" -Level Success
    return $lowCriticalityEvents
}

function Get-AuditPolicyEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-EventMonitoringLog "Monitoring audit policy change events..." -Level Info
    
    $auditPolicyEvents = @()
    
    # Define audit policy related event IDs
    $auditPolicyEventIDs = @{
        4719 = "System audit policy was changed"
        4713 = "Kerberos policy was changed"
        4714 = "Encrypted data recovery policy was changed"
        4715 = "The audit policy (SACL) on an object was changed"
        4716 = "Trusted domain information was modified"
        4717 = "System security access was granted to an account"
        4718 = "System security access was removed from an account"
        4739 = "Domain Policy was changed"
    }
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    foreach ($server in $TargetServers) {
        try {
            foreach ($eventID in $auditPolicyEventIDs.Keys) {
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
                            
                            $auditPolicyEvents += [PSCustomObject]@{
                                ServerName = $server
                                EventID = $eventID
                                EventSummary = $auditPolicyEventIDs[$eventID]
                                Criticality = 'High'
                                TimeCreated = $eventRecord.TimeCreated
                                Level = $eventRecord.LevelDisplayName
                                Source = $eventRecord.ProviderName
                                LogName = $eventRecord.LogName
                                EventData = ($eventData | ConvertTo-Json -Compress)
                                Message = $eventRecord.Message
                                InvestigationRequired = 'Immediate'
                                Recommendation = 'Investigate audit policy changes immediately'
                                PolicyChangeType = 'Audit Policy'
                            }
                        }
                    }
                }
                catch {
                    Write-EventMonitoringLog "Failed to query event $eventID on $server`: $_" -Level Warning
                }
            }
        }
        catch {
            Write-EventMonitoringLog "Failed to connect to $server`: $_" -Level Warning
        }
    }
    
    Write-EventMonitoringLog "Found $($auditPolicyEvents.Count) audit policy change events" -Level Success
    return $auditPolicyEvents
}

function Get-CompromiseIndicatorEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TargetServers,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-EventMonitoringLog "Monitoring compromise indicator events..." -Level Info
    
    $compromiseIndicatorEvents = @()
    
    # Define compromise indicator event IDs
    $compromiseIndicatorEventIDs = @{
        4765 = "SID History was added to an account"
        4766 = "An attempt to add SID History to an account failed"
        4794 = "An attempt was made to set the Directory Services Restore Mode"
        4897 = "Role separation enabled"
        4964 = "Special groups have been assigned to a new logon"
        4649 = "A replay attack was detected"
        4618 = "A monitored security event pattern has occurred"
        1102 = "The audit log was cleared"
        4621 = "Administrator recovered system from CrashOnAuditFail"
    }
    
    $startDate = (Get-Date).AddDays(-$Days)
    
    foreach ($server in $TargetServers) {
        try {
            foreach ($eventID in $compromiseIndicatorEventIDs.Keys) {
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
                            
                            $compromiseIndicatorEvents += [PSCustomObject]@{
                                ServerName = $server
                                EventID = $eventID
                                EventSummary = $compromiseIndicatorEventIDs[$eventID]
                                Criticality = 'High'
                                TimeCreated = $eventRecord.TimeCreated
                                Level = $eventRecord.LevelDisplayName
                                Source = $eventRecord.ProviderName
                                LogName = $eventRecord.LogName
                                EventData = ($eventData | ConvertTo-Json -Compress)
                                Message = $eventRecord.Message
                                InvestigationRequired = 'Immediate'
                                Recommendation = 'Investigate immediately - potential compromise indicator'
                                CompromiseIndicator = 'Yes'
                            }
                        }
                    }
                }
                catch {
                    Write-EventMonitoringLog "Failed to query event $eventID on $server`: $_" -Level Warning
                }
            }
        }
        catch {
            Write-EventMonitoringLog "Failed to connect to $server`: $_" -Level Warning
        }
    }
    
    Write-EventMonitoringLog "Found $($compromiseIndicatorEvents.Count) compromise indicator events" -Level Success
    return $compromiseIndicatorEvents
}

function Get-EventMonitoringSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AllResults
    )
    
    Write-EventMonitoringLog "Generating event monitoring summary..." -Level Info
    
    $summary = @{
        TotalEvents = 0
        HighCriticalityEvents = 0
        MediumCriticalityEvents = 0
        LowCriticalityEvents = 0
        AuditPolicyEvents = 0
        CompromiseIndicatorEvents = 0
        UniqueEventIDs = 0
        ServersMonitored = 0
        InvestigationRequired = 0
    }
    
    $uniqueEventIDs = @()
    $serversMonitored = @()
    
    foreach ($result in $AllResults) {
        $summary.TotalEvents++
        
        # Count by criticality
        switch ($result.Criticality) {
            'High' { $summary.HighCriticalityEvents++ }
            'Medium' { $summary.MediumCriticalityEvents++ }
            'Low' { $summary.LowCriticalityEvents++ }
        }
        
        # Count by type
        if ($result.PolicyChangeType) {
            $summary.AuditPolicyEvents++
        }
        
        if ($result.CompromiseIndicator) {
            $summary.CompromiseIndicatorEvents++
        }
        
        # Track unique event IDs
        if ($result.EventID -notin $uniqueEventIDs) {
            $uniqueEventIDs += $result.EventID
        }
        
        # Track servers monitored
        if ($result.ServerName -notin $serversMonitored) {
            $serversMonitored += $result.ServerName
        }
        
        # Count investigation required
        if ($result.InvestigationRequired -eq 'Immediate') {
            $summary.InvestigationRequired++
        }
    }
    
    $summary.UniqueEventIDs = $uniqueEventIDs.Count
    $summary.ServersMonitored = $serversMonitored.Count
    
    return $summary
}

#endregion

#region Main Execution

try {
    Write-EventMonitoringLog "Starting Event Monitoring Analysis..." -Level Info
    Write-EventMonitoringLog "Database path: $DatabasePath" -Level Info
    Write-EventMonitoringLog "Output path: $OutputPath" -Level Info
    Write-EventMonitoringLog "Analysis period: $Days days" -Level Info
    
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
    
    Write-EventMonitoringLog "Monitoring $($targetServers.Count) servers: $($targetServers -join ', ')" -Level Info
    
    # Optional analyses based on parameters
    if ($IncludeHighCriticalityEvents) {
        Write-EventMonitoringLog "Monitoring high criticality events..." -Level Info
        $highCriticalityEvents = Get-HighCriticalityEvents -TargetServers $targetServers -Days $Days
        $allResults += $highCriticalityEvents
    }
    
    if ($IncludeMediumCriticalityEvents) {
        Write-EventMonitoringLog "Monitoring medium criticality events..." -Level Info
        $mediumCriticalityEvents = Get-MediumCriticalityEvents -TargetServers $targetServers -Days $Days
        $allResults += $mediumCriticalityEvents
    }
    
    if ($IncludeLowCriticalityEvents) {
        Write-EventMonitoringLog "Monitoring low criticality events..." -Level Info
        $lowCriticalityEvents = Get-LowCriticalityEvents -TargetServers $targetServers -Days $Days
        $allResults += $lowCriticalityEvents
    }
    
    if ($IncludeAuditPolicyEvents) {
        Write-EventMonitoringLog "Monitoring audit policy events..." -Level Info
        $auditPolicyEvents = Get-AuditPolicyEvents -TargetServers $targetServers -Days $Days
        $allResults += $auditPolicyEvents
    }
    
    if ($IncludeCompromiseIndicators) {
        Write-EventMonitoringLog "Monitoring compromise indicator events..." -Level Info
        $compromiseIndicatorEvents = Get-CompromiseIndicatorEvents -TargetServers $targetServers -Days $Days
        $allResults += $compromiseIndicatorEvents
    }
    
    # Generate summary
    $summary = Get-EventMonitoringSummary -AllResults $allResults
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-EventMonitoringLog "Event monitoring results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-EventMonitoringLog "Event Monitoring Summary:" -Level Info
    Write-EventMonitoringLog "  Total Events: $($summary.TotalEvents)" -Level Info
    Write-EventMonitoringLog "  High Criticality Events: $($summary.HighCriticalityEvents)" -Level Error
    Write-EventMonitoringLog "  Medium Criticality Events: $($summary.MediumCriticalityEvents)" -Level Warning
    Write-EventMonitoringLog "  Low Criticality Events: $($summary.LowCriticalityEvents)" -Level Info
    Write-EventMonitoringLog "  Audit Policy Events: $($summary.AuditPolicyEvents)" -Level Error
    Write-EventMonitoringLog "  Compromise Indicator Events: $($summary.CompromiseIndicatorEvents)" -Level Error
    Write-EventMonitoringLog "  Unique Event IDs: $($summary.UniqueEventIDs)" -Level Info
    Write-EventMonitoringLog "  Servers Monitored: $($summary.ServersMonitored)" -Level Info
    Write-EventMonitoringLog "  Events Requiring Investigation: $($summary.InvestigationRequired)" -Level Error
    
    Write-EventMonitoringLog "Event monitoring analysis completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allResults
        Message = "Event monitoring analysis completed successfully"
    }
}
catch {
    Write-EventMonitoringLog "Event monitoring analysis failed: $_" -Level Error
    throw
}

#endregion
