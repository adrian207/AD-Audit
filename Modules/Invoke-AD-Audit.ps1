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
    [switch]$SkipSQL
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
            ForestDN = $forest.RootDomain -replace '\.',',DC='
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
        $users = Get-ADUser -Filter * -Properties * |
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
        $computers = Get-ADComputer -Filter * -Properties * |
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
        $groups = Get-ADGroup -Filter * -Properties * |
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
                Write-ModuleLog "Failed to query group $groupName: $_" -Level Warning
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
    $processed = 0
    
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
        $processed = [System.Threading.Interlocked]::Increment(([ref]$using:processed))
        Write-Verbose "[$processed/$($using:Servers.Count)] Processing $serverName..."
        
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
        $resultBag = $using:storageResults
        
        try {
            $sessionOption = New-CimSessionOption -Protocol Dcom
            $cimSession = New-CimSession -ComputerName $serverName -SessionOption $sessionOption -OperationTimeoutSec 120 -ErrorAction Stop
            
            try {
                $disks = Get-CimInstance -CimSession $cimSession -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
                
                foreach ($disk in $disks) {
                    $storageResults.Add([PSCustomObject]@{
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
            Write-Verbose "Failed to collect storage from $serverName: $_"
        }
    }
    
    $results = @($storageResults)
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path (Join-Path $using:script:ServerOutputPath "Server_Storage_Details.csv") -NoTypeInformation
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
            Write-Verbose "Failed to collect applications from $serverName: $_"
        }
    }
    
    $results = @($appResults)
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path (Join-Path $using:script:ServerOutputPath "Server_Installed_Applications.csv") -NoTypeInformation
        Write-Verbose "Collected $($results.Count) application installations"
        
        # Create application summary (aggregated)
        $summary = $results | Group-Object ApplicationName | Select-Object @{N='ApplicationName';E={$_.Name}},
            @{N='ServerCount';E={$_.Count}},
            @{N='MostCommonVersion';E={($_.Group | Group-Object Version | Sort-Object Count -Descending | Select-Object -First 1).Name}},
            @{N='Servers';E={($_.Group.ServerName | Sort-Object -Unique) -join '; '}}
        
        $summary | Sort-Object ServerCount -Descending | 
            Export-Csv -Path (Join-Path $using:script:ServerOutputPath "Server_Application_Summary.csv") -NoTypeInformation
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
                             @{N='Message';E={($_.Group[0].Message -replace '[\r\n]+', ' ').Substring(0, [Math]::Min(500, ($_.Group[0].Message -replace '[\r\n]+', ' ').Length))}}
            
            foreach ($event in $criticals) {
                $criticalBag.Add($event)
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
                             @{N='Message';E={($_.Group[0].Message -replace '[\r\n]+', ' ').Substring(0, [Math]::Min(500, ($_.Group[0].Message -replace '[\r\n]+', ' ').Length))}}
            
            foreach ($event in $errors) {
                $errorBag.Add($event)
            }
            
            Write-Verbose "Collected event logs from $serverName"
        }
        catch {
            Write-Verbose "Failed to collect event logs from $serverName: $_"
        }
    }
    
    # Export results
    $criticalResults = @($criticalEvents) | Sort-Object Count -Descending
    if ($criticalResults.Count -gt 0) {
        $criticalResults | Export-Csv -Path (Join-Path $using:script:ServerOutputPath "Server_Event_Log_Critical.csv") -NoTypeInformation
        Write-Verbose "Collected $($criticalResults.Count) unique critical event types"
    }
    
    $errorResults = @($errorEvents) | Sort-Object Count -Descending
    if ($errorResults.Count -gt 0) {
        $errorResults | Export-Csv -Path (Join-Path $using:script:ServerOutputPath "Server_Event_Log_Errors.csv") -NoTypeInformation
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
            Write-Verbose "Failed to collect logon history from $serverName: $_"
        }
    }
    
    # Export results
    $logonResults = @($logonResults) | Sort-Object LogonCount -Descending
    if ($logonResults.Count -gt 0) {
        $logonResults | Export-Csv -Path (Join-Path $using:script:ServerOutputPath "Server_Logon_History.csv") -NoTypeInformation
        Write-Verbose "Collected logon history for $($logonResults.Count) users"
    }
    
    $failureResults = @($failureResults) | Sort-Object FailureCount -Descending
    if ($failureResults.Count -gt 0) {
        $failureResults | Export-Csv -Path (Join-Path $using:script:ServerOutputPath "Server_Logon_Failures.csv") -NoTypeInformation
        Write-Verbose "Collected $($failureResults.Count) users with failed logon attempts"
    }
    
    return @{
        Logons = $logonResults
        Failures = $failureResults
    }
}

#endregion

#region Main Execution

try {
    Write-ModuleLog "Starting Active Directory audit..." -Level Info
    Write-ModuleLog "Output folder: $OutputFolder" -Level Info
    
    # Collect forest and domain information
    $forestInfo = Get-ADForestInfo
    
    # Collect user inventory
    $users = Get-ADUserInventory
    
    # Collect computer inventory (returns member servers)
    $memberServers = Get-ADComputerInventory
    
    # Collect group inventory
    $groups = Get-ADGroupInventory
    
    # Collect privileged accounts
    $privilegedAccounts = Get-PrivilegedAccounts
    
    # TODO: Implement remaining AD audit components:
    # - GPO inventory
    # - Service accounts
    # - Trusts
    # - ACL analysis
    # - Password policies
    # - Kerberos delegation
    # - DNS zones
    # - DHCP scopes
    
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
            $storage = Get-ServerStorageInventory -Servers $onlineServers -MaxParallel $MaxParallelServers
            
            # Step 3: Installed applications
            $applications = Get-ServerApplications -Servers $onlineServers -MaxParallel $MaxParallelServers
            
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

#endregion

