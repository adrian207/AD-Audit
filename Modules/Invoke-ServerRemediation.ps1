<#
.SYNOPSIS
    Server and Infrastructure Remediation Scripts

.DESCRIPTION
    Provides automated remediation for common server and infrastructure issues:
    - Server patch management
    - Service configuration cleanup
    - Event log cleanup
    - Storage optimization
    - Application cleanup
    - Security configuration hardening

.PARAMETER RemediationType
    Type of remediation to perform (Patches, Services, EventLogs, Storage, Applications, Security, All)

.PARAMETER DatabasePath
    Path to audit database for issue identification

.PARAMETER Servers
    Array of server names to remediate (if not specified, uses database)

.PARAMETER DryRun
    Show what would be remediated without making changes

.PARAMETER Credential
    Server credentials for remediation operations

.PARAMETER LogPath
    Path to save remediation log

.EXAMPLE
    .\Invoke-ServerRemediation.ps1 -RemediationType "Patches" -DatabasePath "C:\Audits\AuditData.db" -DryRun

.EXAMPLE
    .\Invoke-ServerRemediation.ps1 -RemediationType "All" -Servers @("SERVER01", "SERVER02") -Credential $cred

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Requires: Local admin rights on target servers
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Patches', 'Services', 'EventLogs', 'Storage', 'Applications', 'Security', 'All')]
    [string]$RemediationType,
    
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [string[]]$Servers,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Temp\ServerRemediation.log"
)

$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-RemediationLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Action')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [Server-Remediation] [$Level] $Message"
    
    # Write to console
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Action'  { Write-Host $logMessage -ForegroundColor Cyan }
        default   { Write-Verbose $logMessage }
    }
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
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
        Write-RemediationLog "Failed to connect to database: $_" -Level Error
        throw
    }
}

function Invoke-DatabaseQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.SQLite.SQLiteConnection]$Connection,
        
        [Parameter(Mandatory = $true)]
        [string]$Query
    )
    
    try {
        $command = $Connection.CreateCommand()
        $command.CommandText = $Query
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        $adapter.Fill($dataSet)
        return $dataSet.Tables[0]
    }
    catch {
        Write-RemediationLog "Database query failed: $_" -Level Error
        throw
    }
}

function Invoke-RemoteCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    
    try {
        if ($Credential) {
            return Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -Credential $Credential -ErrorAction Stop
        }
        else {
            return Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop
        }
    }
    catch {
        Write-RemediationLog "Failed to execute command on $ComputerName`: $_" -Level Error
        throw
    }
}

#endregion

#region Patch Management Remediation

function Install-MissingPatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting patch management remediation..." -Level Info
    
    $actions = @()
    
    foreach ($server in $Servers) {
        try {
            Write-RemediationLog "Processing server: $server" -Level Info
            
            $scriptBlock = {
                # Check for missing updates
                $updateSession = New-Object -ComObject Microsoft.Update.Session
                $updateSearcher = $updateSession.CreateUpdateSearcher()
                $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
                
                $missingUpdates = @()
                foreach ($update in $searchResult.Updates) {
                    $missingUpdates += [PSCustomObject]@{
                        Title = $update.Title
                        Description = $update.Description
                        Size = $update.MaxDownloadSize
                        SecurityBulletin = $update.SecurityBulletinIDs
                    }
                }
                
                return $missingUpdates
            }
            
            $missingUpdates = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $scriptBlock -Credential $Credential
            
            if ($missingUpdates.Count -gt 0) {
                $action = [PSCustomObject]@{
                    Server = $server
                    MissingUpdates = $missingUpdates.Count
                    Action = "Install missing patches"
                    Updates = $missingUpdates
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        # Install critical and security updates
                        $installScriptBlock = {
                            $updateSession = New-Object -ComObject Microsoft.Update.Session
                            $updateSearcher = $updateSession.CreateUpdateSearcher()
                            $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
                            
                            $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
                            foreach ($update in $searchResult.Updates) {
                                if ($update.AutoSelectOnWebSites -or $update.SecurityBulletinIDs.Count -gt 0) {
                                    $updatesToDownload.Add($update)
                                }
                            }
                            
                            if ($updatesToDownload.Count -gt 0) {
                                $downloader = $updateSession.CreateUpdateDownloader()
                                $downloader.Updates = $updatesToDownload
                                $downloader.Download()
                                
                                $installer = $updateSession.CreateUpdateInstaller()
                                $installer.Updates = $updatesToDownload
                                $installer.Install()
                                
                                return "Installed $($updatesToDownload.Count) updates"
                            }
                            else {
                                return "No critical updates to install"
                            }
                        }
                        
                        $result = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $installScriptBlock -Credential $Credential
                        Write-RemediationLog "Installed patches on $server`: $result" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to install patches on $server`: $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would install $($missingUpdates.Count) patches on $server" -Level Action
                }
            }
            else {
                Write-RemediationLog "No missing patches found on $server" -Level Success
            }
        }
        catch {
            Write-RemediationLog "Failed to process patches for $server`: $_" -Level Error
        }
    }
    
    Write-RemediationLog "Patch management remediation complete: $($actions.Count) servers processed" -Level Success
    return $actions
}

#endregion

#region Service Configuration Remediation

function Optimize-ServiceConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting service configuration remediation..." -Level Info
    
    $actions = @()
    
    foreach ($server in $Servers) {
        try {
            Write-RemediationLog "Processing services on: $server" -Level Info
            
            $scriptBlock = {
                # Get services that should be disabled for security
                $servicesToDisable = @(
                    'Telnet',
                    'FTP Publishing Service',
                    'Simple TCP/IP Services',
                    'SNMP Service',
                    'SNMP Trap',
                    'World Wide Web Publishing Service', # If not needed
                    'IIS Admin Service' # If not needed
                )
                
                $servicesToOptimize = @()
                
                foreach ($serviceName in $servicesToDisable) {
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    if ($service -and $service.Status -eq 'Running') {
                        $servicesToOptimize += [PSCustomObject]@{
                            Name = $serviceName
                            CurrentStatus = $service.Status
                            RecommendedAction = 'Disable'
                            Reason = 'Security risk - unnecessary service'
                        }
                    }
                }
                
                # Check for services with weak startup accounts
                $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.StartMode -eq 'Auto' }
                foreach ($service in $services) {
                    if ($service.StartName -eq 'LocalSystem' -and $service.Name -notin @('Windows Update', 'Windows Defender', 'Windows Firewall')) {
                        $servicesToOptimize += [PSCustomObject]@{
                            Name = $service.Name
                            CurrentAccount = $service.StartName
                            RecommendedAction = 'Change to service account'
                            Reason = 'Running as LocalSystem - security risk'
                        }
                    }
                }
                
                return $servicesToOptimize
            }
            
            $servicesToOptimize = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $scriptBlock -Credential $Credential
            
            if ($servicesToOptimize.Count -gt 0) {
                $action = [PSCustomObject]@{
                    Server = $server
                    ServicesToOptimize = $servicesToOptimize.Count
                    Action = "Optimize service configuration"
                    Services = $servicesToOptimize
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        $optimizeScriptBlock = {
                            param($ServicesToOptimize)
                            
                            foreach ($service in $ServicesToOptimize) {
                                try {
                                    if ($service.RecommendedAction -eq 'Disable') {
                                        Set-Service -Name $service.Name -StartupType Disabled -ErrorAction Stop
                                        Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                                        Write-Output "Disabled service: $($service.Name)"
                                    }
                                }
                                catch {
                                    Write-Output "Failed to optimize service $($service.Name): $_"
                                }
                            }
                        }
                        
                        $result = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $optimizeScriptBlock -ArgumentList $servicesToOptimize -Credential $Credential
                        Write-RemediationLog "Optimized services on $server`: $($result -join ', ')" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to optimize services on $server`: $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would optimize $($servicesToOptimize.Count) services on $server" -Level Action
                }
            }
            else {
                Write-RemediationLog "No service optimization needed on $server" -Level Success
            }
        }
        catch {
            Write-RemediationLog "Failed to process services for $server`: $_" -Level Error
        }
    }
    
    Write-RemediationLog "Service configuration remediation complete: $($actions.Count) servers processed" -Level Success
    return $actions
}

#endregion

#region Event Log Cleanup

function Clear-EventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting event log cleanup..." -Level Info
    
    $actions = @()
    
    foreach ($server in $Servers) {
        try {
            Write-RemediationLog "Processing event logs on: $server" -Level Info
            
            $scriptBlock = {
                # Get event logs that are too large
                $logsToClean = @()
                $eventLogs = Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 10000 }
                
                foreach ($log in $eventLogs) {
                    $logsToClean += [PSCustomObject]@{
                        LogName = $log.LogName
                        RecordCount = $log.RecordCount
                        MaxSize = $log.MaximumSizeInBytes
                        CurrentSize = $log.FileSize
                        Action = 'Archive and clear'
                    }
                }
                
                return $logsToClean
            }
            
            $logsToClean = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $scriptBlock -Credential $Credential
            
            if ($logsToClean.Count -gt 0) {
                $action = [PSCustomObject]@{
                    Server = $server
                    LogsToClean = $logsToClean.Count
                    Action = "Clean event logs"
                    Logs = $logsToClean
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        $cleanScriptBlock = {
                            param($LogsToClean)
                            
                            foreach ($log in $LogsToClean) {
                                try {
                                    # Archive the log before clearing
                                    $logPath = "C:\Windows\System32\winevt\Logs\$($log.LogName).evtx"
                                    $archivePath = "C:\LogArchive\$($log.LogName)_$(Get-Date -Format 'yyyyMMdd').evtx"
                                    
                                    # Create archive directory
                                    $archiveDir = Split-Path $archivePath
                                    if (-not (Test-Path $archiveDir)) {
                                        New-Item -ItemType Directory -Path $archiveDir -Force
                                    }
                                    
                                    # Copy log to archive
                                    Copy-Item -Path $logPath -Destination $archivePath -ErrorAction SilentlyContinue
                                    
                                    # Clear the log
                                    Clear-EventLog -LogName $log.LogName -ErrorAction Stop
                                    
                                    Write-Output "Cleaned log: $($log.LogName)"
                                }
                                catch {
                                    Write-Output "Failed to clean log $($log.LogName): $_"
                                }
                            }
                        }
                        
                        $result = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $cleanScriptBlock -ArgumentList $logsToClean -Credential $Credential
                        Write-RemediationLog "Cleaned event logs on $server`: $($result -join ', ')" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to clean event logs on $server`: $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would clean $($logsToClean.Count) event logs on $server" -Level Action
                }
            }
            else {
                Write-RemediationLog "No event log cleanup needed on $server" -Level Success
            }
        }
        catch {
            Write-RemediationLog "Failed to process event logs for $server`: $_" -Level Error
        }
    }
    
    Write-RemediationLog "Event log cleanup complete: $($actions.Count) servers processed" -Level Success
    return $actions
}

#endregion

#region Storage Optimization

function Optimize-Storage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting storage optimization..." -Level Info
    
    $actions = @()
    
    foreach ($server in $Servers) {
        try {
            Write-RemediationLog "Processing storage on: $server" -Level Info
            
            $scriptBlock = {
                # Get drives with low free space
                $drivesToOptimize = @()
                $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
                
                foreach ($drive in $drives) {
                    $freeSpacePercent = ($drive.FreeSpace / $drive.Size) * 100
                    
                    if ($freeSpacePercent -lt 20) {
                        $drivesToOptimize += [PSCustomObject]@{
                            Drive = $drive.DeviceID
                            FreeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
                            TotalSizeGB = [math]::Round($drive.Size / 1GB, 2)
                            FreeSpacePercent = [math]::Round($freeSpacePercent, 1)
                            Action = 'Clean up disk space'
                        }
                    }
                }
                
                return $drivesToOptimize
            }
            
            $drivesToOptimize = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $scriptBlock -Credential $Credential
            
            if ($drivesToOptimize.Count -gt 0) {
                $action = [PSCustomObject]@{
                    Server = $server
                    DrivesToOptimize = $drivesToOptimize.Count
                    Action = "Optimize storage"
                    Drives = $drivesToOptimize
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        $optimizeScriptBlock = {
                            param($DrivesToOptimize)
                            
                            foreach ($drive in $DrivesToOptimize) {
                                try {
                                    $driveLetter = $drive.Drive -replace ':', ''
                                    
                                    # Clean temporary files
                                    $tempPaths = @(
                                        "$driveLetter`:\Windows\Temp\*",
                                        "$driveLetter`:\Users\*\AppData\Local\Temp\*",
                                        "$driveLetter`:\Windows\SoftwareDistribution\Download\*"
                                    )
                                    
                                    foreach ($path in $tempPaths) {
                                        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                                            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
                                            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                                    }
                                    
                                    # Run disk cleanup
                                    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -ErrorAction SilentlyContinue
                                    
                                    Write-Output "Optimized drive: $($drive.Drive)"
                                }
                                catch {
                                    Write-Output "Failed to optimize drive $($drive.Drive): $_"
                                }
                            }
                        }
                        
                        $result = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $optimizeScriptBlock -ArgumentList $drivesToOptimize -Credential $Credential
                        Write-RemediationLog "Optimized storage on $server`: $($result -join ', ')" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to optimize storage on $server`: $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would optimize $($drivesToOptimize.Count) drives on $server" -Level Action
                }
            }
            else {
                Write-RemediationLog "No storage optimization needed on $server" -Level Success
            }
        }
        catch {
            Write-RemediationLog "Failed to process storage for $server`: $_" -Level Error
        }
    }
    
    Write-RemediationLog "Storage optimization complete: $($actions.Count) servers processed" -Level Success
    return $actions
}

#endregion

#region Application Cleanup

function Remove-UnnecessaryApplications {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting application cleanup..." -Level Info
    
    $actions = @()
    
    foreach ($server in $Servers) {
        try {
            Write-RemediationLog "Processing applications on: $server" -Level Info
            
            $scriptBlock = {
                # Get applications that should be removed
                $appsToRemove = @()
                
                # Common unnecessary applications
                $unnecessaryApps = @(
                    '*Java*',
                    '*Adobe Reader*',
                    '*Flash Player*',
                    '*Silverlight*',
                    '*QuickTime*',
                    '*RealPlayer*',
                    '*WinRAR*',
                    '*7-Zip*' # Keep one compression tool
                )
                
                $installedApps = Get-WmiObject -Class Win32_Product | Where-Object { $null -ne $_.Name }
                
                foreach ($app in $installedApps) {
                    foreach ($pattern in $unnecessaryApps) {
                        if ($app.Name -like $pattern) {
                            $appsToRemove += [PSCustomObject]@{
                                Name = $app.Name
                                Version = $app.Version
                                Vendor = $app.Vendor
                                Action = 'Uninstall'
                                Reason = 'Unnecessary application'
                            }
                            break
                        }
                    }
                }
                
                return $appsToRemove
            }
            
            $appsToRemove = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $scriptBlock -Credential $Credential
            
            if ($appsToRemove.Count -gt 0) {
                $action = [PSCustomObject]@{
                    Server = $server
                    AppsToRemove = $appsToRemove.Count
                    Action = "Remove unnecessary applications"
                    Applications = $appsToRemove
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        $removeScriptBlock = {
                            param($AppsToRemove)
                            
                            foreach ($app in $AppsToRemove) {
                                try {
                                    $product = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq $app.Name }
                                    if ($product) {
                                        $product.Uninstall()
                                        Write-Output "Uninstalled: $($app.Name)"
                                    }
                                }
                                catch {
                                    Write-Output "Failed to uninstall $($app.Name): $_"
                                }
                            }
                        }
                        
                        $result = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $removeScriptBlock -ArgumentList $appsToRemove -Credential $Credential
                        Write-RemediationLog "Removed applications on $server`: $($result -join ', ')" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to remove applications on $server`: $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would remove $($appsToRemove.Count) applications on $server" -Level Action
                }
            }
            else {
                Write-RemediationLog "No unnecessary applications found on $server" -Level Success
            }
        }
        catch {
            Write-RemediationLog "Failed to process applications for $server`: $_" -Level Error
        }
    }
    
    Write-RemediationLog "Application cleanup complete: $($actions.Count) servers processed" -Level Success
    return $actions
}

#endregion

#region Security Hardening

function Set-SecurityHardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-RemediationLog "Starting security hardening..." -Level Info
    
    $actions = @()
    
    foreach ($server in $Servers) {
        try {
            Write-RemediationLog "Applying security hardening to: $server" -Level Info
            
            $scriptBlock = {
                # Security hardening configurations
                $hardeningActions = @()
                
                # Check Windows Firewall
                $firewallProfiles = Get-NetFirewallProfile
                foreach ($firewallProfile in $firewallProfiles) {
                    if ($firewallProfile.Enabled -eq $false) {
                        $hardeningActions += [PSCustomObject]@{
                            Setting = "Windows Firewall - $($firewallProfile.Name)"
                            CurrentValue = "Disabled"
                            RecommendedValue = "Enabled"
                            Action = "Enable firewall profile"
                        }
                    }
                }
                
                # Check UAC
                $uacEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA").EnableLUA
                if ($uacEnabled -eq 0) {
                    $hardeningActions += [PSCustomObject]@{
                        Setting = "User Account Control"
                        CurrentValue = "Disabled"
                        RecommendedValue = "Enabled"
                        Action = "Enable UAC"
                    }
                }
                
                # Check Windows Update
                $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
                if ($wuService -and $wuService.StartType -ne 'Automatic') {
                    $hardeningActions += [PSCustomObject]@{
                        Setting = "Windows Update Service"
                        CurrentValue = $wuService.StartType
                        RecommendedValue = "Automatic"
                        Action = "Set to automatic startup"
                    }
                }
                
                return $hardeningActions
            }
            
            $hardeningActions = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $scriptBlock -Credential $Credential
            
            if ($hardeningActions.Count -gt 0) {
                $action = [PSCustomObject]@{
                    Server = $server
                    HardeningActions = $hardeningActions.Count
                    Action = "Apply security hardening"
                    Settings = $hardeningActions
                }
                $actions += $action
                
                if (-not $DryRun) {
                    try {
                        $hardenScriptBlock = {
                            param($HardeningActions)
                            
                            foreach ($setting in $HardeningActions) {
                                try {
                                    switch ($setting.Action) {
                                        "Enable firewall profile" {
                                            $firewallProfileName = $setting.Setting -replace "Windows Firewall - ", ""
                                            Set-NetFirewallProfile -Profile $firewallProfileName -Enabled True
                                            Write-Output "Enabled firewall profile: $firewallProfileName"
                                        }
                                        "Enable UAC" {
                                            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
                                            Write-Output "Enabled User Account Control"
                                        }
                                        "Set to automatic startup" {
                                            Set-Service -Name "wuauserv" -StartupType Automatic
                                            Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
                                            Write-Output "Set Windows Update service to automatic"
                                        }
                                    }
                                }
                                catch {
                                    Write-Output "Failed to apply hardening: $($setting.Action) - $_"
                                }
                            }
                        }
                        
                        $result = Invoke-RemoteCommand -ComputerName $server -ScriptBlock $hardenScriptBlock -ArgumentList $hardeningActions -Credential $Credential
                        Write-RemediationLog "Applied security hardening on $server`: $($result -join ', ')" -Level Action
                    }
                    catch {
                        Write-RemediationLog "Failed to apply security hardening on $server`: $_" -Level Error
                    }
                }
                else {
                    Write-RemediationLog "DRY RUN: Would apply $($hardeningActions.Count) security hardening settings on $server" -Level Action
                }
            }
            else {
                Write-RemediationLog "No security hardening needed on $server" -Level Success
            }
        }
        catch {
            Write-RemediationLog "Failed to apply security hardening to $server`: $_" -Level Error
        }
    }
    
    Write-RemediationLog "Security hardening complete: $($actions.Count) servers processed" -Level Success
    return $actions
}

#endregion

#region Main Execution

try {
    Write-RemediationLog "Starting server remediation process..." -Level Info
    Write-RemediationLog "Remediation Type: $RemediationType" -Level Info
    Write-RemediationLog "Dry Run: $DryRun" -Level Info
    Write-RemediationLog "Log Path: $LogPath" -Level Info
    
    # Get server list
    if (-not $Servers -and $DatabasePath) {
        try {
            $connection = Get-DatabaseConnection -DatabasePath $DatabasePath
            $serverData = Invoke-DatabaseQuery -Connection $connection -Query "SELECT DISTINCT ServerName FROM Server_Hardware_Details WHERE Status = 'Success'"
            $Servers = $serverData.Rows | ForEach-Object { $_.ServerName }
            $connection.Close()
            Write-RemediationLog "Retrieved $($Servers.Count) servers from database" -Level Success
        }
        catch {
            Write-RemediationLog "Failed to get servers from database: $_" -Level Error
            throw
        }
    }
    elseif (-not $Servers) {
        throw "Either Servers parameter or DatabasePath must be specified"
    }
    
    Write-RemediationLog "Processing $($Servers.Count) servers: $($Servers -join ', ')" -Level Info
    
    $allActions = @()
    
    # Execute remediation based on type
    switch ($RemediationType) {
        'Patches' {
            $actions = Install-MissingPatches -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
        }
        'Services' {
            $actions = Optimize-ServiceConfiguration -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
        }
        'EventLogs' {
            $actions = Clean-EventLogs -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
        }
        'Storage' {
            $actions = Optimize-Storage -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
        }
        'Applications' {
            $actions = Remove-UnnecessaryApplications -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
        }
        'Security' {
            $actions = Apply-SecurityHardening -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
        }
        'All' {
            Write-RemediationLog "Executing all server remediation types..." -Level Info
            
            $actions = Install-MissingPatches -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Optimize-ServiceConfiguration -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Clean-EventLogs -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Optimize-Storage -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Remove-UnnecessaryApplications -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
            
            $actions = Apply-SecurityHardening -Servers $Servers -Credential $Credential -DryRun:$DryRun
            $allActions += $actions
        }
    }
    
    # Export actions summary
    if ($allActions.Count -gt 0) {
        $summaryPath = Join-Path (Split-Path $LogPath) "ServerRemediationSummary.csv"
        $allActions | Export-Csv -Path $summaryPath -NoTypeInformation
        Write-RemediationLog "Actions summary exported to: $summaryPath" -Level Success
    }
    
    Write-RemediationLog "Server remediation process completed successfully" -Level Success
    Write-RemediationLog "Total actions: $($allActions.Count)" -Level Success
    
    return @{
        Success = $true
        ActionsCount = $allActions.Count
        Actions = $allActions
        Message = "Server remediation completed successfully"
    }
}
catch {
    Write-RemediationLog "Server remediation process failed: $_" -Level Error
    throw
}

#endregion
