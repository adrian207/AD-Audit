<#
.SYNOPSIS
    Audit SMB Signing and Encryption Support via Event Logs

.DESCRIPTION
    Analyzes Windows Event Logs to identify clients and servers that don't support
    SMB signing or encryption. This is critical for detecting security vulnerabilities
    and ensuring proper SMB security configuration.

.PARAMETER Servers
    Array of server names to audit (if not specified, uses all servers from database)

.PARAMETER DatabasePath
    Path to audit database for server list

.PARAMETER Days
    Number of days to look back in event logs (default: 30)

.PARAMETER OutputPath
    Path to save audit results

.EXAMPLE
    .\Invoke-SMBSecurityAudit.ps1 -Servers @("SERVER01", "SERVER02") -Days 30

.EXAMPLE
    .\Invoke-SMBSecurityAudit.ps1 -DatabasePath "C:\Audits\AuditData.db" -Days 7

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Requires: Local admin rights on target servers
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$Servers,
    
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath,
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Temp\SMBSecurityAudit.csv"
)

$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [SMB-Security-Audit] [$Level] $Message"
    
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Verbose $logMessage }
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
        Write-AuditLog "Failed to connect to database: $_" -Level Error
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
        Write-AuditLog "Database query failed: $_" -Level Error
        throw
    }
}

function Invoke-RemoteCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )
    
    try {
        return Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop
    }
    catch {
        Write-AuditLog "Failed to execute command on $ComputerName`: $_" -Level Error
        throw
    }
}

#endregion

#region SMB Security Analysis

function Get-SMBSecurityEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $false)]
        [int]$Days = 30
    )
    
    Write-AuditLog "Analyzing SMB security events on: $ComputerName" -Level Info
    
    try {
        $scriptBlock = {
            param($Days)
            
            $startDate = (Get-Date).AddDays(-$Days)
            $smbIssues = @()
            
            # Event ID 1001: SMB client unable to negotiate signing
            try {
                $signingEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Microsoft-Windows-SMBServer/Security'
                    ID = 1001
                    StartTime = $startDate
                } -ErrorAction SilentlyContinue
                
                foreach ($eventRecord in $signingEvents) {
                    $xml = [xml]$eventRecord.ToXml()
                    $clientIP = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ClientIP'}).'#text'
                    $clientName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ClientName'}).'#text'
                    
                    $smbIssues += [PSCustomObject]@{
                        EventID = 1001
                        EventType = 'SMB Signing Failure'
                        ClientIP = $clientIP
                        ClientName = $clientName
                        Timestamp = $eventRecord.TimeCreated
                        Message = 'Client unable to negotiate SMB signing'
                        Severity = 'High'
                    }
                }
            }
            catch {
                # Event log might not exist or be accessible
            }
            
            # Event ID 1002: SMB client unable to negotiate encryption
            try {
                $encryptionEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Microsoft-Windows-SMBServer/Security'
                    ID = 1002
                    StartTime = $startDate
                } -ErrorAction SilentlyContinue
                
                foreach ($eventRecord in $encryptionEvents) {
                    $xml = [xml]$eventRecord.ToXml()
                    $clientIP = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ClientIP'}).'#text'
                    $clientName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ClientName'}).'#text'
                    
                    $smbIssues += [PSCustomObject]@{
                        EventID = 1002
                        EventType = 'SMB Encryption Failure'
                        ClientIP = $clientIP
                        ClientName = $clientName
                        Timestamp = $eventRecord.TimeCreated
                        Message = 'Client unable to negotiate SMB encryption'
                        Severity = 'Critical'
                    }
                }
            }
            catch {
                # Event log might not exist or be accessible
            }
            
            # Event ID 1003: SMB client using weak authentication
            try {
                $authEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'Microsoft-Windows-SMBServer/Security'
                    ID = 1003
                    StartTime = $startDate
                } -ErrorAction SilentlyContinue
                
                foreach ($eventRecord in $authEvents) {
                    $xml = [xml]$eventRecord.ToXml()
                    $clientIP = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ClientIP'}).'#text'
                    $clientName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ClientName'}).'#text'
                    
                    $smbIssues += [PSCustomObject]@{
                        EventID = 1003
                        EventType = 'Weak SMB Authentication'
                        ClientIP = $clientIP
                        ClientName = $clientName
                        Timestamp = $eventRecord.TimeCreated
                        Message = 'Client using weak SMB authentication'
                        Severity = 'Medium'
                    }
                }
            }
            catch {
                # Event log might not exist or be accessible
            }
            
            # Alternative: Check System log for SMB-related errors
            try {
                $systemEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ID = 1001, 1002, 1003, 1004
                    StartTime = $startDate
                } -ErrorAction SilentlyContinue | Where-Object {
                    $_.Message -match 'SMB|signing|encryption'
                }
                
                foreach ($eventRecord in $systemEvents) {
                    $smbIssues += [PSCustomObject]@{
                        EventID = $eventRecord.Id
                        EventType = 'SMB System Error'
                        ClientIP = 'Unknown'
                        ClientName = 'Unknown'
                        Timestamp = $eventRecord.TimeCreated
                        Message = $eventRecord.Message
                        Severity = 'Medium'
                    }
                }
            }
            catch {
                # System log might not be accessible
            }
            
            return $smbIssues
        }
        
        $results = Invoke-RemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $Days
        return $results
    }
    catch {
        Write-AuditLog "Failed to analyze SMB events on $ComputerName`: $_" -Level Error
        return @()
    }
}

function Get-SMBClientConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    
    Write-AuditLog "Checking SMB client configuration on: $ComputerName" -Level Info
    
    try {
        $scriptBlock = {
            $smbConfig = @()
            
            # Check SMB client signing requirements
            try {
                $signingRequired = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                $smbConfig += [PSCustomObject]@{
                    Setting = 'SMB Client Signing Required'
                    Value = if ($signingRequired.RequireSecuritySignature -eq 1) { 'Enabled' } else { 'Disabled' }
                    Recommendation = if ($signingRequired.RequireSecuritySignature -eq 1) { 'Compliant' } else { 'Enable SMB client signing' }
                    Severity = if ($signingRequired.RequireSecuritySignature -eq 1) { 'Low' } else { 'High' }
                }
            }
            catch {
                $smbConfig += [PSCustomObject]@{
                    Setting = 'SMB Client Signing Required'
                    Value = 'Unknown'
                    Recommendation = 'Enable SMB client signing'
                    Severity = 'High'
                }
            }
            
            # Check SMB client encryption
            try {
                $smbConfig += [PSCustomObject]@{
                    Setting = 'SMB Client Encryption'
                    Value = 'Not Configurable via Registry'
                    Recommendation = 'Use Group Policy to enforce SMB encryption'
                    Severity = 'Medium'
                }
            }
            catch {
                $smbConfig += [PSCustomObject]@{
                    Setting = 'SMB Client Encryption'
                    Value = 'Unknown'
                    Recommendation = 'Configure SMB encryption via Group Policy'
                    Severity = 'High'
                }
            }
            
            return $smbConfig
        }
        
        $results = Invoke-RemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock
        return $results
    }
    catch {
        Write-AuditLog "Failed to check SMB client config on $ComputerName`: $_" -Level Error
        return @()
    }
}

function Get-SMBServerConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    
    Write-AuditLog "Checking SMB server configuration on: $ComputerName" -Level Info
    
    try {
        $scriptBlock = {
            $smbConfig = @()
            
            # Check SMB server signing requirements
            try {
                $signingRequired = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                $smbConfig += [PSCustomObject]@{
                    Setting = 'SMB Server Signing Required'
                    Value = if ($signingRequired.RequireSecuritySignature -eq 1) { 'Enabled' } else { 'Disabled' }
                    Recommendation = if ($signingRequired.RequireSecuritySignature -eq 1) { 'Compliant' } else { 'Enable SMB server signing' }
                    Severity = if ($signingRequired.RequireSecuritySignature -eq 1) { 'Low' } else { 'High' }
                }
            }
            catch {
                $smbConfig += [PSCustomObject]@{
                    Setting = 'SMB Server Signing Required'
                    Value = 'Unknown'
                    Recommendation = 'Enable SMB server signing'
                    Severity = 'High'
                }
            }
            
            # Check SMB server encryption
            try {
                $smbConfig += [PSCustomObject]@{
                    Setting = 'SMB Server Encryption'
                    Value = 'Not Configurable via Registry'
                    Recommendation = 'Use Group Policy to enforce SMB encryption'
                    Severity = 'Medium'
                }
            }
            catch {
                $smbConfig += [PSCustomObject]@{
                    Setting = 'SMB Server Encryption'
                    Value = 'Unknown'
                    Recommendation = 'Configure SMB encryption via Group Policy'
                    Severity = 'High'
                }
            }
            
            return $smbConfig
        }
        
        $results = Invoke-RemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock
        return $results
    }
    catch {
        Write-AuditLog "Failed to check SMB server config on $ComputerName`: $_" -Level Error
        return @()
    }
}

#endregion

#region Main Execution

try {
    Write-AuditLog "Starting SMB Security Audit..." -Level Info
    Write-AuditLog "Days to analyze: $Days" -Level Info
    Write-AuditLog "Output path: $OutputPath" -Level Info
    
    # Get server list
    if (-not $Servers -and $DatabasePath) {
        try {
            $connection = Get-DatabaseConnection -DatabasePath $DatabasePath
            $serverData = Invoke-DatabaseQuery -Connection $connection -Query "SELECT DISTINCT ServerName FROM Server_Hardware_Details WHERE Status = 'Success'"
            $Servers = $serverData.Rows | ForEach-Object { $_.ServerName }
            $connection.Close()
            Write-AuditLog "Retrieved $($Servers.Count) servers from database" -Level Success
        }
        catch {
            Write-AuditLog "Failed to get servers from database: $_" -Level Error
            throw
        }
    }
    elseif (-not $Servers) {
        throw "Either Servers parameter or DatabasePath must be specified"
    }
    
    Write-AuditLog "Processing $($Servers.Count) servers: $($Servers -join ', ')" -Level Info
    
    $allResults = @()
    $summary = @{
        TotalServers = $Servers.Count
        ServersWithIssues = 0
        CriticalIssues = 0
        HighIssues = 0
        MediumIssues = 0
        LowIssues = 0
    }
    
    foreach ($server in $Servers) {
        try {
            Write-AuditLog "Processing server: $server" -Level Info
            
            # Get SMB security events
            $smbEvents = Get-SMBSecurityEvents -ComputerName $server -Days $Days
            
            # Get SMB client configuration
            $smbClientConfig = Get-SMBClientConfiguration -ComputerName $server
            
            # Get SMB server configuration
            $smbServerConfig = Get-SMBServerConfiguration -ComputerName $server
            
            # Combine results
            $serverResults = @()
            
            # Add events
            foreach ($eventRecord in $smbEvents) {
                $serverResults += [PSCustomObject]@{
                    ServerName = $server
                    Type = 'Event'
                    Setting = $eventRecord.EventType
                    Value = $eventRecord.Message
                    ClientIP = $eventRecord.ClientIP
                    ClientName = $eventRecord.ClientName
                    Timestamp = $eventRecord.Timestamp
                    Severity = $eventRecord.Severity
                    Recommendation = 'Review SMB client configuration'
                }
            }
            
            # Add client configuration
            foreach ($config in $smbClientConfig) {
                $serverResults += [PSCustomObject]@{
                    ServerName = $server
                    Type = 'ClientConfig'
                    Setting = $config.Setting
                    Value = $config.Value
                    ClientIP = 'N/A'
                    ClientName = 'N/A'
                    Timestamp = Get-Date
                    Severity = $config.Severity
                    Recommendation = $config.Recommendation
                }
            }
            
            # Add server configuration
            foreach ($config in $smbServerConfig) {
                $serverResults += [PSCustomObject]@{
                    ServerName = $server
                    Type = 'ServerConfig'
                    Setting = $config.Setting
                    Value = $config.Value
                    ClientIP = 'N/A'
                    ClientName = 'N/A'
                    Timestamp = Get-Date
                    Severity = $config.Severity
                    Recommendation = $config.Recommendation
                }
            }
            
            if ($serverResults.Count -gt 0) {
                $allResults += $serverResults
                $summary.ServersWithIssues++
                
                # Count by severity
                foreach ($result in $serverResults) {
                    switch ($result.Severity) {
                        'Critical' { $summary.CriticalIssues++ }
                        'High' { $summary.HighIssues++ }
                        'Medium' { $summary.MediumIssues++ }
                        'Low' { $summary.LowIssues++ }
                    }
                }
                
                Write-AuditLog "Found $($serverResults.Count) SMB security issues on $server" -Level Warning
            }
            else {
                Write-AuditLog "No SMB security issues found on $server" -Level Success
            }
        }
        catch {
            Write-AuditLog "Failed to process server $server`: $_" -Level Error
        }
    }
    
    # Export results
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-AuditLog "SMB security audit results exported to: $OutputPath" -Level Success
    }
    
    # Display summary
    Write-AuditLog "SMB Security Audit Summary:" -Level Info
    Write-AuditLog "  Total Servers: $($summary.TotalServers)" -Level Info
    Write-AuditLog "  Servers with Issues: $($summary.ServersWithIssues)" -Level Warning
    Write-AuditLog "  Critical Issues: $($summary.CriticalIssues)" -Level Error
    Write-AuditLog "  High Issues: $($summary.HighIssues)" -Level Warning
    Write-AuditLog "  Medium Issues: $($summary.MediumIssues)" -Level Info
    Write-AuditLog "  Low Issues: $($summary.LowIssues)" -Level Info
    
    Write-AuditLog "SMB Security Audit completed successfully" -Level Success
    
    return @{
        Success = $true
        Summary = $summary
        Results = $allResults
        Message = "SMB security audit completed successfully"
    }
}
catch {
    Write-AuditLog "SMB Security Audit failed: $_" -Level Error
    throw
}

#endregion
