<#
.SYNOPSIS
    M&A Audit Database - Web-Based Query Builder (Pode/Kestrel)
    
.DESCRIPTION
    Modern web-based query builder for non-technical users to query SQLite audit database.
    Built with Pode PowerShell web framework and Kestrel server.
    
.PARAMETER Port
    Port number for web server (default: 5000)
    
.PARAMETER Address
    IP address to bind to (default: localhost, use 0.0.0.0 for network access)
    
.PARAMETER DatabasePath
    Path to SQLite database (default: searches for most recent AuditData.db)
    
.EXAMPLE
    .\Start-M&A-QueryBuilder-Web.ps1
    
.EXAMPLE
    .\Start-M&A-QueryBuilder-Web.ps1 -Port 8080 -Address "0.0.0.0"
    
.EXAMPLE
    .\Start-M&A-QueryBuilder-Web.ps1 -DatabasePath "C:\Audits\Contoso\AuditData.db"
    
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Requires: Pode module, System.Data.SQLite
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Port = 5000,
    
    [Parameter(Mandatory = $false)]
    [string]$Address = "localhost",
    
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath = ""
)

# Check for Pode module
if (-not (Get-Module -ListAvailable -Name Pode)) {
    Write-Host "Pode module not found. Installing..." -ForegroundColor Yellow
    Install-Module -Name Pode -Scope CurrentUser -Force
}

Import-Module Pode

# Load SQLite library
$sqliteDll = Join-Path $PSScriptRoot "Libraries\System.Data.SQLite.dll"
if (Test-Path $sqliteDll) {
    Add-Type -Path $sqliteDll
} else {
    try {
        Add-Type -AssemblyName "System.Data.SQLite"
    } catch {
        Write-Error "SQLite library not found. Please install System.Data.SQLite or place DLL in Libraries folder."
        exit 1
    }
}

# Auto-detect database if not specified
if ([string]::IsNullOrWhiteSpace($DatabasePath)) {
    Write-Host "Searching for most recent AuditData.db..." -ForegroundColor Cyan
    $auditFolders = Get-ChildItem -Path $PSScriptRoot -Filter "AuditData.db" -Recurse -ErrorAction SilentlyContinue
    if ($auditFolders.Count -eq 0) {
        # Try parent Output folder
        $outputPath = Join-Path (Split-Path $PSScriptRoot -Parent) "Output"
        if (Test-Path $outputPath) {
            $auditFolders = Get-ChildItem -Path $outputPath -Filter "AuditData.db" -Recurse -ErrorAction SilentlyContinue
        }
    }
    
    if ($auditFolders.Count -gt 0) {
        $DatabasePath = ($auditFolders | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
        Write-Host "Found database: $DatabasePath" -ForegroundColor Green
    } else {
        Write-Warning "No AuditData.db found. You'll need to browse to it in the UI."
        $DatabasePath = ""
    }
}

# Global variable for database connection pool
$script:DbConnections = @{}

# Start Pode server
Start-PodeServer {
    
    # Add endpoint
    Add-PodeEndpoint -Address $Address -Port $Port -Protocol Http
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   M&A Audit Query Builder - RUNNING" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   URL: http://${Address}:${Port}" -ForegroundColor White
    Write-Host "   Database: $DatabasePath" -ForegroundColor White
    Write-Host ""
    Write-Host "   Press Ctrl+C to stop server" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Enable static file serving
    $wwwroot = Join-Path $PSScriptRoot "wwwroot"
    if (Test-Path $wwwroot) {
        Add-PodeStaticRoute -Path '/' -Source $wwwroot -Defaults @('index.html')
    }
    
    # Enable logging
    New-PodeLoggingMethod -Terminal | Enable-PodeRequestLogging
    
    #region Helper Functions
    
    function Get-DatabaseConnection {
        param([string]$DbPath)
        
        if ([string]::IsNullOrWhiteSpace($DbPath)) {
            throw "Database path not specified"
        }
        
        if (-not (Test-Path $DbPath)) {
            throw "Database file not found: $DbPath"
        }
        
        $connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$DbPath;Version=3;")
        $connection.Open()
        return $connection
    }
    
    function Get-DatabaseSchema {
        param([System.Data.SQLite.SQLiteConnection]$Connection)
        
        $schema = @{}
        
        # Get list of tables
        $tablesQuery = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        $command = $Connection.CreateCommand()
        $command.CommandText = $tablesQuery
        $reader = $command.ExecuteReader()
        
        $tables = @()
        while ($reader.Read()) {
            $tables += $reader["name"]
        }
        $reader.Close()
        
        # Get columns for each table
        foreach ($table in $tables) {
            $columnsQuery = "PRAGMA table_info('$table')"
            $colCommand = $Connection.CreateCommand()
            $colCommand.CommandText = $columnsQuery
            $colReader = $colCommand.ExecuteReader()
            
            $columns = @()
            while ($colReader.Read()) {
                $columns += @{
                    name = $colReader["name"]
                    type = $colReader["type"]
                    notnull = [bool]$colReader["notnull"]
                    pk = [bool]$colReader["pk"]
                }
            }
            $colReader.Close()
            
            $schema[$table] = $columns
        }
        
        return $schema
    }
    
    function Invoke-DatabaseQuery {
        param(
            [System.Data.SQLite.SQLiteConnection]$Connection,
            [string]$Query,
            [int]$Limit = 1000
        )
        
        # Add LIMIT if not present
        if ($Query -notmatch '\bLIMIT\b' -and $Query -match '^\s*SELECT\b') {
            $Query += " LIMIT $Limit"
        }
        
        $command = $Connection.CreateCommand()
        $command.CommandText = $Query
        $command.CommandTimeout = 30
        
        $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter($command)
        $dataSet = New-Object System.Data.DataSet
        [void]$adapter.Fill($dataSet)
        
        $results = @()
        if ($dataSet.Tables.Count -gt 0) {
            foreach ($row in $dataSet.Tables[0].Rows) {
                $obj = @{}
                foreach ($col in $dataSet.Tables[0].Columns) {
                    $value = $row[$col]
                    if ($null -eq $value -or $value -is [System.DBNull]) {
                        $obj[$col.ColumnName] = $null
                    } else {
                        $obj[$col.ColumnName] = $value.ToString()
                    }
                }
                $results += $obj
            }
        }
        
        return $results
    }
    
    #endregion
    
    #region API Routes
    
    # Home page
    Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
        $htmlPath = Join-Path $using:PSScriptRoot "wwwroot\index.html"
        if (Test-Path $htmlPath) {
            Write-PodeFileResponse -Path $htmlPath
        } else {
            Write-PodeHtmlResponse -Value "<h1>Query Builder UI not found</h1><p>Please ensure wwwroot/index.html exists</p>"
        }
    }
    
    # API: Get database schema
    Add-PodeRoute -Method Post -Path '/api/schema' -ScriptBlock {
        try {
            $body = $WebEvent.Data
            $dbPath = $body.databasePath
            
            if ([string]::IsNullOrWhiteSpace($dbPath)) {
                $dbPath = $using:DatabasePath
            }
            
            $connection = Get-DatabaseConnection -DbPath $dbPath
            $schema = Get-DatabaseSchema -Connection $connection
            $connection.Close()
            
            Write-PodeJsonResponse -Value @{ 
                success = $true
                schema = $schema
                databasePath = $dbPath
            }
        }
        catch {
            Write-PodeJsonResponse -Value @{ 
                success = $false
                error = $_.Exception.Message
            } -StatusCode 500
        }
    }
    
    # API: Get table columns
    Add-PodeRoute -Method Post -Path '/api/columns' -ScriptBlock {
        try {
            $body = $WebEvent.Data
            $dbPath = $body.databasePath
            $table = $body.table
            
            if ([string]::IsNullOrWhiteSpace($dbPath)) {
                $dbPath = $using:DatabasePath
            }
            
            $connection = Get-DatabaseConnection -DbPath $dbPath
            
            $columnsQuery = "PRAGMA table_info('$table')"
            $command = $connection.CreateCommand()
            $command.CommandText = $columnsQuery
            $reader = $command.ExecuteReader()
            
            $columns = @()
            while ($reader.Read()) {
                $columns += @{
                    name = $reader["name"]
                    type = $reader["type"]
                    notnull = [bool]$reader["notnull"]
                    pk = [bool]$reader["pk"]
                }
            }
            $reader.Close()
            $connection.Close()
            
            Write-PodeJsonResponse -Value @{ 
                success = $true
                columns = $columns
            }
        }
        catch {
            Write-PodeJsonResponse -Value @{ 
                success = $false
                error = $_.Exception.Message
            } -StatusCode 500
        }
    }
    
    # API: Execute query
    Add-PodeRoute -Method Post -Path '/api/query' -ScriptBlock {
        try {
            $body = $WebEvent.Data
            $query = $body.query
            $dbPath = $body.databasePath
            $limit = if ($body.limit) { [int]$body.limit } else { 1000 }
            
            if ([string]::IsNullOrWhiteSpace($dbPath)) {
                $dbPath = $using:DatabasePath
            }
            
            # Security: Only allow SELECT statements
            if ($query -notmatch '^\s*SELECT\b') {
                throw "Only SELECT queries are allowed"
            }
            
            $startTime = Get-Date
            $connection = Get-DatabaseConnection -DbPath $dbPath
            $results = Invoke-DatabaseQuery -Connection $connection -Query $query -Limit $limit
            $connection.Close()
            $endTime = Get-Date
            
            $duration = ($endTime - $startTime).TotalMilliseconds
            
            Write-PodeJsonResponse -Value @{ 
                success = $true
                data = $results
                rowCount = $results.Count
                executionTime = [math]::Round($duration, 2)
                query = $query
            }
        }
        catch {
            Write-PodeJsonResponse -Value @{ 
                success = $false
                error = $_.Exception.Message
                query = $body.query
            } -StatusCode 500
        }
    }
    
    # API: Get sample data for table
    Add-PodeRoute -Method Post -Path '/api/sample' -ScriptBlock {
        try {
            $body = $WebEvent.Data
            $table = $body.table
            $dbPath = $body.databasePath
            
            if ([string]::IsNullOrWhiteSpace($dbPath)) {
                $dbPath = $using:DatabasePath
            }
            
            $connection = Get-DatabaseConnection -DbPath $dbPath
            $query = "SELECT * FROM [$table] LIMIT 10"
            $results = Invoke-DatabaseQuery -Connection $connection -Query $query
            $connection.Close()
            
            Write-PodeJsonResponse -Value @{ 
                success = $true
                data = $results
            }
        }
        catch {
            Write-PodeJsonResponse -Value @{ 
                success = $false
                error = $_.Exception.Message
            } -StatusCode 500
        }
    }
    
    # API: Get query templates
    Add-PodeRoute -Method Get -Path '/api/templates' -ScriptBlock {
        $templates = @(
            @{
                name = "Stale Privileged Accounts"
                description = "Admin accounts that haven't logged in for 90+ days"
                category = "Security"
                query = @"
SELECT 
    u.SamAccountName,
    u.DisplayName,
    u.DaysSinceLastLogon,
    pa.GroupName,
    u.Enabled
FROM Users u
INNER JOIN PrivilegedAccounts pa ON u.SamAccountName = pa.MemberSamAccountName
WHERE u.IsStale = 1 AND u.Enabled = 1
ORDER BY u.DaysSinceLastLogon DESC
"@
            },
            @{
                name = "SQL Backup Risk Servers"
                description = "Servers with SQL databases that have no recent backups"
                category = "SQL"
                query = @"
SELECT 
    s.ServerName,
    s.MemoryGB,
    s.CPUCores,
    d.DatabaseName,
    d.SizeGB,
    d.DaysSinceLastBackup,
    d.BackupIssue
FROM Servers s
INNER JOIN SQLDatabases d ON s.ServerName = d.ServerName
WHERE d.BackupIssue IS NOT NULL
ORDER BY d.SizeGB DESC
"@
            },
            @{
                name = "Top 20 Applications by Server Count"
                description = "Most widely deployed applications across infrastructure"
                category = "Servers"
                query = @"
SELECT 
    ApplicationName,
    COUNT(DISTINCT ServerName) AS ServerCount,
    Publisher
FROM ServerApplications
GROUP BY ApplicationName, Publisher
ORDER BY ServerCount DESC
LIMIT 20
"@
            },
            @{
                name = "Virtual vs Physical Servers"
                description = "Breakdown of virtualization across environment"
                category = "Servers"
                query = @"
SELECT 
    CASE WHEN IsVirtual = 1 THEN 'Virtual' ELSE 'Physical' END AS ServerType,
    COUNT(*) AS Count,
    SUM(MemoryGB) AS TotalMemoryGB,
    SUM(CPUCores) AS TotalCPUCores
FROM Servers
WHERE Online = 1
GROUP BY IsVirtual
"@
            },
            @{
                name = "Service Account Inventory"
                description = "All detected service accounts with SPN details"
                category = "Security"
                query = @"
SELECT 
    SamAccountName,
    DisplayName,
    SPNCount,
    PasswordLastSet,
    LastLogonDate,
    DetectionReason
FROM ServiceAccounts
ORDER BY SPNCount DESC
"@
            },
            @{
                name = "Stale Computer Accounts"
                description = "Computers that haven't checked in for 90+ days"
                category = "Active Directory"
                query = @"
SELECT 
    Name,
    OperatingSystem,
    LastLogonDate,
    DaysSinceLastLogon,
    Enabled
FROM Computers
WHERE DaysSinceLastLogon > 90 AND Enabled = 1
ORDER BY DaysSinceLastLogon DESC
"@
            },
            @{
                name = "SQL Server Inventory Summary"
                description = "Overview of all SQL Server instances"
                category = "SQL"
                query = @"
SELECT 
    ServerName,
    InstanceName,
    ProductVersion,
    Edition,
    IsClustered,
    IsHadrEnabled
FROM SQLInstances
ORDER BY ServerName
"@
            },
            @{
                name = "Users by Department"
                description = "User count and breakdown by department"
                category = "Active Directory"
                query = @"
SELECT 
    Department,
    COUNT(*) AS UserCount,
    SUM(CASE WHEN Enabled = 1 THEN 1 ELSE 0 END) AS EnabledCount,
    SUM(CASE WHEN IsStale = 1 THEN 1 ELSE 0 END) AS StaleCount
FROM Users
WHERE Department IS NOT NULL AND Department != ''
GROUP BY Department
ORDER BY UserCount DESC
"@
            }
        )
        
        Write-PodeJsonResponse -Value @{ 
            success = $true
            templates = $templates
        }
    }
    
    # API: Export results to CSV
    Add-PodeRoute -Method Post -Path '/api/export' -ScriptBlock {
        try {
            $body = $WebEvent.Data
            $data = $body.data
            
            if ($data.Count -eq 0) {
                throw "No data to export"
            }
            
            # Convert to CSV
            $csv = ""
            $columns = $data[0].Keys
            $csv += ($columns -join ",") + "`r`n"
            
            foreach ($row in $data) {
                $values = foreach ($col in $columns) {
                    $value = $row[$col]
                    if ($null -eq $value) {
                        '""'
                    } elseif ($value -match '[,"\r\n]') {
                        '"' + ($value -replace '"', '""') + '"'
                    } else {
                        $value
                    }
                }
                $csv += ($values -join ",") + "`r`n"
            }
            
            $filename = "query_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            
            Write-PodeTextResponse -Value $csv -ContentType 'text/csv; charset=utf-8' `
                -Headers @{ 'Content-Disposition' = "attachment; filename=$filename" }
        }
        catch {
            Write-PodeJsonResponse -Value @{ 
                success = $false
                error = $_.Exception.Message
            } -StatusCode 500
        }
    }
    
    #endregion
}

