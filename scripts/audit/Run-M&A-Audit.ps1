<#
.SYNOPSIS
    M&A Technical Discovery Script - Main Orchestration Engine

.DESCRIPTION
    Comprehensive PowerShell-based auditing toolset for M&A technical discovery and due diligence.
    Audits Active Directory, servers, SQL databases, Entra ID, Microsoft 365, Power Platform, and compliance.

.PARAMETER CompanyName
    Name of the target company being audited (used in report titles and output folder naming)

.PARAMETER OutputFolder
    Path where audit results will be saved (folder created if doesn't exist)

.PARAMETER ADCredential
    Credentials for Active Directory access (Domain User with read-only permissions)

.PARAMETER ServerInventory
    Enable detailed server hardware and application inventory (default: $true)

.PARAMETER ServerEventLogDays
    Number of days to query event logs (default: 30, options: 7/30/60/90)

.PARAMETER ServerLogonHistoryDays
    Number of days for logon history analysis (default: 90, options: 30/60/90/180/365)

.PARAMETER MaxParallelServers
    Number of servers to query in parallel (default: 10, max: 50)

.PARAMETER ServerQueryTimeout
    Timeout in seconds per server (default: 300 = 5 minutes)

.PARAMETER SkipOfflineServers
    Skip servers that don't respond to ping (default: $true)

.PARAMETER SkipEventLogs
    Skip event log collection (faster execution, default: $false)

.PARAMETER SkipLogonHistory
    Skip logon history collection (faster execution, default: $false)

.PARAMETER IncludeServerServices
    Include Windows services inventory (verbose, default: $false)

.PARAMETER SkipAD
    Skip Active Directory audit (for cloud-only environments)

.PARAMETER OnlyAD
    Run AD and server audit only (skip cloud modules)

.PARAMETER SkipSQL
    Skip SQL Server inventory

.PARAMETER SkipPowerPlatform
    Skip Power Platform audit

.PARAMETER CreateEncryptedArchive
    Create password-protected 7z archive of output

.PARAMETER ArchivePassword
    Password for encrypted archive (SecureString)

.PARAMETER SkipEFSEncryption
    Skip Windows EFS encryption of output folder

.PARAMETER UseAzureKeyVault
    Use Azure Key Vault for encryption key management

.PARAMETER KeyVaultName
    Azure Key Vault name (when using -UseAzureKeyVault)

.PARAMETER KeyName
    Key name in Azure Key Vault

.PARAMETER SkipEncryption
    Skip all encryption (NOT RECOMMENDED - for development only)

.PARAMETER CreateDatabase
    Create SQLite database from CSV audit data (enables cross-dataset queries and reporting)

.EXAMPLE
    .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" -Verbose

.EXAMPLE
    .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -OutputFolder "C:\Audits\Contoso" `
        -ServerEventLogDays 30 -ServerLogonHistoryDays 90 -MaxParallelServers 20

.EXAMPLE
    .\Run-M&A-Audit.ps1 -CompanyName "Contoso" -SkipAD -OutputFolder "C:\Audits\Contoso"

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 2.0
    Requires: PowerShell 5.1 or PowerShell 7+
    Modules: ActiveDirectory, Microsoft.Graph, ExchangeOnlineManagement, PnP.PowerShell, MicrosoftTeams
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CompanyName,

    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,

    [Parameter(Mandatory = $false)]
    [PSCredential]$ADCredential,

    [Parameter(Mandatory = $false)]
    [string]$ReportTitle,

    [Parameter(Mandatory = $false)]
    [string]$DomainName,

    [Parameter(Mandatory = $false)]
    [bool]$ServerInventory = $true,

    [Parameter(Mandatory = $false)]
    [ValidateSet(7, 30, 60, 90)]
    [int]$ServerEventLogDays = 30,

    [Parameter(Mandatory = $false)]
    [ValidateSet(30, 60, 90, 180, 365)]
    [int]$ServerLogonHistoryDays = 90,

    [Parameter(Mandatory = $false)]
    [ValidateSet(30, 60, 90, 180)]
    [int]$StaleThresholdDays = 90,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50)]
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
    [switch]$ExcludeTestOUs,

    [Parameter(Mandatory = $false)]
    [string]$FocusOUs,

    [Parameter(Mandatory = $false)]
    [string]$KnownSQLInstances,

    [Parameter(Mandatory = $false)]
    [string]$PriorityServers,

    [Parameter(Mandatory = $false)]
    [string]$ComplianceFocus,

    [Parameter(Mandatory = $false)]
    [string]$NotificationEmail,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAD,

    [Parameter(Mandatory = $false)]
    [switch]$OnlyAD,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSQL,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPowerPlatform,

    [Parameter(Mandatory = $false)]
    [switch]$CreateEncryptedArchive,

    [Parameter(Mandatory = $false)]
    [SecureString]$ArchivePassword,

    [Parameter(Mandatory = $false)]
    [switch]$SkipEFSEncryption,

    [Parameter(Mandatory = $false)]
    [switch]$UseAzureKeyVault,

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [string]$KeyName,

    [Parameter(Mandatory = $false)]
    [switch]$SkipEncryption,

    [Parameter(Mandatory = $false)]
    [switch]$CreateDatabase
)

#Requires -Version 5.1

#region Script Initialization

# Script metadata
$script:ScriptVersion = "2.0"
$script:ScriptAuthor = "Adrian Johnson <adrian207@gmail.com>"
$script:StartTime = Get-Date
$script:Timestamp = $StartTime.ToString("yyyyMMdd_HHmmss")

# Create timestamped output folder
$script:AuditOutputFolder = Join-Path $OutputFolder "$($Timestamp)_$($CompanyName -replace '[^\w\-]', '_')"

# Logging setup
$script:LogFolder = Join-Path $AuditOutputFolder "Logs"
$script:ExecutionLog = Join-Path $LogFolder "execution.log"
$script:ErrorLog = Join-Path $LogFolder "errors.log"

# Module tracking
$script:ModuleResults = @{}
$script:DataQualityScore = 100
$script:FailedModules = @()
$script:SuccessfulModules = @()

#endregion

#region Helper Functions

function Write-AuditLog {
    <#
    .SYNOPSIS
        Writes timestamped log entries to both console and log file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $script:ExecutionLog -Value $logMessage -ErrorAction SilentlyContinue
    
    # Write to console
    if (-not $NoConsole) {
        switch ($Level) {
            'Error'   { Write-Host $logMessage -ForegroundColor Red }
            'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
            'Success' { Write-Host $logMessage -ForegroundColor Green }
            'Debug'   { if ($VerbosePreference -eq 'Continue') { Write-Host $logMessage -ForegroundColor Cyan } }
            default   { Write-Host $logMessage }
        }
    }
    
    # Write errors to separate error log
    if ($Level -eq 'Error') {
        Add-Content -Path $script:ErrorLog -Value $logMessage -ErrorAction SilentlyContinue
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates PowerShell version, required modules, and permissions
    #>
    [CmdletBinding()]
    param()
    
    Write-AuditLog "Starting prerequisite checks..." -Level Info
    
    # PowerShell version check
    $psVersion = $PSVersionTable.PSVersion
    Write-AuditLog "PowerShell Version: $($psVersion.Major).$($psVersion.Minor)" -Level Info
    
    if ($psVersion.Major -lt 5) {
        Write-AuditLog "PowerShell 5.1 or higher required. Current version: $psVersion" -Level Error
        return $false
    }
    
    # Check if running as Administrator (required for server inventory)
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-AuditLog "Running with Administrator privileges" -Level Success
    } else {
        Write-AuditLog "Not running as Administrator - server inventory may be limited" -Level Warning
    }
    
    # Check required modules
    $requiredModules = @(
        @{Name='ActiveDirectory'; Required=$true; SkipIf=$SkipAD},
        @{Name='Microsoft.Graph'; Required=$false; SkipIf=$OnlyAD},
        @{Name='ExchangeOnlineManagement'; Required=$false; SkipIf=$OnlyAD},
        @{Name='PnP.PowerShell'; Required=$false; SkipIf=$OnlyAD},
        @{Name='MicrosoftTeams'; Required=$false; SkipIf=$OnlyAD},
        @{Name='Microsoft.PowerApps.Administration.PowerShell'; Required=$false; SkipIf=($OnlyAD -or $SkipPowerPlatform)}
    )
    
    $missingModules = @()
    foreach ($module in $requiredModules) {
        if ($module.SkipIf) {
            Write-AuditLog "Skipping module check: $($module.Name)" -Level Debug
            continue
        }
        
        $installed = Get-Module -Name $module.Name -ListAvailable
        if ($installed) {
            Write-AuditLog "Module found: $($module.Name) (Version: $($installed[0].Version))" -Level Success
        } else {
            if ($module.Required) {
                Write-AuditLog "Required module missing: $($module.Name)" -Level Error
                $missingModules += $module.Name
            } else {
                Write-AuditLog "Optional module missing: $($module.Name) - related audit will be skipped" -Level Warning
            }
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-AuditLog "Missing required modules: $($missingModules -join ', ')" -Level Error
        Write-AuditLog "Install with: Install-Module $($missingModules -join ', ') -Force" -Level Info
        return $false
    }
    
    Write-AuditLog "Prerequisite checks completed successfully" -Level Success
    return $true
}

function Initialize-OutputStructure {
    <#
    .SYNOPSIS
        Creates the output folder structure
    #>
    [CmdletBinding()]
    param()
    
    Write-AuditLog "Creating output folder structure..." -Level Info
    
    try {
        # Create main output folder
        New-Item -ItemType Directory -Path $script:AuditOutputFolder -Force | Out-Null
        Write-AuditLog "Created output folder: $script:AuditOutputFolder" -Level Success
        
        # Create subfolder structure
        $folders = @(
            'Logs',
            'RawData',
            'RawData\AD',
            'RawData\Servers',
            'RawData\SQL',
            'RawData\EntraID',
            'RawData\Exchange',
            'RawData\SharePoint',
            'RawData\Teams',
            'RawData\PowerPlatform',
            'RawData\Compliance'
        )
        
        foreach ($folder in $folders) {
            $path = Join-Path $script:AuditOutputFolder $folder
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            Write-AuditLog "Created subfolder: $folder" -Level Debug
        }
        
        Write-AuditLog "Output structure created successfully" -Level Success
        return $true
    }
    catch {
        Write-AuditLog "Failed to create output structure: $_" -Level Error
        return $false
    }
}

function Invoke-AuditModule {
    <#
    .SYNOPSIS
        Executes an individual audit module and tracks results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [string]$ModulePath,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )
    
    Write-AuditLog "======================================" -Level Info
    Write-AuditLog "Starting module: $ModuleName" -Level Info
    Write-AuditLog "======================================" -Level Info
    
    $moduleStartTime = Get-Date
    
    try {
        # Check if module file exists
        if (-not (Test-Path $ModulePath)) {
            throw "Module file not found: $ModulePath"
        }
        
        # Execute module
        $result = & $ModulePath @Parameters
        
        $moduleEndTime = Get-Date
        $duration = ($moduleEndTime - $moduleStartTime).TotalMinutes
        
        # Store results
        $script:ModuleResults[$ModuleName] = @{
            Status = 'Success'
            Duration = $duration
            Result = $result
            StartTime = $moduleStartTime
            EndTime = $moduleEndTime
        }
        
        $script:SuccessfulModules += $ModuleName
        
        Write-AuditLog "Module $ModuleName completed successfully in $([math]::Round($duration, 2)) minutes" -Level Success
        
        return $true
    }
    catch {
        $moduleEndTime = Get-Date
        $duration = ($moduleEndTime - $moduleStartTime).TotalMinutes
        
        # Store error details
        $script:ModuleResults[$ModuleName] = @{
            Status = 'Failed'
            Duration = $duration
            Error = $_.Exception.Message
            StartTime = $moduleStartTime
            EndTime = $moduleEndTime
        }
        
        $script:FailedModules += $ModuleName
        $script:DataQualityScore -= 10  # Deduct 10% for each failed module
        
        Write-AuditLog "Module $ModuleName failed after $([math]::Round($duration, 2)) minutes: $($_.Exception.Message)" -Level Error
        Write-AuditLog "Stack Trace: $($_.ScriptStackTrace)" -Level Debug
        
        return $false
    }
}

function Export-AuditMetadata {
    <#
    .SYNOPSIS
        Exports audit execution metadata to JSON
    #>
    [CmdletBinding()]
    param()
    
    Write-AuditLog "Generating audit metadata..." -Level Info
    
    $endTime = Get-Date
    $totalDuration = ($endTime - $script:StartTime).TotalMinutes
    
    $metadata = @{
        AuditInfo = @{
            CompanyName = $CompanyName
            AuditDate = $script:StartTime.ToString("yyyy-MM-dd HH:mm:ss")
            AuditDuration = "$([math]::Round($totalDuration, 2)) minutes"
            ScriptVersion = $script:ScriptVersion
            Author = $script:ScriptAuthor
        }
        ExecutionDetails = @{
            ExecutedBy = "$env:USERDOMAIN\$env:USERNAME"
            ExecutedFrom = $env:COMPUTERNAME
            PowerShellVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
            RunAsAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        Parameters = @{
            ReportTitle = $ReportTitle
            DomainName = $DomainName
            ServerInventory = $ServerInventory
            ServerEventLogDays = $ServerEventLogDays
            ServerLogonHistoryDays = $ServerLogonHistoryDays
            StaleThresholdDays = $StaleThresholdDays
            MaxParallelServers = $MaxParallelServers
            ExcludeTestOUs = $ExcludeTestOUs.IsPresent
            FocusOUs = $FocusOUs
            KnownSQLInstances = $KnownSQLInstances
            PriorityServers = $PriorityServers
            ComplianceFocus = $ComplianceFocus
            NotificationEmail = $NotificationEmail
            SkipAD = $SkipAD.IsPresent
            OnlyAD = $OnlyAD.IsPresent
            SkipSQL = $SkipSQL.IsPresent
            SkipEventLogs = $SkipEventLogs.IsPresent
            SkipLogonHistory = $SkipLogonHistory.IsPresent
        }
        Results = @{
            SuccessfulModules = $script:SuccessfulModules
            FailedModules = $script:FailedModules
            ModuleDetails = $script:ModuleResults
            DataQualityScore = $script:DataQualityScore
        }
        Encryption = @{
            EFSEncrypted = (-not $SkipEFSEncryption.IsPresent -and -not $SkipEncryption.IsPresent)
            ArchiveCreated = $CreateEncryptedArchive.IsPresent
            AzureKeyVault = $UseAzureKeyVault.IsPresent
            SkippedEncryption = $SkipEncryption.IsPresent
        }
    }
    
    $metadataPath = Join-Path $script:AuditOutputFolder "audit_metadata.json"
    $metadata | ConvertTo-Json -Depth 10 | Set-Content -Path $metadataPath
    
    Write-AuditLog "Metadata exported to: $metadataPath" -Level Success
}

function Send-AuditNotification {
    <#
    .SYNOPSIS
        Sends email notification with audit completion summary
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ToEmail,
        
        [Parameter(Mandatory = $false)]
        [string]$SmtpServer = "smtp.office365.com",
        
        [Parameter(Mandatory = $false)]
        [int]$SmtpPort = 587,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    
    if ([string]::IsNullOrWhiteSpace($ToEmail)) {
        Write-AuditLog "No notification email configured - skipping email notification" -Level Info
        return
    }
    
    Write-AuditLog "Sending email notification to: $ToEmail" -Level Info
    
    try {
        # Calculate summary stats
        $endTime = Get-Date
        $duration = ($endTime - $script:StartTime).TotalMinutes
        
        # Build email body
        $emailBody = @"
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; margin: -30px -30px 20px -30px; }
        h1 { margin: 0; font-size: 24px; }
        .status { display: inline-block; padding: 8px 16px; border-radius: 4px; font-weight: bold; margin: 10px 0; }
        .status-success { background-color: #10b981; color: white; }
        .status-warning { background-color: #f59e0b; color: white; }
        .status-error { background-color: #ef4444; color: white; }
        .section { margin: 20px 0; padding: 15px; background-color: #f9fafb; border-left: 4px solid #667eea; border-radius: 4px; }
        .section h2 { margin-top: 0; color: #374151; font-size: 18px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 15px 0; }
        .metric { background-color: white; padding: 15px; border-radius: 6px; border: 1px solid #e5e7eb; text-align: center; }
        .metric-value { font-size: 28px; font-weight: bold; color: #667eea; }
        .metric-label { font-size: 12px; color: #6b7280; margin-top: 5px; }
        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; }
        a { color: #667eea; text-decoration: none; }
        a:hover { text-decoration: underline; }
        ul { padding-left: 20px; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 M&A Audit Complete</h1>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">$CompanyName Technical Discovery Audit</p>
        </div>
        
        <div class="section">
            <h2>Audit Summary</h2>
            <span class="status status-$(if($script:FailedModules.Count -eq 0){'success'}else{'warning'})">
                $(if($script:FailedModules.Count -eq 0){'✓ COMPLETED'}else{'⚠ COMPLETED WITH WARNINGS'})
            </span>
            
            <div class="metrics">
                <div class="metric">
                    <div class="metric-value">$([math]::Round($duration, 1))m</div>
                    <div class="metric-label">Duration</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($script:SuccessfulModules.Count)</div>
                    <div class="metric-label">Modules Completed</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$($script:FailedModules.Count)</div>
                    <div class="metric-label">Modules Failed</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$script:DataQualityScore%</div>
                    <div class="metric-label">Data Quality</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Successful Modules</h2>
            <ul>
$(foreach ($module in $script:SuccessfulModules) {
    "                <li>✓ $module</li>"
})
            </ul>
        </div>
        
$(if ($script:FailedModules.Count -gt 0) {
    @"
        <div class="section" style="border-left-color: #f59e0b;">
            <h2>⚠ Failed Modules</h2>
            <ul>
$(foreach ($module in $script:FailedModules) {
    "                <li>✗ $module</li>"
})
            </ul>
            <p><strong>Note:</strong> Check error log for details: <code>$($script:ErrorLog)</code></p>
        </div>
"@
})
        
        <div class="section">
            <h2>📂 Output Location</h2>
            <p><code>$($script:AuditOutputFolder)</code></p>
            
            <h2>📊 Generated Reports</h2>
            <ul>
                <li><strong>Executive Summary:</strong> <code>index.html</code></li>
                <li><strong>Active Directory Report:</strong> <code>active-directory.html</code></li>
                <li><strong>Server Infrastructure:</strong> <code>servers.html</code></li>
                <li><strong>SQL Databases:</strong> <code>sql-databases.html</code></li>
                <li><strong>Security Analysis:</strong> <code>security.html</code></li>
                <li><strong>Raw Data:</strong> <code>RawData/</code> folder (CSV files)</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>🔍 Next Steps</h2>
            <ul>
                <li>Review the executive summary dashboard (open <code>index.html</code>)</li>
                <li>Check migration readiness score and key findings</li>
                <li>Review detailed drill-down reports for each area</li>
                <li>Analyze raw CSV data for custom queries</li>
                <li>Document any security or compliance concerns</li>
                <li>Share findings with stakeholders</li>
            </ul>
        </div>
        
        <div class="footer">
            <p><strong>M&A Technical Discovery Script v$($script:ScriptVersion)</strong></p>
            <p>Executed by: $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME</p>
            <p>Start Time: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
            <p>End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p style="margin-top: 15px;">
                <em>This email was automatically generated by the M&A Audit Tool.</em><br>
                For support or questions, contact your IT team or the tool administrator.
            </p>
        </div>
    </div>
</body>
</html>
"@
        
        $emailSubject = "✓ M&A Audit Complete - $CompanyName - Data Quality: $script:DataQualityScore%"
        
        # Prepare email parameters
        $mailParams = @{
            To = $ToEmail
            Subject = $emailSubject
            Body = $emailBody
            BodyAsHtml = $true
            SmtpServer = $SmtpServer
            Port = $SmtpPort
            UseSsl = $true
        }
        
        # Add From address (use current user's email if available)
        try {
            $fromEmail = "$env:USERNAME@$($env:USERDNSDOMAIN)"
            $mailParams['From'] = $fromEmail
        }
        catch {
            # Fallback to generic sender
            $mailParams['From'] = "noreply@audit.local"
        }
        
        # Add credential if provided
        if ($Credential) {
            $mailParams['Credential'] = $Credential
        }
        
        # Send email
        Send-MailMessage @mailParams
        
        Write-AuditLog "Email notification sent successfully to: $ToEmail" -Level Success
        Write-Host "✓ Email notification sent to: $ToEmail" -ForegroundColor Green
    }
    catch {
        Write-AuditLog "Failed to send email notification: $_" -Level Warning
        Write-Host "Warning: Failed to send email notification: $_" -ForegroundColor Yellow
        Write-Host "You can manually check the audit results at: $script:AuditOutputFolder" -ForegroundColor Yellow
    }
}

function Protect-AuditOutput {
    <#
    .SYNOPSIS
        Applies encryption to audit output files
    #>
    [CmdletBinding()]
    param()
    
    if ($SkipEncryption) {
        Write-AuditLog "WARNING: Encryption skipped - output files are NOT ENCRYPTED!" -Level Warning
        Write-AuditLog "This is NOT RECOMMENDED for production use - sensitive data is exposed" -Level Warning
        return
    }
    
    Write-AuditLog "Applying encryption to output files..." -Level Info
    
    # Method 1: EFS Encryption
    if (-not $SkipEFSEncryption) {
        try {
            Write-AuditLog "Applying Windows EFS encryption..." -Level Info
            
            # Encrypt entire output folder
            $folder = Get-Item $script:AuditOutputFolder
            $folder.Encrypt()
            
            # Verify encryption
            $encrypted = (Get-Item $script:AuditOutputFolder).Attributes -band [System.IO.FileAttributes]::Encrypted
            if ($encrypted) {
                Write-AuditLog "EFS encryption applied successfully" -Level Success
            } else {
                Write-AuditLog "EFS encryption verification failed" -Level Warning
            }
        }
        catch {
            Write-AuditLog "EFS encryption failed: $($_.Exception.Message)" -Level Error
            Write-AuditLog "Possible causes: Not NTFS volume, Windows Home edition, insufficient permissions" -Level Warning
        }
    }
    
    # Method 2: Encrypted Archive
    if ($CreateEncryptedArchive) {
        Write-AuditLog "Creating encrypted archive..." -Level Info
        
        # Check if 7-Zip is available
        $7zipPath = "C:\Program Files\7-Zip\7z.exe"
        if (-not (Test-Path $7zipPath)) {
            $7zipPath = "C:\Program Files (x86)\7-Zip\7z.exe"
        }
        
        if (Test-Path $7zipPath) {
            try {
                if (-not $ArchivePassword) {
                    $ArchivePassword = Read-Host -AsSecureString "Enter password for encrypted archive (min 16 chars)"
                }
                
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ArchivePassword))
                
                # Validate password strength
                if ($plainPassword.Length -lt 16) {
                    Write-AuditLog "Password must be at least 16 characters" -Level Error
                    return
                }
                
                $archivePath = "$($script:AuditOutputFolder).7z"
                $arguments = "a -p`"$plainPassword`" -mhe=on -t7z -mhc=on -mx=9 `"$archivePath`" `"$($script:AuditOutputFolder)\*`""
                
                Write-AuditLog "Creating encrypted 7z archive..." -Level Info
                Start-Process -FilePath $7zipPath -ArgumentList $arguments -Wait -NoNewWindow
                
                if (Test-Path $archivePath) {
                    $archiveSize = [math]::Round((Get-Item $archivePath).Length / 1MB, 2)
                    Write-AuditLog "Encrypted archive created: $archivePath ($archiveSize MB)" -Level Success
                } else {
                    Write-AuditLog "Archive creation failed" -Level Error
                }
            }
            catch {
                Write-AuditLog "Archive encryption failed: $($_.Exception.Message)" -Level Error
            }
        } else {
            # Fallback to PowerShell native Compress-Archive
            Write-AuditLog "7-Zip not found. Using PowerShell native compression (AES-256)..." -Level Warning
            
            try {
                if (-not $ArchivePassword) {
                    $ArchivePassword = Read-Host -AsSecureString "Enter password for encrypted archive (min 16 chars)"
                }
                
                # Create temporary compressed archive (unencrypted)
                $tempArchivePath = "$($script:AuditOutputFolder)-temp.zip"
                $archivePath = "$($script:AuditOutputFolder).zip.enc"
                
                Write-AuditLog "Creating compressed archive..." -Level Info
                Compress-Archive -Path "$($script:AuditOutputFolder)\*" -DestinationPath $tempArchivePath -CompressionLevel Optimal -Force
                
                # Encrypt the archive using AES
                $aes = [System.Security.Cryptography.Aes]::Create()
                $aes.KeySize = 256
                $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                
                # Derive key from password using PBKDF2
                $salt = New-Object byte[] 32
                $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
                $rng.GetBytes($salt)
                
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ArchivePassword))
                
                if ($plainPassword.Length -lt 16) {
                    Write-AuditLog "Password must be at least 16 characters" -Level Error
                    Remove-Item $tempArchivePath -Force
                    return
                }
                
                $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($plainPassword, $salt, 100000)
                $aes.Key = $pbkdf2.GetBytes(32) # 256-bit key
                $aes.GenerateIV()
                
                # Read temp archive and encrypt it
                $inputBytes = [System.IO.File]::ReadAllBytes($tempArchivePath)
                $encryptor = $aes.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)
                
                # Write encrypted archive with salt and IV prepended
                $outputStream = [System.IO.File]::OpenWrite($archivePath)
                $outputStream.Write($salt, 0, 32)
                $outputStream.Write($aes.IV, 0, 16)
                $outputStream.Write($encryptedBytes, 0, $encryptedBytes.Length)
                $outputStream.Close()
                
                # Clean up
                $aes.Dispose()
                Remove-Item $tempArchivePath -Force
                
                if (Test-Path $archivePath) {
                    $archiveSize = [math]::Round((Get-Item $archivePath).Length / 1MB, 2)
                    Write-AuditLog "Encrypted archive created: $archivePath ($archiveSize MB)" -Level Success
                    Write-AuditLog "Archive uses AES-256 encryption with PBKDF2 key derivation (100,000 iterations)" -Level Info
                    
                    # Save decryption instructions
                    $decryptInstructions = @"
# Decryption Instructions

This archive was encrypted using PowerShell native AES-256 encryption.

## To decrypt and extract:

```powershell
`$encryptedFile = "$archivePath"
`$password = Read-Host -AsSecureString "Enter archive password"
`$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$password))

# Read encrypted file
`$encryptedData = [System.IO.File]::ReadAllBytes(`$encryptedFile)

# Extract salt (first 32 bytes) and IV (next 16 bytes)
`$salt = `$encryptedData[0..31]
`$iv = `$encryptedData[32..47]
`$cipherBytes = `$encryptedData[48..(`$encryptedData.Length-1)]

# Derive key using PBKDF2
`$pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(`$plainPassword, `$salt, 100000)
`$key = `$pbkdf2.GetBytes(32)

# Decrypt
`$aes = [System.Security.Cryptography.Aes]::Create()
`$aes.Key = `$key
`$aes.IV = `$iv
`$decryptor = `$aes.CreateDecryptor()
`$decryptedBytes = `$decryptor.TransformFinalBlock(`$cipherBytes, 0, `$cipherBytes.Length)

# Save decrypted ZIP
[System.IO.File]::WriteAllBytes("decrypted-audit.zip", `$decryptedBytes)

# Extract ZIP
Expand-Archive -Path "decrypted-audit.zip" -DestinationPath "."
```

**Important**: Store this password securely. Without it, the data cannot be recovered.
"@
                    $instructionsPath = Join-Path (Split-Path $archivePath -Parent) "DECRYPTION_INSTRUCTIONS.txt"
                    $decryptInstructions | Out-File $instructionsPath -Encoding UTF8
                    Write-AuditLog "Decryption instructions saved to: $instructionsPath" -Level Info
                } else {
                    Write-AuditLog "Archive creation failed" -Level Error
                }
            }
            catch {
                Write-AuditLog "PowerShell native archive encryption failed: $($_.Exception.Message)" -Level Error
            }
        }
    }
    
    # Method 3: Azure Key Vault
    if ($UseAzureKeyVault) {
        try {
            Write-AuditLog "Implementing Azure Key Vault encryption..." -Level Info
            
            # Check if Az.KeyVault module is available
            if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
                Write-AuditLog "Az.KeyVault module not found. Installing..." -Level Warning
                Install-Module -Name Az.KeyVault -Scope CurrentUser -Force -AllowClobber
            }
            
            Import-Module Az.KeyVault -ErrorAction Stop
            
            # Ensure we're connected to Azure
            $context = Get-AzContext
            if (-not $context) {
                Write-AuditLog "Not connected to Azure. Please authenticate..." -Level Info
                Connect-AzAccount
            }
            
            if (-not $KeyVaultName -or -not $KeyName) {
                Write-AuditLog "KeyVaultName and KeyName are required for Azure Key Vault encryption" -Level Error
                throw "Missing Key Vault parameters"
            }
            
            # Get or create encryption key
            $key = Get-AzKeyVaultKey -VaultName $KeyVaultName -Name $KeyName -ErrorAction SilentlyContinue
            if (-not $key) {
                Write-AuditLog "Creating new RSA key in Key Vault: $KeyName" -Level Info
                $key = Add-AzKeyVaultKey -VaultName $KeyVaultName -Name $KeyName -Destination 'Software' -KeyOps encrypt,decrypt
            }
            
            # Generate AES key for file encryption
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.KeySize = 256
            $aes.GenerateKey()
            $aes.GenerateIV()
            
            # Encrypt AES key with Key Vault RSA key
            $encryptedAESKey = Invoke-AzKeyVaultKeyOperation -Operation Encrypt -VaultName $KeyVaultName -Name $KeyName -Algorithm RSA-OAEP -Value $aes.Key
            
            # Save encrypted AES key and IV for later decryption
            $keyInfo = @{
                EncryptedAESKey = [Convert]::ToBase64String($encryptedAESKey.Result)
                IV = [Convert]::ToBase64String($aes.IV)
                KeyVaultName = $KeyVaultName
                KeyName = $KeyName
                Timestamp = (Get-Date).ToString('o')
            }
            
            $keyInfoPath = Join-Path $script:AuditOutputFolder "encryption_key_info.json"
            $keyInfo | ConvertTo-Json | Out-File $keyInfoPath -Encoding UTF8
            
            # Encrypt all CSV and JSON files
            $filesToEncrypt = Get-ChildItem -Path $script:AuditOutputFolder -Recurse -Include *.csv,*.json -Exclude encryption_key_info.json
            $encryptedCount = 0
            
            foreach ($file in $filesToEncrypt) {
                try {
                    $inputBytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    
                    $encryptor = $aes.CreateEncryptor()
                    $encryptedBytes = $encryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)
                    
                    $encryptedFilePath = "$($file.FullName).enc"
                    [System.IO.File]::WriteAllBytes($encryptedFilePath, $encryptedBytes)
                    
                    # Remove original file
                    Remove-Item $file.FullName -Force
                    $encryptedCount++
                }
                catch {
                    Write-AuditLog "Failed to encrypt file $($file.Name): $($_.Exception.Message)" -Level Warning
                }
            }
            
            $aes.Dispose()
            
            Write-AuditLog "Azure Key Vault encryption completed: $encryptedCount files encrypted" -Level Success
            Write-AuditLog "Decryption key stored in Azure Key Vault: $KeyVaultName/$KeyName" -Level Info
            Write-AuditLog "Key metadata saved to: encryption_key_info.json" -Level Info
        }
        catch {
            Write-AuditLog "Azure Key Vault encryption failed: $($_.Exception.Message)" -Level Error
            Write-AuditLog "Ensure Az.KeyVault module is installed and you have permissions" -Level Warning
        }
    }
}

#endregion

#region Main Execution

try {
    # Display banner
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   M&A Technical Discovery Script v$script:ScriptVersion" -ForegroundColor Cyan
    Write-Host "   Author: $script:ScriptAuthor" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Initialize output structure first (so we can log)
    if (-not (Initialize-OutputStructure)) {
        throw "Failed to initialize output structure"
    }
    
    Write-AuditLog "M&A Audit Started" -Level Info
    Write-AuditLog "Company: $CompanyName" -Level Info
    Write-AuditLog "Output Folder: $script:AuditOutputFolder" -Level Info
    Write-AuditLog "Start Time: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info
    
    # Run prerequisite checks
    if (-not (Test-Prerequisites)) {
        throw "Prerequisite checks failed"
    }
    
    # Display execution plan
    Write-AuditLog "Execution Plan:" -Level Info
    if (-not $SkipAD) { Write-AuditLog "  - Active Directory Audit (Servers, SQL, Users, Groups)" -Level Info }
    if (-not $OnlyAD) {
        Write-AuditLog "  - Entra ID Audit" -Level Info
        Write-AuditLog "  - Exchange Online Audit" -Level Info
        Write-AuditLog "  - SharePoint & Teams Audit" -Level Info
        if (-not $SkipPowerPlatform) { Write-AuditLog "  - Power Platform Audit" -Level Info }
        Write-AuditLog "  - Compliance & Security Audit" -Level Info
    }
    
    Write-Host ""
    
    # Execute audit modules
    $modulesPath = Join-Path $PSScriptRoot "Modules"
    
    # Active Directory Module
    if (-not $SkipAD) {
        $adParams = @{
            OutputFolder = Join-Path $script:AuditOutputFolder "RawData"
            ServerInventory = $ServerInventory
            ServerEventLogDays = $ServerEventLogDays
            ServerLogonHistoryDays = $ServerLogonHistoryDays
            MaxParallelServers = $MaxParallelServers
            ServerQueryTimeout = $ServerQueryTimeout
            SkipOfflineServers = $SkipOfflineServers
            SkipEventLogs = $SkipEventLogs
            SkipLogonHistory = $SkipLogonHistory
            IncludeServerServices = $IncludeServerServices
            SkipSQL = $SkipSQL
        }
        
        if ($ADCredential) {
            $adParams['Credential'] = $ADCredential
        }
        
        Invoke-AuditModule -ModuleName "Active Directory" -ModulePath (Join-Path $modulesPath "Invoke-AD-Audit.ps1") -Parameters $adParams
    }
    
    # Cloud modules (only if not OnlyAD)
    if (-not $OnlyAD) {
        # Entra ID Module
        $entraIDParams = @{
            OutputFolder = Join-Path $script:AuditOutputFolder "RawData"
        }
        Invoke-AuditModule -ModuleName "Microsoft Entra ID" -ModulePath (Join-Path $modulesPath "Invoke-EntraID-Audit.ps1") -Parameters $entraIDParams

        # Exchange Online Module
        $exchangeParams = @{
            OutputFolder = Join-Path $script:AuditOutputFolder "RawData"
        }
        Invoke-AuditModule -ModuleName "Exchange Online" -ModulePath (Join-Path $modulesPath "Invoke-Exchange-Audit.ps1") -Parameters $exchangeParams

        # SharePoint, OneDrive & Teams Module
        $sharePointParams = @{
            OutputFolder = Join-Path $script:AuditOutputFolder "RawData"
        }
        Invoke-AuditModule -ModuleName "SharePoint, OneDrive & Teams" -ModulePath (Join-Path $modulesPath "Invoke-SharePoint-Teams-Audit.ps1") -Parameters $sharePointParams

        # Power Platform Module (skip if requested)
        if (-not $SkipPowerPlatform) {
            $powerPlatformParams = @{
                OutputFolder = Join-Path $script:AuditOutputFolder "RawData"
            }
            Invoke-AuditModule -ModuleName "Power Platform" -ModulePath (Join-Path $modulesPath "Invoke-PowerPlatform-Audit.ps1") -Parameters $powerPlatformParams
        }

        # Compliance & Security Module
        $complianceParams = @{
            OutputFolder = Join-Path $script:AuditOutputFolder "RawData"
        }
        Invoke-AuditModule -ModuleName "Compliance & Security" -ModulePath (Join-Path $modulesPath "Invoke-Compliance-Audit.ps1") -Parameters $complianceParams
    }
    
    # Export metadata
    Export-AuditMetadata
    
    # Apply encryption
    Protect-AuditOutput
    
    # Display summary
    $endTime = Get-Date
    $totalDuration = ($endTime - $script:StartTime).TotalMinutes
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   Audit Completed Successfully!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Total Duration: $([math]::Round($totalDuration, 2)) minutes" -ForegroundColor White
    Write-Host "  Successful Modules: $($script:SuccessfulModules.Count)" -ForegroundColor Green
    Write-Host "  Failed Modules: $($script:FailedModules.Count)" -ForegroundColor $(if($script:FailedModules.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  Data Quality Score: $script:DataQualityScore%" -ForegroundColor $(if($script:DataQualityScore -ge 90){'Green'}elseif($script:DataQualityScore -ge 70){'Yellow'}else{'Red'})
    Write-Host ""
    Write-Host "Output Location:" -ForegroundColor Cyan
    Write-Host "  $script:AuditOutputFolder" -ForegroundColor White
    Write-Host ""
    
    if ($script:FailedModules.Count -gt 0) {
        Write-Host "Failed Modules:" -ForegroundColor Red
        foreach ($module in $script:FailedModules) {
            Write-Host "  - $module" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "Check error log for details: $script:ErrorLog" -ForegroundColor Yellow
    }
    
    # Create SQLite database (if requested)
    if ($CreateDatabase) {
        Write-Host ""
        Write-Host "Creating SQLite database..." -ForegroundColor Cyan
        try {
            $dbScript = Join-Path $PSScriptRoot "Libraries\SQLite-AuditDB.ps1"
            if (Test-Path $dbScript) {
                . $dbScript  # Dot-source to load functions
                
                $dbPath = Join-Path $script:AuditOutputFolder "AuditData.db"
                $dbConnection = Initialize-AuditDatabase -DatabasePath $dbPath
                
                if ($dbConnection) {
                    $importedRows = Import-AuditCSVsToDatabase -Connection $dbConnection -RawDataFolder $script:AuditOutputFolder
                    $dbConnection.Close()
                    
                    Write-Host "SQLite database created: $dbPath" -ForegroundColor Green
                    Write-Host "Total rows imported: $importedRows" -ForegroundColor Green
                    Write-AuditLog "SQLite database created with $importedRows rows" -Level Success
                }
            }
            else {
                Write-AuditLog "SQLite library not found: $dbScript" -Level Warning
                Write-Host "Warning: SQLite library not found - database not created" -ForegroundColor Yellow
            }
        }
        catch {
            Write-AuditLog "Failed to create SQLite database: $_" -Level Warning
            Write-Host "Warning: SQLite database creation failed: $_" -ForegroundColor Yellow
        }
    }
    
    # Generate HTML reports
    Write-Host ""
    Write-Host "Generating HTML reports..." -ForegroundColor Cyan
    try {
        $reportScript = Join-Path $PSScriptRoot "Modules\New-AuditReport.ps1"
        if (Test-Path $reportScript) {
            & $reportScript -OutputFolder $script:AuditOutputFolder -CompanyName $CompanyName -ReportTitle $ReportTitle
            Write-AuditLog "HTML reports generated successfully" -Level Success
        }
        else {
            Write-AuditLog "Report generator not found: $reportScript" -Level Warning
        }
    }
    catch {
        Write-AuditLog "Failed to generate HTML reports: $_" -Level Warning
        Write-Host "Warning: HTML report generation failed" -ForegroundColor Yellow
    }
    
    # Send email notification (if configured)
    if ($NotificationEmail) {
        Write-Host ""
        Send-AuditNotification -ToEmail $NotificationEmail
    }
    
    Write-AuditLog "Audit completed successfully" -Level Success
}
catch {
    Write-AuditLog "Audit failed with critical error: $($_.Exception.Message)" -Level Error
    Write-AuditLog "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "   Audit Failed!" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check logs for details:" -ForegroundColor Yellow
    Write-Host "  Execution Log: $script:ExecutionLog" -ForegroundColor White
    Write-Host "  Error Log: $script:ErrorLog" -ForegroundColor White
    Write-Host ""
    
    exit 1
}

#endregion

