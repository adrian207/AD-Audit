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
    [switch]$SkipEncryption
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
            Write-AuditLog "7-Zip not found. Install from: https://www.7-zip.org/" -Level Warning
            Write-AuditLog "Archive creation skipped" -Level Warning
        }
    }
    
    # Method 3: Azure Key Vault (future implementation)
    if ($UseAzureKeyVault) {
        Write-AuditLog "Azure Key Vault encryption not yet implemented" -Level Warning
        Write-AuditLog "This feature is planned for a future release" -Level Info
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
        # Placeholder for cloud modules (to be implemented)
        Write-AuditLog "Cloud modules (Entra ID, Exchange, SharePoint, Teams, Power Platform, Compliance) pending implementation" -Level Warning
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

