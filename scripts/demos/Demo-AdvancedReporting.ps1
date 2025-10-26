<#
.SYNOPSIS
    Demonstration of SQLite-powered advanced reporting capabilities
    
.DESCRIPTION
    This script demonstrates how to use SQLite in-memory database
    to enable advanced cross-dataset reporting for M&A audits.
    
    Author: Adrian Johnson <adrian207@gmail.com>
    
.PARAMETER AuditFolder
    Path to existing audit output folder (must contain RawData with CSV files)
    
.EXAMPLE
    .\Demo-AdvancedReporting.ps1 -AuditFolder "C:\Audits\Contoso\20241021_153045_Contoso"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AuditFolder,
    
    [Parameter(Mandatory = $false)]
    [string]$CompanyName = "Demo Company"
)

#Requires -Version 5.1

# Script setup
$ErrorActionPreference = 'Stop'

Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   SQLite Advanced Reporting - Proof of Concept               ║
║   M&A Technical Discovery Tool                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "📊 This demonstration shows 3 advanced reports that are ONLY possible" -ForegroundColor Yellow
Write-Host "   with an in-memory database (impossible with CSV-only approach):`n" -ForegroundColor Yellow

Write-Host "   1. Privileged User Risk Analysis" -ForegroundColor White
Write-Host "      → Cross-references: PrivilegedAccounts → ServerLogon → SQLInstances → SQLDatabases" -ForegroundColor Gray
Write-Host "      → Identifies: Admin users accessing servers with backup issues`n" -ForegroundColor Gray

Write-Host "   2. Service Account Dependency Analysis" -ForegroundColor White
Write-Host "      → Cross-references: ServiceAccounts → ServerLogon → SQLLogins → SQLJobs" -ForegroundColor Gray
Write-Host "      → Identifies: Blast radius if service account disabled`n" -ForegroundColor Gray

Write-Host "   3. Migration Complexity Scoring" -ForegroundColor White
Write-Host "      → Cross-references: Servers → SQLDatabases → ServerLogon → Applications" -ForegroundColor Gray
Write-Host "      → Calculates: Dynamic risk score based on 10+ factors`n" -ForegroundColor Gray

Write-Host "════════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# Check for audit folder
if (-not $AuditFolder) {
    Write-Host "⚠️  No audit folder specified." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To use this demo:" -ForegroundColor Cyan
    Write-Host "  1. Run a full audit first:" -ForegroundColor White
    Write-Host "     .\Run-M&A-Audit.ps1 -CompanyName 'TestCo' -OutputFolder 'C:\Audits'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. Then run this demo:" -ForegroundColor White
    Write-Host "     .\Demo-AdvancedReporting.ps1 -AuditFolder 'C:\Audits\20241021_TestCo'" -ForegroundColor Gray
    Write-Host ""
    
    # Check if there's an existing audit in Output folder
    $outputPath = Join-Path $PSScriptRoot "Output"
    if (Test-Path $outputPath) {
        $recentAudits = Get-ChildItem -Path $outputPath -Directory | 
            Where-Object { $_.Name -match '^\d{8}_\d{6}_' } |
            Sort-Object Name -Descending |
            Select-Object -First 5
        
        if ($recentAudits) {
            Write-Host "📁 Found recent audits in Output folder:" -ForegroundColor Green
            $i = 1
            foreach ($audit in $recentAudits) {
                Write-Host "   $i. $($audit.Name)" -ForegroundColor White
                $i++
            }
            Write-Host ""
            
            $selection = Read-Host "Select audit number (1-$($recentAudits.Count)) or press Enter to exit"
            if ($selection -match '^\d+$' -and [int]$selection -le $recentAudits.Count -and [int]$selection -gt 0) {
                $AuditFolder = $recentAudits[[int]$selection - 1].FullName
                Write-Host "✅ Using: $AuditFolder`n" -ForegroundColor Green
            } else {
                exit 0
            }
        } else {
            exit 0
        }
    } else {
        exit 0
    }
}

# Validate audit folder
if (-not (Test-Path $AuditFolder)) {
    Write-Host "❌ Audit folder not found: $AuditFolder" -ForegroundColor Red
    exit 1
}

$rawDataPath = Join-Path $AuditFolder "RawData"
if (-not (Test-Path $rawDataPath)) {
    Write-Host "❌ RawData folder not found in audit folder" -ForegroundColor Red
    exit 1
}

# Check for required CSV files
$requiredFiles = @(
    "AD\AD_Users.csv",
    "AD\AD_PrivilegedAccounts.csv",
    "SQL\SQL_Databases.csv"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $rawDataPath $file
    if (-not (Test-Path $filePath)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "⚠️  Some required CSV files are missing:" -ForegroundColor Yellow
    foreach ($file in $missingFiles) {
        Write-Host "   - $file" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "The demo will continue but some reports may be incomplete." -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 2
}

# Check for SQLite
Write-Host "🔍 Checking SQLite availability..." -ForegroundColor Cyan

$sqliteAvailable = $false
try {
    Add-Type -AssemblyName "System.Data.SQLite" -ErrorAction Stop
    $sqliteAvailable = $true
    Write-Host "✅ SQLite loaded from GAC" -ForegroundColor Green
}
catch {
    $sqliteDll = Join-Path $PSScriptRoot "Libraries\System.Data.SQLite.dll"
    if (Test-Path $sqliteDll) {
        try {
            Add-Type -Path $sqliteDll
            $sqliteAvailable = $true
            Write-Host "✅ SQLite loaded from Libraries folder" -ForegroundColor Green
        }
        catch {
            Write-Host "⚠️  SQLite DLL found but failed to load: $_" -ForegroundColor Yellow
        }
    }
}

if (-not $sqliteAvailable) {
    Write-Host ""
    Write-Host "❌ SQLite not available. Installing from NuGet..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   To install SQLite manually:" -ForegroundColor Cyan
    Write-Host "   1. Download: https://system.data.sqlite.org/downloads/" -ForegroundColor White
    Write-Host "   2. Or run: Install-Package System.Data.SQLite.Core" -ForegroundColor White
    Write-Host ""
    Write-Host "   For this demo, we'll try to install automatically..." -ForegroundColor Gray
    Write-Host ""
    
    try {
        # Try to install via NuGet
        $nugetPath = Join-Path $env:TEMP "nuget.exe"
        if (-not (Test-Path $nugetPath)) {
            Write-Host "   Downloading NuGet.exe..." -ForegroundColor Gray
            Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $nugetPath
        }
        
        Write-Host "   Installing System.Data.SQLite..." -ForegroundColor Gray
        & $nugetPath install System.Data.SQLite.Core -OutputDirectory (Join-Path $PSScriptRoot "packages") -NonInteractive
        
        # Find the DLL
        $sqliteDll = Get-ChildItem -Path (Join-Path $PSScriptRoot "packages") -Filter "System.Data.SQLite.dll" -Recurse | 
            Where-Object { $_.FullName -match "net\d+" } | 
            Select-Object -First 1 -ExpandProperty FullName
        
        if ($sqliteDll -and (Test-Path $sqliteDll)) {
            Add-Type -Path $sqliteDll
            $sqliteAvailable = $true
            Write-Host "✅ SQLite installed and loaded successfully" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "❌ Failed to install SQLite automatically: $_" -ForegroundColor Red
    }
}

if (-not $sqliteAvailable) {
    Write-Host ""
    Write-Host "⚠️  DEMO MODE: Running without SQLite (showing concept only)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The advanced reports require SQLite. Here's what you would get:`n" -ForegroundColor White
    
    Write-Host "Report 1: Privileged User Risk Analysis" -ForegroundColor Cyan
    Write-Host "  • Identifies privileged users accessing at-risk SQL servers" -ForegroundColor Gray
    Write-Host "  • Shows stale admin accounts still in privileged groups" -ForegroundColor Gray
    Write-Host "  • Cross-references 4 data sources (impossible with CSV only)`n" -ForegroundColor Gray
    
    Write-Host "Report 2: Service Account Dependency Analysis" -ForegroundColor Cyan
    Write-Host "  • Maps service account impact across servers and SQL" -ForegroundColor Gray
    Write-Host "  • Calculates blast radius for each service account" -ForegroundColor Gray
    Write-Host "  • Shows CRITICAL/HIGH/MEDIUM/LOW impact ratings`n" -ForegroundColor Gray
    
    Write-Host "Report 3: Migration Complexity Scoring" -ForegroundColor Cyan
    Write-Host "  • Dynamic scoring based on 10+ factors per server" -ForegroundColor Gray
    Write-Host "  • Combines: VM status, DBs, users, apps, storage, dependencies" -ForegroundColor Gray
    Write-Host "  • Prioritizes migration planning efforts`n" -ForegroundColor Gray
    
    Write-Host "To see actual reports, install SQLite and re-run this demo.`n" -ForegroundColor Yellow
    
    Read-Host "Press Enter to exit"
    exit 0
}

# Extract company name from folder if not provided
if ($CompanyName -eq "Demo Company") {
    if ($AuditFolder -match '_([^_]+)$') {
        $CompanyName = $Matches[1]
    }
}

Write-Host ""
Write-Host "🚀 Starting advanced report generation..." -ForegroundColor Green
Write-Host "   Company: $CompanyName" -ForegroundColor White
Write-Host "   Data Source: $rawDataPath" -ForegroundColor White
Write-Host ""

# Run the advanced reporting script
$reportScript = Join-Path $PSScriptRoot "Modules\New-AdvancedAuditReports.ps1"

if (-not (Test-Path $reportScript)) {
    Write-Host "❌ Advanced reporting script not found: $reportScript" -ForegroundColor Red
    exit 1
}

try {
    & $reportScript -OutputFolder $rawDataPath -CompanyName $CompanyName
    
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                                                               ║" -ForegroundColor Green
    Write-Host "║   ✅ SUCCESS! Advanced Reports Generated                      ║" -ForegroundColor Green
    Write-Host "║                                                               ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "📊 Reports should open in your browser automatically." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "💡 Key Observations:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Traditional CSV Approach:" -ForegroundColor White
    Write-Host "   • Each report reads and re-parses CSV files" -ForegroundColor Gray
    Write-Host "   • Cross-dataset analysis requires complex PowerShell loops" -ForegroundColor Gray
    Write-Host "   • Performance degrades with large datasets" -ForegroundColor Gray
    Write-Host "   • Difficult to add new cross-domain queries" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "   SQLite Database Approach:" -ForegroundColor White
    Write-Host "   • Import once, query instantly" -ForegroundColor Gray
    Write-Host "   • Complex joins handled by SQL engine" -ForegroundColor Gray
    Write-Host "   • Scales to millions of rows" -ForegroundColor Gray
    Write-Host "   • Easy to add new reports (just write SQL)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "📁 Database Location:" -ForegroundColor Cyan
    Write-Host "   $(Join-Path $rawDataPath 'audit.db')" -ForegroundColor White
    Write-Host ""
    Write-Host "   You can query this database directly using:" -ForegroundColor Gray
    Write-Host "   • DB Browser for SQLite (https://sqlitebrowser.org/)" -ForegroundColor Gray
    Write-Host "   • PowerShell with Invoke-AuditQuery function" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "❌ Error generating reports: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    exit 1
}

Write-Host "Press Enter to exit..." -ForegroundColor Cyan
Read-Host

