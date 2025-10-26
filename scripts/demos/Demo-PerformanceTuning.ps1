# AD Performance Tuning Demo Script

<#
.SYNOPSIS
    Demonstrates the new Microsoft AD Performance Tuning features in AD-Audit v2.1.0

.DESCRIPTION
    This script showcases the performance optimizations and capacity planning features
    implemented based on Microsoft's AD performance tuning guidelines.

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 2.1.0
    Requires: AD-Audit module, ActiveDirectory module
#>

param(
    [string]$OutputFolder = "C:\ADAudit\PerformanceDemo",
    [switch]$PerformanceOnly,
    [switch]$SkipServerInventory
)

Write-Host "=== AD-Audit Performance Tuning Demo ===" -ForegroundColor Cyan
Write-Host "Version: 2.1.0" -ForegroundColor Yellow
Write-Host "Author: Adrian Johnson" -ForegroundColor Yellow
Write-Host ""

# Create output folder
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    Write-Host "Created output folder: $OutputFolder" -ForegroundColor Green
}

Write-Host "=== Performance Optimizations Implemented ===" -ForegroundColor Cyan
Write-Host "1. LDAP Query Optimization - Only request required properties" -ForegroundColor White
Write-Host "2. Capacity Planning Analysis - Object count thresholds" -ForegroundColor White
Write-Host "3. Server-Side Tuning Recommendations - Hardware and configuration" -ForegroundColor White
Write-Host "4. Client/Application Optimization - Parallel processing" -ForegroundColor White
Write-Host "5. Performance Monitoring - Metrics and recommendations" -ForegroundColor White
Write-Host ""

# Import the AD-Audit module
Write-Host "Importing AD-Audit module..." -ForegroundColor Yellow
try {
    Import-Module "$PSScriptRoot\Modules\Invoke-AD-Audit.ps1" -Force
    Write-Host "Module imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "Failed to import module: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Running Performance Analysis ===" -ForegroundColor Cyan

# Run performance analysis
try {
    if ($PerformanceOnly) {
        Write-Host "Running performance analysis only..." -ForegroundColor Yellow
        Invoke-AD-Audit -PerformanceAnalysisOnly -OutputFolder $OutputFolder
    }
    else {
        Write-Host "Running full audit with performance analysis..." -ForegroundColor Yellow
        
        $params = @{
            OutputFolder = $OutputFolder
            MaxParallelServers = 5  # Conservative for demo
            ServerQueryTimeout = 300
            SkipOfflineServers = $true
        }
        
        if ($SkipServerInventory) {
            $params.SkipEventLogs = $true
            $params.SkipLogonHistory = $true
            $params.SkipSQL = $true
        }
        
        Invoke-AD-Audit @params
    }
    
    Write-Host ""
    Write-Host "=== Performance Analysis Complete ===" -ForegroundColor Green
    Write-Host "Check the following files in $OutputFolder:" -ForegroundColor White
    Write-Host "  - AD_Performance_CapacityPlanning.csv" -ForegroundColor Cyan
    Write-Host "  - AD_Performance_ServerTuning.csv" -ForegroundColor Cyan
    Write-Host "  - AD_Performance_ClientOptimization.csv" -ForegroundColor Cyan
    Write-Host "  - AD_Performance_Metrics.csv" -ForegroundColor Cyan
    Write-Host "  - AD_Performance_Recommendations.csv" -ForegroundColor Cyan
    Write-Host ""
    
    # Display key recommendations
    $recommendationsFile = Join-Path $OutputFolder "AD_Performance_Recommendations.csv"
    if (Test-Path $recommendationsFile) {
        Write-Host "=== Key Performance Recommendations ===" -ForegroundColor Cyan
        $recommendations = Import-Csv $recommendationsFile
        foreach ($rec in $recommendations) {
            Write-Host "  [$($rec.Priority)] $($rec.Recommendation)" -ForegroundColor White
            Write-Host "    Impact: $($rec.Impact)" -ForegroundColor Gray
            Write-Host "    Effort: $($rec.Effort)" -ForegroundColor Gray
            Write-Host ""
        }
    }
    
    # Display capacity planning results
    $capacityFile = Join-Path $OutputFolder "AD_Performance_CapacityPlanning.csv"
    if (Test-Path $capacityFile) {
        Write-Host "=== Capacity Planning Analysis ===" -ForegroundColor Cyan
        $capacity = Import-Csv $capacityFile
        foreach ($item in $capacity) {
            $color = if ($item.Severity -eq "High") { "Red" } 
                    elseif ($item.Severity -eq "Medium") { "Yellow" } 
                    else { "Green" }
            Write-Host "  $($item.Metric): $($item.Value) - $($item.Recommendation)" -ForegroundColor $color
        }
        Write-Host ""
    }
    
}
catch {
    Write-Host "Performance analysis failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "=== Demo Complete ===" -ForegroundColor Green
Write-Host "Performance tuning features successfully demonstrated!" -ForegroundColor Green
Write-Host ""
Write-Host "For more information, see:" -ForegroundColor White
Write-Host "  - docs/AD_PERFORMANCE_TUNING_GUIDE.md" -ForegroundColor Cyan
Write-Host "  - Microsoft AD Performance Tuning Guidelines" -ForegroundColor Cyan
Write-Host "    https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/active-directory-server/" -ForegroundColor Cyan
