<#
.SYNOPSIS
    Test runner script for Ad-Audit Pester tests
    
.DESCRIPTION
    Executes all Pester tests for the Ad-Audit project with coverage reporting
    
.PARAMETER TestPath
    Path to specific test file or folder (default: all tests in Tests folder)
    
.PARAMETER OutputFormat
    Output format: Console, NUnitXml, JUnitXml (default: Console)
    
.PARAMETER CodeCoverage
    Enable code coverage analysis
    
.PARAMETER Tag
    Run only tests with specific tags
    
.PARAMETER ExcludeTag
    Exclude tests with specific tags
    
.EXAMPLE
    .\RunTests.ps1
    
.EXAMPLE
    .\RunTests.ps1 -CodeCoverage
    
.EXAMPLE
    .\RunTests.ps1 -TestPath ".\SQLite-AuditDB.Tests.ps1"
    
.EXAMPLE
    .\RunTests.ps1 -Tag "Integration"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TestPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Console', 'NUnitXml', 'JUnitXml')]
    [string]$OutputFormat = 'Console',
    
    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage,
    
    [Parameter(Mandatory = $false)]
    [string[]]$Tag,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeTag,
    
    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

#Requires -Modules Pester

$ErrorActionPreference = 'Stop'

# Banner
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Ad-Audit Pester Test Suite" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check Pester version
$pesterVersion = (Get-Module Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version

Write-Host "Pester Version: $pesterVersion" -ForegroundColor Yellow

$isPester5 = $pesterVersion.Major -ge 5

if (-not $isPester5) {
    Write-Warning "Pester 5.x or higher is recommended. Current version: $pesterVersion"
    Write-Host "To upgrade: Install-Module Pester -Force -SkipPublisherCheck" -ForegroundColor Cyan
    Write-Host "Using Pester 3.x compatibility mode" -ForegroundColor Yellow
    Write-Host ""
}

# Determine test path
if ([string]::IsNullOrWhiteSpace($TestPath)) {
    $TestPath = $PSScriptRoot
}

# For Pester 5.x, we can use directory paths directly
# For Pester 3.x, we need to specify individual files
if ($isPester5) {
    # Pester 5.x can handle directory paths with *.Tests.ps1 pattern
    if (-not (Test-Path $TestPath)) {
        Write-Error "Test path not found: $TestPath"
        exit 1
    }
} else {
    # Pester 3.x needs individual file paths
    if ($TestPath -match '\*') {
        $TestPath = Get-ChildItem -Path $TestPath -File | Select-Object -ExpandProperty FullName
    } else {
        $TestPath = Resolve-Path $TestPath -ErrorAction SilentlyContinue
    }
    
    if (-not $TestPath -or $TestPath.Count -eq 0) {
        Write-Error "Test path not found: $TestPath"
        exit 1
    }
    
    # Ensure TestPath is an array
    if ($TestPath -is [string]) {
        $TestPath = @($TestPath)
    }
}

Write-Host "Test Path: $TestPath" -ForegroundColor Cyan
Write-Host ""

# Build Pester configuration based on version
if ($isPester5) {
    # Pester 5.x configuration
    $config = New-PesterConfiguration

    # Test discovery
    $config.Run.Path = $TestPath
    $config.Run.PassThru = $true

    # Output configuration
    $config.Output.Verbosity = 'Detailed'

    # Filter configuration
    if ($Tag) {
        $config.Filter.Tag = $Tag
        Write-Host "Running tests with tags: $($Tag -join ', ')" -ForegroundColor Yellow
    }

    if ($ExcludeTag) {
        $config.Filter.ExcludeTag = $ExcludeTag
        Write-Host "Excluding tests with tags: $($ExcludeTag -join ', ')" -ForegroundColor Yellow
    }

    # Code coverage configuration
    if ($CodeCoverage) {
        Write-Host "Code coverage enabled" -ForegroundColor Yellow
        
        $modulePath = Join-Path $PSScriptRoot ".."
        $coveragePaths = @(
            Join-Path $modulePath "Libraries\*.ps1"
            Join-Path $modulePath "Modules\*.ps1"
        )
        
        $config.CodeCoverage.Enabled = $true
        $config.CodeCoverage.Path = $coveragePaths
        $config.CodeCoverage.OutputFormat = 'JaCoCo'
        $config.CodeCoverage.OutputPath = Join-Path $PSScriptRoot "coverage.xml"
    }

    # Output format configuration
    $outputPath = Join-Path $PSScriptRoot "TestResults"
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    }

    switch ($OutputFormat) {
        'NUnitXml' {
            $config.TestResult.Enabled = $true
            $config.TestResult.OutputFormat = 'NUnitXml'
            $config.TestResult.OutputPath = Join-Path $outputPath "TestResults.xml"
            Write-Host "Output: NUnit XML - $($config.TestResult.OutputPath)" -ForegroundColor Yellow
        }
        'JUnitXml' {
            $config.TestResult.Enabled = $true
            $config.TestResult.OutputFormat = 'JUnitXml'
            $config.TestResult.OutputPath = Join-Path $outputPath "TestResults.xml"
            Write-Host "Output: JUnit XML - $($config.TestResult.OutputPath)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Starting test execution..." -ForegroundColor Green
    Write-Host ""

    # Execute tests
    $startTime = Get-Date
    $result = Invoke-Pester -Configuration $config
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
} else {
    # Pester 3.x configuration
    $pesterParams = @{
        Path = $TestPath
        PassThru = $true
        Verbose = $true
    }

    # Add tags if specified
    if ($Tag) {
        $pesterParams.Tag = $Tag
        Write-Host "Running tests with tags: $($Tag -join ', ')" -ForegroundColor Yellow
    }

    if ($ExcludeTag) {
        $pesterParams.ExcludeTag = $ExcludeTag
        Write-Host "Excluding tests with tags: $($ExcludeTag -join ', ')" -ForegroundColor Yellow
    }

    # Code coverage configuration for Pester 3.x
    if ($CodeCoverage) {
        Write-Host "Code coverage enabled" -ForegroundColor Yellow
        
        $modulePath = Join-Path $PSScriptRoot ".."
        $coveragePaths = @(
            Join-Path $modulePath "Libraries\*.ps1"
            Join-Path $modulePath "Modules\*.ps1"
        )
        
        $pesterParams.CodeCoverage = $coveragePaths
        $pesterParams.CodeCoverageOutputFile = Join-Path $PSScriptRoot "coverage.xml"
        $pesterParams.CodeCoverageOutputFileFormat = 'JaCoCo'
    }

    # Output format configuration for Pester 3.x
    $outputPath = Join-Path $PSScriptRoot "TestResults"
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    }

    switch ($OutputFormat) {
        'NUnitXml' {
            $pesterParams.OutputFile = Join-Path $outputPath "TestResults.xml"
            $pesterParams.OutputFormat = 'NUnitXml'
            Write-Host "Output: NUnit XML - $($pesterParams.OutputFile)" -ForegroundColor Yellow
        }
        'JUnitXml' {
            $pesterParams.OutputFile = Join-Path $outputPath "TestResults.xml"
            $pesterParams.OutputFormat = 'JUnitXml'
            Write-Host "Output: JUnit XML - $($pesterParams.OutputFile)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Starting test execution..." -ForegroundColor Green
    Write-Host ""

    # Execute tests
    $startTime = Get-Date
    $result = Invoke-Pester @pesterParams
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
}

# Display results
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Test Results Summary" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Duration:        $([math]::Round($duration, 2)) seconds" -ForegroundColor White
Write-Host "Total Tests:     $($result.TotalCount)" -ForegroundColor White
Write-Host "Passed:          $($result.PassedCount)" -ForegroundColor Green
Write-Host "Failed:          $($result.FailedCount)" -ForegroundColor $(if($result.FailedCount -gt 0){'Red'}else{'Green'})
Write-Host "Skipped:         $($result.SkippedCount)" -ForegroundColor Yellow
Write-Host "Not Run:         $($result.NotRunCount)" -ForegroundColor Gray
Write-Host ""

# Display code coverage
if ($CodeCoverage) {
    if ($isPester5 -and $result.CodeCoverage) {
        $coverage = $result.CodeCoverage
        $coveragePercent = if ($coverage.NumberOfCommandsAnalyzed -gt 0) {
            [math]::Round(($coverage.NumberOfCommandsExecuted / $coverage.NumberOfCommandsAnalyzed) * 100, 2)
        } else {
            0
        }
        
        $coverageColor = if ($coveragePercent -ge 80) { 'Green' } 
                         elseif ($coveragePercent -ge 60) { 'Yellow' }
                         else { 'Red' }
        
        Write-Host "Code Coverage:" -ForegroundColor Cyan
        Write-Host "  Commands Analyzed:  $($coverage.NumberOfCommandsAnalyzed)" -ForegroundColor White
        Write-Host "  Commands Executed:  $($coverage.NumberOfCommandsExecuted)" -ForegroundColor White
        Write-Host "  Coverage:           $coveragePercent%" -ForegroundColor $coverageColor
        Write-Host ""
        
        if ($coverage.MissedCommands.Count -gt 0) {
            Write-Host "Missed Commands (showing first 10):" -ForegroundColor Yellow
            $coverage.MissedCommands | Select-Object -First 10 | ForEach-Object {
                Write-Host "  $($_.File):$($_.Line) - $($_.Function)" -ForegroundColor Gray
            }
            Write-Host ""
        }
        
        Write-Host "Coverage report saved: $($config.CodeCoverage.OutputPath)" -ForegroundColor Cyan
        Write-Host ""
    } elseif (-not $isPester5 -and $result.CodeCoverage) {
        # Pester 3.x coverage handling
        $coverage = $result.CodeCoverage
        $coveragePercent = if ($coverage.NumberOfCommandsAnalyzed -gt 0) {
            [math]::Round(($coverage.NumberOfCommandsExecuted / $coverage.NumberOfCommandsAnalyzed) * 100, 2)
        } else {
            0
        }
        
        $coverageColor = if ($coveragePercent -ge 80) { 'Green' } 
                         elseif ($coveragePercent -ge 60) { 'Yellow' }
                         else { 'Red' }
        
        Write-Host "Code Coverage:" -ForegroundColor Cyan
        Write-Host "  Commands Analyzed:  $($coverage.NumberOfCommandsAnalyzed)" -ForegroundColor White
        Write-Host "  Commands Executed:  $($coverage.NumberOfCommandsExecuted)" -ForegroundColor White
        Write-Host "  Coverage:           $coveragePercent%" -ForegroundColor $coverageColor
        Write-Host ""
        
        Write-Host "Coverage report saved: $($pesterParams.CodeCoverageOutputFile)" -ForegroundColor Cyan
        Write-Host ""
    }
}

# Display failed tests
if ($result.FailedCount -gt 0) {
    Write-Host "Failed Tests:" -ForegroundColor Red
    Write-Host ""
    
    foreach ($test in $result.Failed) {
        Write-Host "  × $($test.Path) > $($test.Name)" -ForegroundColor Red
        Write-Host "    $($test.ErrorRecord.Exception.Message)" -ForegroundColor Gray
        Write-Host ""
    }
}

# Overall result
Write-Host ""
if ($result.FailedCount -eq 0) {
    Write-Host "✓ ALL TESTS PASSED" -ForegroundColor Green -BackgroundColor Black
    $exitCode = 0
} else {
    Write-Host "✗ TESTS FAILED" -ForegroundColor Red -BackgroundColor Black
    $exitCode = 1
}
Write-Host ""

# Return result if PassThru
if ($PassThru) {
    return $result
}

# Exit with appropriate code
exit $exitCode

