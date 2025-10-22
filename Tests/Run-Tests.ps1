<#
.SYNOPSIS
    Test runner for AD-Audit Pester tests

.DESCRIPTION
    Runs Pester tests for the AD-Audit module with proper configuration.
    Supports code coverage analysis and CI/CD integration.

.PARAMETER TestPath
    Path to test files (default: current directory)

.PARAMETER OutputFormat
    Output format for test results (NUnitXml, JUnitXml, or Console)

.PARAMETER CodeCoverage
    Enable code coverage analysis

.PARAMETER CI
    Run in CI/CD mode (stricter requirements, exit with error code on failure)

.EXAMPLE
    .\Run-Tests.ps1

.EXAMPLE
    .\Run-Tests.ps1 -CodeCoverage -OutputFormat NUnitXml

.EXAMPLE
    .\Run-Tests.ps1 -CI

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0
    Requires: Pester 5.x
#>

[CmdletBinding()]
param(
    [string]$TestPath = $PSScriptRoot,

    [ValidateSet('Console', 'NUnitXml', 'JUnitXml')]
    [string]$OutputFormat = 'Console',

    [switch]$CodeCoverage,

    [switch]$CI
)

# Check Pester version
$pesterModule = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if (-not $pesterModule) {
    Write-Host "Pester module not found. Installing Pester 5.x..." -ForegroundColor Yellow
    try {
        Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -Scope CurrentUser -SkipPublisherCheck
        Import-Module Pester -MinimumVersion 5.0.0
        Write-Host "Pester installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Pester: $_"
        exit 1
    }
}
elseif ($pesterModule.Version.Major -lt 5) {
    Write-Warning "Pester $($pesterModule.Version) found. Pester 5.x or higher is recommended."
    Write-Host "To upgrade: Install-Module -Name Pester -MinimumVersion 5.0.0 -Force" -ForegroundColor Yellow
}
else {
    Write-Host "Using Pester $($pesterModule.Version)" -ForegroundColor Green
    Import-Module Pester -MinimumVersion 5.0.0
}

# Configure Pester
$pesterConfig = New-PesterConfiguration

# Test discovery
$pesterConfig.Run.Path = $TestPath
$pesterConfig.Run.PassThru = $true

# Output configuration
if ($OutputFormat -ne 'Console') {
    $outputPath = Join-Path $TestPath "TestResults.$OutputFormat"
    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputPath = $outputPath
    $pesterConfig.TestResult.OutputFormat = $OutputFormat
}

# Code coverage configuration
if ($CodeCoverage) {
    $modulePath = Join-Path $TestPath '..' 'Modules' 'Invoke-AD-Audit.ps1'
    $pesterConfig.CodeCoverage.Enabled = $true
    $pesterConfig.CodeCoverage.Path = $modulePath
    $pesterConfig.CodeCoverage.OutputPath = Join-Path $TestPath 'coverage.xml'
    $pesterConfig.CodeCoverage.OutputFormat = 'JaCoCo'
}

# CI/CD mode configuration
if ($CI) {
    $pesterConfig.Run.Exit = $true
    $pesterConfig.Output.Verbosity = 'Detailed'
}
else {
    $pesterConfig.Output.Verbosity = 'Normal'
}

# Display configuration
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "  AD-Audit Test Runner" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test Path:     $TestPath"
Write-Host "Output Format: $OutputFormat"
Write-Host "Code Coverage: $($CodeCoverage.IsPresent)"
Write-Host "CI Mode:       $($CI.IsPresent)"
Write-Host ""

# Run tests
$startTime = Get-Date
$testResults = Invoke-Pester -Configuration $pesterConfig

# Display results summary
$duration = (Get-Date) - $startTime
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "  Test Results Summary" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Tests:   $($testResults.TotalCount)"
Write-Host "Passed:        $($testResults.PassedCount)" -ForegroundColor Green
Write-Host "Failed:        $($testResults.FailedCount)" -ForegroundColor $(if($testResults.FailedCount -gt 0){'Red'}else{'Green'})
Write-Host "Skipped:       $($testResults.SkippedCount)" -ForegroundColor Yellow
Write-Host "Duration:      $([math]::Round($duration.TotalSeconds, 2)) seconds"
Write-Host ""

# Code coverage summary
if ($CodeCoverage -and $testResults.CodeCoverage) {
    $coverage = $testResults.CodeCoverage
    $coveragePercent = if ($coverage.NumberOfCommandsAnalyzed -gt 0) {
        [math]::Round(($coverage.NumberOfCommandsExecuted / $coverage.NumberOfCommandsAnalyzed) * 100, 2)
    } else { 0 }

    Write-Host "Code Coverage:" -ForegroundColor Cyan
    Write-Host "  Commands Analyzed: $($coverage.NumberOfCommandsAnalyzed)"
    Write-Host "  Commands Executed: $($coverage.NumberOfCommandsExecuted)"
    Write-Host "  Coverage:          $coveragePercent%" -ForegroundColor $(if($coveragePercent -ge 80){'Green'}elseif($coveragePercent -ge 60){'Yellow'}else{'Red'})
    Write-Host ""
}

# Exit with appropriate code for CI/CD
if ($CI) {
    if ($testResults.FailedCount -gt 0) {
        Write-Host "Tests failed. Exiting with error code 1" -ForegroundColor Red
        exit 1
    }
    else {
        Write-Host "All tests passed!" -ForegroundColor Green
        exit 0
    }
}
else {
    if ($testResults.FailedCount -gt 0) {
        Write-Host "Some tests failed. Review the output above for details." -ForegroundColor Red
    }
    else {
        Write-Host "All tests passed!" -ForegroundColor Green
    }
}
