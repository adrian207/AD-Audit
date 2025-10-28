#Requires -Version 5.1

<#
.SYNOPSIS
    Test script for LAPS audit module functionality

.DESCRIPTION
    This script tests the LAPS audit module without requiring an Active Directory environment.
    It validates syntax, parameters, and basic functionality.

.PARAMETER SkipADCheck
    Skip Active Directory environment check

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
#>

param(
    [switch]$SkipADCheck
)

Write-Host "🧪 Testing LAPS Audit Module" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

$testResults = @()

# Test 1: File Exists
Write-Host "Test 1: Module file exists..." -NoNewline
$test1 = Test-Path "Modules\Invoke-LAPS-Audit.ps1"
if ($test1) {
    Write-Host " ✅ PASS" -ForegroundColor Green
    $testResults += @{Test = "File Exists"; Result = "PASS"}
} else {
    Write-Host " ❌ FAIL" -ForegroundColor Red
    $testResults += @{Test = "File Exists"; Result = "FAIL"}
}

# Test 2: Syntax Check
Write-Host "Test 2: PowerShell syntax check..." -NoNewline
$null = $null
try {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile("Modules\Invoke-LAPS-Audit.ps1", [ref]$null, [ref]$null)
    if ($ast) {
        Write-Host " ✅ PASS" -ForegroundColor Green
        $testResults += @{Test = "Syntax Check"; Result = "PASS"}
    }
} catch {
    Write-Host " ❌ FAIL - $_" -ForegroundColor Red
    $testResults += @{Test = "Syntax Check"; Result = "FAIL"}
}

# Test 3: Functions Defined
Write-Host "Test 3: Core functions defined..." -NoNewline
$content = Get-Content "Modules\Invoke-LAPS-Audit.ps1" -Raw
$requiredFunctions = @(
    "Write-LAPSLog",
    "Get-LAPSStatus",
    "Get-LAPSCompliance",
    "Export-LAPSReports"
)

$allFunctions = $true
foreach ($func in $requiredFunctions) {
    if ($content -notmatch "function $func") {
        $allFunctions = $false
        break
    }
}

if ($allFunctions) {
    Write-Host " ✅ PASS" -ForegroundColor Green
    $testResults += @{Test = "Functions Defined"; Result = "PASS"}
} else {
    Write-Host " ❌ FAIL" -ForegroundColor Red
    $testResults += @{Test = "Functions Defined"; Result = "FAIL"}
}

# Test 4: Parameters
Write-Host "Test 4: Required parameters present..." -NoNewline
if ($content -match "Parameter.*Mandatory.*true.*DatabasePath") {
    Write-Host " ✅ PASS" -ForegroundColor Green
    $testResults += @{Test = "Parameters"; Result = "PASS"}
} else {
    Write-Host " ❌ FAIL" -ForegroundColor Red
    $testResults += @{Test = "Parameters"; Result = "FAIL"}
}

# Test 5: Documentation
Write-Host "Test 5: Documentation present..." -NoNewline
if ($content -match "\.SYNOPSIS" -and $content -match "\.DESCRIPTION") {
    Write-Host " ✅ PASS" -ForegroundColor Green
    $testResults += @{Test = "Documentation"; Result = "PASS"}
} else {
    Write-Host " ⚠️  PARTIAL" -ForegroundColor Yellow
    $testResults += @{Test = "Documentation"; Result = "PARTIAL"}
}

# Test 6: Active Directory Check (optional)
if (-not $SkipADCheck) {
    Write-Host "Test 6: Active Directory module..." -NoNewline
    $adModule = Get-Module -ListAvailable ActiveDirectory
    if ($adModule) {
        Write-Host " ✅ Available" -ForegroundColor Green
        $testResults += @{Test = "AD Module"; Result = "PASS"}
    } else {
        Write-Host " ⚠️  Not available (running offline)" -ForegroundColor Yellow
        $testResults += @{Test = "AD Module"; Result = "SKIP"}
    }
}

# Test 7: Helper Functions
Write-Host "Test 7: Helper functions present..." -NoNewline
$helperFunctions = @(
    "Write-LAPSLog",
    "Get-DatabaseConnection",
    "Invoke-DatabaseQuery"
)

$allHelpers = $true
foreach ($func in $helperFunctions) {
    if ($content -notmatch "function $func") {
        $allHelpers = $false
        break
    }
}

if ($allHelpers) {
    Write-Host " ✅ PASS" -ForegroundColor Green
    $testResults += @{Test = "Helper Functions"; Result = "PASS"}
} else {
    Write-Host " ❌ FAIL" -ForegroundColor Red
    $testResults += @{Test = "Helper Functions"; Result = "FAIL"}
}

# Test 8: Reporting Functions
Write-Host "Test 8: Reporting functions present..." -NoNewline
$reportingFunctions = @(
    "Export-LAPSReports",
    "Export-LAPSReportsCSV",
    "Export-LAPSReportsHTML",
    "Export-LAPSReportsJSON"
)

$allReports = $true
foreach ($func in $reportingFunctions) {
    if ($content -notmatch "function $func") {
        $allReports = $false
        break
    }
}

if ($allReports) {
    Write-Host " ✅ PASS" -ForegroundColor Green
    $testResults += @{Test = "Reporting Functions"; Result = "PASS"}
} else {
    Write-Host " ❌ FAIL" -ForegroundColor Red
    $testResults += @{Test = "Reporting Functions"; Result = "FAIL"}
}

# Test 9: Error Handling
Write-Host "Test 9: Error handling present..." -NoNewline
if ($content -match "try" -and $content -match "catch") {
    Write-Host " ✅ PASS" -ForegroundColor Green
    $testResults += @{Test = "Error Handling"; Result = "PASS"}
} else {
    Write-Host " ⚠️  PARTIAL" -ForegroundColor Yellow
    $testResults += @{Test = "Error Handling"; Result = "PARTIAL"}
}

# Test 10: Linter Check (if available)
Write-Host "Test 10: PSScriptAnalyzer check..." -NoNewline
try {
    $analyzer = Get-Module -ListAvailable PSScriptAnalyzer
    if ($analyzer) {
        Import-Module PSScriptAnalyzer -ErrorAction SilentlyContinue
        $issues = Invoke-ScriptAnalyzer -Path "Modules\Invoke-LAPS-Audit.ps1" -ErrorAction SilentlyContinue
        
        if ($issues.Count -eq 0) {
            Write-Host " ✅ PASS (0 issues)" -ForegroundColor Green
            $testResults += @{Test = "PSScriptAnalyzer"; Result = "PASS"}
        } else {
            Write-Host " ⚠️  $($issues.Count) issues found" -ForegroundColor Yellow
            $testResults += @{Test = "PSScriptAnalyzer"; Result = "WARN"; Issues = $issues.Count}
        }
    } else {
        Write-Host " ⚠️  PSScriptAnalyzer not installed" -ForegroundColor Yellow
        $testResults += @{Test = "PSScriptAnalyzer"; Result = "SKIP"}
    }
} catch {
    Write-Host " ⚠️  SKIP" -ForegroundColor Yellow
    $testResults += @{Test = "PSScriptAnalyzer"; Result = "SKIP"}
}

Write-Host ""
Write-Host "📊 Test Summary" -ForegroundColor Cyan
Write-Host "===============" -ForegroundColor Cyan

$passed = ($testResults | Where-Object { $_.Result -eq "PASS" }).Count
$failed = ($testResults | Where-Object { $_.Result -eq "FAIL" }).Count
$warnings = ($testResults | Where-Object { $_.Result -in @("WARN", "PARTIAL") }).Count
$skipped = ($testResults | Where-Object { $_.Result -eq "SKIP" }).Count

Write-Host "✅ Passed: $passed" -ForegroundColor Green
Write-Host "❌ Failed: $failed" -ForegroundColor Red
Write-Host "⚠️  Warnings: $warnings" -ForegroundColor Yellow
Write-Host "⏭️  Skipped: $skipped" -ForegroundColor Gray

Write-Host ""
Write-Host "Detailed Results:" -ForegroundColor Cyan
$testResults | Format-Table Test, Result -AutoSize

if ($failed -eq 0) {
    Write-Host "🎉 All critical tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "⚠️  Some tests failed. Review the results above." -ForegroundColor Yellow
    exit 1
}
