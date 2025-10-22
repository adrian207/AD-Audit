# Ad-Audit Pester Test Suite

Comprehensive testing framework for the Ad-Audit PowerShell project using Pester 5.x.

## Table of Contents

- [Overview](#overview)
- [Benefits](#benefits)
- [Prerequisites](#prerequisites)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Writing New Tests](#writing-new-tests)
- [Continuous Integration](#continuous-integration)
- [Troubleshooting](#troubleshooting)

## Overview

This testing framework provides:

- **Unit Tests**: Test individual functions in isolation with mocked dependencies
- **Integration Tests**: Test complete workflows and data pipelines
- **Performance Tests**: Verify efficiency with large datasets
- **Code Coverage**: Track which lines of code are tested

## Benefits

### Why You Need Both Framework and Tests

The testing framework and test files work together as a complete system:

1. **Framework Components** (`RunTests.ps1`, `PesterConfiguration.psd1`):
   - Provides consistent test execution environment
   - Configures code coverage analysis
   - Generates standardized reports
   - Enables CI/CD integration
   - Manages test discovery and filtering

2. **Test Files** (`*.Tests.ps1`):
   - Contain actual test cases for your code
   - Define expected behavior and assertions
   - Catch bugs before production
   - Document how code should work
   - Enable safe refactoring

### Key Benefits:

✅ **Early Bug Detection**: Find issues before they reach production  
✅ **Regression Prevention**: Ensure fixes don't break existing functionality  
✅ **Code Confidence**: Refactor with safety net  
✅ **Living Documentation**: Tests document expected behavior  
✅ **Quality Metrics**: Track code coverage and test pass rates  
✅ **CI/CD Ready**: Automated testing in pipelines  

## Prerequisites

### Install Pester

```powershell
# Install Pester 5.x (recommended)
Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser

# Verify installation
Get-Module Pester -ListAvailable
```

### Verify Version

Pester 5.x or higher is required for this test suite.

```powershell
Import-Module Pester
$Pester = Get-Module Pester
Write-Host "Pester Version: $($Pester.Version)"
```

## Test Structure

```
AD-Audit/
├── Tests/
│   ├── SQLite-AuditDB.Tests.ps1      # SQLite library unit tests
│   ├── Invoke-AD-Audit.Tests.ps1     # AD audit module unit tests
│   ├── Integration.Tests.ps1          # End-to-end integration tests
│   ├── RunTests.ps1                   # Test runner script
│   ├── PesterConfiguration.psd1       # Pester configuration
│   └── README.md                      # This file
├── Libraries/
│   └── SQLite-AuditDB.ps1
├── Modules/
│   ├── Invoke-AD-Audit.ps1
│   ├── Invoke-Exchange-Audit.ps1
│   └── ...
```

## Running Tests

### Run All Tests

```powershell
cd AD-Audit\Tests
.\RunTests.ps1
```

### Run Specific Test File

```powershell
.\RunTests.ps1 -TestPath ".\SQLite-AuditDB.Tests.ps1"
```

### Run with Code Coverage

```powershell
.\RunTests.ps1 -CodeCoverage
```

### Run Tests with Specific Tags

```powershell
# Run only integration tests
.\RunTests.ps1 -Tag "Integration"

# Run only unit tests (exclude integration)
.\RunTests.ps1 -ExcludeTag "Integration"

# Run performance tests
.\RunTests.ps1 -Tag "Performance"
```

### Export Test Results

```powershell
# NUnit format (for CI/CD)
.\RunTests.ps1 -OutputFormat NUnitXml

# JUnit format
.\RunTests.ps1 -OutputFormat JUnitXml
```

## Test Coverage

### Current Coverage

The test suite includes:

- **SQLite-AuditDB.Tests.ps1**: 
  - `Initialize-AuditDatabase` function (in-memory and file-based)
  - `Import-CSVToTable` function (data import, type conversion, UPSERT)
  - `Invoke-AuditQuery` function (queries, parameters, aggregations)
  - `Import-AuditCSVsToDatabase` function (CSV import workflow)
  - Edge cases and error handling

- **Invoke-AD-Audit.Tests.ps1**:
  - Helper functions (`Write-ModuleLog`, `Test-ServerOnline`)
  - Forest and domain information collection
  - User, computer, and group inventory
  - Privileged account detection
  - GPO inventory
  - Service account detection
  - Server hardware inventory
  - Virtualization detection

- **Integration.Tests.ps1**:
  - End-to-end database workflow
  - Multi-table relationships
  - Complex analytical queries
  - Error handling and edge cases
  - Performance tests with large datasets

### View Coverage Report

After running with `-CodeCoverage`:

```powershell
.\RunTests.ps1 -CodeCoverage
```

Coverage report saved to: `Tests/coverage.xml`

View in PowerShell:

```powershell
$coverage = [xml](Get-Content .\coverage.xml)
$coverage.report.counter | Format-Table
```

## Writing New Tests

### Test File Naming Convention

- **Unit Tests**: `<ModuleName>.Tests.ps1`
- **Integration Tests**: `Integration.Tests.ps1` or `<Feature>.Integration.Tests.ps1`

### Basic Test Structure

```powershell
BeforeAll {
    # Import module or script under test
    . "$PSScriptRoot\..\Libraries\MyScript.ps1"
    
    # Setup mocks and test data
    Mock Get-ADUser { return @() }
}

Describe "Function Name" {
    Context "Specific Scenario" {
        It "Should do something expected" {
            # Arrange
            $input = "test"
            
            # Act
            $result = My-Function -Parameter $input
            
            # Assert
            $result | Should -Be "expected"
        }
    }
}
```

### Common Assertions

```powershell
# Equality
$value | Should -Be "expected"
$value | Should -Not -Be "unexpected"

# Type checking
$object | Should -BeOfType [string]

# Null checks
$value | Should -BeNullOrEmpty
$value | Should -Not -BeNullOrEmpty

# Collections
$array.Count | Should -Be 5
$array | Should -Contain "item"

# Exceptions
{ My-Function -BadParam } | Should -Throw

# Comparison
$number | Should -BeGreaterThan 10
$number | Should -BeLessThan 100
```

### Using Mocks

```powershell
# Basic mock
Mock Get-ADUser { return @() }

# Mock with specific return value
Mock Get-ADComputer {
    return [PSCustomObject]@{
        Name = "TESTPC"
        OperatingSystem = "Windows 10"
    }
}

# Mock with parameter filter
Mock Export-Csv { } -ParameterFilter {
    $Path -like "*AD_Users.csv"
}

# Verify mock was called
Mock Export-Csv { } -Verifiable
My-Function
Should -InvokeVerifiable
```

### Using TestDrive

```powershell
BeforeAll {
    # TestDrive:\ is automatically cleaned up after tests
    $testFile = Join-Path $TestDrive "test.csv"
}

It "Should create file" {
    "data" | Out-File $testFile
    Test-Path $testFile | Should -Be $true
}
```

## Continuous Integration

### Azure DevOps

```yaml
# azure-pipelines.yml
steps:
- task: PowerShell@2
  displayName: 'Run Pester Tests'
  inputs:
    targetType: 'filePath'
    filePath: '$(System.DefaultWorkingDirectory)/AD-Audit/Tests/RunTests.ps1'
    arguments: '-OutputFormat NUnitXml -CodeCoverage'
    
- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'NUnit'
    testResultsFiles: '**/TestResults.xml'
    
- task: PublishCodeCoverageResults@1
  inputs:
    codeCoverageTool: 'JaCoCo'
    summaryFileLocation: '**/coverage.xml'
```

### GitHub Actions

```yaml
# .github/workflows/test.yml
name: Pester Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install Pester
        shell: pwsh
        run: Install-Module -Name Pester -Force -SkipPublisherCheck
        
      - name: Run Tests
        shell: pwsh
        run: |
          cd AD-Audit/Tests
          ./RunTests.ps1 -OutputFormat NUnitXml -CodeCoverage
          
      - name: Publish Test Results
        uses: EnricoMi/publish-unit-test-result-action@v1
        if: always()
        with:
          files: AD-Audit/Tests/TestResults/*.xml
```

## Troubleshooting

### Pester Version Conflicts

If you see version conflicts:

```powershell
# Remove old versions
Get-Module Pester -ListAvailable | Where-Object Version -lt 5.0.0 | Uninstall-Module -Force

# Install latest
Install-Module Pester -Force -SkipPublisherCheck
```

### Tests Fail with "Module Not Found"

Ensure paths are correct:

```powershell
# Check relative paths in test files
$PSScriptRoot                          # Current test file directory
Join-Path $PSScriptRoot "..\Libraries" # Libraries directory
```

### Mock Not Working

Ensure mocks are in `BeforeAll` or `BeforeEach` blocks:

```powershell
BeforeAll {
    Mock Get-ADUser { return @() }  # ✓ Correct
}

# Don't place mocks outside blocks
Mock Get-ADUser { return @() }  # ✗ Won't work
```

### Test Isolation Issues

Use `BeforeEach` and `AfterEach` for cleanup:

```powershell
BeforeEach {
    # Setup before each test
    $script:TestVar = "initial"
}

AfterEach {
    # Cleanup after each test
    Remove-Variable TestVar -Scope Script -ErrorAction SilentlyContinue
}
```

## Best Practices

1. **Test Independence**: Each test should be independent and not rely on others
2. **Clear Test Names**: Use descriptive names that explain what's being tested
3. **Arrange-Act-Assert**: Structure tests clearly (setup, execute, verify)
4. **Mock External Dependencies**: Don't call real AD, databases, or APIs
5. **Test Edge Cases**: Test boundary conditions, null values, empty arrays
6. **Use Tags**: Tag tests for selective execution (Unit, Integration, Performance)
7. **Keep Tests Fast**: Unit tests should execute in milliseconds
8. **Test One Thing**: Each test should verify one specific behavior
9. **Avoid Test Logic**: Tests should be simple and easy to understand
10. **Clean Up Resources**: Close connections, delete temp files

## Additional Resources

- [Pester Documentation](https://pester.dev/)
- [Pester GitHub](https://github.com/pester/Pester)
- [PowerShell Testing Best Practices](https://pester.dev/docs/usage/test-file-structure)

## Support

For issues with tests, please:

1. Check this README first
2. Review test file comments
3. Check Pester documentation
4. Open an issue with details (error message, Pester version, PowerShell version)

---

**Author**: Adrian Johnson  
**Project**: Ad-Audit  
**Test Framework Version**: 1.0

