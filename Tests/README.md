# AD-Audit Tests

Comprehensive Pester tests for the AD-Audit PowerShell module.

## Prerequisites

- PowerShell 5.1 or PowerShell 7+
- Pester 5.x (will be auto-installed if missing)

## Quick Start

### Run All Tests

```powershell
cd Tests
.\Run-Tests.ps1
```

### Run Tests with Code Coverage

```powershell
.\Run-Tests.ps1 -CodeCoverage
```

### Run Tests in CI/CD Mode

```powershell
.\Run-Tests.ps1 -CI
```

This will exit with error code 1 if any tests fail (useful for build pipelines).

### Export Results to NUnit XML

```powershell
.\Run-Tests.ps1 -OutputFormat NUnitXml
```

## Test Coverage

### Current Test Suites

1. **Helper Functions Tests**
   - `Test-ServerOnline` - Server connectivity testing
   - `Write-ModuleLog` - Logging functionality
   - `Invoke-WithRetry` - Retry logic with exponential backoff

2. **Retry Logic Integration Tests**
   - CIM session retry behavior
   - WinEvent query retry behavior
   - Remote PowerShell (Invoke-Command) retry behavior

3. **Edge Cases and Boundary Conditions**
   - Null/empty input handling
   - Boundary value testing (MaxAttempts = 1, InitialDelay = 0)
   - Error classification (retryable vs non-retryable)

4. **Code Quality Tests**
   - Module structure validation
   - PowerShell best practices (approved verbs)
   - Documentation completeness

## Test Structure

```
Tests/
├── Invoke-AD-Audit.Tests.ps1   # Main test suite
├── Run-Tests.ps1                # Test runner script
└── README.md                    # This file
```

## Writing New Tests

### Test Naming Convention

```powershell
Describe 'FunctionName' {
    Context 'When condition' {
        It 'Should expected behavior' {
            # Arrange
            $input = 'test'

            # Act
            $result = SomeFunction -Parameter $input

            # Assert
            $result | Should -Be 'expected'
        }
    }
}
```

### Best Practices

1. **Use descriptive test names** - Test names should clearly describe what's being tested
2. **Follow AAA pattern** - Arrange, Act, Assert
3. **Test one thing per test** - Each `It` block should verify one specific behavior
4. **Use BeforeAll/BeforeEach** - Setup test data and mocks properly
5. **Mock external dependencies** - Don't rely on actual AD, network, or servers

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Pester Tests
        shell: pwsh
        run: |
          cd Tests
          .\Run-Tests.ps1 -CI -CodeCoverage -OutputFormat NUnitXml

      - name: Publish Test Results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: Tests/TestResults.NUnitXml
```

### Azure DevOps Example

```yaml
steps:
- task: PowerShell@2
  displayName: 'Run Pester Tests'
  inputs:
    targetType: 'filePath'
    filePath: '$(System.DefaultWorkingDirectory)/Tests/Run-Tests.ps1'
    arguments: '-CI -CodeCoverage -OutputFormat NUnitXml'

- task: PublishTestResults@2
  displayName: 'Publish Test Results'
  condition: always()
  inputs:
    testResultsFormat: 'NUnit'
    testResultsFiles: '**/TestResults.NUnitXml'
    failTaskOnFailedTests: true
```

## Test Results Interpretation

### Success Example

```
================================
  Test Results Summary
================================

Total Tests:   45
Passed:        45
Failed:        0
Skipped:       0
Duration:      3.42 seconds

Code Coverage:
  Commands Analyzed: 245
  Commands Executed: 198
  Coverage:          80.82%

All tests passed!
```

### Failure Example

```
================================
  Test Results Summary
================================

Total Tests:   45
Passed:        43
Failed:        2
Skipped:       0
Duration:      3.87 seconds

Some tests failed. Review the output above for details.
```

## Troubleshooting

### Issue: Pester not found

**Solution:** Run `Install-Module -Name Pester -MinimumVersion 5.0.0 -Force`

### Issue: Tests fail with "Module not found"

**Solution:** Ensure you're running from the `Tests` directory:
```powershell
cd /path/to/AD-Audit/Tests
.\Run-Tests.ps1
```

### Issue: Import errors

**Solution:** Check that `Invoke-AD-Audit.ps1` exists in `../Modules/` relative to the Tests directory.

## Contributing

When adding new features to the main module:

1. Write tests first (TDD approach recommended)
2. Ensure tests pass locally
3. Aim for >80% code coverage on new code
4. Update this README if adding new test suites

## Resources

- [Pester Documentation](https://pester.dev/)
- [PowerShell Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/strongly-encouraged-development-guidelines)
- [Mocking in Pester](https://pester.dev/docs/usage/mocking)
