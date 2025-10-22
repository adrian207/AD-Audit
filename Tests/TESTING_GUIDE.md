# Testing Guide - Quick Start

## 🚀 5-Minute Quick Start

### 1. Install Pester

```powershell
Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser
```

### 2. Run All Tests

```powershell
cd C:\Users\<YourUser>\OneDrive\Documents\GitHub\Ad-Audit\AD-Audit\Tests
.\RunTests.ps1
```

### 3. View Results

You'll see output like:

```
============================================
   Ad-Audit Pester Test Suite
============================================

Pester Version: 5.6.0
Test Path: C:\...\Tests\*.Tests.ps1

Starting test execution...

Running tests from 'SQLite-AuditDB.Tests.ps1'
  [+] Initialize-AuditDatabase 250ms
  [+] Import-CSVToTable 180ms
  [+] Invoke-AuditQuery 95ms
  ...

============================================
   Test Results Summary
============================================

Duration:        45.23 seconds
Total Tests:     87
Passed:          87
Failed:          0
Skipped:         0

✓ ALL TESTS PASSED
```

## 📋 Common Test Commands

### Run specific test file

```powershell
.\RunTests.ps1 -TestPath ".\SQLite-AuditDB.Tests.ps1"
```

### Run with code coverage

```powershell
.\RunTests.ps1 -CodeCoverage
```

### Run only integration tests

```powershell
.\RunTests.ps1 -Tag "Integration"
```

### Run excluding slow tests

```powershell
.\RunTests.ps1 -ExcludeTag "Performance"
```

## 🎯 What's Being Tested

### ✅ Currently Tested Components

- **SQLite Database Operations** (`SQLite-AuditDB.Tests.ps1`)
  - Database initialization (in-memory and file-based)
  - CSV data import with type conversion
  - SQL query execution with parameters
  - Multi-table imports from audit CSV files
  - Error handling and edge cases

- **Active Directory Audit** (`Invoke-AD-Audit.Tests.ps1`)
  - Forest and domain information collection
  - User, computer, and group inventory
  - Privileged account detection
  - GPO inventory and analysis
  - Service account detection
  - Server hardware inventory
  - Virtualization detection

- **Cloud Services** (`CloudModules.Tests.ps1`)
  - Microsoft Entra ID (Azure AD) users, groups, apps
  - Exchange Online mailboxes and statistics
  - SharePoint Online sites
  - Microsoft Teams
  - Power Platform apps and flows

- **Integration Tests** (`Integration.Tests.ps1`)
  - End-to-end database workflows
  - Multi-table data relationships
  - Complex analytical queries
  - Performance with large datasets (10,000+ records)

### 📊 Test Coverage Summary

| Component | Tests | Coverage |
|-----------|-------|----------|
| SQLite Library | 25+ | High |
| AD Audit Functions | 30+ | Medium-High |
| Cloud Modules | 25+ | Medium |
| Integration Workflows | 10+ | Medium |
| **Total** | **90+** | **~75%** |

## 🔍 Understanding Test Results

### Passed Test ✓

```
[+] Should create an in-memory database connection 45ms
```

- **[+]** = Test passed
- **45ms** = Execution time

### Failed Test ✗

```
[-] Should handle connection failures gracefully 120ms
    Expected: 'Connection failed'
    But was: 'Timeout'
```

- **[-]** = Test failed
- Shows expected vs actual values

### Skipped Test ⊘

```
[!] Performance test with 100k records (Skipped)
```

- **[!]** = Test skipped (usually due to tags or conditions)

## 🛠️ Troubleshooting

### "Pester module not found"

```powershell
# Install Pester
Install-Module Pester -Force -SkipPublisherCheck

# Or update existing
Update-Module Pester
```

### "Tests fail with mocking errors"

This is expected for tests that mock AD/Cloud services. The tests use mocks to simulate these services without requiring actual connections.

### "Cannot find path"

Make sure you're in the correct directory:

```powershell
cd C:\Users\<YourUser>\OneDrive\Documents\GitHub\Ad-Audit\AD-Audit\Tests
```

### "SQLite DLL not found"

For SQLite tests, the DLL should be in `Libraries\System.Data.SQLite.dll`. If missing:

```powershell
cd ..\
.\Install-SQLite-Simple.ps1
```

## 📈 Code Coverage

### What is Code Coverage?

Code coverage shows what percentage of your code is executed by tests. Higher coverage = more confidence.

### View Coverage

```powershell
.\RunTests.ps1 -CodeCoverage
```

Output:

```
Code Coverage:
  Commands Analyzed:  1,234
  Commands Executed:  925
  Coverage:           75.0%

Coverage report saved: coverage.xml
```

### Coverage Targets

- **80%+** = Excellent (high confidence)
- **60-80%** = Good (acceptable)
- **<60%** = Needs improvement

## 🎨 Writing Your First Test

Create `MyFunction.Tests.ps1`:

```powershell
BeforeAll {
    # Load your script
    . "$PSScriptRoot\..\Libraries\MyScript.ps1"
}

Describe "My-Function" {
    It "Should return expected value" {
        # Act
        $result = My-Function -Input "test"
        
        # Assert
        $result | Should -Be "test-processed"
    }
}
```

Run it:

```powershell
.\RunTests.ps1 -TestPath ".\MyFunction.Tests.ps1"
```

## 📚 Test Categories

### Unit Tests
- Test individual functions in isolation
- Fast execution (milliseconds)
- Mock all external dependencies
- **Tag**: None or `Unit`

### Integration Tests
- Test complete workflows
- Moderate execution time (seconds)
- May use real database (in-memory)
- **Tag**: `Integration`

### Performance Tests
- Test with large datasets
- Slow execution (minutes)
- Verify efficiency and scalability
- **Tag**: `Performance`

## 🔄 CI/CD Integration

### Azure DevOps

```yaml
- task: PowerShell@2
  inputs:
    filePath: 'AD-Audit/Tests/RunTests.ps1'
    arguments: '-OutputFormat NUnitXml'
```

### GitHub Actions

```yaml
- name: Run Tests
  run: |
    cd AD-Audit/Tests
    ./RunTests.ps1 -OutputFormat JUnitXml
```

## ❓ FAQ

**Q: Do I need to run tests before every commit?**  
A: Recommended, especially if you modified code. Quick test: `.\RunTests.ps1`

**Q: Can I run tests without Active Directory?**  
A: Yes! All AD/Cloud dependencies are mocked. Tests run on any machine.

**Q: How long do tests take?**  
A: Unit tests: ~30 seconds, All tests: ~1-2 minutes, With coverage: ~2-3 minutes

**Q: What if a test fails?**  
A: Read the error message carefully. It shows what was expected vs what happened. Fix your code or update the test if requirements changed.

**Q: Should I write tests for my changes?**  
A: Yes! New features should include tests. See "Writing Your First Test" above.

## 🎯 Next Steps

1. ✅ Run all tests: `.\RunTests.ps1`
2. ✅ Review test output and ensure all pass
3. ✅ Run with coverage: `.\RunTests.ps1 -CodeCoverage`
4. ✅ Review `README.md` for detailed documentation
5. ✅ Write tests for new features you add

## 📞 Support

- **Documentation**: See `README.md` for detailed info
- **Pester Docs**: https://pester.dev/
- **Issues**: Review test error messages carefully - they show exactly what failed

---

Happy Testing! 🚀

**Pro Tip**: Bind `.\RunTests.ps1` to a keyboard shortcut in VS Code for instant testing!

