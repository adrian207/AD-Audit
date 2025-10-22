# Contributing to AD-Audit

Thank you for your interest in contributing to the AD-Audit PowerShell module! We welcome contributions from the community and appreciate your help in making this project better.

## 🚀 **Getting Started**

### **Prerequisites**
- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core)
- **Git** for version control
- **Pester** for testing
- **PSScriptAnalyzer** for code analysis
- **Active Directory Module** (`RSAT-AD-PowerShell`)

### **Development Setup**
```powershell
# Clone the repository
git clone https://github.com/yourusername/AD-Audit.git
cd AD-Audit

# Install development dependencies
Install-Module -Name Pester -Force -SkipPublisherCheck
Install-Module -Name PSScriptAnalyzer -Force -SkipPublisherCheck

# Import the module for testing
Import-Module .\AD-Audit.psd1 -Force
```

## 📋 **Contribution Guidelines**

### **Code Standards**
- **PowerShell Best Practices**: Follow PowerShell best practices and conventions
- **Approved Verbs**: Use only approved PowerShell verbs (Get, Set, New, Remove, etc.)
- **Error Handling**: Include comprehensive error handling with try-catch blocks
- **Documentation**: Document all functions with proper comment-based help
- **Testing**: Write Pester tests for new functionality
- **Linting**: Ensure code passes PSScriptAnalyzer without errors or warnings

### **Function Naming Conventions**
```powershell
# Good examples
Get-ADUserSecurity
Set-PasswordPolicy
New-AuditReport
Remove-StaleAccounts

# Bad examples
Get-ADUserSec  # Too abbreviated
Set-PassPol    # Too abbreviated
New-Report     # Too generic
Remove-Stale   # Incomplete
```

### **Code Style**
```powershell
# Use proper indentation (4 spaces)
function Get-ExampleFunction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parameter1,
        
        [Parameter(Mandatory = $false)]
        [int]$Parameter2 = 30
    )
    
    try {
        # Function implementation
        Write-Verbose "Processing parameter: $Parameter1"
        
        # Return results
        return $results
    }
    catch {
        Write-Error "Function failed: $_"
        throw
    }
}
```

## 🧪 **Testing Requirements**

### **Pester Tests**
All new functionality must include comprehensive Pester tests:

```powershell
# Example test structure
Describe "Get-ExampleFunction" {
    Context "When called with valid parameters" {
        It "Should return expected results" {
            # Arrange
            $testInput = "test value"
            
            # Act
            $result = Get-ExampleFunction -Parameter1 $testInput
            
            # Assert
            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -BeGreaterThan 0
        }
    }
    
    Context "When called with invalid parameters" {
        It "Should throw an error" {
            # Arrange
            $invalidInput = $null
            
            # Act & Assert
            { Get-ExampleFunction -Parameter1 $invalidInput } | Should -Throw
        }
    }
}
```

### **Test Coverage**
- **Minimum Coverage**: 80% code coverage
- **Critical Functions**: 100% coverage for security-critical functions
- **Edge Cases**: Test edge cases and error conditions
- **Integration Tests**: Include integration tests for complex workflows

## 📝 **Documentation Requirements**

### **Comment-Based Help**
All functions must include comprehensive comment-based help:

```powershell
<#
.SYNOPSIS
    Brief description of the function

.DESCRIPTION
    Detailed description of what the function does, including examples
    and any important notes about usage or behavior.

.PARAMETER Parameter1
    Description of the parameter, including type and requirements

.PARAMETER Parameter2
    Description of the parameter, including default values

.EXAMPLE
    Get-ExampleFunction -Parameter1 "test value"
    Description of what this example demonstrates

.EXAMPLE
    Get-ExampleFunction -Parameter1 "test value" -Parameter2 60
    Description of what this example demonstrates

.NOTES
    Author: Your Name <your.email@example.com>
    Version: 1.0.0
    Requires: PowerShell 5.1+, Active Directory Module
#>
```

### **Documentation Files**
- **README.md**: Update with new features and examples
- **Module Documentation**: Update module-specific documentation
- **Changelog**: Document changes in CHANGELOG.md

## 🔄 **Pull Request Process**

### **Before Submitting**
1. **Fork the repository** and create a feature branch
2. **Write tests** for your new functionality
3. **Run tests** to ensure they pass
4. **Run PSScriptAnalyzer** to check for issues
5. **Update documentation** as needed
6. **Test your changes** in a real environment

### **Pull Request Template**
```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] PSScriptAnalyzer passes without errors

## Checklist
- [ ] Code follows PowerShell best practices
- [ ] Functions include comment-based help
- [ ] Tests cover new functionality
- [ ] Documentation updated
- [ ] No sensitive information included
```

### **Review Process**
1. **Automated Checks**: CI/CD pipeline runs tests and linting
2. **Code Review**: Maintainers review code quality and functionality
3. **Testing**: Changes are tested in various environments
4. **Approval**: Changes are approved and merged

## 🐛 **Bug Reports**

### **Before Reporting**
1. **Check existing issues** to avoid duplicates
2. **Test with latest version** to ensure issue persists
3. **Gather information** about your environment

### **Bug Report Template**
```markdown
## Bug Description
Clear description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What you expected to happen

## Actual Behavior
What actually happened

## Environment
- PowerShell Version: 
- OS Version: 
- Module Version: 
- Active Directory Version: 

## Additional Context
Any additional information that might be helpful
```

## 💡 **Feature Requests**

### **Feature Request Template**
```markdown
## Feature Description
Clear description of the requested feature

## Use Case
Why is this feature needed? What problem does it solve?

## Proposed Solution
How would you like this feature to work?

## Alternatives Considered
What other solutions have you considered?

## Additional Context
Any additional information that might be helpful
```

## 🔒 **Security Considerations**

### **Security Guidelines**
- **No Hardcoded Credentials**: Never include hardcoded passwords or API keys
- **Input Validation**: Validate all input parameters
- **Error Handling**: Don't expose sensitive information in error messages
- **Least Privilege**: Use least privilege principles in code
- **Secure Coding**: Follow secure coding practices

### **Security Reporting**
For security vulnerabilities, please email security@example.com instead of creating a public issue.

## 📚 **Resources**

### **PowerShell Resources**
- [PowerShell Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/dev-cross-plat/writing-portable-modules)
- [Pester Testing](https://pester.dev/)
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer)
- [PowerShell Gallery](https://www.powershellgallery.com/)

### **Active Directory Resources**
- [Microsoft AD Security Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [AD FS Operations](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-operations)
- [Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [AD DS Auditing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc731607(v=ws.10))

## 🤝 **Community Guidelines**

### **Code of Conduct**
- **Be Respectful**: Treat everyone with respect and kindness
- **Be Constructive**: Provide constructive feedback and suggestions
- **Be Patient**: Be patient with newcomers and learning processes
- **Be Professional**: Maintain a professional tone in all interactions

### **Getting Help**
- **GitHub Issues**: Use GitHub issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and general discussion
- **Email**: Contact maintainers directly for sensitive issues

## 📞 **Contact**

- **Maintainer**: Adrian Johnson <adrian207@gmail.com>
- **GitHub**: [@yourusername](https://github.com/yourusername)
- **Issues**: [GitHub Issues](https://github.com/yourusername/AD-Audit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/AD-Audit/discussions)

## 🙏 **Acknowledgments**

Thank you to all contributors who have helped make this project better! Your contributions are greatly appreciated.

---

**Happy Contributing! 🚀**
