# Security Policy

> Executive summary: Report vulnerabilities privately and responsibly; we target fast triage and timely fixes for supported versions.
>
> Key recommendations:
> - Do not open public issues for security findings
> - Email the maintainer with version, environment, impact, and steps
> - Use PGP if available; expect initial response within 48 hours
>
> Supporting points:
> - Supported version matrix included
> - Clear information checklist for reporters
> - Target resolution timeline documented

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in the AD-Audit PowerShell module, please follow these steps:

### 1. **DO NOT** create a public GitHub issue
Security vulnerabilities should be reported privately to prevent exploitation.

### 2. Contact Information
- **Email**: adrian207@gmail.com
- **Subject**: [SECURITY] AD-Audit Vulnerability Report
- **Encryption**: Use PGP if available (key available upon request)

### 3. Information to Include
Please provide the following information in your report:

- **Version**: Which version of AD-Audit is affected
- **Environment**: Operating system, PowerShell version, domain environment
- **Description**: Detailed description of the vulnerability
- **Impact**: Potential impact and attack vectors
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Mitigation**: Any workarounds or mitigations you've identified

### 4. Response Timeline
- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution**: Target resolution within 30 days

### 5. Security Best Practices

#### For Users
- Always run AD-Audit with least privilege principles
- Use encrypted output options for sensitive data
- Regularly update to the latest version
- Review audit results in a secure environment
- Implement proper access controls on audit data

#### For Developers
- Follow PowerShell security best practices
- Use PSScriptAnalyzer security rules
- Implement proper error handling
- Avoid hardcoded credentials
- Use secure coding practices

### 6. Security Features

The AD-Audit module includes several security features:

- **Encrypted Output**: Support for EFS, 7-Zip, and Azure Key Vault encryption
- **Credential Protection**: Secure credential handling and storage
- **Least Privilege**: Functions designed to run with minimal required permissions
- **Audit Trail**: Comprehensive logging and audit metadata
- **Input Validation**: Proper input validation and sanitization

### 7. Security Scanning

We regularly perform security scans on the codebase:

- **Static Analysis**: PSScriptAnalyzer with security rules
- **Dependency Scanning**: Regular dependency vulnerability checks
- **Code Review**: Manual security code reviews
- **Penetration Testing**: Regular security testing

### 8. Security Updates

Security updates are released as:
- **Critical**: Immediate patch release
- **High**: Next minor version release
- **Medium/Low**: Next major version release

### 9. Responsible Disclosure

We follow responsible disclosure practices:
- Vulnerabilities are kept private until patched
- Credit is given to security researchers
- Coordinated disclosure with affected parties
- Clear communication about fixes and mitigations

### 10. Security Contact

For security-related questions or concerns:
- **Email**: adrian207@gmail.com
- **Response Time**: Within 24 hours for security inquiries

---

**Note**: This security policy is subject to change. Please check back regularly for updates.
