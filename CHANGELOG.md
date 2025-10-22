# Changelog

All notable changes to the AD-Audit PowerShell module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI/CD pipeline
- Comprehensive documentation
- Contributing guidelines
- Issue templates
- Security scanning

## [3.0.0] - 2025-01-XX

### Added
- **9 Comprehensive Security Modules**: Complete Active Directory security auditing based on Microsoft's official best practices
- **Master Orchestration**: Unified execution across all modules with priority-based processing
- **Microsoft Compliance**: 100% coverage of Microsoft AD Security Best Practices, AD FS Operations, Events to Monitor Appendix L, AD DS Auditing Step-by-Step Guide
- **Advanced Event Monitoring**: High/medium/low criticality events with old/new value tracking
- **SACL Analysis**: System Access Control List configuration analysis
- **Schema Auditing Configuration**: Schema attribute auditing analysis

#### Security Modules
- **Credential Theft Prevention** (`Invoke-CredentialTheftPrevention.ps1`): Permanently privileged account detection, VIP account protection, privileged account usage monitoring
- **Domain Controller Security** (`Invoke-DomainControllerSecurity.ps1`): DC hardening verification, physical security assessment, application allowlist verification
- **Least Privilege Assessment** (`Invoke-LeastPrivilegeAssessment.ps1`): RBAC analysis, privilege escalation detection, cross-system privilege analysis
- **Legacy System Management** (`Invoke-LegacySystemManagement.ps1`): Legacy system identification, isolation verification, decommissioning planning
- **Advanced Threat Detection** (`Invoke-AdvancedThreatDetection.ps1`): Advanced audit policy verification, compromise indicators, lateral movement detection
- **AD FS Security Audit** (`Invoke-ADFSSecurityAudit.ps1`): Service configuration analysis, authentication configuration, authorization configuration
- **Event Monitoring** (`Invoke-EventMonitoring.ps1`): High criticality events (9 types), medium criticality events (100+ types), low criticality events (13 types)
- **AD DS Auditing** (`Invoke-ADDSAuditing.ps1`): Directory service access/changes/replication events with old/new value tracking

#### Remediation Modules
- **AD Remediation** (`Invoke-ADRemediation.ps1`): Active Directory security remediation
- **Server Remediation** (`Invoke-ServerRemediation.ps1`): Server security remediation
- **M365 Remediation** (`Invoke-M365Remediation.ps1`): Microsoft 365 security remediation
- **Master Remediation** (`Invoke-MasterRemediation.ps1`): Unified remediation orchestration

### Changed
- **Module Version**: Updated to 3.0.0
- **Module Description**: Updated to reflect comprehensive Active Directory security focus
- **Function Exports**: Added all new security and remediation functions
- **Tags**: Updated tags to reflect security focus
- **Release Notes**: Comprehensive release notes for version 3.0.0

### Technical Features
- **Dry-Run Mode**: Preview mode for safe testing
- **Parallel Processing**: Multi-threaded execution for large environments
- **Comprehensive Reporting**: HTML reports, CSV exports, executive dashboards
- **Email Notifications**: Automated alerts and reports
- **SQLite Database Integration**: Advanced queries and trend analysis
- **Error Handling**: Robust error handling and graceful degradation

### Documentation
- Comprehensive module-specific documentation for all 9 security modules
- Microsoft compliance guides and implementation documentation
- Complete usage examples and integration guidance
- Troubleshooting guides and best practices

### Testing & Quality
- Comprehensive Pester tests with high coverage
- Zero linter errors across all modules
- Comprehensive error handling and recovery
- CI/CD integration (GitHub Actions, Azure DevOps)

## [2.3.0] - 2025-10-22

### Added
- **Advanced Analytics Engine**: Baseline comparison, trend analysis, anomaly detection
- **Risk Scoring System**: Comprehensive 0-100 security risk score
- **Executive Dashboards**: Beautiful HTML reports with risk gauges and interactive charts
- **Alert System**: Email notifications for threshold breaches (SMTP integration)
- **Query Builder Enhancements**: 20 templates (was 8), saved queries, query history, dark mode, Chart.js visualization

### Analytics Capabilities
- Baseline vs Current comparison (7 entity types tracked)
- 7 anomaly types (privileged accounts, Kerberos, ACLs, databases, servers)
- Risk levels: Low/Medium/High/Critical with color-coding
- Trend analysis across multiple audits
- Configurable alert thresholds

### Dashboard Features
- Animated risk gauge (circular, color-coded)
- Interactive metric cards with change indicators
- Anomaly cards with severity badges
- Executive summary section
- Responsive design (mobile-friendly, print-optimized)
- Professional gradients and animations

### Alert System
- 6 alert types with configurable thresholds
- HTML-formatted email notifications
- SMTP support (Office 365, Gmail, Exchange)
- Actionable recommendations

### Query Builder v2.2
- 20 pre-built query templates (12 new)
- Saved queries with descriptions
- Query history (last 100 executions)
- Chart visualization (Bar, Line, Pie)
- Dark mode with localStorage persistence
- Advanced filters (IN, BETWEEN operators)

### Security Enhancements (v2.1)
- ACL analysis (dangerous permissions detection)
- Kerberos delegation audit (unconstrained/constrained)
- DHCP scope inventory
- GPO comprehensive inventory
- Service account security analysis
- AD trust relationships audit
- Password policy analysis (default + fine-grained)
- DNS zone inventory
- Certificate Services audit

### Documentation
- Analytics Guide (550+ lines)
- Query Builder Enhancements Guide (500+ lines)
- AD Security Components Guide
- Complete PowerShell Gallery publishing guide

### Testing & Quality
- 118+ Pester tests (~78% coverage)
- Zero linter errors
- Comprehensive error handling
- CI/CD integration (GitHub Actions + Azure DevOps)

### Technical Details
- 3 new analytics modules (~1,700 lines)
- Start-M&A-Analytics.ps1 orchestrator (360 lines)
- Risk scoring with 7 factors
- Anomaly detection with 7 types
- JSON/CSV/HTML output formats

## [2.2.0] - 2025-09-15

### Added
- **Query Builder Web Interface**: Web-based query builder with 8 pre-built templates
- **Advanced Reporting**: Enhanced reporting capabilities
- **SQLite Integration**: SQLite database integration for advanced queries
- **Visual Query Builder**: GUI-based query builder with templates

### Query Builder Features
- 8 pre-built query templates
- Visual query building interface
- Template management
- Query execution and results display
- Export capabilities

### Reporting Enhancements
- Advanced audit reports
- Executive dashboards
- HTML report generation
- CSV export functionality

### Database Integration
- SQLite database support
- Advanced query capabilities
- Data import/export
- Database management utilities

## [2.1.0] - 2025-08-20

### Added
- **Security Components**: Advanced Active Directory security auditing
- **ACL Analysis**: Dangerous permissions detection
- **Kerberos Delegation Audit**: Unconstrained/constrained delegation analysis
- **DHCP Scope Inventory**: DHCP configuration auditing
- **GPO Comprehensive Inventory**: Group Policy Object analysis
- **Service Account Security**: Service account security analysis
- **AD Trust Relationships**: Trust relationship auditing
- **Password Policy Analysis**: Default and fine-grained password policy analysis
- **DNS Zone Inventory**: DNS zone configuration auditing
- **Certificate Services Audit**: Certificate Services auditing

### Security Enhancements
- Comprehensive ACL analysis
- Kerberos delegation auditing
- Service account security analysis
- Trust relationship auditing
- Password policy analysis
- Certificate Services auditing

### Documentation
- AD Security Components Guide
- Security auditing documentation
- Best practices documentation

## [2.0.0] - 2025-07-10

### Added
- **M&A Technical Discovery**: Comprehensive merger and acquisition due diligence tool
- **Active Directory Audit**: 9 advanced security components
- **Server Hardware Inventory**: CPU, memory, storage, virtualization, applications
- **SQL Server Discovery**: Instances, databases, backups, logins, jobs, security
- **Microsoft 365 Audit**: Entra ID, Exchange, SharePoint, Teams, Power Platform
- **Compliance Audit**: DLP, retention, sensitivity labels, eDiscovery

### Core Features
- Active Directory comprehensive audit
- Server hardware inventory
- SQL Server discovery
- Microsoft 365 audit
- Compliance audit
- Advanced reporting
- Executive dashboards

### Technical Implementation
- PowerShell-based implementation
- SQLite database integration
- Enterprise encryption support
- Comprehensive testing framework
- CI/CD integration

## [1.0.0] - 2025-06-01

### Added
- **Initial Release**: Basic Active Directory auditing capabilities
- **Core Audit Functions**: Basic AD user, group, and computer auditing
- **Basic Reporting**: Simple CSV and HTML report generation
- **Documentation**: Initial documentation and user guide

### Core Features
- Basic Active Directory auditing
- User account analysis
- Group membership analysis
- Computer account analysis
- Basic reporting capabilities

### Technical Implementation
- PowerShell module structure
- Basic error handling
- Simple reporting
- Initial documentation

---

## Version History Summary

| Version | Date | Major Features |
|---------|------|----------------|
| 3.0.0 | 2025-01-XX | Comprehensive AD Security Auditing (9 modules) |
| 2.3.0 | 2025-10-22 | Advanced Analytics & Reporting |
| 2.2.0 | 2025-09-15 | Query Builder Web Interface |
| 2.1.0 | 2025-08-20 | Security Components |
| 2.0.0 | 2025-07-10 | M&A Technical Discovery |
| 1.0.0 | 2025-06-01 | Initial Release |

## Breaking Changes

### Version 3.0.0
- **Module Focus**: Changed from M&A focus to comprehensive AD security auditing
- **Function Names**: Updated function names to reflect security focus
- **Module Structure**: Reorganized module structure for security modules

### Version 2.0.0
- **Module Scope**: Expanded from basic AD auditing to comprehensive M&A tool
- **Database Schema**: Updated database schema for new features
- **Reporting Format**: Changed reporting format for enhanced capabilities

## Migration Guide

### Upgrading to Version 3.0.0
1. **Backup Existing Data**: Backup existing audit databases and reports
2. **Update Module**: Install new version using `Install-Module -Name AD-Audit -Force`
3. **Update Scripts**: Update any custom scripts to use new function names
4. **Test Configuration**: Test new security modules in a test environment
5. **Update Documentation**: Review new documentation for updated features

### Upgrading to Version 2.0.0
1. **Backup Existing Data**: Backup existing audit databases and reports
2. **Update Module**: Install new version using `Install-Module -Name AD-Audit -Force`
3. **Update Database**: Run database migration scripts if available
4. **Test New Features**: Test new M&A features in a test environment
5. **Update Documentation**: Review new documentation for updated features

## Support

For questions about version upgrades or migration, please:
- Check the [Documentation](docs/)
- Create an [Issue](https://github.com/yourusername/AD-Audit/issues)
- Contact the maintainer: adrian207@gmail.com

---

**Note**: This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format and [Semantic Versioning](https://semver.org/spec/v2.0.0.html) principles.
