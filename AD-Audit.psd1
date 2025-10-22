@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'Run-M&A-Audit.ps1'

    # Version number of this module.
    ModuleVersion = '2.3.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = '8f4e3d2c-1a5b-4c9e-8f3d-2a1b5c9e8f3d'

    # Author of this module
    Author = 'Adrian Johnson'

    # Company or vendor of this module
    CompanyName = 'Unknown'

    # Copyright statement for this module
    Copyright = '(c) 2025 Adrian Johnson. All rights reserved.'

    # Description of the functionality provided by this module
    Description = @'
M&A Technical Discovery Audit Tool - Comprehensive PowerShell-based auditing solution for merger and acquisition due diligence with advanced analytics and reporting.

Key Features:
- Active Directory comprehensive audit (9 advanced security components: ACL, Kerberos, DHCP, GPO, DNS, Certs, etc.)
- Server hardware inventory (CPU, memory, storage, virtualization, applications)
- SQL Server discovery (instances, databases, backups, logins, jobs, security)
- Microsoft 365 audit (Entra ID, Exchange, SharePoint, Teams, Power Platform)
- Compliance audit (DLP, retention, sensitivity labels, eDiscovery)
- Advanced Analytics Engine (baseline comparison, anomaly detection, risk scoring)
- Executive Dashboards (beautiful HTML reports with risk gauges and charts)
- Alert System (email notifications for threshold breaches)
- Visual Query Builder (web-based with 20+ templates, saved queries, dark mode)
- SQLite database integration for advanced queries and trend analysis
- Enterprise encryption (EFS, 7-Zip, Azure Key Vault)
- Comprehensive testing (118+ tests, ~78% coverage)
- CI/CD integration (GitHub Actions, Azure DevOps)

Designed for IT consultants, M&A teams, security analysts, and technical due diligence professionals.
'@

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    DotNetFrameworkVersion = '4.7.2'

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # ClrVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{ModuleName='ActiveDirectory'; ModuleVersion='1.0.0.0'; GUID='43c15630-959c-49e4-a977-758c5cc93408'}
    )

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'Modules\Invoke-AD-Audit.ps1',
        'Modules\Invoke-EntraID-Audit.ps1',
        'Modules\Invoke-Exchange-Audit.ps1',
        'Modules\Invoke-SharePoint-Teams-Audit.ps1',
        'Modules\Invoke-PowerPlatform-Audit.ps1',
        'Modules\Invoke-Compliance-Audit.ps1',
        'Modules\New-AuditReport.ps1',
        'Modules\New-AdvancedAuditReports.ps1',
        'Modules\Invoke-Analytics-Engine.ps1',
        'Modules\New-ExecutiveDashboard.ps1',
        'Modules\Send-AnalyticsAlert.ps1',
        'Libraries\SQLite-AuditDB.ps1',
        'Utilities\Decrypt-AuditData.ps1'
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        # Main orchestration
        'Start-MAAudit',
        
        # Audit modules
        'Invoke-ADAudit',
        'Invoke-EntraIDAudit',
        'Invoke-ExchangeAudit',
        'Invoke-SharePointTeamsAudit',
        'Invoke-PowerPlatformAudit',
        'Invoke-ComplianceAudit',
        
        # Reporting
        'New-AuditReport',
        'New-AdvancedAuditReports',
        
        # Analytics Engine (v2.3.0)
        'Compare-AuditData',
        'Get-TrendAnalysis',
        'Find-Anomalies',
        'Get-RiskScore',
        'New-ExecutiveDashboard',
        'Send-AnalyticsAlert',
        'Test-AlertThresholds',
        'Send-AlertEmail',
        
        # SQLite database
        'Initialize-AuditDatabase',
        'Import-AuditCSVsToDatabase',
        'Import-CSVToTable',
        'Invoke-AuditQuery',
        'Get-DatabaseConnection',
        'Invoke-DatabaseQuery',
        
        # Utilities
        'Unprotect-EFSFolder',
        'Unprotect-ArchiveFile',
        'Unprotect-KeyVaultFiles'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    FileList = @(
        'Run-M&A-Audit.ps1',
        'Start-M&A-Audit-GUI.ps1',
        'Start-M&A-Analytics.ps1',
        'Start-M&A-QueryBuilder-GUI-POC.ps1',
        'Start-M&A-QueryBuilder-Web.ps1',
        'Setup-SQLite.ps1',
        'Install-SQLite-Simple.ps1',
        'Demo-AdvancedReporting.ps1',
        'Sample-AuditQueries.ps1',
        'README.md',
        'AD-Audit.psd1'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @(
                'M&A',
                'Audit',
                'Due-Diligence',
                'Active-Directory',
                'SQL-Server',
                'Microsoft365',
                'EntraID',
                'Exchange',
                'SharePoint',
                'Teams',
                'PowerPlatform',
                'Security',
                'Compliance',
                'Reporting',
                'Analytics',
                'Risk-Assessment',
                'Dashboard',
                'Anomaly-Detection',
                'Technical-Discovery',
                'Query-Builder',
                'SQLite',
                'PSEdition_Desktop',
                'PSEdition_Core',
                'Windows'
            )

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/adrian207/AD-Audit'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
## Version 2.3.0 (2025-10-22) - Advanced Analytics & Reporting

### 🚀 New Major Features
- **Advanced Analytics Engine**: Baseline comparison, trend analysis, anomaly detection
- **Risk Scoring System**: Comprehensive 0-100 security risk score
- **Executive Dashboards**: Beautiful HTML reports with risk gauges and interactive charts
- **Alert System**: Email notifications for threshold breaches (SMTP integration)
- **Query Builder Enhancements**: 20 templates (was 8), saved queries, query history, dark mode, Chart.js visualization

### 📊 Analytics Capabilities
- Baseline vs Current comparison (7 entity types tracked)
- 7 anomaly types (privileged accounts, Kerberos, ACLs, databases, servers)
- Risk levels: Low/Medium/High/Critical with color-coding
- Trend analysis across multiple audits
- Configurable alert thresholds

### 🎨 Dashboard Features
- Animated risk gauge (circular, color-coded)
- Interactive metric cards with change indicators
- Anomaly cards with severity badges
- Executive summary section
- Responsive design (mobile-friendly, print-optimized)
- Professional gradients and animations

### 🔔 Alert System
- 6 alert types with configurable thresholds
- HTML-formatted email notifications
- SMTP support (Office 365, Gmail, Exchange)
- Actionable recommendations

### 📈 Query Builder v2.2
- 20 pre-built query templates (12 new)
- Saved queries with descriptions
- Query history (last 100 executions)
- Chart visualization (Bar, Line, Pie)
- Dark mode with localStorage persistence
- Advanced filters (IN, BETWEEN operators)

### 🔒 Security Enhancements (v2.1)
- ACL analysis (dangerous permissions detection)
- Kerberos delegation audit (unconstrained/constrained)
- DHCP scope inventory
- GPO comprehensive inventory
- Service account security analysis
- AD trust relationships audit
- Password policy analysis (default + fine-grained)
- DNS zone inventory
- Certificate Services audit

### 📝 Documentation
- Analytics Guide (550+ lines)
- Query Builder Enhancements Guide (500+ lines)
- AD Security Components Guide
- Complete PowerShell Gallery publishing guide

### 🧪 Testing & Quality
- 118+ Pester tests (~78% coverage)
- Zero linter errors
- Comprehensive error handling
- CI/CD integration (GitHub Actions + Azure DevOps)

### 🛠️ Technical Details
- 3 new analytics modules (~1,700 lines)
- Start-M&A-Analytics.ps1 orchestrator (360 lines)
- Risk scoring with 7 factors
- Anomaly detection with 7 types
- JSON/CSV/HTML output formats

### 📦 Total Value
- ~6,100 lines of production code
- ~2,000 lines of documentation
- 5 releases (v2.0 → v2.3)
- Enterprise-grade M&A audit platform
'@

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            ExternalModuleDependencies = @(
                'ActiveDirectory',
                'Microsoft.Graph',
                'ExchangeOnlineManagement',
                'PnP.PowerShell',
                'MicrosoftTeams',
                'Microsoft.PowerApps.Administration.PowerShell'
            )

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/adrian207/AD-Audit/blob/main/docs/USER_GUIDE.md'

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}

