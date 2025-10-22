@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'Run-M&A-Audit.ps1'

    # Version number of this module.
    ModuleVersion = '2.0.0'

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
M&A Technical Discovery Audit Tool - Comprehensive PowerShell-based auditing solution for merger and acquisition due diligence.

Features:
- Active Directory audit (users, computers, groups, GPOs, trusts, service accounts)
- Server hardware inventory (CPU, memory, storage, virtualization)
- SQL Server discovery (instances, databases, backups, logins, jobs)
- Microsoft 365 audit (Entra ID, Exchange, SharePoint, Teams, Power Platform)
- Compliance audit (DLP, retention, sensitivity labels, eDiscovery)
- HTML reporting with executive dashboard and migration readiness score
- SQLite database integration for advanced queries
- Enterprise encryption (EFS, 7-Zip, Azure Key Vault)
- Pester testing framework with 110+ tests (~75% coverage)

Designed for IT consultants, M&A teams, and technical due diligence professionals.
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
        
        # SQLite database
        'Initialize-AuditDatabase',
        'Import-AuditCSVsToDatabase',
        'Import-CSVToTable',
        'Invoke-AuditQuery',
        
        # Utilities
        'Decrypt-AuditData'
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
                'Technical-Discovery',
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
## Version 2.0.0 (2025-10-22)

### New Features
- Comprehensive Pester testing framework (110+ tests, ~75% coverage)
- CI/CD integration (GitHub Actions + Azure DevOps)
- Email notification system
- PowerShell module manifest for professional packaging
- Production-ready enterprise deployment

### Core Capabilities
- Active Directory comprehensive audit (16 components)
- Server hardware and application inventory
- SQL Server discovery and analysis
- Microsoft 365 full audit (Entra ID, Exchange, SharePoint, Teams)
- Power Platform audit (apps, flows, DLP)
- Compliance and security audit (retention, DLP, sensitivity labels)
- HTML reporting suite (5 reports + executive dashboard)
- SQLite database integration for advanced queries
- Enterprise encryption (EFS, 7-Zip, Azure Key Vault)

### Test Coverage
- SQLite database operations (25+ tests)
- AD audit functions (30+ tests)
- Cloud services (25+ tests)
- Integration tests (10+ tests)
- Utilities and helpers (20+ tests)

### Bug Fixes
- Fixed variable scoping in parallel processing
- Resolved linter warnings
- Improved error handling in server inventory

### Documentation
- Complete Pester testing documentation
- CI/CD integration guides
- Module packaging instructions
- Quick start guides
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

