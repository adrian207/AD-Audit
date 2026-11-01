# AD-Audit

PowerShell scripts for auditing an Active Directory environment and its connected Microsoft 365 tenant. Collects inventory and security data into CSV files, an optional SQLite database and an HTML report. Written for M&A due diligence and security assessments.

## What it does

**Data collection** (writes CSV output to a folder):

| Script | Collects |
|---|---|
| `Modules/Invoke-AD-Audit.ps1` | Forest and domain info, users, computers, groups, privileged accounts, ACLs, Kerberos delegation, GPOs, service accounts, trusts, password policies, DNS zones, AD CS, DHCP scopes, server hardware/storage/applications, event logs and logon history |
| `Modules/Invoke-EntraID-Audit.ps1` | Entra ID tenant configuration |
| `Modules/Invoke-Exchange-Audit.ps1` | Exchange Online |
| `Modules/Invoke-SharePoint-Teams-Audit.ps1` | SharePoint Online and Teams |
| `Modules/Invoke-PowerPlatform-Audit.ps1` | Power Platform environments |
| `Modules/Invoke-Compliance-Audit.ps1` | Microsoft Purview compliance settings |

**Security assessments** (run against the SQLite database the collection step creates, `-DatabasePath`):
credential theft prevention, domain controller security, least privilege, legacy systems, advanced threat detection, AD FS, event monitoring, AD DS auditing, LAPS and SMB. Each is a script in `Modules/` named `Invoke-<Area>.ps1`.

**Remediation** (`Invoke-MasterRemediation.ps1`, plus AD, server and M365 remediation scripts) supports `-DryRun` to preview changes.

**Reporting**: HTML audit report, advanced reports and an executive dashboard (`New-AuditReport.ps1`, `New-AdvancedAuditReports.ps1`, `New-ExecutiveDashboard.ps1`).

## Requirements

- Windows with PowerShell 5.1 or later
- RSAT Active Directory module (`ActiveDirectory`); `GroupPolicy` for GPO data
- Read access to the domain. Domain Admin or equivalent for server-level data (event logs, logon history)
- For cloud collection (optional, skipped with `-OnlyAD`): `Microsoft.Graph`, `ExchangeOnlineManagement`, `PnP.PowerShell`, `MicrosoftTeams` and `Microsoft.PowerApps.Administration.PowerShell`, plus an account that can read tenant configuration
- For the SQLite database: `System.Data.SQLite` (see [docs/SQLITE_SETUP.md](docs/SQLITE_SETUP.md))

## Quick start

```powershell
git clone https://github.com/adrian207/AD-Audit.git
cd AD-Audit

# Full audit (AD, servers and Microsoft 365) with a SQLite database
& '.\scripts\audit\Run-M&A-Audit.ps1' -CompanyName "Contoso" -OutputFolder "C:\Audits" -CreateDatabase

# Active Directory only
& '.\scripts\audit\Run-M&A-Audit.ps1' -CompanyName "Contoso" -OutputFolder "C:\Audits" -OnlyAD

# Run one security assessment against the database from a previous run
.\Modules\Invoke-CredentialTheftPrevention.ps1 -DatabasePath "C:\Audits\<run folder>\AuditData.db" -IncludeAll

# Preview remediation without changing anything
.\Modules\Invoke-MasterRemediation.ps1 -DatabasePath "C:\Audits\<run folder>\AuditData.db" -RemediationScope All -DryRun
```

Each run creates a timestamped folder under `-OutputFolder` with raw CSV data, logs and the report. Output is EFS-encrypted by default (`-SkipEFSEncryption` turns this off; `-CreateEncryptedArchive` adds an encrypted archive). Run `Get-Help '.\scripts\audit\Run-M&A-Audit.ps1' -Detailed` for every option, including server scope, OU filtering, encryption of the output and Azure Key Vault integration.

A Windows Forms launcher (`scripts/audit/Start-M&A-Audit-GUI.ps1`) and a query builder for the database are also included.

## Repository layout

```
Modules/      Collection, assessment, remediation and reporting scripts
Libraries/    SQLite database helpers
Utilities/    Decrypt-AuditData.ps1 for encrypted output
scripts/      Orchestrator (audit/), demos, setup and release tooling
Tests/        Pester tests
docs/         Guides and module reference
```

## Documentation

- [docs/INDEX.md](docs/INDEX.md): documentation index
- [docs/MODULE_REFERENCE.md](docs/MODULE_REFERENCE.md): parameters for each script
- [docs/LAPS_AUDIT_GUIDE.md](docs/LAPS_AUDIT_GUIDE.md), [docs/AD_PERFORMANCE_TUNING_GUIDE.md](docs/AD_PERFORMANCE_TUNING_GUIDE.md)

## Tests

```powershell
.\Tests\RunTests.ps1
```

Requires Pester 5. CI runs PSScriptAnalyzer and Pester on `windows-latest` ([.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml)).

## License

MIT. See [LICENSE](LICENSE).

## Author

Adrian Johnson · [github.com/adrian207](https://github.com/adrian207)
