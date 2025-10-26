# AD-Audit Scripts Directory

This directory contains all PowerShell scripts for the AD-Audit framework, organized by functionality.

## Directory Structure

### 📁 audit/
Core audit and analysis scripts:
- **Run-M&A-Audit.ps1** - Main audit execution script for M&A scenarios
- **Sample-AuditQueries.ps1** - Sample audit queries for testing and examples
- **Start-M&A-Analytics.ps1** - M&A analytics engine launcher
- **Start-M&A-Audit-GUI.ps1** - GUI interface for M&A audits
- **Start-M&A-QueryBuilder-GUI-POC.ps1** - Query builder GUI proof of concept
- **Start-M&A-QueryBuilder-Web.ps1** - Web-based query builder launcher

### 📁 demos/
Demonstration and example scripts:
- **Demo-AdvancedReporting.ps1** - Advanced reporting features demonstration
- **Demo-PerformanceTuning.ps1** - Performance tuning examples

### 📁 deployment/
Deployment and publishing scripts:
- **Create-GitHubRelease.ps1** - GitHub release creation automation
- **Publish-ToGallery.ps1** - PowerShell Gallery publishing script

### 📁 setup/
Installation and setup scripts:
- **Install-SQLite-Simple.ps1** - Simplified SQLite installation
- **Setup-SQLite.ps1** - Complete SQLite setup and configuration

## Usage Guidelines

### Audit Scripts
The audit scripts are the main entry points for running AD audits:
```powershell
# Run a comprehensive M&A audit
.\audit\Run-M&A-Audit.ps1

# Start the GUI interface
.\audit\Start-M&A-Audit-GUI.ps1

# Launch analytics engine
.\audit\Start-M&A-Analytics.ps1
```

### Setup Scripts
Run setup scripts first to prepare your environment:
```powershell
# Basic SQLite setup
.\setup\Install-SQLite-Simple.ps1

# Full SQLite configuration
.\setup\Setup-SQLite.ps1
```

### Demo Scripts
Use demo scripts to explore features:
```powershell
# See advanced reporting capabilities
.\demos\Demo-AdvancedReporting.ps1

# Explore performance tuning options
.\demos\Demo-PerformanceTuning.ps1
```

### Deployment Scripts
For maintainers and contributors:
```powershell
# Create a GitHub release
.\deployment\Create-GitHubRelease.ps1

# Publish to PowerShell Gallery
.\deployment\Publish-ToGallery.ps1
```

## Prerequisites

- Windows PowerShell 5.1 or PowerShell Core 6.0+
- Active Directory PowerShell module
- Appropriate permissions for AD querying
- SQLite (for database features)

## Execution Policy

Ensure your PowerShell execution policy allows script execution:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Support

For script-specific help, use the `-Help` parameter:
```powershell
Get-Help .\audit\Run-M&A-Audit.ps1 -Full
```

Refer to the documentation in the `docs/` directory for comprehensive guides and troubleshooting information.