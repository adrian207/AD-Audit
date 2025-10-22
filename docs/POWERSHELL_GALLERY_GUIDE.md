# PowerShell Gallery Publishing Guide

**Module**: AD-Audit  
**Version**: 2.3.0  
**Last Updated**: October 22, 2025  

---

## 📦 Quick Installation (Once Published)

```powershell
# Install from PowerShell Gallery
Install-Module AD-Audit -Scope CurrentUser

# Import the module
Import-Module AD-Audit

# Verify installation
Get-Command -Module AD-Audit

# Get module info
Get-Module AD-Audit -ListAvailable
```

---

## 🚀 Publishing to PowerShell Gallery

### Prerequisites

1. **PowerShell Gallery Account**
   - Create account: https://www.powershellgallery.com/
   - Verify email address

2. **NuGet API Key**
   - Log in to PowerShell Gallery
   - Go to Account Settings → API Keys
   - Create new key or use existing
   - Copy the key (you won't see it again!)

3. **PowerShellGet Module**
   ```powershell
   Install-Module PowerShellGet -Force -AllowClobber
   ```

### Step-by-Step Publishing

#### Method 1: Using the Publishing Script (Recommended)

```powershell
# Navigate to module directory
cd C:\Path\To\AD-Audit

# Set your API key (one-time)
$env:NUGET_API_KEY = "your-api-key-here"

# Publish
.\Publish-ToGallery.ps1
```

The script will:
✅ Validate prerequisites  
✅ Test module manifest  
✅ Test module import  
✅ Check version conflicts  
✅ Publish to Gallery  
✅ Verify publication  

#### Method 2: Manual Publishing

```powershell
# Test the manifest first
Test-ModuleManifest .\AD-Audit.psd1

# Publish to PowerShell Gallery
Publish-Module -Path . `
               -NuGetApiKey "your-api-key-here" `
               -Repository PSGallery `
               -Verbose
```

---

## 📋 Pre-Publishing Checklist

Before publishing, ensure:

- [ ] **Version incremented** in `AD-Audit.psd1`
- [ ] **All tests passing**: `.\Tests\RunTests.ps1`
- [ ] **No linter errors**: Check all `.ps1` files
- [ ] **Documentation updated**: README.md, docs/*.md
- [ ] **ReleaseNotes updated** in manifest
- [ ] **Git committed**: All changes committed
- [ ] **Git tagged**: `git tag v2.3.0`
- [ ] **Dependencies listed** in manifest
- [ ] **Functions exported** in FunctionsToExport
- [ ] **Files included** in FileList

---

## 🔄 Version Management

### Semantic Versioning

AD-Audit follows [Semantic Versioning](https://semver.org/):

**MAJOR.MINOR.PATCH**
- **MAJOR**: Breaking changes (e.g., 2.0.0 → 3.0.0)
- **MINOR**: New features, backward compatible (e.g., 2.2.0 → 2.3.0)
- **PATCH**: Bug fixes, backward compatible (e.g., 2.3.0 → 2.3.1)

### Version History

| Version | Date | Type | Description |
|---------|------|------|-------------|
| 1.0.0 | Initial | Major | Initial release |
| 2.0.0 | Oct 20 | Major | Enterprise features (CI/CD, Module, Tests) |
| 2.1.0 | Oct 22 | Minor | AD Security Components (9 functions) |
| 2.2.0 | Oct 22 | Minor | Query Builder Enhanced |
| 2.3.0 | Oct 22 | Minor | Analytics & Reporting |

### Updating Version

Update in `AD-Audit.psd1`:
```powershell
ModuleVersion = '2.3.0'  # Change this
```

Update in `README.md`:
```markdown
![Version](https://img.shields.io/badge/version-2.3.0-green)
```

---

## 🧪 Testing Before Publication

### Run All Tests
```powershell
cd Tests
.\RunTests.ps1
```

### Test Manifest
```powershell
Test-ModuleManifest .\AD-Audit.psd1
```

### Test Import
```powershell
Import-Module .\AD-Audit.psd1 -Force
Get-Command -Module AD-Audit
```

### Test Core Functions
```powershell
# Test analytics
Get-Help Compare-AuditData
Get-Help Get-RiskScore

# Test query builder
Get-Help Start-MAAudit
```

---

## 📝 Manifest Configuration

### Key Fields

**Required**:
- `RootModule`: Entry point script
- `ModuleVersion`: Current version
- `GUID`: Unique identifier (don't change!)
- `Author`: Your name
- `Description`: Module description
- `PowerShellVersion`: Minimum PS version (5.1)

**Important for Gallery**:
- `Tags`: Searchability keywords
- `ProjectUri`: GitHub repository URL
- `ReleaseNotes`: What's new in this version
- `ExternalModuleDependencies`: Required modules
- `FunctionsToExport`: Public functions

### Current Configuration

```powershell
@{
    ModuleVersion = '2.3.0'
    GUID = '8f4e3d2c-1a5b-4c9e-8f3d-2a1b5c9e8f3d'
    Author = 'Adrian Johnson'
    PowerShellVersion = '5.1'
    
    FunctionsToExport = @(
        'Start-MAAudit',
        'Compare-AuditData',
        'Get-RiskScore',
        'New-ExecutiveDashboard',
        # ... 20+ more functions
    )
    
    PrivateData = @{
        PSData = @{
            Tags = @('M&A', 'Audit', 'Analytics', 'Security')
            ProjectUri = 'https://github.com/adrian207/AD-Audit'
            ReleaseNotes = '## Version 2.3.0...'
        }
    }
}
```

---

## 🔍 Troubleshooting

### Issue: "Module already exists with version X"
**Solution**: Increment version in `AD-Audit.psd1`

### Issue: "Invalid API key"
**Solution**: 
1. Verify key is correct
2. Check key hasn't expired
3. Regenerate key if needed

### Issue: "Module manifest invalid"
**Solution**: Run `Test-ModuleManifest .\AD-Audit.psd1` for details

### Issue: "Function not exported"
**Solution**: Add to `FunctionsToExport` in manifest

### Issue: "Cannot find module 'ActiveDirectory'"
**Solution**: Ensure RSAT is installed on Windows

### Issue: "Publishing takes too long"
**Solution**: PowerShell Gallery can take 1-2 minutes to process

---

## 📊 Post-Publishing

### Verify Publication

```powershell
# Search for your module
Find-Module AD-Audit

# Check specific version
Find-Module AD-Audit -RequiredVersion 2.3.0

# View details
Find-Module AD-Audit | Select-Object *
```

### Test Installation

```powershell
# Install in new PowerShell session
Install-Module AD-Audit -Scope CurrentUser

# Verify
Get-Module AD-Audit -ListAvailable

# Test import
Import-Module AD-Audit
Get-Command -Module AD-Audit
```

### Monitor

1. **View on Gallery**: https://www.powershellgallery.com/packages/AD-Audit
2. **Check download stats**: Gallery dashboard
3. **Monitor issues**: GitHub Issues
4. **Track feedback**: PowerShell Gallery reviews

---

## 🎯 Best Practices

### Before Publishing
1. **Test extensively** in clean environment
2. **Update all documentation**
3. **Increment version properly**
4. **Write detailed release notes**
5. **Commit and tag in Git**

### Manifest
1. **Use specific versions** for dependencies
2. **Export only public functions**
3. **Keep GUID unchanged** (identifies your module)
4. **Use descriptive tags** (max 10-12)
5. **Include ProjectUri** for GitHub

### Documentation
1. **README.md**: Quick start and features
2. **docs/*.md**: Detailed guides
3. **Comment-based help**: For all functions
4. **Examples**: Real-world usage scenarios

### Versioning
1. **Follow SemVer**: MAJOR.MINOR.PATCH
2. **Tag in Git**: `git tag v2.3.0`
3. **Document changes**: Update ReleaseNotes
4. **Backward compatibility**: Avoid breaking changes in MINOR/PATCH

---

## 🔐 Security

### API Key Security
- **Never commit** API keys to Git
- **Use environment variables**: `$env:NUGET_API_KEY`
- **Rotate keys** regularly
- **Revoke unused keys**

### Module Security
- **Code signing**: Consider signing scripts
- **Virus scanning**: Scan before publishing
- **Dependency audit**: Review external modules
- **Security advisories**: Monitor for vulnerabilities

---

## 📈 Updating Published Module

### Patch Release (2.3.0 → 2.3.1)
```powershell
# Fix bugs, update version
ModuleVersion = '2.3.1'

# Update release notes
ReleaseNotes = '## Version 2.3.1 - Bug Fixes...'

# Publish
.\Publish-ToGallery.ps1
```

### Minor Release (2.3.0 → 2.4.0)
```powershell
# Add features, update version
ModuleVersion = '2.4.0'

# Add new functions to FunctionsToExport
FunctionsToExport = @(
    # ... existing ...
    'New-FeatureFunction'
)

# Update release notes
ReleaseNotes = '## Version 2.4.0 - New Features...'

# Publish
.\Publish-ToGallery.ps1
```

### Major Release (2.3.0 → 3.0.0)
```powershell
# Breaking changes, update version
ModuleVersion = '3.0.0'

# Update ReleaseNotes with breaking changes
ReleaseNotes = @'
## Version 3.0.0 - BREAKING CHANGES
### Breaking Changes
- Renamed function X to Y
- Removed deprecated parameter Z
...
'@

# Publish
.\Publish-ToGallery.ps1
```

---

## 🌐 Gallery Links

- **PowerShell Gallery**: https://www.powershellgallery.com/
- **Your Module**: https://www.powershellgallery.com/packages/AD-Audit
- **API Keys**: https://www.powershellgallery.com/account/apikeys
- **Publishing Docs**: https://docs.microsoft.com/powershell/gallery/how-to/publishing-packages/publishing-a-package

---

## 📞 Support

### Questions?
- **Email**: adrian207@gmail.com
- **GitHub Issues**: https://github.com/adrian207/AD-Audit/issues
- **Documentation**: See `/docs` folder

### Reporting Issues
1. Check existing issues first
2. Provide version: `(Get-Module AD-Audit).Version`
3. Include error messages
4. Steps to reproduce
5. Expected vs actual behavior

---

## 🎉 Success!

Once published, users worldwide can install your module with:
```powershell
Install-Module AD-Audit
```

**Congratulations on publishing to PowerShell Gallery!** 🚀

---

**Last Updated**: October 22, 2025  
**Module Version**: 2.3.0  
**Status**: Ready for Publication

