<#
.SYNOPSIS
    Publishes the AD-Audit module to PowerShell Gallery
    
.DESCRIPTION
    Handles the complete publishing workflow for the AD-Audit module:
    - Validates module manifest
    - Tests module loading
    - Checks for API key
    - Publishes to PowerShell Gallery
    - Verifies publication
    
.PARAMETER NuGetApiKey
    Your PowerShell Gallery NuGet API key. If not provided, will look for
    environment variable $env:NUGET_API_KEY
    
.PARAMETER WhatIf
    Shows what would happen without actually publishing
    
.PARAMETER Force
    Skip confirmation prompts
    
.EXAMPLE
    .\Publish-ToGallery.ps1 -NuGetApiKey "your-api-key-here"
    
.EXAMPLE
    # Using environment variable
    $env:NUGET_API_KEY = "your-api-key-here"
    .\Publish-ToGallery.ps1
    
.EXAMPLE
    # Test run (WhatIf)
    .\Publish-ToGallery.ps1 -WhatIf
    
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    
    Prerequisites:
    - PowerShellGet module (Install-Module PowerShellGet -Force)
    - PowerShell Gallery account (https://www.powershellgallery.com/)
    - NuGet API key from PowerShell Gallery
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$NuGetApiKey,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   PowerShell Gallery Publishing Script - AD-Audit Module    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

#region Step 1: Validate Prerequisites

Write-Host "[Step 1/6] Validating prerequisites..." -ForegroundColor Cyan

# Check PowerShellGet
$psGetModule = Get-Module PowerShellGet -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $psGetModule) {
    Write-Host "  ❌ PowerShellGet module not found" -ForegroundColor Red
    Write-Host "  Install with: Install-Module PowerShellGet -Force" -ForegroundColor Yellow
    exit 1
}
Write-Host "  ✓ PowerShellGet $($psGetModule.Version) installed" -ForegroundColor Green

# Check for API key
if (-not $NuGetApiKey) {
    $NuGetApiKey = $env:NUGET_API_KEY
}

if (-not $NuGetApiKey) {
    Write-Host "  ❌ NuGet API key not provided" -ForegroundColor Red
    Write-Host "`n  How to get your API key:" -ForegroundColor Yellow
    Write-Host "  1. Go to https://www.powershellgallery.com/" -ForegroundColor White
    Write-Host "  2. Sign in or create an account" -ForegroundColor White
    Write-Host "  3. Go to Account Settings → API Keys" -ForegroundColor White
    Write-Host "  4. Create a new API key or copy existing one" -ForegroundColor White
    Write-Host "`n  Then run:" -ForegroundColor Yellow
    Write-Host "  `$env:NUGET_API_KEY = 'your-key-here'" -ForegroundColor White
    Write-Host "  .\Publish-ToGallery.ps1`n" -ForegroundColor White
    exit 1
}
Write-Host "  ✓ NuGet API key provided" -ForegroundColor Green

#endregion

#region Step 2: Validate Module

Write-Host "`n[Step 2/6] Validating module..." -ForegroundColor Cyan

$modulePath = Join-Path $PSScriptRoot "AD-Audit.psd1"
if (-not (Test-Path $modulePath)) {
    Write-Host "  ❌ Module manifest not found: $modulePath" -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ Module manifest found" -ForegroundColor Green

# Test manifest
try {
    $manifest = Test-ModuleManifest -Path $modulePath -ErrorAction Stop
    Write-Host "  ✓ Module manifest is valid" -ForegroundColor Green
    Write-Host "    Name: $($manifest.Name)" -ForegroundColor Gray
    Write-Host "    Version: $($manifest.Version)" -ForegroundColor Gray
    Write-Host "    Author: $($manifest.Author)" -ForegroundColor Gray
    Write-Host "    Description: $($manifest.Description.Substring(0, [Math]::Min(80, $manifest.Description.Length)))..." -ForegroundColor Gray
}
catch {
    Write-Host "  ❌ Module manifest validation failed: $_" -ForegroundColor Red
    exit 1
}

#endregion

#region Step 3: Test Module Loading

Write-Host "`n[Step 3/6] Testing module import..." -ForegroundColor Cyan

try {
    # Try to import in a new PowerShell session to avoid conflicts
    $testScript = @"
Import-Module '$modulePath' -Force -ErrorAction Stop
Get-Command -Module AD-Audit | Measure-Object | Select-Object -ExpandProperty Count
"@
    
    $result = powershell.exe -NoProfile -Command $testScript
    if ($result -gt 0) {
        Write-Host "  ✓ Module imports successfully" -ForegroundColor Green
        Write-Host "    Exported functions: $result" -ForegroundColor Gray
    }
    else {
        Write-Host "  ❌ Module import failed or no functions exported" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "  ❌ Module import test failed: $_" -ForegroundColor Red
    exit 1
}

#endregion

#region Step 4: Check if Module Already Exists

Write-Host "`n[Step 4/6] Checking PowerShell Gallery..." -ForegroundColor Cyan

try {
    $existingModule = Find-Module -Name "AD-Audit" -ErrorAction SilentlyContinue
    if ($existingModule) {
        Write-Host "  ⚠️  Module already exists in PowerShell Gallery" -ForegroundColor Yellow
        Write-Host "    Current version: $($existingModule.Version)" -ForegroundColor Gray
        Write-Host "    Your version: $($manifest.Version)" -ForegroundColor Gray
        
        if ([version]$manifest.Version -le [version]$existingModule.Version) {
            Write-Host "  ❌ Your version must be greater than the published version" -ForegroundColor Red
            Write-Host "    Update ModuleVersion in AD-Audit.psd1" -ForegroundColor Yellow
            exit 1
        }
        Write-Host "  ✓ Version check passed (newer version)" -ForegroundColor Green
    }
    else {
        Write-Host "  ✓ Module not yet published (first-time publish)" -ForegroundColor Green
    }
}
catch {
    Write-Host "  ⚠️  Could not check PowerShell Gallery: $_" -ForegroundColor Yellow
}

#endregion

#region Step 5: Publish Module

Write-Host "`n[Step 5/6] Publishing module..." -ForegroundColor Cyan

if ($PSCmdlet.ShouldProcess("AD-Audit v$($manifest.Version)", "Publish to PowerShell Gallery")) {
    
    if (-not $Force) {
        $confirm = Read-Host "  Publish AD-Audit v$($manifest.Version) to PowerShell Gallery? (Y/N)"
        if ($confirm -ne 'Y' -and $confirm -ne 'y') {
            Write-Host "  ℹ️  Publishing cancelled by user" -ForegroundColor Yellow
            exit 0
        }
    }
    
    try {
        Write-Host "  Publishing... (this may take a minute)" -ForegroundColor Gray
        
        Publish-Module -Path $PSScriptRoot `
                      -NuGetApiKey $NuGetApiKey `
                      -Repository PSGallery `
                      -Verbose `
                      -ErrorAction Stop
        
        Write-Host "  ✓ Module published successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "  ❌ Publishing failed: $_" -ForegroundColor Red
        Write-Host "`n  Troubleshooting tips:" -ForegroundColor Yellow
        Write-Host "  - Verify your API key is valid" -ForegroundColor White
        Write-Host "  - Ensure version is incremented from previous release" -ForegroundColor White
        Write-Host "  - Check that all required files are present" -ForegroundColor White
        Write-Host "  - Review manifest for any errors" -ForegroundColor White
        exit 1
    }
}
else {
    Write-Host "  ℹ️  WhatIf: Would publish AD-Audit v$($manifest.Version)" -ForegroundColor Yellow
    Write-Host "  Run without -WhatIf to actually publish" -ForegroundColor Gray
    exit 0
}

#endregion

#region Step 6: Verify Publication

Write-Host "`n[Step 6/6] Verifying publication..." -ForegroundColor Cyan
Write-Host "  Waiting for PowerShell Gallery to index (30 seconds)..." -ForegroundColor Gray
Start-Sleep -Seconds 30

try {
    $publishedModule = Find-Module -Name "AD-Audit" -RequiredVersion $manifest.Version -ErrorAction Stop
    if ($publishedModule) {
        Write-Host "  ✓ Module verified in PowerShell Gallery!" -ForegroundColor Green
        Write-Host "`n  Module Details:" -ForegroundColor Cyan
        Write-Host "    Name: $($publishedModule.Name)" -ForegroundColor White
        Write-Host "    Version: $($publishedModule.Version)" -ForegroundColor White
        Write-Host "    Published: $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
        Write-Host "`n  Users can now install with:" -ForegroundColor Cyan
        Write-Host "    Install-Module AD-Audit" -ForegroundColor Green
        Write-Host "`n  View on Gallery:" -ForegroundColor Cyan
        Write-Host "    https://www.powershellgallery.com/packages/AD-Audit/$($manifest.Version)" -ForegroundColor Blue
    }
}
catch {
    Write-Host "  ⚠️  Could not immediately verify (Gallery indexing may take a few minutes)" -ForegroundColor Yellow
    Write-Host "  Check manually: https://www.powershellgallery.com/packages/AD-Audit" -ForegroundColor Gray
}

#endregion

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                 PUBLISHING COMPLETE!                         ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Green

Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Verify module on PowerShell Gallery" -ForegroundColor White
Write-Host "  2. Test installation: Install-Module AD-Audit" -ForegroundColor White
Write-Host "  3. Share with community!" -ForegroundColor White
Write-Host "  4. Monitor downloads and feedback" -ForegroundColor White
Write-Host "`n🎉 Congratulations on publishing your module!`n" -ForegroundColor Yellow

