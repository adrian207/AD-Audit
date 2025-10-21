<#
.SYNOPSIS
    Downloads and installs System.Data.SQLite library for M&A Audit Tool
    
.DESCRIPTION
    This script downloads the System.Data.SQLite NuGet package and extracts
    the necessary DLL to the Libraries folder.
    
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Run this once to set up SQLite support
#>

[CmdletBinding()]
param()

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   System.Data.SQLite Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Create Libraries folder if it doesn't exist
$libFolder = Join-Path $PSScriptRoot "Libraries"
if (-not (Test-Path $libFolder)) {
    Write-Host "Creating Libraries folder..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $libFolder -Force | Out-Null
}

# Check if DLL already exists
$dllPath = Join-Path $libFolder "System.Data.SQLite.dll"
if (Test-Path $dllPath) {
    Write-Host "SQLite DLL already exists at: $dllPath" -ForegroundColor Green
    Write-Host ""
    $overwrite = Read-Host "Do you want to re-download? (y/N)"
    if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
        Write-Host "Setup cancelled." -ForegroundColor Yellow
        return
    }
}

Write-Host "Downloading System.Data.SQLite..." -ForegroundColor Cyan

try {
    # Option 1: Try NuGet package manager (fastest)
    Write-Host "Attempting to install via NuGet..." -ForegroundColor Yellow
    
    $nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nugetProvider) {
        Write-Host "Installing NuGet provider..." -ForegroundColor Yellow
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    }
    
    # Install package
    $package = Install-Package System.Data.SQLite.Core -Source nuget.org -Force -Scope CurrentUser -SkipDependencies
    
    if ($package) {
        Write-Host "Package installed successfully!" -ForegroundColor Green
        
        # Find the DLL in the package
        $packagePath = Split-Path $package.Source -Parent
        
        # Look for the DLL (different paths for x64/x86)
        $possiblePaths = @(
            (Get-ChildItem -Path $packagePath -Recurse -Filter "System.Data.SQLite.dll" | Where-Object { $_.FullName -match "net46.*x64" } | Select-Object -First 1),
            (Get-ChildItem -Path $packagePath -Recurse -Filter "System.Data.SQLite.dll" | Where-Object { $_.FullName -match "net4" } | Select-Object -First 1),
            (Get-ChildItem -Path $packagePath -Recurse -Filter "System.Data.SQLite.dll" | Select-Object -First 1)
        )
        
        $sourceDll = $possiblePaths | Where-Object { $_ -ne $null } | Select-Object -First 1
        
        if ($sourceDll) {
            Write-Host "Found DLL at: $($sourceDll.FullName)" -ForegroundColor Green
            Copy-Item -Path $sourceDll.FullName -Destination $dllPath -Force
            Write-Host "Copied to: $dllPath" -ForegroundColor Green
            
            # Also copy interop DLL if exists
            $interopDll = Join-Path (Split-Path $sourceDll.FullName) "SQLite.Interop.dll"
            if (Test-Path $interopDll) {
                $destInterop = Join-Path $libFolder "SQLite.Interop.dll"
                Copy-Item -Path $interopDll -Destination $destInterop -Force
                Write-Host "Copied SQLite.Interop.dll as well" -ForegroundColor Green
            }
        } else {
            throw "DLL not found in package"
        }
    }
}
catch {
    Write-Host "NuGet method failed, trying direct download..." -ForegroundColor Yellow
    
    # Option 2: Direct download from SQLite.org
    try {
        # Determine architecture
        $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
        
        # SQLite version (update this as needed)
        $version = "1.0.118"
        $year = "2023"
        
        # Download URL (example - may need to be updated)
        $downloadUrl = "https://system.data.sqlite.org/blobs/$version/sqlite-netFx46-binary-x64-$year-$version.zip"
        
        Write-Host "Downloading from: $downloadUrl" -ForegroundColor Yellow
        
        $tempZip = Join-Path $env:TEMP "sqlite.zip"
        $tempExtract = Join-Path $env:TEMP "sqlite_extract"
        
        # Download
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing
        
        # Extract
        if (Test-Path $tempExtract) {
            Remove-Item $tempExtract -Recurse -Force
        }
        Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force
        
        # Copy DLLs
        $extractedDll = Get-ChildItem -Path $tempExtract -Filter "System.Data.SQLite.dll" -Recurse | Select-Object -First 1
        if ($extractedDll) {
            Copy-Item -Path $extractedDll.FullName -Destination $dllPath -Force
            Write-Host "Copied to: $dllPath" -ForegroundColor Green
            
            # Copy interop
            $extractedInterop = Get-ChildItem -Path $tempExtract -Filter "SQLite.Interop.dll" -Recurse | Select-Object -First 1
            if ($extractedInterop) {
                Copy-Item -Path $extractedInterop.FullName -Destination (Join-Path $libFolder "SQLite.Interop.dll") -Force
            }
        }
        
        # Cleanup
        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Direct download failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Manual Installation Required:" -ForegroundColor Yellow
        Write-Host "1. Download System.Data.SQLite from: https://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki" -ForegroundColor White
        Write-Host "2. Choose 'sqlite-netFx46-binary-x64' (or x86 for 32-bit)" -ForegroundColor White
        Write-Host "3. Extract the ZIP file" -ForegroundColor White
        Write-Host "4. Copy System.Data.SQLite.dll to: $libFolder" -ForegroundColor White
        Write-Host "5. Copy SQLite.Interop.dll to: $libFolder" -ForegroundColor White
        Write-Host ""
        
        # Open download page
        $openBrowser = Read-Host "Open download page in browser? (Y/n)"
        if ($openBrowser -ne 'n' -and $openBrowser -ne 'N') {
            Start-Process "https://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki"
        }
        
        return
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "   Setup Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "SQLite library installed at:" -ForegroundColor White
Write-Host "  $dllPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "You can now run:" -ForegroundColor White
Write-Host "  .\Start-M&A-QueryBuilder-Web.ps1" -ForegroundColor Cyan
Write-Host ""

# Test loading the DLL
try {
    Add-Type -Path $dllPath
    Write-Host "[OK] DLL loads successfully!" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "[WARNING] DLL exists but could not be loaded: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "This might be normal - try running the query builder anyway." -ForegroundColor Yellow
    Write-Host ""
}

