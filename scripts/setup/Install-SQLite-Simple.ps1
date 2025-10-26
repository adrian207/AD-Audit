<#
.SYNOPSIS
    Simple SQLite DLL installer
.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
#>

Write-Host ""
Write-Host "=== SQLite Setup ===" -ForegroundColor Cyan
Write-Host ""

# Create Libraries folder
$libFolder = ".\Libraries"
if (-not (Test-Path $libFolder)) {
    New-Item -ItemType Directory -Path $libFolder | Out-Null
}

Write-Host "Downloading SQLite..." -ForegroundColor Yellow

try {
    # Download the NuGet package (it's just a zip file)
    $url = "https://www.nuget.org/api/v2/package/System.Data.SQLite.Core/1.0.118"
    $zipFile = Join-Path $env:TEMP "sqlite.zip"
    
    Invoke-WebRequest -Uri $url -OutFile $zipFile -UseBasicParsing
    
    # Extract it
    $extractPath = Join-Path $env:TEMP "sqlite_temp"
    if (Test-Path $extractPath) {
        Remove-Item $extractPath -Recurse -Force
    }
    
    # Use .NET to extract since it's more reliable
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $extractPath)
    
    # Find and copy the x64 DLL (most common)
    $dllPath = Get-ChildItem -Path $extractPath -Filter "System.Data.SQLite.dll" -Recurse | 
               Where-Object { $_.FullName -like "*net46*" } | 
               Select-Object -First 1
    
    if ($dllPath) {
        Copy-Item $dllPath.FullName -Destination "$libFolder\System.Data.SQLite.dll" -Force
        Write-Host "SUCCESS: Installed System.Data.SQLite.dll" -ForegroundColor Green
        
        # Also try to copy SQLite.Interop.dll
        $interopPath = Get-ChildItem -Path $extractPath -Filter "SQLite.Interop.dll" -Recurse | 
                      Where-Object { $_.FullName -like "*x64*" } | 
                      Select-Object -First 1
        
        if ($interopPath) {
            Copy-Item $interopPath.FullName -Destination "$libFolder\SQLite.Interop.dll" -Force
            Write-Host "SUCCESS: Installed SQLite.Interop.dll" -ForegroundColor Green
        }
    } else {
        throw "DLL not found in package"
    }
    
    # Cleanup
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host ""
    Write-Host "Setup complete! You can now run:" -ForegroundColor Green
    Write-Host "  .\Start-M&A-QueryBuilder-Web.ps1" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "Automated install failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "MANUAL INSTALL:" -ForegroundColor Yellow
    Write-Host "1. Go to: https://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki" -ForegroundColor White
    Write-Host "2. Download: sqlite-netFx46-binary-x64-2015-1.0.118.0.zip" -ForegroundColor White
    Write-Host "3. Extract and copy System.Data.SQLite.dll to: $((Resolve-Path $libFolder).Path)" -ForegroundColor White
    Write-Host ""
    
    $open = Read-Host "Open download page? (Y/n)"
    if ($open -ne 'n') {
        Start-Process "https://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki"
    }
}

