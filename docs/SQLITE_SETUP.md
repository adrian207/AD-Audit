# SQLite Setup - Quick Fix

**Error**: `SQLite library not found`

---

## Quick Fix (2 minutes)

### Option 1: Automated Setup (Recommended)
```powershell
.\Setup-SQLite.ps1
```

This script will:
1. ✅ Download System.Data.SQLite from NuGet
2. ✅ Extract the DLL
3. ✅ Copy to Libraries folder
4. ✅ Test that it loads

### Option 2: Manual Installation

#### Step 1: Download SQLite
**Download Link**: https://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki

**What to download**:
- For 64-bit Windows (most common): `sqlite-netFx46-binary-x64-2015-*.zip`
- For 32-bit Windows: `sqlite-netFx46-binary-Win32-2015-*.zip`

**Direct Download** (latest version):
https://system.data.sqlite.org/downloads/1.0.118.0/sqlite-netFx46-binary-x64-2015-1.0.118.0.zip

#### Step 2: Extract Files
1. Extract the ZIP file to a temporary folder
2. Look for these files:
   - `System.Data.SQLite.dll`
   - `SQLite.Interop.dll`

#### Step 3: Copy to Libraries Folder
```powershell
# From PowerShell, in your AD-Audit directory:
Copy-Item "C:\Downloads\System.Data.SQLite.dll" -Destination ".\Libraries\"
Copy-Item "C:\Downloads\SQLite.Interop.dll" -Destination ".\Libraries\"
```

Or manually:
1. Navigate to `C:\Users\adria\OneDrive\Documents\GitHub\Ad-Audit\AD-Audit\Libraries`
2. Paste the two DLL files there

#### Step 4: Verify
```powershell
# Check files exist
Test-Path ".\Libraries\System.Data.SQLite.dll"
Test-Path ".\Libraries\SQLite.Interop.dll"
```

Both should return `True`

---

## Then Run Query Builder

```powershell
.\Start-M&A-QueryBuilder-Web.ps1
```

Should now work!

---

## Alternative: Use GAC-Installed Version

If you have SQL Server Management Studio or other tools, SQLite might already be installed.

```powershell
# This will use system-installed version
Add-Type -AssemblyName "System.Data.SQLite"
```

If this works, the query builder will automatically use it.

---

## Troubleshooting

### "DLL loads but query builder still fails"
- Make sure BOTH files are copied (System.Data.SQLite.dll AND SQLite.Interop.dll)
- SQLite.Interop.dll must be in the SAME folder

### "Downloaded wrong version"
- You need .NET Framework 4.6+ version (not .NET Core)
- Match your Windows architecture (x64 vs x86)

### "Can't download"
Use NuGet directly:
```powershell
Install-Package System.Data.SQLite.Core -Source nuget.org -Force -Scope CurrentUser
```

Then find DLL in:
```
C:\Users\<username>\.nuget\packages\system.data.sqlite.core\<version>\lib\net46\
```

---

## Quick Status Check

```powershell
# Run this to check current state:
if (Test-Path ".\Libraries\System.Data.SQLite.dll") {
    Write-Host "✓ System.Data.SQLite.dll found" -ForegroundColor Green
} else {
    Write-Host "✗ System.Data.SQLite.dll missing" -ForegroundColor Red
}

if (Test-Path ".\Libraries\SQLite.Interop.dll") {
    Write-Host "✓ SQLite.Interop.dll found" -ForegroundColor Green
} else {
    Write-Host "⚠ SQLite.Interop.dll missing (optional but recommended)" -ForegroundColor Yellow
}
```

---

**Author**: Adrian Johnson <adrian207@gmail.com>

