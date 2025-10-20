<#
.SYNOPSIS
    Decrypts M&A audit data encrypted by Run-M&A-Audit.ps1

.DESCRIPTION
    This utility decrypts audit data that was encrypted using one of three methods:
    1. Windows EFS (Encrypting File System)
    2. Password-protected archive (7-Zip or PowerShell native)
    3. Azure Key Vault encryption

    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0
    Date: October 2025

.PARAMETER EncryptedPath
    Path to the encrypted audit folder or archive file

.PARAMETER OutputPath
    Destination folder for decrypted data

.PARAMETER DecryptionMethod
    The encryption method used: EFS, Archive, or KeyVault

.PARAMETER ArchivePassword
    Password for encrypted archive (required for Archive method)

.PARAMETER KeyVaultName
    Azure Key Vault name (required for KeyVault method)

.PARAMETER KeyName
    Key name in Azure Key Vault (required for KeyVault method)

.EXAMPLE
    # Decrypt EFS-encrypted folder
    .\Decrypt-AuditData.ps1 -EncryptedPath "C:\Audits\Contoso-2025-10-20" -OutputPath "C:\Decrypted" -DecryptionMethod EFS

.EXAMPLE
    # Decrypt password-protected 7z archive
    .\Decrypt-AuditData.ps1 -EncryptedPath "C:\Audits\Contoso-2025-10-20.7z" -OutputPath "C:\Decrypted" -DecryptionMethod Archive

.EXAMPLE
    # Decrypt PowerShell native encrypted archive
    .\Decrypt-AuditData.ps1 -EncryptedPath "C:\Audits\Contoso-2025-10-20.zip.enc" -OutputPath "C:\Decrypted" -DecryptionMethod Archive

.EXAMPLE
    # Decrypt Azure Key Vault encrypted data
    .\Decrypt-AuditData.ps1 -EncryptedPath "C:\Audits\Contoso-2025-10-20" -OutputPath "C:\Decrypted" `
        -DecryptionMethod KeyVault -KeyVaultName "ContosoAuditVault" -KeyName "M&AAuditKey"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EncryptedPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet('EFS', 'Archive', 'KeyVault')]
    [string]$DecryptionMethod,

    [Parameter(Mandatory = $false)]
    [SecureString]$ArchivePassword,

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [string]$KeyName
)

$ErrorActionPreference = 'Stop'

function Write-DecryptLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        default   { 'White' }
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Decrypt-EFSFolder {
    param([string]$Path, [string]$Destination)

    Write-DecryptLog "Decrypting EFS-encrypted folder..." -Level Info

    # EFS decryption is automatic if you have the certificate
    # Just copy the folder - Windows will decrypt automatically for authorized users
    if (-not (Test-Path $Path)) {
        throw "Encrypted folder not found: $Path"
    }

    $encrypted = (Get-Item $Path).Attributes -band [System.IO.FileAttributes]::Encrypted
    if (-not $encrypted) {
        Write-DecryptLog "Warning: Folder is not EFS-encrypted" -Level Warning
    }

    Write-DecryptLog "Copying encrypted data to destination..." -Level Info
    Copy-Item -Path $Path -Destination $Destination -Recurse -Force

    Write-DecryptLog "EFS decryption completed successfully" -Level Success
    Write-DecryptLog "If you see errors, you may not have the EFS certificate" -Level Info
}

function Decrypt-ArchiveFile {
    param([string]$ArchivePath, [string]$Destination)

    if (-not (Test-Path $ArchivePath)) {
        throw "Archive file not found: $ArchivePath"
    }

    $extension = [System.IO.Path]::GetExtension($ArchivePath)

    if ($extension -eq '.7z') {
        # 7-Zip archive
        Write-DecryptLog "Decrypting 7-Zip archive..." -Level Info

        $7zipPath = "C:\Program Files\7-Zip\7z.exe"
        if (-not (Test-Path $7zipPath)) {
            $7zipPath = "C:\Program Files (x86)\7-Zip\7z.exe"
        }

        if (-not (Test-Path $7zipPath)) {
            throw "7-Zip not found. Please install from https://www.7-zip.org/"
        }

        if (-not $ArchivePassword) {
            $ArchivePassword = Read-Host -AsSecureString "Enter archive password"
        }

        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ArchivePassword)
        )

        $arguments = "x -p`"$plainPassword`" -o`"$Destination`" `"$ArchivePath`" -y"
        $process = Start-Process -FilePath $7zipPath -ArgumentList $arguments -Wait -NoNewWindow -PassThru

        if ($process.ExitCode -eq 0) {
            Write-DecryptLog "7-Zip archive decrypted successfully" -Level Success
        } else {
            throw "7-Zip extraction failed. Check password and try again."
        }

    } elseif ($extension -eq '.enc') {
        # PowerShell native encrypted archive
        Write-DecryptLog "Decrypting PowerShell native encrypted archive..." -Level Info

        if (-not $ArchivePassword) {
            $ArchivePassword = Read-Host -AsSecureString "Enter archive password"
        }

        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ArchivePassword)
        )

        # Read encrypted file
        $encryptedData = [System.IO.File]::ReadAllBytes($ArchivePath)

        # Extract salt (first 32 bytes) and IV (next 16 bytes)
        $salt = $encryptedData[0..31]
        $iv = $encryptedData[32..47]
        $cipherBytes = $encryptedData[48..($encryptedData.Length-1)]

        # Derive key using PBKDF2
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($plainPassword, $salt, 100000)
        $key = $pbkdf2.GetBytes(32)

        # Decrypt
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)

        # Save decrypted ZIP
        $tempZipPath = Join-Path ([System.IO.Path]::GetTempPath()) "decrypted-audit-$([Guid]::NewGuid()).zip"
        [System.IO.File]::WriteAllBytes($tempZipPath, $decryptedBytes)

        # Extract ZIP
        Write-DecryptLog "Extracting decrypted archive..." -Level Info
        Expand-Archive -Path $tempZipPath -DestinationPath $Destination -Force

        # Clean up
        Remove-Item $tempZipPath -Force
        $aes.Dispose()

        Write-DecryptLog "PowerShell native archive decrypted successfully" -Level Success

    } else {
        throw "Unsupported archive format: $extension"
    }
}

function Decrypt-KeyVaultFiles {
    param([string]$EncryptedFolder, [string]$Destination)

    Write-DecryptLog "Decrypting Azure Key Vault encrypted files..." -Level Info

    # Check for encryption metadata
    $keyInfoPath = Join-Path $EncryptedFolder "encryption_key_info.json"
    if (-not (Test-Path $keyInfoPath)) {
        throw "Encryption key info not found. Expected: $keyInfoPath"
    }

    $keyInfo = Get-Content $keyInfoPath | ConvertFrom-Json

    if (-not $KeyVaultName) {
        $KeyVaultName = $keyInfo.KeyVaultName
    }
    if (-not $KeyName) {
        $KeyName = $keyInfo.KeyName
    }

    # Check if Az.KeyVault module is available
    if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
        Write-DecryptLog "Az.KeyVault module not found. Installing..." -Level Warning
        Install-Module -Name Az.KeyVault -Scope CurrentUser -Force -AllowClobber
    }

    Import-Module Az.KeyVault -ErrorAction Stop

    # Ensure we're connected to Azure
    $context = Get-AzContext
    if (-not $context) {
        Write-DecryptLog "Not connected to Azure. Please authenticate..." -Level Info
        Connect-AzAccount
    }

    Write-DecryptLog "Using Key Vault: $KeyVaultName, Key: $KeyName" -Level Info

    # Decrypt the AES key using Key Vault
    $encryptedAESKeyBytes = [Convert]::FromBase64String($keyInfo.EncryptedAESKey)
    $decryptedAESKey = Invoke-AzKeyVaultKeyOperation -Operation Decrypt -VaultName $KeyVaultName `
        -Name $KeyName -Algorithm RSA-OAEP -Value $encryptedAESKeyBytes

    # Prepare AES decryptor
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Key = $decryptedAESKey.Result
    $aes.IV = [Convert]::FromBase64String($keyInfo.IV)

    # Create output directory
    if (-not (Test-Path $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    # Decrypt all .enc files
    $encryptedFiles = Get-ChildItem -Path $EncryptedFolder -Recurse -Filter "*.enc"
    $decryptedCount = 0

    foreach ($file in $encryptedFiles) {
        try {
            $encryptedBytes = [System.IO.File]::ReadAllBytes($file.FullName)

            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

            # Determine output path
            $relativePath = $file.FullName.Replace($EncryptedFolder, '').TrimStart('\')
            $outputFilePath = Join-Path $Destination $relativePath
            $outputFilePath = $outputFilePath.Replace('.enc', '')

            $outputDir = Split-Path $outputFilePath -Parent
            if (-not (Test-Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }

            [System.IO.File]::WriteAllBytes($outputFilePath, $decryptedBytes)
            $decryptedCount++
        }
        catch {
            Write-DecryptLog "Failed to decrypt file $($file.Name): $($_.Exception.Message)" -Level Warning
        }
    }

    # Copy non-encrypted files
    $otherFiles = Get-ChildItem -Path $EncryptedFolder -Recurse | Where-Object { $_.Extension -ne '.enc' -and $_.Name -ne 'encryption_key_info.json' }
    foreach ($file in $otherFiles) {
        if (-not $file.PSIsContainer) {
            $relativePath = $file.FullName.Replace($EncryptedFolder, '').TrimStart('\')
            $outputFilePath = Join-Path $Destination $relativePath
            $outputDir = Split-Path $outputFilePath -Parent
            if (-not (Test-Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }
            Copy-Item $file.FullName -Destination $outputFilePath -Force
        }
    }

    $aes.Dispose()

    Write-DecryptLog "Azure Key Vault decryption completed: $decryptedCount files decrypted" -Level Success
}

# Main Execution
try {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   M&A Audit Data Decryption Utility" -ForegroundColor Cyan
    Write-Host "   Author: Adrian Johnson" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    # Validate inputs
    if (-not (Test-Path $EncryptedPath)) {
        throw "Encrypted path not found: $EncryptedPath"
    }

    if (Test-Path $OutputPath) {
        $response = Read-Host "Output path already exists. Overwrite? (y/n)"
        if ($response -ne 'y') {
            Write-DecryptLog "Decryption cancelled by user" -Level Warning
            exit
        }
    } else {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Perform decryption based on method
    switch ($DecryptionMethod) {
        'EFS' {
            Decrypt-EFSFolder -Path $EncryptedPath -Destination $OutputPath
        }
        'Archive' {
            Decrypt-ArchiveFile -ArchivePath $EncryptedPath -Destination $OutputPath
        }
        'KeyVault' {
            if (-not $KeyVaultName -or -not $KeyName) {
                # Try to read from metadata
                $keyInfoPath = Join-Path $EncryptedPath "encryption_key_info.json"
                if (Test-Path $keyInfoPath) {
                    $keyInfo = Get-Content $keyInfoPath | ConvertFrom-Json
                    $KeyVaultName = $keyInfo.KeyVaultName
                    $KeyName = $keyInfo.KeyName
                } else {
                    throw "KeyVaultName and KeyName are required for KeyVault decryption"
                }
            }
            Decrypt-KeyVaultFiles -EncryptedFolder $EncryptedPath -Destination $OutputPath
        }
    }

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   Decryption Completed Successfully!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Decrypted data location:" -ForegroundColor Cyan
    Write-Host "  $OutputPath" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "   Decryption Failed!" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Yellow
    exit 1
}

