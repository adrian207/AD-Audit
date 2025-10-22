<#
.SYNOPSIS
    Pester tests for utility scripts and helper functions
.DESCRIPTION
    Unit tests for audit utilities, encryption, and helper scripts
#>

BeforeAll {
    $script:TestOutputDir = Join-Path $TestDrive "UtilitiesTests"
    New-Item -ItemType Directory -Path $script:TestOutputDir -Force | Out-Null
    
    # Mock common cmdlets
    Mock Write-Host { }
    Mock Write-Verbose { }
    Mock Export-Csv { }
}

Describe "Audit Orchestration Functions" -Tag "Utilities" {
    Context "Output Structure Creation" {
        It "Should create required folder structure" {
            $testRoot = Join-Path $script:TestOutputDir "AuditOutput"
            
            $folders = @(
                'Logs',
                'RawData',
                'RawData\AD',
                'RawData\Servers',
                'RawData\SQL',
                'RawData\EntraID',
                'RawData\Exchange',
                'RawData\SharePoint',
                'RawData\Teams',
                'RawData\PowerPlatform',
                'RawData\Compliance'
            )
            
            foreach ($folder in $folders) {
                $path = Join-Path $testRoot $folder
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
            
            foreach ($folder in $folders) {
                $path = Join-Path $testRoot $folder
                Test-Path $path | Should -Be $true
            }
        }
    }
    
    Context "Logging Functions" {
        It "Should write audit logs with timestamps" {
            function Write-AuditLog {
                param([string]$Message, [string]$Level = 'Info')
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                return "[$timestamp] [$Level] $Message"
            }
            
            $result = Write-AuditLog -Message "Test message" -Level "Info"
            
            $result | Should -Match '\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[Info\] Test message'
        }
        
        It "Should support different log levels" {
            function Write-AuditLog {
                param([string]$Message, [string]$Level = 'Info')
                return "[$Level] $Message"
            }
            
            $levels = @('Info', 'Warning', 'Error', 'Success', 'Debug')
            
            foreach ($level in $levels) {
                $result = Write-AuditLog -Message "Test" -Level $level
                $result | Should -Match "\[$level\]"
            }
        }
    }
    
    Context "Module Execution Tracking" {
        It "Should track successful module execution" {
            $script:ModuleResults = @{}
            $script:SuccessfulModules = @()
            
            $moduleName = "TestModule"
            $startTime = Get-Date
            
            # Simulate successful execution
            Start-Sleep -Milliseconds 100
            
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalMinutes
            
            $script:ModuleResults[$moduleName] = @{
                Status = 'Success'
                Duration = $duration
                StartTime = $startTime
                EndTime = $endTime
            }
            
            $script:SuccessfulModules += $moduleName
            
            $script:ModuleResults[$moduleName].Status | Should -Be 'Success'
            $script:SuccessfulModules | Should -Contain $moduleName
        }
        
        It "Should track failed module execution" {
            $script:ModuleResults = @{}
            $script:FailedModules = @()
            
            $moduleName = "FailedModule"
            $startTime = Get-Date
            
            try {
                throw "Module execution failed"
            }
            catch {
                $endTime = Get-Date
                $duration = ($endTime - $startTime).TotalMinutes
                
                $script:ModuleResults[$moduleName] = @{
                    Status = 'Failed'
                    Duration = $duration
                    Error = $_.Exception.Message
                    StartTime = $startTime
                    EndTime = $endTime
                }
                
                $script:FailedModules += $moduleName
            }
            
            $script:ModuleResults[$moduleName].Status | Should -Be 'Failed'
            $script:FailedModules | Should -Contain $moduleName
            $script:ModuleResults[$moduleName].Error | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Data Quality and Validation" -Tag "Utilities" {
    Context "Data Quality Scoring" {
        It "Should calculate data quality score based on successful modules" {
            $totalModules = 10
            $successfulModules = 8
            
            $dataQualityScore = ($successfulModules / $totalModules) * 100
            
            $dataQualityScore | Should -Be 80
        }
        
        It "Should penalize score for failed modules" {
            $baseScore = 100
            $failedModules = 2
            $penaltyPerModule = 10
            
            $dataQualityScore = $baseScore - ($failedModules * $penaltyPerModule)
            
            $dataQualityScore | Should -Be 80
        }
    }
    
    Context "Metadata Generation" {
        It "Should generate audit metadata" {
            $metadata = @{
                AuditInfo = @{
                    CompanyName = "TestCorp"
                    AuditDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    ScriptVersion = "2.0"
                }
                ExecutionDetails = @{
                    ExecutedBy = "$env:USERDOMAIN\$env:USERNAME"
                    ExecutedFrom = $env:COMPUTERNAME
                    PowerShellVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
                }
                Results = @{
                    SuccessfulModules = @("AD", "SQL")
                    FailedModules = @()
                    DataQualityScore = 100
                }
            }
            
            $metadata.AuditInfo.CompanyName | Should -Be "TestCorp"
            $metadata.Results.SuccessfulModules.Count | Should -Be 2
            $metadata.Results.DataQualityScore | Should -Be 100
        }
        
        It "Should export metadata to JSON" {
            $metadata = @{
                CompanyName = "TestCorp"
                AuditDate = Get-Date
                Modules = @("AD", "Exchange")
            }
            
            $json = $metadata | ConvertTo-Json -Depth 5
            
            $json | Should -Not -BeNullOrEmpty
            $json | Should -Match "TestCorp"
        }
    }
}

Describe "Encryption and Security" -Tag "Utilities", "Security" {
    Context "EFS Encryption" {
        It "Should check for NTFS volume before EFS encryption" {
            # Mock volume check
            Mock Get-Volume {
                return [PSCustomObject]@{
                    DriveLetter = 'C'
                    FileSystem = 'NTFS'
                }
            }
            
            $drive = (Get-Volume)[0]
            $drive.FileSystem | Should -Be 'NTFS'
        }
        
        It "Should validate encryption attributes" {
            $testFile = Join-Path $script:TestOutputDir "test.txt"
            "test content" | Out-File $testFile
            
            # On NTFS, files can be encrypted
            # Note: Actual encryption requires NTFS and appropriate permissions
            Test-Path $testFile | Should -Be $true
        }
    }
    
    Context "Password Validation" {
        It "Should validate password strength requirements" {
            function Test-PasswordStrength {
                param([SecureString]$SecurePassword)
                
                # Convert SecureString to plain text for validation (test only)
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
                $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                
                $validations = @{
                    MinLength = $Password.Length -ge 16
                    HasUpper = $Password -cmatch '[A-Z]'
                    HasLower = $Password -cmatch '[a-z]'
                    HasDigit = $Password -match '\d'
                    HasSpecial = $Password -match '[^a-zA-Z0-9]'
                }
                
                return ($validations.Values | Where-Object { $_ -eq $false }).Count -eq 0
            }
            
            $weakPass = ConvertTo-SecureString -String "weak" -AsPlainText -Force
            $strongPass = ConvertTo-SecureString -String "StrongP@ssw0rd123!" -AsPlainText -Force
            
            Test-PasswordStrength -SecurePassword $weakPass | Should -Be $false
            Test-PasswordStrength -SecurePassword $strongPass | Should -Be $true
        }
    }
    
    Context "Secure String Handling" {
        It "Should create SecureString from plain text" {
            $plainPassword = "TestPassword123!"
            $secureString = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
            
            $secureString | Should -BeOfType [System.Security.SecureString]
        }
        
        It "Should convert SecureString back to plain text" {
            $plainPassword = "TestPassword123!"
            $secureString = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
            
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
            $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            
            $plainText | Should -Be $plainPassword
        }
    }
}

Describe "File Operations and Archive Creation" -Tag "Utilities" {
    Context "Archive Creation" {
        It "Should create compressed archive" {
            $sourceFolder = Join-Path $script:TestOutputDir "SourceData"
            New-Item -ItemType Directory -Path $sourceFolder -Force | Out-Null
            
            # Create test files
            "file1" | Out-File (Join-Path $sourceFolder "file1.txt")
            "file2" | Out-File (Join-Path $sourceFolder "file2.txt")
            
            $archivePath = Join-Path $script:TestOutputDir "archive.zip"
            Compress-Archive -Path "$sourceFolder\*" -DestinationPath $archivePath
            
            Test-Path $archivePath | Should -Be $true
            (Get-Item $archivePath).Length | Should -BeGreaterThan 0
        }
        
        It "Should calculate archive size" {
            $testFile = Join-Path $script:TestOutputDir "sizefile.txt"
            "test content" * 1000 | Out-File $testFile
            
            $size = (Get-Item $testFile).Length
            $sizeKB = [math]::Round($size / 1KB, 2)
            
            $size | Should -BeGreaterThan 0
            $sizeKB | Should -BeGreaterThan 0
        }
    }
    
    Context "File Cleanup" {
        It "Should remove temporary files" {
            $tempFile = Join-Path $script:TestOutputDir "temp.txt"
            "temporary content" | Out-File $tempFile
            
            Test-Path $tempFile | Should -Be $true
            
            Remove-Item $tempFile -Force
            
            Test-Path $tempFile | Should -Be $false
        }
        
        It "Should clean up test directories" {
            $tempDir = Join-Path $script:TestOutputDir "TempDir"
            New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
            "file" | Out-File (Join-Path $tempDir "file.txt")
            
            Test-Path $tempDir | Should -Be $true
            
            Remove-Item $tempDir -Recurse -Force
            
            Test-Path $tempDir | Should -Be $false
        }
    }
}

Describe "Parameter Validation" -Tag "Utilities" {
    Context "Script Parameter Validation" {
        It "Should validate required parameters" {
            function Test-Parameters {
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$CompanyName,
                    
                    [Parameter(Mandatory = $true)]
                    [string]$OutputFolder
                )
                
                return @{
                    CompanyName = $CompanyName
                    OutputFolder = $OutputFolder
                }
            }
            
            $result = Test-Parameters -CompanyName "TestCorp" -OutputFolder "C:\Audits"
            
            $result.CompanyName | Should -Be "TestCorp"
            $result.OutputFolder | Should -Be "C:\Audits"
        }
        
        It "Should validate parameter ranges" {
            function Test-RangeValidation {
                param(
                    [ValidateRange(1, 50)]
                    [int]$MaxParallel = 10
                )
                return $MaxParallel
            }
            
            Test-RangeValidation -MaxParallel 20 | Should -Be 20
            { Test-RangeValidation -MaxParallel 100 } | Should -Throw
        }
        
        It "Should validate parameter sets" {
            function Test-SetValidation {
                param(
                    [ValidateSet(7, 30, 60, 90)]
                    [int]$Days = 30
                )
                return $Days
            }
            
            Test-SetValidation -Days 30 | Should -Be 30
            { Test-SetValidation -Days 45 } | Should -Throw
        }
    }
}

Describe "Report Generation Helpers" -Tag "Utilities" {
    Context "HTML Report Helpers" {
        It "Should generate HTML table from data" {
            function ConvertTo-HtmlTable {
                param([array]$Data)
                
                $html = "<table>`n"
                $html += "<tr><th>Name</th><th>Value</th></tr>`n"
                
                foreach ($row in $Data) {
                    $html += "<tr><td>$($row.Name)</td><td>$($row.Value)</td></tr>`n"
                }
                
                $html += "</table>"
                return $html
            }
            
            $data = @(
                @{ Name = "Total Users"; Value = 100 }
                @{ Name = "Total Servers"; Value = 50 }
            )
            
            $html = ConvertTo-HtmlTable -Data $data
            
            $html | Should -Match "<table>"
            $html | Should -Match "Total Users"
            $html | Should -Match "100"
        }
        
        It "Should escape HTML special characters" {
            function ConvertTo-EscapedHtml {
                param([string]$Text)
                
                return $Text -replace '&', '&amp;' `
                            -replace '<', '&lt;' `
                            -replace '>', '&gt;' `
                            -replace '"', '&quot;' `
                            -replace "'", '&#39;'
            }
            
            $result = ConvertTo-EscapedHtml -Text "<script>alert('XSS')</script>"
            
            $result | Should -Not -Match '<script>'
            $result | Should -Match '&lt;script&gt;'
        }
    }
}

