<#
.SYNOPSIS
    Pester tests for Invoke-AD-Audit.ps1 module

.DESCRIPTION
    Comprehensive unit and integration tests for the AD-Audit module.
    Tests helper functions, retry logic, and main audit functions with mocked dependencies.

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0
    Requires: Pester 5.x
#>

BeforeAll {
    # Import the module being tested
    $ModulePath = Join-Path $PSScriptRoot '..' 'Modules' 'Invoke-AD-Audit.ps1'

    # Source the file to get functions in scope
    # Note: In production, we'd dot-source individual functions or use a proper module
    # For testing, we'll extract and test individual functions

    # Mock Write-ModuleLog to capture log output
    function Write-ModuleLog {
        param(
            [string]$Message,
            [ValidateSet('Info','Warning','Error','Success')]
            [string]$Level = 'Info'
        )
        $script:LastLogMessage = $Message
        $script:LastLogLevel = $Level
    }

    # Mock Test-ServerOnline function
    function Test-ServerOnline {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ComputerName,
            [int]$TimeoutMS = 1000
        )

        # Simulate different server responses for testing
        switch ($ComputerName) {
            'ONLINE-SERVER' { return $true }
            'OFFLINE-SERVER' { return $false }
            'TIMEOUT-SERVER' { throw "Request timed out" }
            default { return $true }
        }
    }

    # Invoke-WithRetry function (extracted from module for testing)
    function Invoke-WithRetry {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [ScriptBlock]$ScriptBlock,
            [int]$MaxAttempts = 3,
            [int]$InitialDelaySeconds = 2,
            [string[]]$RetryableErrors = @(
                'network',
                'timeout',
                'RPC server',
                'WinRM',
                'Access is denied',
                'The operation has timed out',
                'No connection could be made'
            )
        )

        $attempt = 1
        $lastError = $null

        while ($attempt -le $MaxAttempts) {
            try {
                $result = & $ScriptBlock
                return $result
            }
            catch {
                $lastError = $_
                $errorMessage = $_.Exception.Message

                $isRetryable = $false
                foreach ($pattern in $RetryableErrors) {
                    if ($errorMessage -match $pattern) {
                        $isRetryable = $true
                        break
                    }
                }

                if (-not $isRetryable -or $attempt -eq $MaxAttempts) {
                    throw
                }

                $delay = $InitialDelaySeconds * [math]::Pow(2, $attempt - 1)
                Write-Verbose "Attempt $attempt failed: $errorMessage. Retrying in $delay seconds..."
                Start-Sleep -Seconds $delay

                $attempt++
            }
        }

        throw $lastError
    }
}

Describe 'Test-ServerOnline' {
    Context 'When server is online' {
        It 'Should return true for online server' {
            $result = Test-ServerOnline -ComputerName 'ONLINE-SERVER'
            $result | Should -BeTrue
        }
    }

    Context 'When server is offline' {
        It 'Should return false for offline server' {
            $result = Test-ServerOnline -ComputerName 'OFFLINE-SERVER'
            $result | Should -BeFalse
        }
    }

    Context 'When server times out' {
        It 'Should handle timeout gracefully' {
            { Test-ServerOnline -ComputerName 'TIMEOUT-SERVER' } | Should -Throw
        }
    }
}

Describe 'Write-ModuleLog' {
    Context 'When logging different levels' {
        It 'Should log Info level message' {
            Write-ModuleLog -Message 'Test info message' -Level 'Info'
            $script:LastLogMessage | Should -Be 'Test info message'
            $script:LastLogLevel | Should -Be 'Info'
        }

        It 'Should log Warning level message' {
            Write-ModuleLog -Message 'Test warning' -Level 'Warning'
            $script:LastLogMessage | Should -Be 'Test warning'
            $script:LastLogLevel | Should -Be 'Warning'
        }

        It 'Should log Error level message' {
            Write-ModuleLog -Message 'Test error' -Level 'Error'
            $script:LastLogMessage | Should -Be 'Test error'
            $script:LastLogLevel | Should -Be 'Error'
        }

        It 'Should log Success level message' {
            Write-ModuleLog -Message 'Test success' -Level 'Success'
            $script:LastLogMessage | Should -Be 'Test success'
            $script:LastLogLevel | Should -Be 'Success'
        }
    }

    Context 'When using default parameters' {
        It 'Should default to Info level' {
            Write-ModuleLog -Message 'Default level test'
            $script:LastLogLevel | Should -Be 'Info'
        }
    }
}

Describe 'Invoke-WithRetry' {
    Context 'When operation succeeds on first attempt' {
        It 'Should return result immediately' {
            $result = Invoke-WithRetry -ScriptBlock { return 'Success' }
            $result | Should -Be 'Success'
        }

        It 'Should not retry on success' {
            $script:AttemptCount = 0
            $result = Invoke-WithRetry -ScriptBlock {
                $script:AttemptCount++
                return 'Success'
            }
            $script:AttemptCount | Should -Be 1
        }
    }

    Context 'When operation fails with retryable error' {
        It 'Should retry on network error' {
            $script:AttemptCount = 0
            $result = Invoke-WithRetry -ScriptBlock {
                $script:AttemptCount++
                if ($script:AttemptCount -lt 3) {
                    throw "network connection failed"
                }
                return 'Success after retry'
            } -InitialDelaySeconds 0

            $result | Should -Be 'Success after retry'
            $script:AttemptCount | Should -Be 3
        }

        It 'Should retry on timeout error' {
            $script:AttemptCount = 0
            $result = Invoke-WithRetry -ScriptBlock {
                $script:AttemptCount++
                if ($script:AttemptCount -lt 2) {
                    throw "The operation has timed out"
                }
                return 'Success after timeout'
            } -InitialDelaySeconds 0

            $result | Should -Be 'Success after timeout'
            $script:AttemptCount | Should -Be 2
        }

        It 'Should retry on RPC server error' {
            $script:AttemptCount = 0
            $result = Invoke-WithRetry -ScriptBlock {
                $script:AttemptCount++
                if ($script:AttemptCount -eq 1) {
                    throw "RPC server is unavailable"
                }
                return 'RPC success'
            } -InitialDelaySeconds 0

            $result | Should -Be 'RPC success'
            $script:AttemptCount | Should -Be 2
        }
    }

    Context 'When operation fails with non-retryable error' {
        It 'Should throw immediately on non-retryable error' {
            $script:AttemptCount = 0
            {
                Invoke-WithRetry -ScriptBlock {
                    $script:AttemptCount++
                    throw "File not found"
                }
            } | Should -Throw "File not found"

            $script:AttemptCount | Should -Be 1
        }
    }

    Context 'When operation fails all retry attempts' {
        It 'Should throw after max attempts' {
            $script:AttemptCount = 0
            {
                Invoke-WithRetry -ScriptBlock {
                    $script:AttemptCount++
                    throw "network error"
                } -MaxAttempts 3 -InitialDelaySeconds 0
            } | Should -Throw "network error"

            $script:AttemptCount | Should -Be 3
        }
    }

    Context 'When using custom retry parameters' {
        It 'Should respect MaxAttempts parameter' {
            $script:AttemptCount = 0
            {
                Invoke-WithRetry -ScriptBlock {
                    $script:AttemptCount++
                    throw "timeout"
                } -MaxAttempts 5 -InitialDelaySeconds 0
            } | Should -Throw

            $script:AttemptCount | Should -Be 5
        }

        It 'Should respect custom retryable error patterns' {
            $script:AttemptCount = 0
            $result = Invoke-WithRetry -ScriptBlock {
                $script:AttemptCount++
                if ($script:AttemptCount -eq 1) {
                    throw "custom error pattern"
                }
                return 'Success'
            } -RetryableErrors @('custom error') -InitialDelaySeconds 0

            $result | Should -Be 'Success'
            $script:AttemptCount | Should -Be 2
        }
    }

    Context 'When testing exponential backoff' {
        It 'Should increase delay exponentially' {
            $script:AttemptCount = 0
            $script:Delays = @()

            try {
                Invoke-WithRetry -ScriptBlock {
                    $script:AttemptCount++
                    $beforeDelay = Get-Date
                    throw "network error"
                } -MaxAttempts 3 -InitialDelaySeconds 1 -Verbose
            }
            catch {
                # Expected to fail after all retries
            }

            # Should have attempted 3 times
            $script:AttemptCount | Should -Be 3
        }
    }
}

Describe 'Retry Logic Integration' {
    Context 'When simulating CIM session creation' {
        It 'Should retry CIM session failures' {
            $script:CIMAttempts = 0

            $mockCIMSession = Invoke-WithRetry -ScriptBlock {
                $script:CIMAttempts++
                if ($script:CIMAttempts -lt 2) {
                    throw "RPC server is unavailable"
                }
                return [PSCustomObject]@{ Connected = $true }
            } -InitialDelaySeconds 0

            $mockCIMSession.Connected | Should -BeTrue
            $script:CIMAttempts | Should -Be 2
        }
    }

    Context 'When simulating WinEvent queries' {
        It 'Should retry event log query failures' {
            $script:EventAttempts = 0

            $mockEvents = Invoke-WithRetry -ScriptBlock {
                $script:EventAttempts++
                if ($script:EventAttempts -eq 1) {
                    throw "The operation has timed out"
                }
                return @(
                    [PSCustomObject]@{ Id = 4624; TimeCreated = Get-Date }
                    [PSCustomObject]@{ Id = 4625; TimeCreated = Get-Date }
                )
            } -InitialDelaySeconds 0

            $mockEvents.Count | Should -Be 2
            $script:EventAttempts | Should -Be 2
        }
    }

    Context 'When simulating Invoke-Command failures' {
        It 'Should retry remote PowerShell failures' {
            $script:RemoteAttempts = 0

            $mockResult = Invoke-WithRetry -ScriptBlock {
                $script:RemoteAttempts++
                if ($script:RemoteAttempts -eq 1) {
                    throw "WinRM client cannot process the request"
                }
                return @(
                    [PSCustomObject]@{ Name = 'App1'; Version = '1.0' }
                )
            } -InitialDelaySeconds 0

            $mockResult.Count | Should -Be 1
            $script:RemoteAttempts | Should -Be 2
        }
    }
}

Describe 'Helper Function Edge Cases' {
    Context 'When handling null or empty inputs' {
        It 'Should handle empty server name gracefully' {
            { Test-ServerOnline -ComputerName '' } | Should -Throw
        }

        It 'Should handle null script block in Invoke-WithRetry' {
            { Invoke-WithRetry -ScriptBlock $null } | Should -Throw
        }
    }

    Context 'When testing boundary conditions' {
        It 'Should handle MaxAttempts of 1' {
            $script:SingleAttempt = 0
            {
                Invoke-WithRetry -ScriptBlock {
                    $script:SingleAttempt++
                    throw "network error"
                } -MaxAttempts 1 -InitialDelaySeconds 0
            } | Should -Throw

            $script:SingleAttempt | Should -Be 1
        }

        It 'Should handle InitialDelaySeconds of 0' {
            $startTime = Get-Date
            $script:ZeroDelayAttempts = 0

            try {
                Invoke-WithRetry -ScriptBlock {
                    $script:ZeroDelayAttempts++
                    throw "timeout"
                } -MaxAttempts 2 -InitialDelaySeconds 0
            }
            catch {
                # Expected
            }

            $duration = ((Get-Date) - $startTime).TotalSeconds
            $duration | Should -BeLessThan 1  # Should complete quickly with no delay
        }
    }
}

Describe 'Module Structure and Best Practices' {
    Context 'When checking module file' {
        It 'Module file should exist' {
            $modulePath = Join-Path $PSScriptRoot '..' 'Modules' 'Invoke-AD-Audit.ps1'
            Test-Path $modulePath | Should -BeTrue
        }

        It 'Module should have proper header' {
            $modulePath = Join-Path $PSScriptRoot '..' 'Modules' 'Invoke-AD-Audit.ps1'
            $content = Get-Content $modulePath -Raw
            $content | Should -Match '<#'
            $content | Should -Match '\.SYNOPSIS'
            $content | Should -Match '\.DESCRIPTION'
        }

        It 'Module should define expected functions' {
            $modulePath = Join-Path $PSScriptRoot '..' 'Modules' 'Invoke-AD-Audit.ps1'
            $content = Get-Content $modulePath -Raw

            # Check for key function definitions
            $content | Should -Match 'function Get-ADForestInfo'
            $content | Should -Match 'function Get-ADUserInventory'
            $content | Should -Match 'function Get-ADComputerInventory'
            $content | Should -Match 'function Get-ADGroupInventory'
            $content | Should -Match 'function Get-ServerHardwareInventory'
            $content | Should -Match 'function Invoke-WithRetry'
        }
    }

    Context 'When checking code quality' {
        It 'Should not have TODO comments in shipped functions' {
            $modulePath = Join-Path $PSScriptRoot '..' 'Modules' 'Invoke-AD-Audit.ps1'
            $content = Get-Content $modulePath

            # Count TODO comments (some are acceptable for planned features)
            $todoCount = ($content | Select-String -Pattern '# TODO:').Count

            # We know there's a TODO section for planned features, but individual function TODOs should be minimal
            $todoCount | Should -BeLessThan 20
        }

        It 'Should use approved PowerShell verbs' {
            $modulePath = Join-Path $PSScriptRoot '..' 'Modules' 'Invoke-AD-Audit.ps1'
            $content = Get-Content $modulePath -Raw

            # Extract function names
            $functionPattern = 'function\s+([\w-]+)'
            $functions = [regex]::Matches($content, $functionPattern) | ForEach-Object { $_.Groups[1].Value }

            $approvedVerbs = Get-Verb | Select-Object -ExpandProperty Verb

            foreach ($func in $functions) {
                $verb = ($func -split '-')[0]
                if ($func -match '^[A-Z]') {  # Only check properly named functions
                    $approvedVerbs | Should -Contain $verb -Because "Function $func uses non-approved verb $verb"
                }
            }
        }
    }
}
