@{
    # Test execution configuration
    Run = @{
        Path = @('.')
        ExcludePath = @()
        ScriptBlock = $null
        Container = $null
        TestExtension = '.Tests.ps1'
        Exit = $false
        Throw = $false
        PassThru = $true
        SkipRun = $false
    }
    
    # Filter configuration
    Filter = @{
        Tag = @()
        ExcludeTag = @()
        Line = @()
        FullName = @()
    }
    
    # Code coverage configuration
    CodeCoverage = @{
        Enabled = $false
        OutputFormat = 'JaCoCo'
        OutputPath = 'coverage.xml'
        OutputEncoding = 'UTF8'
        Path = @(
            '../Libraries/*.ps1'
            '../Modules/*.ps1'
        )
        ExcludeTests = $true
        RecursePaths = $true
        CoveragePercentTarget = 75
        UseBreakpoints = $true
    }
    
    # Test result configuration
    TestResult = @{
        Enabled = $false
        OutputFormat = 'NUnitXml'
        OutputPath = 'TestResults/TestResults.xml'
        OutputEncoding = 'UTF8'
        TestSuiteName = 'Ad-Audit Pester Tests'
    }
    
    # Should configuration
    Should = @{
        ErrorAction = 'Stop'
    }
    
    # Debug configuration
    Debug = @{
        ShowFullErrors = $false
        WriteDebugMessages = $false
        WriteDebugMessagesFrom = @()
        ShowNavigationMarkers = $false
        ReturnRawResultObject = $false
    }
    
    # Output configuration
    Output = @{
        Verbosity = 'Detailed'
        StackTraceVerbosity = 'Filtered'
        CIFormat = 'Auto'
        CILogLevel = 'Error'
    }
    
    # Test drive configuration (for TestDrive:\ usage)
    TestDrive = @{
        Enabled = $true
    }
    
    # Test registry configuration (for TestRegistry:\ usage)
    TestRegistry = @{
        Enabled = $false
    }
}

