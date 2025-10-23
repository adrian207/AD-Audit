<#
.SYNOPSIS
    Integration tests for Ad-Audit workflow
.DESCRIPTION
    End-to-end integration tests for complete audit workflow
.NOTES
    These tests require longer execution time and may interact with mocked external systems
#>

BeforeAll {
    $script:TestOutputDir = Join-Path $TestDrive "IntegrationTests"
    New-Item -ItemType Directory -Path $script:TestOutputDir -Force | Out-Null
    
    # Mock all external cmdlets
    Mock Get-ADForest { [PSCustomObject]@{ Name = 'test.local'; RootDomain = 'test.local' } }
    Mock Get-ADDomain { [PSCustomObject]@{ DomainMode = 'Windows2016Domain' } }
    Mock Get-ADUser { @() }
    Mock Get-ADComputer { @() }
    Mock Get-ADGroup { @() }
    Mock Export-Csv { }
    Mock Import-Csv { @() }
}

Describe "End-to-End Workflow Tests" -Tag "Integration" {
    Context "SQLite Database Creation and Import" {
        It "Should create database and import CSV data successfully" {
            # Load SQLite library
            $sqliteScript = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
            . $sqliteScript
            
            # Create in-memory database
            $connection = Initialize-AuditDatabase -DatabasePath ":memory:" -InMemory
            
            $connection | Should -Not -BeNullOrEmpty
            $connection.State | Should -Be 'Open'
            
            # Create test data
            $testUsers = @(
                [PSCustomObject]@{
                    SamAccountName = 'testuser'
                    UserPrincipalName = 'testuser@test.com'
                    DisplayName = 'Test User'
                    Email = 'testuser@test.com'
                    Enabled = $true
                    Created = (Get-Date).ToString('yyyy-MM-dd')
                    LastLogonDate = (Get-Date).ToString('yyyy-MM-dd')
                    PasswordLastSet = (Get-Date).ToString('yyyy-MM-dd')
                    PasswordNeverExpires = $false
                    DaysSinceLastLogon = 5
                    Department = 'IT'
                    Title = 'Engineer'
                    Manager = 'CN=Boss,DC=test,DC=com'
                    IsStale = 'False'
                }
            )
            
            $mapping = @{
                SamAccountName = 'SamAccountName'
                UserPrincipalName = 'UserPrincipalName'
                DisplayName = 'DisplayName'
                Email = 'Email'
                Enabled = 'Enabled'
                Created = 'Created'
                LastLogonDate = 'LastLogonDate'
                PasswordLastSet = 'PasswordLastSet'
                PasswordNeverExpires = 'PasswordNeverExpires'
                DaysSinceLastLogon = 'DaysSinceLastLogon'
                Department = 'Department'
                Title = 'Title'
                Manager = 'Manager'
            }
            
            $mapping.IsStale = 'IsStale'
            
            # Import data
            $imported = Import-CSVToTable -Connection $connection -TableName 'Users' -Data $testUsers -ColumnMapping $mapping
            
            $imported | Should -Be 1
            
            # Query data
            $query = "SELECT * FROM Users WHERE SamAccountName='testuser'"
            $result = Invoke-AuditQuery -Connection $connection -Query $query
            
            $result | Should -Not -BeNullOrEmpty
            $result[0].DisplayName | Should -Be 'Test User'
            $result[0].Department | Should -Be 'IT'
            
            $connection.Close()
        }
    }
    
    Context "Multi-Table Data Relationships" {
        It "Should maintain referential relationships between tables" {
            $sqliteScript = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
            . $sqliteScript
            
            $connection = Initialize-AuditDatabase -DatabasePath ":memory:" -InMemory
            
            # Insert user
            $users = @(
                [PSCustomObject]@{
                    Name = 'admin1'
                    Email = 'admin1@test.com'
                    Active = $true
                }
            )
            Import-CSVToTable -Connection $connection -TableName 'Users' -Data $users -ColumnMapping @{ SamAccountName='Name'; Email='Email'; Enabled='Active' }
            
            # Insert privileged account record
            $privAccounts = @(
                [PSCustomObject]@{
                    MemberSam = 'admin1'
                    MemberName = 'Administrator 1'
                    Group = 'Domain Admins'
                    Type = 'user'
                }
            )
            Import-CSVToTable -Connection $connection -TableName 'PrivilegedAccounts' -Data $privAccounts -ColumnMapping @{ MemberSamAccountName='MemberSam'; MemberName='MemberName'; GroupName='Group'; MemberType='Type' }
            
            # Query with JOIN
            $query = @"
SELECT u.SamAccountName, u.Email, p.GroupName
FROM Users u
INNER JOIN PrivilegedAccounts p ON u.SamAccountName = p.MemberSamAccountName
WHERE p.GroupName = 'Domain Admins'
"@
            
            $result = Invoke-AuditQuery -Connection $connection -Query $query
            
            $result | Should -Not -BeNullOrEmpty
            $result[0].SamAccountName | Should -Be 'admin1'
            $result[0].GroupName | Should -Be 'Domain Admins'
            
            $connection.Close()
        }
    }
    
    Context "Complex Query Scenarios" {
        It "Should execute complex analytical queries" {
            $sqliteScript = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
            . $sqliteScript
            
            $connection = Initialize-AuditDatabase -DatabasePath ":memory:" -InMemory
            
            # Insert test servers with various specs
            $servers = @(
                [PSCustomObject]@{ Name='SRV01'; Online=$true; CPUCores=8; MemoryGB=32; IsVirtual=$true; Hypervisor='VMware' }
                [PSCustomObject]@{ Name='SRV02'; Online=$true; CPUCores=16; MemoryGB=64; IsVirtual=$true; Hypervisor='Hyper-V' }
                [PSCustomObject]@{ Name='SRV03'; Online=$true; CPUCores=4; MemoryGB=16; IsVirtual=$false; Hypervisor='' }
                [PSCustomObject]@{ Name='SRV04'; Online=$false; CPUCores=8; MemoryGB=32; IsVirtual=$true; Hypervisor='VMware' }
            )
            
            $mapping = @{ ServerName='Name'; Online='Online'; CPUCores='CPUCores'; MemoryGB='MemoryGB'; IsVirtual='IsVirtual'; Hypervisor='Hypervisor' }
            Import-CSVToTable -Connection $connection -TableName 'Servers' -Data $servers -ColumnMapping $mapping
            
            # Complex aggregation query
            $query = @"
SELECT 
    Hypervisor,
    COUNT(*) as ServerCount,
    SUM(CPUCores) as TotalCores,
    SUM(MemoryGB) as TotalMemoryGB,
    AVG(CPUCores) as AvgCores,
    AVG(MemoryGB) as AvgMemoryGB
FROM Servers
WHERE IsVirtual = 1 AND Online = 1
GROUP BY Hypervisor
ORDER BY ServerCount DESC
"@
            
            $result = Invoke-AuditQuery -Connection $connection -Query $query
            
            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -Be 2  # VMware and Hyper-V
            
            $vmware = $result | Where-Object { $_.Hypervisor -eq 'VMware' }
            $vmware.ServerCount | Should -Be 1
            $vmware.TotalCores | Should -Be 8
            
            $connection.Close()
        }
    }
}

Describe "Error Handling and Edge Cases" -Tag "Integration" {
    Context "Database Error Handling" {
        It "Should handle connection failures gracefully" {
            $sqliteScript = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
            . $sqliteScript
            
            # Try to connect to invalid path
            { Initialize-AuditDatabase -DatabasePath "Z:\Invalid\Path\db.sqlite" } | Should -Throw
        }
        
        It "Should handle SQL injection attempts safely" {
            $sqliteScript = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
            . $sqliteScript
            
            $connection = Initialize-AuditDatabase -DatabasePath ":memory:" -InMemory
            
            # Insert safe data
            $users = @(
                [PSCustomObject]@{ Name = 'testuser'; Email = 'test@test.com'; Active = $true }
            )
            Import-CSVToTable -Connection $connection -TableName 'Users' -Data $users -ColumnMapping @{ SamAccountName='Name'; Email='Email'; Enabled='Active' }
            
            # Attempt SQL injection via parameters (should be safely escaped)
            $maliciousInput = "admin' OR '1'='1"
            $query = "SELECT * FROM Users WHERE SamAccountName = @username"
            
            $result = Invoke-AuditQuery -Connection $connection -Query $query -Parameters @{ username = $maliciousInput }
            
            # Should return no results (injection blocked)
            $result.Count | Should -Be 0
            
            $connection.Close()
        }
    }
    
    Context "Data Validation" {
        It "Should handle malformed CSV data" {
            $sqliteScript = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
            . $sqliteScript
            
            $connection = Initialize-AuditDatabase -DatabasePath ":memory:" -InMemory
            
            # Data with missing required fields
            $badData = @(
                [PSCustomObject]@{ Name = 'incomplete'; Email = $null }
            )
            
            # Should not throw, but handle nulls gracefully
            { Import-CSVToTable -Connection $connection -TableName 'Users' -Data $badData -ColumnMapping @{ SamAccountName='Name'; Email='Email' } } | Should -Not -Throw
            
            $connection.Close()
        }
        
        It "Should handle large datasets efficiently" {
            $sqliteScript = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
            . $sqliteScript
            
            $connection = Initialize-AuditDatabase -DatabasePath ":memory:" -InMemory
            
            # Generate 1000 test records
            $largeDataset = 1..1000 | ForEach-Object {
                [PSCustomObject]@{
                    Name = "user$_"
                    Email = "user$_@test.com"
                    Active = ($_ % 2 -eq 0)
                }
            }
            
            $startTime = Get-Date
            $imported = Import-CSVToTable -Connection $connection -TableName 'Users' -Data $largeDataset -ColumnMapping @{ SamAccountName='Name'; Email='Email'; Enabled='Active' }
            $duration = (Get-Date) - $startTime
            
            $imported | Should -Be 1000
            $duration.TotalSeconds | Should -BeLessThan 30  # Should complete within 30 seconds
            
            # Verify count
            $query = "SELECT COUNT(*) as Count FROM Users"
            $result = Invoke-AuditQuery -Connection $connection -Query $query
            $result[0].Count | Should -Be 1000
            
            $connection.Close()
        }
    }
}

Describe "Performance Tests" -Tag "Integration", "Performance" {
    Context "Query Performance" {
        It "Should execute indexed queries efficiently" {
            $sqliteScript = Join-Path $PSScriptRoot "..\Libraries\SQLite-AuditDB.ps1"
            . $sqliteScript
            
            $connection = Initialize-AuditDatabase -DatabasePath ":memory:" -InMemory
            
            # Insert 10,000 users
            $users = 1..10000 | ForEach-Object {
                [PSCustomObject]@{
                    Name = "user$_"
                    Email = "user$_@test.com"
                    Active = ($_ % 2 -eq 0)
                    Dept = "Department$(($_ % 10) + 1)"
                    IsStale = ($_ % 5 -eq 0)
                }
            }
            
            Import-CSVToTable -Connection $connection -TableName 'Users' -Data $users -ColumnMapping @{ 
                SamAccountName='Name'
                Email='Email'
                Enabled='Active'
                Department='Dept'
                IsStale='IsStale'
            }
            
            # Query using index (idx_users_stale ON Users(IsStale, Enabled))
            $startTime = Get-Date
            $query = "SELECT * FROM Users WHERE IsStale = 1 AND Enabled = 1"
            $result = Invoke-AuditQuery -Connection $connection -Query $query
            $duration = (Get-Date) - $startTime
            
            $result | Should -Not -BeNullOrEmpty
            $duration.TotalMilliseconds | Should -BeLessThan 1000  # Should complete within 1 second
            
            $connection.Close()
        }
    }
}

