<#
.SYNOPSIS
    Pester tests for Invoke-AD-Audit.ps1
.DESCRIPTION
    Unit tests for Active Directory audit module functions
#>

BeforeAll {
    # Mock ActiveDirectory module cmdlets
    Mock Get-ADForest {
        return [PSCustomObject]@{
            Name = 'test.local'
            ForestMode = 'Windows2016Forest'
            Domains = @('test.local', 'child.test.local')
            GlobalCatalogs = @('DC01.test.local', 'DC02.test.local')
            SchemaMaster = 'DC01.test.local'
            DomainNamingMaster = 'DC01.test.local'
            RootDomain = 'test.local'
            RecycleBinEnabled = $true
            UPNSuffixes = @('test.local')
        }
    }
    
    Mock Get-ADDomain {
        return [PSCustomObject]@{
            DomainMode = 'Windows2016Domain'
        }
    }
    
    Mock Get-ADUser {
        return @(
            [PSCustomObject]@{
                SamAccountName = 'testuser1'
                UserPrincipalName = 'testuser1@test.local'
                DisplayName = 'Test User 1'
                Mail = 'testuser1@test.local'
                Enabled = $true
                Created = (Get-Date).AddYears(-2)
                LastLogonDate = (Get-Date).AddDays(-5)
                PasswordLastSet = (Get-Date).AddDays(-30)
                PasswordNeverExpires = $false
                PasswordNotRequired = $false
                AccountExpirationDate = $null
                LockedOut = $false
                Department = 'IT'
                Title = 'Engineer'
                Manager = 'CN=Manager,DC=test,DC=local'
                DistinguishedName = 'CN=testuser1,OU=Users,DC=test,DC=local'
                MemberOf = @('CN=Domain Users,DC=test,DC=local')
                UserAccountControl = 512
            },
            [PSCustomObject]@{
                SamAccountName = 'staleuser'
                UserPrincipalName = 'staleuser@test.local'
                DisplayName = 'Stale User'
                Mail = 'staleuser@test.local'
                Enabled = $true
                Created = (Get-Date).AddYears(-3)
                LastLogonDate = (Get-Date).AddDays(-100)
                PasswordLastSet = (Get-Date).AddDays(-200)
                PasswordNeverExpires = $false
                PasswordNotRequired = $false
                AccountExpirationDate = $null
                LockedOut = $false
                Department = 'Sales'
                Title = 'Rep'
                Manager = 'CN=Manager,DC=test,DC=local'
                DistinguishedName = 'CN=staleuser,OU=Users,DC=test,DC=local'
                MemberOf = @('CN=Domain Users,DC=test,DC=local')
                UserAccountControl = 512
            }
        )
    }
    
    Mock Get-ADComputer {
        return @(
            [PSCustomObject]@{
                Name = 'DESKTOP01'
                DNSHostName = 'desktop01.test.local'
                OperatingSystem = 'Windows 10 Pro'
                OperatingSystemVersion = '10.0.19045'
                Enabled = $true
                Created = (Get-Date).AddYears(-1)
                LastLogonDate = (Get-Date).AddDays(-1)
                PasswordLastSet = (Get-Date).AddDays(-30)
                IPv4Address = '192.168.1.100'
                DistinguishedName = 'CN=DESKTOP01,OU=Computers,DC=test,DC=local'
            },
            [PSCustomObject]@{
                Name = 'SERVER01'
                DNSHostName = 'server01.test.local'
                OperatingSystem = 'Windows Server 2019 Standard'
                OperatingSystemVersion = '10.0.17763'
                Enabled = $true
                Created = (Get-Date).AddYears(-2)
                LastLogonDate = (Get-Date).AddHours(-2)
                PasswordLastSet = (Get-Date).AddDays(-45)
                IPv4Address = '192.168.1.10'
                DistinguishedName = 'CN=SERVER01,OU=Servers,DC=test,DC=local'
            }
        )
    }
    
    Mock Get-ADGroup {
        return @(
            [PSCustomObject]@{
                Name = 'IT Team'
                GroupScope = 'Global'
                GroupCategory = 'Security'
                Description = 'IT Department Group'
                ManagedBy = 'CN=ITManager,DC=test,DC=local'
                Created = (Get-Date).AddYears(-3)
                Modified = (Get-Date).AddMonths(-1)
                DistinguishedName = 'CN=IT Team,OU=Groups,DC=test,DC=local'
            }
        )
    }
    
    Mock Get-ADGroupMember {
        param($Identity)
        return @(
            [PSCustomObject]@{
                Name = 'testuser1'
                SamAccountName = 'testuser1'
                objectClass = 'user'
            }
        )
    }
    
    Mock Get-GPO {
        return @(
            [PSCustomObject]@{
                DisplayName = 'Default Domain Policy'
                Id = [Guid]::NewGuid()
                GpoStatus = 'AllSettingsEnabled'
                CreationTime = (Get-Date).AddYears(-5)
                ModificationTime = (Get-Date).AddMonths(-6)
                Owner = 'BUILTIN\Administrators'
                WmiFilter = $null
                User = @{ DSVersion = 1; SysvolVersion = 1 }
                Computer = @{ DSVersion = 1; SysvolVersion = 1 }
            }
        )
    }
    
    Mock Get-GPOReport {
        return '<GPO><LinksTo><SOMPath>test.local</SOMPath><Enabled>true</Enabled><NoOverride>false</NoOverride></LinksTo></GPO>'
    }
    
    Mock Test-Connection {
        param($ComputerName)
        return $true
    }
    
    Mock New-CimSession {
        return [PSCustomObject]@{
            ComputerName = $ComputerName
        }
    }
    
    Mock Get-CimInstance {
        param($ClassName)
        
        switch ($ClassName) {
            'Win32_ComputerSystem' {
                return [PSCustomObject]@{
                    Manufacturer = 'Dell Inc.'
                    Model = 'PowerEdge R740'
                    NumberOfLogicalProcessors = 16
                    TotalPhysicalMemory = 68719476736
                }
            }
            'Win32_BIOS' {
                return [PSCustomObject]@{
                    SerialNumber = 'ABC123'
                    SMBIOSBIOSVersion = '2.15.0'
                }
            }
            'Win32_Processor' {
                return [PSCustomObject]@{
                    Name = 'Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz'
                    NumberOfCores = 8
                }
            }
            'Win32_OperatingSystem' {
                return [PSCustomObject]@{
                    Caption = 'Microsoft Windows Server 2019 Standard'
                    Version = '10.0.17763'
                    BuildNumber = '17763'
                    InstallDate = (Get-Date).AddYears(-2)
                    LastBootUpTime = (Get-Date).AddDays(-30)
                }
            }
        }
    }
    
    Mock Remove-CimSession { }
    
    Mock Export-Csv { }
    
    # Create test output directories
    $script:TestOutputDir = Join-Path $TestDrive "AuditOutput"
    $script:ADOutputPath = Join-Path $script:TestOutputDir "AD"
    $script:ServerOutputPath = Join-Path $script:TestOutputDir "Servers"
    $script:SQLOutputPath = Join-Path $script:TestOutputDir "SQL"
    
    New-Item -ItemType Directory -Path $script:ADOutputPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:ServerOutputPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:SQLOutputPath -Force | Out-Null
    
    # Initialize script-level variables
    $script:Stats = @{
        TotalUsers = 0
        EnabledUsers = 0
        TotalComputers = 0
        TotalServers = 0
        ServersOnline = 0
        ServersOffline = 0
        SQLInstances = 0
        SQLDatabases = 0
    }
    
    # Source the helper functions from the module (without running the main script)
    $ModulePath = Join-Path $PSScriptRoot "..\Modules\Invoke-AD-Audit.ps1"
    $ModuleContent = Get-Content $ModulePath -Raw
    
    # Extract only the function definitions (skip main execution)
    $FunctionPattern = '(?s)function\s+(\w+-\w+)\s*\{.*?^}'
    $Functions = [regex]::Matches($ModuleContent, $FunctionPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
    
    foreach ($match in $Functions) {
        Invoke-Expression $match.Value
    }
}

Describe "Write-ModuleLog" {
    It "Should accept Info level" {
        { Write-ModuleLog -Message "Test message" -Level Info } | Should -Not -Throw
    }
    
    It "Should accept Warning level" {
        { Write-ModuleLog -Message "Test warning" -Level Warning } | Should -Not -Throw
    }
    
    It "Should accept Error level" {
        { Write-ModuleLog -Message "Test error" -Level Error } | Should -Not -Throw
    }
    
    It "Should accept Success level" {
        { Write-ModuleLog -Message "Test success" -Level Success } | Should -Not -Throw
    }
}

Describe "Test-ServerOnline" {
    It "Should return true for online server" {
        $result = Test-ServerOnline -ComputerName "testserver"
        $result | Should -Be $true
    }
    
    It "Should accept timeout parameter" {
        { Test-ServerOnline -ComputerName "testserver" -TimeoutMS 500 } | Should -Not -Throw
    }
}

Describe "Get-ADForestInfo" {
    It "Should collect forest information" {
        Mock Export-Csv { }
        
        $result = Get-ADForestInfo
        
        $result | Should -Not -BeNullOrEmpty
        $result.ForestName | Should -Be 'test.local'
        $result.RecycleBinEnabled | Should -Be $true
    }
    
    It "Should export to CSV" {
        Mock Export-Csv { } -Verifiable -ParameterFilter {
            $Path -like "*AD_ForestInfo.csv"
        }
        
        Get-ADForestInfo
        
        Should -InvokeVerifiable
    }
    
    It "Should handle errors gracefully" {
        Mock Get-ADForest { throw "Connection failed" }
        
        $result = Get-ADForestInfo
        
        $result | Should -BeNullOrEmpty
    }
}

Describe "Get-ADUserInventory" {
    It "Should collect user inventory" {
        Mock Export-Csv { }
        
        $result = Get-ADUserInventory
        
        $result | Should -Not -BeNullOrEmpty
        $result.Count | Should -Be 2
    }
    
    It "Should calculate DaysSinceLastLogon" {
        Mock Export-Csv { }
        
        $result = Get-ADUserInventory
        
        $result[0].DaysSinceLastLogon | Should -Not -BeNullOrEmpty
        $result[0].DaysSinceLastLogon | Should -BeOfType [int]
    }
    
    It "Should identify stale accounts" {
        Mock Export-Csv { } -ParameterFilter {
            $Path -like "*AD_Users_Stale.csv"
        } -Verifiable
        
        $users = Get-ADUserInventory
        
        Should -InvokeVerifiable
        $users | Should -Not -BeNullOrEmpty
    }
    
    It "Should update script statistics" {
        Mock Export-Csv { }
        
        Get-ADUserInventory
        
        $script:Stats.TotalUsers | Should -BeGreaterThan 0
        $script:Stats.EnabledUsers | Should -BeGreaterThan 0
    }
}

Describe "Get-ADComputerInventory" {
    It "Should collect computer inventory" {
        Mock Export-Csv { }
        
        $result = Get-ADComputerInventory
        
        $result | Should -Not -BeNullOrEmpty
    }
    
    It "Should identify servers" {
        Mock Export-Csv { }
        
        $result = Get-ADComputerInventory
        
        $servers = $result | Where-Object { $_.IsServer }
        $servers | Should -Not -BeNullOrEmpty
    }
    
    It "Should export member servers separately" {
        Mock Export-Csv { } -ParameterFilter {
            $Path -like "*AD_MemberServers.csv"
        } -Verifiable
        
        Get-ADComputerInventory
        
        Should -InvokeVerifiable
    }
    
    It "Should calculate DaysSinceLastLogon correctly" {
        Mock Export-Csv { }
        
        $result = Get-ADComputerInventory
        
        $result[0].DaysSinceLastLogon | Should -Not -BeNullOrEmpty
    }
}

Describe "Get-ADGroupInventory" {
    It "Should collect group inventory" {
        Mock Export-Csv { }
        
        $result = Get-ADGroupInventory
        
        $result | Should -Not -BeNullOrEmpty
        $result[0].Name | Should -Be 'IT Team'
    }
    
    It "Should calculate member count" {
        Mock Export-Csv { }
        
        $result = Get-ADGroupInventory
        
        $result[0].MemberCount | Should -BeGreaterThan 0
    }
    
    It "Should identify empty groups" {
        Mock Get-ADGroup {
            return @(
                [PSCustomObject]@{
                    Name = 'Empty Group'
                    GroupScope = 'Global'
                    GroupCategory = 'Security'
                    Description = ''
                    ManagedBy = $null
                    Created = Get-Date
                    Modified = Get-Date
                    DistinguishedName = 'CN=Empty Group,DC=test,DC=local'
                }
            )
        }
        
        Mock Get-ADGroupMember { return @() }
        
        Mock Export-Csv { } -ParameterFilter {
            $Path -like "*AD_Groups_Empty.csv"
        } -Verifiable
        
        Get-ADGroupInventory
        
        Should -InvokeVerifiable
    }
}

Describe "Get-PrivilegedAccounts" {
    It "Should collect privileged accounts" {
        Mock Get-ADGroup {
            param($Filter)
            return [PSCustomObject]@{
                Name = 'Domain Admins'
                DistinguishedName = 'CN=Domain Admins,CN=Users,DC=test,DC=local'
            }
        }
        
        Mock Export-Csv { }
        
        $result = Get-PrivilegedAccounts
        
        $result | Should -Not -BeNullOrEmpty
    }
    
    It "Should query all standard privileged groups" {
        Mock Get-ADGroup { return $null } -Verifiable
        Mock Export-Csv { }
        
        $result = Get-PrivilegedAccounts
        
        # Should attempt to query each privileged group
        Should -Invoke Get-ADGroup -Times 8
        $result | Should -BeNullOrEmpty
    }
    
    It "Should handle missing groups gracefully" {
        Mock Get-ADGroup { return $null }
        Mock Export-Csv { }
        
        { Get-PrivilegedAccounts } | Should -Not -Throw
    }
}

Describe "Get-GPOInventory" {
    It "Should collect GPO information" {
        Mock Export-Csv { }
        
        $gpos = Get-GPOInventory
        
        $gpos | Should -Not -BeNullOrEmpty
        $gpos[0].DisplayName | Should -Be 'Default Domain Policy'
    }
    
    It "Should identify unlinked GPOs" {
        Mock Get-GPO {
            return @(
                [PSCustomObject]@{
                    DisplayName = 'Unlinked GPO'
                    Id = [Guid]::NewGuid()
                    GpoStatus = 'AllSettingsEnabled'
                    CreationTime = Get-Date
                    ModificationTime = Get-Date
                    Owner = 'BUILTIN\Administrators'
                    WmiFilter = $null
                    User = @{ DSVersion = 0; SysvolVersion = 0 }
                    Computer = @{ DSVersion = 0; SysvolVersion = 0 }
                }
            )
        }
        
        Mock Get-GPOReport { return '<GPO></GPO>' }  # No links
        
        Mock Export-Csv { } -ParameterFilter {
            $Path -like "*AD_GPOs_Unlinked.csv"
        } -Verifiable
        
        Get-GPOInventory
        
        Should -InvokeVerifiable
    }
}

Describe "Get-ServiceAccounts" {
    It "Should detect service accounts with SPNs" {
        Mock Get-ADUser {
            return @(
                [PSCustomObject]@{
                    SamAccountName = 'svc_sql'
                    DisplayName = 'SQL Service Account'
                    Description = 'SQL Server service account'
                    Enabled = $true
                    PasswordLastSet = Get-Date
                    LastLogonDate = Get-Date
                    ServicePrincipalName = @('MSSQLSvc/server01.test.local:1433')
                    MemberOf = @()
                }
            )
        }
        
        Mock Export-Csv { }
        
        $result = Get-ServiceAccounts
        
        $result | Should -Not -BeNullOrEmpty
        $result[0].SPNCount | Should -BeGreaterThan 0
    }
    
    It "Should detect service accounts by naming pattern" {
        Mock Get-ADUser {
            return @(
                [PSCustomObject]@{
                    SamAccountName = 'svc_app'
                    DisplayName = 'Application Service'
                    Description = ''
                    Enabled = $true
                    PasswordLastSet = Get-Date
                    LastLogonDate = Get-Date
                    ServicePrincipalName = @()
                    MemberOf = @()
                }
            )
        }
        
        Mock Export-Csv { }
        
        $result = Get-ServiceAccounts
        
        $result | Should -Not -BeNullOrEmpty
        $result[0].DetectionReason | Should -Match 'NamePattern'
    }
}

Describe "Get-ServerHardwareInventory" {
    It "Should query server hardware" {
        $testServers = @(
            [PSCustomObject]@{ DNSHostName = 'server01.test.local'; Name = 'SERVER01' }
        )
        
        Mock Export-Csv { }
        
        $result = Get-ServerHardwareInventory -Servers $testServers -MaxParallel 1 -TimeoutSeconds 60 -SkipOffline $false
        
        $result | Should -Not -BeNullOrEmpty
    }
    
    It "Should detect virtualization" {
        Mock Get-CimInstance {
            param($ClassName)
            if ($ClassName -eq 'Win32_ComputerSystem') {
                return [PSCustomObject]@{
                    Manufacturer = 'VMware, Inc.'
                    Model = 'VMware Virtual Platform'
                    NumberOfLogicalProcessors = 4
                    TotalPhysicalMemory = 8589934592
                }
            }
        }
        
        $testServers = @(
            [PSCustomObject]@{ DNSHostName = 'vm01.test.local'; Name = 'VM01' }
        )
        
        Mock Export-Csv { }
        
        $result = Get-ServerHardwareInventory -Servers $testServers -MaxParallel 1 -TimeoutSeconds 60 -SkipOffline $false
        
        $result[0].IsVirtual | Should -Be $true
        $result[0].Hypervisor | Should -Be 'VMware'
    }
}

Describe "Advanced AD Security Components" -Tag "Unit", "ADSecurity" {
    BeforeAll {
        . "$PSScriptRoot/../Modules/Invoke-AD-Audit.ps1"
    }
    
    It "Get-ACLAnalysis should analyze AD ACLs" {
        Mock Get-ADDomain {
            return [PSCustomObject]@{ DistinguishedName = 'DC=test,DC=local' }
        }
        
        Mock Get-Acl {
            return [PSCustomObject]@{
                Access = @(
                    [PSCustomObject]@{
                        IdentityReference = 'BUILTIN\Administrators'
                        ActiveDirectoryRights = 'GenericAll'
                        AccessControlType = 'Allow'
                        IsInherited = $true
                    }
                )
            }
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        { Get-ACLAnalysis } | Should -Not -Throw
    }
    
    It "Get-KerberosDelegation should detect delegation configurations" {
        Mock Get-ADComputer {
            return @(
                [PSCustomObject]@{
                    Name = 'SERVER01'
                    SAMAccountName = 'SERVER01$'
                    TrustedForDelegation = $true
                    ServicePrincipalName = @('HTTP/server01')
                    OperatingSystem = 'Windows Server 2019'
                    DistinguishedName = 'CN=SERVER01,OU=Servers,DC=test,DC=local'
                    PrimaryGroupID = 515
                }
            )
        }
        
        Mock Get-ADUser {
            return @()
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        $result = Get-KerberosDelegation
        $result | Should -Not -BeNullOrEmpty
        $result[0].DelegationType | Should -Be 'Unconstrained'
        $result[0].Severity | Should -Be 'Critical'
    }
    
    It "Get-DHCPScopeAnalysis should analyze DHCP scopes" {
        Mock Get-DhcpServerInDC {
            return @(
                [PSCustomObject]@{
                    DnsName = 'dhcp01.test.local'
                    IPAddress = '10.0.0.10'
                }
            )
        }
        
        Mock Get-DhcpServerv4Scope {
            return @(
                [PSCustomObject]@{
                    ScopeId = '10.0.1.0'
                    Name = 'Office Network'
                    SubnetMask = '255.255.255.0'
                    StartRange = '10.0.1.10'
                    EndRange = '10.0.1.250'
                    LeaseDuration = '8.00:00:00'
                    State = 'Active'
                }
            )
        }
        
        Mock Get-DhcpServerv4ScopeStatistics {
            return [PSCustomObject]@{
                AddressesInUse = 100
                AddressesFree = 140
                PercentageInUse = 42
            }
        }
        
        Mock Get-DhcpServerv4Lease {
            return @()
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        $result = Get-DHCPScopeAnalysis
        $result.Scopes.Count | Should -BeGreaterThan 0
        $result.Scopes[0].ScopeName | Should -Be 'Office Network'
    }
    
    It "Get-GPOInventory should collect GPOs" {
        Mock Import-Module { }
        
        Mock Get-GPO {
            return @(
                [PSCustomObject]@{
                    DisplayName = 'Default Domain Policy'
                    Id = [guid]::NewGuid()
                    GpoStatus = 'AllSettingsEnabled'
                    CreationTime = (Get-Date).AddYears(-5)
                    ModificationTime = (Get-Date).AddDays(-30)
                    User = [PSCustomObject]@{ DSVersion = 2 }
                    Computer = [PSCustomObject]@{ DSVersion = 5 }
                    WmiFilter = $null
                    GpoLinks = @()
                    Owner = 'BUILTIN\Domain Admins'
                }
            )
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        $result = Get-GPOInventory
        $result | Should -Not -BeNullOrEmpty
        $result[0].DisplayName | Should -Be 'Default Domain Policy'
    }
    
    It "Get-ServiceAccounts should identify service accounts" {
        Mock Get-ADUser {
            return @(
                [PSCustomObject]@{
                    Name = 'svc_sql'
                    SAMAccountName = 'svc_sql'
                    Enabled = $true
                    ServicePrincipalName = @('MSSQLSvc/server01:1433')
                    PasswordLastSet = (Get-Date).AddDays(-200)
                    PasswordNeverExpires = $true
                    LastLogonDate = (Get-Date).AddHours(-2)
                    AdminCount = 0
                    DistinguishedName = 'CN=svc_sql,OU=ServiceAccounts,DC=test,DC=local'
                }
            )
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        $result = Get-ServiceAccounts
        $result | Should -Not -BeNullOrEmpty
        $result[0].SAMAccountName | Should -Be 'svc_sql'
        $result[0].SecurityRisk | Should -Be 'High'
    }
    
    It "Get-ADTrustRelationships should analyze trusts" {
        Mock Get-ADTrust {
            return @(
                [PSCustomObject]@{
                    Name = 'partner.local'
                    Direction = 'Bidirectional'
                    TrustType = 'External'
                    TrustAttributes = 'ForestTransitive'
                    Source = 'test.local'
                    Target = 'partner.local'
                    ForestTransitive = $true
                    SelectiveAuthenticationEnabled = $false
                    SIDFilteringQuarantined = $true
                    Created = (Get-Date).AddYears(-2)
                    Modified = (Get-Date).AddMonths(-6)
                }
            )
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        $result = Get-ADTrustRelationships
        $result | Should -Not -BeNullOrEmpty
        $result[0].Name | Should -Be 'partner.local'
        $result[0].SecurityLevel | Should -Be 'Review Required'
    }
    
    It "Get-PasswordPolicies should analyze password policies" {
        Mock Get-ADDefaultDomainPasswordPolicy {
            return [PSCustomObject]@{
                ComplexityEnabled = $true
                LockoutDuration = '00:30:00'
                LockoutObservationWindow = '00:30:00'
                LockoutThreshold = 5
                MaxPasswordAge = '42.00:00:00'
                MinPasswordAge = '1.00:00:00'
                MinPasswordLength = 14
                PasswordHistoryCount = 24
                ReversibleEncryptionEnabled = $false
            }
        }
        
        Mock Get-ADFineGrainedPasswordPolicy {
            return @()
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        $result = Get-PasswordPolicies
        $result.DefaultPolicy | Should -Not -BeNullOrEmpty
        $result.DefaultPolicy.MinPasswordLength | Should -Be 14
        $result.DefaultPolicy.SecurityAssessment | Should -Be 'Adequate'
    }
    
    It "Get-DNSZoneInventory should analyze DNS zones" {
        Mock Get-ADDomain {
            return [PSCustomObject]@{
                PDCEmulator = 'DC01.test.local'
            }
        }
        
        Mock Get-DnsServerZone {
            return @(
                [PSCustomObject]@{
                    ZoneName = 'test.local'
                    ZoneType = 'Primary'
                    DynamicUpdate = 'Secure'
                    IsAutoCreated = $false
                    IsDsIntegrated = $true
                    IsReverseLookupZone = $false
                    IsSigned = $false
                    SecureSecondaries = 'NoTransfer'
                }
            )
        }
        
        Mock Get-DnsServerResourceRecord {
            return @()
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        $result = Get-DNSZoneInventory
        $result.Zones | Should -Not -BeNullOrEmpty
        $result.Zones[0].ZoneName | Should -Be 'test.local'
    }
    
    It "Get-CertificateServices should audit certificate services" {
        Mock Get-ADRootDSE {
            return [PSCustomObject]@{
                configurationNamingContext = 'CN=Configuration,DC=test,DC=local'
            }
        }
        
        Mock Get-ADObject {
            param($Filter, $SearchBase, $Properties)
            if ($Filter.ToString() -match 'pKIEnrollmentService') {
                return @(
                    [PSCustomObject]@{
                        Name = 'TEST-CA'
                        displayName = 'Test Certificate Authority'
                        dNSHostName = 'ca01.test.local'
                        cACertificate = 'Present'
                        DistinguishedName = 'CN=TEST-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local'
                    }
                )
            }
            elseif ($Filter.ToString() -match 'pKICertificateTemplate') {
                return @(
                    [PSCustomObject]@{
                        Name = 'User'
                        displayName = 'User Certificate'
                        Created = (Get-Date).AddYears(-3)
                        Modified = (Get-Date).AddMonths(-6)
                        DistinguishedName = 'CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local'
                    }
                )
            }
        }
        
        Mock Export-Csv { }
        Mock Write-ModuleLog { }
        
        $result = Get-CertificateServices
        $result.CertificationAuthorities | Should -Not -BeNullOrEmpty
        $result.CertificationAuthorities[0].Name | Should -Be 'TEST-CA'
    }
}

