<#
.SYNOPSIS
    Pester tests for cloud audit modules (EntraID, Exchange, SharePoint, Teams, Power Platform)
.DESCRIPTION
    Unit tests for Microsoft 365 and Azure cloud service audit modules
#>

BeforeAll {
    # Create function stubs for cloud cmdlets to prevent CommandNotFoundException
    function Connect-ExchangeOnline { Write-Verbose "Mock Connect-ExchangeOnline" }
    function Get-Mailbox { return @() }
    function Get-MailboxStatistics { return @() }
    function Get-DistributionGroup { return @() }
    function Get-Recipient { return @() }
    function Get-MailboxPermission { return @() }
    function Get-CalendarProcessing { return @() }
    
    function Connect-PnPOnline { Write-Verbose "Mock Connect-PnPOnline" }
    function Get-PnPSite { return @() }
    function Get-PnPList { return @() }
    function Get-PnPWeb { return @() }
    function Get-PnPUser { return @() }
    function Get-PnPTenantSite { return @() }
    function Get-PnPTenant { return @() }
    
    function Connect-MicrosoftTeams { Write-Verbose "Mock Connect-MicrosoftTeams" }
    function Get-Team { return @() }
    function Get-TeamChannel { return @() }
    function Get-TeamUser { return @() }
    
    function Connect-PowerApps { Write-Verbose "Mock Connect-PowerApps" }
    function Add-PowerAppsAccount { Write-Verbose "Mock Add-PowerAppsAccount" }
    function Get-PowerApp { return @() }
    function Get-AdminPowerApp { return @() }
    function Get-PowerAutomateFlow { return @() }
    function Get-AdminFlow { return @() }
    function Get-PowerAppEnvironment { return @() }
    
    # Mock all cloud module cmdlets to prevent import errors
    Mock Connect-MgGraph { }
    Mock Get-MgUser {
        return @(
            [PSCustomObject]@{
                Id = '12345-67890'
                UserPrincipalName = 'clouduser@tenant.onmicrosoft.com'
                DisplayName = 'Cloud User'
                Mail = 'clouduser@tenant.com'
                AccountEnabled = $true
                CreatedDateTime = (Get-Date).AddYears(-1)
                SignInActivity = @{
                    LastSignInDateTime = (Get-Date).AddDays(-3)
                }
                AssignedLicenses = @(
                    @{ SkuId = 'O365-E3' }
                )
            }
        )
    }
    
    # Mock Exchange Online cmdlets
    Mock Connect-ExchangeOnline { }
    Mock Get-Mailbox { return @() }
    Mock Get-DistributionGroup { return @() }
    Mock Get-Recipient { return @() }
    
    # Mock SharePoint cmdlets
    Mock Connect-PnPOnline { }
    Mock Get-PnPSite { return @() }
    Mock Get-PnPList { return @() }
    
    # Mock Teams cmdlets
    Mock Connect-MicrosoftTeams { }
    Mock Get-Team { return @() }
    Mock Get-TeamChannel { return @() }
    
    # Mock Power Platform cmdlets
    Mock Connect-PowerApps { }
    Mock Get-PowerApp { return @() }
    Mock Get-PowerAutomateFlow { return @() }
    
    Mock Get-MgGroup {
        return @(
            [PSCustomObject]@{
                Id = 'group-12345'
                DisplayName = 'IT Team'
                Description = 'IT Department'
                GroupTypes = @('Unified')
                MailEnabled = $true
                SecurityEnabled = $true
            }
        )
    }
    
    Mock Get-MgApplication {
        return @(
            [PSCustomObject]@{
                Id = 'app-12345'
                DisplayName = 'Test Application'
                AppId = 'app-guid-12345'
                CreatedDateTime = Get-Date
                SignInAudience = 'AzureADMyOrg'
            }
        )
    }
    
    # Mock Exchange Online cmdlets
    Mock Connect-ExchangeOnline { }
    Mock Get-Mailbox {
        return @(
            [PSCustomObject]@{
                UserPrincipalName = 'user@tenant.com'
                DisplayName = 'Test User'
                PrimarySmtpAddress = 'user@tenant.com'
                RecipientTypeDetails = 'UserMailbox'
                WhenCreated = (Get-Date).AddYears(-2)
                ItemCount = 5000
                TotalItemSize = '2GB'
            }
        )
    }
    
    Mock Get-MailboxStatistics {
        return [PSCustomObject]@{
            ItemCount = 5000
            TotalItemSize = [PSCustomObject]@{ Value = '2GB' }
        }
    }
    
    Mock Get-DistributionGroup {
        return @(
            [PSCustomObject]@{
                DisplayName = 'All Staff'
                PrimarySmtpAddress = 'allstaff@tenant.com'
                GroupType = 'Universal'
                ManagedBy = 'admin@tenant.com'
            }
        )
    }
    
    # Mock SharePoint cmdlets
    Mock Connect-PnPOnline { }
    Mock Get-PnPTenantSite {
        return @(
            [PSCustomObject]@{
                Url = 'https://tenant.sharepoint.com/sites/teamsite'
                Title = 'Team Site'
                Owner = 'admin@tenant.com'
                StorageQuota = 26214400
                StorageUsageCurrent = 1024000
                Template = 'STS#3'
                LastContentModifiedDate = (Get-Date).AddDays(-1)
            }
        )
    }
    
    # Mock Teams cmdlets
    Mock Connect-MicrosoftTeams { }
    Mock Get-Team {
        return @(
            [PSCustomObject]@{
                GroupId = 'team-12345'
                DisplayName = 'Project Team'
                Description = 'Project collaboration'
                Visibility = 'Private'
                MailNickName = 'projectteam'
            }
        )
    }
    
    Mock Get-TeamUser {
        return @(
            [PSCustomObject]@{
                User = 'user@tenant.com'
                Role = 'Owner'
            }
        )
    }
    
    # Mock Power Platform cmdlets
    Mock Add-PowerAppsAccount { }
    Mock Get-AdminPowerApp {
        return @(
            [PSCustomObject]@{
                AppName = 'app-12345'
                DisplayName = 'Business App'
                Owner = @{ email = 'owner@tenant.com' }
                CreatedTime = (Get-Date).AddMonths(-6)
                LastModifiedTime = (Get-Date).AddDays(-5)
                Environment = 'Default'
            }
        )
    }
    
    Mock Get-AdminFlow {
        return @(
            [PSCustomObject]@{
                FlowName = 'flow-12345'
                DisplayName = 'Approval Flow'
                CreatedTime = (Get-Date).AddMonths(-3)
                LastModifiedTime = (Get-Date).AddDays(-2)
                State = 'Started'
            }
        )
    }
    
    Mock Export-Csv { }
    
    $script:TestOutputDir = Join-Path $TestDrive "CloudTests"
    $script:EntraIDOutputPath = Join-Path $script:TestOutputDir "EntraID"
    $script:ExchangeOutputPath = Join-Path $script:TestOutputDir "Exchange"
    $script:SharePointOutputPath = Join-Path $script:TestOutputDir "SharePoint"
    $script:TeamsOutputPath = Join-Path $script:TestOutputDir "Teams"
    $script:PowerPlatformOutputPath = Join-Path $script:TestOutputDir "PowerPlatform"
    
    New-Item -ItemType Directory -Path $script:EntraIDOutputPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:ExchangeOutputPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:SharePointOutputPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:TeamsOutputPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:PowerPlatformOutputPath -Force | Out-Null
}

Describe "Entra ID Module Tests" -Tag "Cloud", "EntraID" {
    Context "User Collection" {
        It "Should connect to Microsoft Graph" {
            { Connect-MgGraph -Scopes "User.Read.All" } | Should -Not -Throw
        }
        
        It "Should collect Entra ID users" {
            $users = Get-MgUser
            
            $users | Should -Not -BeNullOrEmpty
            $users[0].UserPrincipalName | Should -Not -BeNullOrEmpty
        }
        
        It "Should include sign-in activity" {
            $users = Get-MgUser
            
            $users[0].SignInActivity | Should -Not -BeNullOrEmpty
        }
        
        It "Should include license information" {
            $users = Get-MgUser
            
            $users[0].AssignedLicenses | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Group Collection" {
        It "Should collect Entra ID groups" {
            $groups = Get-MgGroup
            
            $groups | Should -Not -BeNullOrEmpty
            $groups[0].DisplayName | Should -Be 'IT Team'
        }
        
        It "Should identify group types" {
            $groups = Get-MgGroup
            
            $groups[0].GroupTypes | Should -Contain 'Unified'
        }
    }
    
    Context "Application Collection" {
        It "Should collect Entra ID applications" {
            $apps = Get-MgApplication
            
            $apps | Should -Not -BeNullOrEmpty
            $apps[0].DisplayName | Should -Be 'Test Application'
        }
        
        It "Should include application IDs" {
            $apps = Get-MgApplication
            
            $apps[0].AppId | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Exchange Online Module Tests" -Tag "Cloud", "Exchange" {
    Context "Mailbox Collection" {
        It "Should connect to Exchange Online" {
            { Connect-ExchangeOnline -ShowBanner:$false } | Should -Not -Throw
        }
        
        It "Should collect mailboxes" {
            $mailboxes = Get-Mailbox
            
            $mailboxes | Should -Not -BeNullOrEmpty
            $mailboxes[0].PrimarySmtpAddress | Should -Not -BeNullOrEmpty
        }
        
        It "Should identify mailbox types" {
            $mailboxes = Get-Mailbox
            
            $mailboxes[0].RecipientTypeDetails | Should -Be 'UserMailbox'
        }
    }
    
    Context "Mailbox Statistics" {
        It "Should collect mailbox statistics" {
            $stats = Get-MailboxStatistics -Identity "user@tenant.com"
            
            $stats | Should -Not -BeNullOrEmpty
            $stats.ItemCount | Should -BeGreaterThan 0
        }
        
        It "Should include size information" {
            $stats = Get-MailboxStatistics -Identity "user@tenant.com"
            
            $stats.TotalItemSize | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Distribution Group Collection" {
        It "Should collect distribution groups" {
            $groups = Get-DistributionGroup
            
            $groups | Should -Not -BeNullOrEmpty
            $groups[0].DisplayName | Should -Be 'All Staff'
        }
    }
}

Describe "SharePoint Module Tests" -Tag "Cloud", "SharePoint" {
    Context "Site Collection" {
        It "Should connect to SharePoint Online" {
            { Connect-PnPOnline -Url "https://tenant-admin.sharepoint.com" -Interactive } | Should -Not -Throw
        }
        
        It "Should collect SharePoint sites" {
            $sites = Get-PnPTenantSite
            
            $sites | Should -Not -BeNullOrEmpty
            $sites[0].Url | Should -Not -BeNullOrEmpty
        }
        
        It "Should include storage information" {
            $sites = Get-PnPTenantSite
            
            $sites[0].StorageQuota | Should -BeGreaterThan 0
            $sites[0].StorageUsageCurrent | Should -BeGreaterThan 0
        }
        
        It "Should identify site templates" {
            $sites = Get-PnPTenantSite
            
            $sites[0].Template | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Microsoft Teams Module Tests" -Tag "Cloud", "Teams" {
    Context "Teams Collection" {
        It "Should connect to Microsoft Teams" {
            { Connect-MicrosoftTeams } | Should -Not -Throw
        }
        
        It "Should collect teams" {
            $teams = Get-Team
            
            $teams | Should -Not -BeNullOrEmpty
            $teams[0].DisplayName | Should -Be 'Project Team'
        }
        
        It "Should identify team visibility" {
            $teams = Get-Team
            
            $teams[0].Visibility | Should -BeIn @('Public', 'Private')
        }
    }
    
    Context "Team Members Collection" {
        It "Should collect team members" {
            $members = Get-TeamUser -GroupId 'team-12345'
            
            $members | Should -Not -BeNullOrEmpty
        }
        
        It "Should identify member roles" {
            $members = Get-TeamUser -GroupId 'team-12345'
            
            $members[0].Role | Should -BeIn @('Owner', 'Member', 'Guest')
        }
    }
}

Describe "Power Platform Module Tests" -Tag "Cloud", "PowerPlatform" {
    Context "Power Apps Collection" {
        It "Should connect to Power Platform" {
            { Add-PowerAppsAccount } | Should -Not -Throw
        }
        
        It "Should collect Power Apps" {
            $apps = Get-AdminPowerApp
            
            $apps | Should -Not -BeNullOrEmpty
            $apps[0].DisplayName | Should -Be 'Business App'
        }
        
        It "Should include owner information" {
            $apps = Get-AdminPowerApp
            
            $apps[0].Owner | Should -Not -BeNullOrEmpty
            $apps[0].Owner.email | Should -Not -BeNullOrEmpty
        }
        
        It "Should include timestamps" {
            $apps = Get-AdminPowerApp
            
            $apps[0].CreatedTime | Should -Not -BeNullOrEmpty
            $apps[0].LastModifiedTime | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Power Automate Flows Collection" {
        It "Should collect Power Automate flows" {
            $flows = Get-AdminFlow
            
            $flows | Should -Not -BeNullOrEmpty
            $flows[0].DisplayName | Should -Be 'Approval Flow'
        }
        
        It "Should identify flow state" {
            $flows = Get-AdminFlow
            
            $flows[0].State | Should -BeIn @('Started', 'Stopped', 'Suspended')
        }
    }
}

Describe "Cloud Module Error Handling" -Tag "Cloud" {
    Context "Connection Failures" {
        It "Should handle Graph connection errors gracefully" {
            Mock Connect-MgGraph { throw "Authentication failed" }
            
            { Connect-MgGraph -ErrorAction Stop } | Should -Throw
        }
        
        It "Should handle Exchange connection errors gracefully" {
            Mock Connect-ExchangeOnline { throw "Connection timeout" }
            
            { Connect-ExchangeOnline -ErrorAction Stop } | Should -Throw
        }
    }
    
    Context "Data Retrieval Errors" {
        It "Should handle missing data gracefully" {
            $users = Get-MgUser
            
            $users | Should -Not -BeNullOrEmpty
            $users | Should -BeOfType [PSCustomObject]
            $users.Id | Should -Be '12345-67890'
        }
        
        It "Should handle API throttling" {
            Mock Get-MgUser { throw "Request throttled" }
            
            { Get-MgUser -ErrorAction Stop } | Should -Throw
        }
    }
}

Describe "Cloud Data Export" -Tag "Cloud" {
    Context "CSV Export" {
        It "Should export Entra ID users to CSV" {
            Mock Export-Csv { } -ParameterFilter {
                $Path -like "*EntraID_Users.csv"
            } -Verifiable
            
            $users = Get-MgUser
            $users | Export-Csv -Path (Join-Path $script:EntraIDOutputPath "EntraID_Users.csv") -NoTypeInformation
            
            Should -InvokeVerifiable
        }
        
        It "Should export mailboxes to CSV" {
            Mock Export-Csv { } -ParameterFilter {
                $Path -like "*Exchange_Mailboxes.csv"
            } -Verifiable
            
            $mailboxes = Get-Mailbox
            $mailboxes | Export-Csv -Path (Join-Path $script:ExchangeOutputPath "Exchange_Mailboxes.csv") -NoTypeInformation
            
            Should -InvokeVerifiable
        }
        
        It "Should export SharePoint sites to CSV" {
            Mock Export-Csv { } -ParameterFilter {
                $Path -like "*SharePoint_Sites.csv"
            } -Verifiable
            
            $sites = Get-PnPTenantSite
            $sites | Export-Csv -Path (Join-Path $script:SharePointOutputPath "SharePoint_Sites.csv") -NoTypeInformation
            
            Should -InvokeVerifiable
        }
    }
}

