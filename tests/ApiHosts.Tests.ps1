#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . $PSScriptRoot/_Bootstrap.ps1
}

Describe 'Resolve-AdoApiHosts' {
    Context 'Azure DevOps Services (cloud)' {
        # These cases pin the exact behavior of the previous inline derivation
        # so the refactor cannot regress the cloud path.
        It 'expands a bare short name to the dev.azure.com org URL and subdomains' {
            $h = Resolve-AdoApiHosts -Organization 'MyOrg'
            $h.OrgUrl       | Should -Be 'https://dev.azure.com/MyOrg'
            $h.OrgShortName | Should -Be 'MyOrg'
            $h.VsspsUrl     | Should -Be 'https://vssps.dev.azure.com/MyOrg'
            $h.ExtMgmtUrl   | Should -Be 'https://extmgmt.dev.azure.com/MyOrg'
            $h.AuditUrl     | Should -Be 'https://auditservice.dev.azure.com/MyOrg'
            $h.FeedsUrl     | Should -Be 'https://feeds.dev.azure.com/MyOrg'
            $h.IsOnPrem     | Should -BeFalse
        }

        It 'accepts a full dev.azure.com org URL and trims a trailing slash' {
            $h = Resolve-AdoApiHosts -Organization 'https://dev.azure.com/MyOrg/'
            $h.OrgUrl       | Should -Be 'https://dev.azure.com/MyOrg'
            $h.OrgShortName | Should -Be 'MyOrg'
            $h.VsspsUrl     | Should -Be 'https://vssps.dev.azure.com/MyOrg'
            $h.IsOnPrem     | Should -BeFalse
        }

        It 'maps a legacy *.visualstudio.com URL to the short name' {
            $h = Resolve-AdoApiHosts -Organization 'https://myorg.visualstudio.com'
            $h.OrgShortName | Should -Be 'myorg'
            $h.VsspsUrl     | Should -Be 'https://vssps.dev.azure.com/myorg'
            $h.FeedsUrl     | Should -Be 'https://feeds.dev.azure.com/myorg'
            $h.IsOnPrem     | Should -BeFalse
        }
    }

    Context 'Azure DevOps Server (on-prem, experimental)' {
        It 'treats a collection URL as on-prem and serves APIs collection-relative' {
            $h = Resolve-AdoApiHosts -Organization 'https://tfs.contoso.com/DefaultCollection'
            $h.OrgUrl       | Should -Be 'https://tfs.contoso.com/DefaultCollection'
            $h.OrgShortName | Should -Be 'DefaultCollection'
            $h.VsspsUrl     | Should -Be 'https://tfs.contoso.com/DefaultCollection'
            $h.ExtMgmtUrl   | Should -Be 'https://tfs.contoso.com/DefaultCollection'
            $h.FeedsUrl     | Should -Be 'https://tfs.contoso.com/DefaultCollection'
            $h.IsOnPrem     | Should -BeTrue
        }

        It 'handles a /tfs/ virtual directory and trailing slash' {
            $h = Resolve-AdoApiHosts -Organization 'https://server/tfs/MyCollection/'
            $h.OrgUrl       | Should -Be 'https://server/tfs/MyCollection'
            $h.OrgShortName | Should -Be 'MyCollection'
            $h.VsspsUrl     | Should -Be 'https://server/tfs/MyCollection'
            $h.IsOnPrem     | Should -BeTrue
        }
    }
}
