#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . $PSScriptRoot/_Bootstrap.ps1
}

Describe 'Get-ControlCategory' {
    It 'returns Other for empty or unknown Ids' {
        Get-ControlCategory -Id '' | Should -Be 'Other'
        Get-ControlCategory -Id 'XYZ-01' | Should -Be 'Other'
    }

    It 'honours per-Id overrides ahead of prefix matches' {
        # PROJ-* normally maps to Identity & Access, but PROJ-01 / 16 / 17 are
        # overridden to Governance and PROJ-13 / 14 to Resources / Secrets.
        Get-ControlCategory -Id 'PROJ-01' | Should -Be 'Governance'
        Get-ControlCategory -Id 'PROJ-16' | Should -Be 'Governance'
        Get-ControlCategory -Id 'PROJ-17' | Should -Be 'Governance'
        Get-ControlCategory -Id 'PROJ-13' | Should -Be 'Resources'
        Get-ControlCategory -Id 'PROJ-14' | Should -Be 'Secrets & Credentials'
        Get-ControlCategory -Id 'PROJ-99' | Should -Be 'Identity & Access'  # falls back to prefix
    }

    It 'maps BUILD-01 and BUILD-03 to Secrets & Credentials, all other BUILD-* to Pipelines' {
        Get-ControlCategory -Id 'BUILD-01' | Should -Be 'Secrets & Credentials'
        Get-ControlCategory -Id 'BUILD-03' | Should -Be 'Secrets & Credentials'
        Get-ControlCategory -Id 'BUILD-04' | Should -Be 'Pipelines & Actions'
    }

    It 'maps REL-01 to Secrets & Credentials, all other REL-* to Pipelines' {
        Get-ControlCategory -Id 'REL-01' | Should -Be 'Secrets & Credentials'
        Get-ControlCategory -Id 'REL-04' | Should -Be 'Pipelines & Actions'
    }

    It 'maps PATPOL-* to PAT Hygiene without colliding with PAT-*' {
        Get-ControlCategory -Id 'PATPOL-01' | Should -Be 'PAT Hygiene'
        Get-ControlCategory -Id 'PAT-01'    | Should -Be 'PAT Hygiene'
    }

    It 'maps PIPELINE-* without colliding with shorter prefixes' {
        Get-ControlCategory -Id 'PIPELINE-01' | Should -Be 'Pipelines & Actions'
    }

    It 'covers the full ADO-native category set' {
        $expected = @{
            'Identity & Access'         = @('AUTH-01', 'USER-02', 'ADMIN-03', 'ACCESS-04', 'PERM-01', 'PERM-09')
            'Governance'                = @('OAUTH-01', 'EXT-01', 'BADGE-01', 'COPILOT-01', 'GOV-01')
            'Audit Log'                 = @('AUDIT-02')
            'Pipelines & Actions'       = @('PIPELINE-01', 'BUILD-04', 'REL-04')
            'Secrets & Credentials'     = @('VG-02', 'BUILD-01')
            'Repos & Branch Protection' = @('REPO-01', 'REPO-03', 'BRANCH-01', 'BRANCH-04')
            'Service Connections'       = @('SC-01')
            'Resources'                 = @('AP-01', 'FEED-01', 'SF-01', 'ENV-01')
            'PAT Hygiene'               = @('PAT-01', 'PATPOL-01')
        }
        foreach ($cat in $expected.Keys) {
            foreach ($id in $expected[$cat]) {
                Get-ControlCategory -Id $id | Should -Be $cat -Because "$id should be '$cat'"
            }
        }
    }
}

Describe 'New-ControlResult' {
    It 'auto-derives Category from the Id when -Category is omitted' {
        $r = New-ControlResult -Id 'AUTH-01' -Status 'PASS' -Severity 'High' -Control 'AAD auth' -Finding 'OK'
        $r.Category | Should -Be 'Identity & Access'
    }

    It 'honours an explicit -Category override' {
        $r = New-ControlResult -Id 'AUTH-01' -Status 'PASS' -Severity 'High' -Control 'AAD auth' -Finding 'OK' -Category 'Other'
        $r.Category | Should -Be 'Other'
    }

    It 'emits an object with the canonical property shape' {
        $r = New-ControlResult -Id 'REPO-03' -Status 'FAIL' -Severity 'Low' -Control 'README' -Finding 'Missing'
        $r.PSObject.Properties.Name | Should -Contain 'Id'
        $r.PSObject.Properties.Name | Should -Contain 'Status'
        $r.PSObject.Properties.Name | Should -Contain 'Severity'
        $r.PSObject.Properties.Name | Should -Contain 'Category'
        $r.PSObject.Properties.Name | Should -Contain 'Control'
        $r.PSObject.Properties.Name | Should -Contain 'Finding'
    }

    It 'rejects an invalid Status' {
        { New-ControlResult -Id 'AUTH-01' -Status 'Bogus' -Severity 'High' -Control 'x' -Finding 'y' } |
            Should -Throw
    }

    It 'rejects an invalid Severity' {
        { New-ControlResult -Id 'AUTH-01' -Status 'PASS' -Severity 'Bogus' -Control 'x' -Finding 'y' } |
            Should -Throw
    }
}

Describe 'Test-PolicyAppliesToBranch' {
    BeforeAll {
        function script:New-FakePolicy {
            param([bool]$Enabled = $true, $Scopes = @())
            [PSCustomObject]@{
                isEnabled = $Enabled
                settings  = [PSCustomObject]@{ scope = $Scopes }
            }
        }
        $script:RepoA = 'aaaaaaaa-0000-0000-0000-000000000001'
        $script:RepoB = 'bbbbbbbb-0000-0000-0000-000000000002'
    }

    It 'returns true on exact repo + branch match' {
        $p = New-FakePolicy -Scopes @([PSCustomObject]@{ repositoryId = $RepoA; refName = 'refs/heads/main'; matchKind = 'exact' })
        Test-PolicyAppliesToBranch -Policy $p -RepoId $RepoA -RefName 'refs/heads/main' | Should -BeTrue
    }

    It 'returns false when the repository differs' {
        $p = New-FakePolicy -Scopes @([PSCustomObject]@{ repositoryId = $RepoA; refName = 'refs/heads/main'; matchKind = 'exact' })
        Test-PolicyAppliesToBranch -Policy $p -RepoId $RepoB -RefName 'refs/heads/main' | Should -BeFalse
    }

    It 'returns false on exact branch mismatch' {
        $p = New-FakePolicy -Scopes @([PSCustomObject]@{ repositoryId = $RepoA; refName = 'refs/heads/main'; matchKind = 'exact' })
        Test-PolicyAppliesToBranch -Policy $p -RepoId $RepoA -RefName 'refs/heads/dev' | Should -BeFalse
    }

    It 'returns true for a prefix scope that the ref falls under' {
        $p = New-FakePolicy -Scopes @([PSCustomObject]@{ repositoryId = $RepoA; refName = 'refs/heads/'; matchKind = 'prefix' })
        Test-PolicyAppliesToBranch -Policy $p -RepoId $RepoA -RefName 'refs/heads/main' | Should -BeTrue
    }

    It 'returns false for a prefix scope the ref does not fall under' {
        $p = New-FakePolicy -Scopes @([PSCustomObject]@{ repositoryId = $RepoA; refName = 'refs/heads/'; matchKind = 'prefix' })
        Test-PolicyAppliesToBranch -Policy $p -RepoId $RepoA -RefName 'refs/tags/v1' | Should -BeFalse
    }

    It 'treats a scope with no repoId and no refName as project-wide' {
        $p = New-FakePolicy -Scopes @([PSCustomObject]@{ refName = $null })
        Test-PolicyAppliesToBranch -Policy $p -RepoId $RepoB -RefName 'refs/heads/main' | Should -BeTrue
    }

    It 'treats a repo-only scope (no refName) as any branch in that repo' {
        $p = New-FakePolicy -Scopes @([PSCustomObject]@{ repositoryId = $RepoA; refName = $null })
        Test-PolicyAppliesToBranch -Policy $p -RepoId $RepoA -RefName 'refs/heads/main' | Should -BeTrue
    }

    It 'ignores a policy whose isEnabled is false' {
        $p = New-FakePolicy -Enabled $false -Scopes @([PSCustomObject]@{ repositoryId = $RepoA; refName = 'refs/heads/main' })
        Test-PolicyAppliesToBranch -Policy $p -RepoId $RepoA -RefName 'refs/heads/main' | Should -BeFalse
    }

    It 'returns false when policy is null' {
        Test-PolicyAppliesToBranch -Policy $null -RepoId $RepoA -RefName 'refs/heads/main' | Should -BeFalse
    }
}
