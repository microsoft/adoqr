#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . $PSScriptRoot/_Bootstrap.ps1

    function script:New-Result {
        param($Id, $Status, $Severity = 'Medium', $Control = 'X', $Finding = 'Y', $Category = $null)
        if ($Category) {
            New-ControlResult -Id $Id -Status $Status -Severity $Severity -Control $Control -Finding $Finding -Category $Category
        }
        else {
            New-ControlResult -Id $Id -Status $Status -Severity $Severity -Control $Control -Finding $Finding
        }
    }
}

Describe 'Export-AssessmentToJson' {
    BeforeEach {
        $script:TempJson = [System.IO.Path]::GetTempFileName() + '.json'
    }

    AfterEach {
        if (Test-Path $script:TempJson) { Remove-Item $script:TempJson -ErrorAction SilentlyContinue }
    }

    It 'writes a file at the requested path' {
        Export-AssessmentToJson `
            -FilePath $TempJson `
            -OrgName 'TestOrg' `
            -OrgUrl 'https://dev.azure.com/TestOrg' `
            -OrgResults @((New-Result 'AUTH-01' 'PASS')) `
            -ProjectResults @() `
            -ElapsedSeconds 0.5
        Test-Path $TempJson | Should -BeTrue
    }

    It 'emits UTF-8 without a BOM' {
        Export-AssessmentToJson `
            -FilePath $TempJson `
            -OrgName 'TestOrg' `
            -OrgUrl 'https://dev.azure.com/TestOrg' `
            -OrgResults @((New-Result 'AUTH-01' 'PASS')) `
            -ProjectResults @() `
            -ElapsedSeconds 0.5
        $bytes = [System.IO.File]::ReadAllBytes($TempJson)
        $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
        $hasBom | Should -BeFalse
    }

    It 'produces the expected top-level shape and schemaVersion' {
        Export-AssessmentToJson `
            -FilePath $TempJson `
            -OrgName 'TestOrg' `
            -OrgUrl 'https://dev.azure.com/TestOrg' `
            -OrgResults @((New-Result 'AUTH-01' 'PASS')) `
            -ProjectResults @([PSCustomObject]@{ Project = 'P1'; Results = @((New-Result 'REPO-03' 'FAIL' 'Low')) }) `
            -ElapsedSeconds 1.5

        $doc = Get-Content -Raw $TempJson | ConvertFrom-Json
        $doc.schemaVersion | Should -Be '1.0'
        $doc.organization.name | Should -Be 'TestOrg'
        $doc.organization.url | Should -Be 'https://dev.azure.com/TestOrg'
        $doc.meta.tool | Should -Be 'adoqr'
        $doc.meta.generator | Should -Be 'invoke-adoqr.ps1'
        $doc.meta.elapsedSeconds | Should -Be 1.5
        $doc.'$schema' | Should -Match '^https://.*scan\.schema\.json$'
    }

    It 'computes aggregate summary across org + projects' {
        Export-AssessmentToJson `
            -FilePath $TempJson `
            -OrgName 'TestOrg' `
            -OrgUrl 'https://dev.azure.com/TestOrg' `
            -OrgResults @(
                (New-Result 'AUTH-01' 'PASS'),
                (New-Result 'AUTH-02' 'FAIL'),
                (New-Result 'AUTH-03' 'NOT CHECKED')
            ) `
            -ProjectResults @(
                [PSCustomObject]@{ Project = 'P1'; Results = @(
                        (New-Result 'REPO-01' 'PASS'),
                        (New-Result 'REPO-03' 'FAIL')
                    )
                }
            ) `
            -ElapsedSeconds 0.0

        $doc = Get-Content -Raw $TempJson | ConvertFrom-Json
        $doc.summary.pass | Should -Be 2
        $doc.summary.fail | Should -Be 2
        $doc.summary.notChecked | Should -Be 1
        $doc.controls.Count | Should -Be 5
    }

    It 'tags each control with the correct scope' {
        Export-AssessmentToJson `
            -FilePath $TempJson `
            -OrgName 'TestOrg' `
            -OrgUrl 'https://dev.azure.com/TestOrg' `
            -OrgResults @((New-Result 'AUTH-01' 'PASS')) `
            -ProjectResults @([PSCustomObject]@{ Project = 'P1'; Results = @((New-Result 'REPO-03' 'FAIL' 'Low')) }) `
            -ElapsedSeconds 0.0

        $doc = Get-Content -Raw $TempJson | ConvertFrom-Json
        $orgCtrl = $doc.controls | Where-Object { $_.id -eq 'AUTH-01' } | Select-Object -First 1
        $orgCtrl.scope.type | Should -Be 'organization'
        $orgCtrl.scope.organization | Should -Be 'TestOrg'
        $orgCtrl.scope.project | Should -BeNullOrEmpty

        $projCtrl = $doc.controls | Where-Object { $_.id -eq 'REPO-03' } | Select-Object -First 1
        $projCtrl.scope.type | Should -Be 'project'
        $projCtrl.scope.organization | Should -Be 'TestOrg'
        $projCtrl.scope.project | Should -Be 'P1'
    }

    It 'emits a per-project summary block' {
        Export-AssessmentToJson `
            -FilePath $TempJson `
            -OrgName 'TestOrg' `
            -OrgUrl 'https://dev.azure.com/TestOrg' `
            -OrgResults @() `
            -ProjectResults @(
                [PSCustomObject]@{ Project = 'P1'; Results = @(
                        (New-Result 'REPO-01' 'PASS'),
                        (New-Result 'REPO-03' 'FAIL'),
                        (New-Result 'REPO-04' 'NOT CHECKED')
                    )
                }
            ) `
            -ElapsedSeconds 0.0

        $doc = Get-Content -Raw $TempJson | ConvertFrom-Json
        $p1 = $doc.projects | Where-Object { $_.name -eq 'P1' } | Select-Object -First 1
        $p1.summary.pass | Should -Be 1
        $p1.summary.fail | Should -Be 1
        $p1.summary.notChecked | Should -Be 1
    }

    It 'preserves an explicit Category when present on input' {
        # Simulates a future caller that sets Category explicitly.
        $explicit = New-Result 'AUTH-01' 'PASS' 'High' 'AAD' 'OK' 'Other'
        Export-AssessmentToJson `
            -FilePath $TempJson `
            -OrgName 'TestOrg' `
            -OrgUrl 'https://dev.azure.com/TestOrg' `
            -OrgResults @($explicit) `
            -ProjectResults @() `
            -ElapsedSeconds 0.0

        $doc = Get-Content -Raw $TempJson | ConvertFrom-Json
        $doc.controls[0].category | Should -Be 'Other'
    }
}

Describe 'scan.schema.json' {
    BeforeAll {
        $script:SchemaPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'schemas/scan.schema.json'
    }

    It 'exists' {
        Test-Path $SchemaPath | Should -BeTrue
    }

    It 'is valid JSON and declares draft-07' {
        $schema = Get-Content -Raw $SchemaPath | ConvertFrom-Json
        $schema.'$schema' | Should -Match 'draft-07'
        $schema.title    | Should -Not -BeNullOrEmpty
    }

    It 'enumerates exactly the 10 supported categories' {
        $schema = Get-Content -Raw $SchemaPath | ConvertFrom-Json
        $allowed = @(
            'Identity & Access'
            'Governance'
            'Audit Log'
            'Pipelines & Actions'
            'Secrets & Credentials'
            'Repos & Branch Protection'
            'Service Connections'
            'Resources'
            'PAT Hygiene'
            'Other'
        )
        $schemaCats = $schema.definitions.control.properties.category.enum
        $schemaCats.Count | Should -Be $allowed.Count
        foreach ($c in $allowed) { $schemaCats | Should -Contain $c }
    }
}
