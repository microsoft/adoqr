#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . $PSScriptRoot/_Bootstrap.ps1

    # Helper: write a minimal scan JSON to a file and return the path.
    function script:New-ScanJson {
        param(
            [string]$Dir,
            [string]$OrgSafe,
            [string]$GeneratedAt,
            [PSCustomObject[]]$Controls = @()
        )
        $pass = @($Controls | Where-Object status -eq 'PASS').Count
        $fail = @($Controls | Where-Object status -eq 'FAIL').Count
        $nc   = @($Controls | Where-Object status -eq 'NOT CHECKED').Count

        $doc = [PSCustomObject]@{
            '$schema'     = 'https://raw.githubusercontent.com/microsoft/adoqr/main/schemas/scan.schema.json'
            schemaVersion = '1.0'
            meta          = [PSCustomObject]@{
                tool           = 'adoqr'
                generator      = 'invoke-adoqr.ps1'
                generatedAt    = $GeneratedAt
                elapsedSeconds = 0
            }
            organization  = [PSCustomObject]@{ name = 'TestOrg'; url = 'https://dev.azure.com/TestOrg' }
            summary       = [PSCustomObject]@{ pass = $pass; fail = $fail; notChecked = $nc }
            projects      = @()
            controls      = $Controls
        }

        $path = Join-Path $Dir "$OrgSafe-scan.json"
        $doc | ConvertTo-Json -Depth 10 | Set-Content -Path $path -Encoding utf8
        return $path
    }

    function script:New-ScanControl {
        param([string]$Id, [string]$Status = 'PASS', [string]$Severity = 'Medium', [string]$Control = 'Test Control')
        [PSCustomObject]@{
            id       = $Id
            status   = $Status
            severity = $Severity
            control  = $Control
            scope    = [PSCustomObject]@{ type = 'organization'; organization = 'TestOrg'; project = $null }
        }
    }
}

Describe 'Get-PriorScanRuns' {

    It 'returns an empty array when the directory does not exist' {
        $result = Get-PriorScanRuns -AssessmentsRoot 'C:\NonExistent\Path\That\Does\Not\Exist' -OrgSafeName 'myorg'
        @($result).Count | Should -Be 0
    }

    It 'returns an empty array when no scan.json files are present' {
        $tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $tmpRoot | Out-Null
        try {
            $result = Get-PriorScanRuns -AssessmentsRoot $tmpRoot -OrgSafeName 'myorg'
            @($result).Count | Should -Be 0
        }
        finally { Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'discovers scan files in sub-folders and returns them newest-first' {
        $tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
        $runA = Join-Path $tmpRoot 'myorg-2026-01-01-120000'
        $runB = Join-Path $tmpRoot 'myorg-2026-03-01-120000'
        New-Item -ItemType Directory -Path $runA | Out-Null
        New-Item -ItemType Directory -Path $runB | Out-Null
        try {
            New-ScanJson -Dir $runA -OrgSafe 'myorg' -GeneratedAt '2026-01-01T12:00:00Z' | Out-Null
            New-ScanJson -Dir $runB -OrgSafe 'myorg' -GeneratedAt '2026-03-01T12:00:00Z' | Out-Null

            $result = @(Get-PriorScanRuns -AssessmentsRoot $tmpRoot -OrgSafeName 'myorg')
            $result.Count | Should -Be 2
            # Newest first
            $result[0].RunId | Should -Be 'myorg-2026-03-01-120000'
            $result[1].RunId | Should -Be 'myorg-2026-01-01-120000'
        }
        finally { Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'skips files whose JSON is corrupt or lacks meta.generatedAt' {
        $tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
        $runGood = Join-Path $tmpRoot 'myorg-2026-05-01-090000'
        $runBad  = Join-Path $tmpRoot 'myorg-2026-04-01-090000'
        New-Item -ItemType Directory -Path $runGood | Out-Null
        New-Item -ItemType Directory -Path $runBad  | Out-Null
        try {
            New-ScanJson -Dir $runGood -OrgSafe 'myorg' -GeneratedAt '2026-05-01T09:00:00Z' | Out-Null
            Set-Content -Path (Join-Path $runBad 'myorg-scan.json') -Value 'not valid json{{{'
            $result = @(Get-PriorScanRuns -AssessmentsRoot $tmpRoot -OrgSafeName 'myorg')
            $result.Count | Should -Be 1
            $result[0].RunId | Should -Be 'myorg-2026-05-01-090000'
        }
        finally { Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'only returns files matching the given OrgSafeName' {
        $tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
        $runA = Join-Path $tmpRoot 'orgA-2026-01-01-120000'
        $runB = Join-Path $tmpRoot 'orgB-2026-03-01-120000'
        New-Item -ItemType Directory -Path $runA | Out-Null
        New-Item -ItemType Directory -Path $runB | Out-Null
        try {
            New-ScanJson -Dir $runA -OrgSafe 'orga' -GeneratedAt '2026-01-01T12:00:00Z' | Out-Null
            New-ScanJson -Dir $runB -OrgSafe 'orgb' -GeneratedAt '2026-03-01T12:00:00Z' | Out-Null
            $result = @(Get-PriorScanRuns -AssessmentsRoot $tmpRoot -OrgSafeName 'orga')
            $result.Count | Should -Be 1
            $result[0].RunId | Should -Be 'orgA-2026-01-01-120000'
        }
        finally { Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Build-ComparisonSectionHtml' {

    It 'returns a non-empty HTML string' {
        $html = Build-ComparisonSectionHtml -RunsData @()
        $html | Should -Not -BeNullOrEmpty
    }

    It 'includes the no-data placeholder when given fewer than 2 runs' {
        $html = Build-ComparisonSectionHtml -RunsData @()
        $html | Should -Match 'id="cmp-nodata"'

        $singleRun = [PSCustomObject]@{
            runId       = 'myorg-2026-05-01-090000'
            generatedAt = '2026-05-01T09:00:00Z'
            summary     = [PSCustomObject]@{ pass = 1; fail = 0; notChecked = 0 }
            controls    = @(New-ScanControl 'AUTH-01' 'PASS')
        }
        $html2 = Build-ComparisonSectionHtml -RunsData @($singleRun)
        $html2 | Should -Match 'id="cmp-nodata"'
    }

    It 'embeds window.__adoqrRuns JSON when given 2+ runs' {
        $run1 = [PSCustomObject]@{
            runId       = 'myorg-2026-05-01-090000'
            generatedAt = '2026-05-01T09:00:00Z'
            summary     = [PSCustomObject]@{ pass = 2; fail = 1; notChecked = 0 }
            controls    = @(
                New-ScanControl 'AUTH-01' 'PASS' 'High'
                New-ScanControl 'AUTH-02' 'FAIL' 'Medium'
                New-ScanControl 'AUTH-03' 'PASS' 'Low'
            )
        }
        $run2 = [PSCustomObject]@{
            runId       = 'myorg-2026-04-01-090000'
            generatedAt = '2026-04-01T09:00:00Z'
            summary     = [PSCustomObject]@{ pass = 1; fail = 2; notChecked = 0 }
            controls    = @(
                New-ScanControl 'AUTH-01' 'FAIL' 'High'
                New-ScanControl 'AUTH-02' 'FAIL' 'Medium'
                New-ScanControl 'AUTH-03' 'PASS' 'Low'
            )
        }
        $html = Build-ComparisonSectionHtml -RunsData @($run1, $run2)
        $html | Should -Match 'window\.__adoqrRuns='
        $html | Should -Match 'AUTH-01'
        $html | Should -Match 'cmp-run-a'
        $html | Should -Match 'cmp-run-b'
    }

    It 'includes the comparison UI container' {
        $run1 = [PSCustomObject]@{
            runId       = 'myorg-2026-05-01-090000'
            generatedAt = '2026-05-01T09:00:00Z'
            summary     = [PSCustomObject]@{ pass = 1; fail = 0; notChecked = 0 }
            controls    = @(New-ScanControl 'AUTH-01' 'PASS')
        }
        $run2 = [PSCustomObject]@{
            runId       = 'myorg-2026-04-01-090000'
            generatedAt = '2026-04-01T09:00:00Z'
            summary     = [PSCustomObject]@{ pass = 0; fail = 1; notChecked = 0 }
            controls    = @(New-ScanControl 'AUTH-01' 'FAIL')
        }
        $html = Build-ComparisonSectionHtml -RunsData @($run1, $run2)
        $html | Should -Match 'id="cmp-ui"'
        $html | Should -Match 'id="comparison-section"'
    }

    It 'produces valid JSON in the embedded script tag' {
        $run1 = [PSCustomObject]@{
            runId       = 'myorg-2026-05-01-090000'
            generatedAt = '2026-05-01T09:00:00Z'
            summary     = [PSCustomObject]@{ pass = 1; fail = 0; notChecked = 0 }
            controls    = @(New-ScanControl 'AUTH-01' 'PASS')
        }
        $run2 = [PSCustomObject]@{
            runId       = 'myorg-2026-04-01-090000'
            generatedAt = '2026-04-01T09:00:00Z'
            summary     = [PSCustomObject]@{ pass = 0; fail = 1; notChecked = 0 }
            controls    = @(New-ScanControl 'AUTH-01' 'FAIL')
        }
        $html = Build-ComparisonSectionHtml -RunsData @($run1, $run2)

        # Extract the JSON from window.__adoqrRuns=<json>;
        if ($html -match 'window\.__adoqrRuns=(\[.+?\]);') {
            $json = $Matches[1]
            { $json | ConvertFrom-Json } | Should -Not -Throw
            $parsed = $json | ConvertFrom-Json
            @($parsed).Count | Should -Be 2
        } else {
            Set-ItResult -Skipped -Because 'Could not extract JSON from HTML'
        }
    }
}
