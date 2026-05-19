#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . $PSScriptRoot/_Bootstrap.ps1
}

Describe 'Write-RemediationHtmlReport' {
    It 'renders tabs and controls for accepted risk workflow' {
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $filePath = Join-Path $tempDir 'remediation.html'

        $remediation = [PSCustomObject]@{
            ControlId     = 'AUTH-01'
            ControlName   = 'Conditional Access'
            Severity      = 'High'
            Count         = 3
            AffectedAreas = @('Organization', 'Project: Web')
            Finding       = 'Conditional access is not enforced.'
        }

        try {
            Write-RemediationHtmlReport -FilePath $filePath -OrgName 'Contoso' -ExecReportFile 'executive.html' -Remediations @($remediation)

            $html = Get-Content -Path $filePath -Raw
            $html | Should -Match 'Accepted Controls'
            $html | Should -Match 'data-remed-tab="accepted"'
            $html | Should -Match 'data-open-accept'
            $html | Should -Match 'Reason for accepting this control'
            $html | Should -Match 'Save accepted control'
            $html | Should -Match 'Undo acceptance'
            $html | Should -Match 'data-accepted-date'
            $html | Should -Match 'data-control-key="AUTH-01\|Conditional Access"'
            $html | Should -Match 'aria-required="true"'
            $html | Should -Match 'localStorage'
            $html | Should -Match 'saved per organization for future remediation reports opened in the same browser'
        }
        finally {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'uses the accepted-controls storage key scoped to the organization name' {
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        $filePath = Join-Path $tempDir 'remediation.html'

        $remediation = [PSCustomObject]@{
            ControlId     = 'AUTH-01'
            ControlName   = 'Conditional Access'
            Severity      = 'High'
            Count         = 1
            AffectedAreas = @('Organization')
            Finding       = 'Conditional access is not enforced.'
        }

        try {
            Write-RemediationHtmlReport -FilePath $filePath -OrgName 'Fabrikam' -ExecReportFile 'executive.html' -Remediations @($remediation)

            (Get-Content -Path $filePath -Raw) | Should -Match 'adoqr\.acceptedControls\.Fabrikam'
        }
        finally {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
