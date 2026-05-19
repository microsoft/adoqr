#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . $PSScriptRoot/_Bootstrap.ps1

    function script:New-Result {
        param($Id, $Status, $Severity = 'Medium', $Control = 'Test Control', $Finding = 'Manual review required.')
        New-ControlResult -Id $Id -Status $Status -Severity $Severity -Control $Control -Finding $Finding
    }
}

Describe 'Get-NotCheckedReasonCategory' {
    It 'classifies common not-checked reasons' {
        Get-NotCheckedReasonCategory 'Manual review required. Verify setting.' | Should -Be 'Manual review required'
        Get-NotCheckedReasonCategory 'Requires -IncludeGraphCheck switch to cross-reference with Entra ID.' | Should -Be 'Prerequisite or permission needed'
        Get-NotCheckedReasonCategory 'Could not retrieve org pipeline settings.' | Should -Be 'Data unavailable'
        Get-NotCheckedReasonCategory 'Invite new users policy not found.' | Should -Be 'Setting not found'
        Get-NotCheckedReasonCategory 'No Project Administrator members found to check.' | Should -Be 'No applicable data found'
    }
}

Describe 'Build-NotCheckedSectionHtml' {
    It 'returns an empty string when there are no not-checked controls' {
        $org = [PSCustomObject]@{
            Results = @((New-Result 'AUTH-01' 'PASS'))
        }

        Build-NotCheckedSectionHtml -OrgSummary $org -ProjectSummaries @() | Should -Be ''
    }

    It 'renders an explanation, reason groups, and scoped details' {
        $org = [PSCustomObject]@{
            Results = @(
                (New-Result 'AUDIT-01' 'NOT CHECKED' 'Medium' 'Audit Log Backup' 'Manual review required. Verify audit logs are backed up to external storage.')
            )
        }
        $projects = @(
            [PSCustomObject]@{
                Project = 'Web'
                Results = @(
                    (New-Result 'USER-02' 'NOT CHECKED' 'Medium' 'Deleted AAD Users' 'Requires -IncludeGraphCheck switch to cross-reference with Entra ID.'),
                    (New-Result 'REPO-01' 'PASS' 'Low' 'Inactive Repositories' 'OK')
                )
            }
        )

        $html = Build-NotCheckedSectionHtml -OrgSummary $org -ProjectSummaries $projects
        $html | Should -Match 'id="not-checked-section"'
        $html | Should -Match 'Not checked does not mean failed'
        $html | Should -Match 'Manual review required'
        $html | Should -Match 'Prerequisite or permission needed'
        $html | Should -Match 'Project: Web'
        $html | Should -Match 'Why it was not checked'
    }

    It 'renders as a collapsible panel with a count badge and chevron in the summary' {
        $org = [PSCustomObject]@{
            Results = @(
                (New-Result 'AUDIT-01' 'NOT CHECKED' 'Medium' 'Audit Log Backup' 'Manual review required.'),
                (New-Result 'USER-02' 'NOT CHECKED' 'Medium' 'Deleted AAD Users' 'Requires -IncludeGraphCheck switch.')
            )
        }

        $html = Build-NotCheckedSectionHtml -OrgSummary $org -ProjectSummaries @()
        $html | Should -Match '<details[^>]*class="[^"]*\bsection-collapsible\b'
        $html | Should -Match '<summary[^>]*class="[^"]*\bsection-collapsible-summary\b'
        $html | Should -Match 'class="section-collapsible-count"[^>]*>2<'
        $html | Should -Match 'class="section-collapsible-chevron"'
        # Must not be open by default (no `open` attribute on the outer details)
        $html | Should -Not -Match '<details[^>]*\bopen\b[^>]*class="[^"]*\bsection-collapsible\b'
    }
}