#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . $PSScriptRoot/_Bootstrap.ps1
}

Describe 'Test-ShouldAutoOpenReport' {
    It 'opens when no suppressing environment variables are set' {
        Test-ShouldAutoOpenReport -EnvironmentVariables @{} | Should -BeTrue
    }

    It 'suppresses when ADOQR_NO_OPEN is set' {
        Test-ShouldAutoOpenReport -EnvironmentVariables @{ ADOQR_NO_OPEN = '1' } | Should -BeFalse
    }

    It 'suppresses under Azure Pipelines (TF_BUILD)' {
        Test-ShouldAutoOpenReport -EnvironmentVariables @{ TF_BUILD = 'True' } | Should -BeFalse
    }

    It 'suppresses under generic CI (CI)' {
        Test-ShouldAutoOpenReport -EnvironmentVariables @{ CI = 'true' } | Should -BeFalse
    }

    It 'treats empty/whitespace values as not set' {
        Test-ShouldAutoOpenReport -EnvironmentVariables @{ ADOQR_NO_OPEN = ''; TF_BUILD = '   '; CI = $null } |
            Should -BeTrue
    }
}
