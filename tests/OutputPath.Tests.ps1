#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . $PSScriptRoot/_Bootstrap.ps1
}

Describe 'Resolve-AdoqrOutputPath' {
    It 'prefers an explicit -OutputPath over the env var and default' {
        Resolve-AdoqrOutputPath -ExplicitPath '/explicit' -EnvPath '/env' -DefaultPath '/def' |
            Should -Be '/explicit'
    }

    It 'honors ADOQR_OUTPUT_PATH when no explicit path is given' {
        Resolve-AdoqrOutputPath -ExplicitPath $null -EnvPath '/env' -DefaultPath '/def' |
            Should -Be '/env'
    }

    It 'treats a whitespace-only explicit path as not provided' {
        Resolve-AdoqrOutputPath -ExplicitPath '   ' -EnvPath '/env' -DefaultPath '/def' |
            Should -Be '/env'
    }

    It 'ignores an empty ADOQR_OUTPUT_PATH and uses the default' {
        Resolve-AdoqrOutputPath -ExplicitPath $null -EnvPath '' -DefaultPath '/def' |
            Should -Be '/def'
    }

    It 'falls back to the default when neither explicit nor env is set' {
        Resolve-AdoqrOutputPath -ExplicitPath $null -EnvPath $null -DefaultPath '/def' |
            Should -Be '/def'
    }
}
