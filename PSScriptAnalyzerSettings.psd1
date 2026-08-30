# PSScriptAnalyzer configuration for adoqr
#
# Conservative ruleset: keeps all default rules enabled but downgrades a small
# number of patterns that are intentional in this codebase.

@{
    Severity = @('Error', 'Warning')

    # Rules we intentionally suppress, with rationale:
    ExcludeRules = @(
        # The script uses Invoke-Expression to load extracted function bodies
        # into parallel runspaces — an explicit, controlled use, not user input.
        'PSAvoidUsingInvokeExpression'

        # Write-Host is used for human-facing progress and summary output on
        # the console. Switching to Write-Information would suppress output by
        # default and break the interactive UX.
        'PSAvoidUsingWriteHost'

        # PSCustomObject literals built incrementally are clearer than
        # PowerShell-data-style hashtables for the assessment result shape.
        'PSUseDeclaredVarsMoreThanAssignments'

        # Test-* functions name plural noun forms intentionally — they
        # describe groups of checks (Test-OrgUsers, Test-Repositories), not
        # single-resource verbs.
        'PSUseSingularNouns'

        # Modern PowerShell guidance is UTF-8 *without* a BOM. The repo's
        # JSON writer goes out of its way to produce BOM-free output.
        'PSUseBOMForUnicodeEncodedFile'

        # ForEach-Object -Parallel uses dot-sourced function definitions and
        # $using: variables correctly. The analyzer flags the use of param
        # names from the calling scope as false positives.
        'PSUseUsingScopeModifierInNewRunspaces'
        'PSReviewUnusedParameter'

        # Export-AssessmentToJson and the report writers produce files on
        # disk but are internal helpers — not public cmdlets that need
        # -WhatIf / -Confirm semantics.
        'PSUseShouldProcessForStateChangingFunctions'

        # Get-PriorScanRuns intentionally silences all errors from reading
        # prior scan files — corrupt, unreadable, or schema-invalid files
        # should be skipped without surfacing noise to the user.
        'PSAvoidUsingEmptyCatchBlock'

        # The repo's .psd1 files are PowerShell *data* files — a settings
        # example (adoqr.settings.example.psd1) and the remediation-steps data
        # table — not module manifests, so this rule only ever fires as a false
        # positive here.
        'PSMissingModuleManifestField'
    )
}
