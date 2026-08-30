# Loads helper functions from invoke-adoqr.ps1 into the current scope
# by walking the AST and re-evaluating just the function definitions we need.
# This lets Pester tests cover pure helpers without invoking the script (which
# requires -Organization, az login, etc.).

$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repoRoot 'invoke-adoqr.ps1'
if (-not (Test-Path $scriptPath)) {
    throw "invoke-adoqr.ps1 not found at $scriptPath"
}

$tokens = $null
$errs = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errs)
if ($errs.Count -gt 0) {
    throw "Failed to parse invoke-adoqr.ps1: $($errs[0].Message)"
}

$wantedFns = @(
    'Get-SafeProperty'
    'Get-EffectiveJobAuthorizationScope'
    'Get-ControlCategory'
    'New-ControlResult'
    'Test-PolicyAppliesToBranch'
    'Export-AssessmentToJson'
    'Import-ScanRunFromMarkdownReports'
    'Get-PriorScanRuns'
    'Build-ComparisonSectionHtml'
    'Get-NotCheckedReasonCategory'
    'Build-NotCheckedSectionHtml'
    'Get-RemediationSteps'
    'Write-RemediationHtmlReport'
    'Write-ExecutiveHtmlReport'
    'Get-AdoqrLogoDataUri'
    'Get-AdoqrHeaderCss'
    'Get-AdoqrHeaderHtml'
    'Import-AdoqrSettings'
    'Resolve-AdoApiHosts'
)

$funcs = $tree.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($wantedFns -contains $n.Name)
    }, $true)

foreach ($f in $funcs) {
    # Use the dot-source operator on a scriptblock so functions land in the caller's scope chain.
    . ([scriptblock]::Create($f.Extent.Text))
}

# Expose names for tests to assert wiring
$script:LoadedHelperNames = $funcs.Name
