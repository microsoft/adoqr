<#
.SYNOPSIS
    Azure DevOps Quick Review Script (adoqr)
.DESCRIPTION
    Reviews an Azure DevOps organization and its projects against
    Azure DevOps best practices and Microsoft recommendations, by collecting
    settings via Azure CLI and the ADO REST API.

    Produces Markdown report files with PASS/FAIL/NOT CHECKED results for
    115+ best-practice checks, plus an executive HTML summary and a
    prioritized remediation plan.
.PARAMETER Organization
    The ADO organization URL (e.g. "https://dev.azure.com/MyOrg") or short name ("MyOrg").
.PARAMETER Project
    Optional. One or more project names. If omitted, all projects are assessed.
.PARAMETER OutputPath
    Directory for report files. Defaults to current directory.
.PARAMETER MaxParallel
    Maximum number of projects to assess concurrently. Default 1 (sequential).
    Requires PowerShell 7+. Values 3-5 recommended to avoid ADO rate limiting.
.PARAMETER IncludeGraphCheck
    When specified, cross-references ADO users with Entra ID via Microsoft Graph API
    to detect deleted or disabled AAD users (USER-02). Requires the caller to have
    Microsoft Graph User.Read.All permissions via 'az login'.
.PARAMETER OutputFormat
    One or more output formats to produce. Defaults to 'markdown','html' (the
    canonical adoqr experience). Pass 'json' or 'all' to additionally write a
    structured scan document next to the HTML reports — useful for downstream
    tooling, pipelines, and Copilot/MCP integrations. Schema is documented in
    schemas/scan.schema.json.
.EXAMPLE
    .\invoke-adoqr.ps1 -Organization "MyOrg"
.EXAMPLE
    .\invoke-adoqr.ps1 -Organization "https://dev.azure.com/MyOrg" -Project "WebApp","API"
.EXAMPLE
    .\invoke-adoqr.ps1 -Organization "MyOrg" -OutputPath "C:\Reports"
.EXAMPLE
    .\invoke-adoqr.ps1 -Organization "MyOrg" -MaxParallel 5
.EXAMPLE
    .\invoke-adoqr.ps1 -Organization "MyOrg" -IncludeGraphCheck
.EXAMPLE
    .\invoke-adoqr.ps1 -Organization "MyOrg" -OutputFormat all
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Organization,

    [Parameter()]
    [string[]]$Project,

    [Parameter()]
    [string]$OutputPath = (Join-Path $PSScriptRoot "assessments"),

    [Parameter()]
    [ValidateRange(1, 20)]
    [int]$MaxParallel = 1,

    [Parameter()]
    [switch]$IncludeGraphCheck,

    [Parameter()]
    [ValidateSet('markdown', 'html', 'json', 'all')]
    [string[]]$OutputFormat = @('markdown', 'html')
)

Set-StrictMode -Off
$ErrorActionPreference = "Stop"
trap {
    Write-Host "FATAL ERROR at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    Write-Host "Message: $($_.Exception.Message)" -ForegroundColor Red
    break
}

#region Configuration

$script:CredentialPatterns = @(
    'password', 'passwd', 'pwd', 'secret', 'key', 'token',
    'connectionstring', 'conn_string', 'apikey', 'api_key',
    'access_key', 'accesskey', 'client_secret', 'clientsecret',
    'sas', 'signing', 'certificate'
)
$script:CredentialRegex = ($script:CredentialPatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'
$script:InactiveDays = 90
$script:InactiveRepoDays = 180
$script:BroadGroups = @(
    'Contributors', 'Project Valid Users', 'Project Collection Valid Users',
    'Build Administrators', 'Endpoint Administrators'
)
$script:ProductionKeywords = @('prod', 'production', 'prd', 'live', 'release')

#endregion

#region Helpers

function Get-AdoBearerToken {
    try {
        $token = az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --query accessToken -o tsv 2>&1
        if ($LASTEXITCODE -ne 0) { throw "az account get-access-token failed: $token" }
        return $token.Trim()
    }
    catch {
        throw "Failed to obtain bearer token. Ensure you are logged in with 'az login'. Error: $_"
    }
}

function Invoke-AdoApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Header,
        [string]$Method = "GET",
        [string]$Body = $null,
        [int]$MaxRetries = 3
    )
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $params = @{
                Uri         = $Uri
                Headers     = $Header
                Method      = $Method
                ErrorAction = 'Stop'
            }
            if ($Body) { $params['Body'] = $Body; $params['ContentType'] = 'application/json' }

            # Use -ResponseHeadersVariable (PS 7+) for fast header access without Invoke-WebRequest overhead
            $responseHeaders = $null
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $params['ResponseHeadersVariable'] = 'responseHeaders'
            }
            $response = Invoke-RestMethod @params

            # --- Adaptive rate-limit monitoring (PS 7+ only) ---
            if ($responseHeaders) {
                $retryAfter = $responseHeaders['Retry-After']
                if ($retryAfter -is [array]) { $retryAfter = $retryAfter[0] }

                if ($retryAfter) {
                    $waitSec = [math]::Max(1, [int]$retryAfter)
                    Write-Warning "ADO throttling active (Retry-After: ${waitSec}s). Slowing down..."
                    Start-Sleep -Seconds $waitSec
                }
                else {
                    $remaining = $responseHeaders['X-RateLimit-Remaining']
                    $limit     = $responseHeaders['X-RateLimit-Limit']
                    if ($remaining -is [array]) { $remaining = $remaining[0] }
                    if ($limit -is [array])     { $limit = $limit[0] }

                    if ($remaining -and $limit) {
                        $pctRemaining = [double]$remaining / [math]::Max(1, [double]$limit)
                        if ($pctRemaining -le 0.10) {
                            Write-Warning ("Rate limit pressure: {0}/{1} TSTUs remaining ({2:P0}). Pausing 2s..." -f $remaining, $limit, $pctRemaining)
                            Start-Sleep -Seconds 2
                        }
                    }
                }
            }

            return $response
        }
        catch {
            $status = 0
            if ($_.Exception.Response) {
                try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = 0 }
            }
            if ($status -eq 429 -and $attempt -lt $MaxRetries) {
                $retryWait = 0
                try { $retryWait = [int]$_.Exception.Response.Headers['Retry-After'] } catch { $retryWait = 0 }
                $wait = if ($retryWait -gt 0) { $retryWait } else { [math]::Pow(2, $attempt) }
                Write-Warning "Rate limited (429). Waiting ${wait}s before retry ($attempt/$MaxRetries)..."
                Start-Sleep -Seconds $wait
                continue
            }
            if ($status -in @(401, 403, 404)) {
                $statusMsg = switch ($status) {
                    401 { 'Unauthorized — check your login/token' }
                    403 { 'Forbidden — insufficient permissions' }
                    404 { 'Not found — resource may not exist or feature is not enabled' }
                }
                Write-Verbose "HTTP $status on $Uri — $statusMsg. Skipping."
                return $null
            }
            if ($attempt -eq $MaxRetries) {
                Write-Warning "Failed after $MaxRetries attempts on $Uri : $_"
                return $null
            }
            Start-Sleep -Seconds 1
        }
    }
    return $null
}

function Invoke-AzCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Command
    )
    try {
        # Temporarily allow stderr without throwing so we can separate streams
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $rawOutput = Invoke-Expression "az $Command 2>&1"
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP

        # Separate stdout (strings) from stderr (ErrorRecords)
        $stdout = @($rawOutput | Where-Object { $_ -is [string] })

        if ($exitCode -ne 0) {
            Write-Warning "az $Command failed (exit code $exitCode)"
            return $null
        }
        if ($stdout.Count -gt 0) {
            $json = $stdout -join "`n"
            return $json | ConvertFrom-Json
        }
        return $null
    }
    catch {
        Write-Warning "az $Command threw: $_"
        return $null
    }
}

function Get-ControlCategory {
    <#
    .SYNOPSIS
        Maps a control Id (e.g. AUTH-01, BUILD-04) to one of the
        ADO-native best-practice categories used in JSON output.
    .DESCRIPTION
        Categories: Identity & Access, Governance, Audit Log,
        Pipelines & Actions, Secrets & Credentials,
        Repos & Branch Protection, Service Connections, Resources,
        PAT Hygiene, Other.
    #>
    [CmdletBinding()]
    param([string]$Id)

    if (-not $Id) { return 'Other' }

    # Exact-Id overrides take precedence over prefix matches
    $exact = @{
        'PROJ-01'  = 'Governance'
        'PROJ-02'  = 'Identity & Access'
        'PROJ-03'  = 'Identity & Access'
        'PROJ-04'  = 'Identity & Access'
        'PROJ-05'  = 'Identity & Access'
        'PROJ-06'  = 'Identity & Access'
        'PROJ-07'  = 'Identity & Access'
        'PROJ-08'  = 'Identity & Access'
        'PROJ-13'  = 'Resources'
        'PROJ-14'  = 'Secrets & Credentials'
        'PROJ-15'  = 'Secrets & Credentials'
        'PROJ-16'  = 'Governance'
        'PROJ-17'  = 'Governance'
        'BUILD-01' = 'Secrets & Credentials'
        'BUILD-03' = 'Secrets & Credentials'
        'REL-01'   = 'Secrets & Credentials'
    }
    if ($exact.ContainsKey($Id)) { return $exact[$Id] }

    # Prefix → category fallbacks (longer prefixes first to avoid
    # PAT vs PATPOL and PIPELINE vs nothing-shorter clashes)
    $prefixes = @(
        @{ Prefix = 'PIPELINE-'; Category = 'Pipelines & Actions' }
        @{ Prefix = 'PATPOL-';   Category = 'PAT Hygiene' }
        @{ Prefix = 'COPILOT-';  Category = 'Governance' }
        @{ Prefix = 'BRANCH-';   Category = 'Repos & Branch Protection' }
        @{ Prefix = 'ACCESS-';   Category = 'Identity & Access' }
        @{ Prefix = 'ADMIN-';    Category = 'Identity & Access' }
        @{ Prefix = 'AUDIT-';    Category = 'Audit Log' }
        @{ Prefix = 'AUTH-';     Category = 'Identity & Access' }
        @{ Prefix = 'BADGE-';    Category = 'Governance' }
        @{ Prefix = 'BUILD-';    Category = 'Pipelines & Actions' }
        @{ Prefix = 'ENV-';      Category = 'Resources' }
        @{ Prefix = 'EXT-';      Category = 'Governance' }
        @{ Prefix = 'FEED-';     Category = 'Resources' }
        @{ Prefix = 'GOV-';      Category = 'Governance' }
        @{ Prefix = 'OAUTH-';    Category = 'Governance' }
        @{ Prefix = 'PAT-';      Category = 'PAT Hygiene' }
        @{ Prefix = 'PERM-';     Category = 'Identity & Access' }
        @{ Prefix = 'PROJ-';     Category = 'Identity & Access' }
        @{ Prefix = 'REL-';      Category = 'Pipelines & Actions' }
        @{ Prefix = 'REPO-';     Category = 'Repos & Branch Protection' }
        @{ Prefix = 'SC-';       Category = 'Service Connections' }
        @{ Prefix = 'SF-';       Category = 'Resources' }
        @{ Prefix = 'AP-';       Category = 'Resources' }
        @{ Prefix = 'USER-';     Category = 'Identity & Access' }
        @{ Prefix = 'VG-';       Category = 'Secrets & Credentials' }
    )

    foreach ($p in $prefixes) {
        if ($Id.StartsWith($p.Prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $p.Category
        }
    }
    return 'Other'
}

function New-ControlResult {
    param(
        [string]$Id,
        [ValidateSet('PASS','FAIL','NOT CHECKED')][string]$Status,
        [ValidateSet('High','Medium','Low')][string]$Severity,
        [string]$Control,
        [string]$Finding,
        [string]$Category
    )
    if (-not $Category) { $Category = Get-ControlCategory -Id $Id }
    [PSCustomObject]@{
        Id       = $Id
        Status   = $Status
        Severity = $Severity
        Category = $Category
        Control  = $Control
        Finding  = $Finding
    }
}

function Test-LooksLikeSecret {
    param([string]$Name)
    return $Name -imatch $script:CredentialRegex
}

function Test-IsUrlValue {
    param([string]$Value)
    return $Value -imatch '^https?://'
}

function Test-IsBroadGroup {
    param([string]$GroupName)
    foreach ($bg in $script:BroadGroups) {
        if ($GroupName -ilike "*$bg*") { return $true }
    }
    return $false
}

function Get-SafeProperty {
    param($Object, [string]$Property)
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties[$Property]) { return $Object.$Property }
    return $null
}

function Test-IsGuestMember {
    param($Member)
    $mail = Get-SafeProperty $Member 'mailAddress'
    $alias = Get-SafeProperty $Member 'directoryAlias'
    $displayName = Get-SafeProperty $Member 'displayName'
    if ($mail -and $mail -imatch '#EXT#') { return $true }
    if ($alias -and $alias -imatch '#EXT#') { return $true }
    if ($displayName -and $displayName -imatch '#EXT#') { return $true }
    return $false
}

function Test-IsProductionStage {
    param([string]$Name)
    foreach ($kw in $script:ProductionKeywords) {
        if ($Name -ilike "*$kw*") { return $true }
    }
    return $false
}

function Test-PolicyAppliesToBranch {
    <#
    .SYNOPSIS
        Returns $true if a /policy/configurations entry scopes to (and is
        enabled for) the given repository + refName combination.
    .DESCRIPTION
        ADO branch policies have a settings.scope[] array whose entries are
        { repositoryId, refName, matchKind }. A missing repositoryId means the
        policy applies to all repos in the project; a missing refName means it
        applies to all branches in the repo. matchKind is 'exact' or 'prefix'.
    #>
    [CmdletBinding()]
    param(
        $Policy,
        [Parameter(Mandatory)][string]$RepoId,
        [Parameter(Mandatory)][string]$RefName
    )

    if (-not $Policy) { return $false }
    $isEnabled = Get-SafeProperty $Policy 'isEnabled'
    if ($isEnabled -eq $false) { return $false }

    $settings = Get-SafeProperty $Policy 'settings'
    if (-not $settings) { return $false }
    $scopes = Get-SafeProperty $settings 'scope'
    if (-not $scopes) { return $false }

    foreach ($s in @($scopes)) {
        $sRepo  = Get-SafeProperty $s 'repositoryId'
        $sRef   = Get-SafeProperty $s 'refName'
        $sMatch = Get-SafeProperty $s 'matchKind'

        # Repo scope: missing/empty means project-wide
        if ($sRepo -and $sRepo -ne $RepoId) { continue }

        # Branch scope
        if (-not $sRef) { return $true }
        if (-not $sMatch -or $sMatch -ieq 'exact') {
            if ($sRef -ieq $RefName) { return $true }
        }
        elseif ($sMatch -ieq 'prefix') {
            if ($RefName.StartsWith($sRef, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
    }
    return $false
}

function Write-AssessmentReport {
    param(
        [string]$FilePath,
        [string]$Title,
        [string]$Scope,
        [PSCustomObject[]]$Results,
        [switch]$Quiet
    )
    $passCount = @($Results | Where-Object Status -eq 'PASS').Count
    $failCount = @($Results | Where-Object Status -eq 'FAIL').Count
    $ncCount   = @($Results | Where-Object Status -eq 'NOT CHECKED').Count
    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Sort: FAIL first (High→Med→Low), then NOT CHECKED, then PASS
    $sorted = $Results | Sort-Object @{Expression={
        switch ($_.Status) { 'FAIL'{0} 'NOT CHECKED'{1} 'PASS'{2} }
    }}, @{Expression={
        switch ($_.Severity) { 'High'{0} 'Medium'{1} 'Low'{2} }
    }}

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# $Title")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("| Field | Value |")
    [void]$sb.AppendLine("|-------|-------|")
    [void]$sb.AppendLine("| **Assessment Date** | $date |")
    [void]$sb.AppendLine("| **Scope** | $Scope |")
    [void]$sb.AppendLine("| **Assessor** | invoke-adoqr.ps1 |")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("## Summary")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("``$passCount PASS | $failCount FAIL | $ncCount NOT CHECKED``")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("## Control Results")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("| | Status | Severity | Control | Finding |")
    [void]$sb.AppendLine("|---|--------|----------|---------|---------|")
    foreach ($r in $sorted) {
        $icon = switch ($r.Status) { 'PASS' { '✅' } 'FAIL' { '❌' } 'NOT CHECKED' { '⚠️' } }
        $sevIcon = switch ($r.Severity) { 'High' { '🔴' } 'Medium' { '🟡' } 'Low' { '🔵' } }
        $escapedFinding = $r.Finding -replace '\|', '\|' -replace '\r?\n', ' '
        [void]$sb.AppendLine("| $icon | $($r.Status) | $sevIcon $($r.Severity) | $($r.Id): $($r.Control) | $escapedFinding |")
    }
    [void]$sb.AppendLine()

    $criticals = $sorted | Where-Object { $_.Status -eq 'FAIL' }
    if ($criticals) {
        [void]$sb.AppendLine("## Improvement Opportunities")
        [void]$sb.AppendLine()
        foreach ($c in $criticals) {
            $sevIcon = switch ($c.Severity) { 'High' { '🔴' } 'Medium' { '🟡' } 'Low' { '🔵' } }
            [void]$sb.AppendLine("### $sevIcon $($c.Id): $($c.Control) [$($c.Severity)]")
            [void]$sb.AppendLine()
            [void]$sb.AppendLine($c.Finding)
            [void]$sb.AppendLine()
        }
    }

    $sb.ToString() | Set-Content -Path $FilePath -Encoding utf8
    if (-not $Quiet) { Write-Host "  Report saved: $FilePath" -ForegroundColor Green }
}

function Export-AssessmentToJson {
    <#
    .SYNOPSIS
        Writes a single canonical scan document covering the org and every
        assessed project.
    .DESCRIPTION
        Conforms to schemas/scan.schema.json (schemaVersion 1.0). The document
        is purely additive — Markdown and HTML reports remain canonical.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$OrgName,
        [Parameter(Mandatory)][string]$OrgUrl,
        [PSCustomObject[]]$OrgResults,
        [PSCustomObject[]]$ProjectResults,
        [double]$ElapsedSeconds = 0
    )

    $controls = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($OrgResults) {
        foreach ($r in $OrgResults) {
            $cat = if ($r.PSObject.Properties['Category'] -and $r.Category) { $r.Category } else { Get-ControlCategory -Id $r.Id }
            $controls.Add([PSCustomObject]@{
                id       = $r.Id
                status   = $r.Status
                severity = $r.Severity
                category = $cat
                control  = $r.Control
                finding  = $r.Finding
                scope    = [PSCustomObject]@{
                    type         = 'organization'
                    organization = $OrgName
                    project      = $null
                }
            })
        }
    }

    $projectsArr = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($ProjectResults) {
        foreach ($pr in $ProjectResults) {
            $name = $pr.Project
            $items = $pr.Results
            $pPass = @($items | Where-Object Status -eq 'PASS').Count
            $pFail = @($items | Where-Object Status -eq 'FAIL').Count
            $pNc   = @($items | Where-Object Status -eq 'NOT CHECKED').Count

            $projectsArr.Add([PSCustomObject]@{
                name    = $name
                summary = [PSCustomObject]@{ pass = $pPass; fail = $pFail; notChecked = $pNc }
            })

            foreach ($r in $items) {
                $cat = if ($r.PSObject.Properties['Category'] -and $r.Category) { $r.Category } else { Get-ControlCategory -Id $r.Id }
                $controls.Add([PSCustomObject]@{
                    id       = $r.Id
                    status   = $r.Status
                    severity = $r.Severity
                    category = $cat
                    control  = $r.Control
                    finding  = $r.Finding
                    scope    = [PSCustomObject]@{
                        type         = 'project'
                        organization = $OrgName
                        project      = $name
                    }
                })
            }
        }
    }

    $totalPass = @($controls | Where-Object status -eq 'PASS').Count
    $totalFail = @($controls | Where-Object status -eq 'FAIL').Count
    $totalNc   = @($controls | Where-Object status -eq 'NOT CHECKED').Count

    $doc = [PSCustomObject]@{
        '$schema'     = 'https://raw.githubusercontent.com/microsoft/adoqr/main/schemas/scan.schema.json'
        schemaVersion = '1.0'
        meta          = [PSCustomObject]@{
            tool           = 'adoqr'
            generator      = 'invoke-adoqr.ps1'
            generatedAt    = (Get-Date).ToUniversalTime().ToString('o')
            elapsedSeconds = [math]::Round($ElapsedSeconds, 2)
        }
        organization  = [PSCustomObject]@{
            name = $OrgName
            url  = $OrgUrl
        }
        summary       = [PSCustomObject]@{
            pass       = $totalPass
            fail       = $totalFail
            notChecked = $totalNc
        }
        projects      = $projectsArr
        controls      = $controls
    }

    $json = $doc | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($FilePath, $json, [System.Text.UTF8Encoding]::new($false))
}

function Get-SafeFileName {
    param([string]$Name)
    return ($Name -replace '[^a-zA-Z0-9\-]', '-').ToLower().Trim('-')
}

function Add-ResultsSafe {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$List,
        $Items
    )
    if ($null -eq $Items) { return }
    $arr = @($Items)
    if ($arr.Count -gt 0) { $List.AddRange([PSCustomObject[]]$arr) }
}

function Get-FailedControlsFromReports {
    param(
        [string]$OrgReportPath,
        [PSCustomObject[]]$ProjectSummaries
    )
    $allFails = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Parse each markdown report for FAIL rows
    $reportFiles = @()
    if ($OrgReportPath -and (Test-Path $OrgReportPath)) { $reportFiles += @{ File = $OrgReportPath; Scope = 'Organization' } }
    foreach ($p in $ProjectSummaries) {
        if ($p.ReportFile -and (Test-Path $p.ReportFile)) { $reportFiles += @{ File = $p.ReportFile; Scope = $p.Project } }
    }

    foreach ($rf in $reportFiles) {
        $lines = Get-Content $rf.File -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            # Match table rows: | icon | STATUS | sevIcon SEVERITY | ID: Control | Finding |
            if ($line -match '^\|\s*❌\s*\|\s*FAIL\s*\|\s*(🔴|🟡|🔵)\s*(High|Medium|Low)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|') {
                $severity = $Matches[2]
                $control = $Matches[3].Trim()
                $finding = $Matches[4].Trim()
                # Extract the control name (strip ID prefix like "PROJ-01: ")
                $controlName = if ($control -match '^[A-Z]+-\d+:\s*(.+)$') { $Matches[1].Trim() } else { $control }
                $controlId = if ($control -match '^([A-Z]+-[\d\*]+):') { $Matches[1] } else { '' }
                $allFails.Add([PSCustomObject]@{
                    Scope       = $rf.Scope
                    Severity    = $severity
                    ControlId   = $controlId
                    ControlName = $controlName
                    Control     = $control
                    Finding     = $finding
                    SevOrder    = switch ($severity) { 'High' { 0 } 'Medium' { 1 } 'Low' { 2 } }
                })
            }
        }
    }

    # Group by control name, count occurrences, rank by severity then frequency
    $grouped = $allFails | Group-Object ControlName | ForEach-Object {
        $items = $_.Group
        $topSev = ($items | Sort-Object SevOrder | Select-Object -First 1).Severity
        $sevOrder = ($items | Sort-Object SevOrder | Select-Object -First 1).SevOrder
        $scopes = @($items | Select-Object -ExpandProperty Scope -Unique)
        $sampleFinding = ($items | Select-Object -First 1).Finding
        $controlId = ($items | Select-Object -First 1).ControlId
        [PSCustomObject]@{
            ControlId     = $controlId
            ControlName   = $_.Name
            Severity      = $topSev
            SevOrder      = $sevOrder
            Count         = $_.Count
            AffectedAreas = $scopes
            Finding       = $sampleFinding
        }
    } | Sort-Object SevOrder, @{Expression={$_.Count}; Descending=$true}

    return @($grouped)
}

function Get-RemediationSteps {
    param([string]$ControlName)

    if (-not $script:RemediationData) {
        $script:RemediationData = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'remediation-steps.psd1')
    }

    $result = $script:RemediationData[$ControlName]
    if (-not $result) {
        return @{
            Steps  = @('Review the finding details in the assessment report.', 'Navigate to the relevant settings area in Azure DevOps.', 'Apply the recommended configuration change.', 'Verify the fix by re-running the assessment.')
            DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
        }
    }
    return $result
}

function Write-RemediationHtmlReport {
    param(
        [string]$FilePath,
        [string]$OrgName,
        [string]$ExecReportFile,
        [PSCustomObject[]]$Remediations
    )

    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalIssues = ($Remediations | Measure-Object -Property Count -Sum).Sum
    $execFile = [System.IO.Path]::GetFileName($ExecReportFile)

    # Build remediation rows
    $rows = [System.Text.StringBuilder]::new()
    $rank = 0
    foreach ($r in $Remediations) {
        $rank++
        $sevColor = switch ($r.Severity) { 'High' { '#ef4444' } 'Medium' { '#f59e0b' } 'Low' { '#3b82f6' } }
        $sevBg = switch ($r.Severity) { 'High' { 'rgba(239,68,68,.12)' } 'Medium' { 'rgba(245,158,11,.12)' } 'Low' { 'rgba(59,130,246,.12)' } }
        $affectedList = ($r.AffectedAreas | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join ''
        $pctOfTotal = if ($totalIssues -gt 0) { [math]::Round(($r.Count / $totalIssues) * 100) } else { 0 }

        # Get remediation steps
        $stepInfo = Get-RemediationSteps -ControlName $r.ControlName
        $stepsHtml = ($stepInfo.Steps | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join ''
        $docLink = $stepInfo.DocUrl

        [void]$rows.AppendLine(@"
        <div class="remed-card">
          <div class="remed-header">
            <div class="remed-rank">#$rank</div>
            <div class="remed-title">
              <h3>$([System.Web.HttpUtility]::HtmlEncode($r.ControlName))</h3>
              <span class="sev-badge" style="background:$sevBg;color:$sevColor">$($r.Severity)</span>
            </div>
            <div class="remed-metric">
              <div class="metric-val">$($r.Count)</div>
              <div class="metric-lbl">issue$(if($r.Count -ne 1){'s'})</div>
            </div>
            <div class="remed-metric">
              <div class="metric-val">${pctOfTotal}%</div>
              <div class="metric-lbl">of all items</div>
            </div>
          </div>
          <div class="remed-body">
            <div class="remed-finding">
              <strong>Example finding:</strong> $([System.Web.HttpUtility]::HtmlEncode($r.Finding))
            </div>
            <div class="remed-affected">
              <strong>Affected areas ($($r.AffectedAreas.Count)):</strong>
              <ul>$affectedList</ul>
            </div>
          </div>
          <details class="remed-steps">
            <summary>How to adopt — Step-by-step instructions</summary>
            <ol>$stepsHtml</ol>
            <a class="doc-link" href="$([System.Web.HttpUtility]::HtmlAttributeEncode($docLink))" target="_blank" rel="noopener">📄 Microsoft Learn documentation &rarr;</a>
          </details>
          <div class="remed-bar-track">
            <div class="remed-bar-fill" style="width:${pctOfTotal}%;background:$sevColor"></div>
          </div>
        </div>
"@)
    }

    # Top 5 summary for the impact callout
    $top5 = @($Remediations | Select-Object -First 5)
    $top5Issues = ($top5 | Measure-Object -Property Count -Sum).Sum
    $top5Pct = if ($totalIssues -gt 0) { [math]::Round(($top5Issues / $totalIssues) * 100) } else { 0 }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Remediation Plan — $([System.Web.HttpUtility]::HtmlEncode($OrgName))</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
      --text: #f1f5f9; --text2: #94a3b8; --accent: #3b82f6;
      --pass: #22c55e; --fail: #ef4444; --warn: #f59e0b; --info: #3b82f6;
      --radius: 12px; --shadow: 0 4px 24px rgba(0,0,0,.3);
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg); color: var(--text); margin: 0; padding: 0; line-height: 1.6;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .container { max-width: 1000px; margin: 0 auto; padding: 2rem 1.5rem; }

    header { background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 2.5rem 0; border-bottom: 1px solid var(--surface2); }
    header h1 { margin: 0 0 .25rem; font-size: 1.75rem; font-weight: 700; }
    header .subtitle { color: var(--text2); font-size: .95rem; }
    .back-link { margin-top: .75rem; font-size: .9rem; }

    .impact-box {
      background: var(--surface); border-radius: var(--radius); padding: 1.5rem 2rem;
      margin: 2rem 0; box-shadow: var(--shadow); display: flex; align-items: center;
      gap: 2rem; flex-wrap: wrap; border-left: 4px solid var(--accent);
    }
    .impact-box .big-num { font-size: 3rem; font-weight: 800; color: var(--accent); line-height: 1; }
    .impact-box p { margin: 0; color: var(--text2); }
    .impact-box strong { color: var(--text); }

    .remed-card {
      background: var(--surface); border-radius: var(--radius); margin-bottom: 1rem;
      box-shadow: var(--shadow); overflow: hidden;
    }
    .remed-header {
      display: flex; align-items: center; gap: 1.25rem; padding: 1.25rem 1.5rem;
      flex-wrap: wrap;
    }
    .remed-rank {
      font-size: 1.5rem; font-weight: 800; color: var(--text2); min-width: 2.5rem;
    }
    .remed-title { flex: 1; min-width: 200px; }
    .remed-title h3 { margin: 0; font-size: 1.05rem; font-weight: 700; }
    .sev-badge {
      display: inline-block; padding: .15rem .6rem; border-radius: 999px;
      font-size: .75rem; font-weight: 700; text-transform: uppercase; margin-top: .25rem;
    }
    .remed-metric { text-align: center; min-width: 70px; }
    .metric-val { font-size: 1.5rem; font-weight: 800; color: var(--text); }
    .metric-lbl { font-size: .7rem; color: var(--text2); text-transform: uppercase; letter-spacing: .04em; }

    .remed-body { padding: 0 1.5rem 1.25rem; }
    .remed-finding { color: var(--text2); font-size: .9rem; margin-bottom: .75rem; }
    .remed-affected ul { margin: .25rem 0 0; padding-left: 1.25rem; }
    .remed-affected li { font-size: .85rem; color: var(--text2); }
    .remed-affected strong { color: var(--text); font-size: .9rem; }

    .remed-bar-track { height: 4px; background: var(--surface2); }
    .remed-bar-fill { height: 100%; transition: width .3s; }

    .remed-steps { padding: 0 1.5rem 1.25rem; }
    .remed-steps summary {
      cursor: pointer; font-weight: 700; font-size: .9rem; color: var(--accent);
      padding: .5rem 0; user-select: none; list-style: none;
    }
    .remed-steps summary::-webkit-details-marker { display: none; }
    .remed-steps summary::before { content: '▶ '; font-size: .7rem; }
    .remed-steps[open] summary::before { content: '▼ '; font-size: .7rem; }
    .remed-steps ol { margin: .5rem 0 0; padding-left: 1.5rem; }
    .remed-steps li { font-size: .9rem; color: var(--text2); padding: .25rem 0; }
    .remed-steps li::marker { color: var(--accent); font-weight: 700; }
    .remed-steps .doc-link { display: inline-block; margin-top: .5rem; font-size: .85rem; }

    .section { margin: 2.5rem 0; }
    .section h2 { font-size: 1.25rem; font-weight: 700; margin: 0 0 1rem; padding-bottom: .5rem; border-bottom: 1px solid var(--surface2); }

    footer { text-align: center; padding: 2rem; color: var(--text2); font-size: .8rem; border-top: 1px solid var(--surface2); margin-top: 3rem; }

    @media (max-width: 640px) {
      .remed-header { flex-direction: column; align-items: flex-start; }
      .impact-box { flex-direction: column; text-align: center; }
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>Remediation Plan</h1>
      <p class="subtitle">Prioritized remediation actions for <strong>$([System.Web.HttpUtility]::HtmlEncode($OrgName))</strong></p>
      <p class="back-link">&larr; <a href="$([System.Web.HttpUtility]::HtmlAttributeEncode($execFile))">Back to Executive Summary</a></p>
    </div>
  </header>

  <main class="container">

    <div class="impact-box">
      <div class="big-num">$($Remediations.Count)</div>
      <div>
        <p><strong>Unique remediation actions</strong> to address <strong>$totalIssues</strong> total item$(if($totalIssues -ne 1){'s'})</p>
        <p>The top 5 actions alone address <strong>$top5Issues</strong> items (<strong>${top5Pct}%</strong> of all items)</p>
      </div>
    </div>

    <section class="section">
      <h2>Remediation Actions — Ranked by Impact</h2>
      $($rows.ToString())
    </section>

  </main>

  <footer>
    <p>Generated by <strong>invoke-adoqr.ps1</strong> on $date</p>
  </footer>
</body>
</html>
"@

    $html | Set-Content -Path $FilePath -Encoding utf8
    Write-Host "  Remediation report saved: $FilePath" -ForegroundColor Green
}

function Write-ExecutiveHtmlReport {
    param(
        [string]$FilePath,
        [string]$OrgName,
        [string]$OrgUrl,
        [string]$ElapsedTime,
        [PSCustomObject]$OrgSummary,        # @{ Pass; Fail; NotChecked; ReportFile }
        [PSCustomObject[]]$ProjectSummaries, # @( @{ Project; Pass; Fail; NotChecked; ReportFile } )
        [PSCustomObject[]]$TopRemediations   # @( @{ Control; Severity; Count; AffectedAreas; Finding } )
    )

    $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalProjects = $ProjectSummaries.Count
    $totalPass = ($OrgSummary.Pass) + ($ProjectSummaries | Measure-Object -Property Pass -Sum).Sum
    $totalFail = ($OrgSummary.Fail) + ($ProjectSummaries | Measure-Object -Property Fail -Sum).Sum
    $totalNC   = ($OrgSummary.NotChecked) + ($ProjectSummaries | Measure-Object -Property NotChecked -Sum).Sum
    $totalControls = $totalPass + $totalFail + $totalNC
    $passPct = if ($totalControls -gt 0) { [math]::Round(($totalPass / $totalControls) * 100) } else { 0 }
    $failPct = if ($totalControls -gt 0) { [math]::Round(($totalFail / $totalControls) * 100) } else { 0 }
    $ncPct   = if ($totalControls -gt 0) { [math]::Round(($totalNC / $totalControls) * 100) } else { 0 }

    # Adoption rating
    $highFailProjects = @($ProjectSummaries | Where-Object { $_.Fail -gt 20 }).Count
    $riskLevel = if ($totalFail -gt 100 -or $highFailProjects -gt 5) { 'Limited' }
                 elseif ($totalFail -gt 50 -or $highFailProjects -gt 2) { 'Partial' }
                 elseif ($totalFail -gt 20) { 'Good' }
                 else { 'Strong' }
    $riskColor = switch ($riskLevel) { 'Limited' { '#dc2626' } 'Partial' { '#ea580c' } 'Good' { '#d97706' } 'Strong' { '#16a34a' } }

    # Sort projects: most failures first
    $sortedProjects = $ProjectSummaries | Sort-Object @{Expression={$_.Fail}; Descending=$true}

    # Build project rows
    $projectRows = [System.Text.StringBuilder]::new()
    foreach ($p in $sortedProjects) {
        $pTotal = $p.Pass + $p.Fail + $p.NotChecked
        $pPassPct = if ($pTotal -gt 0) { [math]::Round(($p.Pass / $pTotal) * 100) } else { 0 }
        $pStatus = if ($p.Fail -eq 0) { '<span class="badge badge-pass">EXEMPLARY</span>' }
                   elseif ($p.Fail -gt 15) { '<span class="badge badge-fail">PRIORITY</span>' }
                   elseif ($p.Fail -gt 5) { '<span class="badge badge-warn">REVIEW</span>' }
                   else { '<span class="badge badge-info">MINOR</span>' }
        $mdFile = [System.IO.Path]::GetFileName($p.ReportFile)
        [void]$projectRows.AppendLine(@"
              <tr>
                <td><strong>$([System.Web.HttpUtility]::HtmlEncode($p.Project))</strong></td>
                <td class="num">$($p.Pass)</td>
                <td class="num fail-text">$($p.Fail)</td>
                <td class="num">$($p.NotChecked)</td>
                <td>
                  <div class="bar-track" role="progressbar" aria-valuenow="$pPassPct" aria-valuemin="0" aria-valuemax="100" aria-label="$pPassPct percent adopted">
                    <div class="bar-fill" style="width:${pPassPct}%"></div>
                  </div>
                </td>
                <td>$pStatus</td>
                <td><a href="$([System.Web.HttpUtility]::HtmlAttributeEncode($mdFile))">Details</a></td>
              </tr>
"@)
    }

    # Top failures for executive attention (up to 10)
    $topFailProjects = @($sortedProjects | Where-Object { $_.Fail -gt 0 } | Select-Object -First 10)
    $topFailHtml = [System.Text.StringBuilder]::new()
    $rank = 0
    foreach ($tp in $topFailProjects) {
        $rank++
        $urgency = if ($tp.Fail -gt 15) { 'urgent' } elseif ($tp.Fail -gt 5) { 'warning' } else { 'info' }
        [void]$topFailHtml.AppendLine(@"
            <li class="action-item action-$urgency">
              <span class="action-rank">#$rank</span>
              <strong>$([System.Web.HttpUtility]::HtmlEncode($tp.Project))</strong> &mdash; $($tp.Fail) best practice(s) to adopt
            </li>
"@)
    }

    $orgMdFile = [System.IO.Path]::GetFileName($OrgSummary.ReportFile)

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Azure DevOps Quick Review — $([System.Web.HttpUtility]::HtmlEncode($OrgName))</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
      --text: #f1f5f9; --text2: #94a3b8; --accent: #3b82f6;
      --pass: #22c55e; --fail: #ef4444; --warn: #f59e0b; --info: #3b82f6;
      --radius: 12px; --shadow: 0 4px 24px rgba(0,0,0,.3);
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg); color: var(--text); margin: 0; padding: 0;
      line-height: 1.6;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    a:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; border-radius: 3px; }

    .container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }

    header { background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 2.5rem 0; border-bottom: 1px solid var(--surface2); }
    header h1 { margin: 0 0 .25rem; font-size: 1.75rem; font-weight: 700; }
    header .subtitle { color: var(--text2); font-size: .95rem; }
    .meta { display: flex; gap: 2rem; margin-top: 1rem; flex-wrap: wrap; }
    .meta-item { font-size: .85rem; color: var(--text2); }
    .meta-item strong { color: var(--text); }

    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }
    .card {
      background: var(--surface); border-radius: var(--radius); padding: 1.5rem;
      box-shadow: var(--shadow); text-align: center;
    }
    .card-value { font-size: 2.5rem; font-weight: 800; line-height: 1.1; }
    .card-label { font-size: .85rem; color: var(--text2); margin-top: .25rem; text-transform: uppercase; letter-spacing: .05em; }
    .card-pass .card-value { color: var(--pass); }
    .card-fail .card-value { color: var(--fail); }
    .card-nc   .card-value { color: var(--warn); }
    .card-risk .card-value { color: $riskColor; }

    .section { margin: 2.5rem 0; }
    .section h2 { font-size: 1.25rem; font-weight: 700; margin: 0 0 1rem; padding-bottom: .5rem; border-bottom: 1px solid var(--surface2); }

    /* Progress ring */
    .ring-container { display: flex; align-items: center; gap: 2rem; flex-wrap: wrap; }
    .ring { position: relative; width: 140px; height: 140px; }
    .ring svg { transform: rotate(-90deg); }
    .ring-label { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 1.75rem; font-weight: 800; }

    /* Table */
    .tbl-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
    table { width: 100%; border-collapse: collapse; font-size: .9rem; }
    th, td { padding: .75rem 1rem; text-align: left; border-bottom: 1px solid var(--surface2); }
    th { color: var(--text2); font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; background: var(--surface); position: sticky; top: 0; }
    tr:hover td { background: var(--surface); }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .fail-text { color: var(--fail); font-weight: 700; }

    .bar-track { height: 8px; background: var(--surface2); border-radius: 4px; overflow: hidden; min-width: 100px; }
    .bar-fill  { height: 100%; background: var(--pass); border-radius: 4px; transition: width .3s; }

    .badge {
      display: inline-block; padding: .2rem .6rem; border-radius: 999px;
      font-size: .75rem; font-weight: 700; text-transform: uppercase; letter-spacing: .03em;
    }
    .badge-pass { background: rgba(34,197,94,.15); color: var(--pass); }
    .badge-fail { background: rgba(239,68,68,.15); color: var(--fail); }
    .badge-warn { background: rgba(245,158,11,.15); color: var(--warn); }
    .badge-info { background: rgba(59,130,246,.15); color: var(--info); }

    /* Action items */
    .action-list { list-style: none; padding: 0; margin: 0; }
    .action-item {
      padding: .75rem 1rem; margin-bottom: .5rem; border-radius: 8px;
      background: var(--surface); display: flex; align-items: center; gap: .75rem;
    }
    .action-urgent { border-left: 4px solid var(--fail); }
    .action-warning { border-left: 4px solid var(--warn); }
    .action-info    { border-left: 4px solid var(--info); }
    .action-rank { color: var(--text2); font-size: .8rem; font-weight: 700; min-width: 2rem; }

    /* Org row */
    .org-summary {
      background: var(--surface); border-radius: var(--radius); padding: 1.25rem 1.5rem;
      margin-bottom: 1.5rem; box-shadow: var(--shadow);
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;
    }
    .org-summary .org-stats { display: flex; gap: 1.5rem; }
    .org-summary .stat { text-align: center; }
    .org-summary .stat-val { font-size: 1.5rem; font-weight: 800; }
    .org-summary .stat-lbl { font-size: .75rem; color: var(--text2); text-transform: uppercase; }

    footer { text-align: center; padding: 2rem; color: var(--text2); font-size: .8rem; border-top: 1px solid var(--surface2); margin-top: 3rem; }

    /* Skip link for WCAG */
    .skip-link {
      position: absolute; top: -100%; left: 1rem; background: var(--accent); color: #fff;
      padding: .5rem 1rem; border-radius: 4px; z-index: 100; font-weight: 700;
    }
    .skip-link:focus { top: 1rem; }

    @media (max-width: 640px) {
      .cards { grid-template-columns: 1fr 1fr; }
      .meta { flex-direction: column; gap: .5rem; }
      .ring-container { justify-content: center; }
    }
  </style>
</head>
<body>
  <a href="#main" class="skip-link">Skip to main content</a>

  <header>
    <div class="container">
      <h1>Azure DevOps Quick Review</h1>
      <p class="subtitle">Executive Summary for <strong>$([System.Web.HttpUtility]::HtmlEncode($OrgName))</strong></p>
      <div class="meta" role="list">
        <span class="meta-item" role="listitem"><strong>Date:</strong> $date</span>
        <span class="meta-item" role="listitem"><strong>Organization:</strong> $([System.Web.HttpUtility]::HtmlEncode($OrgUrl))</span>
        <span class="meta-item" role="listitem"><strong>Projects:</strong> $totalProjects</span>
        <span class="meta-item" role="listitem"><strong>Duration:</strong> $ElapsedTime</span>
      </div>
    </div>
  </header>

  <main id="main" class="container">

    <!-- KPI Cards -->
    <div class="cards" role="list">
      <div class="card card-risk" role="listitem">
        <div class="card-value" aria-label="Adoption level $riskLevel">$riskLevel</div>
        <div class="card-label">Best Practice Adoption</div>
      </div>
      <div class="card card-pass" role="listitem">
        <div class="card-value">$totalPass</div>
        <div class="card-label">Best Practices Adopted</div>
      </div>
      <div class="card card-fail" role="listitem">
        <div class="card-value">$totalFail</div>
        <div class="card-label">Improvement Opportunities</div>
      </div>
      <div class="card card-nc" role="listitem">
        <div class="card-value">$totalNC</div>
        <div class="card-label">Not Checked</div>
      </div>
    </div>

    <!-- Adoption Ring -->
    <section class="section" aria-label="Best practice adoption overview">
      <h2>Best Practice Adoption</h2>
      <div class="ring-container">
        <div class="ring" role="img" aria-label="$passPct percent of best practices adopted">
          <svg viewBox="0 0 140 140" width="140" height="140">
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--surface2)" stroke-width="12"/>
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--pass)" stroke-width="12"
                    stroke-dasharray="$([math]::Round(377 * $passPct / 100)) 377"
                    stroke-linecap="round"/>
          </svg>
          <span class="ring-label">${passPct}%</span>
        </div>
        <div>
          <p style="margin:0"><strong>$totalControls</strong> best practices evaluated across <strong>$totalProjects</strong> projects</p>
          <p style="margin:.25rem 0;color:var(--text2)">
            <span style="color:var(--pass)">&#9679; $totalPass adopted ($passPct%)</span> &nbsp;
            <span style="color:var(--fail)">&#9679; $totalFail opportunities ($failPct%)</span> &nbsp;
            <span style="color:var(--warn)">&#9679; $totalNC not checked ($ncPct%)</span>
          </p>
        </div>
      </div>
    </section>

    <!-- Priority Remediation Actions -->
    $(if ($TopRemediations -and $TopRemediations.Count -gt 0) {
        $totalRemedIssues = ($TopRemediations | Measure-Object -Property Count -Sum).Sum
        $top5Items = @($TopRemediations | Select-Object -First 5)
        $top5Count = ($top5Items | Measure-Object -Property Count -Sum).Sum
        $top5Pct = if ($totalRemedIssues -gt 0) { [math]::Round(($top5Count / $totalRemedIssues) * 100) } else { 0 }
        $remedFile = [System.IO.Path]::GetFileNameWithoutExtension($FilePath) -replace '-executive-summary$', ''
        $remedFileName = "$remedFile-remediation-plan.html"
        $remedHtml = [System.Text.StringBuilder]::new()
        $rRank = 0
        foreach ($ri in $top5Items) {
            $rRank++
            $rSevColor = switch ($ri.Severity) { 'High' { 'var(--fail)' } 'Medium' { 'var(--warn)' } 'Low' { 'var(--info)' } }
            $rUrgency = switch ($ri.Severity) { 'High' { 'urgent' } 'Medium' { 'warning' } 'Low' { 'info' } }
            [void]$remedHtml.AppendLine(@"
            <li class="action-item action-$rUrgency">
              <span class="action-rank">#$rRank</span>
              <div style="flex:1">
                <strong>$([System.Web.HttpUtility]::HtmlEncode($ri.ControlName))</strong>
                <span style="color:var(--text2);font-size:.85rem;margin-left:.5rem">$($ri.AffectedAreas.Count) area$(if($ri.AffectedAreas.Count -ne 1){'s'}) affected</span>
              </div>
              <div style="text-align:right;min-width:80px">
                <span style="font-size:1.25rem;font-weight:800;color:$rSevColor">$($ri.Count)</span>
                <span style="font-size:.75rem;color:var(--text2);display:block">issue$(if($ri.Count -ne 1){'s'})</span>
              </div>
            </li>
"@)
        }
    @"
    <section class="section" aria-label="Top remediation actions">
      <h2>Top 5 Remediation Actions</h2>
      <p style="color:var(--text2);margin-bottom:1rem">Adopting these 5 actions addresses <strong style="color:var(--text)">$top5Count</strong> of <strong style="color:var(--text)">$totalRemedIssues</strong> total items (<strong style="color:var(--text)">${top5Pct}%</strong>).
        <a href="$remedFileName">View full remediation plan &rarr;</a></p>
      <ol class="action-list">
        $($remedHtml.ToString())
      </ol>
    </section>
"@
    })

    <!-- Priority Actions by Project -->
    $(if ($topFailProjects.Count -gt 0) {
    @"
    <section class="section" aria-label="Priority actions by project">
      <h2>Projects With Improvement Opportunities</h2>
      <ol class="action-list">
        $($topFailHtml.ToString())
      </ol>
    </section>
"@
    })

    <!-- Organization -->
    <section class="section" aria-label="Organization review">
      <h2>Organization Review</h2>
      <div class="org-summary">
        <div>
          <strong>$([System.Web.HttpUtility]::HtmlEncode($OrgName))</strong>
          <span style="color:var(--text2);margin-left:.5rem">
            <a href="$([System.Web.HttpUtility]::HtmlAttributeEncode($orgMdFile))">Full Report</a>
          </span>
        </div>
        <div class="org-stats">
          <div class="stat"><div class="stat-val" style="color:var(--pass)">$($OrgSummary.Pass)</div><div class="stat-lbl">Adopted</div></div>
          <div class="stat"><div class="stat-val" style="color:var(--fail)">$($OrgSummary.Fail)</div><div class="stat-lbl">Opportunities</div></div>
          <div class="stat"><div class="stat-val" style="color:var(--warn)">$($OrgSummary.NotChecked)</div><div class="stat-lbl">Not Checked</div></div>
        </div>
      </div>
    </section>

    <!-- Project Table -->
    <section class="section" aria-label="Project results">
      <h2>Project Results</h2>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Project</th>
              <th scope="col" class="num">Adopted</th>
              <th scope="col" class="num">Opportunities</th>
              <th scope="col" class="num">Not Checked</th>
              <th scope="col">Adoption</th>
              <th scope="col">Status</th>
              <th scope="col">Report</th>
            </tr>
          </thead>
          <tbody>
            $($projectRows.ToString())
          </tbody>
        </table>
      </div>
    </section>

  </main>

  <footer>
    <p>Generated by <strong>invoke-adoqr.ps1</strong> on $date</p>
    <p>Detailed findings are available in the linked Markdown reports.</p>
  </footer>
</body>
</html>
"@

    $html | Set-Content -Path $FilePath -Encoding utf8
    Write-Host "  Executive report saved: $FilePath" -ForegroundColor Green
}

#endregion

#region Organization Assessment

function Test-OrgPolicies {
    param([string]$OrgUrl, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking organization policies..."

    # Primary method: Contribution HierarchyQuery API (works on all orgs)
    $policyMap = @{}
    $contributionBody = @{
        contributionIds = @("ms.vss-admin-web.organization-policies-data-provider")
        dataProviderContext = @{
            properties = @{
                sourcePage = @{
                    url = "$OrgUrl/_settings/organizationPolicy"
                    routeId = "ms.vss-admin-web.collection-admin-hub-route"
                    routeValues = @{
                        adminPivot = "organizationPolicy"
                        controller = "ContributedPage"
                        action = "Execute"
                    }
                }
            }
        }
    } | ConvertTo-Json -Depth 5

    $contribution = Invoke-AdoApi -Uri "$OrgUrl/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -Header $Header -Method "POST" -Body $contributionBody

    if ($contribution) {
        $dp = Get-SafeProperty (Get-SafeProperty $contribution 'dataProviders') 'ms.vss-admin-web.organization-policies-data-provider'
        $policiesObj = Get-SafeProperty $dp 'policies'
        if ($policiesObj) {
            # Flatten all policy categories into one map
            foreach ($category in $policiesObj.PSObject.Properties) {
                foreach ($entry in $category.Value) {
                    $pol = Get-SafeProperty $entry 'policy'
                    if ($pol) {
                        $polName = Get-SafeProperty $pol 'name'
                        if ($polName) { $policyMap[$polName] = $pol }
                    }
                }
            }
        }
    }

    # Fallback: try the OrganizationPolicy REST API
    if ($policyMap.Count -eq 0) {
        $policies = Invoke-AdoApi -Uri "$OrgUrl/_apis/OrganizationPolicy/Policies?api-version=7.1-preview.1" -Header $Header
        if ($policies -and $policies.value) {
            foreach ($p in $policies.value) {
                $policyMap[(Get-SafeProperty (Get-SafeProperty $p 'Policy') 'Name')] = $p.Policy
            }
        }
    }

    # AUTH-01: AAD Authentication — check if org is AAD-backed
    $connectionData = Invoke-AdoApi -Uri "$OrgUrl/_apis/connectiondata?api-version=7.1-preview" -Header $Header
    if ($connectionData) {
        $authUser = Get-SafeProperty $connectionData 'authenticatedUser'
        $subDesc = if ($authUser) { Get-SafeProperty $authUser 'subjectDescriptor' } else { '' }
        if ($subDesc -and $subDesc -imatch '^aad\.') {
            $results.Add((New-ControlResult -Id "AUTH-01" -Status "PASS" -Severity "High" -Control "AAD Authentication" -Finding "Organization is Azure AD backed (subject: aad)."))
        } else {
            $results.Add((New-ControlResult -Id "AUTH-01" -Status "FAIL" -Severity "High" -Control "AAD Authentication" -Finding "Organization does not appear to be AAD-backed. Connect to Azure AD via Organization Settings."))
        }
    } else {
        $results.Add((New-ControlResult -Id "AUTH-01" -Status "NOT CHECKED" -Severity "High" -Control "AAD Authentication" -Finding "Could not retrieve connection data to verify AAD authentication."))
    }

    # AUTH-03: Public Projects
    $projects = Invoke-AzCli -Command "devops project list --org $OrgUrl -o json"
    $publicProjects = @()
    if ($projects -and $projects.value) {
        $publicProjects = @($projects.value | Where-Object { $_.visibility -eq 'public' })
    }
    if ($publicProjects.Count -eq 0) {
        $results.Add((New-ControlResult -Id "AUTH-03" -Status "PASS" -Severity "High" -Control "Public Projects Disabled" -Finding "No public projects found."))
    } else {
        $names = ($publicProjects | ForEach-Object { $_.name }) -join ', '
        $results.Add((New-ControlResult -Id "AUTH-03" -Status "FAIL" -Severity "High" -Control "Public Projects Disabled" -Finding "Public projects found: $names. Change to Private via Project Settings."))
    }

    # Policy-based checks
    if ($policyMap.Count -gt 0) {
        # AUTH-05: Conditional Access
        $cap = $policyMap['Policy.EnforceAADConditionalAccess']
        $capVal = if ($cap) { Get-SafeProperty $cap 'effectiveValue' } else { $null }
        if ($capVal -eq $true) {
            $results.Add((New-ControlResult -Id "AUTH-05" -Status "PASS" -Severity "Medium" -Control "Conditional Access Policy" -Finding "AAD Conditional Access Policy validation is enabled."))
        } elseif ($null -ne $cap) {
            $results.Add((New-ControlResult -Id "AUTH-05" -Status "FAIL" -Severity "Medium" -Control "Conditional Access Policy" -Finding "AAD Conditional Access Policy validation is not enabled. Enable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "AUTH-05" -Status "NOT CHECKED" -Severity "Medium" -Control "Conditional Access Policy" -Finding "Conditional access policy not found in org settings. May require Azure AD P1/P2."))
        }

        # OAUTH-01: Third-Party OAuth
        $oauth = $policyMap['Policy.DisallowOAuthAuthentication']
        $oauthVal = if ($oauth) { Get-SafeProperty $oauth 'effectiveValue' } else { $null }
        if ($oauthVal -eq $true) {
            $results.Add((New-ControlResult -Id "OAUTH-01" -Status "PASS" -Severity "Medium" -Control "Third-Party OAuth Disabled" -Finding "Third-party application access via OAuth is disabled."))
        } elseif ($null -ne $oauth) {
            $results.Add((New-ControlResult -Id "OAUTH-01" -Status "FAIL" -Severity "Medium" -Control "Third-Party OAuth Disabled" -Finding "Third-party application access via OAuth is enabled. Disable unless required."))
        } else {
            $results.Add((New-ControlResult -Id "OAUTH-01" -Status "NOT CHECKED" -Severity "Medium" -Control "Third-Party OAuth Disabled" -Finding "OAuth policy not found."))
        }

        # OAUTH-02: SSH
        $ssh = $policyMap['Policy.DisallowSecureShell']
        $sshVal = if ($ssh) { Get-SafeProperty $ssh 'effectiveValue' } else { $null }
        if ($sshVal -eq $true) {
            $results.Add((New-ControlResult -Id "OAUTH-02" -Status "PASS" -Severity "Medium" -Control "SSH Access Disabled" -Finding "SSH authentication is disabled."))
        } elseif ($null -ne $ssh) {
            $results.Add((New-ControlResult -Id "OAUTH-02" -Status "FAIL" -Severity "Medium" -Control "SSH Access Disabled" -Finding "SSH authentication is enabled. Disable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "OAUTH-02" -Status "NOT CHECKED" -Severity "Medium" -Control "SSH Access Disabled" -Finding "SSH policy not found."))
        }

        # ACCESS-02: Request Access
        $requestAccess = $policyMap['Policy.AllowRequestAccessToken']
        $raVal = if ($requestAccess) { Get-SafeProperty $requestAccess 'effectiveValue' } else { $null }
        if ($raVal -eq $false) {
            $results.Add((New-ControlResult -Id "ACCESS-02" -Status "PASS" -Severity "Medium" -Control "Request Access Policy Disabled" -Finding "Request access policy is disabled."))
        } elseif ($null -ne $requestAccess) {
            $results.Add((New-ControlResult -Id "ACCESS-02" -Status "FAIL" -Severity "Medium" -Control "Request Access Policy Disabled" -Finding "Request access policy is enabled. Disable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "ACCESS-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Request Access Policy Disabled" -Finding "Request access policy not found."))
        }

        # ACCESS-03: Invite New Users
        $invite = $policyMap['Policy.AllowTeamMembersToInviteNewUsers']
        $invVal = if ($invite) { Get-SafeProperty $invite 'effectiveValue' } else { $null }
        if ($invVal -eq $false) {
            $results.Add((New-ControlResult -Id "ACCESS-03" -Status "PASS" -Severity "Medium" -Control "Invite New Users Restricted" -Finding "Only org admins can invite new users."))
        } elseif ($null -ne $invite) {
            $results.Add((New-ControlResult -Id "ACCESS-03" -Status "FAIL" -Severity "Medium" -Control "Invite New Users Restricted" -Finding "Any admin can invite new users. Restrict to org admins only."))
        } else {
            $results.Add((New-ControlResult -Id "ACCESS-03" -Status "NOT CHECKED" -Severity "Medium" -Control "Invite New Users Restricted" -Finding "Invite new users policy not found."))
        }

        # ACCESS-01: Enterprise Access (check Policy.AllowAnonymousAccess or similar)
        $enterpriseAccess = $policyMap['Policy.EnterpriseAccessToProjects']
        if ($enterpriseAccess) {
            $eaVal = Get-SafeProperty $enterpriseAccess 'effectiveValue'
            if ($eaVal -eq $false) {
                $results.Add((New-ControlResult -Id "ACCESS-01" -Status "PASS" -Severity "Medium" -Control "Enterprise Access to Projects" -Finding "Enterprise access to projects is disabled."))
            } else {
                $results.Add((New-ControlResult -Id "ACCESS-01" -Status "FAIL" -Severity "Medium" -Control "Enterprise Access to Projects" -Finding "Enterprise access to projects is enabled. Review via Organization Settings > Policies."))
            }
        } else {
            $results.Add((New-ControlResult -Id "ACCESS-01" -Status "NOT CHECKED" -Severity "Medium" -Control "Enterprise Access to Projects" -Finding "Manual review required. Check Organization Settings > Policies > Enterprise access."))
        }

        # PATPOL-01: Maximum PAT Lifetime
        $patLifetime = $policyMap['Policy.MaximumPATLifetime']
        $patLifeVal = if ($patLifetime) { Get-SafeProperty $patLifetime 'effectiveValue' } else { $null }
        if ($patLifeVal -eq $true) {
            $results.Add((New-ControlResult -Id "PATPOL-01" -Status "PASS" -Severity "Medium" -Control "Maximum PAT Lifetime Policy" -Finding "Maximum PAT lifetime policy is enforced."))
        } elseif ($null -ne $patLifetime) {
            $results.Add((New-ControlResult -Id "PATPOL-01" -Status "FAIL" -Severity "Medium" -Control "Maximum PAT Lifetime Policy" -Finding "Maximum PAT lifetime policy is not enforced. Enable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "PATPOL-01" -Status "NOT CHECKED" -Severity "Medium" -Control "Maximum PAT Lifetime Policy" -Finding "PAT lifetime policy not found in org policies."))
        }

        # PATPOL-02: Restrict PAT Scope
        $patScope = $policyMap['Policy.EnforcePatScopeRestriction']
        $patScopeVal = if ($patScope) { Get-SafeProperty $patScope 'effectiveValue' } else { $null }
        if ($patScopeVal -eq $true) {
            $results.Add((New-ControlResult -Id "PATPOL-02" -Status "PASS" -Severity "Medium" -Control "Restrict PAT Scope" -Finding "PAT scope restriction policy is enforced."))
        } elseif ($null -ne $patScope) {
            $results.Add((New-ControlResult -Id "PATPOL-02" -Status "FAIL" -Severity "Medium" -Control "Restrict PAT Scope" -Finding "PAT scope restriction policy is not enforced. Enable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "PATPOL-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Restrict PAT Scope" -Finding "PAT scope restriction policy not found in org policies."))
        }

        # PATPOL-03: Restrict Global PATs
        $patGlobal = $policyMap['Policy.DisallowFullScopePats']
        $patGlobalVal = if ($patGlobal) { Get-SafeProperty $patGlobal 'effectiveValue' } else { $null }
        if ($patGlobalVal -eq $true) {
            $results.Add((New-ControlResult -Id "PATPOL-03" -Status "PASS" -Severity "Medium" -Control "Restrict Global PATs" -Finding "Full-scope (global) PATs are restricted."))
        } elseif ($null -ne $patGlobal) {
            $results.Add((New-ControlResult -Id "PATPOL-03" -Status "FAIL" -Severity "Medium" -Control "Restrict Global PATs" -Finding "Full-scope PATs are allowed. Restrict via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "PATPOL-03" -Status "NOT CHECKED" -Severity "Medium" -Control "Restrict Global PATs" -Finding "Global PAT restriction policy not found in org policies."))
        }

        # ACCESS-04: IP allow list (conditional access)
        # Surfaced under Org Settings > Policies > Conditional access. There is
        # no documented public REST API for listing IP ranges, so this is a
        # manual-review control with explicit remediation steps.
        $results.Add((New-ControlResult -Id "ACCESS-04" -Status "NOT CHECKED" -Severity "Medium" -Control "IP Allow List" -Finding "Manual review required. Confirm an IP allow list is configured under Organization Settings > Policies > Conditional access (requires Microsoft Entra ID P1/P2)."))
    } else {
        foreach ($id in @("AUTH-05","OAUTH-01","OAUTH-02","ACCESS-02","ACCESS-03")) {
            $results.Add((New-ControlResult -Id $id -Status "NOT CHECKED" -Severity "Medium" -Control "$id" -Finding "Could not retrieve organization policies."))
        }
        $results.Add((New-ControlResult -Id "ACCESS-01" -Status "NOT CHECKED" -Severity "Medium" -Control "Enterprise Access to Projects" -Finding "Manual review required. Check Organization Settings > Policies > Enterprise access."))
        $results.Add((New-ControlResult -Id "ACCESS-04" -Status "NOT CHECKED" -Severity "Medium" -Control "IP Allow List" -Finding "Manual review required. Confirm an IP allow list is configured under Organization Settings > Policies > Conditional access (requires Microsoft Entra ID P1/P2)."))
        $results.Add((New-ControlResult -Id "PATPOL-01" -Status "NOT CHECKED" -Severity "Medium" -Control "Maximum PAT Lifetime Policy" -Finding "Could not retrieve organization policies."))
        $results.Add((New-ControlResult -Id "PATPOL-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Restrict PAT Scope" -Finding "Could not retrieve organization policies."))
        $results.Add((New-ControlResult -Id "PATPOL-03" -Status "NOT CHECKED" -Severity "Medium" -Control "Restrict Global PATs" -Finding "Could not retrieve organization policies."))
    }

    return $results
}

function Test-OrgUsers {
    param([string]$OrgUrl, [hashtable]$Header, [switch]$IncludeGraphCheck)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking users..."
    $users = Invoke-AzCli -Command "devops user list --org $OrgUrl -o json"

    if (-not $users -or -not $users.members) {
        foreach ($id in @("AUTH-02","AUTH-04","USER-01","USER-02","USER-03")) {
            $results.Add((New-ControlResult -Id $id -Status "NOT CHECKED" -Severity "High" -Control "$id" -Finding "Could not retrieve user list."))
        }
        return $results
    }

    $allMembers = $users.members
    $cutoff = (Get-Date).AddDays(-$script:InactiveDays)

    # AUTH-02: External Users
    $externalUsers = @($allMembers | Where-Object {
        $_.user.origin -ne 'aad' -or
        ($_.user.subjectKind -eq 'user' -and $_.user.mailAddress -imatch '@(hotmail|outlook|gmail|yahoo|live)\.')
    })
    if ($externalUsers.Count -eq 0) {
        $results.Add((New-ControlResult -Id "AUTH-02" -Status "PASS" -Severity "High" -Control "External User Access Disabled" -Finding "No external (non-AAD) users found."))
    } else {
        $names = ($externalUsers | Select-Object -First 10 | ForEach-Object { $_.user.mailAddress }) -join ', '
        $results.Add((New-ControlResult -Id "AUTH-02" -Status "FAIL" -Severity "High" -Control "External User Access Disabled" -Finding "$($externalUsers.Count) external user(s) found: $names. Remove via Organization Settings > Users."))
    }

    # AUTH-04: Guest Users
    $guestUsers = @($allMembers | Where-Object {
        $_.user.subjectKind -eq 'user' -and $_.user.origin -eq 'aad' -and
        ((Get-SafeProperty $_.user 'mailAddress') -imatch '#EXT#' -or
         (Get-SafeProperty $_.user 'directoryAlias') -imatch '#EXT#')
    })
    if ($guestUsers.Count -eq 0) {
        $results.Add((New-ControlResult -Id "AUTH-04" -Status "PASS" -Severity "High" -Control "Guest User Justification" -Finding "No guest users found."))
    } else {
        $names = ($guestUsers | Select-Object -First 10 | ForEach-Object { $_.user.mailAddress }) -join ', '
        $results.Add((New-ControlResult -Id "AUTH-04" -Status "FAIL" -Severity "High" -Control "Guest User Justification" -Finding "$($guestUsers.Count) guest user(s) found: $names. Review and document justification."))
    }

    # USER-01: Inactive Users
    $inactiveUsers = @($allMembers | Where-Object {
        $_.lastAccessedDate -and [datetime]$_.lastAccessedDate -lt $cutoff
    })
    if ($inactiveUsers.Count -eq 0) {
        $results.Add((New-ControlResult -Id "USER-01" -Status "PASS" -Severity "Medium" -Control "Inactive User Access" -Finding "No users inactive for more than $($script:InactiveDays) days."))
    } else {
        $results.Add((New-ControlResult -Id "USER-01" -Status "FAIL" -Severity "Medium" -Control "Inactive User Access" -Finding "$($inactiveUsers.Count) user(s) inactive for 90+ days. Remove or disable these accounts."))
    }

    # USER-02: Disconnected AAD Users — cross-reference with Entra ID via Microsoft Graph
    if ($IncludeGraphCheck) {
        Write-Progress -Activity "Org Assessment" -Status "Checking for deleted/disconnected AAD users via Microsoft Graph..."
        $aadUsers = @($allMembers | Where-Object { $_.user.origin -eq 'aad' -and $_.user.subjectKind -eq 'user' })
        $disconnectedUsers = [System.Collections.Generic.List[string]]::new()

        foreach ($adoUser in $aadUsers) {
            $mail = Get-SafeProperty $adoUser.user 'mailAddress'
            if (-not $mail) { continue }
            # Query Graph to see if user exists
            $encodedMail = [System.Uri]::EscapeDataString($mail)
            try {
                $graphResult = Invoke-Expression "az rest --method get --url 'https://graph.microsoft.com/v1.0/users?`$filter=mail eq ''$encodedMail'' or userPrincipalName eq ''$encodedMail''&`$select=id,accountEnabled,displayName' --resource https://graph.microsoft.com 2>&1"
                $exitCode = $LASTEXITCODE
                if ($exitCode -ne 0) {
                    # Graph API failed for this user — skip
                    continue
                }
                $graphData = $graphResult | Where-Object { $_ -is [string] } | Out-String | ConvertFrom-Json
                if (-not $graphData -or -not $graphData.value -or $graphData.value.Count -eq 0) {
                    # User not found in Entra ID — likely deleted
                    $disconnectedUsers.Add($mail)
                } elseif ($graphData.value[0].accountEnabled -eq $false) {
                    # User exists but is disabled
                    $disconnectedUsers.Add("$mail (disabled)")
                }
            }
            catch {
                # Skip individual user failures
                continue
            }
        }

        if ($disconnectedUsers.Count -eq 0) {
            $results.Add((New-ControlResult -Id "USER-02" -Status "PASS" -Severity "Medium" -Control "Deleted/Disconnected AAD Users" -Finding "All AAD users in the organization are active in Entra ID."))
        } else {
            $names = ($disconnectedUsers | Select-Object -First 10) -join ', '
            $results.Add((New-ControlResult -Id "USER-02" -Status "FAIL" -Severity "Medium" -Control "Deleted/Disconnected AAD Users" -Finding "$($disconnectedUsers.Count) user(s) deleted or disabled in Entra ID: $names. Remove from organization."))
        }
    } else {
        $results.Add((New-ControlResult -Id "USER-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Deleted/Disconnected AAD Users" -Finding "Requires -IncludeGraphCheck switch to cross-reference with Entra ID. Run with -IncludeGraphCheck to enable."))
    }

    # USER-03: Inactive Guest Users
    $inactiveGuests = @($guestUsers | Where-Object {
        $_.lastAccessedDate -and [datetime]$_.lastAccessedDate -lt $cutoff
    })
    if ($guestUsers.Count -eq 0) {
        $results.Add((New-ControlResult -Id "USER-03" -Status "PASS" -Severity "High" -Control "Inactive Guest Users" -Finding "No guest users present."))
    } elseif ($inactiveGuests.Count -eq 0) {
        $results.Add((New-ControlResult -Id "USER-03" -Status "PASS" -Severity "High" -Control "Inactive Guest Users" -Finding "All guest users are active."))
    } else {
        $results.Add((New-ControlResult -Id "USER-03" -Status "FAIL" -Severity "High" -Control "Inactive Guest Users" -Finding "$($inactiveGuests.Count) guest user(s) inactive for 90+ days. Remove these accounts."))
    }

    return $results
}

function Test-OrgAdmins {
    param([string]$OrgUrl, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking admin groups..."

    $groups = Invoke-AdoApi -Uri "$($script:VsspsUrl)/_apis/graph/groups?api-version=7.1-preview.1" -Header $Header

    $pcaGroup = $null
    $pcsaGroup = $null
    if ($groups -and $groups.value) {
        $pcaGroup = $groups.value | Where-Object { $_.displayName -eq 'Project Collection Administrators' } | Select-Object -First 1
        $pcsaGroup = $groups.value | Where-Object { $_.displayName -eq 'Project Collection Service Accounts' } | Select-Object -First 1
    }

    # PCA members
    $pcaMembers = @()
    if ($pcaGroup) {
        $memberships = Invoke-AzCli -Command "devops security group membership list --id `"$($pcaGroup.descriptor)`" --org $OrgUrl -o json"
        if ($memberships) {
            $pcaMembers = @($memberships.PSObject.Properties | ForEach-Object { $_.Value })
        }
    }

    # ADMIN-01: Manual review
    $results.Add((New-ControlResult -Id "ADMIN-01" -Status "NOT CHECKED" -Severity "High" -Control "Privileged Group Membership" -Finding "Manual review required. Verify all PCA/admin group members have legitimate business need."))

    # ADMIN-02: Max 6 PCAs
    if ($pcaMembers.Count -le 6) {
        $results.Add((New-ControlResult -Id "ADMIN-02" -Status "PASS" -Severity "Medium" -Control "PCA Count (Max 6)" -Finding "PCA member count: $($pcaMembers.Count) (≤ 6)."))
    } else {
        $results.Add((New-ControlResult -Id "ADMIN-02" -Status "FAIL" -Severity "Medium" -Control "PCA Count (Max 6)" -Finding "PCA member count: $($pcaMembers.Count) (exceeds 6). Remove unnecessary members."))
    }

    # ADMIN-03: Min 2 PCAs
    if ($pcaMembers.Count -ge 2) {
        $results.Add((New-ControlResult -Id "ADMIN-03" -Status "PASS" -Severity "Medium" -Control "PCA Count (Min 2)" -Finding "PCA member count: $($pcaMembers.Count) (≥ 2)."))
    } else {
        $results.Add((New-ControlResult -Id "ADMIN-03" -Status "FAIL" -Severity "Medium" -Control "PCA Count (Min 2)" -Finding "PCA member count: $($pcaMembers.Count) (fewer than 2). Add a backup admin."))
    }

    # ADMIN-04: Service Accounts (manual)
    $results.Add((New-ControlResult -Id "ADMIN-04" -Status "NOT CHECKED" -Severity "High" -Control "Service Accounts in Privileged Roles" -Finding "Manual review required. Inspect PCA members for service/non-person accounts."))

    # ADMIN-05: ALT Accounts
    $results.Add((New-ControlResult -Id "ADMIN-05" -Status "NOT CHECKED" -Severity "High" -Control "ALT Accounts for Admin Activity" -Finding "Manual review required. Verify all admins use ALT/SC-ALT accounts for privileged activity."))

    # ADMIN-06: PCSA Group
    if ($pcsaGroup) {
        $pcsaMemberships = Invoke-AzCli -Command "devops security group membership list --id `"$($pcsaGroup.descriptor)`" --org $OrgUrl -o json"
        $pcsaCount = 0
        if ($pcsaMemberships) { $pcsaCount = @($pcsaMemberships.PSObject.Properties).Count }
        if ($pcsaCount -le 3) {
            $results.Add((New-ControlResult -Id "ADMIN-06" -Status "PASS" -Severity "High" -Control "Project Collection Service Accounts" -Finding "PCSA group has $pcsaCount member(s)."))
        } else {
            $results.Add((New-ControlResult -Id "ADMIN-06" -Status "FAIL" -Severity "High" -Control "Project Collection Service Accounts" -Finding "PCSA group has $pcsaCount members. Minimize membership — these are effectively PCAs."))
        }
    } else {
        $results.Add((New-ControlResult -Id "ADMIN-06" -Status "NOT CHECKED" -Severity "High" -Control "Project Collection Service Accounts" -Finding "Could not locate PCSA group."))
    }

    # USER-04: Guest Users in Admin Roles
    if ($pcaMembers.Count -gt 0) {
        $guestAdmins = @($pcaMembers | Where-Object { Test-IsGuestMember $_ })
        if ($guestAdmins.Count -eq 0) {
            $results.Add((New-ControlResult -Id "USER-04" -Status "PASS" -Severity "High" -Control "Guest Users in Admin Roles" -Finding "No guest users found in PCA group."))
        } else {
            $results.Add((New-ControlResult -Id "USER-04" -Status "FAIL" -Severity "High" -Control "Guest Users in Admin Roles" -Finding "$($guestAdmins.Count) guest user(s) in PCA group. Remove immediately."))
        }
    } else {
        $results.Add((New-ControlResult -Id "USER-04" -Status "NOT CHECKED" -Severity "High" -Control "Guest Users in Admin Roles" -Finding "Could not enumerate PCA group members."))
    }

    # USER-05: Inactive Users in Admin Roles — cross-reference PCA members with user activity
    if ($pcaMembers.Count -gt 0) {
        $users = Invoke-AzCli -Command "devops user list --org $OrgUrl -o json"
        $cutoff = (Get-Date).AddDays(-$script:InactiveDays)
        if ($users -and $users.members) {
            $userMap = @{}
            foreach ($m in $users.members) {
                $mail = Get-SafeProperty $m.user 'mailAddress'
                if ($mail) { $userMap[$mail.ToLower()] = $m }
            }
            $inactiveAdmins = @()
            foreach ($pca in $pcaMembers) {
                $pcaMail = Get-SafeProperty $pca 'mailAddress'
                if ($pcaMail -and $userMap.ContainsKey($pcaMail.ToLower())) {
                    $userEntry = $userMap[$pcaMail.ToLower()]
                    if ($userEntry.lastAccessedDate -and [datetime]$userEntry.lastAccessedDate -lt $cutoff) {
                        $inactiveAdmins += $pcaMail
                    }
                }
            }
            if ($inactiveAdmins.Count -eq 0) {
                $results.Add((New-ControlResult -Id "USER-05" -Status "PASS" -Severity "High" -Control "Inactive Users in Admin Roles" -Finding "All PCA members have been active within the last $($script:InactiveDays) days."))
            } else {
                $names = ($inactiveAdmins | Select-Object -First 10) -join ', '
                $results.Add((New-ControlResult -Id "USER-05" -Status "FAIL" -Severity "High" -Control "Inactive Users in Admin Roles" -Finding "$($inactiveAdmins.Count) PCA member(s) inactive for $($script:InactiveDays)+ days: $names. Remove or reassign."))
            }
        } else {
            $results.Add((New-ControlResult -Id "USER-05" -Status "NOT CHECKED" -Severity "High" -Control "Inactive Users in Admin Roles" -Finding "Could not retrieve user list to cross-reference with PCA members."))
        }
    } else {
        $results.Add((New-ControlResult -Id "USER-05" -Status "NOT CHECKED" -Severity "High" -Control "Inactive Users in Admin Roles" -Finding "No PCA members found to check."))
    }

    return $results
}

function Test-OrgExtensions {
    param([string]$OrgUrl, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking extensions..."

    $extensions = Invoke-AdoApi -Uri "$($script:ExtMgmtUrl)/_apis/extensionmanagement/installedextensions?api-version=7.1-preview.1" -Header $Header

    if ($extensions -and $extensions.value) {
        $extList = $extensions.value
        # EXT-01: Review all extensions — check publisher trust flags
        $untrustedExts = @($extList | Where-Object {
            $installFlags = Get-SafeProperty (Get-SafeProperty $_ 'installState') 'flags'
            $extFlags = Get-SafeProperty $_ 'flags'
            $isBuiltIn = $installFlags -and $installFlags -imatch 'BuiltIn'
            $isTrusted = $extFlags -and $extFlags -imatch 'trusted'
            $isMicrosoft = (Get-SafeProperty $_ 'publisherName') -ieq 'Microsoft'
            (-not $isBuiltIn) -and (-not $isTrusted) -and (-not $isMicrosoft)
        })
        if ($untrustedExts.Count -eq 0) {
            $results.Add((New-ControlResult -Id "EXT-01" -Status "PASS" -Severity "High" -Control "Extension Review" -Finding "$($extList.Count) extension(s) installed. All are built-in, trusted, or from Microsoft."))
        } else {
            $extNames = ($untrustedExts | Select-Object -First 10 | ForEach-Object { "$(Get-SafeProperty $_ 'extensionName') ($(Get-SafeProperty $_ 'publisherName'))" }) -join ', '
            $results.Add((New-ControlResult -Id "EXT-01" -Status "FAIL" -Severity "High" -Control "Extension Review" -Finding "$($untrustedExts.Count) non-trusted extension(s) from non-Microsoft publishers: $extNames. Verify publishers are trusted."))
        }

        # EXT-02: Shared/Private extensions
        $shared = @($extList | Where-Object {
            $installFlags = Get-SafeProperty (Get-SafeProperty $_ 'installState') 'flags'
            $extFlags = Get-SafeProperty $_ 'flags'
            $isBuiltIn = $installFlags -and $installFlags -imatch 'BuiltIn'
            $isTrusted = $extFlags -and $extFlags -imatch 'trusted'
            (-not $isBuiltIn) -and (-not $isTrusted)
        })
        if ($shared.Count -eq 0) {
            $results.Add((New-ControlResult -Id "EXT-02" -Status "PASS" -Severity "High" -Control "Shared Extension Scrutiny" -Finding "No untrusted shared/private extensions detected."))
        } else {
            $results.Add((New-ControlResult -Id "EXT-02" -Status "NOT CHECKED" -Severity "High" -Control "Shared Extension Scrutiny" -Finding "$($shared.Count) non-built-in extension(s) found. Review sources and publishers."))
        }

        # EXT-03: Extension Manager role review
        $results.Add((New-ControlResult -Id "EXT-03" -Status "NOT CHECKED" -Severity "High" -Control "Extension Manager Review" -Finding "Manual review required. Check Organization Settings > Extensions > Permissions for excessive manager role assignments."))
    } else {
        $results.Add((New-ControlResult -Id "EXT-01" -Status "NOT CHECKED" -Severity "High" -Control "Extension Review" -Finding "Could not retrieve installed extensions."))
        $results.Add((New-ControlResult -Id "EXT-02" -Status "NOT CHECKED" -Severity "High" -Control "Shared Extension Scrutiny" -Finding "Could not retrieve extensions."))
        $results.Add((New-ControlResult -Id "EXT-03" -Status "NOT CHECKED" -Severity "High" -Control "Extension Manager Review" -Finding "Could not retrieve extensions."))
    }

    # EXT-04: Requested extensions
    $requested = Invoke-AdoApi -Uri "$($script:ExtMgmtUrl)/_apis/extensionmanagement/requestedextensions?api-version=7.1-preview.1" -Header $Header
    if ($requested -and $requested.value -and $requested.value.Count -gt 0) {
        $results.Add((New-ControlResult -Id "EXT-04" -Status "FAIL" -Severity "High" -Control "Requested Extensions Review" -Finding "$($requested.value.Count) pending extension request(s). Review and approve or deny."))
    } else {
        $results.Add((New-ControlResult -Id "EXT-04" -Status "PASS" -Severity "High" -Control "Requested Extensions Review" -Finding "No pending extension requests."))
    }

    # COPILOT-01: GitHub Copilot extension governance review
    # Surfaces any installed Copilot-related extension so admins can confirm
    # the extension scope, publisher, and policy align with their AI usage
    # guidelines. Treated as informational — presence is neither inherently
    # PASS nor FAIL; it is a governance prompt.
    if ($extensions -and $extensions.value) {
        $copilotExts = @($extensions.value | Where-Object {
            $extName = Get-SafeProperty $_ 'extensionName'
            $extId   = Get-SafeProperty $_ 'extensionId'
            $pubName = Get-SafeProperty $_ 'publisherName'
            $pubId   = Get-SafeProperty $_ 'publisherId'
            ("$extName $extId $pubName $pubId" -imatch 'copilot')
        })
        if ($copilotExts.Count -eq 0) {
            $results.Add((New-ControlResult -Id "COPILOT-01" -Status "PASS" -Severity "Medium" -Control "GitHub Copilot Extension Review" -Finding "No GitHub Copilot extensions detected. If Copilot is in use, install only the admin-approved extension from a trusted publisher (e.g. GitHub)."))
        } else {
            $details = ($copilotExts | Select-Object -First 10 | ForEach-Object {
                "$(Get-SafeProperty $_ 'extensionName') ($(Get-SafeProperty $_ 'publisherName'))"
            }) -join ', '
            $results.Add((New-ControlResult -Id "COPILOT-01" -Status "NOT CHECKED" -Severity "Medium" -Control "GitHub Copilot Extension Review" -Finding "$($copilotExts.Count) Copilot-related extension(s) installed: $details. Confirm publisher trust, admin-controlled scope, and that usage aligns with your AI policy."))
        }
    } else {
        $results.Add((New-ControlResult -Id "COPILOT-01" -Status "NOT CHECKED" -Severity "Medium" -Control "GitHub Copilot Extension Review" -Finding "Could not retrieve installed extensions to evaluate Copilot governance."))
    }

    return $results
}

function Test-OrgAudit {
    param([string]$OrgUrl, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking audit configuration..."

    $streams = Invoke-AdoApi -Uri "$($script:AuditUrl)/_apis/audit/streams?api-version=7.1-preview.1" -Header $Header

    # AUDIT-01: Manual
    $results.Add((New-ControlResult -Id "AUDIT-01" -Status "NOT CHECKED" -Severity "Medium" -Control "Audit Log Backup" -Finding "Manual review required. Verify audit logs are backed up to external storage."))

    # AUDIT-02: Streaming
    if ($streams -and $streams.value -and $streams.value.Count -gt 0) {
        $enabled = @($streams.value | Where-Object { $_.status -eq 'enabled' })
        if ($enabled.Count -gt 0) {
            $results.Add((New-ControlResult -Id "AUDIT-02" -Status "PASS" -Severity "Medium" -Control "Audit Streaming" -Finding "$($enabled.Count) active audit stream(s) configured."))
        } else {
            $results.Add((New-ControlResult -Id "AUDIT-02" -Status "FAIL" -Severity "Medium" -Control "Audit Streaming" -Finding "Audit streams exist but none are enabled. Enable streaming to a SIEM."))
        }
    } elseif ($null -eq $streams) {
        $results.Add((New-ControlResult -Id "AUDIT-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Audit Streaming" -Finding "Could not retrieve audit streams (may require elevated permissions)."))
    } else {
        $results.Add((New-ControlResult -Id "AUDIT-02" -Status "FAIL" -Severity "Medium" -Control "Audit Streaming" -Finding "No audit streams configured. Set up streaming to a SIEM."))
    }

    # AUDIT-03: Manual
    $results.Add((New-ControlResult -Id "AUDIT-03" -Status "NOT CHECKED" -Severity "Medium" -Control "Alerts Configuration" -Finding "Manual review required. Verify alerts are configured for critical actions."))

    return $results
}

function Test-OrgPipelineSettings {
    param([string]$OrgUrl, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking org pipeline settings..."

    $settings = Invoke-AdoApi -Uri "$OrgUrl/_apis/build/generalsettings?api-version=7.1-preview.1" -Header $Header

    if (-not $settings) {
        foreach ($id in @("PIPELINE-01","PIPELINE-02","PIPELINE-03","PIPELINE-04")) {
            $results.Add((New-ControlResult -Id $id -Status "NOT CHECKED" -Severity "Medium" -Control "$id" -Finding "Could not retrieve org pipeline settings."))
        }
        $results.Add((New-ControlResult -Id "PIPELINE-05" -Status "NOT CHECKED" -Severity "High" -Control "Auto-Injected Tasks" -Finding "Manual review required."))
        return $results
    }

    # PIPELINE-01
    if ($settings.enforceJobAuthScope -eq $true) {
        $results.Add((New-ControlResult -Id "PIPELINE-01" -Status "PASS" -Severity "Medium" -Control "Pipeline Auth Scope (Non-Release)" -Finding "enforceJobAuthScope is enabled at org level."))
    } else {
        $results.Add((New-ControlResult -Id "PIPELINE-01" -Status "FAIL" -Severity "Medium" -Control "Pipeline Auth Scope (Non-Release)" -Finding "enforceJobAuthScope is disabled. Enable via Org Settings > Pipelines > Settings."))
    }

    # PIPELINE-02
    if ($settings.enforceJobAuthScopeForReleases -eq $true) {
        $results.Add((New-ControlResult -Id "PIPELINE-02" -Status "PASS" -Severity "Medium" -Control "Pipeline Auth Scope (Release)" -Finding "enforceJobAuthScopeForReleases is enabled at org level."))
    } else {
        $results.Add((New-ControlResult -Id "PIPELINE-02" -Status "FAIL" -Severity "Medium" -Control "Pipeline Auth Scope (Release)" -Finding "enforceJobAuthScopeForReleases is disabled. Enable via Org Settings > Pipelines > Settings."))
    }

    # PIPELINE-03
    if ($settings.enforceReferencedRepoScopedToken -eq $true) {
        $results.Add((New-ControlResult -Id "PIPELINE-03" -Status "PASS" -Severity "Medium" -Control "Pipeline Repository Scope" -Finding "enforceReferencedRepoScopedToken is enabled at org level."))
    } else {
        $results.Add((New-ControlResult -Id "PIPELINE-03" -Status "FAIL" -Severity "Medium" -Control "Pipeline Repository Scope" -Finding "enforceReferencedRepoScopedToken is disabled. Enable via Org Settings > Pipelines > Settings."))
    }

    # PIPELINE-04
    if ($settings.enforceSettableVar -eq $true) {
        $results.Add((New-ControlResult -Id "PIPELINE-04" -Status "PASS" -Severity "Medium" -Control "Settable Variables at Queue Time" -Finding "enforceSettableVar is enabled at org level."))
    } else {
        $results.Add((New-ControlResult -Id "PIPELINE-04" -Status "FAIL" -Severity "Medium" -Control "Settable Variables at Queue Time" -Finding "enforceSettableVar is disabled. Enable via Org Settings > Pipelines > Settings."))
    }

    # PIPELINE-05: Manual
    $results.Add((New-ControlResult -Id "PIPELINE-05" -Status "NOT CHECKED" -Severity "High" -Control "Auto-Injected Tasks" -Finding "Manual review required. Check Organization Settings > Pipelines for auto-injected tasks."))

    return $results
}

function Test-OrgFeeds {
    param([string]$OrgUrl, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking org feeds..."

    $feeds = Invoke-AdoApi -Uri "$($script:FeedsUrl)/_apis/packaging/feeds?api-version=7.1-preview.1" -Header $Header

    if ($feeds -and $feeds.value -and $feeds.value.Count -gt 0) {
        $broadGroupFeeds = [System.Collections.Generic.List[string]]::new()
        foreach ($feed in $feeds.value) {
            $perms = Invoke-AdoApi -Uri "$($script:FeedsUrl)/_apis/packaging/Feeds/$($feed.id)/permissions?api-version=7.1-preview.1" -Header $Header
            if ($perms -and $perms.value) {
                foreach ($perm in $perms.value) {
                    if ((Test-IsBroadGroup $perm.displayName) -and $perm.role -ine 'reader') {
                        $broadGroupFeeds.Add($feed.name)
                        break
                    }
                }
            }
        }
        if ($broadGroupFeeds.Count -eq 0) {
            $results.Add((New-ControlResult -Id "FEED-01" -Status "PASS" -Severity "High" -Control "Feed Permissions for Broad Groups" -Finding "No org-level feeds have broad group write/admin access."))
        } else {
            $results.Add((New-ControlResult -Id "FEED-01" -Status "FAIL" -Severity "High" -Control "Feed Permissions for Broad Groups" -Finding "Feeds with broad group elevated access: $($broadGroupFeeds -join ', '). Restrict to Reader role."))
        }
    } else {
        $results.Add((New-ControlResult -Id "FEED-01" -Status "PASS" -Severity "High" -Control "Feed Permissions for Broad Groups" -Finding "No org-level feeds found."))
    }

    # FEED-02: Feed creation permissions — not easily checked via API
    $results.Add((New-ControlResult -Id "FEED-02" -Status "NOT CHECKED" -Severity "High" -Control "Feed Creation Permissions" -Finding "Manual review required. Check who can create feeds in Organization Settings."))

    # FEED-03: External package protection — check upstream source settings on each feed
    if ($feeds -and $feeds.value -and $feeds.value.Count -gt 0) {
        $unprotectedFeeds = [System.Collections.Generic.List[string]]::new()
        foreach ($feed in $feeds.value) {
            $upstreamEnabled = Get-SafeProperty $feed 'upstreamEnabled'
            $upstreamSources = Get-SafeProperty $feed 'upstreamSources'
            if ($upstreamEnabled -eq $true -and $upstreamSources) {
                # Check if any upstream source lacks upstream protection
                foreach ($src in $upstreamSources) {
                    $protocol = Get-SafeProperty $src 'protocol'
                    $status = Get-SafeProperty $src 'status'
                    if ($status -ne 'disabled') {
                        $unprotectedFeeds.Add($feed.name)
                        break
                    }
                }
            }
        }
        if ($unprotectedFeeds.Count -eq 0) {
            $results.Add((New-ControlResult -Id "FEED-03" -Status "PASS" -Severity "High" -Control "External Package Protection" -Finding "All org-level feeds have upstream sources disabled or protected."))
        } else {
            $results.Add((New-ControlResult -Id "FEED-03" -Status "FAIL" -Severity "High" -Control "External Package Protection" -Finding "Feeds with active upstream sources: $($unprotectedFeeds -join ', '). Review upstream source protection settings."))
        }
    } else {
        $results.Add((New-ControlResult -Id "FEED-03" -Status "PASS" -Severity "High" -Control "External Package Protection" -Finding "No org-level feeds found."))
    }

    # BADGE-01: Anonymous Badge API — check org pipeline settings
    $orgPipeSettings = Invoke-AdoApi -Uri "$OrgUrl/_apis/build/generalsettings?api-version=7.1-preview.1" -Header $Header
    if ($orgPipeSettings -and $orgPipeSettings.PSObject.Properties['statusBadgesArePrivate']) {
        if ($orgPipeSettings.statusBadgesArePrivate -eq $true) {
            $results.Add((New-ControlResult -Id "BADGE-01" -Status "PASS" -Severity "Low" -Control "Anonymous Badge API" -Finding "Anonymous badge access is disabled at org level."))
        } else {
            $results.Add((New-ControlResult -Id "BADGE-01" -Status "FAIL" -Severity "Low" -Control "Anonymous Badge API" -Finding "Anonymous badge access is enabled. Disable via Organization Settings > Pipelines > Settings."))
        }
    } else {
        $results.Add((New-ControlResult -Id "BADGE-01" -Status "NOT CHECKED" -Severity "Low" -Control "Anonymous Badge API" -Finding "Could not retrieve badge setting from org pipeline settings."))
    }

    return $results
}

function Test-OrgPatPolicy {
    param([string]$OrgUrl, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking PAT policies..."

    # PATPOL-01/02/03 are now checked in Test-OrgPolicies via the policyMap.
    # This function is kept for backward compatibility but no longer emits those controls.

    return $results
}

#endregion

#region Project Assessment

function Test-ProjectSettings {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking project settings..."

    # PROJ-01: Visibility
    $projectInfo = Invoke-AzCli -Command "devops project show --project `"$ProjectName`" --org $OrgUrl -o json"
    if ($projectInfo) {
        if ($projectInfo.visibility -ne 'public') {
            $results.Add((New-ControlResult -Id "PROJ-01" -Status "PASS" -Severity "High" -Control "Project Visibility" -Finding "Project visibility is '$($projectInfo.visibility)'."))
        } else {
            $results.Add((New-ControlResult -Id "PROJ-01" -Status "FAIL" -Severity "High" -Control "Project Visibility" -Finding "Project is PUBLIC. Change to Private via Project Settings > Overview."))
        }
    } else {
        $results.Add((New-ControlResult -Id "PROJ-01" -Status "NOT CHECKED" -Severity "High" -Control "Project Visibility" -Finding "Could not retrieve project details."))
    }

    # Project admin groups
    $groups = Invoke-AzCli -Command "devops security group list --org $OrgUrl --project `"$ProjectName`" -o json"
    $paGroup = $null
    $baGroup = $null
    if ($groups -and $groups.graphGroups) {
        $paGroup = $groups.graphGroups | Where-Object { $_.displayName -eq 'Project Administrators' } | Select-Object -First 1
        $baGroup = $groups.graphGroups | Where-Object { $_.displayName -eq 'Build Administrators' } | Select-Object -First 1
    }

    $paMembers = @()
    if ($paGroup) {
        $paMembership = Invoke-AzCli -Command "devops security group membership list --id `"$($paGroup.descriptor)`" --org $OrgUrl -o json"
        if ($paMembership) { $paMembers = @($paMembership.PSObject.Properties | ForEach-Object { $_.Value }) }
    }

    # PROJ-02: Manual
    $results.Add((New-ControlResult -Id "PROJ-02" -Status "NOT CHECKED" -Severity "High" -Control "Project Admin Group Membership" -Finding "Manual review required. $($paMembers.Count) member(s) in Project Administrators group."))

    # PROJ-03: Max 6 admins
    if ($paMembers.Count -le 6) {
        $results.Add((New-ControlResult -Id "PROJ-03" -Status "PASS" -Severity "Medium" -Control "Project Admin Count (Max 6)" -Finding "Project admin count: $($paMembers.Count) (≤ 6)."))
    } else {
        $results.Add((New-ControlResult -Id "PROJ-03" -Status "FAIL" -Severity "Medium" -Control "Project Admin Count (Max 6)" -Finding "Project admin count: $($paMembers.Count) (exceeds 6). Remove unnecessary members."))
    }

    # PROJ-04: Min 2 admins
    if ($paMembers.Count -ge 2) {
        $results.Add((New-ControlResult -Id "PROJ-04" -Status "PASS" -Severity "Medium" -Control "Project Admin Count (Min 2)" -Finding "Project admin count: $($paMembers.Count) (≥ 2)."))
    } else {
        $results.Add((New-ControlResult -Id "PROJ-04" -Status "FAIL" -Severity "Medium" -Control "Project Admin Count (Min 2)" -Finding "Project admin count: $($paMembers.Count) (fewer than 2). Add a backup admin."))
    }

    # PROJ-05: Build Admin count
    $baMembers = @()
    if ($baGroup) {
        $baMembership = Invoke-AzCli -Command "devops security group membership list --id `"$($baGroup.descriptor)`" --org $OrgUrl -o json"
        if ($baMembership) { $baMembers = @($baMembership.PSObject.Properties | ForEach-Object { $_.Value }) }
    }
    if ($baMembers.Count -le 100) {
        $results.Add((New-ControlResult -Id "PROJ-05" -Status "PASS" -Severity "Medium" -Control "Build Admin Count (Max 100)" -Finding "Build admin count: $($baMembers.Count) (≤ 100)."))
    } else {
        $results.Add((New-ControlResult -Id "PROJ-05" -Status "FAIL" -Severity "Medium" -Control "Build Admin Count (Max 100)" -Finding "Build admin count: $($baMembers.Count) (exceeds 100). Reduce membership."))
    }

    # PROJ-06: ALT accounts, PROJ-07: Guest admins, PROJ-08: Inactive admins
    $results.Add((New-ControlResult -Id "PROJ-06" -Status "NOT CHECKED" -Severity "High" -Control "ALT Accounts for Admin Activity" -Finding "Manual review required. Verify project admins use ALT accounts."))

    $guestPAs = @($paMembers | Where-Object { Test-IsGuestMember $_ })
    if ($guestPAs.Count -eq 0) {
        $results.Add((New-ControlResult -Id "PROJ-07" -Status "PASS" -Severity "High" -Control "Guest Users in Admin Roles" -Finding "No guest users in Project Administrators."))
    } else {
        $results.Add((New-ControlResult -Id "PROJ-07" -Status "FAIL" -Severity "High" -Control "Guest Users in Admin Roles" -Finding "$($guestPAs.Count) guest user(s) in Project Administrators. Remove immediately."))
    }

    # PROJ-08: Inactive Users in Admin Roles — cross-reference PA members with user activity
    if ($paMembers.Count -gt 0) {
        $users = Invoke-AzCli -Command "devops user list --org $OrgUrl -o json"
        $cutoff = (Get-Date).AddDays(-$script:InactiveDays)
        if ($users -and $users.members) {
            $userMap = @{}
            foreach ($m in $users.members) {
                $mail = Get-SafeProperty $m.user 'mailAddress'
                if ($mail) { $userMap[$mail.ToLower()] = $m }
            }
            $inactiveAdmins = @()
            foreach ($pa in $paMembers) {
                $paMail = Get-SafeProperty $pa 'mailAddress'
                if ($paMail -and $userMap.ContainsKey($paMail.ToLower())) {
                    $userEntry = $userMap[$paMail.ToLower()]
                    if ($userEntry.lastAccessedDate -and [datetime]$userEntry.lastAccessedDate -lt $cutoff) {
                        $inactiveAdmins += $paMail
                    }
                }
            }
            if ($inactiveAdmins.Count -eq 0) {
                $results.Add((New-ControlResult -Id "PROJ-08" -Status "PASS" -Severity "High" -Control "Inactive Users in Admin Roles" -Finding "All Project Administrator members have been active within the last $($script:InactiveDays) days."))
            } else {
                $names = ($inactiveAdmins | Select-Object -First 10) -join ', '
                $results.Add((New-ControlResult -Id "PROJ-08" -Status "FAIL" -Severity "High" -Control "Inactive Users in Admin Roles" -Finding "$($inactiveAdmins.Count) Project Admin member(s) inactive for $($script:InactiveDays)+ days: $names. Remove or reassign."))
            }
        } else {
            $results.Add((New-ControlResult -Id "PROJ-08" -Status "NOT CHECKED" -Severity "High" -Control "Inactive Users in Admin Roles" -Finding "Could not retrieve user list to cross-reference with Project Administrators."))
        }
    } else {
        $results.Add((New-ControlResult -Id "PROJ-08" -Status "NOT CHECKED" -Severity "High" -Control "Inactive Users in Admin Roles" -Finding "No Project Administrator members found to check."))
    }

    # Pipeline settings (project level)
    $pipeSettings = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/build/generalsettings?api-version=7.1-preview.1" -Header $Header
    if ($pipeSettings) {
        $checks = @(
            @{ Id="PROJ-09"; Prop="enforceJobAuthScope"; Name="Pipeline Scope (Non-Release)" },
            @{ Id="PROJ-10"; Prop="enforceJobAuthScopeForReleases"; Name="Pipeline Scope (Release)" },
            @{ Id="PROJ-11"; Prop="enforceReferencedRepoScopedToken"; Name="Pipeline Repository Scope" },
            @{ Id="PROJ-12"; Prop="enforceSettableVar"; Name="Settable Variables" }
        )
        foreach ($chk in $checks) {
            $val = $pipeSettings.($chk.Prop)
            if ($val -eq $true) {
                $results.Add((New-ControlResult -Id $chk.Id -Status "PASS" -Severity "Medium" -Control $chk.Name -Finding "$($chk.Prop) is enabled at project level."))
            } else {
                $results.Add((New-ControlResult -Id $chk.Id -Status "FAIL" -Severity "Medium" -Control $chk.Name -Finding "$($chk.Prop) is disabled. Enable via Project Settings > Pipelines > Settings."))
            }
        }
    } else {
        foreach ($id in @("PROJ-09","PROJ-10","PROJ-11","PROJ-12")) {
            $results.Add((New-ControlResult -Id $id -Status "NOT CHECKED" -Severity "Medium" -Control "$id" -Finding "Could not retrieve project pipeline settings."))
        }
    }

    # PROJ-13: Artifact Evaluation
    $results.Add((New-ControlResult -Id "PROJ-13" -Status "NOT CHECKED" -Severity "Medium" -Control "Artifact Evaluation" -Finding "Manual review required. Consider configuring artifact evaluation checks."))

    # PROJ-14: Credential Scanner
    $policies = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/policy/configurations?api-version=7.1" -Header $Header
    $credScanFound = $false
    if ($policies -and $policies.value) {
        foreach ($pol in $policies.value) {
            if ($pol.type.displayName -imatch 'credential|secret|push protection') {
                $credScanFound = $true
                break
            }
        }
    }
    if ($credScanFound) {
        $results.Add((New-ControlResult -Id "PROJ-14" -Status "PASS" -Severity "High" -Control "Credential Scanner" -Finding "Credential scanning / push protection policy detected."))
    } else {
        $results.Add((New-ControlResult -Id "PROJ-14" -Status "FAIL" -Severity "High" -Control "Credential Scanner" -Finding "No credential scanning policy found. Enable GHAzDO push protection or add a credential scan policy."))
    }

    # PROJ-15: Commit author email validation
    $emailPolicyFound = $false
    if ($policies -and $policies.value) {
        foreach ($pol in $policies.value) {
            if ($pol.type.displayName -imatch 'commit author email') {
                $emailPolicyFound = $true
                break
            }
        }
    }
    if ($emailPolicyFound) {
        $results.Add((New-ControlResult -Id "PROJ-15" -Status "PASS" -Severity "Medium" -Control "Commit Author Email Validation" -Finding "Commit author email validation policy is configured."))
    } else {
        $results.Add((New-ControlResult -Id "PROJ-15" -Status "FAIL" -Severity "Medium" -Control "Commit Author Email Validation" -Finding "No commit author email validation policy found. Configure via Project Settings > Repos > Policies."))
    }

    # PROJ-16: Inactive Projects — check recent builds and repo activity
    $projInactiveCutoff = (Get-Date).AddDays(-$script:InactiveRepoDays)
    $hasRecentActivity = $false

    # Check recent builds
    $recentBuilds = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/build/builds?`$top=1&api-version=7.1" -Header $Header
    if ($recentBuilds -and $recentBuilds.value -and $recentBuilds.value.Count -gt 0) {
        $lastBuildTime = Get-SafeProperty $recentBuilds.value[0] 'finishTime'
        if (-not $lastBuildTime) { $lastBuildTime = Get-SafeProperty $recentBuilds.value[0] 'queueTime' }
        if ($lastBuildTime -and [datetime]$lastBuildTime -ge $projInactiveCutoff) {
            $hasRecentActivity = $true
        }
    }

    # Check recent repo pushes if no recent builds
    if (-not $hasRecentActivity) {
        $projRepos = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/git/repositories?api-version=7.1" -Header $Header
        if ($projRepos -and $projRepos.value) {
            foreach ($r in $projRepos.value) {
                $defaultBranch = Get-SafeProperty $r 'defaultBranch'
                if ($defaultBranch) {
                    $branchName = $defaultBranch -replace '^refs/heads/', ''
                    $branchStats = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/git/repositories/$($r.id)/stats/branches?name=$branchName&api-version=7.1" -Header $Header
                    if ($branchStats) {
                        $committer = Get-SafeProperty (Get-SafeProperty $branchStats 'commit') 'committer'
                        $dateStr = if ($committer) { Get-SafeProperty $committer 'date' } else { $null }
                        if ($dateStr -and [datetime]$dateStr -ge $projInactiveCutoff) {
                            $hasRecentActivity = $true
                            break
                        }
                    }
                }
            }
        }
    }

    if ($hasRecentActivity) {
        $results.Add((New-ControlResult -Id "PROJ-16" -Status "PASS" -Severity "Medium" -Control "Inactive Projects" -Finding "Project has recent activity within the last $($script:InactiveRepoDays) days."))
    } else {
        $results.Add((New-ControlResult -Id "PROJ-16" -Status "FAIL" -Severity "Medium" -Control "Inactive Projects" -Finding "No recent builds or repo commits found in the last $($script:InactiveRepoDays) days. Review if project is still active."))
    }

    # PROJ-17: Badge API
    if ($pipeSettings -and $pipeSettings.PSObject.Properties['statusBadgesArePrivate']) {
        if ($pipeSettings.statusBadgesArePrivate -eq $true) {
            $results.Add((New-ControlResult -Id "PROJ-17" -Status "PASS" -Severity "Low" -Control "Badge API Access" -Finding "Anonymous badge access is disabled."))
        } else {
            $results.Add((New-ControlResult -Id "PROJ-17" -Status "FAIL" -Severity "Low" -Control "Badge API Access" -Finding "Anonymous badge access is enabled. Disable via Project Settings > Pipelines > Settings."))
        }
    } else {
        $results.Add((New-ControlResult -Id "PROJ-17" -Status "NOT CHECKED" -Severity "Low" -Control "Badge API Access" -Finding "Could not determine badge API setting."))
    }

    # PERM-01 through PERM-08: Project-level inherited permissions for broad groups
    foreach ($permId in @("PERM-01","PERM-02","PERM-03","PERM-04","PERM-05","PERM-06","PERM-07","PERM-08")) {
        $resourceName = switch ($permId) {
            "PERM-01" { "Build Pipeline" }
            "PERM-02" { "Release Pipeline" }
            "PERM-03" { "Service Connection" }
            "PERM-04" { "Agent Pool" }
            "PERM-05" { "Variable Group" }
            "PERM-06" { "Repository" }
            "PERM-07" { "Secure File" }
            "PERM-08" { "Environment" }
        }
        $results.Add((New-ControlResult -Id $permId -Status "NOT CHECKED" -Severity "High" -Control "$resourceName Inherited Permissions" -Finding "Requires querying security namespaces for broad group permissions at project level. Manual review recommended."))
    }

    # PERM-09: Project-level "Create repository" permission
    # The Git Repositories security namespace exposes the "CreateRepository"
    # bit, but enumerating effective permissions per group is a multi-step
    # ACL query. Surface as a manual-review control with clear guidance.
    $results.Add((New-ControlResult -Id "PERM-09" -Status "NOT CHECKED" -Severity "Medium" -Control "Repository Creation Permission" -Finding "Manual review required. In Project Settings > Repositories > Security, confirm only trusted groups (e.g. Project Administrators) have the 'Create repository' permission set to Allow."))

    return $results
}

#endregion

#region Build Pipeline Controls

function Test-BuildPipelines {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking build pipelines..."

    $builds = @(Invoke-AzCli -Command "pipelines list --project `"$ProjectName`" --org $OrgUrl -o json")
    if ($builds.Count -eq 0 -or ($builds.Count -eq 1 -and $null -eq $builds[0])) {
        $results.Add((New-ControlResult -Id "BUILD-*" -Status "NOT CHECKED" -Severity "High" -Control "Build Pipelines" -Finding "Could not retrieve build pipeline list."))
        return $results
    }

    $cutoff = (Get-Date).AddDays(-$script:InactiveDays)

    foreach ($build in $builds) {
        $defId = $build.id
        $defName = $build.name
        $prefix = "Build '$defName' (ID:$defId)"

        $def = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/build/definitions/${defId}?api-version=7.1" -Header $Header
        if (-not $def) { continue }

        # BUILD-01: Plain text secrets
        $defVars = Get-SafeProperty $def 'variables'
        if ($defVars) {
            $suspectVars = @()
            foreach ($prop in $defVars.PSObject.Properties) {
                $isSecret = Get-SafeProperty $prop.Value 'isSecret'
                if (-not $isSecret -and (Test-LooksLikeSecret $prop.Name)) {
                    $suspectVars += $prop.Name
                }
            }
            if ($suspectVars.Count -gt 0) {
                $results.Add((New-ControlResult -Id "BUILD-01" -Status "FAIL" -Severity "High" -Control "No Plain Text Secrets" -Finding "$prefix — Suspect plain-text variables: $($suspectVars -join ', '). Mark as secret or use Key Vault."))
            } else {
                $results.Add((New-ControlResult -Id "BUILD-01" -Status "PASS" -Severity "High" -Control "No Plain Text Secrets" -Finding "$prefix — No plain-text secret variables detected."))
            }

            # BUILD-06: Settable variables
            $settable = @($defVars.PSObject.Properties | Where-Object { (Get-SafeProperty $_.Value 'allowOverride') -eq $true })
            if ($settable.Count -gt 0) {
                $results.Add((New-ControlResult -Id "BUILD-06" -Status "FAIL" -Severity "High" -Control "Settable Variables at Queue Time" -Finding "$prefix — $($settable.Count) variable(s) settable at queue time: $($settable.Name -join ', '). Review necessity."))
            } else {
                $results.Add((New-ControlResult -Id "BUILD-06" -Status "PASS" -Severity "High" -Control "Settable Variables at Queue Time" -Finding "$prefix — No variables settable at queue time."))
            }

            # BUILD-07: Settable URL variables
            $settableUrls = @($settable | Where-Object { $_.Value.value -and (Test-IsUrlValue $_.Value.value) })
            if ($settableUrls.Count -gt 0) {
                $results.Add((New-ControlResult -Id "BUILD-07" -Status "FAIL" -Severity "High" -Control "Settable URL Variables" -Finding "$prefix — URL variables settable at queue time: $($settableUrls.Name -join ', '). Remove allowOverride."))
            }
        }

        # BUILD-04: Inactive
        $lastRun = Invoke-AzCli -Command "pipelines runs list --pipeline-ids $defId --top 1 --project `"$ProjectName`" --org $OrgUrl -o json"
        [array]$lastRunArr = @()
        if ($null -ne $lastRun) { [array]$lastRunArr = @($lastRun) }
        if ($lastRunArr.Length -gt 0) {
            $runDateStr = Get-SafeProperty $lastRunArr[0] 'createdDate'
            if (-not $runDateStr) { $runDateStr = Get-SafeProperty $lastRunArr[0] 'finishedDate' }
            if ($runDateStr) {
                $lastDate = [datetime]$runDateStr
                if ($lastDate -lt $cutoff) {
                    $results.Add((New-ControlResult -Id "BUILD-04" -Status "FAIL" -Severity "Medium" -Control "Inactive Build Pipelines" -Finding "$prefix — Last run: $($lastDate.ToString('yyyy-MM-dd')). Inactive for 90+ days."))
                } else {
                    $results.Add((New-ControlResult -Id "BUILD-04" -Status "PASS" -Severity "Medium" -Control "Inactive Build Pipelines" -Finding "$prefix — Last run: $($lastDate.ToString('yyyy-MM-dd'))."))
                }
            } else {
                $results.Add((New-ControlResult -Id "BUILD-04" -Status "NOT CHECKED" -Severity "Medium" -Control "Inactive Build Pipelines" -Finding "$prefix — Could not determine last run date."))
            }
        } else {
            $results.Add((New-ControlResult -Id "BUILD-04" -Status "FAIL" -Severity "Medium" -Control "Inactive Build Pipelines" -Finding "$prefix — No runs found. Pipeline may be inactive."))
        }

        # BUILD-08: External repos
        $defRepo = Get-SafeProperty $def 'repository'
        $defRepoType = if ($defRepo) { Get-SafeProperty $defRepo 'type' } else { $null }
        if ($defRepoType -and $defRepoType -ine 'TfsGit') {
            $results.Add((New-ControlResult -Id "BUILD-08" -Status "FAIL" -Severity "High" -Control "External Repository Review" -Finding "$prefix — Uses external repository type '$defRepoType'. Review for trustworthiness."))
        }

        # BUILD-11: Authorization scope
        $defAuthScope = Get-SafeProperty $def 'jobAuthorizationScope'
        if ($defAuthScope) {
            if ($defAuthScope -ieq 'projectScoped') {
                $results.Add((New-ControlResult -Id "BUILD-11" -Status "PASS" -Severity "Medium" -Control "Pipeline Authorization Scope" -Finding "$prefix — Authorization scope is project-scoped."))
            } else {
                $results.Add((New-ControlResult -Id "BUILD-11" -Status "FAIL" -Severity "Medium" -Control "Pipeline Authorization Scope" -Finding "$prefix — Authorization scope is '$defAuthScope'. Set to 'Current project'."))
            }
        }

        # BUILD-13: Fork builds and secrets
        $defTriggers = Get-SafeProperty $def 'triggers'
        if ($defTriggers) {
            foreach ($trigger in $defTriggers) {
                $forks = Get-SafeProperty $trigger 'forks'
                if ($forks -and (Get-SafeProperty $forks 'allowSecrets') -eq $true) {
                    $results.Add((New-ControlResult -Id "BUILD-13" -Status "FAIL" -Severity "High" -Control "Fork Builds and Secrets" -Finding "$prefix — Secrets are available to fork builds. Disable 'Make secrets available to builds of forks'."))
                }
            }
        }
    }

    # BUILD-02, BUILD-03: Manual
    $results.Add((New-ControlResult -Id "BUILD-02" -Status "NOT CHECKED" -Severity "High" -Control "Static Code Analysis" -Finding "Manual review required. Verify builds include static analysis tasks (SonarQube, CodeQL, etc.)."))
    $results.Add((New-ControlResult -Id "BUILD-03" -Status "NOT CHECKED" -Severity "Medium" -Control "Secure Files for Secrets" -Finding "Manual review required. Verify secret files use the Secure Files library."))

    return $results
}

#endregion

#region Release Pipeline Controls

function Test-ReleasePipelines {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking release pipelines..."

    # Release definitions live on the vsrm subdomain
    $vsrmUrl = $OrgUrl -replace 'dev\.azure\.com', 'vsrm.dev.azure.com'
    $relDefs = Invoke-AdoApi -Uri "$vsrmUrl/$ProjectName/_apis/release/definitions?api-version=7.1" -Header $Header

    if (-not $relDefs -or -not $relDefs.value -or $relDefs.value.Count -eq 0) {
        $results.Add((New-ControlResult -Id "REL-*" -Status "PASS" -Severity "High" -Control "Release Pipelines" -Finding "No release pipelines found in project."))
        return $results
    }

    $cutoff = (Get-Date).AddDays(-$script:InactiveDays)
    $vsrmUrl = $OrgUrl -replace 'dev\.azure\.com', 'vsrm.dev.azure.com'

    foreach ($relDef in $relDefs.value) {
        $defId = $relDef.id
        $defName = $relDef.name
        $prefix = "Release '$defName' (ID:$defId)"

        $def = Invoke-AdoApi -Uri "$vsrmUrl/$ProjectName/_apis/release/definitions/${defId}?api-version=7.1" -Header $Header
        if (-not $def) { continue }

        # REL-01: Plain text secrets
        $defVars = Get-SafeProperty $def 'variables'
        if ($defVars) {
            $suspectVars = @()
            foreach ($prop in $defVars.PSObject.Properties) {
                $isSecret = Get-SafeProperty $prop.Value 'isSecret'
                if (-not $isSecret -and (Test-LooksLikeSecret $prop.Name)) {
                    $suspectVars += $prop.Name
                }
            }
            if ($suspectVars.Count -gt 0) {
                $results.Add((New-ControlResult -Id "REL-01" -Status "FAIL" -Severity "High" -Control "No Plain Text Secrets" -Finding "$prefix — Suspect plain-text variables: $($suspectVars -join ', ')."))
            }
        }

        # REL-02: Inactive
        $releases = Invoke-AdoApi -Uri "$vsrmUrl/$ProjectName/_apis/release/releases?definitionId=$defId&`$top=1&api-version=7.1" -Header $Header
        if ($releases -and $releases.value -and $releases.value.Count -gt 0) {
            $relDateStr = Get-SafeProperty $releases.value[0] 'createdOn'
            if (-not $relDateStr) { $relDateStr = Get-SafeProperty $releases.value[0] 'modifiedOn' }
            if ($relDateStr) {
                $lastDate = [datetime]$relDateStr
                if ($lastDate -lt $cutoff) {
                    $results.Add((New-ControlResult -Id "REL-02" -Status "FAIL" -Severity "Medium" -Control "Inactive Release Pipelines" -Finding "$prefix — Last release: $($lastDate.ToString('yyyy-MM-dd')). Inactive for 90+ days."))
                }
            }
        } else {
            $results.Add((New-ControlResult -Id "REL-02" -Status "FAIL" -Severity "Medium" -Control "Inactive Release Pipelines" -Finding "$prefix — No releases found. Pipeline may be inactive."))
        }

        # REL-04: Pre-deployment approvals on production stages
        $defEnvs = Get-SafeProperty $def 'environments'
        if ($defEnvs) {
            foreach ($env in $defEnvs) {
                if (Test-IsProductionStage $env.name) {
                    $hasApproval = $false
                    if ($env.preDeployApprovals -and $env.preDeployApprovals.approvals) {
                        foreach ($approval in $env.preDeployApprovals.approvals) {
                            if ($approval.isAutomated -eq $false) { $hasApproval = $true; break }
                        }
                    }
                    if (-not $hasApproval) {
                        $results.Add((New-ControlResult -Id "REL-04" -Status "FAIL" -Severity "High" -Control "Pre-Deployment Approvals" -Finding "$prefix, stage '$($env.name)' — No pre-deployment approval on production stage."))
                    } else {
                        $results.Add((New-ControlResult -Id "REL-04" -Status "PASS" -Severity "High" -Control "Pre-Deployment Approvals" -Finding "$prefix, stage '$($env.name)' — Pre-deployment approval is configured."))
                    }
                }
            }
        }

        # REL-08: Settable variables
        $defVars = Get-SafeProperty $def 'variables'
        if ($defVars) {
            $settable = @($defVars.PSObject.Properties | Where-Object { (Get-SafeProperty $_.Value 'allowOverride') -eq $true })
            if ($settable.Count -gt 0) {
                $results.Add((New-ControlResult -Id "REL-08" -Status "FAIL" -Severity "High" -Control "Settable Variables at Release Time" -Finding "$prefix — $($settable.Count) variable(s) settable at release time. Review necessity."))
            }
        }
    }

    # REL-06: Manual
    $results.Add((New-ControlResult -Id "REL-06" -Status "NOT CHECKED" -Severity "Medium" -Control "Production from Main Branch Only" -Finding "Manual review required. Verify all production deployments use artifacts from the main branch."))

    return $results
}

#endregion

#region Service Connection Controls

function Test-ServiceConnections {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking service connections..."

    $endpoints = @(Invoke-AzCli -Command "devops service-endpoint list --project `"$ProjectName`" --org $OrgUrl -o json")
    if ($endpoints.Count -eq 0 -or ($endpoints.Count -eq 1 -and $null -eq $endpoints[0])) {
        $results.Add((New-ControlResult -Id "SC-*" -Status "PASS" -Severity "High" -Control "Service Connections" -Finding "No service connections found in project."))
        return $results
    }

    foreach ($ep in $endpoints) {
        $epId = $ep.id
        $epName = $ep.name
        $prefix = "SC '$epName'"

        $detail = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/serviceendpoint/endpoints/${epId}?api-version=7.1" -Header $Header
        if (-not $detail) { continue }

        # SC-01: Certificate-based auth
        if ($detail.type -eq 'azurerm') {
            $authType = $detail.authorization.parameters.authenticationType
            if ($authType -ieq 'spnCertificate' -or $detail.authorization.scheme -ieq 'WorkloadIdentityFederation') {
                $results.Add((New-ControlResult -Id "SC-01" -Status "PASS" -Severity "High" -Control "Certificate-Based Authentication" -Finding "$prefix — Uses $authType."))
            } elseif ($authType -ieq 'spnKey') {
                $results.Add((New-ControlResult -Id "SC-01" -Status "FAIL" -Severity "High" -Control "Certificate-Based Authentication" -Finding "$prefix — Uses shared secret (spnKey). Switch to certificate or workload identity federation."))
            }

            # SC-02: Scope level
            $scope = $detail.data.scopeLevel
            if ($scope -ieq 'Subscription' -or $scope -ieq 'ManagementGroup') {
                $results.Add((New-ControlResult -Id "SC-02" -Status "FAIL" -Severity "High" -Control "Subscription/Management Group Scope" -Finding "$prefix — Scoped at '$scope' level. Restrict to Resource Group."))
            } elseif ($scope) {
                $results.Add((New-ControlResult -Id "SC-02" -Status "PASS" -Severity "High" -Control "Subscription/Management Group Scope" -Finding "$prefix — Scoped at '$scope' level."))
            }
        }

        # SC-04: ARM vs classic
        if ($detail.type -ieq 'azure') {
            $results.Add((New-ControlResult -Id "SC-04" -Status "FAIL" -Severity "High" -Control "ARM Service Connections Only" -Finding "$prefix — Classic Azure connection. Migrate to Azure Resource Manager (azurerm)."))
        } elseif ($detail.type -ieq 'azurerm') {
            $results.Add((New-ControlResult -Id "SC-04" -Status "PASS" -Severity "High" -Control "ARM Service Connections Only" -Finding "$prefix — Uses ARM (azurerm)."))
        }

        # SC-08: Accessible to all pipelines
        $pipePerms = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/pipelines/pipelinePermissions/endpoint/${epId}?api-version=7.1-preview.1" -Header $Header
        if ($pipePerms -and ($pipePerms.PSObject.Properties['allPipelines']) -and $pipePerms.allPipelines.authorized -eq $true) {
            $results.Add((New-ControlResult -Id "SC-08" -Status "FAIL" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Accessible to ALL pipelines. Restrict to specific pipelines."))
        } elseif ($pipePerms) {
            $results.Add((New-ControlResult -Id "SC-08" -Status "PASS" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Not accessible to all pipelines."))
        }

        # SC-09: Strong auth
        if ($detail.authorization.scheme -ieq 'UsernamePassword') {
            $results.Add((New-ControlResult -Id "SC-09" -Status "FAIL" -Severity "High" -Control "Strong Authentication Methods" -Finding "$prefix — Uses UsernamePassword auth. Switch to token/cert/workload identity."))
        }

        # SC-11: Cross-project sharing
        if ($detail.isShared -eq $true) {
            $results.Add((New-ControlResult -Id "SC-11" -Status "FAIL" -Severity "High" -Control "No Cross-Project Sharing" -Finding "$prefix — Shared across multiple projects. Use project-specific connections."))
        } else {
            $results.Add((New-ControlResult -Id "SC-11" -Status "PASS" -Severity "High" -Control "No Cross-Project Sharing" -Finding "$prefix — Not shared across projects."))
        }
    }

    # SC-03: Manual
    $results.Add((New-ControlResult -Id "SC-03" -Status "NOT CHECKED" -Severity "High" -Control "Usage History Review" -Finding "Manual review required. Periodically review service connection execution history."))

    return $results
}

#endregion

#region Agent Pool Controls

function Test-AgentPools {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking agent pools..."

    $queues = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/distributedtask/queues?api-version=7.1-preview.1" -Header $Header
    if (-not $queues -or -not $queues.value -or $queues.value.Count -eq 0) {
        $results.Add((New-ControlResult -Id "AP-*" -Status "PASS" -Severity "High" -Control "Agent Pools" -Finding "No agent pool queues found in project."))
        return $results
    }

    $poolsChecked = @{}

    foreach ($queue in $queues.value) {
        $poolId = $queue.pool.id
        $queueId = $queue.id
        if ($poolsChecked.ContainsKey($poolId)) { continue }
        $poolsChecked[$poolId] = $true

        $poolName = $queue.pool.name
        $prefix = "Pool '$poolName'"

        $pool = Invoke-AdoApi -Uri "$OrgUrl/_apis/distributedtask/pools/${poolId}?api-version=7.1" -Header $Header
        if (-not $pool) { continue }

        # AP-01, AP-02: Manual for self-hosted
        if ($pool.isHosted -eq $false) {
            $results.Add((New-ControlResult -Id "AP-01" -Status "NOT CHECKED" -Severity "High" -Control "Security Patches on Self-Hosted VMs" -Finding "$prefix — Self-hosted pool. Manual review required for patch status."))
            $results.Add((New-ControlResult -Id "AP-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Hardened OS Image" -Finding "$prefix — Self-hosted pool. Manual review required for OS hardening."))
        }

        # AP-04: Auto-provisioning
        if ($pool.autoProvision -eq $true) {
            $results.Add((New-ControlResult -Id "AP-04" -Status "FAIL" -Severity "High" -Control "Auto-Provisioning Disabled" -Finding "$prefix — Auto-provision is enabled. Disable and grant access per-project."))
        } else {
            $results.Add((New-ControlResult -Id "AP-04" -Status "PASS" -Severity "High" -Control "Auto-Provisioning Disabled" -Finding "$prefix — Auto-provision is disabled."))
        }

        # AP-05: Accessible to all pipelines
        $pipePerms = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/pipelines/pipelinePermissions/queue/${queueId}?api-version=7.1-preview.1" -Header $Header
        if ($pipePerms -and ($pipePerms.PSObject.Properties['allPipelines']) -and $pipePerms.allPipelines.authorized -eq $true) {
            $results.Add((New-ControlResult -Id "AP-05" -Status "FAIL" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Accessible to ALL pipelines. Restrict to specific pipelines."))
        } elseif ($pipePerms) {
            $results.Add((New-ControlResult -Id "AP-05" -Status "PASS" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Not accessible to all pipelines."))
        }

        # AP-07: Auto-update
        if ($pool.isHosted -eq $false) {
            if ($pool.autoUpdate -eq $true) {
                $results.Add((New-ControlResult -Id "AP-07" -Status "PASS" -Severity "High" -Control "Auto-Update Enabled" -Finding "$prefix — Auto-update is enabled."))
            } else {
                $results.Add((New-ControlResult -Id "AP-07" -Status "FAIL" -Severity "High" -Control "Auto-Update Enabled" -Finding "$prefix — Auto-update is disabled. Enable to keep agents patched."))
            }
        }

        # AP-08: Secrets in capabilities
        if ($pool.isHosted -eq $false) {
            $agents = Invoke-AdoApi -Uri "$OrgUrl/_apis/distributedtask/pools/${poolId}/agents?includeCapabilities=true&api-version=7.1" -Header $Header
            if ($agents -and $agents.value) {
                foreach ($agent in $agents.value) {
                    if ($agent.userCapabilities) {
                        foreach ($cap in $agent.userCapabilities.PSObject.Properties) {
                            if (Test-LooksLikeSecret $cap.Name) {
                                $results.Add((New-ControlResult -Id "AP-08" -Status "FAIL" -Severity "High" -Control "No Plain Text Secrets in Capabilities" -Finding "$prefix, agent '$($agent.name)' — Suspect capability: '$($cap.Name)'. Remove from user capabilities."))
                            }
                        }
                    }
                }
            }
        }
    }

    return $results
}

#endregion

#region Repository Controls

function Test-Repositories {
    param([string]$OrgUrl, [string]$ProjectName, [string]$ProjectId, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking repositories..."

    $repos = @(Invoke-AzCli -Command "repos list --project `"$ProjectName`" --org $OrgUrl -o json")
    if ($repos.Count -eq 0 -or ($repos.Count -eq 1 -and $null -eq $repos[0])) {
        $results.Add((New-ControlResult -Id "REPO-*" -Status "PASS" -Severity "Medium" -Control "Repositories" -Finding "No repositories found in project."))
        return $results
    }

    # Per-repo checks can run in parallel when there are many repos
    if ($repos.Count -gt 3 -and $PSVersionTable.PSVersion.Major -ge 7) {
        # Serialize only the functions needed for repo checks
        # NOTE: Get-ControlCategory must be included because New-ControlResult
        # calls it whenever the caller does not supply an explicit -Category.
        $repoFuncDefs = @(
            "function Invoke-AdoApi {`n$((Get-Item Function:\Invoke-AdoApi).Definition)`n}",
            "function New-ControlResult {`n$((Get-Item Function:\New-ControlResult).Definition)`n}",
            "function Get-ControlCategory {`n$((Get-Item Function:\Get-ControlCategory).Definition)`n}",
            "function Get-SafeProperty {`n$((Get-Item Function:\Get-SafeProperty).Definition)`n}"
        ) -join "`n`n"

        $repoResults = $repos | ForEach-Object -Parallel {
            $repo = $_
            . ([scriptblock]::Create($using:repoFuncDefs))
            $orgUrl = $using:OrgUrl
            $projName = $using:ProjectName
            $projId = $using:ProjectId
            $hdr = $using:Header

            $repoId = $repo.id
            $repoName = $repo.name
            $prefix = "Repo '$repoName'"

            $pipePerms = Invoke-AdoApi -Uri "$orgUrl/$projName/_apis/pipelines/pipelinePermissions/repository/${projId}.${repoId}?api-version=7.1-preview.1" -Header $hdr
            if ($pipePerms -and ($pipePerms.PSObject.Properties['allPipelines']) -and $pipePerms.allPipelines.authorized -eq $true) {
                New-ControlResult -Id "REPO-02" -Status "FAIL" -Severity "Medium" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Accessible to ALL pipelines. Restrict to specific pipelines."
            } elseif ($pipePerms) {
                New-ControlResult -Id "REPO-02" -Status "PASS" -Severity "Medium" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Not accessible to all pipelines."
            }
        } -ThrottleLimit 5

        Add-ResultsSafe $results $repoResults
    } else {
        # Sequential fallback
        foreach ($repo in $repos) {
            $repoId = $repo.id
            $repoName = $repo.name
            $prefix = "Repo '$repoName'"

            # REPO-02: Accessible to all pipelines
            $pipePerms = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/pipelines/pipelinePermissions/repository/${ProjectId}.${repoId}?api-version=7.1-preview.1" -Header $Header
            if ($pipePerms -and ($pipePerms.PSObject.Properties['allPipelines']) -and $pipePerms.allPipelines.authorized -eq $true) {
                $results.Add((New-ControlResult -Id "REPO-02" -Status "FAIL" -Severity "Medium" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Accessible to ALL pipelines. Restrict to specific pipelines."))
            } elseif ($pipePerms) {
                $results.Add((New-ControlResult -Id "REPO-02" -Status "PASS" -Severity "Medium" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Not accessible to all pipelines."))
            }
        }
    }

    # REPO-06: Credential scanner (already checked at project level as PROJ-14)
    # REPO-01: Inactive Repositories — check last push date per repo
    $inactiveRepoCutoff = (Get-Date).AddDays(-$script:InactiveRepoDays)
    $inactiveRepos = [System.Collections.Generic.List[string]]::new()
    foreach ($repo in $repos) {
        $repoName = $repo.name
        # Use the repo's default branch to check last commit
        $defaultBranch = Get-SafeProperty $repo 'defaultBranch'
        if ($defaultBranch) {
            $branchName = $defaultBranch -replace '^refs/heads/', ''
            $stats = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/git/repositories/$($repo.id)/stats/branches?name=$branchName&api-version=7.1" -Header $Header
            if ($stats) {
                $lastCommitDate = Get-SafeProperty (Get-SafeProperty $stats 'commit') 'committer'
                $dateStr = if ($lastCommitDate) { Get-SafeProperty $lastCommitDate 'date' } else { $null }
                if ($dateStr -and [datetime]$dateStr -lt $inactiveRepoCutoff) {
                    $inactiveRepos.Add($repoName)
                }
            }
        }
    }
    if ($inactiveRepos.Count -eq 0) {
        $results.Add((New-ControlResult -Id "REPO-01" -Status "PASS" -Severity "Medium" -Control "Inactive Repositories" -Finding "All repositories have had commits within the last $($script:InactiveRepoDays) days."))
    } else {
        $repoNames = ($inactiveRepos | Select-Object -First 10) -join ', '
        $results.Add((New-ControlResult -Id "REPO-01" -Status "FAIL" -Severity "Medium" -Control "Inactive Repositories" -Finding "$($inactiveRepos.Count) repository(ies) inactive for $($script:InactiveRepoDays)+ days: $repoNames. Review and archive if no longer needed."))
    }

    # === BRANCH POLICIES (BRANCH-01..04) ===
    # Fetch project-scope policy configurations once, then per-repo evaluate
    # whether each well-known policy type applies to the repo's default branch.
    $branchPolicyTypes = @(
        @{ Id = 'BRANCH-01'; TypeId = 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd'; NamePattern = 'minimum number of reviewers';   Severity = 'High';   Control = 'Minimum Reviewers on Default Branch';   Action = 'Configure a "Require a minimum number of reviewers" branch policy via Project Settings > Repos > Policies.' }
        @{ Id = 'BRANCH-02'; TypeId = '0609b952-1397-4640-95ec-e00a01b2c241'; NamePattern = '^build$';                       Severity = 'High';   Control = 'Build Validation on Default Branch';    Action = 'Configure a "Build validation" branch policy via Project Settings > Repos > Policies.' }
        @{ Id = 'BRANCH-03'; TypeId = '40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e'; NamePattern = 'work item linking';             Severity = 'Medium'; Control = 'Work Item Linking Required';            Action = 'Enable the "Check for linked work items" branch policy.' }
        @{ Id = 'BRANCH-04'; TypeId = 'c6a1889d-b943-4856-b76f-9e46bb6b0df2'; NamePattern = 'comment requirements';          Severity = 'Low';    Control = 'Comment Resolution Required';           Action = 'Enable the "Check for comment resolution" branch policy.' }
    )

    $allPolicies = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/policy/configurations?api-version=7.1" -Header $Header
    $policiesByTypeId = @{}
    $policiesByNamePattern = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($allPolicies -and $allPolicies.value) {
        foreach ($pol in $allPolicies.value) {
            $polType   = Get-SafeProperty $pol 'type'
            $polTypeId = if ($polType) { Get-SafeProperty $polType 'id' } else { $null }
            $polName   = if ($polType) { Get-SafeProperty $polType 'displayName' } else { $null }
            if ($polTypeId) {
                if (-not $policiesByTypeId.ContainsKey($polTypeId)) {
                    $policiesByTypeId[$polTypeId] = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $policiesByTypeId[$polTypeId].Add($pol)
            }
            if ($polName) {
                $policiesByNamePattern.Add([PSCustomObject]@{ Name = $polName; Policy = $pol })
            }
        }
    }

    foreach ($bp in $branchPolicyTypes) {
        $missing      = [System.Collections.Generic.List[string]]::new()
        $reposChecked = 0
        # Candidate set: matches by type id OR by display-name pattern (case-insensitive)
        $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($policiesByTypeId.ContainsKey($bp.TypeId)) {
            foreach ($p in $policiesByTypeId[$bp.TypeId]) { $candidates.Add($p) }
        }
        foreach ($entry in $policiesByNamePattern) {
            if ($entry.Name -imatch $bp.NamePattern) { $candidates.Add($entry.Policy) }
        }

        foreach ($repo in $repos) {
            $defaultBranch = Get-SafeProperty $repo 'defaultBranch'
            if (-not $defaultBranch) { continue }
            $reposChecked++

            $applied = $false
            foreach ($p in $candidates) {
                if (Test-PolicyAppliesToBranch -Policy $p -RepoId $repo.id -RefName $defaultBranch) {
                    $applied = $true
                    break
                }
            }
            if (-not $applied) { $missing.Add($repo.name) }
        }

        if ($reposChecked -eq 0) {
            $results.Add((New-ControlResult -Id $bp.Id -Status 'NOT CHECKED' -Severity $bp.Severity -Control $bp.Control -Finding 'No repositories with a default branch were found to evaluate.'))
        }
        elseif ($missing.Count -eq 0) {
            $results.Add((New-ControlResult -Id $bp.Id -Status 'PASS' -Severity $bp.Severity -Control $bp.Control -Finding "All $reposChecked repository default branch(es) have the policy enabled."))
        }
        else {
            $missList = ($missing | Select-Object -First 10) -join ', '
            $results.Add((New-ControlResult -Id $bp.Id -Status 'FAIL' -Severity $bp.Severity -Control $bp.Control -Finding "$($missing.Count)/$reposChecked repository default branch(es) missing the policy: $missList. $($bp.Action)"))
        }
    }

    # === COMMUNITY FILES (REPO-03..05) ===
    # Check default-branch presence of README / CONTRIBUTING / CODE_OF_CONDUCT.
    # 404 from the items endpoint maps to $null in Invoke-AdoApi, so a missing
    # file simply means "not found" without raising an error.
    $communityChecks = @(
        @{ Id = 'REPO-03'; FileNames = @('README.md','README','README.rst','README.txt');                Control = 'README Present on Default Branch';            Severity = 'Low' }
        @{ Id = 'REPO-04'; FileNames = @('CONTRIBUTING.md','CONTRIBUTING','CONTRIBUTING.rst');           Control = 'CONTRIBUTING File Present on Default Branch'; Severity = 'Low' }
        @{ Id = 'REPO-05'; FileNames = @('CODE_OF_CONDUCT.md','CODE_OF_CONDUCT','CODE-OF-CONDUCT.md');   Control = 'CODE_OF_CONDUCT File Present on Default Branch'; Severity = 'Low' }
    )

    foreach ($check in $communityChecks) {
        $missing      = [System.Collections.Generic.List[string]]::new()
        $reposChecked = 0
        foreach ($repo in $repos) {
            $defaultBranch = Get-SafeProperty $repo 'defaultBranch'
            if (-not $defaultBranch) { continue }
            $reposChecked++
            $branchName = $defaultBranch -replace '^refs/heads/', ''

            $found = $false
            foreach ($fileName in $check.FileNames) {
                $encoded = [System.Uri]::EscapeDataString($fileName)
                $itemUri = "$OrgUrl/$ProjectName/_apis/git/repositories/$($repo.id)/items?path=$encoded&versionDescriptor.version=$branchName&versionDescriptor.versionType=branch&api-version=7.1"
                $item = Invoke-AdoApi -Uri $itemUri -Header $Header
                if ($item -and ((Get-SafeProperty $item 'path') -or (Get-SafeProperty $item 'objectId'))) {
                    $found = $true
                    break
                }
            }
            if (-not $found) { $missing.Add($repo.name) }
        }

        if ($reposChecked -eq 0) {
            $results.Add((New-ControlResult -Id $check.Id -Status 'NOT CHECKED' -Severity $check.Severity -Control $check.Control -Finding 'No repositories with a default branch were found to evaluate.'))
        }
        elseif ($missing.Count -eq 0) {
            $results.Add((New-ControlResult -Id $check.Id -Status 'PASS' -Severity $check.Severity -Control $check.Control -Finding "All $reposChecked repository default branch(es) include the file."))
        }
        else {
            $missList = ($missing | Select-Object -First 10) -join ', '
            $results.Add((New-ControlResult -Id $check.Id -Status 'FAIL' -Severity $check.Severity -Control $check.Control -Finding "$($missing.Count)/$reposChecked repository default branch(es) missing the file: $missList."))
        }
    }

    return $results
}

#endregion

#region Feed Controls (Project-Level)

function Test-ProjectFeeds {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking project feeds..."

    $feeds = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/packaging/feeds?api-version=7.1-preview.1" -Header $Header
    if (-not $feeds -or -not $feeds.value -or $feeds.value.Count -eq 0) {
        return $results
    }

    foreach ($feed in $feeds.value) {
        $feedName = $feed.name
        $prefix = "Feed '$feedName'"

        $perms = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/packaging/Feeds/$($feed.id)/permissions?api-version=7.1-preview.1" -Header $Header
        if ($perms -and $perms.value) {
            foreach ($perm in $perms.value) {
                if ((Test-IsBroadGroup $perm.displayName) -and $perm.role -ine 'reader') {
                    $results.Add((New-ControlResult -Id "FEED-01" -Status "FAIL" -Severity "High" -Control "No Broad Upload Permissions" -Finding "$prefix — '$($perm.displayName)' has '$($perm.role)' role. Restrict to Reader."))
                }
            }
        }
    }

    return $results
}

#endregion

#region Secure File Controls

function Test-SecureFiles {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking secure files..."

    $secFiles = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/distributedtask/securefiles?api-version=7.1-preview.1" -Header $Header
    if (-not $secFiles -or -not $secFiles.value -or $secFiles.value.Count -eq 0) {
        return $results
    }

    foreach ($sf in $secFiles.value) {
        $sfName = $sf.name
        $sfId = $sf.id
        $prefix = "SecureFile '$sfName'"

        # SF-01: Accessible to all pipelines
        $pipePerms = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/pipelines/pipelinePermissions/securefile/${sfId}?api-version=7.1-preview.1" -Header $Header
        if ($pipePerms -and ($pipePerms.PSObject.Properties['allPipelines']) -and $pipePerms.allPipelines.authorized -eq $true) {
            $results.Add((New-ControlResult -Id "SF-01" -Status "FAIL" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Accessible to ALL pipelines. Restrict to specific pipelines."))
        } elseif ($pipePerms) {
            $results.Add((New-ControlResult -Id "SF-01" -Status "PASS" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Not accessible to all pipelines."))
        }
    }

    return $results
}

#endregion

#region Environment Controls

function Test-Environments {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking environments..."

    $envs = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/distributedtask/environments?api-version=7.1-preview.1" -Header $Header
    if (-not $envs -or -not $envs.value -or $envs.value.Count -eq 0) {
        return $results
    }

    foreach ($env in $envs.value) {
        $envName = $env.name
        $envId = $env.id
        $prefix = "Environment '$envName'"

        # ENV-01: Accessible to all pipelines
        $pipePerms = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/pipelines/pipelinePermissions/environment/${envId}?api-version=7.1-preview.1" -Header $Header
        if ($pipePerms -and ($pipePerms.PSObject.Properties['allPipelines']) -and $pipePerms.allPipelines.authorized -eq $true) {
            $results.Add((New-ControlResult -Id "ENV-01" -Status "FAIL" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Accessible to ALL pipelines. Restrict to specific pipelines."))
        } elseif ($pipePerms) {
            $results.Add((New-ControlResult -Id "ENV-01" -Status "PASS" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Not accessible to all pipelines."))
        }

        # ENV-03: Production approvals
        if (Test-IsProductionStage $envName) {
            $envDetail = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/distributedtask/environments/${envId}?expands=checks&api-version=7.1-preview.1" -Header $Header
            $hasApproval = $false
            if ($envDetail -and $envDetail.checks) {
                foreach ($check in $envDetail.checks) {
                    if ($check.type.name -imatch 'approval') {
                        $hasApproval = $true
                        break
                    }
                }
            }
            if ($hasApproval) {
                $results.Add((New-ControlResult -Id "ENV-03" -Status "PASS" -Severity "High" -Control "Production Approvals" -Finding "$prefix — Approval checks configured."))
            } else {
                $results.Add((New-ControlResult -Id "ENV-03" -Status "FAIL" -Severity "High" -Control "Production Approvals" -Finding "$prefix — No approval checks on production environment. Add approval checks."))
            }
        }
    }

    return $results
}

#endregion

#region Variable Group Controls

function Test-VariableGroups {
    param([string]$OrgUrl, [string]$ProjectName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Project: $ProjectName" -Status "Checking variable groups..."

    $vgs = @(Invoke-AzCli -Command "pipelines variable-group list --project `"$ProjectName`" --org $OrgUrl -o json")
    if ($vgs.Count -eq 0 -or ($vgs.Count -eq 1 -and $null -eq $vgs[0])) {
        return $results
    }

    foreach ($vg in $vgs) {
        $vgId = $vg.id
        $vgName = $vg.name
        $prefix = "VarGroup '$vgName'"
        $hasSecrets = $false

        # VG-03: Plain text secrets
        if ($vg.variables) {
            $suspectVars = @()
            foreach ($prop in $vg.variables.PSObject.Properties) {
                $isSecret = Get-SafeProperty $prop.Value 'isSecret'
                if ($isSecret -eq $true) { $hasSecrets = $true }
                if (-not $isSecret -and (Test-LooksLikeSecret $prop.Name)) {
                    $suspectVars += $prop.Name
                }
            }
            if ($suspectVars.Count -gt 0) {
                $results.Add((New-ControlResult -Id "VG-03" -Status "FAIL" -Severity "High" -Control "No Plain Text Secrets" -Finding "$prefix — Suspect plain-text variables: $($suspectVars -join ', '). Mark as secret or use Key Vault."))
            } else {
                $results.Add((New-ControlResult -Id "VG-03" -Status "PASS" -Severity "High" -Control "No Plain Text Secrets" -Finding "$prefix — No plain-text secret variables detected."))
            }
        }

        # VG-01: Secret variable groups not accessible to all pipelines
        if ($hasSecrets) {
            $pipePerms = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/pipelines/pipelinePermissions/variablegroup/${vgId}?api-version=7.1-preview.1" -Header $Header
            if ($pipePerms -and ($pipePerms.PSObject.Properties['allPipelines']) -and $pipePerms.allPipelines.authorized -eq $true) {
                $results.Add((New-ControlResult -Id "VG-01" -Status "FAIL" -Severity "High" -Control "Secret Variables Not in All Pipelines" -Finding "$prefix — Contains secrets and is accessible to ALL pipelines. Restrict access."))
            } elseif ($pipePerms) {
                $results.Add((New-ControlResult -Id "VG-01" -Status "PASS" -Severity "High" -Control "Secret Variables Not in All Pipelines" -Finding "$prefix — Contains secrets but access is restricted to specific pipelines."))
            }
        }

        # VG-04: Key Vault usage
        if ($hasSecrets -and $vg.type -ieq 'Vsts') {
            $results.Add((New-ControlResult -Id "VG-04" -Status "FAIL" -Severity "Low" -Control "Use Azure Key Vault" -Finding "$prefix — Contains secrets in a custom variable group. Consider linking to Azure Key Vault."))
        } elseif ($vg.type -ieq 'AzureKeyVault') {
            $results.Add((New-ControlResult -Id "VG-04" -Status "PASS" -Severity "Low" -Control "Use Azure Key Vault" -Finding "$prefix — Linked to Azure Key Vault."))
        }
    }

    return $results
}

#endregion

#region User/PAT Controls

function Test-UserPats {
    param([string]$OrgShortName, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking PATs (current user only)..."

    $pats = Invoke-AdoApi -Uri "https://vssps.dev.azure.com/$OrgShortName/_apis/tokens/pats?api-version=7.1-preview.1" -Header $Header

    if (-not $pats -or -not $pats.patTokens) {
        $results.Add((New-ControlResult -Id "PAT-*" -Status "NOT CHECKED" -Severity "Medium" -Control "Personal Access Tokens" -Finding "Could not retrieve PATs. This API only returns the calling user's own PATs. Org-wide PAT audit requires Azure AD audit logs."))
        return $results
    }

    $cutoff = (Get-Date).AddDays(7)

    foreach ($pat in $pats.patTokens) {
        $patName = $pat.displayName
        $prefix = "PAT '$patName'"

        # PAT-01: Full access
        if ($pat.scope -ieq 'app_token') {
            $results.Add((New-ControlResult -Id "PAT-01" -Status "FAIL" -Severity "Medium" -Control "Minimum Required Permissions" -Finding "$prefix — Has full access (app_token) scope. Recreate with specific scopes."))
        } else {
            $results.Add((New-ControlResult -Id "PAT-01" -Status "PASS" -Severity "Medium" -Control "Minimum Required Permissions" -Finding "$prefix — Has scoped permissions."))
        }

        # PAT-02: Validity period
        if ($pat.validTo) {
            $validTo = [datetime]$pat.validTo
            $validFrom = if ($pat.validFrom) { [datetime]$pat.validFrom } else { $validTo.AddDays(-90) }
            $validityDays = ($validTo - $validFrom).Days
            if ($validityDays -gt 90) {
                $results.Add((New-ControlResult -Id "PAT-02" -Status "FAIL" -Severity "Medium" -Control "Short Validity Period" -Finding "$prefix — Valid for $validityDays days (exceeds 90). Recreate with shorter validity."))
            } else {
                $results.Add((New-ControlResult -Id "PAT-02" -Status "PASS" -Severity "Medium" -Control "Short Validity Period" -Finding "$prefix — Valid for $validityDays days."))
            }

            # PAT-03: Near expiry
            if ($validTo -lt $cutoff -and $validTo -gt (Get-Date)) {
                $results.Add((New-ControlResult -Id "PAT-03" -Status "FAIL" -Severity "Medium" -Control "Near-Expiry PAT Renewal" -Finding "$prefix — Expires on $($validTo.ToString('yyyy-MM-dd')). Renew soon."))
            }
        }

        # PAT-06: Critical permissions
        $criticalScopes = @('vso.security_manage', 'vso.entitlements', 'vso.memberentitlementmanagement_write', 'vso.project_manage', 'app_token')
        if ($pat.scope) {
            foreach ($cs in $criticalScopes) {
                if ($pat.scope -imatch [regex]::Escape($cs)) {
                    $results.Add((New-ControlResult -Id "PAT-06" -Status "FAIL" -Severity "Medium" -Control "No Critical Permission PATs" -Finding "$prefix — Has critical scope '$cs'. Use service principals for automation."))
                    break
                }
            }
        }
    }

    return $results
}

function Test-OrgWidePats {
    param([string]$OrgUrl, [hashtable]$Header)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "Org Assessment" -Status "Checking org-wide PATs (requires PCA)..."

    # The tokenadmin API requires Project Collection Administrator permissions
    $patAdmin = Invoke-AdoApi -Uri "$OrgUrl/_apis/tokenadmin/personalaccesstokens?api-version=7.1-preview.1" -Header $Header

    if (-not $patAdmin -or -not $patAdmin.value) {
        $results.Add((New-ControlResult -Id "PAT-*" -Status "NOT CHECKED" -Severity "Medium" -Control "Personal Access Tokens" -Finding "Could not retrieve org-wide PATs. This API requires Project Collection Administrator permissions."))
        return $results
    }

    $allPats = $patAdmin.value
    $fullAccessPats = @($allPats | Where-Object { $_.scope -ieq 'app_token' })
    $longLivedPats = @($allPats | Where-Object {
        if ($_.validTo -and $_.validFrom) {
            $days = ([datetime]$_.validTo - [datetime]$_.validFrom).Days
            $days -gt 90
        } else { $false }
    })

    if ($fullAccessPats.Count -eq 0) {
        $results.Add((New-ControlResult -Id "PAT-01" -Status "PASS" -Severity "Medium" -Control "Minimum Required Permissions" -Finding "No org-wide full-access PATs found across $($allPats.Count) total PATs."))
    } else {
        $results.Add((New-ControlResult -Id "PAT-01" -Status "FAIL" -Severity "Medium" -Control "Minimum Required Permissions" -Finding "$($fullAccessPats.Count) full-access PAT(s) found across the organization. These should be recreated with specific scopes."))
    }

    if ($longLivedPats.Count -eq 0) {
        $results.Add((New-ControlResult -Id "PAT-02" -Status "PASS" -Severity "Medium" -Control "Short Validity Period" -Finding "No org-wide PATs with validity exceeding 90 days."))
    } else {
        $results.Add((New-ControlResult -Id "PAT-02" -Status "FAIL" -Severity "Medium" -Control "Short Validity Period" -Finding "$($longLivedPats.Count) PAT(s) with validity exceeding 90 days found across the organization."))
    }

    return $results
}

function Import-AdoqrSettings {
    <#
    .SYNOPSIS
        Loads optional user settings from adoqr.settings.psd1.
    .DESCRIPTION
        Reads a PowerShell data file at the specified path and returns a
        hashtable of validated configuration overrides.  If the file does not
        exist an empty hashtable is returned so callers need not null-check.
    .PARAMETER Path
        Full path to the settings file.  Defaults to adoqr.settings.psd1 in
        the same directory as invoke-adoqr.ps1.
    #>
    [CmdletBinding()]
    param(
        [string]$Path = (Join-Path $PSScriptRoot 'adoqr.settings.psd1')
    )

    if (-not (Test-Path $Path)) {
        return @{}
    }

    try {
        $data = Import-PowerShellDataFile -Path $Path -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read settings file '$Path': $_"
        return @{}
    }

    $settings = @{}

    if ($data.ContainsKey('InactiveRepoDays')) {
        $val = $data['InactiveRepoDays']
        if ($val -is [int] -and $val -gt 0) {
            $settings['InactiveRepoDays'] = $val
        }
        else {
            Write-Warning "Settings: 'InactiveRepoDays' must be a positive integer. Ignoring value '$val'."
        }
    }

    return $settings
}

#endregion

#region Main

# Apply optional user settings (adoqr.settings.psd1 next to this script)
$_userSettings = Import-AdoqrSettings -Path (Join-Path $PSScriptRoot 'adoqr.settings.psd1')
if ($_userSettings.ContainsKey('InactiveRepoDays')) {
    $script:InactiveRepoDays = $_userSettings['InactiveRepoDays']
    Write-Verbose "Settings: InactiveRepoDays overridden to $($script:InactiveRepoDays) (from adoqr.settings.psd1)"
}

# Normalize organization URL
if ($Organization -notmatch '^https?://') {
    $OrgUrl = "https://dev.azure.com/$Organization"
} else {
    $OrgUrl = $Organization.TrimEnd('/')
}

$OrgShortName = $OrgUrl -replace '^https?://dev\.azure\.com/', '' -replace '^https?://([^.]+)\.visualstudio\.com.*', '$1'

# Subdomain URLs for specialized ADO REST APIs
$script:VsspsUrl   = "https://vssps.dev.azure.com/$OrgShortName"
$script:ExtMgmtUrl = "https://extmgmt.dev.azure.com/$OrgShortName"
$script:AuditUrl   = "https://auditservice.dev.azure.com/$OrgShortName"
$script:FeedsUrl   = "https://feeds.dev.azure.com/$OrgShortName"

# Ensure output directory exists — create timestamped subfolder per run
$timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
$orgSafeForPath = ($OrgShortName -replace '[^a-zA-Z0-9\-]', '-').ToLower().Trim('-')
$OutputPath = Join-Path $OutputPath "$orgSafeForPath-$timestamp"
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Azure DevOps Quick Review" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Organization : $OrgUrl"
Write-Host "Org Name     : $OrgShortName"
Write-Host "Output Path  : $(Resolve-Path $OutputPath)"
Write-Host ""

# Prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow
try {
    $azVersion = az version 2>&1 | ConvertFrom-Json
    Write-Host "  Azure CLI: $($azVersion.'azure-cli')" -ForegroundColor Green
}
catch {
    Write-Error "Azure CLI is not installed or not in PATH. Install from https://aka.ms/installazurecliwindows"
    return
}

$devopsExt = @(az extension list --query "[?name=='azure-devops']" 2>&1 | ConvertFrom-Json)
if ($devopsExt.Count -eq 0 -or ($devopsExt.Count -eq 1 -and $null -eq $devopsExt[0])) {
    Write-Host "  Installing azure-devops extension..." -ForegroundColor Yellow
    az extension add --name azure-devops 2>&1 | Out-Null
}
Write-Host "  azure-devops extension: installed" -ForegroundColor Green

# Get token
Write-Host "Obtaining bearer token..." -ForegroundColor Yellow
$token = Get-AdoBearerToken
$header = @{ Authorization = "Bearer $token" }
Write-Host "  Token obtained." -ForegroundColor Green
Write-Host ""

# Set default org for az devops commands
az devops configure --defaults organization=$OrgUrl 2>&1 | Out-Null

# Validate organization and discover projects in one call.
# Using Invoke-WebRequest directly so we can distinguish 401/403/404 vs other failures
# and produce actionable guidance for misspelled org / project names.
Write-Host "Validating organization and discovering projects..." -ForegroundColor Yellow
$projectsApi = "$OrgUrl/_apis/projects?api-version=7.1-preview.4&`$top=1000&stateFilter=all"
$discoveredNames = @()
try {
    $resp = Invoke-WebRequest -Uri $projectsApi -Headers $header -Method GET -UseBasicParsing -ErrorAction Stop
    $data = $resp.Content | ConvertFrom-Json
    $discoveredNames = @($data.value | ForEach-Object { $_.name } | Sort-Object)
}
catch {
    $status = 0
    if ($_.Exception.Response) { try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = 0 } }
    switch ($status) {
        401 {
            Write-Error "Authentication failed (HTTP 401) for '$OrgUrl'. Run 'az login' and confirm the active tenant with 'az account show'."
            return
        }
        403 {
            Write-Error "Access denied (HTTP 403) to organization '$OrgShortName'. The signed-in identity does not have permission to list projects. Ensure it is at least a Project Collection Valid User."
            return
        }
        404 {
            Write-Error @"
Organization '$OrgShortName' was not found (HTTP 404).

Resolved URL: $OrgUrl

Check that:
  - The organization name is spelled correctly (you passed: '$Organization')
  - The signed-in account has access (verify with: az account show)
  - If using a legacy *.visualstudio.com URL, pass the full URL form
"@
            return
        }
        default {
            Write-Error "Failed to query organization '$OrgShortName' at $projectsApi`: $($_.Exception.Message)"
            return
        }
    }
}

if ($discoveredNames.Count -eq 0) {
    Write-Warning "Organization '$OrgShortName' returned no projects. It may be empty, or your account may lack visibility."
}

# Resolve -Project filter against discovered list (case-insensitive, with suggestions)
if ($Project) {
    $resolved = New-Object 'System.Collections.Generic.List[string]'
    $unknown  = New-Object 'System.Collections.Generic.List[string]'
    foreach ($req in $Project) {
        $match = $discoveredNames | Where-Object { $_ -ieq $req } | Select-Object -First 1
        if ($match) { [void]$resolved.Add($match) } else { [void]$unknown.Add($req) }
    }
    if ($unknown.Count -gt 0) {
        $lines = foreach ($u in $unknown) {
            # Substring contains either direction
            $suggestions = @($discoveredNames | Where-Object { $_ -like "*$u*" -or $u -like "*$_*" } | Select-Object -First 3)
            if ($suggestions.Count -eq 0 -and $u.Length -ge 2) {
                # Fallback: shared prefix (first 2-3 chars)
                $prefix = $u.Substring(0, [math]::Min(3, $u.Length))
                $suggestions = @($discoveredNames | Where-Object { $_ -like "$prefix*" } | Select-Object -First 3)
            }
            if ($suggestions.Count -gt 0) {
                "  - '$u' (did you mean: $($suggestions -join ', ')?)"
            } else {
                "  - '$u'"
            }
        }
        $availableSample = if ($discoveredNames.Count -le 25) { $discoveredNames -join ', ' } else { ($discoveredNames | Select-Object -First 25) -join ', ' + ", ... (+$($discoveredNames.Count - 25) more)" }
        Write-Error @"
The following project(s) were not found in organization '$OrgShortName':
$($lines -join "`n")

Available projects ($($discoveredNames.Count)):
  $availableSample
"@
        return
    }
    $projectNames = @($resolved)
    Write-Host "  Validated $($projectNames.Count) project(s): $($projectNames -join ', ')" -ForegroundColor Green
} else {
    $projectNames = $discoveredNames
    Write-Host "  Found $($projectNames.Count) project(s) in '$OrgShortName'." -ForegroundColor Green
}
Write-Host ""

# ===== ASSESSMENT EXECUTION =====

$orgSafeName = Get-SafeFileName $OrgShortName

if ($MaxParallel -gt 1 -and $projectNames.Count -gt 1 -and $PSVersionTable.PSVersion.Major -ge 7) {
    # =============================================
    #  PARALLEL MODE — Org + Projects concurrently
    # =============================================
    Write-Host "Running reviews in parallel (throttle: $MaxParallel)..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  NOTE: Parallel mode increases API request volume. Azure DevOps enforces" -ForegroundColor DarkYellow
    Write-Host "  a 200 TSTU limit per user in a sliding 5-minute window. The script monitors" -ForegroundColor DarkYellow
    Write-Host "  X-RateLimit headers and will auto-throttle if limits are approached." -ForegroundColor DarkYellow
    Write-Host "  If you experience slowdowns, reduce -MaxParallel or run sequentially." -ForegroundColor DarkYellow
    Write-Host ""

    # Serialize all assessment functions so parallel runspaces can use them
    $allFunctionDefs = (Get-ChildItem Function: | Where-Object {
        $_.Name -match '^(Invoke-AdoApi|Invoke-AzCli|New-ControlResult|Test-|Get-Safe|Get-ControlCategory|Write-Assessment|Add-ResultsSafe)'
    } | ForEach-Object {
        "function $($_.Name) {`n$($_.Definition)`n}"
    }) -join "`n`n"

    # Collect script-scope variables needed by assessment functions
    $scriptConfig = @{
        CredentialRegex    = $script:CredentialRegex
        CredentialPatterns = $script:CredentialPatterns
        InactiveDays       = $script:InactiveDays
        InactiveRepoDays   = $script:InactiveRepoDays
        BroadGroups        = $script:BroadGroups
        ProductionKeywords = $script:ProductionKeywords
        VsspsUrl           = $script:VsspsUrl
        ExtMgmtUrl         = $script:ExtMgmtUrl
        AuditUrl           = $script:AuditUrl
        FeedsUrl           = $script:FeedsUrl
    }

    # Helper to restore functions and config inside a runspace
    $initRunspace = @"
        . ([scriptblock]::Create(`$using:allFunctionDefs))
        `$cfg = `$using:scriptConfig
        `$script:CredentialRegex    = `$cfg.CredentialRegex
        `$script:CredentialPatterns = `$cfg.CredentialPatterns
        `$script:InactiveDays       = `$cfg.InactiveDays
        `$script:InactiveRepoDays   = `$cfg.InactiveRepoDays
        `$script:BroadGroups        = `$cfg.BroadGroups
        `$script:ProductionKeywords = `$cfg.ProductionKeywords
        `$script:VsspsUrl           = `$cfg.VsspsUrl
        `$script:ExtMgmtUrl         = `$cfg.ExtMgmtUrl
        `$script:AuditUrl           = `$cfg.AuditUrl
        `$script:FeedsUrl           = `$cfg.FeedsUrl
"@

    # --- Phase 1: Org assessment as a thread job (runs concurrently with projects) ---
    $orgJob = Start-ThreadJob -ScriptBlock {
        param($orgUrl, $hdr, $orgShort, $outPath, $orgSafe, $funcDefs, $cfg, $graphCheck)

        . ([scriptblock]::Create($funcDefs))
        $script:CredentialRegex    = $cfg.CredentialRegex
        $script:CredentialPatterns = $cfg.CredentialPatterns
        $script:InactiveDays       = $cfg.InactiveDays
        $script:InactiveRepoDays   = $cfg.InactiveRepoDays
        $script:BroadGroups        = $cfg.BroadGroups
        $script:ProductionKeywords = $cfg.ProductionKeywords
        $script:VsspsUrl           = $cfg.VsspsUrl
        $script:ExtMgmtUrl         = $cfg.ExtMgmtUrl
        $script:AuditUrl           = $cfg.AuditUrl
        $script:FeedsUrl           = $cfg.FeedsUrl

        $orgResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        Add-ResultsSafe $orgResults (Test-OrgPolicies -OrgUrl $orgUrl -Header $hdr)
        Add-ResultsSafe $orgResults (Test-OrgUsers -OrgUrl $orgUrl -Header $hdr -IncludeGraphCheck:$graphCheck)
        Add-ResultsSafe $orgResults (Test-OrgAdmins -OrgUrl $orgUrl -Header $hdr)
        Add-ResultsSafe $orgResults (Test-OrgExtensions -OrgUrl $orgUrl -Header $hdr)
        Add-ResultsSafe $orgResults (Test-OrgAudit -OrgUrl $orgUrl -Header $hdr)
        Add-ResultsSafe $orgResults (Test-OrgPipelineSettings -OrgUrl $orgUrl -Header $hdr)
        Add-ResultsSafe $orgResults (Test-OrgFeeds -OrgUrl $orgUrl -Header $hdr)
        Add-ResultsSafe $orgResults (Test-OrgPatPolicy -OrgUrl $orgUrl -Header $hdr)
        Add-ResultsSafe $orgResults (Test-UserPats -OrgShortName $orgShort -Header $hdr)
        Add-ResultsSafe $orgResults (Test-OrgWidePats -OrgUrl $orgUrl -Header $hdr)

        $orgReportPath = Join-Path $outPath "$orgSafe-org-assessment.md"
        Write-AssessmentReport -FilePath $orgReportPath -Title "Organization Quick Review: $orgShort" -Scope "Organization: $orgUrl" -Results $orgResults -Quiet

        $pass = @($orgResults | Where-Object Status -eq 'PASS').Count
        $fail = @($orgResults | Where-Object Status -eq 'FAIL').Count
        $nc   = @($orgResults | Where-Object Status -eq 'NOT CHECKED').Count

        [PSCustomObject]@{
            Phase      = 'Organization'
            Project    = $orgShort
            ReportFile = $orgReportPath
            Pass       = $pass
            Fail       = $fail
            NotChecked = $nc
            Results    = $orgResults
        }
    } -ArgumentList $OrgUrl, $header, $OrgShortName, $OutputPath, $orgSafeName, $allFunctionDefs, $scriptConfig, $IncludeGraphCheck.IsPresent

    # --- Phase 2: Project assessments in parallel, with per-project inner parallelism ---
    $parallelResults = $projectNames | ForEach-Object -Parallel {
        $projName = $_
        $orgUrl = $using:OrgUrl
        $hdr = $using:header
        $outPath = $using:OutputPath
        $orgSafe = $using:orgSafeName
        $funcDefs = $using:allFunctionDefs
        $cfg = $using:scriptConfig

        # Restore all assessment functions in this runspace
        . ([scriptblock]::Create($funcDefs))

        # Restore script-scope configuration variables
        $script:CredentialRegex    = $cfg.CredentialRegex
        $script:CredentialPatterns = $cfg.CredentialPatterns
        $script:InactiveDays       = $cfg.InactiveDays
        $script:InactiveRepoDays   = $cfg.InactiveRepoDays
        $script:BroadGroups        = $cfg.BroadGroups
        $script:ProductionKeywords = $cfg.ProductionKeywords
        $script:VsspsUrl           = $cfg.VsspsUrl
        $script:ExtMgmtUrl         = $cfg.ExtMgmtUrl
        $script:AuditUrl           = $cfg.AuditUrl
        $script:FeedsUrl           = $cfg.FeedsUrl

        # Get project ID (needed by Test-Repositories)
        $projInfo = Invoke-AzCli -Command "devops project show --project `"$projName`" --org $orgUrl -o json"
        $projId = if ($projInfo) { $projInfo.id } else { "" }

        # Run all 10 check categories as parallel thread jobs within this project
        $checkJobs = @(
            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-ProjectSettings -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-BuildPipelines -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-ReleasePipelines -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-ServiceConnections -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-AgentPools -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h, $pid2)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-Repositories -OrgUrl $o -ProjectName $p -ProjectId $pid2 -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr, $projId

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-ProjectFeeds -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-SecureFiles -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-Environments -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr

            Start-ThreadJob -ScriptBlock {
                param($fd, $c, $o, $p, $h)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                Test-VariableGroups -OrgUrl $o -ProjectName $p -Header $h
            } -ArgumentList $funcDefs, $cfg, $orgUrl, $projName, $hdr
        )

        # Wait for all check jobs and collect results
        $projResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $checkJobs | Wait-Job | ForEach-Object {
            Add-ResultsSafe $projResults (Receive-Job $_ -ErrorAction SilentlyContinue)
            Remove-Job $_ -Force
        }

        # Write report
        $projSafeName = Get-SafeFileName $projName
        $projReportPath = Join-Path $outPath "$orgSafe-$projSafeName-assessment.md"
        Write-AssessmentReport -FilePath $projReportPath -Title "Project Quick Review: $projName" -Scope "Organization: $orgUrl | Project: $projName" -Results $projResults -Quiet

        $projPass = @($projResults | Where-Object Status -eq 'PASS').Count
        $projFail = @($projResults | Where-Object Status -eq 'FAIL').Count
        $projNC   = @($projResults | Where-Object Status -eq 'NOT CHECKED').Count

        [PSCustomObject]@{
            Phase      = 'Project'
            Project    = $projName
            ReportFile = $projReportPath
            Pass       = $projPass
            Fail       = $projFail
            NotChecked = $projNC
            Results    = $projResults
        }
    } -ThrottleLimit $MaxParallel

    # Wait for org assessment job to finish and collect its result
    $orgResult = $orgJob | Wait-Job | ForEach-Object {
        $r = Receive-Job $_ -ErrorAction SilentlyContinue
        Remove-Job $_ -Force
        $r
    }

    # Print clean summary
    Write-Host ""
    Write-Host "  Review Results" -ForegroundColor Cyan
    Write-Host "  ==================" -ForegroundColor Cyan
    Write-Host ""

    # Org result
    if ($orgResult) {
        $color = if ($orgResult.Fail -gt 0) { 'Red' } else { 'Green' }
        Write-Host ("  {0,-40} {1} PASS | {2} FAIL | {3} NOT CHECKED" -f "Organization: $($orgResult.Project)", $orgResult.Pass, $orgResult.Fail, $orgResult.NotChecked) -ForegroundColor $color
    }
    Write-Host ""

    # Project results
    if ($parallelResults) {
        $parallelResults | Sort-Object Project | ForEach-Object {
            $color = if ($_.Fail -gt 0) { 'Red' } else { 'Green' }
            Write-Host ("  {0,-40} {1} PASS | {2} FAIL | {3} NOT CHECKED" -f $_.Project, $_.Pass, $_.Fail, $_.NotChecked) -ForegroundColor $color
        }
    }
    Write-Host ""

} else {
    # =============================================
    #  SEQUENTIAL MODE (original behavior / PS 5.1)
    # =============================================

    # --- Phase 1: Organization Assessment ---
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Phase 1: Organization Review" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $orgResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    Add-ResultsSafe $orgResults (Test-OrgPolicies -OrgUrl $OrgUrl -Header $header)
    Add-ResultsSafe $orgResults (Test-OrgUsers -OrgUrl $OrgUrl -Header $header -IncludeGraphCheck:$IncludeGraphCheck)
    Add-ResultsSafe $orgResults (Test-OrgAdmins -OrgUrl $OrgUrl -Header $header)
    Add-ResultsSafe $orgResults (Test-OrgExtensions -OrgUrl $OrgUrl -Header $header)
    Add-ResultsSafe $orgResults (Test-OrgAudit -OrgUrl $OrgUrl -Header $header)
    Add-ResultsSafe $orgResults (Test-OrgPipelineSettings -OrgUrl $OrgUrl -Header $header)
    Add-ResultsSafe $orgResults (Test-OrgFeeds -OrgUrl $OrgUrl -Header $header)
    Add-ResultsSafe $orgResults (Test-OrgPatPolicy -OrgUrl $OrgUrl -Header $header)
    Add-ResultsSafe $orgResults (Test-UserPats -OrgShortName $OrgShortName -Header $header)
    Add-ResultsSafe $orgResults (Test-OrgWidePats -OrgUrl $OrgUrl -Header $header)

    $orgReportPath = Join-Path $OutputPath "$orgSafeName-org-assessment.md"
    Write-AssessmentReport -FilePath $orgReportPath -Title "Organization Quick Review: $OrgShortName" -Scope "Organization: $OrgUrl" -Results $orgResults

    $orgPass = @($orgResults | Where-Object Status -eq 'PASS').Count
    $orgFail = @($orgResults | Where-Object Status -eq 'FAIL').Count
    $orgNC   = @($orgResults | Where-Object Status -eq 'NOT CHECKED').Count
    Write-Host "  Org Results: $orgPass PASS | $orgFail FAIL | $orgNC NOT CHECKED" -ForegroundColor $(if ($orgFail -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""

    $orgResult = [PSCustomObject]@{ Pass = $orgPass; Fail = $orgFail; NotChecked = $orgNC; ReportFile = $orgReportPath; Results = $orgResults }

    # --- Phase 2: Project Assessments ---
    $parallelResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($projName in $projectNames) {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  Phase 2: Project — $projName" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan

        $projResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        $projInfo = Invoke-AzCli -Command "devops project show --project `"$projName`" --org $OrgUrl -o json"
        $projId = if ($projInfo) { $projInfo.id } else { "" }

        Add-ResultsSafe $projResults (Test-ProjectSettings -OrgUrl $OrgUrl -ProjectName $projName -Header $header)
        Add-ResultsSafe $projResults (Test-BuildPipelines -OrgUrl $OrgUrl -ProjectName $projName -Header $header)
        Add-ResultsSafe $projResults (Test-ReleasePipelines -OrgUrl $OrgUrl -ProjectName $projName -Header $header)
        Add-ResultsSafe $projResults (Test-ServiceConnections -OrgUrl $OrgUrl -ProjectName $projName -Header $header)
        Add-ResultsSafe $projResults (Test-AgentPools -OrgUrl $OrgUrl -ProjectName $projName -Header $header)
        Add-ResultsSafe $projResults (Test-Repositories -OrgUrl $OrgUrl -ProjectName $projName -ProjectId $projId -Header $header)
        Add-ResultsSafe $projResults (Test-ProjectFeeds -OrgUrl $OrgUrl -ProjectName $projName -Header $header)
        Add-ResultsSafe $projResults (Test-SecureFiles -OrgUrl $OrgUrl -ProjectName $projName -Header $header)
        Add-ResultsSafe $projResults (Test-Environments -OrgUrl $OrgUrl -ProjectName $projName -Header $header)
        Add-ResultsSafe $projResults (Test-VariableGroups -OrgUrl $OrgUrl -ProjectName $projName -Header $header)

        $projSafeName = Get-SafeFileName $projName
        $projReportPath = Join-Path $OutputPath "$orgSafeName-$projSafeName-assessment.md"
        Write-AssessmentReport -FilePath $projReportPath -Title "Project Quick Review: $projName" -Scope "Organization: $OrgUrl | Project: $projName" -Results $projResults

        $projPass = @($projResults | Where-Object Status -eq 'PASS').Count
        $projFail = @($projResults | Where-Object Status -eq 'FAIL').Count
        $projNC   = @($projResults | Where-Object Status -eq 'NOT CHECKED').Count
        Write-Host "  Project Results: $projPass PASS | $projFail FAIL | $projNC NOT CHECKED" -ForegroundColor $(if ($projFail -gt 0) { 'Red' } else { 'Green' })
        Write-Host ""

        $parallelResults.Add([PSCustomObject]@{
            Project    = $projName
            ReportFile = $projReportPath
            Pass       = $projPass
            Fail       = $projFail
            NotChecked = $projNC
            Results    = $projResults
        })
    }
}

# ===== SUMMARY & EXECUTIVE REPORT =====
$stopwatch.Stop()
$elapsed = $stopwatch.Elapsed
$timeStr = if ($elapsed.TotalMinutes -ge 1) {
    '{0:0}m {1:0}s' -f [math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds
} else {
    '{0:0.0}s' -f $elapsed.TotalSeconds
}

# Build org summary object (normalize from both paths)
if (-not $orgResult) {
    $orgResult = [PSCustomObject]@{ Pass = 0; Fail = 0; NotChecked = 0; ReportFile = '' }
}

# Generate executive HTML report
$htmlReportPath = Join-Path $OutputPath "$orgSafeName-executive-summary.html"
$projectSummaryList = @()
if ($parallelResults) { $projectSummaryList = @($parallelResults) }

# Parse all markdown reports to build remediation data
$orgReportFile = if ($orgResult -and $orgResult.ReportFile) { $orgResult.ReportFile } else { '' }
$remediations = Get-FailedControlsFromReports -OrgReportPath $orgReportFile -ProjectSummaries $projectSummaryList

Write-ExecutiveHtmlReport -FilePath $htmlReportPath `
    -OrgName $OrgShortName `
    -OrgUrl $OrgUrl `
    -ElapsedTime $timeStr `
    -OrgSummary $orgResult `
    -ProjectSummaries $projectSummaryList `
    -TopRemediations $remediations

# Generate linked remediation report
$remediationReportPath = Join-Path $OutputPath "$orgSafeName-remediation-plan.html"
Write-RemediationHtmlReport -FilePath $remediationReportPath `
    -OrgName $OrgShortName `
    -ExecReportFile $htmlReportPath `
    -Remediations $remediations

# Optional JSON output (opt-in via -OutputFormat json|all). MD + HTML remain
# canonical adoqr outputs; JSON is purely additive for downstream tooling.
$resolvedFormats = if ('all' -in $OutputFormat) { @('markdown', 'html', 'json') } else { $OutputFormat }
$writeJson = $resolvedFormats -contains 'json'
$jsonReportPath = $null
if ($writeJson) {
    $jsonReportPath = Join-Path $OutputPath "$orgSafeName-scan.json"
    $orgResultsList = @()
    if ($orgResult -and $orgResult.PSObject.Properties['Results'] -and $orgResult.Results) {
        $orgResultsList = @($orgResult.Results)
    }
    $projectResultsForJson = @()
    if ($parallelResults) {
        foreach ($pr in $parallelResults) {
            if ($pr.PSObject.Properties['Results']) {
                $projectResultsForJson += [PSCustomObject]@{
                    Project = $pr.Project
                    Results = $pr.Results
                }
            }
        }
    }
    Export-AssessmentToJson `
        -FilePath $jsonReportPath `
        -OrgName $OrgShortName `
        -OrgUrl $OrgUrl `
        -OrgResults $orgResultsList `
        -ProjectResults $projectResultsForJson `
        -ElapsedSeconds $elapsed.TotalSeconds
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Review Complete" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Reports saved to : $(Resolve-Path $OutputPath)" -ForegroundColor Green
Write-Host "Executive report : $htmlReportPath" -ForegroundColor Green
Write-Host "Remediation plan : $remediationReportPath" -ForegroundColor Green
if ($writeJson -and $jsonReportPath) {
    Write-Host "JSON scan        : $jsonReportPath" -ForegroundColor Green
}
Write-Host "Elapsed time     : $timeStr" -ForegroundColor Green
Write-Host ""

Write-Progress -Activity "Assessment" -Completed

# Auto-open the executive report in the default browser
Start-Process $htmlReportPath

#endregion
