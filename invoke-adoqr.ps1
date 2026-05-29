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
    Maximum concurrency for project assessment. Default 3.
    Requires PowerShell 7+ for parallel execution. Values 2-4 recommended to avoid ADO rate limiting.
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
    [int]$MaxParallel = 3,

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
# Additional groups treated as "broad" for ACL-based checks (PERM-*) but
# excluded from the feed-permission BroadGroups list because they routinely
# need feed Reader access.
$script:BroadAclExtras = @(
    'Build Service',
    'Project Collection Build Service',
    'Project Collection Service Accounts'
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
    $cacheKey = $null
    if ($Method -ieq 'GET' -and -not $Body) {
        if (-not $script:AdoApiCache) { $script:AdoApiCache = @{} }
        $cacheKey = $Uri
        if ($script:AdoApiCache.ContainsKey($cacheKey)) { return $script:AdoApiCache[$cacheKey] }
    }

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

                    if ($remaining -and $limit -and [double]$limit -gt 0 -and [double]$remaining -ge 0) {
                        # NOTE: ADO only emits these headers when usage exceeds ~80% of the
                        # budget, so their mere presence isn't a problem — only act when
                        # remaining is genuinely low. Tiered pauses align with ADO's ~5s
                        # TSTU replenishment window.
                        $pctRemaining = [double]$remaining / [math]::Max(1, [double]$limit)
                        $pauseSec = 0
                        if     ($pctRemaining -le 0.05) { $pauseSec = 5 }
                        elseif ($pctRemaining -le 0.15) { $pauseSec = 2 }
                        if ($pauseSec -gt 0) {
                            Write-Warning ("Rate limit pressure: {0}/{1} TSTUs remaining ({2:P0}). Pausing {3}s..." -f $remaining, $limit, $pctRemaining, $pauseSec)
                            Start-Sleep -Seconds $pauseSec
                        }
                    }
                }
            }

            if ($cacheKey) { $script:AdoApiCache[$cacheKey] = $response }
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
                if ($cacheKey) { $script:AdoApiCache[$cacheKey] = $null }
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
    if (-not $script:AzCliCache) { $script:AzCliCache = @{} }
    if ($script:AzCliCache.ContainsKey($Command)) { return $script:AzCliCache[$Command] }

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
            $result = $json | ConvertFrom-Json
            $script:AzCliCache[$Command] = $result
            return $result
        }
        $script:AzCliCache[$Command] = $null
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

function Convert-ToBooleanOrNull {
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }

    if ($Value -is [string]) {
        $normalized = $Value.Trim().ToLowerInvariant()
        if ($normalized -in @('true', '1', 'yes', 'on', 'enabled')) { return $true }
        if ($normalized -in @('false', '0', 'no', 'off', 'disabled')) { return $false }
        return $null
    }

    if ($Value -is [int] -or $Value -is [long] -or $Value -is [byte]) {
        return ([int64]$Value) -ne 0
    }

    return $null
}

function Get-OrgPolicyBoolean {
    param($Policy)

    if ($null -eq $Policy) { return $null }

    # Azure DevOps org policy payloads expose the UI toggle state in `value`.
    $raw = Get-SafeProperty $Policy 'value'
    if ($null -eq $raw) { $raw = Get-SafeProperty $Policy 'Value' }
    if ($null -eq $raw) { $raw = Get-SafeProperty $Policy 'effectiveValue' }
    if ($null -eq $raw) { $raw = Get-SafeProperty $Policy 'EffectiveValue' }

    return (Convert-ToBooleanOrNull -Value $raw)
}

function Get-EffectiveJobAuthorizationScope {
    param(
        [AllowNull()][string]$DefinitionScope,
        [bool]$IsRelease,
        $ProjectPipelineSettings,
        $OrgPipelineSettings
    )

    $settingProp = if ($IsRelease) { 'enforceJobAuthScopeForReleases' } else { 'enforceJobAuthScope' }

    if ((Get-SafeProperty $ProjectPipelineSettings $settingProp) -eq $true) {
        return [PSCustomObject]@{ Scope = 'projectScoped'; Source = 'project-setting'; Setting = $settingProp }
    }

    if ((Get-SafeProperty $OrgPipelineSettings $settingProp) -eq $true) {
        return [PSCustomObject]@{ Scope = 'projectScoped'; Source = 'org-setting'; Setting = $settingProp }
    }

    if ($DefinitionScope) {
        $normalized = $DefinitionScope.Trim()
        if ($normalized) {
            return [PSCustomObject]@{ Scope = $normalized; Source = 'pipeline-setting'; Setting = $null }
        }
    }

    if ($ProjectPipelineSettings -or $OrgPipelineSettings) {
        return [PSCustomObject]@{ Scope = 'projectCollection'; Source = 'default'; Setting = $settingProp }
    }

    return [PSCustomObject]@{ Scope = $null; Source = 'unknown'; Setting = $settingProp }
}

function Get-AdoSecurityNamespaces {
    <#
    .SYNOPSIS
        Returns all ADO security namespaces, cached per scan.
    .DESCRIPTION
        Each namespace describes a resource type's permission bit layout
        (actions[].bit, actions[].name, actions[].displayName). The response
        is several KB and identical for the lifetime of a scan, so we cache
        it in $script:SecurityNamespaceCache.
    #>
    param(
        [Parameter(Mandatory)][string]$OrgUrl,
        [Parameter(Mandatory)][hashtable]$Header
    )
    if (-not $script:SecurityNamespaceCache) {
        $resp = Invoke-AdoApi -Uri "$OrgUrl/_apis/securitynamespaces?api-version=7.1" -Header $Header
        if ($resp -and $resp.value) {
            $script:SecurityNamespaceCache = @($resp.value)
        } else {
            $script:SecurityNamespaceCache = @()
        }
    }
    return $script:SecurityNamespaceCache
}

function Get-AdoNamespaceByName {
    <#
    .SYNOPSIS
        Returns a single namespace by its 'name' field (e.g. 'Build',
        'ReleaseManagement', 'Git Repositories', 'Library', 'ServiceEndpoints',
        'Environment'). Returns the most-recently-defined match when multiple
        namespaces share a name (e.g. ReleaseManagement legacy + current).
    #>
    param(
        [Parameter(Mandatory)][string]$OrgUrl,
        [Parameter(Mandatory)][hashtable]$Header,
        [Parameter(Mandatory)][string]$Name
    )
    $namespaces = Get-AdoSecurityNamespaces -OrgUrl $OrgUrl -Header $Header
    $matched = @()
    foreach ($ns in $namespaces) {
        $nsName = Get-SafeProperty $ns 'name'
        if ($nsName -ieq $Name) { $matched += $ns }
    }
    if ($matched.Count -eq 0) { return $null }
    if ($matched.Count -eq 1) { return $matched[0] }
    # When multiple namespaces share a name (e.g. legacy + current
    # ReleaseManagement), prefer the one with the richest actions[] schema.
    # The canonical namespace tends to expose more action bits than its
    # deprecated counterpart, and ACLs are populated against the canonical
    # one.
    $best = $null
    $bestCount = -1
    foreach ($m in $matched) {
        $acts = Get-SafeProperty $m 'actions'
        $count = if ($acts) { @($acts).Count } else { 0 }
        if ($count -gt $bestCount) {
            $best = $m
            $bestCount = $count
        }
    }
    if ($best) { return $best }
    return $matched[-1]
}

function Get-AdoAccessControlList {
    <#
    .SYNOPSIS
        Returns the ACL entries for a security namespace + token.
    .DESCRIPTION
        Calls /_apis/accesscontrollists/{nsId}?token={token}&includeExtendedInfo=true.
        Response includes acesDictionary keyed by identity descriptor, with
        allow/deny bitmasks and extendedInfo.effectiveAllow/effectiveDeny
        for inheritance-aware values.
    #>
    param(
        [Parameter(Mandatory)][string]$OrgUrl,
        [Parameter(Mandatory)][hashtable]$Header,
        [Parameter(Mandatory)][string]$NamespaceId,
        [Parameter(Mandatory)][string]$Token,
        [switch]$Recurse
    )
    $encToken = [uri]::EscapeDataString($Token)
    $recurseStr = if ($Recurse) { 'true' } else { 'false' }
    $uri = "$OrgUrl/_apis/accesscontrollists/$NamespaceId" + "?token=$encToken&includeExtendedInfo=true&recurse=$recurseStr&api-version=7.1"
    return Invoke-AdoApi -Uri $uri -Header $Header
}

function Get-AdoIdentitiesByDescriptors {
    <#
    .SYNOPSIS
        Bulk-resolves identity descriptors to displayName via the vssps
        identities endpoint. Caches per-descriptor in
        $script:IdentityDescriptorCache (including negative lookups).
    #>
    param(
        [Parameter(Mandatory)][string]$OrgUrl,
        [Parameter(Mandatory)][hashtable]$Header,
        [Parameter(Mandatory)][string[]]$Descriptors
    )
    if (-not $script:IdentityDescriptorCache) { $script:IdentityDescriptorCache = @{} }

    $unresolved = @(
        $Descriptors |
            Where-Object { $_ -and -not $script:IdentityDescriptorCache.ContainsKey($_) } |
            Select-Object -Unique
    )
    if ($unresolved.Count -gt 0) {
        $vsspsBase = if ($script:VsspsUrl) { $script:VsspsUrl } else { $OrgUrl -replace '://dev\.azure\.com/', '://vssps.dev.azure.com/' }
        for ($i = 0; $i -lt $unresolved.Count; $i += 100) {
            $end = [Math]::Min($i + 99, $unresolved.Count - 1)
            $batch = $unresolved[$i..$end]
            $descList = ($batch | ForEach-Object { [uri]::EscapeDataString($_) }) -join ','
            $resp = Invoke-AdoApi -Uri "$vsspsBase/_apis/identities?descriptors=$descList&api-version=7.1" -Header $Header
            $found = @{}
            if ($resp -and $resp.value) {
                foreach ($id in $resp.value) {
                    $desc = Get-SafeProperty $id 'descriptor'
                    if ($desc) {
                        $script:IdentityDescriptorCache[$desc] = $id
                        $found[$desc] = $true
                    }
                }
            }
            foreach ($d in $batch) {
                if (-not $found.ContainsKey($d)) {
                    $script:IdentityDescriptorCache[$d] = $null
                }
            }
        }
    }

    $result = @{}
    foreach ($d in $Descriptors) {
        if ($d) { $result[$d] = $script:IdentityDescriptorCache[$d] }
    }
    return $result
}

function Get-AceElevatedActions {
    <#
    .SYNOPSIS
        Decodes an ACE allow bitmask against a namespace's actions[] table
        and returns the elevated action displayNames granted.
    .DESCRIPTION
        Excludes pure read/view bits ('View*', 'Read*', 'Generic*Read') —
        we only flag bits that would let a broader group mutate, queue,
        use, or administer the resource.
    #>
    param(
        $Namespace,
        [int]$AllowMask,
        [string[]]$RequiredActionNames
    )
    $elevated = [System.Collections.Generic.List[string]]::new()
    if (-not $Namespace -or $AllowMask -le 0) { return $elevated }
    $actions = Get-SafeProperty $Namespace 'actions'
    if (-not $actions) { return $elevated }
    foreach ($act in $actions) {
        $bit = Get-SafeProperty $act 'bit'
        $name = Get-SafeProperty $act 'name'
        $display = Get-SafeProperty $act 'displayName'
        if (-not $display) { $display = $name }
        if ($null -eq $bit -or -not $name) { continue }
        if ($RequiredActionNames -and $RequiredActionNames.Count -gt 0) {
            if ($RequiredActionNames -notcontains $name) { continue }
        } else {
            # Default: exclude pure read/view bits.
            if ($name -imatch '^(View|Read|GenericRead)') { continue }
        }
        if (($AllowMask -band [int]$bit) -ne 0) {
            $elevated.Add($display)
        }
    }
    return $elevated
}

function Test-IsBroadGroupForAcl {
    <#
    .SYNOPSIS
        Like Test-IsBroadGroup, but also matches build/service-account
        identity names that show up in ACL ACEs but are intentionally
        excluded from the feed-permission BroadGroups list.
    #>
    param([string]$GroupName)
    if (-not $GroupName) { return $false }
    if (Test-IsBroadGroup $GroupName) { return $true }
    foreach ($g in $script:BroadAclExtras) {
        if ($GroupName -ilike "*$g*") { return $true }
    }
    return $false
}

function Find-BroadGroupAclOffenders {
    <#
    .SYNOPSIS
        For a (namespaceName, token) tuple, returns the list of broader-group
        ACEs that hold elevated allow bits at that scope.
    .OUTPUTS
        $null  -> namespace or ACL could not be retrieved (caller emits NOT CHECKED)
        @()    -> no offenders (caller emits PASS)
        array  -> "DisplayName: action1, action2" strings (caller emits FAIL)
    #>
    param(
        [Parameter(Mandatory)][string]$OrgUrl,
        [Parameter(Mandatory)][hashtable]$Header,
        [Parameter(Mandatory)][string]$NamespaceName,
        [Parameter(Mandatory)][string]$Token,
        [string[]]$RequiredActionNames
    )

    $ns = Get-AdoNamespaceByName -OrgUrl $OrgUrl -Header $Header -Name $NamespaceName
    if (-not $ns) { return $null }
    $nsId = Get-SafeProperty $ns 'namespaceId'
    if (-not $nsId) { return $null }

    $aclResp = Get-AdoAccessControlList -OrgUrl $OrgUrl -Header $Header -NamespaceId $nsId -Token $Token
    if (-not $aclResp) { return $null }
    if (-not $aclResp.value -or @($aclResp.value).Count -eq 0) { return ,@() }

    $allDescriptors = [System.Collections.Generic.List[string]]::new()
    foreach ($acl in $aclResp.value) {
        $aces = Get-SafeProperty $acl 'acesDictionary'
        if ($aces) {
            foreach ($prop in $aces.PSObject.Properties) { [void]$allDescriptors.Add($prop.Name) }
        }
    }
    if ($allDescriptors.Count -eq 0) { return ,@() }

    $identityMap = Get-AdoIdentitiesByDescriptors -OrgUrl $OrgUrl -Header $Header -Descriptors $allDescriptors.ToArray()

    $offenders = [System.Collections.Generic.List[string]]::new()
    foreach ($acl in $aclResp.value) {
        $aces = Get-SafeProperty $acl 'acesDictionary'
        if (-not $aces) { continue }
        foreach ($prop in $aces.PSObject.Properties) {
            $desc = $prop.Name
            $ace = $prop.Value
            $identity = $identityMap[$desc]
            if (-not $identity) { continue }
            $displayName = Get-SafeProperty $identity 'providerDisplayName'
            if (-not $displayName) { $displayName = Get-SafeProperty $identity 'displayName' }
            if (-not $displayName) { continue }
            if (-not (Test-IsBroadGroupForAcl $displayName)) { continue }
            $effAllow = 0
            $extInfo = Get-SafeProperty $ace 'extendedInfo'
            if ($extInfo) {
                $ea = Get-SafeProperty $extInfo 'effectiveAllow'
                if ($null -ne $ea) { $effAllow = [int]$ea }
            }
            if ($effAllow -eq 0) {
                $a = Get-SafeProperty $ace 'allow'
                if ($null -ne $a) { $effAllow = [int]$a }
            }
            if ($effAllow -eq 0) { continue }
            $elevated = Get-AceElevatedActions -Namespace $ns -AllowMask $effAllow -RequiredActionNames $RequiredActionNames
            if ($elevated.Count -gt 0) {
                $offenders.Add(("{0}: {1}" -f $displayName, ($elevated -join ', ')))
            }
        }
    }
    return ,$offenders.ToArray()
}

function Test-IsGuestMember {
    param($Member)
    $mail = Get-SafeProperty $Member 'mailAddress'
    if (-not $mail) { $mail = Get-SafeProperty $Member 'principalName' }
    $alias = Get-SafeProperty $Member 'directoryAlias'
    $displayName = Get-SafeProperty $Member 'displayName'
    if ($mail -and $mail -imatch '#EXT#') { return $true }
    if ($alias -and $alias -imatch '#EXT#') { return $true }
    if ($displayName -and $displayName -imatch '#EXT#') { return $true }
    return $false
}

function Get-AdoGraphSubjectDescriptor {
    param([string]$OrgUrl, [hashtable]$Header, [string]$StorageKey)
    if (-not $StorageKey) { return $null }

    $descriptor = Invoke-AdoApi -Uri "$($script:VsspsUrl)/_apis/graph/descriptors/$StorageKey`?api-version=7.1-preview.1" -Header $Header
    if ($descriptor) { return Get-SafeProperty $descriptor 'value' }
    return $null
}

function Get-AdoGraphProjectGroups {
    param([string]$OrgUrl, [string]$ProjectId, [hashtable]$Header)

    $scopeDescriptor = Get-AdoGraphSubjectDescriptor -OrgUrl $OrgUrl -Header $Header -StorageKey $ProjectId
    if (-not $scopeDescriptor) { return @() }

    $groups = Invoke-AdoApi -Uri "$($script:VsspsUrl)/_apis/graph/groups?scopeDescriptor=$([System.Uri]::EscapeDataString($scopeDescriptor))&api-version=7.1-preview.1" -Header $Header
    if ($groups -and $groups.value) { return @($groups.value) }
    return @()
}

function Get-AdoGraphSubjectsByDescriptor {
    param([string]$OrgUrl, [hashtable]$Header, [string[]]$Descriptors)

    $uniqueDescriptors = @($Descriptors | Where-Object { $_ } | Select-Object -Unique)
    if ($uniqueDescriptors.Count -eq 0) { return @{} }

    $body = @{
        lookupKeys = @($uniqueDescriptors | ForEach-Object { @{ descriptor = $_ } })
    } | ConvertTo-Json -Depth 5

    $lookup = Invoke-AdoApi -Uri "$($script:VsspsUrl)/_apis/graph/subjectlookup?api-version=7.1-preview.1" -Header $Header -Method 'POST' -Body $body
    $subjectMap = @{}
    if ($lookup -and $lookup.value) {
        foreach ($subject in @($lookup.value)) {
            $descriptor = Get-SafeProperty $subject 'descriptor'
            if ($descriptor) { $subjectMap[$descriptor] = $subject }
        }
    }
    return $subjectMap
}

function Get-AdoGraphGroupMembers {
    param([string]$OrgUrl, [hashtable]$Header, [string]$GroupDescriptor)
    if (-not $GroupDescriptor) { return @() }

    $encodedDescriptor = [System.Uri]::EscapeDataString($GroupDescriptor)
    $memberships = Invoke-AdoApi -Uri "$($script:VsspsUrl)/_apis/graph/memberships/$encodedDescriptor`?direction=down&depth=1&api-version=7.1-preview.1" -Header $Header
    if (-not $memberships -or -not $memberships.value) { return @() }

    $memberDescriptors = @($memberships.value | ForEach-Object { Get-SafeProperty $_ 'memberDescriptor' } | Where-Object { $_ })
    $subjectMap = Get-AdoGraphSubjectsByDescriptor -OrgUrl $OrgUrl -Header $Header -Descriptors $memberDescriptors

    $members = foreach ($descriptor in $memberDescriptors) {
        if ($subjectMap.ContainsKey($descriptor)) { $subjectMap[$descriptor] }
        else { [PSCustomObject]@{ descriptor = $descriptor; displayName = $descriptor } }
    }
    return @($members)
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

function Import-ScanRunFromMarkdownReports {
    <#
    .SYNOPSIS
        Reconstructs lightweight comparison data from generated Markdown reports.
    .DESCRIPTION
        Used as a compatibility fallback for runs created before JSON output was
        enabled. The parser reads the stable Control Results table emitted by
        Write-AssessmentReport and returns the same lightweight shape consumed
        by Build-ComparisonSectionHtml.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$OrgSafeName
    )

    if (-not (Test-Path $RunDirectory -PathType Container -ErrorAction SilentlyContinue)) {
        return $null
    }

    $reportFiles = @(Get-ChildItem -Path $RunDirectory -Filter "$OrgSafeName-*-assessment.md" -File -ErrorAction SilentlyContinue)
    if ($reportFiles.Count -eq 0) { return $null }

    $controls = [System.Collections.Generic.List[PSCustomObject]]::new()
    $dates = [System.Collections.Generic.List[datetime]]::new()
    $orgName = $OrgSafeName

    foreach ($file in $reportFiles) {
        $raw = Get-Content -Raw $file.FullName -ErrorAction SilentlyContinue
        if (-not $raw) { continue }

        $scopeType = 'organization'
        $projectName = $null
        if ($raw -match '(?m)^#\s+Organization Quick Review:\s*(.+?)\s*$') {
            $orgName = $Matches[1].Trim()
        }
        elseif ($raw -match '(?m)^#\s+Project Quick Review:\s*(.+?)\s*$') {
            $scopeType = 'project'
            $projectName = $Matches[1].Trim()
        }

        if ($raw -match '\|\s*\*\*Assessment Date\*\*\s*\|\s*([^|]+?)\s*\|') {
            $parsedDate = [datetime]::MinValue
            if ([datetime]::TryParse($Matches[1].Trim(), [ref]$parsedDate)) {
                $dates.Add($parsedDate)
            }
        }

        foreach ($line in ($raw -split "`r?`n")) {
            $match = [regex]::Match(
                $line,
                '^\|\s*[^|]*\|\s*(?<status>PASS|FAIL|NOT CHECKED)\s*\|\s*[^|]*?(?<severity>High|Medium|Low)\s*\|\s*(?<id>[^:|]+):\s*(?<control>[^|]+?)\s*\|'
            )
            if (-not $match.Success) { continue }

            $controls.Add([PSCustomObject]@{
                id       = $match.Groups['id'].Value.Trim()
                status   = $match.Groups['status'].Value.Trim().ToUpperInvariant()
                severity = $match.Groups['severity'].Value.Trim()
                control  = $match.Groups['control'].Value.Trim()
                scope    = [PSCustomObject]@{
                    type         = $scopeType
                    organization = $orgName
                    project      = $projectName
                }
            })
        }
    }

    if ($controls.Count -eq 0) { return $null }

    $generatedAt = if ($dates.Count -gt 0) {
        ($dates | Sort-Object -Descending | Select-Object -First 1).ToString('o')
    } else {
        (Get-Item $RunDirectory).LastWriteTime.ToString('o')
    }

    [PSCustomObject]@{
        meta         = [PSCustomObject]@{ generatedAt = $generatedAt }
        organization = [PSCustomObject]@{ name = $orgName; url = $null }
        summary      = [PSCustomObject]@{
            pass       = @($controls | Where-Object status -eq 'PASS').Count
            fail       = @($controls | Where-Object status -eq 'FAIL').Count
            notChecked = @($controls | Where-Object status -eq 'NOT CHECKED').Count
        }
        controls     = $controls
    }
}

function Get-PriorScanRuns {
    <#
    .SYNOPSIS
        Discovers prior adoqr scan JSON files from the assessments root directory.
    .DESCRIPTION
        Searches sibling run folders under AssessmentsRoot for files matching
        <OrgSafeName>-scan.json and returns them sorted newest-first.
        Only files that conform to scan.schema.json (schemaVersion 1.0) are returned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AssessmentsRoot,
        [Parameter(Mandatory)][string]$OrgSafeName,
        [string]$ExcludeRunId = ''
    )

    $runs = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not (Test-Path $AssessmentsRoot -ErrorAction SilentlyContinue)) {
        return
    }

    $seenRunIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $scanFiles = Get-ChildItem -Path $AssessmentsRoot -Filter "$OrgSafeName-scan.json" -Recurse -Depth 2 -ErrorAction SilentlyContinue

    foreach ($f in $scanFiles) {
        if ($ExcludeRunId -and $f.Directory.Name -eq $ExcludeRunId) { continue }
        try {
            $raw = Get-Content -Raw $f.FullName -ErrorAction SilentlyContinue
            if (-not $raw) { continue }
            $doc = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if (-not $doc -or -not $doc.meta -or -not $doc.meta.generatedAt) { continue }
            $ts = [datetime]::MinValue
            if (-not [datetime]::TryParse($doc.meta.generatedAt, [ref]$ts)) { continue }
            $runs.Add([PSCustomObject]@{
                RunId       = $f.Directory.Name
                GeneratedAt = $ts
                FilePath    = $f.FullName
                Doc         = $doc
            })
            [void]$seenRunIds.Add($f.Directory.Name)
        }
        catch { <# Skip files that cannot be read or parsed #> }
    }

    $runDirs = @(Get-ChildItem -Path $AssessmentsRoot -Directory -Filter "$OrgSafeName-*" -ErrorAction SilentlyContinue)
    foreach ($dir in $runDirs) {
        if ($ExcludeRunId -and $dir.Name -eq $ExcludeRunId) { continue }
        if ($seenRunIds.Contains($dir.Name)) { continue }

        try {
            $doc = Import-ScanRunFromMarkdownReports -RunDirectory $dir.FullName -OrgSafeName $OrgSafeName
            if (-not $doc -or -not $doc.meta -or -not $doc.meta.generatedAt) { continue }
            $ts = [datetime]::MinValue
            if (-not [datetime]::TryParse($doc.meta.generatedAt, [ref]$ts)) { continue }
            $runs.Add([PSCustomObject]@{
                RunId       = $dir.Name
                GeneratedAt = $ts
                FilePath    = $dir.FullName
                Doc         = $doc
            })
        }
        catch { <# Skip folders whose Markdown cannot be parsed #> }
    }

    $runs | Sort-Object GeneratedAt -Descending
}

function Build-ComparisonSectionHtml {
    <#
    .SYNOPSIS
        Builds the Run Comparison HTML section embedded in the executive summary.
    .DESCRIPTION
        Embeds all scan run data as JSON and generates self-contained JavaScript
        that computes improved / regressed / persistent-fail / new / removed
        controls between any two selected runs.  Requires 2+ runs to activate;
        renders a "no data" placeholder otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][PSCustomObject[]]$RunsData
    )

    if (-not $RunsData -or $RunsData.Count -eq 0) {
        $RunsData = @()
    }

    # Build a lightweight payload — strip verbose finding text to keep HTML size small.
    $lightweight = @($RunsData | ForEach-Object {
        [PSCustomObject]@{
            runId       = $_.runId
            generatedAt = $_.generatedAt
            summary     = $_.summary
            controls    = @($_.controls | ForEach-Object {
                [PSCustomObject]@{
                    id       = $_.id
                    status   = $_.status
                    severity = $_.severity
                    control  = $_.control
                    scope    = $_.scope
                }
            })
        }
    })

    $runsJson = $lightweight | ConvertTo-Json -Depth 10 -Compress
    if (-not $runsJson) { $runsJson = '[]' }
    # Wrap scalar (single object) in an array
    if ($runsJson -and $runsJson.TrimStart()[0] -ne '[') { $runsJson = "[$runsJson]" }
    # Prevent premature script-tag closure inside JSON string values
    $runsJson = $runsJson -replace '</script>', '<\/script>'

    # JavaScript — written as a literal here-string so PowerShell does not expand $ signs.
    $jsCode = @'
(function () {
  var runs = window.__adoqrRuns || [];
  var elNoData  = document.getElementById('cmp-nodata');
  var elUi      = document.getElementById('cmp-ui');
  var elResult  = document.getElementById('cmp-result');
  var selA      = document.getElementById('cmp-run-a');
  var selB      = document.getElementById('cmp-run-b');
  if (!elNoData || !elUi || !elResult || !selA || !selB) return;
  if (runs.length < 2) return;
  elNoData.style.display = 'none';
  elUi.style.display = 'block';

  runs.forEach(function (r, i) {
    var ts  = r.generatedAt ? r.generatedAt.substring(0, 19).replace('T', ' ') + ' UTC' : r.runId;
    var lbl = ts + '  \u2014  ' + r.runId;
    selA.add(new Option(lbl, String(i)));
    selB.add(new Option(lbl, String(i)));
  });
  selA.value = '0';
  selB.value = '1';

  function sevOrd(s) { return s === 'High' ? 0 : s === 'Medium' ? 1 : 2; }
  function sevClr(s) { return s === 'High' ? 'var(--fail)' : s === 'Medium' ? 'var(--warn)' : 'var(--info)'; }
  function sevBg(s)  { return s === 'High' ? 'rgba(239,68,68,.12)' : s === 'Medium' ? 'rgba(245,158,11,.12)' : 'rgba(59,130,246,.12)'; }
  function esc(v)    { return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function ctrlKey(c) {
    var sc = c.scope ? (c.scope.type + '|' + (c.scope.project || '')) : '';
    return c.id + '|' + sc;
  }
  function scopeLbl(c) { return c.scope && c.scope.type === 'project' ? esc(c.scope.project || '') : 'Org'; }

  function renderRow(c, statusHtml) {
    return '<tr>'
      + '<td><strong>' + esc(c.id) + '</strong><br><span style="color:var(--text2);font-size:.85rem">' + esc(c.control || '') + '</span></td>'
      + '<td><span style="display:inline-block;padding:.15rem .5rem;border-radius:999px;font-size:.75rem;font-weight:700;text-transform:uppercase;background:' + sevBg(c.severity) + ';color:' + sevClr(c.severity) + '">' + esc(c.severity) + '</span></td>'
      + '<td>' + scopeLbl(c) + '</td>'
      + '<td>' + statusHtml + '</td>'
      + '</tr>';
  }

    function renderGroup(title, rows, emptyMsg, borderClr, openByDefault) {
        var openAttr = openByDefault ? ' open' : '';
        var h = '<details class="cmp-group"' + openAttr + ' style="border-left-color:' + borderClr + '">'
                    + '<summary class="cmp-group-hdr">'
                    + '<span class="cmp-cnt">' + rows.length + '</span>'
                    + '<span>' + title + '</span>'
                    + '<span class="cmp-disclosure">Details</span>'
                    + '</summary>';
    if (rows.length === 0) {
            h += '<p class="cmp-empty">' + emptyMsg + '</p>';
    } else {
      h += '<div class="tbl-wrap"><table><thead><tr><th>Control</th><th>Severity</th><th>Scope</th><th>Change</th></tr></thead>'
         + '<tbody>' + rows.join('') + '</tbody></table></div>';
    }
        return h + '</details>';
    }

    function trendLabel(dPct, dFail, regressed, improved) {
        if (regressed > 0 || dPct < 0 || dFail > 0) return { text: 'Needs attention', cls: 'cmp-verdict-risk' };
        if (improved > 0 || dPct > 0 || dFail < 0) return { text: 'Improving', cls: 'cmp-verdict-good' };
        return { text: 'Stable', cls: 'cmp-verdict-stable' };
    }

    function renderExecutiveSummary(a, b, aPct, bPct, dPct, dFail, improved, regressed, persist) {
        var trend = trendLabel(dPct, dFail, regressed.length, improved.length);
        var direction = dPct > 0 ? 'up' : dPct < 0 ? 'down' : 'unchanged';
        var failDirection = dFail < 0 ? 'down' : dFail > 0 ? 'up' : 'unchanged';
        var primary = '';
        if (regressed.length > 0) {
            primary = regressed.length + ' control' + (regressed.length === 1 ? ' has' : 's have') + ' regressed since the baseline.';
        } else if (improved.length > 0) {
            primary = improved.length + ' control' + (improved.length === 1 ? ' is' : 's are') + ' now passing with no new regressions.';
        } else if (persist.length > 0) {
            primary = 'No new regressions, but ' + persist.length + ' control' + (persist.length === 1 ? ' remains' : 's remain') + ' failing.';
        } else {
            primary = 'No material control movement detected between the selected runs.';
        }

        return '<div class="cmp-executive-summary">'
            + '<div class="cmp-verdict ' + trend.cls + '">' + esc(trend.text) + '</div>'
            + '<div class="cmp-summary-copy">'
            +   '<strong>' + esc(primary) + '</strong>'
            +   '<span>Pass rate is ' + direction + ' from ' + bPct + '% to ' + aPct + '%, and failures are ' + failDirection + ' by ' + Math.abs(dFail) + '.</span>'
            + '</div>'
            + '<div class="cmp-summary-meta">Comparing <strong>' + esc(a.runId) + '</strong> against <strong>' + esc(b.runId) + '</strong>.</div>'
            + '</div>';
  }

  function run() {
    var ai = parseInt(selA.value, 10);
    var bi = parseInt(selB.value, 10);
    if (ai === bi) {
      elResult.innerHTML = '<p style="color:var(--text2);margin:.5rem 0">Please select two different runs to compare.</p>';
      return;
    }
    var a = runs[ai];
    var b = runs[bi];
    var aMap = {}, bMap = {};
    (a.controls || []).forEach(function (c) { aMap[ctrlKey(c)] = c; });
    (b.controls || []).forEach(function (c) { bMap[ctrlKey(c)] = c; });

    var improved = [], regressed = [], persist = [], added = [], removed = [];
    Object.keys(aMap).forEach(function (k) {
      var ac = aMap[k], bc = bMap[k];
      if (!bc)                                        { added.push(ac); return; }
      if (bc.status !== 'PASS' && ac.status === 'PASS')  { improved.push({ a: ac, b: bc }); }
      else if (bc.status === 'PASS' && ac.status === 'FAIL') { regressed.push({ a: ac, b: bc }); }
      else if (ac.status === 'FAIL' && bc.status === 'FAIL') { persist.push({ a: ac, b: bc }); }
    });
    Object.keys(bMap).forEach(function (k) { if (!aMap[k]) removed.push(bMap[k]); });

    function srt(arr, fn) { arr.sort(function (x, y) { return sevOrd(fn(x).severity) - sevOrd(fn(y).severity); }); }
    srt(improved, function (x) { return x.a; });
    srt(regressed, function (x) { return x.a; });
    srt(persist,   function (x) { return x.a; });
    added.sort(function (x, y)   { return sevOrd(x.severity) - sevOrd(y.severity); });
    removed.sort(function (x, y) { return sevOrd(x.severity) - sevOrd(y.severity); });

    var aSum = a.summary || {}, bSum = b.summary || {};
    var aT = (aSum.pass || 0) + (aSum.fail || 0) + (aSum.notChecked || 0);
    var bT = (bSum.pass || 0) + (bSum.fail || 0) + (bSum.notChecked || 0);
    var aPct = aT > 0 ? Math.round((aSum.pass || 0) * 100 / aT) : 0;
    var bPct = bT > 0 ? Math.round((bSum.pass || 0) * 100 / bT) : 0;
    var dPct  = aPct - bPct;
    var dFail = (aSum.fail || 0) - (bSum.fail || 0);
    var pArrow = dPct  > 0 ? '\u25B2' : dPct  < 0 ? '\u25BC' : '\u25AC';
    var pClr   = dPct  > 0 ? 'var(--pass)' : dPct  < 0 ? 'var(--fail)' : 'var(--text2)';
    var fArrow = dFail < 0 ? '\u25B2' : dFail > 0 ? '\u25BC' : '\u25AC';
    var fClr   = dFail < 0 ? 'var(--pass)' : dFail > 0 ? 'var(--fail)' : 'var(--text2)';

        var html = renderExecutiveSummary(a, b, aPct, bPct, dPct, dFail, improved, regressed, persist);

        html += '<div class="cards cmp-delta-cards">'
      + '<div class="card"><div class="card-value" style="color:' + pClr + '">' + pArrow + ' ' + Math.abs(dPct) + '%</div>'
      +   '<div class="card-label">Pass Rate Change</div>'
      +   '<div style="font-size:.8rem;color:var(--text2);margin-top:.25rem">' + bPct + '% \u2192 ' + aPct + '%</div></div>'
      + '<div class="card"><div class="card-value"><span style="color:' + fClr + '">' + fArrow + '</span> ' + Math.abs(dFail) + '</div>'
      +   '<div class="card-label">Failure Count Change</div>'
      +   '<div style="font-size:.8rem;color:var(--text2);margin-top:.25rem">' + (bSum.fail || 0) + ' \u2192 ' + (aSum.fail || 0) + '</div></div>'
      + '<div class="card"><div class="card-value" style="color:var(--pass)">' + improved.length + '</div><div class="card-label">Improved</div></div>'
      + '<div class="card"><div class="card-value" style="color:var(--fail)">' + regressed.length + '</div><div class="card-label">Regressed</div></div>'
      + '<div class="card"><div class="card-value" style="color:var(--warn)">' + persist.length + '</div><div class="card-label">Still Failing</div></div>'
      + '</div>';

        html += '<div class="cmp-detail-intro"><strong>Detailed movement</strong><span>Expand a section to review the specific controls behind the summary.</span></div>';

    html += renderGroup(
      'Regressed \u2014 PASS \u2192 FAIL',
      regressed.map(function (x) { return renderRow(x.a, '<span style="color:var(--fail)">\u25BC PASS \u2192 FAIL</span>'); }),
            'No regressions in the selected comparison.', 'var(--fail)', regressed.length > 0);

    html += renderGroup(
      'Improved \u2014 now PASS',
      improved.map(function (x) {
        var fr = x.b.status === 'NOT CHECKED' ? 'NOT CHECKED' : 'FAIL';
        return renderRow(x.a, '<span style="color:var(--pass)">\u25B2 ' + fr + ' \u2192 PASS</span>');
      }),
            'No controls moved into PASS.', 'var(--pass)', false);

    html += renderGroup(
      'Still Failing',
      persist.map(function (x) { return renderRow(x.a, '<span style="color:var(--warn)">\u25AC Still FAIL</span>'); }),
            'No controls failed in both selected runs.', 'var(--warn)', regressed.length === 0 && persist.length > 0);

    if (added.length > 0) {
      html += renderGroup(
        'New Controls (in current run only)',
        added.map(function (c) { return renderRow(c, '<span style="color:var(--info)">New</span>'); }),
                '', 'var(--info)', false);
    }
    if (removed.length > 0) {
      html += renderGroup(
        'Removed Controls (from baseline only)',
        removed.map(function (c) { return renderRow(c, '<span style="color:var(--text2)">Removed</span>'); }),
                '', 'var(--surface2)', false);
    }
    elResult.innerHTML = html;
  }

  selA.addEventListener('change', run);
  selB.addEventListener('change', run);
  run();
}());
'@

    return @"
    <!-- Run Comparison Section -->
    <section class="section section-accent-info" id="comparison-section" aria-label="Run comparison">
      <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Trend</p>
      <h2>&#128202; Run Comparison</h2>
      <p id="cmp-nodata" style="color:var(--text2)">No previous scan data available for comparison.
                Keep prior assessment folders, or run with <code style="background:var(--surface2);padding:.1rem .4rem;border-radius:4px">-OutputFormat json</code>
                or <code style="background:var(--surface2);padding:.1rem .4rem;border-radius:4px">-OutputFormat all</code>
                for richer scan data.</p>
      <div id="cmp-ui" style="display:none">
        <div class="cmp-pickers">
          <div class="cmp-picker-grp">
            <label class="cmp-lbl" for="cmp-run-a">Current Run</label>
            <select id="cmp-run-a" class="cmp-sel" aria-label="Select current run to compare"></select>
          </div>
          <span class="cmp-vs">vs</span>
          <div class="cmp-picker-grp">
            <label class="cmp-lbl" for="cmp-run-b">Baseline Run</label>
            <select id="cmp-run-b" class="cmp-sel" aria-label="Select baseline run to compare against"></select>
          </div>
        </div>
        <div id="cmp-result"></div>
      </div>
    </section>
    <script>window.__adoqrRuns=$runsJson;</script>
    <script>$jsCode</script>
"@
}

function Get-NotCheckedReasonCategory {
        <#
        .SYNOPSIS
                Classifies a NOT CHECKED finding into an executive-readable reason.
        #>
        [CmdletBinding()]
        param([string]$Finding)

        if ($Finding -match '(?i)manual review required|manual review recommended') {
                return 'Manual review required'
        }
        if ($Finding -match '(?i)requires\s+-|requires querying|requires .+permission|may require') {
                return 'Prerequisite or permission needed'
        }
        if ($Finding -match '(?i)could not retrieve|could not determine|could not locate|could not enumerate|unable to') {
                return 'Data unavailable'
        }
        if ($Finding -match '(?i)not found|policy not found|setting not found') {
                return 'Setting not found'
        }
        if ($Finding -match '(?i)^no .+ found|nothing .+ found') {
                return 'No applicable data found'
        }
        return 'Review needed'
}

function Build-NotCheckedSectionHtml {
        <#
        .SYNOPSIS
                Builds an executive explanation section for NOT CHECKED controls.
        .DESCRIPTION
                NOT CHECKED is not a pass/fail outcome. This section explains why a
                control could not be evaluated automatically and gives the reader a
                scoped evidence list without cluttering the primary KPI cards.
        #>
        [CmdletBinding()]
        param(
                [PSCustomObject]$OrgSummary,
                [PSCustomObject[]]$ProjectSummaries
        )

        $items = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($OrgSummary -and $OrgSummary.PSObject.Properties['Results'] -and $OrgSummary.Results) {
                foreach ($r in @($OrgSummary.Results | Where-Object Status -eq 'NOT CHECKED')) {
                        $items.Add([PSCustomObject]@{
                                Scope    = 'Organization'
                                Control  = "$($r.Id): $($r.Control)"
                                Severity = $r.Severity
                                Finding  = $r.Finding
                                Reason   = Get-NotCheckedReasonCategory -Finding $r.Finding
                        })
                }
        }

        foreach ($p in @($ProjectSummaries)) {
                if (-not ($p.PSObject.Properties['Results']) -or -not $p.Results) { continue }
                foreach ($r in @($p.Results | Where-Object Status -eq 'NOT CHECKED')) {
                        $items.Add([PSCustomObject]@{
                                Scope    = "Project: $($p.Project)"
                                Control  = "$($r.Id): $($r.Control)"
                                Severity = $r.Severity
                                Finding  = $r.Finding
                                Reason   = Get-NotCheckedReasonCategory -Finding $r.Finding
                        })
                }
        }

        if ($items.Count -eq 0) { return '' }

        $reasonCards = [System.Text.StringBuilder]::new()
        $reasonCounts = @{}
        foreach ($item in $items) {
                if (-not $reasonCounts.ContainsKey($item.Reason)) { $reasonCounts[$item.Reason] = 0 }
                $reasonCounts[$item.Reason]++
        }
        foreach ($reason in $reasonCounts.Keys) {
            $desc = 'The scanner captured a reason, but it does not map to a standard category yet.'
            $reasonCount = $reasonCounts[$reason]
            [void]$reasonCards.AppendLine('                    <div class="nc-reason-card">')
            [void]$reasonCards.AppendLine('                        <div class="nc-reason-count">' + $reasonCount + '</div>')
            [void]$reasonCards.AppendLine('                        <div>')
            [void]$reasonCards.AppendLine("                            <strong>$([System.Web.HttpUtility]::HtmlEncode($reason))</strong>")
            [void]$reasonCards.AppendLine("                            <p>$([System.Web.HttpUtility]::HtmlEncode($desc))</p>")
            [void]$reasonCards.AppendLine('                        </div>')
            [void]$reasonCards.AppendLine('                    </div>')
        }

        $detailGroups = [System.Text.StringBuilder]::new()
        $scopeGroups = @{}
        foreach ($item in $items) {
            if (-not $scopeGroups.ContainsKey($item.Scope)) { $scopeGroups[$item.Scope] = [System.Collections.Generic.List[PSCustomObject]]::new() }
            $scopeGroups[$item.Scope].Add($item)
        }
        foreach ($scope in $scopeGroups.Keys) {
                $rows = [System.Text.StringBuilder]::new()
            foreach ($item in $scopeGroups[$scope]) {
                        $sevClass = switch ($item.Severity) { 'High' { 'nc-sev-high' } 'Medium' { 'nc-sev-medium' } 'Low' { 'nc-sev-low' } default { 'nc-sev-low' } }
                        [void]$rows.AppendLine(@"
                            <tr>
                                <td><strong>$([System.Web.HttpUtility]::HtmlEncode($item.Control))</strong><br><span>$([System.Web.HttpUtility]::HtmlEncode($item.Reason))</span></td>
                                <td><span class="nc-sev $sevClass">$([System.Web.HttpUtility]::HtmlEncode($item.Severity))</span></td>
                                <td>$([System.Web.HttpUtility]::HtmlEncode($item.Finding))</td>
                            </tr>
"@)
                }

                [void]$detailGroups.AppendLine(@"
                <details class="nc-detail">
                    <summary><span>$([System.Web.HttpUtility]::HtmlEncode($scope))</span><span class="nc-detail-count">$($scopeGroups[$scope].Count)</span></summary>
                    <div class="tbl-wrap">
                        <table>
                            <thead><tr><th>Control</th><th>Severity</th><th>Why it was not checked</th></tr></thead>
                            <tbody>
                                $($rows.ToString())
                            </tbody>
                        </table>
                    </div>
                </details>
"@)
        }

        return @"
        <details class="section section-accent-warn section-collapsible" id="not-checked-section" aria-label="Not checked controls explanation">
            <summary class="section-collapsible-summary">
                <div class="section-collapsible-title">
                    <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Not Checked</p>
                    <h2>Not Checked Controls</h2>
                </div>
                <span class="section-collapsible-count" aria-label="$($items.Count) controls not checked">$($items.Count)</span>
                <span class="section-collapsible-chevron" aria-hidden="true"></span>
            </summary>
            <div class="nc-explainer">
                <strong>Not checked does not mean failed.</strong>
                <span>These controls need more context, permissions, configuration data, or manual confirmation before adoqr can make a PASS/FAIL determination.
                    See the <a href="https://microsoft.github.io/adoqr/controls.html" target="_blank" rel="noopener noreferrer">controls reference&nbsp;&#8599;</a> for what each control evaluates and how to remediate it.</span>
            </div>
            <div class="nc-reason-grid">
                $($reasonCards.ToString())
            </div>
            <div class="nc-details-intro"><strong>Review details</strong><span>Expand a scope to see the exact controls and the recorded reason.</span></div>
            $($detailGroups.ToString())
        </details>
"@
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
        $parentRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { $null }
        $candidateRoots = [System.Collections.Generic.List[string]]::new()
        foreach ($candidate in @(
                $PSScriptRoot,
                $MyInvocation.PSScriptRoot,
                $parentRoot,
                (Get-Location).Path
            )) {
            if ($candidate -and -not $candidateRoots.Contains($candidate)) {
                $candidateRoots.Add($candidate)
            }
        }

        $dataPath = $null
        foreach ($root in $candidateRoots) {
            $candidatePath = Join-Path $root 'remediation-steps.psd1'
            if (Test-Path -LiteralPath $candidatePath) {
                $dataPath = $candidatePath
                break
            }
        }
        if (-not $dataPath) {
            throw "Could not locate remediation-steps.psd1."
        }

        $script:RemediationData = Import-PowerShellDataFile $dataPath
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
        $controlIdPart = if ($r.ControlId) { $r.ControlId } else { '' }
        $controlKey = '{0}|{1}' -f $controlIdPart, $r.ControlName
        $controlKeyAttr = [System.Web.HttpUtility]::HtmlAttributeEncode($controlKey)
        $noteId = "accepted-note-$rank"

        # Get remediation steps
        $stepInfo = Get-RemediationSteps -ControlName $r.ControlName
        $stepsHtml = ($stepInfo.Steps | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join ''
        $docLink = $stepInfo.DocUrl

        [void]$rows.AppendLine(@"
        <article class="remed-card" data-control-key="$controlKeyAttr" data-rank="$rank">
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
          <div class="remed-acceptance">
            <div class="remed-acceptance-actions">
              <button type="button" class="remed-btn remed-btn-secondary" data-open-accept>Accept risk</button>
                            <button type="button" class="remed-btn remed-btn-secondary" data-unaccept hidden>Undo acceptance</button>
            </div>
            <div class="remed-accept-form" data-accept-form hidden>
              <label class="remed-accept-label" for="$noteId">Reason for accepting this control</label>
              <textarea id="$noteId" class="remed-accept-text" rows="3" maxlength="1000" aria-required="true" placeholder="Describe the accepted risk, business justification, and approval context." data-accept-note></textarea>
              <p class="remed-accept-error" data-accept-error hidden>Please enter a description before accepting this control.</p>
              <div class="remed-accept-form-actions">
                <button type="button" class="remed-btn remed-btn-primary" data-accept-save>Save accepted control</button>
                <button type="button" class="remed-btn remed-btn-link" data-accept-cancel>Cancel</button>
              </div>
            </div>
            <div class="remed-accepted-meta" data-accepted-meta hidden>
              <div class="remed-accepted-badge">Accepted control</div>
              <dl class="remed-accepted-grid">
                <div>
                  <dt>Accepted on</dt>
                  <dd data-accepted-date></dd>
                </div>
                <div>
                  <dt>Description</dt>
                  <dd data-accepted-note></dd>
                </div>
              </dl>
            </div>
          </div>
          <div class="remed-bar-track">
            <div class="remed-bar-fill" style="width:${pctOfTotal}%;background:$sevColor"></div>
          </div>
        </article>
"@)
    }

    # Top 5 summary for the impact callout
    $top5 = @($Remediations | Select-Object -First 5)
    $top5Issues = ($top5 | Measure-Object -Property Count -Sum).Sum
    $top5Pct = if ($totalIssues -gt 0) { [math]::Round(($top5Issues / $totalIssues) * 100) } else { 0 }

    # Branded header (shared with executive report + controls reference)
    $issuesLabel = if ($totalIssues -eq 1) { '1 item to address' } else { "$([int]$totalIssues) items to address" }
    $headerHtml = Get-AdoqrHeaderHtml -Eyebrow 'Remediation Plan' -Title $OrgName -MetaItems @(
        "<a href=""$([System.Web.HttpUtility]::HtmlAttributeEncode($execFile))"">&larr; Back to Executive Summary</a>",
        [System.Web.HttpUtility]::HtmlEncode($issuesLabel),
        [System.Web.HttpUtility]::HtmlEncode($date)
    )

    $storageKeyJson = ("adoqr.acceptedControls.$OrgName" | ConvertTo-Json -Compress)
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
    [hidden] { display: none !important; }
    .container { max-width: 1000px; margin: 0 auto; padding: 2rem 1.5rem; }

$(Get-AdoqrHeaderCss)
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

    .remed-tabs {
      display: inline-flex; gap: .5rem; flex-wrap: wrap; margin: 0 0 1rem;
      padding: .35rem; background: var(--surface); border: 1px solid var(--surface2); border-radius: 999px;
    }
    .remed-tab {
      border: 0; border-radius: 999px; background: transparent; color: var(--text2);
      padding: .55rem 1rem; font: inherit; font-weight: 700; cursor: pointer;
      display: inline-flex; align-items: center; gap: .5rem;
    }
    .remed-tab:hover { color: var(--text); background: rgba(59,130,246,.08); }
    .remed-tab[aria-selected="true"] { color: var(--text); background: rgba(59,130,246,.16); }
    .remed-tab-count {
      min-width: 1.7rem; height: 1.7rem; padding: 0 .45rem; border-radius: 999px;
      display: inline-flex; align-items: center; justify-content: center;
      background: var(--surface2); color: var(--text); font-size: .78rem; font-weight: 800;
    }
    .remed-tab-panel-note { margin: 0 0 1rem; color: var(--text2); font-size: .9rem; }
    .remed-tab-panel-note strong { color: var(--text); }
    .remed-empty {
      margin: 0; padding: 1rem 1.25rem; color: var(--text2);
      background: var(--surface); border: 1px dashed var(--surface2); border-radius: 12px;
    }
    .remed-card-accepted { border: 1px solid rgba(34,197,94,.22); }
    .remed-acceptance {
      padding: 0 1.5rem 1.25rem;
      display: flex; flex-direction: column; gap: .85rem;
    }
    .remed-acceptance-actions, .remed-accept-form-actions {
      display: flex; gap: .75rem; flex-wrap: wrap; align-items: center;
    }
    .remed-btn {
      border: 0; border-radius: 999px; padding: .65rem 1rem;
      font: inherit; font-weight: 700; cursor: pointer;
    }
    .remed-btn-primary { background: var(--accent); color: #fff; }
    .remed-btn-secondary { background: rgba(59,130,246,.14); color: var(--accent); }
    .remed-btn-link { background: transparent; color: var(--text2); padding-left: 0; padding-right: 0; }
    .remed-btn-link:hover { color: var(--text); text-decoration: underline; }
    .remed-accept-form {
      background: rgba(15,23,42,.35); border: 1px solid var(--surface2); border-radius: 12px; padding: 1rem;
    }
    .remed-accept-label { display: block; font-weight: 700; margin-bottom: .5rem; }
    .remed-accept-text {
      width: 100%; min-height: 7rem; resize: vertical; border-radius: 10px;
      border: 1px solid var(--surface2); background: var(--bg); color: var(--text);
      padding: .8rem .95rem; font: inherit;
    }
    .remed-accept-text:focus, .remed-tab:focus, .remed-btn:focus {
      outline: 3px solid var(--accent); outline-offset: 2px;
    }
    .remed-accept-error { color: var(--fail); font-size: .85rem; margin: .5rem 0 0; }
    .remed-accepted-meta {
      background: rgba(34,197,94,.08); border: 1px solid rgba(34,197,94,.2);
      border-radius: 12px; padding: 1rem;
    }
    .remed-accepted-badge {
      display: inline-flex; align-items: center; gap: .35rem;
      padding: .25rem .7rem; border-radius: 999px; background: rgba(34,197,94,.15); color: var(--pass);
      font-size: .78rem; font-weight: 800; text-transform: uppercase; letter-spacing: .04em; margin-bottom: .75rem;
    }
    .remed-accepted-grid { margin: 0; display: grid; gap: .75rem; }
    .remed-accepted-grid div { display: grid; gap: .2rem; }
    .remed-accepted-grid dt { color: var(--text2); font-size: .8rem; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
    .remed-accepted-grid dd { margin: 0; white-space: pre-wrap; }

    .section { margin: 2.5rem 0; }
    .section h2 { font-size: 1.25rem; font-weight: 700; margin: 0 0 1rem; padding-bottom: .5rem; border-bottom: 1px solid var(--surface2); }

    footer { text-align: center; padding: 2rem; color: var(--text2); font-size: .8rem; border-top: 1px solid var(--surface2); margin-top: 3rem; }

    @media (max-width: 640px) {
      .remed-header { flex-direction: column; align-items: flex-start; }
      .impact-box { flex-direction: column; text-align: center; }
      .remed-tabs { width: 100%; border-radius: 20px; }
      .remed-tab { flex: 1 1 100%; justify-content: center; }
    }
  </style>
</head>
<body>

$headerHtml

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
      <div class="remed-tabs" role="tablist" aria-label="Remediation workflow">
        <button type="button" class="remed-tab" id="tab-active-controls" role="tab" aria-selected="true" aria-controls="panel-active-controls" data-remed-tab="active">
          Remediation Actions
          <span class="remed-tab-count" data-active-count>$($Remediations.Count)</span>
        </button>
        <button type="button" class="remed-tab" id="tab-accepted-controls" role="tab" aria-selected="false" aria-controls="panel-accepted-controls" data-remed-tab="accepted">
          Accepted Controls
          <span class="remed-tab-count" data-accepted-count>0</span>
        </button>
      </div>
      <div id="panel-active-controls" role="tabpanel" aria-labelledby="tab-active-controls" data-remed-panel="active">
        <p class="remed-tab-panel-note"><strong>Use "Accept risk"</strong> when the business has approved the control gap and provided justification. Accepted controls move out of the active remediation list and are saved per organization for future remediation reports opened in the same browser.</p>
        <div id="remed-active-list">
          $($rows.ToString())
        </div>
      </div>
      <div id="panel-accepted-controls" role="tabpanel" aria-labelledby="tab-accepted-controls" data-remed-panel="accepted" hidden>
        <p class="remed-tab-panel-note">Accepted controls keep the business justification and the acceptance date together for later review, they are automatically reused on later remediation reports for this organization in the same browser, and <strong>Undo acceptance</strong> moves a control back into the active remediation list.</p>
        <div id="remed-accepted-list"></div>
        <p class="remed-empty" id="accepted-controls-empty">No controls have been accepted yet.</p>
      </div>
    </section>

  </main>

  <footer>
    <p>Generated by <strong>invoke-adoqr.ps1</strong> on $date</p>
  </footer>
  <script>
    (function () {
      var storageKey = $storageKeyJson;
      var cards = Array.prototype.slice.call(document.querySelectorAll('.remed-card'));
      if (cards.length === 0) { return; }

      var activeList = document.getElementById('remed-active-list');
      var acceptedList = document.getElementById('remed-accepted-list');
      var acceptedEmpty = document.getElementById('accepted-controls-empty');
      var activeCount = document.querySelector('[data-active-count]');
      var acceptedCount = document.querySelector('[data-accepted-count]');
      var tabs = Array.prototype.slice.call(document.querySelectorAll('[data-remed-tab]'));
      var panels = {
        active: document.querySelector('[data-remed-panel="active"]'),
        accepted: document.querySelector('[data-remed-panel="accepted"]')
      };

      function readState() {
        try {
          var raw = window.localStorage ? window.localStorage.getItem(storageKey) : null;
          if (!raw) { return {}; }
          var parsed = JSON.parse(raw);
          return parsed && typeof parsed === 'object' ? parsed : {};
        } catch (e) {
          return {};
        }
      }

      function writeState(nextState) {
        try {
          if (window.localStorage) {
            window.localStorage.setItem(storageKey, JSON.stringify(nextState));
          }
        } catch (e) {
        }
      }

      function insertByRank(container, card) {
        var rank = parseInt(card.getAttribute('data-rank') || '0', 10);
        var inserted = false;
        Array.prototype.forEach.call(container.children, function (child) {
          if (inserted) { return; }
          var childRank = parseInt(child.getAttribute('data-rank') || '0', 10);
          if (rank < childRank) {
            container.insertBefore(card, child);
            inserted = true;
          }
        });
        if (!inserted) {
          container.appendChild(card);
        }
      }

      function formatAcceptedAt(value) {
        var parsed = new Date(value);
        return isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
      }

      function setTab(name) {
        tabs.forEach(function (tab) {
          var isSelected = tab.getAttribute('data-remed-tab') === name;
          tab.setAttribute('aria-selected', isSelected ? 'true' : 'false');
        });
        Object.keys(panels).forEach(function (key) {
          panels[key].hidden = key !== name;
        });
      }

      function updateCounts() {
        var openCount = activeList.children.length;
        var acceptedTotal = acceptedList.children.length;
        activeCount.textContent = openCount;
        acceptedCount.textContent = acceptedTotal;
        acceptedEmpty.hidden = acceptedTotal > 0;
      }

      function applyAcceptedState(card, acceptedInfo) {
        var meta = card.querySelector('[data-accepted-meta]');
        var metaDate = card.querySelector('[data-accepted-date]');
        var metaNote = card.querySelector('[data-accepted-note]');
        var form = card.querySelector('[data-accept-form]');
        var openAccept = card.querySelector('[data-open-accept]');
        var unaccept = card.querySelector('[data-unaccept]');
        var noteField = card.querySelector('[data-accept-note]');
        var error = card.querySelector('[data-accept-error]');

        card.classList.add('remed-card-accepted');
        form.hidden = true;
        error.hidden = true;
        openAccept.hidden = true;
        unaccept.hidden = false;
        meta.hidden = false;
        noteField.value = acceptedInfo.note || '';
        metaDate.textContent = formatAcceptedAt(acceptedInfo.acceptedAt);
        metaNote.textContent = acceptedInfo.note || '';
        insertByRank(acceptedList, card);
      }

      function applyOpenState(card) {
        var meta = card.querySelector('[data-accepted-meta]');
        var form = card.querySelector('[data-accept-form]');
        var openAccept = card.querySelector('[data-open-accept]');
        var unaccept = card.querySelector('[data-unaccept]');
        var error = card.querySelector('[data-accept-error]');

        card.classList.remove('remed-card-accepted');
        form.hidden = true;
        error.hidden = true;
        openAccept.hidden = false;
        unaccept.hidden = true;
        meta.hidden = true;
        insertByRank(activeList, card);
      }

      var state = readState();
      cards.forEach(function (card) {
        var controlKey = card.getAttribute('data-control-key');
        if (state[controlKey]) {
          applyAcceptedState(card, state[controlKey]);
        } else {
          applyOpenState(card);
        }

        var form = card.querySelector('[data-accept-form]');
        var noteField = card.querySelector('[data-accept-note]');
        var error = card.querySelector('[data-accept-error]');

        card.querySelector('[data-open-accept]').addEventListener('click', function () {
          form.hidden = false;
          error.hidden = true;
          noteField.focus();
        });

        card.querySelector('[data-accept-cancel]').addEventListener('click', function () {
          form.hidden = true;
          error.hidden = true;
        });

        card.querySelector('[data-accept-save]').addEventListener('click', function () {
          var note = (noteField.value || '').trim();
          if (!note) {
            error.hidden = false;
            noteField.focus();
            return;
          }

          state[controlKey] = {
            note: note,
            acceptedAt: new Date().toISOString()
          };
          writeState(state);
          applyAcceptedState(card, state[controlKey]);
          updateCounts();
          setTab('accepted');
        });

        card.querySelector('[data-unaccept]').addEventListener('click', function () {
          delete state[controlKey];
          writeState(state);
          applyOpenState(card);
          updateCounts();
          setTab('active');
        });
      });

      tabs.forEach(function (tab) {
        tab.addEventListener('click', function () {
          setTab(tab.getAttribute('data-remed-tab'));
        });
      });

      updateCounts();
      setTab('active');
    })();
  </script>
</body>
</html>
"@

    $html | Set-Content -Path $FilePath -Encoding utf8
    Write-Host "  Remediation report saved: $FilePath" -ForegroundColor Green
}

# Returns the adoqr logo as a base64 data URI so HTML reports stay self-contained
# when shared without the assets folder. Cached after first read; returns '' on
# failure so callers can gracefully fall back to a text-only header.
function Get-AdoqrLogoDataUri {
    if ($script:AdoqrLogoDataUri -is [string]) { return $script:AdoqrLogoDataUri }
    $script:AdoqrLogoDataUri = ''
    try {
        # Prefer the script's own directory; fall back to caller invocation root,
        # then current location. This lets the helper work both when invoke-adoqr.ps1
        # runs normally and when the function is loaded standalone (e.g. tests).
        $root = if ($PSScriptRoot) { $PSScriptRoot }
                elseif ($MyInvocation.PSScriptRoot) { $MyInvocation.PSScriptRoot }
                else { (Get-Location).Path }
        $logoPath = Join-Path $root 'assets/adoqr_logo.png'
        if (-not (Test-Path -LiteralPath $logoPath)) { return $script:AdoqrLogoDataUri }
        $bytes = [System.IO.File]::ReadAllBytes($logoPath)
        if ($bytes.Length -gt 0) {
            $script:AdoqrLogoDataUri = 'data:image/png;base64,' + [Convert]::ToBase64String($bytes)
        }
    } catch {
        Write-Verbose "Could not embed adoqr logo: $_"
    }
    return $script:AdoqrLogoDataUri
}

# Returns the shared CSS rules for the adoqr branded header. Used by every
# generated HTML report (executive summary, remediation plan) and kept in sync
# with docs/controls.html for a consistent look.
function Get-AdoqrHeaderCss {
    return @'
    header { background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 2rem 0; border-bottom: 1px solid var(--surface2); }
    .header-brand { display: flex; align-items: center; gap: 1.5rem; flex-wrap: wrap; margin: 0; }
    .header-brand .header-logo {
      display: block; height: 72px; width: auto; max-width: 100%;
      flex: 0 0 auto;
      filter: drop-shadow(0 4px 12px rgba(0,0,0,.35));
    }
    .header-brand .header-title-group { min-width: 0; }
    .header-brand .header-logo + .header-title-group {
      padding-left: 1.5rem;
      border-left: 1px solid rgba(255,255,255,.12);
    }
    .header-brand h1 {
      margin: 0; font-size: 1.5rem; font-weight: 700; line-height: 1.2;
      display: flex; flex-direction: column; gap: .15rem;
    }
    .header-eyebrow {
      font-size: .72rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: .14em; color: var(--text2);
    }
    .header-org { color: var(--text); }
    .header-meta {
      display: flex; flex-wrap: wrap; align-items: center;
      gap: .35rem .85rem; margin: 1.25rem 0 0;
      color: var(--text2); font-size: .82rem;
    }
    .header-meta > span { display: inline-flex; align-items: center; }
    .header-meta > span + span::before {
      content: ''; display: inline-block;
      width: 3px; height: 3px; border-radius: 50%;
      background: currentColor; opacity: .5;
      margin-right: .85rem;
    }
    .header-meta a { color: inherit; text-decoration: none; border-bottom: 1px dotted rgba(148,163,184,.4); }
    .header-meta a:hover { color: var(--text); border-bottom-color: var(--text); }
    .visually-hidden {
      position: absolute !important; width: 1px; height: 1px; padding: 0; margin: -1px;
      overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0;
    }
    @media (max-width: 640px) {
      header { padding: 1.5rem 0; }
      .header-brand { gap: 1rem; }
      .header-brand .header-logo { height: 56px; }
      .header-brand .header-logo + .header-title-group { padding-left: 1rem; }
      .header-brand h1 { font-size: 1.25rem; }
      .header-meta { margin-top: 1rem; font-size: .78rem; gap: .25rem .65rem; }
      .header-meta > span + span::before { margin-right: .65rem; }
    }
'@
}

# Returns the shared <header> HTML for all adoqr reports.
# - Eyebrow:   small caps label (e.g. "Executive Summary", "Remediation Plan").
# - Title:     prominent visible heading (usually the org name).
# - MetaItems: optional array of HTML snippets rendered as a bullet-separated
#              meta row. Each item is already HTML-encoded by the caller.
function Get-AdoqrHeaderHtml {
    param(
        [Parameter(Mandatory)][string]$Eyebrow,
        [Parameter(Mandatory)][string]$Title,
        [string[]]$MetaItems = @()
    )

    $logoDataUri = Get-AdoqrLogoDataUri
    $logoImgHtml = if ($logoDataUri) {
        "<img class=""header-logo"" src=""$logoDataUri"" alt=""ADOQR — Azure DevOps Quick Review"" width=""288"" height=""72"" />"
    } else { '' }

    $eyebrowEnc = [System.Web.HttpUtility]::HtmlEncode($Eyebrow)
    $titleEnc   = [System.Web.HttpUtility]::HtmlEncode($Title)

    $metaHtml = ''
    if ($MetaItems -and $MetaItems.Count -gt 0) {
        $spans = ($MetaItems | ForEach-Object { "<span>$_</span>" }) -join "`n        "
        $metaHtml = @"
      <p class="header-meta" aria-label="Report metadata">
        $spans
      </p>
"@
    }

    return @"
  <header>
    <div class="container">
      <div class="header-brand">
        $logoImgHtml
        <div class="header-title-group">
          <h1>
            <span class="header-eyebrow">$eyebrowEnc</span>
            <span class="header-org">$titleEnc</span>
          </h1>
        </div>
      </div>
$metaHtml
    </div>
  </header>
"@
}

function Write-ExecutiveHtmlReport {
    param(
        [string]$FilePath,
        [string]$OrgName,
        [string]$OrgUrl,
        [string]$ElapsedTime,
        [PSCustomObject]$OrgSummary,        # @{ Pass; Fail; NotChecked; ReportFile }
        [PSCustomObject[]]$ProjectSummaries, # @( @{ Project; Pass; Fail; NotChecked; ReportFile } )
        [PSCustomObject[]]$TopRemediations,  # @( @{ Control; Severity; Count; AffectedAreas; Finding } )
        [string]$ComparisonHtml = ''        # Pre-rendered HTML for the Run Comparison section
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
                            <tr data-project-row="$([System.Web.HttpUtility]::HtmlAttributeEncode($p.Project))">
                <td><strong>$([System.Web.HttpUtility]::HtmlEncode($p.Project))</strong></td>
                                <td class="num" data-project-pass>$($p.Pass)</td>
                                <td class="num fail-text" data-project-fail>$($p.Fail)</td>
                                <td class="num" data-project-notchecked>$($p.NotChecked)</td>
                <td>
                                    <div class="bar-track" data-project-adoption role="progressbar" aria-valuenow="$pPassPct" aria-valuemin="0" aria-valuemax="100" aria-label="$pPassPct percent adopted">
                                        <div class="bar-fill" data-project-adoption-fill style="width:${pPassPct}%"></div>
                  </div>
                </td>
                                <td data-project-status>$pStatus</td>
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
    $orgExtensions = if ($OrgSummary -and $OrgSummary.PSObject.Properties['OrgExtensions']) { $OrgSummary.OrgExtensions } else { $null }
    $installedAvailable = $false
    $installedExtensions = @()
    if ($orgExtensions) {
        if ($orgExtensions.PSObject.Properties['InstalledAvailable']) { $installedAvailable = [bool]$orgExtensions.InstalledAvailable }
        if ($orgExtensions.PSObject.Properties['Installed']) { $installedExtensions = @($orgExtensions.Installed) }
    }

    $extensionRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($ext in $installedExtensions) {
        $isDefault = [bool]$ext.IsBuiltIn
        $typeLabel = if ($isDefault) { 'Default' } else { 'Installed' }
        $typeSort = if ($isDefault) { 1 } else { 0 }
        $source = if ($ext.IsMicrosoft) { 'Microsoft' } elseif ($ext.IsTrusted) { 'Trusted' } else { 'Other' }
        $extensionRows.Add([PSCustomObject]@{
            Name = [string]$ext.Name
            Publisher = [string]$ext.Publisher
            Version = [string]$ext.Version
            Type = $typeLabel
            TypeSort = $typeSort
            Source = $source
        })
    }

    $installedCount = @($extensionRows | Where-Object { $_.Type -eq 'Installed' }).Count
    $defaultCount = @($extensionRows | Where-Object { $_.Type -eq 'Default' }).Count

    $installedRows = [System.Text.StringBuilder]::new()
    foreach ($ext in ($extensionRows | Sort-Object TypeSort, Name, Publisher)) {
        $name = [System.Web.HttpUtility]::HtmlEncode([string]$ext.Name)
        $publisher = [System.Web.HttpUtility]::HtmlEncode([string]$ext.Publisher)
        $version = [System.Web.HttpUtility]::HtmlEncode([string]$ext.Version)
        $type = [System.Web.HttpUtility]::HtmlEncode([string]$ext.Type)
        $source = [System.Web.HttpUtility]::HtmlEncode([string]$ext.Source)
        if ([string]::IsNullOrWhiteSpace($name)) { $name = '(Unnamed extension)' }
        if ([string]::IsNullOrWhiteSpace($publisher)) { $publisher = '-' }
        if ([string]::IsNullOrWhiteSpace($version)) { $version = '-' }
        [void]$installedRows.AppendLine("                <tr><td>$name</td><td>$publisher</td><td>$version</td><td>$type</td><td>$source</td></tr>")
    }

    $installedHtml = if (-not $installedAvailable) {
        '<p class="cmp-empty">Installed extensions could not be retrieved for this run.</p>'
    } elseif ($installedRows.Length -eq 0) {
        '<p class="cmp-empty">No installed extensions were returned by the organization API.</p>'
    } else {
@"
            <div class="tbl-wrap">
                <table>
                    <thead>
                        <tr>
                            <th scope="col">Extension</th>
                            <th scope="col">Publisher</th>
                            <th scope="col">Version</th>
                            <th scope="col">Type</th>
                            <th scope="col">Source</th>
                        </tr>
                    </thead>
                    <tbody>
$($installedRows.ToString())                    </tbody>
                </table>
            </div>
"@
    }

    $orgExtensionsHtml = @"
        <section class="section section-accent-accent" id="organization-extensions" aria-label="Organization extensions">
            <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Extensions</p>
            <h2>Organization Extensions</h2>
            <p class="org-ext-meta"><strong>Installed:</strong> $installedCount <span aria-hidden="true">|</span> <strong>Defaults:</strong> $defaultCount</p>
            <div class="org-ext-panel">
                <h3>Installed and Default Extensions ($($installedExtensions.Count))</h3>
$installedHtml
            </div>
        </section>
"@

    $notCheckedHtml = Build-NotCheckedSectionHtml -OrgSummary $OrgSummary -ProjectSummaries $ProjectSummaries

    $acceptedStorageKeyJson = ("adoqr.acceptedControls.$OrgName" | ConvertTo-Json -Compress)

    $currentRunControls = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($OrgSummary -and $OrgSummary.PSObject.Properties['Results'] -and $OrgSummary.Results) {
        foreach ($r in @($OrgSummary.Results)) {
            $currentRunControls.Add([PSCustomObject]@{
                key    = ('{0}|{1}' -f $r.Id, $r.Control)
                id     = $r.Id
                control = $r.Control
                status = $r.Status
                scope  = [PSCustomObject]@{
                    type    = 'organization'
                    project = $null
                }
            })
        }
    }
    foreach ($p in @($ProjectSummaries)) {
        if (-not ($p.PSObject.Properties['Results']) -or -not $p.Results) { continue }
        foreach ($r in @($p.Results)) {
            $currentRunControls.Add([PSCustomObject]@{
                key     = ('{0}|{1}' -f $r.Id, $r.Control)
                id      = $r.Id
                control = $r.Control
                status  = $r.Status
                scope   = [PSCustomObject]@{
                    type    = 'project'
                    project = $p.Project
                }
            })
        }
    }

    $currentRunControlsJson = ($currentRunControls | ConvertTo-Json -Depth 6 -Compress)
    if (-not $currentRunControlsJson) { $currentRunControlsJson = '[]' }
    if ($currentRunControlsJson.TrimStart()[0] -ne '[') { $currentRunControlsJson = "[$currentRunControlsJson]" }
    $currentRunControlsJson = $currentRunControlsJson -replace '</script>', '<\/script>'

    $remediationPayload = @($TopRemediations | ForEach-Object {
        [PSCustomObject]@{
            key           = ('{0}|{1}' -f $_.ControlId, $_.ControlName)
            controlName   = $_.ControlName
            severity      = $_.Severity
            count         = $_.Count
            affectedAreas = @($_.AffectedAreas)
        }
    })
    $remediationPayloadJson = ($remediationPayload | ConvertTo-Json -Depth 6 -Compress)
    if (-not $remediationPayloadJson) { $remediationPayloadJson = '[]' }
    if ($remediationPayloadJson.TrimStart()[0] -ne '[') { $remediationPayloadJson = "[$remediationPayloadJson]" }
    $remediationPayloadJson = $remediationPayloadJson -replace '</script>', '<\/script>'

    # Branded header (shared with remediation plan + controls reference)
    $orgUrlDisplay   = $OrgUrl -replace '^https?://', ''
    $orgUrlAttr      = [System.Web.HttpUtility]::HtmlAttributeEncode($OrgUrl)
    $orgUrlDisplayEnc = [System.Web.HttpUtility]::HtmlEncode($orgUrlDisplay)
    $projectsLabel   = if ($totalProjects -eq 1) { '1 project' } else { "$totalProjects projects" }
    $headerHtml = Get-AdoqrHeaderHtml -Eyebrow 'Executive Summary' -Title $OrgName -MetaItems @(
        "<a href=""$orgUrlAttr"" target=""_blank"" rel=""noopener noreferrer"">$orgUrlDisplayEnc</a>",
        [System.Web.HttpUtility]::HtmlEncode($projectsLabel),
        [System.Web.HttpUtility]::HtmlEncode($ElapsedTime),
        [System.Web.HttpUtility]::HtmlEncode($date)
    )

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

$(Get-AdoqrHeaderCss)
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

    /* Section panels — each report section is a distinct elevated card with an accent edge */
    .section {
      background: var(--surface);
      border: 1px solid var(--surface2);
      border-top: 3px solid var(--surface2);
      border-radius: 16px;
      padding: 1.75rem 1.75rem 1.5rem;
      margin: 0 0 1.75rem;
      box-shadow: 0 1px 3px rgba(0,0,0,.25), 0 8px 24px rgba(0,0,0,.18);
      scroll-margin-top: 5rem;
      break-inside: avoid;
    }
    .section-accent-pass    { border-top-color: var(--pass); }
    .section-accent-fail    { border-top-color: var(--fail); }
    .section-accent-warn    { border-top-color: var(--warn); }
    .section-accent-info    { border-top-color: var(--info); }
    .section-accent-accent  { border-top-color: var(--accent); }

    .section-eyebrow {
      display: inline-flex; align-items: center; gap: .5rem;
      font-size: .72rem; font-weight: 700;
      text-transform: uppercase; letter-spacing: .12em;
      color: var(--text2); margin: 0 0 .35rem;
    }
    .section-eyebrow-dot {
      display: inline-block; width: .55rem; height: .55rem; border-radius: 999px;
      background: var(--surface2);
    }
    .section-accent-pass   .section-eyebrow-dot { background: var(--pass); }
    .section-accent-fail   .section-eyebrow-dot { background: var(--fail); }
    .section-accent-warn   .section-eyebrow-dot { background: var(--warn); }
    .section-accent-info   .section-eyebrow-dot { background: var(--info); }
    .section-accent-accent .section-eyebrow-dot { background: var(--accent); }

    .section h2 { font-size: 1.5rem; font-weight: 700; margin: 0 0 1.25rem; padding: 0; border-bottom: none; }

    /* Collapsible section panel — entire section toggles open/closed */
    details.section-collapsible { padding-top: 1.25rem; }
    .section-collapsible-summary {
      list-style: none; cursor: pointer; outline: none;
      display: flex; align-items: center; gap: 1rem;
    }
    .section-collapsible-summary::-webkit-details-marker { display: none; }
    .section-collapsible-summary:focus-visible { outline: 3px solid var(--accent); outline-offset: 4px; border-radius: 8px; }
    .section-collapsible-title { flex: 1; min-width: 0; }
    .section-collapsible-title .section-eyebrow { margin: 0 0 .25rem; }
    .section-collapsible-title h2 { margin: 0; }
    .section-collapsible-count {
      display: inline-flex; align-items: center; justify-content: center;
      min-width: 2.2rem; height: 1.9rem; padding: 0 .7rem; border-radius: 999px;
      background: var(--surface2); color: var(--text); font-weight: 800; font-size: .85rem;
    }
    .section-accent-warn .section-collapsible-count { background: rgba(245,158,11,.15); color: var(--warn); }
    .section-accent-fail .section-collapsible-count { background: rgba(239,68,68,.15);  color: var(--fail); }
    .section-accent-pass .section-collapsible-count { background: rgba(34,197,94,.15);  color: var(--pass); }
    .section-accent-info .section-collapsible-count { background: rgba(59,130,246,.15); color: var(--info); }
    .section-collapsible-chevron {
      width: 1.9rem; height: 1.9rem; border-radius: 999px;
      background: var(--surface2); color: var(--text);
      display: inline-flex; align-items: center; justify-content: center;
      font-size: 1.1rem; line-height: 1; font-weight: 700; flex: 0 0 auto;
    }
    .section-collapsible-chevron::before { content: '+'; }
    details.section-collapsible[open] .section-collapsible-chevron::before { content: '\2212'; } /* minus sign */
    details.section-collapsible[open] > .section-collapsible-summary { margin-bottom: 1.25rem; }

    @media print {
      details.section-collapsible .section-collapsible-chevron { display: none; }
    }

    /* Sticky in-page navigation — jump links to each section */
    .section-nav {
      position: sticky; top: 0; z-index: 50;
      background: rgba(15,23,42,.88); backdrop-filter: saturate(160%) blur(10px);
      -webkit-backdrop-filter: saturate(160%) blur(10px);
      border-bottom: 1px solid var(--surface2);
    }
    .section-nav-inner {
      max-width: 1200px; margin: 0 auto; padding: .55rem 1.5rem;
      display: flex; gap: .4rem; overflow-x: auto;
      -webkit-overflow-scrolling: touch; scrollbar-width: none;
    }
    .section-nav-inner::-webkit-scrollbar { display: none; }
    .section-nav a {
      flex: 0 0 auto;
      padding: .4rem .85rem; border-radius: 999px;
      font-size: .8rem; font-weight: 600; color: var(--text2);
      background: transparent; border: 1px solid transparent;
      white-space: nowrap; text-decoration: none;
      transition: background .15s, color .15s, border-color .15s;
    }
    .section-nav a:hover { color: var(--text); background: var(--surface); }
    .section-nav a.is-active { color: var(--text); background: var(--surface); border-color: var(--surface2); }
    .section-nav a:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
    .section-nav-resources { margin-left: auto; display: flex; gap: .4rem; flex: 0 0 auto; padding-left: .75rem; }
    .section-nav a.nav-external { color: var(--accent); }
    .section-nav a.nav-external::after { content: ' \2197'; font-size: .85em; opacity: .75; }

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

        /* Not checked explanation */
        .nc-explainer {
            display: flex; flex-direction: column; gap: .2rem; background: var(--surface);
            border-left: 4px solid var(--warn); border-radius: 0 8px 8px 0;
            padding: 1rem 1.25rem; margin-bottom: 1rem;
        }
        .nc-explainer span, .nc-reason-card p, .nc-details-intro span { color: var(--text2); }
        .nc-reason-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: .75rem; margin-bottom: 1rem; }
        .nc-reason-card {
            display: flex; gap: .75rem; align-items: flex-start; background: var(--surface);
            border: 1px solid var(--surface2); border-radius: 8px; padding: .9rem 1rem;
        }
        .nc-reason-count {
            display: inline-flex; align-items: center; justify-content: center;
            min-width: 2rem; height: 2rem; padding: 0 .45rem; border-radius: 999px;
            background: rgba(245,158,11,.15); color: var(--warn); font-weight: 800;
        }
        .nc-reason-card p { margin: .15rem 0 0; font-size: .85rem; line-height: 1.4; }
        .nc-details-intro { display: flex; align-items: baseline; gap: .6rem; margin: 0 0 .75rem; font-size: .9rem; }
        .nc-detail { background: var(--surface); border-radius: 8px; margin-bottom: .75rem; overflow: hidden; }
        .nc-detail summary {
            display: flex; align-items: center; gap: .75rem; cursor: pointer; list-style: none;
            padding: .75rem 1rem; font-weight: 700;
        }
        .nc-detail summary::-webkit-details-marker { display: none; }
        .nc-detail summary::after { content: '+'; margin-left: auto; color: var(--text2); font-size: 1.15rem; line-height: 1; }
        .nc-detail[open] summary { border-bottom: 1px solid var(--surface2); }
        .nc-detail[open] summary::after { content: '-'; }
        .nc-detail-count {
            display: inline-flex; align-items: center; justify-content: center;
            min-width: 1.6rem; height: 1.6rem; padding: 0 .4rem; border-radius: 999px;
            background: var(--surface2); color: var(--text); font-size: .8rem; font-weight: 800;
        }
        .nc-detail td span { color: var(--text2); font-size: .85rem; }
        .nc-sev { display: inline-block; padding: .15rem .5rem; border-radius: 999px; font-size: .75rem; font-weight: 800; text-transform: uppercase; }
        .nc-sev-high { background: rgba(239,68,68,.12); color: var(--fail); }
        .nc-sev-medium { background: rgba(245,158,11,.12); color: var(--warn); }
        .nc-sev-low { background: rgba(59,130,246,.12); color: var(--info); }

    /* Org row */
    .org-summary {
      background: var(--surface2); border-radius: var(--radius); padding: 1.25rem 1.5rem;
      margin-bottom: 0;
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;
    }
    .org-summary .org-stats { display: flex; gap: 1.5rem; }
    .org-summary .stat { text-align: center; }
    .org-summary .stat-val { font-size: 1.5rem; font-weight: 800; }
    .org-summary .stat-lbl { font-size: .75rem; color: var(--text2); text-transform: uppercase; }
        .org-ext-meta { margin: 0 0 .75rem; color: var(--text2); font-size: .9rem; }
        .org-ext-panel h3 { margin: 0 0 .6rem; font-size: 1rem; }
        .org-ext-panel table { margin: 0; }

    footer { text-align: center; padding: 2rem; color: var(--text2); font-size: .8rem; border-top: 1px solid var(--surface2); margin-top: 3rem; }

    /* Skip link for WCAG */
    .skip-link {
      position: absolute; top: -100%; left: 1rem; background: var(--accent); color: #fff;
      padding: .5rem 1rem; border-radius: 4px; z-index: 100; font-weight: 700;
    }
    .skip-link:focus { top: 1rem; }

    /* Run Comparison */
    .cmp-pickers {
      display: flex; align-items: flex-end; gap: 1.25rem; flex-wrap: wrap; margin-bottom: 1.5rem;
    }
    .cmp-picker-grp { display: flex; flex-direction: column; gap: .35rem; }
    .cmp-lbl { font-size: .8rem; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: .04em; }
    .cmp-sel {
      background: var(--surface2); color: var(--text); border: 1px solid var(--surface2);
      border-radius: 8px; padding: .5rem .75rem; font-size: .9rem; cursor: pointer;
      min-width: 280px;
    }
    .cmp-sel:focus { outline: 3px solid var(--accent); outline-offset: 2px; }
    .cmp-vs {
      font-size: 1rem; font-weight: 700; color: var(--text2); padding-bottom: .5rem; align-self: flex-end;
    }
        .cmp-executive-summary {
            display: grid; grid-template-columns: auto minmax(0, 1fr); gap: .75rem 1rem;
            align-items: center; background: var(--surface); border: 1px solid var(--surface2);
            border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; box-shadow: var(--shadow);
        }
        .cmp-verdict {
            display: inline-flex; align-items: center; justify-content: center; min-width: 8.5rem;
            padding: .4rem .75rem; border-radius: 999px; font-size: .8rem; font-weight: 800;
            text-transform: uppercase; letter-spacing: .04em;
        }
        .cmp-verdict-good { background: rgba(34,197,94,.15); color: var(--pass); }
        .cmp-verdict-risk { background: rgba(239,68,68,.15); color: var(--fail); }
        .cmp-verdict-stable { background: rgba(148,163,184,.15); color: var(--text2); }
        .cmp-summary-copy { display: flex; flex-direction: column; gap: .2rem; }
        .cmp-summary-copy strong { font-size: 1rem; }
        .cmp-summary-copy span, .cmp-summary-meta { color: var(--text2); font-size: .9rem; }
        .cmp-summary-meta { grid-column: 2; }
        .cmp-detail-intro {
            display: flex; align-items: baseline; gap: .6rem; margin: 0 0 .75rem;
            color: var(--text2); font-size: .9rem;
        }
        .cmp-detail-intro strong { color: var(--text); }
        .cmp-group {
            margin-bottom: .75rem; background: var(--surface); border-left: 4px solid var(--accent);
            border-radius: 0 8px 8px 0; overflow: hidden;
        }
    .cmp-group-hdr {
            display: flex; align-items: center; gap: .6rem; list-style: none;
            padding: .75rem 1rem; font-weight: 700; font-size: .95rem; cursor: pointer;
        }
        .cmp-group-hdr::-webkit-details-marker { display: none; }
        .cmp-group-hdr::after {
            content: '+'; margin-left: auto; color: var(--text2); font-size: 1.15rem; line-height: 1;
        }
        .cmp-group[open] .cmp-group-hdr::after { content: '-'; }
        .cmp-group[open] .cmp-group-hdr { border-bottom: 1px solid var(--surface2); }
        .cmp-disclosure {
            margin-left: auto; color: var(--text2); font-size: .75rem; font-weight: 700;
            text-transform: uppercase; letter-spacing: .04em;
    }
    .cmp-cnt {
      display: inline-flex; align-items: center; justify-content: center;
      background: var(--surface2); border-radius: 999px;
      min-width: 1.6rem; height: 1.6rem; padding: 0 .4rem;
      font-size: .8rem; font-weight: 800; color: var(--text);
    }
        .cmp-empty { color: var(--text2); font-size: .9rem; padding: 0 1rem 1rem; margin: .75rem 0 0; }
    .cmp-delta-cards { margin-bottom: 1.5rem; }

    @media (max-width: 640px) {
      .cards { grid-template-columns: 1fr 1fr; }
      .meta { flex-direction: column; gap: .5rem; }
      .ring-container { justify-content: center; }
            .cmp-pickers { flex-direction: column; align-items: stretch; gap: .75rem; }
            .cmp-picker-grp { width: 100%; }
      .cmp-sel { min-width: 0; width: 100%; }
            .cmp-vs { align-self: center; padding-bottom: 0; }
            .cmp-executive-summary { grid-template-columns: 1fr; }
            .cmp-summary-meta { grid-column: 1; }
            .cmp-detail-intro { flex-direction: column; gap: .15rem; }
            .cmp-disclosure { display: none; }
            .section { padding: 1.25rem 1.1rem 1rem; border-radius: 12px; }
            .section h2 { font-size: 1.25rem; }
    }

    @media print {
      .section-nav { display: none; }
      .section { box-shadow: none; border: 1px solid #ddd; break-inside: avoid; page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <a href="#main" class="skip-link">Skip to main content</a>

$headerHtml

  <nav class="section-nav" aria-label="Section navigation">
    <div class="section-nav-inner">
      <a href="#adoption" data-target="adoption">Overview</a>
      <a href="#top-remediations" data-target="top-remediations">Top Actions</a>
      <a href="#hot-spots" data-target="hot-spots">Hot Spots</a>
      <a href="#organization" data-target="organization">Organization</a>
      <a href="#project-results" data-target="project-results">Projects</a>
      <a href="#not-checked-section" data-target="not-checked-section">Not Checked</a>
    <a href="#organization-extensions" data-target="organization-extensions">Extensions</a>
      <a href="#comparison-section" data-target="comparison-section">Run Comparison</a>
      <span class="section-nav-resources">
        <a class="nav-external" href="https://microsoft.github.io/adoqr/controls.html"
           target="_blank" rel="noopener noreferrer"
           aria-label="Open the full controls reference in a new tab">Controls reference</a>
      </span>
    </div>
  </nav>

  <main id="main" class="container">

        <!-- KPI Cards -->
        <div class="cards" role="list">
            <div class="card card-risk" role="listitem">
                <div class="card-value" data-summary-risk aria-label="Adoption level $riskLevel">$riskLevel</div>
                <div class="card-label">Best Practice Adoption</div>
            </div>
            <div class="card card-pass" role="listitem">
                <div class="card-value" data-summary-pass>$totalPass</div>
                <div class="card-label">Best Practices Adopted</div>
            </div>
            <div class="card card-fail" role="listitem">
                <div class="card-value" data-summary-fail>$totalFail</div>
                <div class="card-label">Improvement Opportunities</div>
            </div>
            <div class="card card-nc" role="listitem">
                <div class="card-value" data-summary-notchecked title="Controls that need more context, permissions, configuration data, or manual confirmation before a PASS/FAIL determination.">$totalNC</div>
                <div class="card-label">Not Checked</div>
            </div>
        </div>

        <!-- Adoption Ring -->
        <section class="section section-accent-pass" id="adoption" aria-label="Best practice adoption overview">
            <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Overview</p>
            <h2>Best Practice Adoption</h2>
            <div class="ring-container">
                <div class="ring" role="img" aria-label="$passPct percent of best practices adopted">
                    <svg viewBox="0 0 140 140" width="140" height="140">
                        <circle cx="70" cy="70" r="60" fill="none" stroke="var(--surface2)" stroke-width="12"/>
                        <circle data-adoption-ring-fill cx="70" cy="70" r="60" fill="none" stroke="var(--pass)" stroke-width="12"
                                        stroke-dasharray="$([math]::Round(377 * $passPct / 100)) 377"
                                        stroke-linecap="round"/>
                    </svg>
                    <span class="ring-label" data-adoption-pass-pct>${passPct}%</span>
                </div>
                <div>
                    <p style="margin:0"><strong data-total-controls>$totalControls</strong> best practices evaluated across <strong data-total-projects>$totalProjects</strong> projects</p>
                    <p style="margin:.25rem 0;color:var(--text2)">
                        <span style="color:var(--pass)">&#9679; <span data-overview-pass>$totalPass</span> adopted (<span data-overview-pass-pct>${passPct}%</span>)</span> &nbsp;
                        <span style="color:var(--fail)">&#9679; <span data-overview-fail>$totalFail</span> opportunities (<span data-overview-fail-pct>${failPct}%</span>)</span> &nbsp;
                        <span style="color:var(--warn)">&#9679; <span data-overview-notchecked>$totalNC</span> not checked (<span data-overview-notchecked-pct>${ncPct}%</span>)</span>
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
    <section class="section section-accent-fail" id="top-remediations" aria-label="Top remediation actions">
      <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Top actions</p>
      <h2>Top 5 Remediation Actions</h2>
            <p style="color:var(--text2);margin-bottom:1rem" data-top-remediations-summary>Adopting these 5 actions addresses <strong style="color:var(--text)" data-top-remediations-top-count>$top5Count</strong> of <strong style="color:var(--text)" data-top-remediations-total-count>$totalRemedIssues</strong> total items (<strong style="color:var(--text)" data-top-remediations-top-pct>${top5Pct}%</strong>).
        <a href="$remedFileName">View full remediation plan &rarr;</a></p>
            <ol class="action-list" data-top-remediations-list>
        $($remedHtml.ToString())
      </ol>
            <p class="cmp-empty" data-top-remediations-empty hidden>All remediation actions in the current top 5 have been accepted.</p>
    </section>
"@
    })

    <!-- Priority Actions by Project -->
    $(if ($topFailProjects.Count -gt 0) {
    @"
    <section class="section section-accent-warn" id="hot-spots" aria-label="Priority actions by project">
      <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Hot spots</p>
      <h2>Projects With Improvement Opportunities</h2>
            <ol class="action-list" data-hot-spots-list>
        $($topFailHtml.ToString())
      </ol>
            <p class="cmp-empty" data-hot-spots-empty hidden>No projects currently have active improvement opportunities.</p>
    </section>
"@
    })

        <!-- Organization -->
        <section class="section section-accent-accent" id="organization" aria-label="Organization review">
            <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Organization</p>
            <h2>Organization Review</h2>
            <div class="org-summary">
                <div>
                    <strong>$([System.Web.HttpUtility]::HtmlEncode($OrgName))</strong>
                    <span style="color:var(--text2);margin-left:.5rem">
                        <a href="$([System.Web.HttpUtility]::HtmlAttributeEncode($orgMdFile))">Full Report</a>
                    </span>
                </div>
                <div class="org-stats">
                    <div class="stat"><div class="stat-val" data-org-pass style="color:var(--pass)">$($OrgSummary.Pass)</div><div class="stat-lbl">Adopted</div></div>
                    <div class="stat"><div class="stat-val" data-org-fail style="color:var(--fail)">$($OrgSummary.Fail)</div><div class="stat-lbl">Opportunities</div></div>
                    <div class="stat"><div class="stat-val" data-org-notchecked style="color:var(--warn)">$($OrgSummary.NotChecked)</div><div class="stat-lbl">Not Checked</div></div>
                </div>
            </div>
        </section>

    $orgExtensionsHtml

        <!-- Project Table -->
        <section class="section section-accent-accent" id="project-results" aria-label="Project results">
            <p class="section-eyebrow"><span class="section-eyebrow-dot"></span>Projects</p>
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

    $notCheckedHtml

    $ComparisonHtml

  </main>

  <footer>
    <p>Generated by <strong>invoke-adoqr.ps1</strong> on $date</p>
    <p>Detailed findings are available in the linked Markdown reports.</p>
    <p>Reference: <a href="https://microsoft.github.io/adoqr/controls.html" target="_blank" rel="noopener noreferrer">https://microsoft.github.io/adoqr/controls.html</a></p>
  </footer>

    <script>
        window.__adoqrCurrentRunControls = $currentRunControlsJson;
        window.__adoqrTopRemediations = $remediationPayloadJson;

        (function () {
            var storageKey = $acceptedStorageKeyJson;
            var controls = window.__adoqrCurrentRunControls || [];
            if (!controls.length) { return; }

            function readState() {
                try {
                    var raw = window.localStorage ? window.localStorage.getItem(storageKey) : null;
                    if (!raw) { return {}; }
                    var parsed = JSON.parse(raw);
                    return parsed && typeof parsed === 'object' ? parsed : {};
                } catch (e) {
                    return {};
                }
            }

            function controlKey(control) {
                return String(control.id || '') + '|' + String(control.control || '');
            }

            function percent(value, total) {
                return total > 0 ? Math.round((value * 100) / total) : 0;
            }

            function riskLevel(totalFail, projectMap) {
                var highFailProjects = Object.keys(projectMap).filter(function (name) {
                    return (projectMap[name].fail || 0) > 20;
                }).length;
                if (totalFail > 100 || highFailProjects > 5) { return 'Limited'; }
                if (totalFail > 50 || highFailProjects > 2) { return 'Partial'; }
                if (totalFail > 20) { return 'Good'; }
                return 'Strong';
            }

            function statusBadge(failCount) {
                if (failCount === 0) { return '<span class="badge badge-pass">EXEMPLARY</span>'; }
                if (failCount > 15) { return '<span class="badge badge-fail">PRIORITY</span>'; }
                if (failCount > 5) { return '<span class="badge badge-warn">REVIEW</span>'; }
                return '<span class="badge badge-info">MINOR</span>'; }

            function summarize(state) {
                var summary = {
                    pass: 0,
                    fail: 0,
                    notChecked: 0,
                    organization: { pass: 0, fail: 0, notChecked: 0 },
                    projects: {}
                };

                controls.forEach(function (control) {
                    if (state[controlKey(control)]) { return; }

                    var bucket = summary.organization;
                    if (control.scope && control.scope.type === 'project') {
                        var projectName = control.scope.project || '';
                        if (!summary.projects[projectName]) {
                            summary.projects[projectName] = { pass: 0, fail: 0, notChecked: 0 };
                        }
                        bucket = summary.projects[projectName];
                    }

                    if (control.status === 'PASS') {
                        summary.pass += 1;
                        bucket.pass += 1;
                    } else if (control.status === 'FAIL') {
                        summary.fail += 1;
                        bucket.fail += 1;
                    } else if (control.status === 'NOT CHECKED') {
                        summary.notChecked += 1;
                        bucket.notChecked += 1;
                    }
                });

                return summary;
            }

            function updateText(selector, value) {
                var el = document.querySelector(selector);
                if (el) { el.textContent = value; }
            }

            function applyAcceptedSummary() {
                var summary = summarize(readState());
                var total = summary.pass + summary.fail + summary.notChecked;
                var passPct = percent(summary.pass, total);
                var failPct = percent(summary.fail, total);
                var notCheckedPct = percent(summary.notChecked, total);
                var risk = riskLevel(summary.fail, summary.projects);

                updateText('[data-summary-pass]', summary.pass);
                updateText('[data-summary-fail]', summary.fail);
                updateText('[data-summary-notchecked]', summary.notChecked);
                updateText('[data-summary-risk]', risk);
                updateText('[data-total-controls]', total);
                updateText('[data-overview-pass]', summary.pass);
                updateText('[data-overview-pass-pct]', passPct + '%');
                updateText('[data-overview-fail]', summary.fail);
                updateText('[data-overview-fail-pct]', failPct + '%');
                updateText('[data-overview-notchecked]', summary.notChecked);
                updateText('[data-overview-notchecked-pct]', notCheckedPct + '%');
                updateText('[data-org-pass]', summary.organization.pass);
                updateText('[data-org-fail]', summary.organization.fail);
                updateText('[data-org-notchecked]', summary.organization.notChecked);

                var riskEl = document.querySelector('[data-summary-risk]');
                if (riskEl) { riskEl.setAttribute('aria-label', 'Adoption level ' + risk); }

                var ringFill = document.querySelector('[data-adoption-ring-fill]');
                var ringLabel = document.querySelector('[data-adoption-pass-pct]');
                var ring = document.querySelector('.ring');
                if (ringFill) { ringFill.setAttribute('stroke-dasharray', Math.round(377 * passPct / 100) + ' 377'); }
                if (ringLabel) { ringLabel.textContent = passPct + '%'; }
                if (ring) { ring.setAttribute('aria-label', passPct + ' percent of best practices adopted'); }

                Array.prototype.forEach.call(document.querySelectorAll('[data-project-row]'), function (row) {
                    var name = row.getAttribute('data-project-row') || '';
                    var project = summary.projects[name] || { pass: 0, fail: 0, notChecked: 0 };
                    var projectTotal = project.pass + project.fail + project.notChecked;
                    var projectPassPct = percent(project.pass, projectTotal);
                    var passEl = row.querySelector('[data-project-pass]');
                    var failEl = row.querySelector('[data-project-fail]');
                    var notCheckedEl = row.querySelector('[data-project-notchecked]');
                    var adoptionEl = row.querySelector('[data-project-adoption]');
                    var adoptionFill = row.querySelector('[data-project-adoption-fill]');
                    var statusEl = row.querySelector('[data-project-status]');
                    if (passEl) { passEl.textContent = project.pass; }
                    if (failEl) { failEl.textContent = project.fail; }
                    if (notCheckedEl) { notCheckedEl.textContent = project.notChecked; }
                    if (adoptionEl) {
                        adoptionEl.setAttribute('aria-valuenow', String(projectPassPct));
                        adoptionEl.setAttribute('aria-label', projectPassPct + ' percent adopted');
                    }
                    if (adoptionFill) { adoptionFill.style.width = projectPassPct + '%'; }
                    if (statusEl) { statusEl.innerHTML = statusBadge(project.fail); }
                });
            }

            window.addEventListener('storage', function (event) {
                if (!event.key || event.key === storageKey) {
                    applyAcceptedSummary();
                }
            });
            document.addEventListener('visibilitychange', function () {
                if (!document.hidden) {
                    applyAcceptedSummary();
                }
            });

            applyAcceptedSummary();
        }());

        (function () {
      var nav = document.querySelector('.section-nav');
      if (!nav) { return; }
      var links = Array.prototype.slice.call(nav.querySelectorAll('a[data-target]'));
      // Hide jump-links whose target section is not rendered on this page
      links = links.filter(function (a) {
        var id = a.getAttribute('data-target');
        var el = id ? document.getElementById(id) : null;
        if (!el) { a.style.display = 'none'; return false; }
        a.__section = el;
        return true;
      });
      if (links.length === 0) { nav.style.display = 'none'; return; }
      if (!('IntersectionObserver' in window)) { return; }
      var byId = {};
      links.forEach(function (a) { byId[a.__section.id] = a; });
      var visible = {};
      var observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          visible[entry.target.id] = entry.isIntersecting ? entry.intersectionRatio : 0;
        });
        var bestId = null, bestRatio = 0;
        Object.keys(visible).forEach(function (id) {
          if (visible[id] > bestRatio) { bestRatio = visible[id]; bestId = id; }
        });
        links.forEach(function (a) { a.classList.toggle('is-active', a.__section.id === bestId); });
      }, { rootMargin: '-80px 0px -55% 0px', threshold: [0, 0.25, 0.5, 1] });
      links.forEach(function (a) { observer.observe(a.__section); });
    }());

    // Auto-open all <details> for printing, restore prior state after
    (function () {
      function setAll(open) {
        document.querySelectorAll('details').forEach(function (d) {
          if (open) {
            if (!d.hasAttribute('data-adoqr-prior')) {
              d.setAttribute('data-adoqr-prior', d.open ? '1' : '0');
            }
            d.open = true;
          } else {
            var prior = d.getAttribute('data-adoqr-prior');
            if (prior !== null) {
              d.open = prior === '1';
              d.removeAttribute('data-adoqr-prior');
            }
          }
        });
      }
      window.addEventListener('beforeprint', function () { setAll(true); });
      window.addEventListener('afterprint', function () { setAll(false); });
    }());

        (function () {
            var storageKey = $acceptedStorageKeyJson;
            var controls = window.__adoqrCurrentRunControls || [];
            var remediations = window.__adoqrTopRemediations || [];
            if (!controls.length) { return; }

            function readAcceptedState() {
                try {
                    var raw = window.localStorage ? window.localStorage.getItem(storageKey) : null;
                    if (!raw) { return {}; }
                    var parsed = JSON.parse(raw);
                    return parsed && typeof parsed === 'object' ? parsed : {};
                } catch (e) {
                    return {};
                }
            }

            function summarizeControls(state) {
                var summary = {
                    global: { pass: 0, fail: 0, notChecked: 0, accepted: 0 },
                    org: { pass: 0, fail: 0, notChecked: 0, accepted: 0 },
                    projects: {}
                };

                controls.forEach(function (control) {
                    var projectName = control.scope && control.scope.type === 'project' ? control.scope.project : null;
                    var bucket = projectName ? (summary.projects[projectName] = summary.projects[projectName] || { pass: 0, fail: 0, notChecked: 0, accepted: 0 }) : summary.org;
                    var isAcceptedFail = !!state[control.key] && control.status === 'FAIL';

                    if (isAcceptedFail) {
                        summary.global.accepted += 1;
                        bucket.accepted += 1;
                        return;
                    }

                    if (control.status === 'PASS') {
                        summary.global.pass += 1;
                        bucket.pass += 1;
                    } else if (control.status === 'FAIL') {
                        summary.global.fail += 1;
                        bucket.fail += 1;
                    } else if (control.status === 'NOT CHECKED') {
                        summary.global.notChecked += 1;
                        bucket.notChecked += 1;
                    }
                });

                return summary;
            }

            function getRiskLevel(totalFail, projects) {
                var highFailProjects = Object.keys(projects).filter(function (name) {
                    return (projects[name].fail || 0) > 20;
                }).length;
                if (totalFail > 100 || highFailProjects > 5) { return 'Limited'; }
                if (totalFail > 50 || highFailProjects > 2) { return 'Partial'; }
                if (totalFail > 20) { return 'Good'; }
                return 'Strong';
            }

            function riskColor(level) {
                if (level === 'Limited') { return '#dc2626'; }
                if (level === 'Partial') { return '#ea580c'; }
                if (level === 'Good') { return '#d97706'; }
                return '#16a34a';
            }

            function updateText(selector, value) {
                var el = document.querySelector(selector);
                if (el) { el.textContent = value; }
            }

            function updateHtml(selector, value) {
                var el = document.querySelector(selector);
                if (el) { el.innerHTML = value; }
            }

            function renderProjectStatus(failCount) {
                if (failCount === 0) { return '<span class="badge badge-pass">EXEMPLARY</span>'; }
                if (failCount > 15) { return '<span class="badge badge-fail">PRIORITY</span>'; }
                if (failCount > 5) { return '<span class="badge badge-warn">REVIEW</span>'; }
                return '<span class="badge badge-info">MINOR</span>';
            }

            function renderTopRemediationItem(item, rank) {
                var urgency = item.severity === 'High' ? 'urgent' : item.severity === 'Medium' ? 'warning' : 'info';
                var color = item.severity === 'High' ? 'var(--fail)' : item.severity === 'Medium' ? 'var(--warn)' : 'var(--info)';
                var areaCount = (item.affectedAreas || []).length;
                return '<li class="action-item action-' + urgency + '">' 
                    + '<span class="action-rank">#' + rank + '</span>'
                    + '<div style="flex:1"><strong>' + item.controlName.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</strong>'
                    + '<span style="color:var(--text2);font-size:.85rem;margin-left:.5rem">' + areaCount + ' area' + (areaCount === 1 ? '' : 's') + ' affected</span></div>'
                    + '<div style="text-align:right;min-width:80px"><span style="font-size:1.25rem;font-weight:800;color:' + color + '">' + item.count + '</span>'
                    + '<span style="font-size:.75rem;color:var(--text2);display:block">issue' + (item.count === 1 ? '' : 's') + '</span></div></li>';
            }

            function renderHotSpot(projectName, failCount, rank) {
                var urgency = failCount > 15 ? 'urgent' : failCount > 5 ? 'warning' : 'info';
                return '<li class="action-item action-' + urgency + '"><span class="action-rank">#' + rank + '</span><strong>'
                    + projectName.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                    + '</strong> &mdash; ' + failCount + ' best practice' + (failCount === 1 ? '' : 's') + ' to adopt</li>';
            }

            function refreshExecutiveSummary() {
                var state = readAcceptedState();
                var summary = summarizeControls(state);
                var accepted = summary.global.accepted;
                var totalControls = summary.global.pass + summary.global.fail + summary.global.notChecked + accepted;
                var passPct = totalControls > 0 ? Math.round((summary.global.pass * 100) / totalControls) : 0;
                var failPct = totalControls > 0 ? Math.round((summary.global.fail * 100) / totalControls) : 0;
                var ncPct = totalControls > 0 ? Math.round((summary.global.notChecked * 100) / totalControls) : 0;
                var level = getRiskLevel(summary.global.fail, summary.projects);

                updateText('[data-kpi-risk]', level);
                var riskEl = document.querySelector('[data-kpi-risk]');
                if (riskEl) {
                    riskEl.style.color = riskColor(level);
                    riskEl.setAttribute('aria-label', 'Adoption level ' + level);
                }
                updateText('[data-kpi-pass]', summary.global.pass);
                updateText('[data-kpi-fail]', summary.global.fail);
                updateText('[data-kpi-nc]', summary.global.notChecked);
                updateText('[data-kpi-accepted]', accepted);

                var acceptedCard = document.querySelector('[data-kpi-accepted-card]');
                if (acceptedCard) { acceptedCard.hidden = accepted === 0; }

                updateText('[data-adoption-pass-pct]', passPct + '%');
                updateText('[data-summary-total]', totalControls);
                updateHtml('[data-summary-pass-text]', '&#9679; ' + summary.global.pass + ' adopted (' + passPct + '%)');
                updateHtml('[data-summary-fail-text]', '&#9679; ' + summary.global.fail + ' opportunities (' + failPct + '%)');
                updateHtml('[data-summary-nc-text]', '&#9679; ' + summary.global.notChecked + ' not checked (' + ncPct + '%)');

                var acceptedText = document.querySelector('[data-summary-accepted-text]');
                if (acceptedText) {
                    acceptedText.hidden = accepted === 0;
                    acceptedText.innerHTML = '&nbsp;&#9679; ' + accepted + ' accepted';
                }

                updateText('[data-org-pass]', summary.org.pass);
                updateText('[data-org-fail]', summary.org.fail);
                updateText('[data-org-nc]', summary.org.notChecked);

                Array.prototype.forEach.call(document.querySelectorAll('[data-project-row]'), function (row) {
                    var projectName = row.getAttribute('data-project-row');
                    var project = summary.projects[projectName] || { pass: 0, fail: 0, notChecked: 0, accepted: 0 };
                    var projectTotal = project.pass + project.fail + project.notChecked + project.accepted;
                    var projectPassPct = projectTotal > 0 ? Math.round((project.pass * 100) / projectTotal) : 0;
                    var passCell = row.querySelector('[data-project-pass]');
                    var failCell = row.querySelector('[data-project-fail]');
                    var ncCell = row.querySelector('[data-project-nc]');
                    var progress = row.querySelector('[data-project-progress]');
                    var progressFill = row.querySelector('[data-project-progress-fill]');
                    var statusCell = row.querySelector('[data-project-status]');
                    if (passCell) { passCell.textContent = project.pass; }
                    if (failCell) { failCell.textContent = project.fail; }
                    if (ncCell) { ncCell.textContent = project.notChecked; }
                    if (progress) {
                        progress.setAttribute('aria-valuenow', String(projectPassPct));
                        progress.setAttribute('aria-label', projectPassPct + ' percent adopted');
                    }
                    if (progressFill) { progressFill.style.width = projectPassPct + '%'; }
                    if (statusCell) { statusCell.innerHTML = renderProjectStatus(project.fail); }
                });

                var activeRemediations = remediations.filter(function (item) { return !state[item.key]; });
                var topRemediations = activeRemediations.slice(0, 5);
                var totalRemediationItems = activeRemediations.reduce(function (sum, item) { return sum + (item.count || 0); }, 0);
                var topRemediationCount = topRemediations.reduce(function (sum, item) { return sum + (item.count || 0); }, 0);
                var topRemediationPct = totalRemediationItems > 0 ? Math.round((topRemediationCount * 100) / totalRemediationItems) : 0;
                updateText('[data-top-remediations-total-count]', totalRemediationItems);
                updateText('[data-top-remediations-top-count]', topRemediationCount);
                updateText('[data-top-remediations-top-pct]', topRemediationPct + '%');
                var topRemediationList = document.querySelector('[data-top-remediations-list]');
                var topRemediationEmpty = document.querySelector('[data-top-remediations-empty]');
                if (topRemediationList) {
                    topRemediationList.innerHTML = topRemediations.map(function (item, index) {
                        return renderTopRemediationItem(item, index + 1);
                    }).join('');
                }
                if (topRemediationEmpty) { topRemediationEmpty.hidden = topRemediations.length > 0; }

                var hotSpots = Object.keys(summary.projects)
                    .map(function (projectName) { return { project: projectName, fail: summary.projects[projectName].fail || 0 }; })
                    .filter(function (project) { return project.fail > 0; })
                    .sort(function (a, b) { return b.fail - a.fail; })
                    .slice(0, 10);
                var hotSpotList = document.querySelector('[data-hot-spots-list]');
                var hotSpotEmpty = document.querySelector('[data-hot-spots-empty]');
                if (hotSpotList) {
                    hotSpotList.innerHTML = hotSpots.map(function (project, index) {
                        return renderHotSpot(project.project, project.fail, index + 1);
                    }).join('');
                }
                if (hotSpotEmpty) { hotSpotEmpty.hidden = hotSpots.length > 0; }
            }

            refreshExecutiveSummary();
            window.addEventListener('storage', refreshExecutiveSummary);
            document.addEventListener('visibilitychange', function () {
                if (!document.hidden) { refreshExecutiveSummary(); }
            });
        }());
  </script>
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
    $projects = Invoke-AdoApi -Uri "$OrgUrl/_apis/projects?api-version=7.1" -Header $Header
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
        $capVal = Get-OrgPolicyBoolean $cap
        if ($capVal -eq $true) {
            $results.Add((New-ControlResult -Id "AUTH-05" -Status "PASS" -Severity "Medium" -Control "Conditional Access Policy" -Finding "AAD Conditional Access Policy validation is enabled."))
        } elseif ($null -ne $cap) {
            $results.Add((New-ControlResult -Id "AUTH-05" -Status "FAIL" -Severity "Medium" -Control "Conditional Access Policy" -Finding "AAD Conditional Access Policy validation is not enabled. Enable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "AUTH-05" -Status "NOT CHECKED" -Severity "Medium" -Control "Conditional Access Policy" -Finding "Conditional access policy not found in org settings. May require Azure AD P1/P2."))
        }

        # OAUTH-01: Third-Party OAuth
        $oauth = $policyMap['Policy.DisallowOAuthAuthentication']
        $oauthVal = Get-OrgPolicyBoolean $oauth
        if ($oauthVal -eq $true) {
            $results.Add((New-ControlResult -Id "OAUTH-01" -Status "PASS" -Severity "Medium" -Control "Third-Party OAuth Disabled" -Finding "Third-party application access via OAuth is disabled."))
        } elseif ($null -ne $oauth) {
            $results.Add((New-ControlResult -Id "OAUTH-01" -Status "FAIL" -Severity "Medium" -Control "Third-Party OAuth Disabled" -Finding "Third-party application access via OAuth is enabled. Disable unless required."))
        } else {
            $results.Add((New-ControlResult -Id "OAUTH-01" -Status "NOT CHECKED" -Severity "Medium" -Control "Third-Party OAuth Disabled" -Finding "OAuth policy not found."))
        }

        # OAUTH-02: SSH
        $ssh = $policyMap['Policy.DisallowSecureShell']
        $sshVal = Get-OrgPolicyBoolean $ssh
        if ($sshVal -eq $true) {
            $results.Add((New-ControlResult -Id "OAUTH-02" -Status "PASS" -Severity "Medium" -Control "SSH Access Disabled" -Finding "SSH authentication is disabled."))
        } elseif ($null -ne $ssh) {
            $results.Add((New-ControlResult -Id "OAUTH-02" -Status "FAIL" -Severity "Medium" -Control "SSH Access Disabled" -Finding "SSH authentication is enabled. Disable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "OAUTH-02" -Status "NOT CHECKED" -Severity "Medium" -Control "SSH Access Disabled" -Finding "SSH policy not found."))
        }

        # ACCESS-02: Request Access
        $requestAccess = $policyMap['Policy.AllowRequestAccessToken']
        $raVal = Get-OrgPolicyBoolean $requestAccess
        if ($raVal -eq $false) {
            $results.Add((New-ControlResult -Id "ACCESS-02" -Status "PASS" -Severity "Medium" -Control "Request Access Policy Disabled" -Finding "Request access policy is disabled."))
        } elseif ($null -ne $requestAccess) {
            $results.Add((New-ControlResult -Id "ACCESS-02" -Status "FAIL" -Severity "Medium" -Control "Request Access Policy Disabled" -Finding "Request access policy is enabled. Disable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "ACCESS-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Request Access Policy Disabled" -Finding "Request access policy not found."))
        }

        # ACCESS-03: Invite New Users
        $invite = $policyMap['Policy.AllowTeamMembersToInviteNewUsers']
        $invVal = Get-OrgPolicyBoolean $invite
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
            $eaVal = Get-OrgPolicyBoolean $enterpriseAccess
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
        $patLifeVal = Get-OrgPolicyBoolean $patLifetime
        if ($patLifeVal -eq $true) {
            $results.Add((New-ControlResult -Id "PATPOL-01" -Status "PASS" -Severity "Medium" -Control "Maximum PAT Lifetime Policy" -Finding "Maximum PAT lifetime policy is enforced."))
        } elseif ($null -ne $patLifetime) {
            $results.Add((New-ControlResult -Id "PATPOL-01" -Status "FAIL" -Severity "Medium" -Control "Maximum PAT Lifetime Policy" -Finding "Maximum PAT lifetime policy is not enforced. Enable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "PATPOL-01" -Status "NOT CHECKED" -Severity "Medium" -Control "Maximum PAT Lifetime Policy" -Finding "PAT lifetime policy not found in org policies."))
        }

        # PATPOL-02: Restrict PAT Scope
        $patScope = $policyMap['Policy.EnforcePatScopeRestriction']
        $patScopeVal = Get-OrgPolicyBoolean $patScope
        if ($patScopeVal -eq $true) {
            $results.Add((New-ControlResult -Id "PATPOL-02" -Status "PASS" -Severity "Medium" -Control "Restrict PAT Scope" -Finding "PAT scope restriction policy is enforced."))
        } elseif ($null -ne $patScope) {
            $results.Add((New-ControlResult -Id "PATPOL-02" -Status "FAIL" -Severity "Medium" -Control "Restrict PAT Scope" -Finding "PAT scope restriction policy is not enforced. Enable via Organization Settings > Policies."))
        } else {
            $results.Add((New-ControlResult -Id "PATPOL-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Restrict PAT Scope" -Finding "PAT scope restriction policy not found in org policies."))
        }

        # PATPOL-03: Restrict Global PATs
        $patGlobal = $policyMap['Policy.DisallowFullScopePats']
        $patGlobalVal = Get-OrgPolicyBoolean $patGlobal
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
        $pcaMembers = @(Get-AdoGraphGroupMembers -OrgUrl $OrgUrl -Header $Header -GroupDescriptor $pcaGroup.descriptor)
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
        $pcsaMembers = @(Get-AdoGraphGroupMembers -OrgUrl $OrgUrl -Header $Header -GroupDescriptor $pcsaGroup.descriptor)
        $pcsaCount = $pcsaMembers.Count
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
    $installedInventory = [System.Collections.Generic.List[PSCustomObject]]::new()
    $requestedInventory = [System.Collections.Generic.List[PSCustomObject]]::new()
    $installedAvailable = $false
    $requestedAvailable = $false

    Write-Progress -Activity "Org Assessment" -Status "Checking extensions..."

    $extensions = Invoke-AdoApi -Uri "$($script:ExtMgmtUrl)/_apis/extensionmanagement/installedextensions?api-version=7.1-preview.1" -Header $Header

    if ($extensions -and $extensions.value) {
        $installedAvailable = $true
        $extList = $extensions.value
        foreach ($ext in $extList) {
            $installState = Get-SafeProperty $ext 'installState'
            $installFlags = Get-SafeProperty $installState 'flags'
            $extFlags = Get-SafeProperty $ext 'flags'
            $isBuiltIn = $installFlags -and $installFlags -imatch 'BuiltIn'
            $isTrusted = $extFlags -and $extFlags -imatch 'trusted'
            $isMicrosoft = (Get-SafeProperty $ext 'publisherName') -ieq 'Microsoft'
            $installedInventory.Add([PSCustomObject]@{
                Name        = (Get-SafeProperty $ext 'extensionName')
                Publisher   = (Get-SafeProperty $ext 'publisherName')
                Version     = (Get-SafeProperty $ext 'version')
                IsBuiltIn   = [bool]$isBuiltIn
                IsTrusted   = [bool]$isTrusted
                IsMicrosoft = [bool]$isMicrosoft
                InstallFlags = [string]$installFlags
            })
        }
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
    if ($requested -and $requested.PSObject.Properties['value']) {
        $requestedAvailable = $true
        foreach ($req in @($requested.value)) {
            $requestedInventory.Add([PSCustomObject]@{
                Name      = (Get-SafeProperty $req 'extensionName')
                Publisher = (Get-SafeProperty $req 'publisherName')
                Status    = (Get-SafeProperty $req 'requestState')
            })
        }
    }
    if ($requestedAvailable -and $requestedInventory.Count -gt 0) {
        $results.Add((New-ControlResult -Id "EXT-04" -Status "FAIL" -Severity "High" -Control "Requested Extensions Review" -Finding "$($requestedInventory.Count) pending extension request(s). Review and approve or deny."))
    } elseif ($requestedAvailable) {
        $results.Add((New-ControlResult -Id "EXT-04" -Status "PASS" -Severity "High" -Control "Requested Extensions Review" -Finding "No pending extension requests."))
    } else {
        $results.Add((New-ControlResult -Id "EXT-04" -Status "NOT CHECKED" -Severity "High" -Control "Requested Extensions Review" -Finding "Could not retrieve pending extension requests."))
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

    return [PSCustomObject]@{
        Results = $results
        Inventory = [PSCustomObject]@{
            InstalledAvailable = $installedAvailable
            RequestedAvailable = $requestedAvailable
            Installed = @($installedInventory)
            Requested = @($requestedInventory)
        }
    }
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

    # FEED-03: External package protection — upstreams can't be assessed reliably via API.
    # The real mitigation (save-to-feed / package source protection) isn't surfaced in the
    # feed payload, so flag feeds with active upstreams as advisory rather than FAIL.
    if ($feeds -and $feeds.value -and $feeds.value.Count -gt 0) {
        $feedsWithUpstreams = [System.Collections.Generic.List[string]]::new()
        foreach ($feed in $feeds.value) {
            $upstreamEnabled = Get-SafeProperty $feed 'upstreamEnabled'
            $upstreamSources = Get-SafeProperty $feed 'upstreamSources'
            if ($upstreamEnabled -eq $true -and $upstreamSources) {
                foreach ($src in $upstreamSources) {
                    $status = Get-SafeProperty $src 'status'
                    if ($status -ne 'disabled') {
                        $feedsWithUpstreams.Add($feed.name)
                        break
                    }
                }
            }
        }
        if ($feedsWithUpstreams.Count -eq 0) {
            $results.Add((New-ControlResult -Id "FEED-03" -Status "PASS" -Severity "Medium" -Control "External Package Protection" -Finding "No org-scoped feeds have active upstream sources."))
        } else {
            $results.Add((New-ControlResult -Id "FEED-03" -Status "NOT CHECKED" -Severity "Medium" -Control "External Package Protection" -Finding "Feeds with active upstream sources: $($feedsWithUpstreams -join ', '). Upstreams are typically required for npm/NuGet/Maven; the dependency-confusion mitigation is to publish every internal package name to the feed at least once (save-to-feed makes the local copy win over upstream). Verify each internal package name is saved, and accept this control if the mitigation is in place."))
        }
    } else {
        $results.Add((New-ControlResult -Id "FEED-03" -Status "PASS" -Severity "Medium" -Control "External Package Protection" -Finding "No org-scoped feeds found."))
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
    $encodedProjectName = [System.Uri]::EscapeDataString($ProjectName)
    $projectInfo = Invoke-AdoApi -Uri "$OrgUrl/_apis/projects/$encodedProjectName`?api-version=7.1" -Header $Header
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
    $groups = if ($projectInfo) { Get-AdoGraphProjectGroups -OrgUrl $OrgUrl -ProjectId $projectInfo.id -Header $Header } else { @() }
    $paGroup = $null
    $baGroup = $null
    if ($groups) {
        $paGroup = $groups | Where-Object { $_.displayName -eq 'Project Administrators' } | Select-Object -First 1
        $baGroup = $groups | Where-Object { $_.displayName -eq 'Build Administrators' } | Select-Object -First 1
    }

    $paMembers = @()
    if ($paGroup) {
        $paMembers = @(Get-AdoGraphGroupMembers -OrgUrl $OrgUrl -Header $Header -GroupDescriptor $paGroup.descriptor)
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
        $baMembers = @(Get-AdoGraphGroupMembers -OrgUrl $OrgUrl -Header $Header -GroupDescriptor $baGroup.descriptor)
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

    # PERM-01 through PERM-08: Broader-group permissions at project default scope
    # for each pipeline-related resource type. We query the relevant security
    # namespace's ACL at the project-default token, resolve each ACE descriptor
    # to a display name, and FAIL the control if any "broad" group (Contributors,
    # Project Valid Users, Project Collection Valid Users, Build Service, etc.)
    # holds elevated allow bits (anything beyond pure View/Read).
    #
    # PERM-04 (Agent Pool) and PERM-08 (Environment) stay NOT CHECKED here
    # because they require per-pool / per-environment ACL enumeration that
    # doesn't fit the single project-default-token pattern; those are tracked
    # for Phase 2b.

    $projectIdForAcl = if ($projectInfo) { $projectInfo.id } else { $null }

    $permAclChecks = @(
        @{ Id = 'PERM-01'; NamespaceName = 'Build';             Control = 'Build Pipeline Inherited Permissions';   Action = "Project Settings > Pipelines > Builds > Security"; TokenBuilder = { param($projId) $projId } }
        @{ Id = 'PERM-02'; NamespaceName = 'ReleaseManagement'; Control = 'Release Pipeline Inherited Permissions'; Action = "Project Settings > Pipelines > Releases > Security"; TokenBuilder = { param($projId) $projId } }
        @{ Id = 'PERM-03'; NamespaceName = 'ServiceEndpoints';  Control = 'Service Connection Inherited Permissions'; Action = "Project Settings > Service Connections > Security"; TokenBuilder = { param($projId) "endpoints/$projId" } }
        @{ Id = 'PERM-05'; NamespaceName = 'Library';           Control = 'Variable Group Inherited Permissions';   Action = "Pipelines > Library > Security"; TokenBuilder = { param($projId) "Library/$projId" } }
        @{ Id = 'PERM-06'; NamespaceName = 'Git Repositories';  Control = 'Repository Inherited Permissions';       Action = "Project Settings > Repositories > Security"; TokenBuilder = { param($projId) "repoV2/$projId" } }
        @{ Id = 'PERM-07'; NamespaceName = 'Library';           Control = 'Secure File Inherited Permissions';      Action = "Pipelines > Library > Secure files > Security"; TokenBuilder = { param($projId) "Library/$projId" } }
    )

    foreach ($chk in $permAclChecks) {
        if (-not $projectIdForAcl) {
            $results.Add((New-ControlResult -Id $chk.Id -Status "NOT CHECKED" -Severity "High" -Control $chk.Control -Finding "Project ID unavailable; ACL probe skipped."))
            continue
        }
        $token = & $chk.TokenBuilder $projectIdForAcl
        try {
            $offenders = Find-BroadGroupAclOffenders -OrgUrl $OrgUrl -Header $Header -NamespaceName $chk.NamespaceName -Token $token
        } catch {
            $offenders = $null
        }
        if ($null -eq $offenders) {
            $results.Add((New-ControlResult -Id $chk.Id -Status "NOT CHECKED" -Severity "High" -Control $chk.Control -Finding "Could not retrieve ACL for namespace '$($chk.NamespaceName)' at token '$token'."))
        } elseif ($offenders.Count -eq 0) {
            $results.Add((New-ControlResult -Id $chk.Id -Status "PASS" -Severity "High" -Control $chk.Control -Finding "No broader group holds elevated permissions at the project default scope."))
        } else {
            $list = ($offenders | Select-Object -First 5) -join '; '
            $more = if ($offenders.Count -gt 5) { " (+$($offenders.Count - 5) more)" } else { "" }
            $results.Add((New-ControlResult -Id $chk.Id -Status "FAIL" -Severity "High" -Control $chk.Control -Finding "$($offenders.Count) broader-group ACE(s) hold elevated permissions: $list$more. Restrict via $($chk.Action)."))
        }
    }

    # PERM-04: Agent Pool — per-pool ACL enumeration deferred to Phase 2b.
    $results.Add((New-ControlResult -Id "PERM-04" -Status "NOT CHECKED" -Severity "High" -Control "Agent Pool Inherited Permissions" -Finding "Requires per-pool ACL enumeration against the DistributedTask namespace; not yet automated. Manually review Project Settings > Agent pools > Security for each pool to confirm no broader group has Use/Manage/Administer."))

    # PERM-08: Environment — per-environment ACL enumeration deferred to Phase 2b.
    $results.Add((New-ControlResult -Id "PERM-08" -Status "NOT CHECKED" -Severity "High" -Control "Environment Inherited Permissions" -Finding "Requires per-environment ACL enumeration against the Environment namespace; not yet automated. Manually review Pipelines > Environments > Security for each environment to confirm no broader group has Use/Manage/Administer."))

    # PERM-09: Project-level "Create repository" permission. Probe the Git
    # Repositories namespace at the project-root token and look specifically
    # for the CreateRepository action bit being allowed to any broader group.
    if ($projectIdForAcl) {
        $createRepoOffenders = $null
        $perm09Err = $null
        try {
            $createRepoOffenders = Find-BroadGroupAclOffenders -OrgUrl $OrgUrl -Header $Header -NamespaceName 'Git Repositories' -Token "repoV2/$projectIdForAcl" -RequiredActionNames @('CreateRepository')
        } catch {
            $perm09Err = $_.Exception.Message
            $createRepoOffenders = $null
        }
        if ($null -eq $createRepoOffenders) {
            $detail = if ($perm09Err) { "Could not retrieve Git Repositories ACL for project root ($perm09Err)." } else { "Could not retrieve Git Repositories ACL for project root." }
            $results.Add((New-ControlResult -Id "PERM-09" -Status "NOT CHECKED" -Severity "Medium" -Control "Repository Creation Permission" -Finding $detail))
        } elseif ($createRepoOffenders.Count -eq 0) {
            $results.Add((New-ControlResult -Id "PERM-09" -Status "PASS" -Severity "Medium" -Control "Repository Creation Permission" -Finding "No broader group has 'Create repository' allowed at project scope."))
        } else {
            $list = ($createRepoOffenders | Select-Object -First 5) -join '; '
            $results.Add((New-ControlResult -Id "PERM-09" -Status "FAIL" -Severity "Medium" -Control "Repository Creation Permission" -Finding "$($createRepoOffenders.Count) broader-group ACE(s) granted 'Create repository': $list. Restrict via Project Settings > Repositories > Security."))
        }
    } else {
        $results.Add((New-ControlResult -Id "PERM-09" -Status "NOT CHECKED" -Severity "Medium" -Control "Repository Creation Permission" -Finding "Project ID unavailable; CreateRepository ACL probe skipped."))
    }

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
    $orgPipeSettings = Invoke-AdoApi -Uri "$OrgUrl/_apis/build/generalsettings?api-version=7.1-preview.1" -Header $Header
    $projectPipeSettings = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/build/generalsettings?api-version=7.1-preview.1" -Header $Header

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
        $lastRun = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/build/builds?definitions=$defId&`$top=1&queryOrder=finishTimeDescending&api-version=7.1" -Header $Header
        [array]$lastRunArr = @()
        if ($lastRun -and $lastRun.value) { [array]$lastRunArr = @($lastRun.value) }
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
        $effectiveAuthScope = Get-EffectiveJobAuthorizationScope -DefinitionScope $defAuthScope -IsRelease:$false -ProjectPipelineSettings $projectPipeSettings -OrgPipelineSettings $orgPipeSettings
        if ($effectiveAuthScope -and $effectiveAuthScope.Scope) {
            if ($effectiveAuthScope.Scope -ieq 'projectScoped') {
                if ($effectiveAuthScope.Source -ieq 'pipeline-setting') {
                    $results.Add((New-ControlResult -Id "BUILD-11" -Status "PASS" -Severity "Medium" -Control "Pipeline Authorization Scope" -Finding "$prefix — Authorization scope is project-scoped."))
                } elseif ($effectiveAuthScope.Source -ieq 'project-setting') {
                    $results.Add((New-ControlResult -Id "BUILD-11" -Status "PASS" -Severity "Medium" -Control "Pipeline Authorization Scope" -Finding "$prefix — Effective authorization scope is project-scoped via project pipeline settings."))
                } elseif ($effectiveAuthScope.Source -ieq 'org-setting') {
                    $results.Add((New-ControlResult -Id "BUILD-11" -Status "PASS" -Severity "Medium" -Control "Pipeline Authorization Scope" -Finding "$prefix — Effective authorization scope is project-scoped via org pipeline settings."))
                } else {
                    $results.Add((New-ControlResult -Id "BUILD-11" -Status "PASS" -Severity "Medium" -Control "Pipeline Authorization Scope" -Finding "$prefix — Effective authorization scope is project-scoped."))
                }
            } else {
                $results.Add((New-ControlResult -Id "BUILD-11" -Status "FAIL" -Severity "Medium" -Control "Pipeline Authorization Scope" -Finding "$prefix — Effective authorization scope is '$($effectiveAuthScope.Scope)' (source: $($effectiveAuthScope.Source)). Set to 'Current project'."))
            }
        } else {
            $results.Add((New-ControlResult -Id "BUILD-11" -Status "NOT CHECKED" -Severity "Medium" -Control "Pipeline Authorization Scope" -Finding "$prefix — Could not determine effective authorization scope from pipeline/project/org settings."))
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
    $orgPipeSettings = Invoke-AdoApi -Uri "$OrgUrl/_apis/build/generalsettings?api-version=7.1-preview.1" -Header $Header
    $projectPipeSettings = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/build/generalsettings?api-version=7.1-preview.1" -Header $Header
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

        # REL-09: Release job authorization scope
        # Parallel to BUILD-11 — guards against the release identity reaching
        # resources in other projects across the same collection.
        $defAuthScope = Get-SafeProperty $def 'jobAuthorizationScope'
        $effectiveAuthScope = Get-EffectiveJobAuthorizationScope -DefinitionScope $defAuthScope -IsRelease:$true -ProjectPipelineSettings $projectPipeSettings -OrgPipelineSettings $orgPipeSettings
        if ($effectiveAuthScope -and $effectiveAuthScope.Scope) {
            if ($effectiveAuthScope.Scope -ieq 'projectCollection') {
                $results.Add((New-ControlResult -Id "REL-09" -Status "FAIL" -Severity "Medium" -Control "Release Authorization Scope" -Finding "$prefix — Effective authorization scope is '$($effectiveAuthScope.Scope)' (source: $($effectiveAuthScope.Source)). Set to 'Current project' so the release identity cannot reach resources in other projects."))
            } else {
                if ($effectiveAuthScope.Source -ieq 'project-setting') {
                    $results.Add((New-ControlResult -Id "REL-09" -Status "PASS" -Severity "Medium" -Control "Release Authorization Scope" -Finding "$prefix — Effective authorization scope is '$($effectiveAuthScope.Scope)' via project pipeline settings."))
                } elseif ($effectiveAuthScope.Source -ieq 'org-setting') {
                    $results.Add((New-ControlResult -Id "REL-09" -Status "PASS" -Severity "Medium" -Control "Release Authorization Scope" -Finding "$prefix — Effective authorization scope is '$($effectiveAuthScope.Scope)' via org pipeline settings."))
                } else {
                    $results.Add((New-ControlResult -Id "REL-09" -Status "PASS" -Severity "Medium" -Control "Release Authorization Scope" -Finding "$prefix — Authorization scope is '$($effectiveAuthScope.Scope)'."))
                }
            }
        } else {
            $results.Add((New-ControlResult -Id "REL-09" -Status "NOT CHECKED" -Severity "Medium" -Control "Release Authorization Scope" -Finding "$prefix — Could not determine effective authorization scope from pipeline/project/org settings."))
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

        $detail = $ep
        if (-not $detail.authorization -or -not $detail.PSObject.Properties['isShared']) {
            $detail = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/serviceendpoint/endpoints/${epId}?api-version=7.1" -Header $Header
        }
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
    $poolMap = @{}
    $poolList = Invoke-AdoApi -Uri "$OrgUrl/_apis/distributedtask/pools?api-version=7.1" -Header $Header
    if ($poolList -and $poolList.value) {
        foreach ($poolItem in $poolList.value) {
            $poolMap[[string]$poolItem.id] = $poolItem
        }
    }

    foreach ($queue in $queues.value) {
        $poolId = $queue.pool.id
        $queueId = $queue.id
        if ($poolsChecked.ContainsKey($poolId)) { continue }
        $poolsChecked[$poolId] = $true

        $poolName = $queue.pool.name
        $prefix = "Pool '$poolName'"

        $pool = if ($poolMap.ContainsKey([string]$poolId)) { $poolMap[[string]$poolId] } else { $queue.pool }
        if (-not $pool -or -not $pool.PSObject.Properties['autoProvision'] -or ($pool.isHosted -eq $false -and -not $pool.PSObject.Properties['autoUpdate'])) {
            $pool = Invoke-AdoApi -Uri "$OrgUrl/_apis/distributedtask/pools/${poolId}?api-version=7.1" -Header $Header
        }
        if (-not $pool) { continue }

        # AP-01, AP-02: Manual for self-hosted
        if ($pool.isHosted -eq $false) {
            $results.Add((New-ControlResult -Id "AP-01" -Status "NOT CHECKED" -Severity "High" -Control "Security Patches on Self-Hosted VMs" -Finding "$prefix — Self-hosted pool. Manual review required for patch status."))
            $results.Add((New-ControlResult -Id "AP-02" -Status "NOT CHECKED" -Severity "Medium" -Control "Hardened OS Image" -Finding "$prefix — Self-hosted pool. Manual review required for OS hardening."))
        }

        # AP-04: Auto-provisioning.
        # Only flag self-hosted pools. Microsoft-hosted pools (Azure Pipelines,
        # Hosted macOS, Hosted Ubuntu, Hosted Windows, etc.) default to
        # autoProvision=true by design — they are isolated, ephemeral VMs
        # managed by Microsoft, so auto-provisioning to new projects does not
        # expand the customer's attack surface in a meaningful way. The
        # AzSK/SDL control targets self-hosted pools where auto-provision
        # could expose a customer-managed build farm to new projects.
        if ($pool.isHosted -eq $true) {
            $results.Add((New-ControlResult -Id "AP-04" -Status "PASS" -Severity "High" -Control "Auto-Provisioning Disabled" -Finding "$prefix — Microsoft-hosted pool; auto-provision is Microsoft-managed and not a customer-side security concern."))
        } elseif ($pool.autoProvision -eq $true) {
            $results.Add((New-ControlResult -Id "AP-04" -Status "FAIL" -Severity "High" -Control "Auto-Provisioning Disabled" -Finding "$prefix — Auto-provision is enabled on a self-hosted pool. Disable and grant access per-project."))
        } else {
            $results.Add((New-ControlResult -Id "AP-04" -Status "PASS" -Severity "High" -Control "Auto-Provisioning Disabled" -Finding "$prefix — Auto-provision is disabled."))
        }

        # AP-05: Accessible to all pipelines.
        # Same reasoning as AP-04: Microsoft-hosted pools (Azure Pipelines,
        # Hosted Ubuntu/macOS/Windows, etc.) default to "open to all
        # pipelines" by design. The agents are isolated, ephemeral, and
        # Microsoft-managed, so broad pipeline access does not expose
        # customer infrastructure. The AzSK/SDL control targets self-hosted
        # pools where unauthorized pipelines could reach internal networks
        # or persisted credentials on the agent.
        $pipePerms = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/pipelines/pipelinePermissions/queue/${queueId}?api-version=7.1-preview.1" -Header $Header
        if ($pool.isHosted -eq $true) {
            $results.Add((New-ControlResult -Id "AP-05" -Status "PASS" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Microsoft-hosted pool; broad pipeline access is the Microsoft-managed default and not a customer-side security concern."))
        } elseif ($pipePerms -and ($pipePerms.PSObject.Properties['allPipelines']) -and $pipePerms.allPipelines.authorized -eq $true) {
            $results.Add((New-ControlResult -Id "AP-05" -Status "FAIL" -Severity "High" -Control "Not Accessible to All YAML Pipelines" -Finding "$prefix — Self-hosted pool accessible to ALL pipelines. Restrict to specific pipelines."))
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
    if ($repos.Count -gt 3 -and $PSVersionTable.PSVersion.Major -ge 7 -and $MaxParallel -gt 1) {
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
        } -ThrottleLimit $MaxParallel

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

    # === PER-REPO REPOSITORY POLICIES (REPO-06, REPO-07) ===
    # Granular per-repo equivalents of PROJ-14 (credential scanner) and
    # PROJ-15 (commit author email validation). The project-level checks
    # PASS when the policy exists anywhere in the project; REPO-06/07
    # confirm it is actually enabled for each repo's default branch.
    $repoPolicyTypes = @(
        @{ Id = 'REPO-06'; NamePattern = 'credential|secret|push protection'; Severity = 'High';   Control = 'Per-Repository Credentials & Secrets Policy'; Action = "Enable GHAzDO push-protection or a credential-scanner policy scoped to this repo's default branch." }
        @{ Id = 'REPO-07'; NamePattern = 'commit author email';               Severity = 'Medium'; Control = 'Per-Repository Author Email Validation';      Action = "Enable the 'Commit author email validation' branch policy on this repo's default branch via Project Settings > Repos > Policies." }
    )

    foreach ($rp in $repoPolicyTypes) {
        $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($entry in $policiesByNamePattern) {
            if ($entry.Name -imatch $rp.NamePattern) { $candidates.Add($entry.Policy) }
        }

        $missing      = [System.Collections.Generic.List[string]]::new()
        $reposChecked = 0
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
            $results.Add((New-ControlResult -Id $rp.Id -Status 'NOT CHECKED' -Severity $rp.Severity -Control $rp.Control -Finding 'No repositories with a default branch were found to evaluate.'))
        }
        elseif ($missing.Count -eq 0) {
            $results.Add((New-ControlResult -Id $rp.Id -Status 'PASS' -Severity $rp.Severity -Control $rp.Control -Finding "All $reposChecked repository default branch(es) have the policy enabled."))
        }
        else {
            $missList = ($missing | Select-Object -First 10) -join ', '
            $results.Add((New-ControlResult -Id $rp.Id -Status 'FAIL' -Severity $rp.Severity -Control $rp.Control -Finding "$($missing.Count)/$reposChecked repository default branch(es) missing the policy: $missList. $($rp.Action)"))
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

    $rootFilesByRepo = @{}
    foreach ($repo in $repos) {
        $defaultBranch = Get-SafeProperty $repo 'defaultBranch'
        if (-not $defaultBranch) { continue }
        $branchName = $defaultBranch -replace '^refs/heads/', ''
        $rootUri = "$OrgUrl/$ProjectName/_apis/git/repositories/$($repo.id)/items?scopePath=/&recursionLevel=OneLevel&versionDescriptor.version=$branchName&versionDescriptor.versionType=branch&api-version=7.1"
        $rootItems = Invoke-AdoApi -Uri $rootUri -Header $Header
        $fileSet = @{}
        if ($rootItems -and $rootItems.value) {
            foreach ($item in $rootItems.value) {
                $path = Get-SafeProperty $item 'path'
                if ($path -and $path -ne '/') {
                    $leafName = Split-Path $path -Leaf
                    if ($leafName) { $fileSet[$leafName.ToUpperInvariant()] = $true }
                }
            }
        }
        $rootFilesByRepo[[string]$repo.id] = $fileSet
    }

    foreach ($check in $communityChecks) {
        $missing      = [System.Collections.Generic.List[string]]::new()
        $reposChecked = 0
        foreach ($repo in $repos) {
            $defaultBranch = Get-SafeProperty $repo 'defaultBranch'
            if (-not $defaultBranch) { continue }
            $reposChecked++

            $found = $false
            $fileSet = if ($rootFilesByRepo.ContainsKey([string]$repo.id)) { $rootFilesByRepo[[string]$repo.id] } else { @{} }
            foreach ($fileName in $check.FileNames) {
                if ($fileSet.ContainsKey($fileName.ToUpperInvariant())) {
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

        # ENV-03/04/05: Production environment posture
        # ENV-03 — approval check present
        # ENV-04 — effective required approvers >= 2 (uses minRequiredApprovers
        #          when set; otherwise approver-list count, since 0 means
        #          "all listed approvers must approve")
        # ENV-05 — branch-control check restricts deployments to a protected
        #          branch (surfaces as a Task Check with a definitionRef of
        #          'evaluatebranchProtection' or a displayName containing
        #          'branch control')
        if (Test-IsProductionStage $envName) {
            # Environment-level approval and Task Check (branch control) checks
            # are NOT returned by the Environments Get endpoint. They must be
            # fetched via the Approvals-and-Checks "Check Configurations" API,
            # which returns a typed list keyed to the environment resource and
            # supports ?$expand=settings to surface approver/branch-control
            # details inline.
            $checksResp = Invoke-AdoApi -Uri "$OrgUrl/$ProjectName/_apis/pipelines/checks/configurations?resourceType=environment&resourceId=${envId}&`$expand=settings&api-version=7.1-preview.1" -Header $Header
            $approvalCheck    = $null
            $hasBranchControl = $false
            if ($checksResp -and $checksResp.value) {
                foreach ($check in $checksResp.value) {
                    # Skip explicitly disabled checks — they do not enforce anything.
                    if ((Get-SafeProperty $check 'isDisabled') -eq $true) { continue }
                    $checkTypeName = Get-SafeProperty (Get-SafeProperty $check 'type') 'name'
                    if (-not $approvalCheck -and $checkTypeName -and $checkTypeName -imatch 'approval') {
                        $approvalCheck = $check
                    }
                    if (-not $hasBranchControl) {
                        $settingsObj  = Get-SafeProperty $check 'settings'
                        $defRefObj    = Get-SafeProperty $settingsObj 'definitionRef'
                        $defRefName   = Get-SafeProperty $defRefObj 'name'
                        $displayName  = Get-SafeProperty $settingsObj 'displayName'
                        if (($defRefName -and $defRefName -imatch 'branch') -or ($displayName -and $displayName -imatch 'branch control')) {
                            $hasBranchControl = $true
                        }
                    }
                }
            }

            # ENV-03
            if ($approvalCheck) {
                $results.Add((New-ControlResult -Id "ENV-03" -Status "PASS" -Severity "High" -Control "Production Approvals" -Finding "$prefix — Approval checks configured."))
            } else {
                $results.Add((New-ControlResult -Id "ENV-03" -Status "FAIL" -Severity "High" -Control "Production Approvals" -Finding "$prefix — No approval checks on production environment. Add approval checks."))
            }

            # ENV-04
            if ($approvalCheck) {
                $approvalSettings = Get-SafeProperty $approvalCheck 'settings'
                $approvers        = @(Get-SafeProperty $approvalSettings 'approvers')
                $approverCount    = ($approvers | Where-Object { $_ } | Measure-Object).Count
                $minRequiredRaw   = Get-SafeProperty $approvalSettings 'minRequiredApprovers'
                $minRequired      = 0
                if ($null -ne $minRequiredRaw) { [int]::TryParse([string]$minRequiredRaw, [ref]$minRequired) | Out-Null }
                $effectiveRequired = if ($minRequired -gt 0) { $minRequired } else { $approverCount }
                if ($effectiveRequired -ge 2) {
                    $results.Add((New-ControlResult -Id "ENV-04" -Status "PASS" -Severity "High" -Control "Multiple Approvers on Production" -Finding "$prefix — Effective required approvers: $effectiveRequired (approvers configured: $approverCount, minRequired: $minRequired)."))
                } else {
                    $results.Add((New-ControlResult -Id "ENV-04" -Status "FAIL" -Severity "High" -Control "Multiple Approvers on Production" -Finding "$prefix — Only $effectiveRequired effective approver(s) (approvers configured: $approverCount, minRequired: $minRequired). Configure at least 2 distinct approvers to prevent single-point bypass."))
                }
            } else {
                $results.Add((New-ControlResult -Id "ENV-04" -Status "FAIL" -Severity "High" -Control "Multiple Approvers on Production" -Finding "$prefix — No approval check exists; cannot satisfy multi-approver requirement."))
            }

            # ENV-05
            if ($hasBranchControl) {
                $results.Add((New-ControlResult -Id "ENV-05" -Status "PASS" -Severity "High" -Control "Branch Control on Production" -Finding "$prefix — Branch control check is configured."))
            } else {
                $results.Add((New-ControlResult -Id "ENV-05" -Status "FAIL" -Severity "High" -Control "Branch Control on Production" -Finding "$prefix — No Branch control check found. Add a Branch control check restricting deployments to a protected production branch."))
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

if ($MaxParallel -gt 1 -and $projectNames.Count -ge 1 -and $PSVersionTable.PSVersion.Major -ge 7) {
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
    $projectCount = $projectNames.Count
    $projectWorkerBudget = 6
    $allFunctionDefs = (Get-ChildItem Function: | Where-Object {
        $_.Name -match '^(Invoke-AdoApi|Invoke-AzCli|New-ControlResult|Test-|Get-Safe|Get-Effective|Get-Ado|Get-Ace|Get-OrgPolicyBoolean|Convert-ToBooleanOrNull|Find-BroadGroup|Get-ControlCategory|Write-Assessment|Add-ResultsSafe)'
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
        BroadAclExtras     = $script:BroadAclExtras
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
        `$script:BroadAclExtras     = `$cfg.BroadAclExtras
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
        $script:BroadAclExtras     = $cfg.BroadAclExtras
        $script:ProductionKeywords = $cfg.ProductionKeywords
        $script:VsspsUrl           = $cfg.VsspsUrl
        $script:ExtMgmtUrl         = $cfg.ExtMgmtUrl
        $script:AuditUrl           = $cfg.AuditUrl
        $script:FeedsUrl           = $cfg.FeedsUrl

        $orgResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $orgTimings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $orgExtensionsInventory = [PSCustomObject]@{
            InstalledAvailable = $false
            RequestedAvailable = $false
            Installed = @()
            Requested = @()
        }

        $orgTimings.Add([PSCustomObject]@{ Name='OrgPolicies'; Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgPolicies -OrgUrl $orgUrl -Header $hdr) }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='OrgUsers';    Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgUsers -OrgUrl $orgUrl -Header $hdr -IncludeGraphCheck:$graphCheck) }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='OrgAdmins';   Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgAdmins -OrgUrl $orgUrl -Header $hdr) }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='OrgExtensions';Ms=(Measure-Command {
            $orgExtensionsData = Test-OrgExtensions -OrgUrl $orgUrl -Header $hdr
            if ($orgExtensionsData -and $orgExtensionsData.PSObject.Properties['Results']) {
                Add-ResultsSafe $orgResults $orgExtensionsData.Results
                if ($orgExtensionsData.PSObject.Properties['Inventory'] -and $orgExtensionsData.Inventory) {
                    $orgExtensionsInventory = $orgExtensionsData.Inventory
                }
            } else {
                Add-ResultsSafe $orgResults $orgExtensionsData
            }
        }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='OrgAudit';    Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgAudit -OrgUrl $orgUrl -Header $hdr) }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='OrgPipelineSettings';Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgPipelineSettings -OrgUrl $orgUrl -Header $hdr) }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='OrgFeeds';    Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgFeeds -OrgUrl $orgUrl -Header $hdr) }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='OrgPatPolicy';Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgPatPolicy -OrgUrl $orgUrl -Header $hdr) }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='UserPats';    Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-UserPats -OrgShortName $orgShort -Header $hdr) }).TotalMilliseconds })
        $orgTimings.Add([PSCustomObject]@{ Name='OrgWidePats'; Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgWidePats -OrgUrl $orgUrl -Header $hdr) }).TotalMilliseconds })

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
            OrgExtensions = $orgExtensionsInventory
            Timings    = $orgTimings
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
        $script:BroadAclExtras     = $cfg.BroadAclExtras
        $script:ProductionKeywords = $cfg.ProductionKeywords
        $script:VsspsUrl           = $cfg.VsspsUrl
        $script:ExtMgmtUrl         = $cfg.ExtMgmtUrl
        $script:AuditUrl           = $cfg.AuditUrl
        $script:FeedsUrl           = $cfg.FeedsUrl

        # Get project ID (needed by Test-Repositories)
        $projInfo = Invoke-AzCli -Command "devops project show --project `"$projName`" --org $orgUrl -o json"
        $projId = if ($projInfo) { $projInfo.id } else { "" }

        # Run all 10 check categories as parallel thread jobs within this project.
        # Each job returns @{ Name; Ms; Results } so we can report per-category timing.
        $baseArgs = @($funcDefs, $cfg, $orgUrl, $projName, $hdr, $null)
        $repoArgs = @($funcDefs, $cfg, $orgUrl, $projName, $hdr, $projId)

        $checkSpecs = @(
            @{ Name='ProjectSettings';    Args=$baseArgs }
            @{ Name='BuildPipelines';     Args=$baseArgs }
            @{ Name='ReleasePipelines';   Args=$baseArgs }
            @{ Name='ServiceConnections'; Args=$baseArgs }
            @{ Name='AgentPools';         Args=$baseArgs }
            @{ Name='Repositories';       Args=$repoArgs }
            @{ Name='ProjectFeeds';       Args=$baseArgs }
            @{ Name='SecureFiles';        Args=$baseArgs }
            @{ Name='Environments';       Args=$baseArgs }
            @{ Name='VariableGroups';     Args=$baseArgs }
        )

        $activeProjectSlots = [math]::Max(1, [math]::Min($using:MaxParallel, $using:projectCount))
        $categoryThrottle = [math]::Max(1, [math]::Min(3, [math]::Floor($using:projectWorkerBudget / $activeProjectSlots)))
        $pendingSpecs = [System.Collections.Queue]::new()
        foreach ($spec in $checkSpecs) { $pendingSpecs.Enqueue($spec) }

        $checkScript = {
                param($tn, $fd, $c, $o, $p, $h, $pid2)
                . ([scriptblock]::Create($fd))
                $c.GetEnumerator() | ForEach-Object { Set-Variable -Scope Script -Name $_.Key -Value $_.Value }
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $r = switch ($tn) {
                    'ProjectSettings'    { Test-ProjectSettings    -OrgUrl $o -ProjectName $p -Header $h }
                    'BuildPipelines'     { Test-BuildPipelines     -OrgUrl $o -ProjectName $p -Header $h }
                    'ReleasePipelines'   { Test-ReleasePipelines   -OrgUrl $o -ProjectName $p -Header $h }
                    'ServiceConnections' { Test-ServiceConnections -OrgUrl $o -ProjectName $p -Header $h }
                    'AgentPools'         { Test-AgentPools         -OrgUrl $o -ProjectName $p -Header $h }
                    'Repositories'       { Test-Repositories       -OrgUrl $o -ProjectName $p -ProjectId $pid2 -Header $h }
                    'ProjectFeeds'       { Test-ProjectFeeds       -OrgUrl $o -ProjectName $p -Header $h }
                    'SecureFiles'        { Test-SecureFiles        -OrgUrl $o -ProjectName $p -Header $h }
                    'Environments'       { Test-Environments       -OrgUrl $o -ProjectName $p -Header $h }
                    'VariableGroups'     { Test-VariableGroups     -OrgUrl $o -ProjectName $p -Header $h }
                }
                $sw.Stop()
                [PSCustomObject]@{ Name = $tn; Ms = $sw.ElapsedMilliseconds; Results = $r }
        }

        # Run check categories with a small per-project throttle. This keeps a
        # single project fast without returning to the old 10-way API burst.
        $projResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $projTimings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $checkJobs = @()
        while ($pendingSpecs.Count -gt 0 -or $checkJobs.Count -gt 0) {
            while ($pendingSpecs.Count -gt 0 -and $checkJobs.Count -lt $categoryThrottle) {
                $spec = $pendingSpecs.Dequeue()
                $checkJobs += Start-ThreadJob -ScriptBlock $checkScript -ArgumentList (@($spec.Name) + $spec.Args)
            }

            if ($checkJobs.Count -gt 0) {
                $finished = @(Wait-Job -Job $checkJobs -Any)
                foreach ($job in $finished) {
                    $out = Receive-Job $job -ErrorAction SilentlyContinue
                    Remove-Job $job -Force
                    if ($out) {
                        Add-ResultsSafe $projResults $out.Results
                        $projTimings.Add([PSCustomObject]@{ Name = $out.Name; Ms = $out.Ms })
                    }
                }
                $finishedIds = @($finished | ForEach-Object { $_.Id })
                $checkJobs = @($checkJobs | Where-Object { $_.Id -notin $finishedIds })
            }
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
            Timings    = $projTimings
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
    $orgTimings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $orgExtensionsInventory = [PSCustomObject]@{
        InstalledAvailable = $false
        RequestedAvailable = $false
        Installed = @()
        Requested = @()
    }

    $orgTimings.Add([PSCustomObject]@{ Name='OrgPolicies';         Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgPolicies -OrgUrl $OrgUrl -Header $header) }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='OrgUsers';            Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgUsers -OrgUrl $OrgUrl -Header $header -IncludeGraphCheck:$IncludeGraphCheck) }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='OrgAdmins';           Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgAdmins -OrgUrl $OrgUrl -Header $header) }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='OrgExtensions';       Ms=(Measure-Command {
        $orgExtensionsData = Test-OrgExtensions -OrgUrl $OrgUrl -Header $header
        if ($orgExtensionsData -and $orgExtensionsData.PSObject.Properties['Results']) {
            Add-ResultsSafe $orgResults $orgExtensionsData.Results
            if ($orgExtensionsData.PSObject.Properties['Inventory'] -and $orgExtensionsData.Inventory) {
                $orgExtensionsInventory = $orgExtensionsData.Inventory
            }
        } else {
            Add-ResultsSafe $orgResults $orgExtensionsData
        }
    }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='OrgAudit';            Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgAudit -OrgUrl $OrgUrl -Header $header) }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='OrgPipelineSettings'; Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgPipelineSettings -OrgUrl $OrgUrl -Header $header) }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='OrgFeeds';            Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgFeeds -OrgUrl $OrgUrl -Header $header) }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='OrgPatPolicy';        Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgPatPolicy -OrgUrl $OrgUrl -Header $header) }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='UserPats';            Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-UserPats -OrgShortName $OrgShortName -Header $header) }).TotalMilliseconds })
    $orgTimings.Add([PSCustomObject]@{ Name='OrgWidePats';         Ms=(Measure-Command { Add-ResultsSafe $orgResults (Test-OrgWidePats -OrgUrl $OrgUrl -Header $header) }).TotalMilliseconds })

    $orgReportPath = Join-Path $OutputPath "$orgSafeName-org-assessment.md"
    Write-AssessmentReport -FilePath $orgReportPath -Title "Organization Quick Review: $OrgShortName" -Scope "Organization: $OrgUrl" -Results $orgResults

    $orgPass = @($orgResults | Where-Object Status -eq 'PASS').Count
    $orgFail = @($orgResults | Where-Object Status -eq 'FAIL').Count
    $orgNC   = @($orgResults | Where-Object Status -eq 'NOT CHECKED').Count
    Write-Host "  Org Results: $orgPass PASS | $orgFail FAIL | $orgNC NOT CHECKED" -ForegroundColor $(if ($orgFail -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""

    $orgResult = [PSCustomObject]@{ Pass = $orgPass; Fail = $orgFail; NotChecked = $orgNC; ReportFile = $orgReportPath; Results = $orgResults; OrgExtensions = $orgExtensionsInventory; Timings = $orgTimings }

    # --- Phase 2: Project Assessments ---
    $parallelResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($projName in $projectNames) {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  Phase 2: Project — $projName" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan

        $projResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $projTimings = [System.Collections.Generic.List[PSCustomObject]]::new()

        $projInfo = Invoke-AzCli -Command "devops project show --project `"$projName`" --org $OrgUrl -o json"
        $projId = if ($projInfo) { $projInfo.id } else { "" }

        $projTimings.Add([PSCustomObject]@{ Name='ProjectSettings';    Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-ProjectSettings -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='BuildPipelines';     Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-BuildPipelines -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='ReleasePipelines';   Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-ReleasePipelines -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='ServiceConnections'; Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-ServiceConnections -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='AgentPools';         Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-AgentPools -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='Repositories';       Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-Repositories -OrgUrl $OrgUrl -ProjectName $projName -ProjectId $projId -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='ProjectFeeds';       Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-ProjectFeeds -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='SecureFiles';        Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-SecureFiles -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='Environments';       Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-Environments -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })
        $projTimings.Add([PSCustomObject]@{ Name='VariableGroups';     Ms=(Measure-Command { Add-ResultsSafe $projResults (Test-VariableGroups -OrgUrl $OrgUrl -ProjectName $projName -Header $header) }).TotalMilliseconds })

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
            Timings    = $projTimings
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
    $orgResult = [PSCustomObject]@{
        Pass = 0
        Fail = 0
        NotChecked = 0
        ReportFile = ''
        OrgExtensions = [PSCustomObject]@{
            InstalledAvailable = $false
            RequestedAvailable = $false
            Installed = @()
            Requested = @()
        }
    }
}

# Generate executive HTML report
$htmlReportPath = Join-Path $OutputPath "$orgSafeName-executive-summary.html"
$projectSummaryList = @()
if ($parallelResults) { $projectSummaryList = @($parallelResults) }

# Parse all markdown reports to build remediation data
$orgReportFile = if ($orgResult -and $orgResult.ReportFile) { $orgResult.ReportFile } else { '' }
$remediations = Get-FailedControlsFromReports -OrgReportPath $orgReportFile -ProjectSummaries $projectSummaryList

# ── Build comparison section ─────────────────────────────────────────────────
# Collect per-control data for the current run (available in memory).
$curRunControls = [System.Collections.Generic.List[PSCustomObject]]::new()
if ($orgResult.PSObject.Properties['Results'] -and $orgResult.Results) {
    foreach ($r in $orgResult.Results) {
        $curRunControls.Add([PSCustomObject]@{
            id       = $r.Id
            status   = $r.Status
            severity = $r.Severity
            control  = $r.Control
            scope    = [PSCustomObject]@{ type = 'organization'; organization = $OrgShortName; project = $null }
        })
    }
}
foreach ($pr in $projectSummaryList) {
    if ($pr.PSObject.Properties['Results'] -and $pr.Results) {
        foreach ($r in $pr.Results) {
            $curRunControls.Add([PSCustomObject]@{
                id       = $r.Id
                status   = $r.Status
                severity = $r.Severity
                control  = $r.Control
                scope    = [PSCustomObject]@{ type = 'project'; organization = $OrgShortName; project = $pr.Project }
            })
        }
    }
}
$curRunSummary = [PSCustomObject]@{
    pass       = @($curRunControls | Where-Object status -eq 'PASS').Count
    fail       = @($curRunControls | Where-Object status -eq 'FAIL').Count
    notChecked = @($curRunControls | Where-Object status -eq 'NOT CHECKED').Count
}
$currentRunDoc = [PSCustomObject]@{
    runId       = (Split-Path $OutputPath -Leaf)
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    summary     = $curRunSummary
    controls    = $curRunControls
}

# Discover prior scan JSON files from sibling run folders.
$assessmentsParent = Split-Path $OutputPath -Parent
$priorRuns = Get-PriorScanRuns -AssessmentsRoot $assessmentsParent -OrgSafeName $orgSafeName -ExcludeRunId (Split-Path $OutputPath -Leaf)

$allRunsForCompare = [System.Collections.Generic.List[PSCustomObject]]::new()
$allRunsForCompare.Add($currentRunDoc)
foreach ($pr in $priorRuns) {
    $rdoc = $pr.Doc
    $allRunsForCompare.Add([PSCustomObject]@{
        runId       = $pr.RunId
        generatedAt = $rdoc.meta.generatedAt
        summary     = $rdoc.summary
        controls    = @($rdoc.controls | Select-Object id, status, severity, control, scope)
    })
}

$comparisonHtml = Build-ComparisonSectionHtml -RunsData $allRunsForCompare.ToArray()
# ─────────────────────────────────────────────────────────────────────────────

Write-ExecutiveHtmlReport -FilePath $htmlReportPath `
    -OrgName $OrgShortName `
    -OrgUrl $OrgUrl `
    -ElapsedTime $timeStr `
    -OrgSummary $orgResult `
    -ProjectSummaries $projectSummaryList `
    -TopRemediations $remediations `
    -ComparisonHtml $comparisonHtml

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
Write-Host "  Phase Timings (ms)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
if ($orgResult -and $orgResult.PSObject.Properties['Timings'] -and $orgResult.Timings) {
    $orgTotal = ($orgResult.Timings | Measure-Object -Property Ms -Sum).Sum
    Write-Host ("  [Org]  total: {0,8:N0} ms" -f $orgTotal) -ForegroundColor Yellow
    $orgResult.Timings | Sort-Object Ms -Descending | ForEach-Object {
        Write-Host ("    {0,-22} {1,9:N0} ms" -f $_.Name, $_.Ms)
    }
}
if ($parallelResults) {
    foreach ($pr in ($parallelResults | Sort-Object Project)) {
        if (-not ($pr.PSObject.Properties['Timings']) -or -not $pr.Timings) { continue }
        $projTotal   = ($pr.Timings | Measure-Object -Property Ms -Sum).Sum
        $projSlowest = ($pr.Timings | Measure-Object -Property Ms -Maximum).Maximum
        Write-Host ("  [Proj] {0}  sum: {1,8:N0} ms  slowest-category: {2,8:N0} ms" -f $pr.Project, $projTotal, $projSlowest) -ForegroundColor Yellow
        $pr.Timings | Sort-Object Ms -Descending | ForEach-Object {
            Write-Host ("    {0,-22} {1,9:N0} ms" -f $_.Name, $_.Ms)
        }
    }
}
Write-Host ""

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

# Auto-open the executive report in the default browser (cross-platform)
if ($IsMacOS) {
    & open $htmlReportPath
}
elseif ($IsLinux) {
    & xdg-open $htmlReportPath
}
else {
    Start-Process $htmlReportPath
}

#endregion
