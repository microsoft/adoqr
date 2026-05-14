# Common Errors & Troubleshooting

## Authentication Errors

### 401 Unauthorized
```
TF401019: The Git repository with name or identifier {repo} does not exist
VS403463: The caller is not authorized to perform this operation
```
**Cause:** Invalid or expired PAT/token, or missing `az login`.
**Fix:**
```powershell
# Re-authenticate
az login

# If using PAT
$env:AZURE_DEVOPS_EXT_PAT = '<valid-pat>'
az devops login

# If using REST API, refresh the token
$token = az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --query accessToken -o tsv
```

### 403 Forbidden
```
VS403392: {user} needs the following permission(s) on the resource {resource} to perform this action
TF401027: You need the Git 'GenericRead' permission to perform this action
```
**Cause:** The authenticated user lacks the required permissions.
**Fix:** Ensure the user/PAT has the correct permissions:
- For org assessment: Project Collection Administrator or Project Collection Valid Users
- For project assessment: Project Administrator or appropriate read permissions
- For security namespace queries: `vso.security_manage` scope on PAT

### Token Scope Insufficient
```
The personal access token used has the scope 'vso.code' but needs 'vso.security_manage'
```
**Cause:** PAT missing required scopes for the assessment.
**Fix:** Create a new PAT with these scopes for a full assessment:
- `vso.security_manage` — Security (manage)
- `vso.project` — Project and team (read)
- `vso.build` — Build (read)
- `vso.release` — Release (read)
- `vso.serviceendpoint` — Service Endpoints (read)
- `vso.variablegroups_read` — Variable Groups (read)
- `vso.packaging` — Packaging (read)
- `vso.auditlog` — Audit Log (read)

## Azure CLI Errors

### Extension Not Installed
```
'devops' is not a registered command
```
**Fix:**
```powershell
az extension add --name azure-devops
```

### Organization Not Set
```
--organization is required when not in a Git repository
```
**Fix:**
```powershell
az devops configure --defaults organization=https://dev.azure.com/<YourOrg>
```

### Project Not Set
```
--project is required
```
**Fix:**
```powershell
az devops configure --defaults project=<YourProject>
```

### Azure CLI Version Too Old
```
ERROR: unrecognized arguments: --query-order
```
**Fix:**
```powershell
az upgrade
# Verify version is 2.81.0+
az version
```

## REST API Errors

### 404 Not Found
```
Page not found. VS800059: The requested resource does not exist.
```
**Cause:** Wrong API path, incorrect api-version, or resource doesn't exist.
**Fix:**
- Verify the org URL format: `https://dev.azure.com/{org}` (not `https://{org}.visualstudio.com`)
- Check API version is supported (use `7.1` or `7.1-preview.1`)
- Verify resource IDs are correct

### 400 Bad Request / API Version
```
The requested api-version is not supported
```
**Fix:**
- Use a supported API version. Common versions:
  - `7.1` for stable endpoints
  - `7.1-preview.1` for preview endpoints
  - `6.0` for older organizations

### Rate Limiting / 429 Too Many Requests
```
TF400733: The request has been canceled
```
**Cause:** Hitting the ADO API rate limits (especially in large orgs).
**Fix:**
```powershell
# Add delays between API calls
Start-Sleep -Seconds 1

# Use batch endpoints where available
# Process in smaller chunks (e.g., 100 items at a time)
```

## Permission Namespace Errors

### Unknown Security Namespace
```
VS403507: The security namespace '...' does not exist
```
**Common namespace IDs for reference:**
| Namespace | ID |
|---|---|
| Git Repositories | `2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87` |
| Build | `33344d9c-fc72-4d6f-aba5-fa317101a7e9` |
| ReleaseManagement | `c788c23e-1b46-4162-8f5e-d7585343b5de` |
| Identity | `5a27515b-ccd7-42c9-84f1-54c998f03866` |
| Project | `52d39943-cb85-4d7f-8fa8-c6baac873819` |
| Tagging | `bb50f182-8e5e-40b8-bc21-e8752a1e7ae2` |

### SecurityNamespace Token Format
Building the correct token for security permission queries:
```powershell
# For a repository
$token = "repoV2/$projectId/$repoId"

# For a build definition
$token = "$projectId/$definitionId"

# For project-level
$token = "$projectId"

# For org-level
$token = "/" # or empty
```

## PowerShell Errors

### Execution Policy
```
File cannot be loaded because running scripts is disabled on this system
```
**Fix:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### TLS/SSL Errors
```
The underlying connection was closed: Could not establish trust relationship
```
**Fix:**
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

### JSON Parsing
```
ConvertFrom-Json : Invalid JSON primitive
```
**Fix:**
```powershell
# Ensure you're getting raw JSON, not table format
$result = az devops project list --org $org -o json | ConvertFrom-Json
```

## Common Assessment Pitfalls

1. **Partial visibility:** Your PAT scope determines what you can see. A PAT with limited scopes will miss settings, leading to false negatives.
2. **Project vs. Org settings:** Some settings exist at both org and project level. The project-level setting may override the org-level one.
3. **Inherited permissions:** Even if a resource has clean direct permissions, inherited permissions may still grant broad access.
4. **Classic vs. YAML pipelines:** Classic pipelines use a different security model than YAML pipelines. Some controls apply only to YAML (`allPipelines.authorized`).
5. **API version differences:** Older organizations may not support the latest API versions. Fall back to `6.0` if needed.
