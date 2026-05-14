# User & PAT Best-Practice Controls

Collect and assess user account and Personal Access Token (PAT) settings against Azure DevOps best practices.

## How to Collect User & PAT Settings

```powershell
$org = "https://dev.azure.com/{organization}"
$header = @{ Authorization = "Bearer $token" }

# List all users in the organization
az devops user list --org $org -o json

# Get user details
az devops user show --user {email} --org $org -o json

# List PATs for the current user (REST — user can only see their own)
Invoke-RestMethod -Uri "https://vssps.dev.azure.com/{organization}/_apis/tokens/pats?api-version=7.1-preview.1" -Headers $header

# Audit log approach for PAT activity (requires audit access)
# Check PAT creation/modification events in audit
Invoke-RestMethod -Uri "$org/_apis/audit/auditlog?api-version=7.1-preview.1" -Headers $header
```

### Note on PAT Visibility
PATs are scoped to individual users. Organization admins cannot directly list all PATs across all users via a single API call. To audit PATs across the organization:
1. Use **Audit Logs** to review PAT creation, modification, and revocation events
2. Use **Azure AD Conditional Access** to enforce PAT policies
3. Use **Organization Settings → Policies** to restrict PAT scope and lifetime

---

## Best-Practice Controls

### PAT-01: Minimum Required Permissions
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Personal access tokens (PAT) must be defined with minimum required permissions to resources. |
| **Rationale** | Granting minimum access ensures that PAT is granted with just enough permissions to perform required tasks. This minimizes exposure of the resources in case of PAT compromise. |
| **Collection** | REST: `_apis/tokens/pats` — check `scope` for each PAT. Flag PATs with `app_token` (full access) scope. |
| **Remediation** | Recreate PATs with specific scopes (e.g., `vso.code` for code read, `vso.build_execute` for builds). Revoke full-access PATs. |

### PAT-02: Short Validity Period
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Personal access tokens (PAT) must have a shortest possible validity period. |
| **Rationale** | If a PAT gets compromised, the Azure DevOps assets accessible to the user can be accessed by unauthorized users. Minimizing the validity period ensures the window of time available to an attacker is small. |
| **Collection** | REST: `_apis/tokens/pats` — check `validTo` for each PAT. Flag PATs with validity > 90 days. |
| **Remediation** | Recreate PATs with shorter validity periods (30-90 days max). Use Organization Settings → Policies to enforce maximum PAT lifetime. |

### PAT-03: Near-Expiry PAT Renewal
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Personal access tokens (PAT) near expiry should be renewed. |
| **Rationale** | PATs near expiry should be renewed to avoid service disruption and ensure continued secure access. |
| **Collection** | REST: `_apis/tokens/pats` — check `validTo` for each PAT. Flag PATs expiring within 7 days. |
| **Remediation** | Renew or regenerate PATs before they expire. Consider automation for PAT rotation. |

### PAT-04: Alternate Credentials Disabled
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | No (manual review) |
| **Check** | Alternate credentials must be disabled. |
| **Rationale** | Alternate credentials allow users to create username and password to access Git repositories. Login with these credentials doesn't expire and can't be scoped to limit access to Azure DevOps Services data. |
| **Collection** | Check Organization Settings → Policies → "Alternate authentication credentials". Note: This feature has been deprecated by Microsoft as of March 2020. |
| **Remediation** | Ensure alternate authentication credentials policy is disabled at the organization level. |

### PAT-05: No Multi-Organization PATs
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Do not use personal access tokens (PATs) that are scoped across multiple organizations. |
| **Rationale** | If a PAT gets compromised, the Azure DevOps assets accessible to the user can be accessed by unauthorized users. Restricting access to individual organizations reduces exposure in an event of compromise. |
| **Collection** | REST: `_apis/tokens/pats` — check `scope` and `targetAccounts` for multi-org PATs. Also check Organization Settings → Policies for "Allow personal access tokens scoped to one or more organizations". |
| **Remediation** | Recreate multi-org PATs as single-org scoped. Restrict multi-org PAT creation via organization policy. |

### PAT-06: No Critical Permission PATs
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Do not use personal access tokens (PATs) that have critical permissions on the organization unless required. |
| **Rationale** | Granting minimum access ensures that PAT is granted with just enough permissions. This minimizes exposure of the resources in case of compromise. |
| **Collection** | REST: `_apis/tokens/pats` — flag PATs with scopes including: `vso.security_manage`, `vso.entitlements`, `vso.memberentitlementmanagement_write`, `vso.project_manage`, or `app_token` (full access). |
| **Remediation** | Recreate PATs with reduced scopes. Use service principals or managed identities for automation instead of PATs with broad permissions. |

---

## Organization-Level PAT Policies

These policies can be set at the organization level to enforce PAT hygiene across all users:

### PATPOL-01: Maximum PAT Lifetime
```
Organization Settings → Policies → "Enforce maximum personal access token lifespan"
```
Set a maximum lifetime (e.g., 90 days) for all new PATs. Existing PATs that exceed this limit will need to be rotated.

### PATPOL-02: Restrict PAT Scope
```
Organization Settings → Policies → "Restrict scope of personal access tokens"
```
Prevent users from creating full-access PATs. Require specific scopes.

### PATPOL-03: Restrict Global PATs
```
Organization Settings → Policies → "Restrict global personal access tokens"
```
Prevent users from creating PATs that work across all accessible organizations.
