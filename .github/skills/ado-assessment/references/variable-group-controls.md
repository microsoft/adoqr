# Variable Group Best-Practice Controls

Collect and assess variable group settings against Azure DevOps best practices.

## How to Collect Variable Group Settings

```powershell
$org = "https://dev.azure.com/{organization}"
$project = "{project}"
$header = @{ Authorization = "Bearer $token" }

# List all variable groups
az pipelines variable-group list --project $project --org $org -o json

# Get a specific variable group (includes variables and type)
az pipelines variable-group show --id {groupId} --project $project --org $org -o json

# Get variable group via REST (includes permissions info)
Invoke-RestMethod -Uri "$org/$project/_apis/distributedtask/variablegroups/{groupId}?api-version=7.1-preview.2" -Headers $header

# Check pipeline permissions for variable group
Invoke-RestMethod -Uri "$org/$project/_apis/pipelines/pipelinePermissions/variablegroup/{groupId}?api-version=7.1-preview.1" -Headers $header

# Check variable group permissions (roles)
Invoke-RestMethod -Uri "$org/$project/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{project}_{groupId}?api-version=7.1-preview.1" -Headers $header
```

---

## Best-Practice Controls

### VG-01: Secret Variables Not in All Pipelines
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not make variable groups with secret variables accessible to all (YAML) pipelines. |
| **Rationale** | If a variable group containing secrets is marked as accessible to all YAML pipelines, an attacker can extract or compromise assets involving the secret variables by creating a new pipeline. |
| **Collection** | First check if the variable group has secrets: `az pipelines variable-group show --id {id} -o json` — look for variables with `isSecret: true`. Then check: REST `_apis/pipelines/pipelinePermissions/variablegroup/{id}` — if `allPipelines.authorized` is `true`, it's a finding. |
| **Remediation** | Disable "Grant access permission to all pipelines" on variable groups containing secrets. Add individual pipeline authorizations. |

### VG-02: Inherited Permissions Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow inherited permissions on variable groups. |
| **Rationale** | Disabling inherited permissions lets you finely control access at the variable group level. This ensures the principle of least privilege. |
| **Collection** | Check variable group permissions for inheritance flag. |
| **Remediation** | Disable inheritance on individual variable groups and set explicit permissions. |

### VG-03: No Plain Text Secrets
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Secrets and keys must not be stored as plain text in variable group variables. |
| **Rationale** | Keeping secrets in plain text can expose credentials to a wider audience and lead to credential theft. Marking them as secret protects them from unintended disclosure. |
| **Collection** | `az pipelines variable-group show --id {id} -o json` — check `variables` for non-secret values that look like credentials (contain "password", "secret", "key", "token", "connectionstring" patterns). |
| **Remediation** | Mark sensitive variables as secret (`isSecret: true`). Better: use Azure Key Vault linked variable groups. |

### VG-04: Use Azure Key Vault
| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Automated** | No (manual review) |
| **Check** | Consider using a linked Azure key vault for secret variables of the variable group. |
| **Rationale** | Storing secrets in a custom variable group is less secure than storing them in Azure Key Vault. Key Vault offers an extra layer of security (identity & access management, network access control, and monitoring). |
| **Collection** | `az pipelines variable-group show --id {id} -o json` — check `type`. If it's `Vsts` instead of `AzureKeyVault`, and contains secrets, flag it. |
| **Remediation** | Create an Azure Key Vault and link it as a variable group. Migrate secrets from custom variable groups. |

### VG-05: Broader Group Excessive Permissions (Admin)
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Broader groups should not have excessive permissions on variable group. |
| **Rationale** | If broader groups (e.g., Contributors) have excessive permissions (Admin), the integrity of the variable group can be compromised by a malicious user. |
| **Collection** | Check variable group role assignments for broad groups with Administrator role. |
| **Remediation** | Remove Admin role from broad groups. Grant Reader role only where needed. |

### VG-06: Broader Group Permissions on Secret Groups
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Broader groups should not have user/administrator privileges on variable group which contains secrets. |
| **Rationale** | If a broad group has excessive permissions on variable groups with secrets, a malicious user can compromise security of the variable group and assets involving the secret variables. |
| **Collection** | For variable groups with secret variables, check role assignments for broad groups with User or Administrator roles. |
| **Remediation** | Remove User and Administrator roles for broad groups on secret-containing variable groups. |

### VG-07: Branch Restrictions
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Allow variable groups to be accessed only by select branches. |
| **Rationale** | Once a variable group is made accessible to a YAML pipeline, malicious users with 'create branch' permissions can access the variable group by queueing from any branch. |
| **Collection** | Check variable group approvals and checks for branch control. |
| **Remediation** | Add branch control check — restrict to main/release branches only. |

### VG-08: Protected Branch for Templates
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Templates required to access the variable group must reside in a protected branch. |
| **Rationale** | If malicious users have 'contribute' permissions to the repository containing the template, they can tamper it and misuse the variable group. |
| **Collection** | Check required template checks for branch protection. |
| **Remediation** | Enable branch protection on template branches. |

### VG-09: No Broader Group Approvers
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Broader groups should not be added as approvers to the variable group. |
| **Rationale** | Approvers can approve pipeline runs accessing the resource even without direct access to the variable group. |
| **Collection** | Check variable group approval configurations for broad group approvers. |
| **Remediation** | Remove broad groups as approvers. Add specific individuals or small teams. |

### VG-10: Inactive Variable Groups
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Inactive variable groups should be reviewed and removed. |
| **Rationale** | Variable groups may contain sensitive information such as secret variables or secrets from a key vault. Each inactive variable group increases exposure of important information. |
| **Collection** | Check variable group references in pipeline definitions. Flag groups not referenced by any active pipeline. |
| **Remediation** | Delete inactive variable groups after confirming they are no longer needed. |
