# Release Pipeline Best-Practice Controls

Collect and assess release pipeline settings against Azure DevOps best practices.

## How to Collect Release Settings

```powershell
$org = "https://dev.azure.com/{organization}"
$project = "{project}"
$header = @{ Authorization = "Bearer $token" }

# List all release definitions
az pipelines release definition list --project $project --org $org -o json

# Get a specific release definition (includes variables, environments, triggers)
az pipelines release definition show --id {releaseDefId} --project $project --org $org -o json

# Get release definition via REST (full detail)
Invoke-RestMethod -Uri "$org/$project/_apis/release/definitions/{definitionId}?api-version=7.1" -Headers $header

# List recent releases for a definition
az pipelines release list --definition-id {releaseDefId} --project $project --org $org --top 5 -o json

# Check release permissions
az devops security permission list --namespace-id "c788c23e-1b46-4162-8f5e-d7585343b5de" --token "$project/{definitionId}" --org $org
```

---

## Best-Practice Controls

### REL-01: No Plain Text Secrets
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Secrets and keys must not be stored as plain text in release variables/task parameters. |
| **Rationale** | Keeping secrets in plain text can expose credentials to a wider audience and lead to credential theft. Marking them as secret protects them from unintended disclosure. |
| **Collection** | `az pipelines release definition show --id {id} -o json` — inspect `variables` for non-secret variables containing keywords like "password", "secret", "key", "token". Also inspect environment-level variables. |
| **Remediation** | Mark sensitive variables as secret. Use variable groups linked to Azure Key Vault. |

### REL-02: Inactive Release Pipelines
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Inactive release pipelines must be removed if no more required. |
| **Rationale** | Each additional release having access to repositories/other artifacts increases the attack surface. Only active and legitimate release pipelines should be present. |
| **Collection** | `az pipelines release list --definition-id {id} --top 1` — check date of last release. Flag definitions with no releases in 90+ days. |
| **Remediation** | Delete or disable inactive release pipelines. |

### REL-03: Inherited Permissions Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow inherited permission on release definitions. |
| **Rationale** | Disabling inherited permissions lets you finely control access at the release level. This ensures you follow the principle of least privilege. |
| **Collection** | Check release definition permissions for inheritance flag. |
| **Remediation** | Disable inheritance on individual release definitions and set explicit permissions. |

### REL-04: Pre-Deployment Approvals
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Release pipelines for production deployments must have pre-deployment approval enabled. |
| **Rationale** | Pre-deployment approvals give you an additional layer of defense against inadvertent (or possibly malicious) changes to your production environment. |
| **Collection** | `az pipelines release definition show --id {id} -o json` — check `environments[].preDeployApprovals.approvals`. For production stages, verify `isAutomated` is `false`. |
| **Remediation** | Enable pre-deployment approvals on production and pre-production stages. |

### REL-05: Approver List Review
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Only legitimate users should be added as approvers for releases. |
| **Rationale** | Periodic review of approvers list for production releases ensures that only appropriate people are members of such a critical role. As team composition changes, privileges may need to be revoked. |
| **Collection** | `az pipelines release definition show --id {id} -o json` — check `environments[].preDeployApprovals.approvals[].approver`. |
| **Remediation** | Review and update approver lists. Remove departed team members. |

### REL-06: Production from Main Branch Only
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | No (manual review) |
| **Check** | All releases to production or pre-production stages must be done from one and only one (main) branch. |
| **Rationale** | You should ensure production releases are always done from the main branch. The main branch should have the tightest access controls and approval standards. Source code should correspond to production bits at all times. |
| **Collection** | Check release definition artifact filters and triggers. Verify branch filters on production environments. |
| **Remediation** | Add artifact filters on production stages to only allow artifacts from the main branch. |

### REL-07: External Repository Review
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Review external source code repositories before adding them to your pipeline. |
| **Rationale** | Building code from untrusted external sources can allow an attacker to execute arbitrary code. All repositories added to the pipeline should be carefully reviewed. |
| **Collection** | Check release definition artifacts for external repository sources. |
| **Remediation** | Review all external repositories. Consider mirroring external repos internally. |

### REL-08: Settable Variables at Release Time
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Pipeline variables marked settable at release time should be carefully reviewed. |
| **Rationale** | Variables settable at queue time can be changed by anyone who can create a release. Such variables can be misused for code injection/data theft attacks. |
| **Collection** | `az pipelines release definition show --id {id} -o json` — check `variables` for `allowOverride: true`. |
| **Remediation** | Remove `allowOverride` from variables that don't need to be settable at release time. |

### REL-09: Settable URL Variables
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Pipeline variables marked settable at release time and containing URLs should be avoided. |
| **Rationale** | Settable URL variables can be changed to a malicious server to intercept secrets used to interact with the intended server. |
| **Collection** | Check variables with `allowOverride: true` that contain URL patterns. |
| **Remediation** | Remove `allowOverride` from URL-containing variables. |

### REL-10: Task Group Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Releases should not use task groups that are editable by a broad pool of users. |
| **Rationale** | If a broad pool of users have edit permissions on a task group, then integrity of your pipeline can be compromised by a malicious user who edits the task group. |
| **Collection** | Identify task groups used by the release. Check permissions on each task group. |
| **Remediation** | Restrict edit permissions on task groups to pipeline administrators only. |

### REL-11: Variable Group Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not use variable groups that are editable by a broad group of users. |
| **Rationale** | If a broad group has edit permissions on a variable group, pipeline integrity can be compromised by a malicious user. |
| **Collection** | Identify variable groups used by the release. Check permissions on each. |
| **Remediation** | Restrict edit permissions on variable groups to pipeline administrators only. |

### REL-12: Excessive Permissions for Broad Groups
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow release pipeline to have excessive permissions by a broad group of users. |
| **Rationale** | If a broad group (e.g., Contributors) have excessive permissions on a pipeline, a malicious user can abuse these permissions to compromise security. |
| **Collection** | Check pipeline-level security for broad groups with Edit/Admin permissions. |
| **Remediation** | Remove excessive permissions for Contributors and other broad groups. |

### REL-13: OAuth Token Access
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Do not allow agent jobs to access OAuth token unless explicitly required. |
| **Rationale** | Malicious tasks or extensions can use OAuth access token for stealing project details like builds, releases, agent pools, etc. |
| **Collection** | Check release definition environments/phases for OAuth token access settings. |
| **Remediation** | Remove OAuth token access from release phases that don't require it. |
