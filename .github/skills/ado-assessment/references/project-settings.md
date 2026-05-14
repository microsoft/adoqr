# Project-Level Settings

Collect and assess project-level settings against Azure DevOps best practices.

## How to Collect Project Settings

### REST API Base
```powershell
$org = "https://dev.azure.com/{organization}"
$project = "{project}"
$header = @{ Authorization = "Bearer $token" }
```

### Project Overview
```powershell
# Get project details including visibility
az devops project show --project $project --org $org -o json

# Get project properties
Invoke-RestMethod -Uri "$org/_apis/projects/$project/properties?api-version=7.1-preview.1" -Headers $header

# Get project pipeline settings
Invoke-RestMethod -Uri "$org/$project/_apis/build/generalsettings?api-version=7.1-preview.1" -Headers $header
```

### Project Groups & Permissions
```powershell
# List project security groups
az devops security group list --org $org --project $project --query "graphGroups[].{name:displayName, descriptor:descriptor}" -o table

# List members of Project Administrators
az devops security group membership list --id "<PA-group-descriptor>" --org $org

# Check permissions on build definitions at project level
az devops security permission list --namespace-id "33344d9c-fc72-4d6f-aba5-fa317101a7e9" --token "$project" --org $org
```

### Pipeline Settings (Project Level)
```powershell
# Get project-level pipeline settings
Invoke-RestMethod -Uri "$org/$project/_apis/build/generalsettings?api-version=7.1-preview.1" -Headers $header
# Returns: enforceSettableVar, enforceJobAuthScope, enforceJobAuthScopeForReleases, enforceReferencedRepoScopedToken, etc.
```

### Resource Permissions at Project Level
```powershell
# Check build pipeline permissions at project level
Invoke-RestMethod -Uri "$org/$project/_apis/pipelines/pipelinePermissions?api-version=7.1-preview.1" -Headers $header

# Check service connection permissions
az devops service-endpoint list --project $project --org $org -o json

# Check agent pool permissions for the project
Invoke-RestMethod -Uri "$org/$project/_apis/distributedtask/queues?api-version=7.1-preview.1" -Headers $header

# Check repository settings
Invoke-RestMethod -Uri "$org/$project/_apis/git/repositories?api-version=7.1" -Headers $header

# Check credential scanner (push protection)
Invoke-RestMethod -Uri "$org/$project/_apis/policy/configurations?api-version=7.1" -Headers $header
```

---

## Best-Practice Controls

### PROJ-01: Project Visibility
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Ensure that project visibility is set to either private or enterprise. |
| **Rationale** | Data/content in projects that have public visibility can be downloaded by anyone on the internet without authentication. This can lead to a compromise of corporate data/assets. |
| **Collection** | `az devops project show --project $project -o json` — check `visibility` field. |
| **Remediation** | Project Settings → Overview → change visibility to "Private" or "Enterprise". |

### PROJ-02: Project Admin Group Membership
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | No (manual review) |
| **Check** | Review membership of all project level privileged groups and teams. |
| **Rationale** | Accounts that are a member of these groups without a legitimate business reason increase the risk. By carefully reviewing and removing accounts that shouldn't be there, you can avoid attacks if those accounts are compromised. |
| **Collection** | `az devops security group list --project $project` then list members of each admin group. |
| **Remediation** | Remove members who don't have a legitimate business need for privileged access. |

### PROJ-03: Project Admin Count (Max 6)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Ensure that there are at most 6 project administrators in your project. |
| **Rationale** | Each additional person in the administrator role increases the attack surface for the entire project. |
| **Collection** | Count members of the "Project Administrators" group. |
| **Remediation** | Remove unnecessary members from Project Administrators group. |

### PROJ-04: Project Admin Count (Min 2)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Ensure that there are at least 2 project administrators in your project. |
| **Rationale** | Having the minimum required number of administrators reduces the risk of losing admin access. Useful in break-glass scenarios. |
| **Collection** | Count members of the "Project Administrators" group. |
| **Remediation** | Add a second administrator for redundancy. |

### PROJ-05: Build Admin Count (Max 100)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Ensure that there are at most 100 build administrators in your project. |
| **Rationale** | Each additional person in the build administrator role increases the attack surface. A compromised account can create/tamper resources such as builds and task groups. |
| **Collection** | Count members of the "Build Administrators" group. |
| **Remediation** | Review and reduce build administrator count. |

### PROJ-06: ALT Accounts for Admin Activity
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Alternate (ALT) accounts must be used for administrative activity at project scope. |
| **Rationale** | Corporate accounts are subject to credential theft attacks. A compromised account immediately subjects the project to risk. Use of smartcard-backed alternate (SC-ALT) accounts protects the organization. |
| **Collection** | Review project admin group members. Check for ALT account naming convention. |
| **Remediation** | Require ALT accounts for all project admin-level access. |

### PROJ-07: Guest Users in Admin Roles
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Remove guest users from administrative roles in your project. |
| **Rationale** | Guest user accounts are not carefully managed. If these accounts have admin access, a compromised account can be easily leveraged to access arbitrary resources. |
| **Collection** | List project admin group members, cross-reference with guest users. |
| **Remediation** | Remove guest users from all project administrative groups. |

### PROJ-08: Inactive Users in Admin Roles
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Remove inactive users from administrative roles in your project. |
| **Rationale** | Inactive users in administrative roles provide opportunities for credential harvesting attacks to gain admin access. |
| **Collection** | List project admin members, cross-reference with `lastAccessedDate`. |
| **Remediation** | Remove inactive users from all project administrative groups. |

### PROJ-09: Pipeline Scope (Non-Release)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Limit scope of access for non-release pipelines to the current project. |
| **Rationale** | If authorization scope is not limited to current project, an attacker can build a pipeline from a different project to access resources in a more sensitive project. |
| **Collection** | REST: `$project/_apis/build/generalsettings` — check `enforceJobAuthScope`. |
| **Remediation** | Project Settings → Pipelines → Settings → Enable "Limit job authorization scope to current project for non-release pipelines". |

### PROJ-10: Pipeline Scope (Release)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Limit scope of access for release pipelines to the current project. |
| **Rationale** | Same as PROJ-09, applied to release pipelines. |
| **Collection** | REST: `$project/_apis/build/generalsettings` — check `enforceJobAuthScopeForReleases`. |
| **Remediation** | Project Settings → Pipelines → Settings → Enable "Limit job authorization scope to current project for release pipelines". |

### PROJ-11: Pipeline Repository Scope
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Limit scope of access for pipelines to explicitly referenced Azure DevOps repositories. |
| **Rationale** | If authorization scope is not limited to referenced repos, an attacker can create a pipeline that can access sensitive repos within the project. |
| **Collection** | REST: `$project/_apis/build/generalsettings` — check `enforceReferencedRepoScopedToken`. |
| **Remediation** | Project Settings → Pipelines → Settings → Enable "Protect access to repositories in YAML pipelines". |

### PROJ-12: Settable Variables
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Allow queue time changes only to pipeline variables explicitly marked as settable. |
| **Rationale** | By default a pipeline user can set any variables at queue time. Enabling this setting enforces that variables must be explicitly marked settable. |
| **Collection** | REST: `$project/_apis/build/generalsettings` — check `enforceSettableVar`. |
| **Remediation** | Project Settings → Pipelines → Settings → Enable "Limit variables that can be set at queue time". |

### PROJ-13: Artifact Evaluation
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Consider using artifact evaluation for fine-grained control over pipeline stages. |
| **Rationale** | Allow pipelines to record metadata. Evaluate artifact check can be configured to define policies using the metadata recorded. |
| **Collection** | Check if artifact evaluation is configured in pipeline checks. |
| **Remediation** | Configure artifact evaluation checks on environments and service connections. |

### PROJ-14: Credential Scanner
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Enable credential scanner to block pushes that contain credentials and other secrets. |
| **Rationale** | Exposed credentials in engineering systems continue to provide easily exploitable opportunities for attackers. CredScan automatically finds exposed secrets and indexes/scans for credentials and other sensitive content in source code. |
| **Collection** | Check repository policies for push protection / credential scanning. REST: `$project/_apis/policy/configurations` — look for credential scan policy type. Also check GHAzDO (GitHub Advanced Security for Azure DevOps) if enabled. |
| **Remediation** | Enable push protection in GHAzDO, or configure credential scanning in pipeline tasks. |

### PROJ-15: Commit Author Email Validation
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Enable commit author email validation to restrict commits from untrusted users. |
| **Rationale** | Allowing commits from untrusted users can be dangerous as any malicious actor can push changes that can expose secrets/vulnerabilities outside the organization. |
| **Collection** | `az repos policy list --project $project` — check for commit author email validation policy. |
| **Remediation** | Project Settings → Repos → Policies → Enable commit author email validation. |

### PROJ-16: Inactive Projects
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Projects with no development activity should be deleted. |
| **Rationale** | Projects with no activity (no active builds, releases, repos, agent pools, service connections, etc.) are likely abandoned. It is recommended to delete such projects to minimize exposure of corporate assets and credentials. |
| **Collection** | Check project for recent build/release activity, active repos, service connections, agent pools. |
| **Remediation** | Archive or delete inactive projects after review. |

### PROJ-17: Badge API Access
| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Automated** | Yes |
| **Check** | Disable anonymous access to status badge API for parallel pipelines. |
| **Rationale** | Information in the status badge API response should be hidden from external users. |
| **Collection** | Project Settings → Pipelines → Settings. |
| **Remediation** | Disable anonymous badge access at project level. |

### PERM-01: Build Pipeline Inherited Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow build pipelines to inherit excessive permissions for a broad group of users at project level. |
| **Rationale** | If a broad group (e.g., Contributors) is configured with excessive permissions at project level, they are inherited by individual build pipelines. A malicious user can abuse these permissions. |
| **Collection** | Check build pipeline permissions at project level — look for Contributors/Project Valid Users with excessive access. |
| **Remediation** | Remove or restrict excessive permissions for broad groups on build pipeline namespace at project level. |

### PERM-02: Release Pipeline Inherited Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow release pipelines to inherit excessive permissions for a broad group of users at project level. |
| **Rationale** | If a broad group is configured with excessive permissions at project level, they are inherited by individual release pipelines. A malicious user can compromise pipeline security. |
| **Collection** | Check release pipeline permissions at project level. |
| **Remediation** | Remove or restrict excessive permissions for broad groups on release pipeline namespace at project level. |

### PERM-03: Service Connection Inherited Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow service connections to inherit excessive permissions for a broad group of users at project level. |
| **Rationale** | If a broad group is configured with excessive permissions at project level, they are inherited by individual service connections. The confidentiality/integrity of pipelines using such connections can be compromised. |
| **Collection** | Check service connection permissions at project level. |
| **Remediation** | Remove or restrict excessive permissions for broad groups. |

### PERM-04: Agent Pool Inherited Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow agent pools to inherit excessive permissions for a broad group of users at project level. |
| **Rationale** | If a broad group is configured with excessive permissions, they are inherited by individual agent pools. The integrity of such agent pools can be compromised. |
| **Collection** | Check agent pool permissions at project level. |
| **Remediation** | Remove or restrict excessive permissions for broad groups. |

### PERM-05: Variable Group Inherited Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow variable groups to inherit excessive permissions for a broad group of users at project level. |
| **Rationale** | If a broad group is configured with excessive permissions, they are inherited by individual variable groups. The integrity of variable groups can be compromised. |
| **Collection** | Check variable group permissions at project level. |
| **Remediation** | Remove or restrict excessive permissions for broad groups. |

### PERM-06: Repository Inherited Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow repositories to inherit excessive permissions for a broad group of users at project level. |
| **Rationale** | If a broad group is configured with excessive permissions, they are inherited by individual repositories. The integrity of the repository can be compromised. |
| **Collection** | Check repository permissions at project level. |
| **Remediation** | Remove or restrict excessive permissions for broad groups. |

### PERM-07: Secure File Inherited Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow secure files to inherit excessive permissions for a broad group of users at project level. |
| **Rationale** | If a broad group has excessive permissions, they are inherited by individual secure files. The integrity of secure files can be compromised. |
| **Collection** | Check secure file permissions at project level. |
| **Remediation** | Remove or restrict excessive permissions for broad groups. |

### PERM-08: Environment Inherited Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow environments to inherit excessive permissions for a broad group of users at project level. |
| **Rationale** | If a broad group is configured with excessive permissions, they are inherited by individual environments. The integrity of environments can be compromised. |
| **Collection** | Check environment permissions at project level. |
| **Remediation** | Remove or restrict excessive permissions for broad groups. |
