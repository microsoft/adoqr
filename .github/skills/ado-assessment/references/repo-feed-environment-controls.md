# Repository, Feed, Secure File & Environment Controls

Collect and assess settings for repositories, feeds, secure files, and environments against Azure DevOps best practices.

## How to Collect Settings

### Repositories
```powershell
$org = "https://dev.azure.com/{organization}"
$project = "{project}"
$header = @{ Authorization = "Bearer $token" }

# List all repositories
az repos list --project $project --org $org -o json

# Get repository details
az repos show --repository {repoName} --project $project --org $org -o json

# List branch policies
az repos policy list --project $project --org $org --repository-id {repoId} -o json

# Check repository permissions
az devops security permission list --namespace-id "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87" --token "repoV2/$project/{repoId}" --org $org

# Check pipeline permissions for repository
Invoke-RestMethod -Uri "$org/$project/_apis/pipelines/pipelinePermissions/repository/$project.{repoId}?api-version=7.1-preview.1" -Headers $header

# Check push policies (credential scanning)
Invoke-RestMethod -Uri "$org/$project/_apis/policy/configurations?api-version=7.1" -Headers $header
```

### Feeds
```powershell
# List project-level feeds
Invoke-RestMethod -Uri "$org/$project/_apis/packaging/feeds?api-version=7.1-preview.1" -Headers $header

# Get feed details
Invoke-RestMethod -Uri "$org/$project/_apis/packaging/feeds/{feedId}?api-version=7.1-preview.1" -Headers $header

# Check feed permissions
Invoke-RestMethod -Uri "$org/$project/_apis/packaging/Feeds/{feedId}/permissions?api-version=7.1-preview.1" -Headers $header

# List packages in a feed
Invoke-RestMethod -Uri "$org/$project/_apis/packaging/Feeds/{feedId}/packages?api-version=7.1-preview.1" -Headers $header
```

### Secure Files
```powershell
# List secure files
Invoke-RestMethod -Uri "$org/$project/_apis/distributedtask/securefiles?api-version=7.1-preview.1" -Headers $header

# Check pipeline permissions for secure file
Invoke-RestMethod -Uri "$org/$project/_apis/pipelines/pipelinePermissions/securefile/{secureFileId}?api-version=7.1-preview.1" -Headers $header
```

### Environments
```powershell
# List environments
Invoke-RestMethod -Uri "$org/$project/_apis/distributedtask/environments?api-version=7.1-preview.1" -Headers $header

# Get environment details (includes checks)
Invoke-RestMethod -Uri "$org/$project/_apis/distributedtask/environments/{environmentId}?expands=checks&api-version=7.1-preview.1" -Headers $header

# Check pipeline permissions for environment
Invoke-RestMethod -Uri "$org/$project/_apis/pipelines/pipelinePermissions/environment/{environmentId}?api-version=7.1-preview.1" -Headers $header
```

---

## Repository Controls

### REPO-01: Inactive Repositories
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Inactive repositories must be removed if no more required. |
| **Rationale** | Each additional repository being accessed by pipelines increases the attack surface. Only active and legitimate repositories should be present. |
| **Collection** | Check last commit date for each repository. Flag repos with no commits in 180+ days. |
| **Remediation** | Archive or delete inactive repositories. |

### REPO-02: Not Accessible to All YAML Pipelines
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Do not make repository accessible to all (YAML) pipelines. |
| **Rationale** | If a repository is granted access to all YAML pipelines, an unauthorized user can steal information by building a pipeline and accessing the repository. |
| **Collection** | REST: `_apis/pipelines/pipelinePermissions/repository/$project.{repoId}` — check if `allPipelines.authorized` is `true`. |
| **Remediation** | Disable "Grant access permission to all pipelines". Add individual pipeline authorizations. |

### REPO-03: Build Service Group Excessive Permissions
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Do not grant build service groups excessive permissions on repository branches. |
| **Rationale** | If 'Project Collection Build Service' or 'Project Build Service' groups have excessive permissions on important branches, a malicious user can access the repository and tamper its contents by bypassing defined policies. |
| **Collection** | Check branch-level permissions for build service accounts. |
| **Remediation** | Restrict build service account permissions on important branches (main, release). |

### REPO-04: Inherited Permissions Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow inherited permission on repository. |
| **Rationale** | Disabling inherited permissions lets you finely control access at the repository level. This ensures the principle of least privilege. |
| **Collection** | Check repository permissions for inheritance flag. |
| **Remediation** | Disable inheritance on individual repositories and set explicit permissions. |

### REPO-05: No Build Service Account Direct Access
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not grant Build Service Account direct access to repositories. |
| **Rationale** | Build service account is the default identity used in every build. Configuring these identities with excessive permissions will expose repository details to all build definitions. |
| **Collection** | Check repository permissions for "Project Collection Build Service" and "Project Build Service" groups. |
| **Remediation** | Remove direct access. Use pipeline-specific repository authorization. |

### REPO-06: Credential Scanner / Push Protection
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Enable policy to block pushes that contain credentials and other secrets. |
| **Rationale** | Exposed credentials provide easily exploitable opportunities for attackers. CredScan should be enabled at each repo level to avoid committing credentials or secrets. |
| **Collection** | Check repository policies for push protection. Check GHAzDO secret scanning configuration. |
| **Remediation** | Enable push protection via GHAzDO, or configure credential scanning policies on the repository. |

### REPO-07: Branch Restrictions
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Allow repositories to be accessed only by select branches. |
| **Rationale** | Once a repository is accessible to a YAML pipeline, malicious users with contribute/'create branch' permissions can access it by queueing from any branch. |
| **Collection** | Check repository approvals and checks for branch control. |
| **Remediation** | Add branch control check — restrict to main/release branches only. |

### REPO-08: Protected Branch for Templates
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Templates required to access repositories must reside in a protected branch. |
| **Rationale** | If malicious users have 'contribute' permissions to the template repository, they can tamper the template and misuse the repository. |
| **Collection** | Check if required template checks reference a protected branch. |
| **Remediation** | Enable branch protection policies on template branches. |

### REPO-09: No Broader Group Approvers
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Broader groups should not be added as approvers to the repository. |
| **Rationale** | Any user/group added as an approver can approve pipeline runs accessing the resource even without direct access. |
| **Collection** | Check repository approvals/checks for broad group approvers. |
| **Remediation** | Remove broad groups as approvers. Add specific individuals. |

---

## Feed Controls

### FEED-01: No Broad Upload Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow a broad group of users to upload packages to feed. |
| **Rationale** | If a broad group (e.g., Contributors) have permissions to upload packages, a malicious user can upload a compromised package. |
| **Collection** | REST: `_apis/packaging/Feeds/{feedId}/permissions` — check for broad groups with Contributor or Administrator roles. |
| **Remediation** | Restrict upload (Contributor) permissions to specific trusted users/groups. |

### FEED-02: No Build Service Account Direct Access
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not grant Build Service Account direct access to feed. |
| **Rationale** | Build service account is the default identity in every build. Providing direct access exposes feeds to all build definitions. |
| **Collection** | Check feed permissions for build service accounts. |
| **Remediation** | Remove Build Service Account direct access. Use pipeline-specific feed authorization. |

### FEED-03: Inactive Feeds
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Inactive feeds must be removed if no more required. |
| **Rationale** | An attacker can abuse an inactive feed to start publishing packages that might seem useful but contain trojan horses. |
| **Collection** | Check feed package update dates. Flag feeds with no package updates in 180+ days. |
| **Remediation** | Delete inactive feeds after confirming they are no longer needed. |

### FEED-04: Inactive Packages
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Inactive packages must be removed if no more required. |
| **Rationale** | An attacker can abuse an inactive package to publish malicious updates. |
| **Collection** | Check package last version update dates. |
| **Remediation** | Delete or deprecate inactive packages. |

---

## Secure File Controls

### SF-01: Not Accessible to All YAML Pipelines
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not make secure files accessible to all (YAML) pipelines. |
| **Rationale** | If a secure file is granted access to all YAML pipelines, an unauthorized user can steal information by building a YAML pipeline. |
| **Collection** | REST: `_apis/pipelines/pipelinePermissions/securefile/{id}` — check if `allPipelines.authorized` is `true`. |
| **Remediation** | Disable "Grant access permission to all pipelines". Add individual pipeline authorizations. |

### SF-02: No Broad Group Excessive Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow secure file to have excessive permissions for a broad group of users. |
| **Rationale** | If a broad group has excessive permissions, a malicious user may gain access to stored secrets/certificates which may enable attacks. |
| **Collection** | Check secure file permissions for broad groups with Admin or User roles. |
| **Remediation** | Remove excessive permissions for broad groups. |

### SF-03: Branch Restrictions
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Allow secure files to be accessed only by select branches. |
| **Rationale** | Malicious users with contribute/'create branch' permissions can access the secure file by queueing from any branch. |
| **Collection** | Check secure file approvals/checks for branch control. |
| **Remediation** | Add branch control check — restrict to main/release branches. |

### SF-04: Protected Branch for Templates
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Templates required to access secure files must reside in a protected branch. |
| **Rationale** | Malicious users with 'contribute' permissions to template repos can tamper the template and misuse the secure file. |
| **Collection** | Check required template checks for branch protection. |
| **Remediation** | Enable branch protection on template branches. |

### SF-05: No Broader Group Approvers
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Broader groups should not be added as approvers to the secure file. |
| **Rationale** | Approvers can approve pipeline runs accessing the resource even without direct secure file access. |
| **Collection** | Check secure file approvals for broad group approvers. |
| **Remediation** | Remove broad groups as approvers. Add specific individuals. |

### SF-06: Inactive Secure Files
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Inactive secure files should be reviewed and removed if no longer required. |
| **Rationale** | Secure files can store sensitive files like SSH keys and signing certificates. Each inactive secure file increases exposure of sensitive information. |
| **Collection** | Check secure file usage history. Flag files with no usage in 90+ days. |
| **Remediation** | Delete inactive secure files after confirming they are no longer needed. |

---

## Environment Controls

### ENV-01: Not Accessible to All YAML Pipelines
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not make environment accessible to all (YAML) pipelines. |
| **Rationale** | Environments must not be granted access to all YAML pipelines. A vulnerability in one pipeline can be leveraged to attack other pipelines with access to critical resources. |
| **Collection** | REST: `_apis/pipelines/pipelinePermissions/environment/{id}` — check if `allPipelines.authorized` is `true`. |
| **Remediation** | Disable "Grant access permission to all pipelines". Add individual pipeline authorizations. |

### ENV-02: No Broad Group Excessive Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow environment to have excessive permissions for a broad group of users. |
| **Rationale** | If a broad group has excessive permissions, a malicious user can abuse them to compromise environment integrity. |
| **Collection** | Check environment permissions for broad groups. |
| **Remediation** | Remove excessive permissions for broad groups. |

### ENV-03: Production Approvals
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Environments for production deployments must have approvals enabled. |
| **Rationale** | Approvals ensure deployment from a YAML pipeline happens only after designated users have reviewed the changes. This provides defense against inadvertent or malicious changes to production. |
| **Collection** | REST: `_apis/distributedtask/environments/{id}?expands=checks` — check for approval checks on production-named environments. |
| **Remediation** | Add approval checks on production and pre-production environments. |

### ENV-04: Approver List Review
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Approvers on environment must be periodically reviewed. |
| **Rationale** | Periodic review ensures only appropriate people are members of this critical role. As team composition changes, privileges may need to be revoked. |
| **Collection** | Check environment approval configurations for approver list. |
| **Remediation** | Review and update approver lists regularly. Remove departed team members. |

### ENV-05: Standard Branch Deployments
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | All deployments to production environments must be done from standard branches. |
| **Rationale** | Production deployments should come from standard branches (main, master, develop) which have the tightest access controls and approval standards. |
| **Collection** | Check environment checks for branch control policies. |
| **Remediation** | Add branch control check to production environments — restrict to standard branches only. |

### ENV-06: Protected Branch for Templates
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Templates required to access environments must reside in a protected branch. |
| **Rationale** | Malicious users with 'contribute' permissions can tamper the template and misuse the environment. |
| **Collection** | Check required template checks for branch protection. |
| **Remediation** | Enable branch protection on template branches. |

### ENV-07: No Broader Group Approvers
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Broader groups should not be added as approvers to the environment. |
| **Rationale** | Approvers can approve pipeline runs accessing the environment even without direct access. |
| **Collection** | Check environment approval configurations for broad group approvers. |
| **Remediation** | Remove broad groups as approvers. Add specific individuals or small teams. |
