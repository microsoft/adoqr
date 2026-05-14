# Build Pipeline Best-Practice Controls

Collect and assess build pipeline settings against Azure DevOps best practices.

## How to Collect Build Settings

```powershell
$org = "https://dev.azure.com/{organization}"
$project = "{project}"
$header = @{ Authorization = "Bearer $token" }

# List all build definitions
az pipelines list --project $project --org $org -o json

# Get a specific build definition (includes variables, triggers, etc.)
az pipelines show --id {buildId} --project $project --org $org -o json

# Get build definition details via REST (includes process, triggers, options)
Invoke-RestMethod -Uri "$org/$project/_apis/build/definitions/{definitionId}?api-version=7.1" -Headers $header

# List build pipeline permissions
az devops security permission list --namespace-id "33344d9c-fc72-4d6f-aba5-fa317101a7e9" --token "$project/{definitionId}" --org $org

# Check if pipeline accesses OAuth token
# In the definition JSON, look at: process.phases[].target.allowScriptsAuthAccessOption

# Check pipeline variable groups
# In the definition JSON, look at: variableGroups[]

# Check pipeline triggers
# In the definition JSON, look at: triggers[]
```

---

## Best-Practice Controls

### BUILD-01: No Plain Text Secrets
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Secrets and keys must not be stored as plain text in build variables/task parameters. |
| **Rationale** | Keeping secrets such as connection strings, passwords, keys, etc. in plain text can expose the credentials to a wider audience and can lead to credential theft. Marking them as secret protects them from unintended disclosure and/or misuse. |
| **Collection** | `az pipelines show --id {id} -o json` — inspect `variables` object. Any variable with `isSecret: false` that contains keywords like "password", "secret", "key", "token", "connectionstring" or looks like a credential. |
| **Remediation** | Mark sensitive variables as secret (`isSecret: true`). Better: use variable groups linked to Azure Key Vault. |

### BUILD-02: Static Code Analysis
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | No (manual review) |
| **Check** | Consider adding static code analysis step in your pipelines. |
| **Rationale** | Static code analyzers ensure that many kinds of security vulnerabilities are detected in early stages of software/service development. |
| **Collection** | Review pipeline YAML/definition for static analysis tasks (e.g., SonarQube, Checkmarx, Fortify, CodeQL, Semgrep). |
| **Remediation** | Add a static analysis task to the pipeline. Consider GHAzDO code scanning if available. |

### BUILD-03: Secure Files for Secrets
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | No (manual review) |
| **Check** | Secure Files library must be used to store secret files such as signing certificates, Apple Provisioning Profiles, Android KeyStore files, and SSH keys. |
| **Rationale** | Secure file contents are encrypted and can only be used during the build or release pipeline by referencing them from a task. |
| **Collection** | Review pipeline tasks for hardcoded file paths to certificates/keys. Check if Secure Files library is used. |
| **Remediation** | Upload sensitive files to Secure Files library and reference them via the "Download Secure File" task. |

### BUILD-04: Inactive Build Pipelines
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Inactive build pipelines must be removed if no more required. |
| **Rationale** | Each additional build having access to repositories increases the attack surface. Only active and legitimate build pipelines should be present. |
| **Collection** | `az pipelines runs list --pipeline-ids {id} --top 1` — check the date of the last run. Flag pipelines with no runs in 90+ days. |
| **Remediation** | Delete or disable inactive build pipelines. |

### BUILD-05: Inherited Permissions Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow inherited permission on build definitions. |
| **Rationale** | Disabling inherited permissions lets you finely control access to various operations at the build level. This ensures you follow the principle of least privilege. |
| **Collection** | Check pipeline permissions for inheritance flag. REST: `_apis/build/definitions/{id}` — check security settings. |
| **Remediation** | Disable inheritance on individual build definitions and set explicit permissions. |

### BUILD-06: Settable Variables at Queue Time
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Pipeline variables marked settable at queue time should be carefully reviewed. |
| **Rationale** | Variables marked settable at queue time can be changed by anyone who can queue a build. Such variables can be misused for code injection/data theft attacks. |
| **Collection** | `az pipelines show --id {id} -o json` — check `variables` for `allowOverride: true`. |
| **Remediation** | Remove `allowOverride` from variables that don't need to be settable. Enable org/project setting "Limit variables that can be set at queue time". |

### BUILD-07: Settable URL Variables
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Pipeline variables marked settable at queue time and containing URLs should be avoided. |
| **Rationale** | Settable URL variables can be changed by anyone who can queue a build. Someone can change the URL to a server they control and intercept any secrets used to interact with the intended server. |
| **Collection** | `az pipelines show --id {id} -o json` — check variables with `allowOverride: true` that contain URL patterns. |
| **Remediation** | Remove `allowOverride` from URL-containing variables, or move URLs to non-settable configuration. |

### BUILD-08: External Repository Review
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Review external source code repositories before adding them to your pipeline. |
| **Rationale** | Building code from untrusted external sources can allow an attacker to execute arbitrary code in your pipeline. All repositories added to the pipeline should be carefully reviewed. |
| **Collection** | `az pipelines show --id {id} -o json` — check `repository.type` for values like "GitHub", "GitHubEnterprise", "Bitbucket". |
| **Remediation** | Review all external repositories. Consider mirroring external repos internally. |

### BUILD-09: Task Group Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Builds should not use task groups that are editable by a broad pool of users. |
| **Rationale** | If a broad pool of users (e.g., Contributors) have edit permissions on a task group, then integrity of your pipeline can be compromised by a malicious user who edits the task group. |
| **Collection** | Identify task groups used by the build. Check permissions on each task group for broad group access. |
| **Remediation** | Restrict edit permissions on task groups to pipeline administrators only. |

### BUILD-10: Variable Group Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not use variable groups that are editable by a broad group of users. |
| **Rationale** | If a broad group of users have edit permissions on a variable group, then integrity of your pipeline can be compromised by a malicious user who edits the variable group. |
| **Collection** | Identify variable groups used by the build. Check permissions on each for broad group access. |
| **Remediation** | Restrict edit permissions on variable groups to pipeline administrators only. |

### BUILD-11: Pipeline Authorization Scope
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Limit scope of access for build pipeline to the current project. |
| **Rationale** | If pipelines use project collection level tokens, a vulnerability in one project can be leveraged to attack all other projects. |
| **Collection** | `az pipelines show --id {id} -o json` — check `jobAuthorizationScope`. Value should be "projectScoped" not "projectCollection". |
| **Remediation** | Set pipeline authorization scope to "Current project" in pipeline settings. |

### BUILD-12: Excessive Permissions for Broad Groups
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow build pipeline to have excessive permissions by a broad group of users. |
| **Rationale** | If a broad group (e.g., Contributors) have excessive permissions on a pipeline, a malicious user can abuse these permissions to compromise security. |
| **Collection** | Check pipeline-level security for broad groups with Edit/Admin permissions. |
| **Remediation** | Remove excessive permissions for Contributors and other broad groups. |

### BUILD-13: Fork Builds and Secrets
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not make secrets available to builds for fork of public repository. |
| **Rationale** | For GitHub public repositories, people from outside the organization can create forks and run builds. If this setting is enabled, outsiders can get access to build pipeline secrets meant to be internal. |
| **Collection** | `az pipelines show --id {id} -o json` — check `triggers` for fork settings: `forks.allowSecrets`. |
| **Remediation** | Disable "Make secrets available to builds of forks" in pipeline trigger settings. |

### BUILD-14: Fork Builds on Self-Hosted Agents
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Do not allow build pipeline to build code from forked repository on self-hosted agent. |
| **Rationale** | Since pipelines are associated with a repository and not with specific branches, you must assume the code and YAML files are untrusted. Anyone with a GitHub account can fork the repo and propose contributions. |
| **Collection** | Check pipeline configuration for fork build settings on self-hosted agent pools. |
| **Remediation** | Restrict fork builds to Microsoft-hosted agents only. |

### BUILD-15: CI Triggers on External Repos
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Do not run continuous integration or scheduled builds on untrusted code from external or public GitHub repositories. |
| **Rationale** | Build agents possess a token scoped to either current project or project collection. If an adversary pushed a malicious commit to the upstream public GitHub repo, they can exfiltrate the token. |
| **Collection** | Check pipeline triggers for external/public repositories with CI enabled. |
| **Remediation** | Disable CI triggers for external public repositories. Use manual triggers or PR-triggered builds with approval gates. |

### BUILD-16: OAuth Token Access
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Do not allow agent jobs to access OAuth token unless explicitly required. |
| **Rationale** | Malicious tasks or extensions can use OAuth access token for stealing project details like builds, releases, agent pools, etc. |
| **Collection** | `az pipelines show --id {id} -o json` — check steps/jobs for `env: SYSTEM_ACCESSTOKEN` or `options.allowScriptsAuthAccessOption`. |
| **Remediation** | Remove OAuth token access from pipelines that don't require it. |

### BUILD-17: YAML CI Branch Restrictions
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Use CI triggers to allow YAML CI only from select branches. |
| **Rationale** | If YAML CI is enabled, malicious users with contribute/'create branch' access can push malicious code and trigger the pipeline from a corrupted branch even without permission to queue the pipeline. This bypasses user permissions to access all protected resources. |
| **Collection** | Check pipeline YAML for `trigger:` configuration. If it's `trigger: none` or includes specific branches, it's good. If missing or `trigger: '*'`, flag it. |
| **Remediation** | Add explicit branch filters to CI triggers in the YAML file: `trigger: branches: include: [main, release/*]`. |

### BUILD-18: Default Branch Protection
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | The default branch of the pipeline must have branch protection policies enabled. |
| **Rationale** | The YAML pipeline content in the default branch is used for scheduled runs and repository trigger runs. If the default branch is not protected, malicious users can push changes to edit the pipeline and access all resources. |
| **Collection** | Check branch policies on the default branch of the pipeline's repository. `az repos policy list --repository-id {repoId} --branch main --project $project` |
| **Remediation** | Enable branch protection policies (minimum reviewers, build validation) on the default branch. |
