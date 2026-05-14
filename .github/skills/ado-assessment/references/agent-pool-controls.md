# Agent Pool Best-Practice Controls

Collect and assess agent pool settings against Azure DevOps best practices.

## How to Collect Agent Pool Settings

```powershell
$org = "https://dev.azure.com/{organization}"
$project = "{project}"
$header = @{ Authorization = "Bearer $token" }

# List all agent pools (org level)
Invoke-RestMethod -Uri "$org/_apis/distributedtask/pools?api-version=7.1" -Headers $header

# Get a specific agent pool
Invoke-RestMethod -Uri "$org/_apis/distributedtask/pools/{poolId}?api-version=7.1" -Headers $header

# List agents in a pool
Invoke-RestMethod -Uri "$org/_apis/distributedtask/pools/{poolId}/agents?api-version=7.1" -Headers $header

# Get agent details (includes capabilities, status, last completed request)
Invoke-RestMethod -Uri "$org/_apis/distributedtask/pools/{poolId}/agents/{agentId}?includeCapabilities=true&includeLastCompletedRequest=true&api-version=7.1" -Headers $header

# Check agent pool permissions
Invoke-RestMethod -Uri "$org/_apis/distributedtask/pools/{poolId}/roles?api-version=7.1" -Headers $header

# Check pipeline permissions for agent pool
Invoke-RestMethod -Uri "$org/$project/_apis/pipelines/pipelinePermissions/queue/{queueId}?api-version=7.1-preview.1" -Headers $header

# List project-level queues (agent pools visible to a project)
Invoke-RestMethod -Uri "$org/$project/_apis/distributedtask/queues?api-version=7.1-preview.1" -Headers $header
```

---

## Best-Practice Controls

### AP-01: Security Patches on Self-Hosted VMs
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | No (manual review) |
| **Check** | Non-hosted agent virtual machines must have all required security patches installed. |
| **Rationale** | Unpatched VMs are easy targets for compromise from various malware/trojan attacks that exploit known vulnerabilities in operating systems and related software. |
| **Collection** | Identify self-hosted agent pools (`isHosted: false`). Check agent OS version and patch level via agent capabilities. |
| **Remediation** | Implement automated patching for self-hosted agent VMs. Use Azure Update Manager or WSUS. |

### AP-02: Hardened OS Image
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | No (manual review) |
| **Check** | Use a security hardened, locked down OS image for self-hosted VMs in agent pool. |
| **Rationale** | The agent machine is serving as a 'gateway' into the corporate environment. Using a locked-down, secure baseline configuration ensures this machine is not leveraged as an entry point. |
| **Collection** | Review self-hosted agent OS images for CIS benchmark compliance. |
| **Remediation** | Use CIS-hardened images for agent VMs. Remove unnecessary software and services. |

### AP-03: Inherited Permissions Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow inherited permission on agent pool. |
| **Rationale** | Disabling inherited permissions lets you finely control access at the agent level. This ensures the principle of least privilege and provides access only to persons that require it. |
| **Collection** | Check agent pool permissions for inheritance settings. |
| **Remediation** | Disable inheritance on individual agent pools and set explicit permissions. |

### AP-04: Auto-Provisioning Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not enable auto-provisioning for agent pools. |
| **Rationale** | By enabling auto-provisioning, the organization agent pool is imported in all new team projects and is accessible immediately. A vulnerability in components used by one project can be leveraged to attack other projects. |
| **Collection** | `Invoke-RestMethod -Uri "$org/_apis/distributedtask/pools/{poolId}?api-version=7.1"` — check `autoProvision` property. |
| **Remediation** | Set `autoProvision: false` on agent pools. Manually grant access per-project. |

### AP-05: Not Accessible to All YAML Pipelines
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not make agent pool accessible to all (YAML) pipelines in the project. |
| **Rationale** | To support security of pipeline operations, agent pools must not be granted access to all YAML pipelines. A vulnerability in one pipeline can be leveraged to attack other pipelines with access to critical resources. |
| **Collection** | REST: `_apis/pipelines/pipelinePermissions/queue/{queueId}` — check if `allPipelines.authorized` is `true`. |
| **Remediation** | Disable "Grant access permission to all pipelines". Add individual pipeline authorizations. |

### AP-06: Inactive Agent Pools
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Inactive agent pools must be removed if no more required. |
| **Rationale** | Agent pools may contain potentially sensitive information (such as code, secrets, pre-release information and logs) from previously run pipelines. Each inactive agent pool can increase exposure. |
| **Collection** | Check agent last completed request date. Flag pools where all agents have no activity in 90+ days. |
| **Remediation** | Delete inactive agent pools after confirming they are no longer needed. |

### AP-07: Auto-Update Enabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Enable auto-update of agents in the pool. |
| **Rationale** | Unpatched agents are easy targets for compromise. Being on the latest OS version significantly reduces risks from security design issues and bugs present in older versions. |
| **Collection** | `Invoke-RestMethod -Uri "$org/_apis/distributedtask/pools/{poolId}?api-version=7.1"` — check `autoUpdate` property. Also check individual agent `version` against latest available. |
| **Remediation** | Enable auto-update on agent pools. Verify agents are running the latest version. |

### AP-08: No Plain Text Secrets in Capabilities
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Secrets and keys must not be stored as plain text in agent capabilities. |
| **Rationale** | Keeping secrets as plain text in agent capabilities can expose credentials. Any user who can deploy a pipeline to run on such agents can access these secrets and compromise the security of resources involving the secrets. |
| **Collection** | REST: `_apis/distributedtask/pools/{poolId}/agents/{agentId}?includeCapabilities=true` — inspect `userCapabilities` for values containing keywords like "password", "secret", "key", "token", "connectionstring". |
| **Remediation** | Remove sensitive data from agent user capabilities. Use pipeline variables or Key Vault instead. |

### AP-09: Broader Group Excessive Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Broader groups should not have excessive permissions on agent pool. |
| **Rationale** | If broader groups (e.g., Contributors) have excessive permissions (Admin/User) on an agent pool, integrity can be compromised by a malicious user. Removing unnecessary access minimizes exposure in case of compromise. |
| **Collection** | Check agent pool role assignments for broad groups (Contributors, Project Valid Users). |
| **Remediation** | Remove excessive role assignments for broad groups. Grant Reader role only where needed. |
