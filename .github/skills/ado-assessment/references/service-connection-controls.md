# Service Connection Best-Practice Controls

Collect and assess service connection settings against Azure DevOps best practices.

## How to Collect Service Connection Settings

```powershell
$org = "https://dev.azure.com/{organization}"
$project = "{project}"
$header = @{ Authorization = "Bearer $token" }

# List all service connections
az devops service-endpoint list --project $project --org $org -o json

# Get a specific service connection
az devops service-endpoint show --id {endpointId} --project $project --org $org -o json

# Get service connection details via REST (includes authorization, data, permissions)
Invoke-RestMethod -Uri "$org/$project/_apis/serviceendpoint/endpoints/{endpointId}?api-version=7.1" -Headers $header

# Check pipeline permissions for service connection
Invoke-RestMethod -Uri "$org/$project/_apis/pipelines/pipelinePermissions/endpoint/{endpointId}?api-version=7.1-preview.1" -Headers $header

# Check service connection sharing across projects
Invoke-RestMethod -Uri "$org/_apis/serviceendpoint/endpoints/{endpointId}?api-version=7.1" -Headers $header
# Look at: serviceEndpointProjectReferences[] for cross-project sharing

# Check service connection security/permissions
Invoke-RestMethod -Uri "$org/$project/_apis/serviceendpoint/endpoints/{endpointId}/executionhistory?api-version=7.1-preview.1" -Headers $header
```

---

## Best-Practice Controls

### SC-01: Certificate-Based Authentication
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Azure Active Directory applications used in pipeline must use certificate based authentication. |
| **Rationale** | Password/shared secret credentials can be easily shared and compromised. Certificate credentials offer better security. |
| **Collection** | Check service connection `authorization.parameters` for `authenticationType`. Flag connections using `spnKey` (secret) instead of `spnCertificate`. |
| **Remediation** | Reconfigure Azure service connections to use certificate-based or workload identity federation authentication. |

### SC-02: Subscription/Management Group Scope
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Azure service connection should not be provided access at subscription/management group scope. |
| **Rationale** | SPN-based logins do not have MFA protection. It is important to restrict access granted to Azure service connections only to specific resource/resource group as needed. |
| **Collection** | Check service connection `data.scopeLevel`. Flag connections with `scopeLevel: "Subscription"` or `"ManagementGroup"`. |
| **Remediation** | Scope service connections to specific resource groups. Create separate connections for each resource group. |

### SC-03: Usage History Review
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | No (manual review) |
| **Check** | Periodically review usage history of service connection to validate use from legitimate pipelines. |
| **Rationale** | Periodic reviews of request history logs ensures that service connections have been used from legitimate build definitions and avoid major compromise. |
| **Collection** | REST: `_apis/serviceendpoint/endpoints/{id}/executionhistory` |
| **Remediation** | Review execution history. Revoke access for pipelines that shouldn't be using the connection. |

### SC-04: ARM Service Connections Only
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not use classic Azure service connections to access a subscription. |
| **Rationale** | Use Azure Resource Manager type service connections as the ARM model provides security enhancements: stronger RBAC, better auditing, ARM-based deployment/governance, access to managed identities, Key Vault access, AAD-based auth, support for tags and resource groups. |
| **Collection** | Check service connection `type`. Flag connections with type `azure` (classic) instead of `azurerm`. |
| **Remediation** | Create new ARM-based service connections and migrate pipelines. Delete classic connections. |

### SC-05: Inherited Permissions Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow inherited permissions on service connections. |
| **Rationale** | Service connections represent credentials. You should exercise fine-grained control over who can access them. Removing inherited access ensures individuals beyond your control do not get access. |
| **Collection** | Check service connection permissions for inheritance settings. |
| **Remediation** | Disable inheritance on individual service connections and set explicit permissions. |

### SC-06: No Global Group Access
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not grant global groups access to service connections. |
| **Rationale** | Global groups are maintained at organization and project level and may contain users at a very broad scope. Granting elevated permissions to these groups risks exposure to unwarranted individuals. |
| **Collection** | Check service connection permissions for groups like "Contributors", "Project Valid Users", "Build Administrators". |
| **Remediation** | Remove global group permissions. Grant access to specific teams or users only. |

### SC-07: No Build Service Account Direct Access
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not grant Build Service Account direct access to service connections. |
| **Rationale** | Build service account is the default identity used in every build. Providing direct access exposes connection details to all build definitions in the project. |
| **Collection** | Check service connection permissions for "Project Collection Build Service" or "{project} Build Service" accounts. |
| **Remediation** | Remove Build Service Account direct access. Use pipeline-specific permissions instead. |

### SC-08: Not Accessible to All YAML Pipelines
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not make service connection accessible to all (YAML) pipelines. |
| **Rationale** | To support security of pipeline operations, connections must not be granted access to all YAML pipelines. A vulnerability in one pipeline can be leveraged to attack other pipelines having access to critical resources. |
| **Collection** | REST: `_apis/pipelines/pipelinePermissions/endpoint/{id}` — check if `allPipelines.authorized` is `true`. |
| **Remediation** | Disable "Grant access permission to all pipelines". Add individual pipeline authorizations. |

### SC-09: Strong Authentication Methods
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Service connections should use strong authentication methods. |
| **Rationale** | Weaker authentication methods such as basic authentication can be easily compromised. Stronger methods (certificate, token, etc.) offer better security. |
| **Collection** | Check `authorization.scheme` for each service connection. Flag connections using `UsernamePassword` or basic auth. |
| **Remediation** | Reconfigure service connections to use token-based, certificate-based, or workload identity federation authentication. |

### SC-10: Inactive Service Connections
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Inactive service connection must be removed if no more required. |
| **Rationale** | Each inactive service connection increases the window of attack for a malicious user who can use it to access underlying target resources. |
| **Collection** | Check execution history for each service connection. Flag connections with no usage in 90+ days. |
| **Remediation** | Delete inactive service connections after confirming they are no longer needed. |

### SC-11: No Cross-Project Sharing
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Service connections should not be shared across multiple projects. |
| **Rationale** | If a service connection is shared across projects, a user in another project can access data/components they were otherwise not supposed to access. |
| **Collection** | Check `serviceEndpointProjectReferences` for multiple entries. `Invoke-RestMethod -Uri "$org/_apis/serviceendpoint/endpoints/{id}?api-version=7.1" -Headers $header` — check if `isShared` is true. |
| **Remediation** | Create project-specific service connections. Remove cross-project sharing. |

### SC-12: Pipeline-Specific Access
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Ensure that service connection access is granted only to (YAML) pipelines that require it. |
| **Rationale** | If a service connection is shared across multiple pipelines, then a vulnerability in one pipeline can be leveraged to attack other pipelines with access to critical resources. |
| **Collection** | REST: `_apis/pipelines/pipelinePermissions/endpoint/{id}` — review `pipelines[]` list. |
| **Remediation** | Remove unnecessary pipeline authorizations. Grant access only to pipelines that need it. |

### SC-13: Broader Group Excessive Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Broader groups should not have excessive permissions on service connection. |
| **Rationale** | If broader groups (e.g., Contributors) have excessive permissions (Admin/User) on service connections, then confidentiality/integrity of pipelines using the connection can be compromised. |
| **Collection** | Check service connection permissions for broad groups with Admin or User roles. |
| **Remediation** | Remove excessive permissions for broad groups. Grant Reader role only if needed. |

### SC-14: Restricted Cloud Environments
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Azure service connections to certain environments are not permitted from this org. |
| **Rationale** | Service connections should not connect to restricted cloud environments to align with data sovereignty requirements and ensure data and workloads stay in allowed cloud environments. |
| **Collection** | Check `data.environment` for each Azure service connection. |
| **Remediation** | Remove service connections to disallowed cloud environments. |

### SC-15: Branch Restrictions
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Allow service connections to be accessed only by select branches. |
| **Rationale** | Once a service connection is made accessible to a YAML pipeline, malicious users with 'create branch' permissions can access the service connection by queueing the pipeline from any branch. |
| **Collection** | Check service connection approvals and checks for branch control. |
| **Remediation** | Add branch control check to service connection — restrict to main/release branches only. |

### SC-16: Protected Branch for Templates
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Templates required to access the service connection must reside in a protected branch. |
| **Rationale** | If malicious users have 'contribute' permissions to the repository containing the template, they can tamper the template itself and misuse the service connection. |
| **Collection** | Check if required template checks reference a protected branch. |
| **Remediation** | Enable branch protection policies on the branch containing the template. |

### SC-17: No Broader Group Approvers
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Broader groups should not be added as approvers to the service connection. |
| **Rationale** | Any user/group can be added as an approver, which gives users the permission to approve any run of pipelines accessing the resource even if they don't have access to the service connection. |
| **Collection** | Check service connection approvals and checks for broad group approvers. |
| **Remediation** | Remove broad groups as approvers. Add specific individuals or small security teams. |
