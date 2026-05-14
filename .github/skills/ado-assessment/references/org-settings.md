# Organization-Level Settings

Collect and assess organization-level settings against Azure DevOps best practices.

## How to Collect Org Settings

### REST API Base
```
$org = "https://dev.azure.com/{organization}"
$header = @{ Authorization = "Bearer $token" }
```

### Organization Overview & Policies
```powershell
# Get organization settings / policies
Invoke-RestMethod -Uri "$org/_apis/OrganizationPolicy/Policies?api-version=7.1-preview.1" -Headers $header

# List all projects (check for public ones)
az devops project list --org $org --query "value[].{name:name, visibility:visibility}" -o table

# Get organization details
Invoke-RestMethod -Uri "$org/_apis/connectiondata?api-version=7.1" -Headers $header
```

### Users & Groups
```powershell
# List all users in the organization
az devops user list --org $org --query "members[].{name:user.displayName, access:accessLevel.accountLicenseType, lastAccess:lastAccessedDate}" -o table

# List members of Project Collection Administrators
$securityGroups = Invoke-RestMethod -Uri "$org/_apis/graph/groups?api-version=7.1-preview.1" -Headers $header
# Find PCA group, then list memberships
az devops security group membership list --id "<PCA-group-descriptor>" --org $org

# List extension managers
Invoke-RestMethod -Uri "$org/_apis/extensionmanagement/installedextensions?api-version=7.1-preview.1" -Headers $header
```

### Extensions
```powershell
# List installed extensions
az devops extension list --org $org -o table

# List requested extensions
Invoke-RestMethod -Uri "$org/_apis/extensionmanagement/requestedextensions?api-version=7.1-preview.1" -Headers $header
```

### Audit
```powershell
# Check audit log (requires audit permissions)
Invoke-RestMethod -Uri "$org/_apis/audit/streams?api-version=7.1-preview.1" -Headers $header

# Query recent audit events
Invoke-RestMethod -Uri "$org/_apis/audit/auditlog?api-version=7.1-preview.1" -Headers $header
```

### Pipeline Settings (Org Level)
```powershell
# Get org-level pipeline settings
Invoke-RestMethod -Uri "$org/_apis/build/generalsettings?api-version=7.1-preview.1" -Headers $header
# Returns: enforceSettableVar, disableImpliedYAMLCiTrigger, enforceJobAuthScope, enforceJobAuthScopeForReleases, enforceReferencedRepoScopedToken, etc.
```

### Feed Settings
```powershell
# List org-level feeds
Invoke-RestMethod -Uri "$org/_apis/packaging/feeds?api-version=7.1-preview.1" -Headers $header

# Check org-level feed permissions
Invoke-RestMethod -Uri "$org/_apis/packaging/Feeds/{feedId}/permissions?api-version=7.1-preview.1" -Headers $header
```

---

## Best-Practice Controls

### AUTH-01: AAD Authentication
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Organization must be configured to authenticate users using Azure Active Directory backed credentials. |
| **Rationale** | Using the native enterprise directory for authentication ensures a built-in high level of assurance in user identity. All enterprise organizations are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication. |
| **Remediation** | Connect the organization to an Azure AD tenant via Organization Settings → Azure Active Directory. |

### AUTH-02: External User Access Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not enable access for external users in your organization. |
| **Rationale** | Non-AD accounts (such as xyz@hotmail.com, pqr@outlook.com, etc.) present at any scope within an organization subject your assets to undue risk. These accounts are not managed to the same standards as enterprise tenant identities. They don't have MFA enabled. |
| **Collection** | `az devops user list --org $org` — filter for non-AAD accounts (originId not in tenant). |
| **Remediation** | Remove external users via Organization Settings → Users, or restrict via AAD tenant policy. |

### AUTH-03: Public Projects Disabled
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Public projects should be turned off for your organization. |
| **Rationale** | Data/content in projects that have anonymous access can be downloaded by anyone on the internet without authentication. This can lead to a compromise of corporate data/assets. |
| **Collection** | `az devops project list --org $org -o json` — check `visibility` field for "public". |
| **Remediation** | Organization Settings → Policies → disable "Allow public projects". Change any existing public projects to private. |

### AUTH-04: Guest User Justification
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Justify all guest members that have been granted access to your organization. |
| **Rationale** | Guest user accounts are not carefully managed and governed. If these accounts have admin access, a compromised account can be easily leveraged to access arbitrary resources. |
| **Collection** | `az devops user list --org $org` — filter where `user.origin` = "aad" and `user.subjectKind` = "user" with guest domain. |
| **Remediation** | Review and remove unnecessary guest users. Ensure remaining guests have MFA enforced via conditional access. |

### AUTH-05: Conditional Access Policy
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Consider enabling AAD conditional access policy for your organization. |
| **Rationale** | Enabling AAD conditional access policy helps manage organization restrictions on security group membership, location and network identity, specific operating system and enabled device in a management system. |
| **Collection** | Check Organization Settings → Policies → "Enable Azure Active Directory Conditional Access Policy Validation". |
| **Remediation** | Enable via Organization Settings → Policies. Configure conditional access policies in Azure AD. |

### EXT-01: Extension Review
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Carefully review all extensions enabled for your organization. |
| **Rationale** | Running extensions from untrusted source can lead to all types of attacks and loss of sensitive enterprise data/assets. |
| **Collection** | `az devops extension list --org $org -o json` |
| **Remediation** | Remove unnecessary or untrusted extensions. Establish an extension approval process. |

### EXT-02: Shared Extension Scrutiny
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Exercise due care when installing (private) shared extensions for your organization. |
| **Rationale** | Shared extensions can be risky because they might undergo even lesser scrutiny from a security standpoint. |
| **Collection** | `az devops extension list --org $org -o json` — filter for shared/private extensions. |
| **Remediation** | Review source and publisher of all shared extensions. Remove those not explicitly needed. |

### EXT-03: Extension Manager Review
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Review the set of users who have permission to manage extensions. |
| **Rationale** | Users with extension manager role can install/manage extensions for the organization. By carefully reviewing and removing users that shouldn't be in this role, you can avoid attacks if those user accounts are compromised. |
| **Collection** | Check roles in Organization Settings → Extensions → Permissions. |
| **Remediation** | Remove extension manager role from users who do not require it. |

### EXT-04: Requested Extensions Review
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Carefully review requested extensions for your organization. |
| **Rationale** | Approving and running extensions from untrusted sources can lead to all types of attacks and loss of sensitive enterprise data. |
| **Collection** | REST API: `_apis/extensionmanagement/requestedextensions` |
| **Remediation** | Establish a review/approval policy for extension requests. Deny requests for unvetted extensions. |

### USER-01: Inactive User Access
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Consider revoking access for inactive users in your organization. |
| **Rationale** | Each additional person having access at organization level increases the attack surface. To minimize this risk, ensure that critical resources are accessed only by the legitimate users when required. |
| **Collection** | `az devops user list --org $org` — check `lastAccessedDate`, flag users inactive > 90 days. |
| **Remediation** | Remove or disable users who have not accessed the organization in 90+ days. |

### USER-02: Deleted/Disconnected AAD Users
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Remove access for users whose accounts have been deleted/disconnected from Azure Active Directory. |
| **Rationale** | Cleaning up/removing RBAC entries for users who have left the organization is a good security hygiene practice. |
| **Collection** | Compare ADO user list with AAD directory membership. |
| **Remediation** | Remove orphaned user accounts from the organization. |

### USER-03: Inactive Guest Users
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Remove access for inactive guest users from your organization. |
| **Rationale** | Guest accounts are not managed to the same standards as native enterprise identities. They don't have MFA enabled. Even where needed for business purposes, such accounts should be promptly removed if they have not been active for a specified period. |
| **Collection** | `az devops user list --org $org` — filter guest users with `lastAccessedDate` > 90 days. |
| **Remediation** | Remove inactive guest user accounts. |

### USER-04: Guest Users in Admin Roles
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Remove guest users from administrative roles in your organization. |
| **Rationale** | Guest user accounts are not carefully managed and governed. If these accounts have admin access, a compromised account can be easily leveraged to access arbitrary resources. |
| **Collection** | List members of PCA and other admin groups, cross-reference with guest users. |
| **Remediation** | Remove guest users from all administrative groups. |

### USER-05: Inactive Users in Admin Roles
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Remove inactive users from administrative roles in your organization. |
| **Rationale** | Inactive users in administrative roles provide opportunities for hackers to leverage credential harvesting attacks to gain admin access. It is best to restrict critical roles to active members only. |
| **Collection** | List PCA members, cross-reference with `lastAccessedDate`. |
| **Remediation** | Remove inactive users from all administrative groups. |

### ADMIN-01: Privileged Group Membership
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | No (manual review) |
| **Check** | Review membership of all organization level privileged groups and teams. |
| **Rationale** | Accounts that are a member of these groups without a legitimate business reason increase the risk for your Organization. By carefully reviewing and removing accounts that shouldn't be there, you can avoid attacks if those accounts are compromised. |
| **Collection** | `az devops security group list --org $org --scope organization` then `az devops security group membership list --id <descriptor>` for each privileged group. |
| **Remediation** | Remove members who don't have a legitimate business need for privileged access. |

### ADMIN-02: PCA Count (Max 6)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Ensure that there are at most 6 project collection administrators in your organization. |
| **Rationale** | Each additional person in the administrator role increases the attack surface for the entire organization. |
| **Collection** | Count members of the "Project Collection Administrators" group. |
| **Remediation** | Remove unnecessary members from PCA group. Use just-in-time access where possible. |

### ADMIN-03: PCA Count (Min 2)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Ensure that there are at least 2 project collection administrators in your organization. |
| **Rationale** | Having at least the minimum required number of administrators reduces the risk of losing admin access. This is useful in break-glass scenarios. |
| **Collection** | Count members of the "Project Collection Administrators" group. |
| **Remediation** | Add a second administrator for redundancy. |

### ADMIN-04: Service Accounts in Privileged Roles
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | No (manual review) |
| **Check** | Service accounts cannot support MFA and should not be used for organization activity. |
| **Rationale** | Service accounts are typically not MFA capable. Teams who own these accounts don't exercise due care (e.g., someone may login interactively on servers). Using service accounts in any privileged role exposes the Organization data to 'credential theft'-related attack vectors. |
| **Collection** | Review PCA and admin group members. Flag non-person accounts. |
| **Remediation** | Use managed identities or PATs scoped to minimal permissions instead of service accounts in admin roles. |

### ADMIN-05: ALT Accounts for Admin Activity
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Alternate (ALT) accounts must be used for administrative activity at organization scope. |
| **Rationale** | Corporate accounts are subject to credential theft attacks due to browsing, clicking email links, etc. A compromised account immediately subjects the entire organization to risk if it is privileged. Use of smartcard-backed alternate (SC-ALT) accounts protects the organization. |
| **Collection** | Review admin group members. Check for ALT account naming convention. |
| **Remediation** | Require ALT accounts for all admin-level access. Enforce via policy. |

### ADMIN-06: Project Collection Service Accounts
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Review and minimize accounts that are members of the Project Collection Service Accounts group. |
| **Rationale** | Any accounts that are members of Project Collection Service Accounts are effectively Project Collection Administrators. If an adversary compromises one of these accounts they can take over the entire ADO organization. |
| **Collection** | `az devops security group membership list --id <PCSA-descriptor>` |
| **Remediation** | Remove unnecessary members. Use scoped service connections instead. |

### PIPELINE-01: Pipeline Authorization Scope (Non-Release)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Limit scope of access for non-release pipelines to the current project. |
| **Rationale** | If the authorization scope is not limited to current project, an attacker can build a pipeline from a different (less sensitive project) to access resources in a target (more sensitive) project. |
| **Collection** | REST: `_apis/build/generalsettings` — check `enforceJobAuthScope`. |
| **Remediation** | Organization Settings → Pipelines → Settings → Enable "Limit job authorization scope to current project for non-release pipelines". |

### PIPELINE-02: Pipeline Authorization Scope (Release)
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Limit scope of access for release pipelines to the current project. |
| **Rationale** | Same as PIPELINE-01, applied to release pipelines. |
| **Collection** | REST: `_apis/build/generalsettings` — check `enforceJobAuthScopeForReleases`. |
| **Remediation** | Organization Settings → Pipelines → Settings → Enable "Limit job authorization scope to current project for release pipelines". |

### PIPELINE-03: Pipeline Repository Scope
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Limit scope of access for pipelines to explicitly referenced Azure DevOps repositories. |
| **Rationale** | If authorization scope is not limited to referenced repos, an attacker can create a pipeline that can access sensitive repos. |
| **Collection** | REST: `_apis/build/generalsettings` — check `enforceReferencedRepoScopedToken`. |
| **Remediation** | Organization Settings → Pipelines → Settings → Enable "Protect access to repositories in YAML pipelines". |

### PIPELINE-04: Settable Variables at Queue Time
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Allow queue time changes only to pipeline variables explicitly marked as settable. |
| **Rationale** | By default a pipeline user can set any variables at queue time unless this option is enabled. Enabling this enforces that variables must be explicitly marked settable. |
| **Collection** | REST: `_apis/build/generalsettings` — check `enforceSettableVar`. |
| **Remediation** | Organization Settings → Pipelines → Settings → Enable "Limit variables that can be set at queue time". |

### PIPELINE-05: Auto-Injected Tasks
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Set of auto-injected pipeline tasks should be carefully scrutinized. |
| **Rationale** | Auto-injected pipeline tasks will run in every pipeline. If an attacker can change/influence the task logic/code, it can have catastrophic consequences for the entire organization. |
| **Collection** | Organization Settings → Pipelines → Task groups → review auto-injected tasks. |
| **Remediation** | Remove unnecessary auto-injected tasks. Restrict edit permissions on remaining ones. |

### OAUTH-01: Third-Party OAuth
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Third-party application access via OAuth should be disabled. |
| **Rationale** | Malicious ADO OAuth applications can be used to phish ADO admins or users. OAuth app access should be disabled if your organization does not use any third-party OAuth application. |
| **Collection** | Organization Settings → Policies → check "Third-party application access via OAuth". |
| **Remediation** | Disable unless explicitly required by approved applications. |

### OAUTH-02: SSH Access
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Connecting to Git repos via SSH should be disabled. |
| **Rationale** | Malicious SSH connections to ADO repos can be used to extract sensitive code/content leading to compromise of corporate data. |
| **Collection** | Organization Settings → Policies → check "SSH authentication". |
| **Remediation** | Disable SSH access unless explicitly required. |

### ACCESS-01: Enterprise Access to Projects
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Consider disabling enterprise access to projects in your organization. |
| **Rationale** | If enterprise access to projects is enabled, data/content in enterprise projects can be viewed/downloaded by anyone within the organization. This can lead to compromise of sensitive corporate data. |
| **Collection** | Organization Settings → Policies. |
| **Remediation** | Disable unless required for cross-org collaboration. |

### ACCESS-02: Request Access Policy
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Disable request access policy in your organization. |
| **Rationale** | Access to the ADO instance should be allowed only by joining standard groups set up by the respective teams. If the setting is on, an admin may hurriedly grant access to a potentially malicious user. |
| **Collection** | Organization Settings → Policies → "Request access". |
| **Remediation** | Disable the "Request access" policy. |

### ACCESS-03: Invite New Users
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Review if project and team admins should be allowed to invite new users. |
| **Rationale** | By default, all administrators can invite new users. Restricting this ensures new users can be invited only by organization admins. |
| **Collection** | Organization Settings → Policies → "Invite GitHub users". |
| **Remediation** | Restrict to organization admins only if appropriate. |

### AUDIT-01: Audit Log Backup
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | No (manual review) |
| **Check** | Backup audit logs to an external location periodically. |
| **Rationale** | By default, ADO keeps audit logs for 90 days. Most sensitive operation logs should be retained for 365 days. |
| **Collection** | Check if external log export is configured. |
| **Remediation** | Configure audit log streaming to SIEM or Azure Monitor. Export logs regularly. |

### AUDIT-02: Audit Streaming
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | Yes |
| **Check** | Enable audit streaming to support alerting, monitoring and analysis of audit logs over longer periods. |
| **Rationale** | Audit streaming sends data to other locations for further processing. Sending auditing data to SIEM tools opens possibilities such as alerting on specific events, creating views on audit data, and performing anomaly detection. |
| **Collection** | REST: `_apis/audit/streams` — check if any streams are configured. |
| **Remediation** | Organization Settings → Auditing → configure streaming to Splunk, Azure Monitor, or other SIEM. |

### AUDIT-03: Alerts Configuration
| Field | Value |
|-------|-------|
| **Severity** | Medium |
| **Automated** | No (manual review) |
| **Check** | Alerts must be configured for critical actions on the Organization. |
| **Rationale** | Alerts notify the configured security point of contact about various sensitive activities (e.g., external extensions installed/modified). |
| **Collection** | Manual review of notification settings. |
| **Remediation** | Configure notifications for security-sensitive events under Organization Settings → Notifications. |

### FEED-01: Feed Permissions for Broad Groups
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Do not allow feeds to inherit excessive permissions for a broad group of users at organization level. |
| **Rationale** | If a broad group (e.g., Contributors) is configured with excessive permissions at org level, they are inherited by individual feeds and cannot be removed. The integrity of feeds can be compromised by a malicious user. |
| **Collection** | REST: `_apis/packaging/Feeds/{feedId}/permissions` — check for broad group assignments. |
| **Remediation** | Remove excessive permissions for broad groups on org-level feeds. |

### FEED-02: Feed Creation Permissions
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Allow only limited group of users permission to create feeds in the organization. |
| **Rationale** | If everyone in the organization is granted permission to create feeds, it leads to poor governance and high possibility of attacks that leverage tampering with feeds. |
| **Collection** | Organization Settings → Permissions → check who can create feeds. |
| **Remediation** | Restrict feed creation to a small group of trusted users. |

### FEED-03: External Package Protection
| Field | Value |
|-------|-------|
| **Severity** | High |
| **Automated** | Yes |
| **Check** | Enable protection from externally sourced packages in Azure Artifacts feeds. |
| **Rationale** | Enabling this provides an additional layer of security by preventing malicious packages from public registries being inadvertently consumed. If not set, an attacker can publish a malicious (newer) version of an internal feed package. |
| **Collection** | Feed settings → check "Upstream sources" configuration. |
| **Remediation** | Enable package source protection on all feeds with upstream sources. |

### BADGE-01: Anonymous Badge API
| Field | Value |
|-------|-------|
| **Severity** | Low |
| **Automated** | Yes |
| **Check** | Disable anonymous access to status badge API for parallel pipelines. |
| **Rationale** | Information that appears in the status badge API response should be hidden from external users. |
| **Collection** | Organization Settings → Pipelines → Settings. |
| **Remediation** | Disable anonymous access to status badges. |
