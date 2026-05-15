# Remediation steps data for adoqr
#
# Each key is a control name (as emitted by New-ControlResult). Each value is a
# hashtable with:
#   Steps  — ordered array of human-readable instructions
#   DocUrl — link to the relevant Microsoft Learn page

@{
    'Project Visibility' = @{
        Steps = @('Navigate to Project Settings.','Click Overview.','Under Visibility, select Private.','Save.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/projects/make-project-public'
    }
    'Pipeline Auth Scope (Non-Release)' = @{
        Steps = @('Navigate to Organization Settings (or Project Settings).','Open Settings under Pipelines.','Turn On the setting "Limit job authorization scope to current project for non-release pipelines".')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/secure-access-to-repos'
    }
    'Pipeline Auth Scope (Release)' = @{
        Steps = @('Navigate to Organization Settings (or Project Settings).','Open Settings under Pipelines.','Turn On the setting "Limit job authorization scope to current project for release pipelines".')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/secure-access-to-repos'
    }
    'Pipeline Repository Scope' = @{
        Steps = @('Navigate to Organization Settings (or Project Settings).','Open Settings under Pipelines.','Turn On the setting "Protect access to repositories in YAML pipelines".')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/secure-access-to-repos'
    }
    'Settable Variables at Queue Time' = @{
        Steps = @('Navigate to Organization Settings (or Project Settings).','Open Settings under Pipelines.','Turn On the setting "Limit variables that can be set at queue time".','For each pipeline, mark only necessary variables as "Settable at queue time".')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/inputs'
    }
    'Not Accessible to All YAML Pipelines' = @{
        Steps = @('Navigate to Project Settings.','Open the relevant resource (Service connections / Agent pools / Environments / Secure files / Variable groups).','Select the resource, click the three dots button, then Security.','Under Pipeline permissions, click "Restrict Permission".','Add only the specific YAML pipelines that need access.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/resources'
    }
    'Secret Variables Not in All Pipelines' = @{
        Steps = @('Navigate to Project > Pipelines > Library.','Select the variable group containing secrets.','Click Security (or the three dots > Security).','Under Pipeline permissions, click "Restrict Permission".','Add only the pipelines that need access.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/resources'
    }
    'No Plain Text Secrets' = @{
        Steps = @('Open the pipeline definition (build or release).','Review all variables for sensitive values (passwords, keys, tokens, connection strings).','For each secret, click the lock icon to mark it as a secret variable.','Consider moving secrets to Azure Key Vault and linking via variable groups.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/process/set-secret-variables'
    }
    'Pre-Deployment Approvals' = @{
        Steps = @('Navigate to Project > Pipelines > Releases.','Edit the release pipeline.','Click on the pre-deployment conditions icon (lightning bolt) on the production stage.','Enable Pre-deployment approvals.','Add at least one approver who is not the release creator.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/release/approvals/approvals'
    }
    'Production Approvals' = @{
        Steps = @('Navigate to Project > Pipelines > Environments.','Select the production environment.','Click the three dots > Approvals and checks.','Add an Approvals check with at least one approver.','Consider also adding a Branch control check to restrict to main branch.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals'
    }
    'Credential Scanner' = @{
        Steps = @('Navigate to Project Settings > Repos > Repositories.','Select a repository.','Click Settings tab.','Enable "Push protection" under GitHub Advanced Security for Azure DevOps (GHAzDO).','Alternatively, add a credential scanning task (CredScan, CodeQL) to your build pipeline.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/repos/security/github-advanced-security-secret-scanning'
    }
    'Commit Author Email Validation' = @{
        Steps = @('Navigate to Project Settings > Repos > Repositories.','Select a repository (or All Repositories for project-wide).','Click the Policies tab.','Under Repository Policies, turn On "Commit author email validation".','Configure the author email pattern (e.g., *@yourcompany.com).')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/repos/git/repository-settings#commit-author-email-validation-policy'
    }
    'Subscription/Management Group Scope' = @{
        Steps = @('Navigate to Project Settings.','Open Service connections under Pipelines.','Select the Azure Resource Manager service connection.','Click Edit.','Change the Scope level from Subscription to a specific Resource Group.','Save the changes.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints'
    }
    'No Cross-Project Sharing' = @{
        Steps = @('Navigate to Project Settings.','Open Service connections under Pipelines.','Select a service connection, click the three dots > Security.','Under Project permissions, ensure only the current project has access.','Remove any other projects that no longer require access.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints#project-permissions---cross-project-sharing-of-service-connections'
    }
    'ARM Service Connections Only' = @{
        Steps = @('Navigate to Project Settings.','Open Service connections under Pipelines.','Identify any Azure Classic service connections.','Delete the Azure Classic connection (three dots > Delete).','Create a new Azure Resource Manager service connection scoped to a resource group.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints'
    }
    'AAD Authentication' = @{
        Steps = @('Navigate to Organization Settings > Azure Active Directory.','Click Connect directory.','Select your Azure AD tenant and complete the connection.','Verify all users are AAD-backed.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/connect-organization-to-azure-ad'
    }
    'External User Access Disabled' = @{
        Steps = @('Navigate to Organization Settings > Users.','Filter for users with non-AAD origins (personal accounts).','Review each external user for business justification.','Remove unnecessary external users by clicking the three dots > Remove.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/add-external-user'
    }
    'Public Projects Disabled' = @{
        Steps = @('Navigate to Project Settings > Overview.','Under Visibility, change from Public to Private.','Click Save.','Repeat for each public project.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/projects/make-project-public'
    }
    'Guest User Justification' = @{
        Steps = @('Navigate to Organization Settings > Users.','Filter for guest users (look for #EXT# in email).','Review each guest user for documented business justification.','Remove unnecessary guest users via the three dots > Remove.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'Conditional Access Policy' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Enable "Enable Azure Active Directory (Azure AD) Conditional Access Policy Validation".','Configure Conditional Access policies in Azure AD (requires Azure AD P1/P2).','Test that policies are enforced for ADO access.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies'
    }
    'Third-Party OAuth Disabled' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Find "Third-party application access via OAuth".','Set it to Off.','Review any existing OAuth applications and revoke unnecessary access.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies'
    }
    'SSH Access Disabled' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Find "SSH authentication".','Set it to Off.','Users should use HTTPS with credential managers instead.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies'
    }
    'Request Access Policy Disabled' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Find "Request access".','Set it to Off to prevent users from requesting access to the organization.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies'
    }
    'Invite New Users Restricted' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Find "Allow team and project administrators to invite new users".','Set it to Off.','Only Organization Administrators will be able to add new users.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies'
    }
    'Inactive User Access' = @{
        Steps = @('Navigate to Organization Settings > Users.','Sort by Last Access Date.','Identify users inactive for 90+ days.','Remove or disable inactive accounts via the three dots > Remove.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'Inactive Guest Users' = @{
        Steps = @('Navigate to Organization Settings > Users.','Filter for guest users (#EXT#) and sort by Last Access Date.','Identify guest users inactive for 90+ days.','Remove inactive guest accounts via the three dots > Remove.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'Inactive Users in Admin Roles' = @{
        Steps = @('Navigate to Organization Settings > Permissions (or Project Settings > Permissions).','Select the Administrators group.','Review the Members tab for inactive users.','Remove inactive members who have not accessed the org in 90+ days.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'Guest Users in Admin Roles' = @{
        Steps = @('Navigate to Organization Settings > Permissions (or Project Settings > Permissions).','Select the Administrators group.','Identify any guest users (look for #EXT# in email).','Remove guest users from administrator groups immediately.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'Deleted/Disconnected AAD Users' = @{
        Steps = @('Run the assessment with -IncludeGraphCheck to auto-detect deleted/disabled users.','Navigate to Organization Settings > Users.','Cross-reference with Azure AD to find deleted or disabled accounts.','Remove any users whose AAD accounts no longer exist.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'PCA Count (Max 6)' = @{
        Steps = @('Navigate to Organization Settings > Permissions.','Select "Project Collection Administrators".','Review the Members tab.','Remove unnecessary members to reduce to 6 or fewer.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'PCA Count (Min 2)' = @{
        Steps = @('Navigate to Organization Settings > Permissions.','Select "Project Collection Administrators".','Add at least one backup administrator to ensure continuity.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'Project Admin Count (Max 6)' = @{
        Steps = @('Navigate to Project Settings > Permissions.','Select "Project Administrators".','Review the Members tab.','Remove unnecessary members to reduce to 6 or fewer.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'Project Admin Count (Min 2)' = @{
        Steps = @('Navigate to Project Settings > Permissions.','Select "Project Administrators".','Add at least one backup administrator.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/security-best-practices'
    }
    'Project Collection Service Accounts' = @{
        Steps = @('Navigate to Organization Settings > Permissions.','Select "Project Collection Service Accounts".','Review members — these have PCA-equivalent permissions.','Remove any unnecessary members or service accounts.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions'
    }
    'Extension Review' = @{
        Steps = @('Navigate to Organization Settings > Extensions.','Review each installed extension and its publisher.','Verify the publisher is trusted (Microsoft or verified publisher).','Remove any extensions from untrusted or unknown publishers.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/marketplace/install-extension'
    }
    'Requested Extensions Review' = @{
        Steps = @('Navigate to Organization Settings > Extensions.','Click the Requested tab.','Review each pending request.','Approve trusted extensions and reject unknown ones.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/marketplace/request-extensions'
    }
    'Audit Streaming' = @{
        Steps = @('Navigate to Organization Settings > Auditing.','Click the Streams tab.','Click New Stream to set up audit log streaming.','Select your SIEM target (Splunk, Azure Monitor, Azure Event Grid, etc.).','Configure and enable the stream.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/audit/auditing-streaming'
    }
    'Anonymous Badge API' = @{
        Steps = @('Navigate to Organization Settings (or Project Settings).','Open Settings under Pipelines.','Turn On the setting "Disable anonymous access to badges".')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/create-first-pipeline#add-a-status-badge-to-your-repository'
    }
    'Badge API Access' = @{
        Steps = @('Navigate to Project Settings.','Open Settings under Pipelines.','Turn On the setting "Disable anonymous access to badges".')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/create-first-pipeline#add-a-status-badge-to-your-repository'
    }
    'Feed Permissions for Broad Groups' = @{
        Steps = @('Navigate to Artifacts > select the feed.','Click the gear icon (Feed settings).','Click Permissions.','For broad groups (Contributors, Readers, Valid Users), set role to Reader.','Remove any unnecessary admin/write access.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/artifacts/feeds/feed-permissions'
    }
    'No Broad Upload Permissions' = @{
        Steps = @('Navigate to Artifacts > select the feed.','Click the gear icon (Feed settings).','Click Permissions.','Restrict upload (Contributor/Collaborator) roles to specific service accounts or build identities.','Set broad groups to Reader only.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/artifacts/feeds/feed-permissions'
    }
    'External Package Protection' = @{
        Steps = @('Navigate to Artifacts > select the feed.','Click the gear icon (Feed settings).','Review Upstream sources.','Disable unnecessary upstream sources.','Enable "Override packages from public sources" protection if available.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/artifacts/concepts/upstream-sources'
    }
    'Maximum PAT Lifetime Policy' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Find "Enforce maximum personal access token lifespan".','Set it to On and configure the maximum lifetime (e.g., 90 days).')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/manage-pats-with-policies-for-administrators'
    }
    'Restrict PAT Scope' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Find "Restrict scope of personal access tokens".','Set it to On to enforce scoped PATs.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/manage-pats-with-policies-for-administrators'
    }
    'Restrict Global PATs' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Find "Restrict global personal access tokens".','Set it to On to block full-access PATs.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/manage-pats-with-policies-for-administrators'
    }
    'Minimum Required Permissions' = @{
        Steps = @('Navigate to User Settings > Personal access tokens.','Select the PAT with full access.','Click Edit / Regenerate.','Select only the specific scopes needed (e.g., Code: Read, Build: Read & execute).','Save with the restricted scope.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate'
    }
    'Short Validity Period' = @{
        Steps = @('Navigate to User Settings > Personal access tokens.','Select the long-lived PAT.','Click Regenerate.','Set the expiration to 90 days or less.','Update any automation using the old PAT value.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate'
    }
    'Near-Expiry PAT Renewal' = @{
        Steps = @('Navigate to User Settings > Personal access tokens.','Identify the PAT expiring within 7 days.','Click Regenerate to extend with appropriate scope and duration.','Update any automation or scripts using the PAT.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate'
    }
    'No Critical Permission PATs' = @{
        Steps = @('Navigate to User Settings > Personal access tokens.','Identify PATs with critical scopes (security_manage, entitlements, project_manage).','Delete the PAT and recreate with minimal required scopes.','For automation, use a Service Principal or Managed Identity instead.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate'
    }
    'Auto-Provisioning Disabled' = @{
        Steps = @('Navigate to Organization Settings > Pipelines > Agent pools.','Click Settings.','Turn Off "Auto-provision this pool in all projects".','Manually provision pools only in projects that need them.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues'
    }
    'Auto-Update Enabled' = @{
        Steps = @('Navigate to Organization Settings > Pipelines > Agent pools.','Select the agent pool.','Click Settings.','Turn On "Allow agents in this pool to automatically update".')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/agents#agent-version-and-upgrades'
    }
    'No Plain Text Secrets in Capabilities' = @{
        Steps = @('Navigate to Organization Settings > Agent pools.','Select the pool, then click the Agents tab.','Select an agent and click Capabilities.','Review user-defined capabilities for any values that look like secrets.','Remove or replace with variable references.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/agents#capabilities'
    }
    'Inactive Build Pipelines' = @{
        Steps = @('Navigate to Project > Pipelines.','Identify pipelines that have not run in 90+ days.','Delete or disable unused pipelines via the three dots menu.','Document any pipelines kept for archival purposes.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/get-started/what-is-azure-pipelines'
    }
    'Inactive Release Pipelines' = @{
        Steps = @('Navigate to Project > Pipelines > Releases.','Identify release pipelines that have not run in 90+ days.','Delete or disable unused pipelines via the three dots menu.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/release'
    }
    'Inactive Repositories' = @{
        Steps = @('Navigate to Project > Repos.','Identify repositories with no commits in 180+ days.','Archive or delete unused repositories.','Consider moving to a dedicated archive project.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/repos/git/manage-repos'
    }
    'Inactive Projects' = @{
        Steps = @('Navigate to Organization Settings > Projects.','Identify projects with no recent builds or commits (180+ days).','Contact project owners to confirm the project is still needed.','Disable or delete inactive projects.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/projects/delete-project'
    }
    'Certificate-Based Authentication' = @{
        Steps = @('Navigate to Project Settings > Service connections.','Select the service connection.','Click Edit.','Change authentication from secret to certificate-based or Workload Identity Federation.','Upload the certificate or configure federation.','Save.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/library/connect-to-azure#create-an-azure-resource-manager-service-connection-using-workload-identity-federation'
    }
    'Strong Authentication Methods' = @{
        Steps = @('Navigate to Project Settings > Service connections.','Select the service connection.','Click Edit.','Switch to Workload Identity Federation (recommended) or certificate authentication.','Save and verify pipeline access.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/library/connect-to-azure#create-an-azure-resource-manager-service-connection-using-workload-identity-federation'
    }
    'Use Azure Key Vault' = @{
        Steps = @('Navigate to Project > Pipelines > Library.','Click + Variable group.','Enable "Link secrets from an Azure key vault".','Select the Azure subscription and Key Vault.','Choose the secrets to link.','Save the variable group.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups#link-secrets-from-an-azure-key-vault'
    }
    'Enterprise Access to Projects' = @{
        Steps = @('Navigate to Organization Settings > Policies.','Find "Enterprise access to projects".','Set it to Off to restrict access.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/change-application-access-policies'
    }
    'Pipeline Authorization Scope' = @{
        Steps = @('Open the build pipeline definition.','Click Settings (three dots > Settings).','Under "Build job authorization scope", select "Current project".','Save the pipeline.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/secure-access-to-repos'
    }
    'External Repository Review' = @{
        Steps = @('Open the build pipeline definition.','Check the repository source — if it points to an external repo (GitHub, Bitbucket, etc.).','Review and document the business justification for using external repositories.','Ensure the external repo connection uses least-privilege authentication.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/repos'
    }
    'Fork Builds and Secrets' = @{
        Steps = @('Open the build pipeline definition.','Go to Triggers > Pull request validation.','Uncheck "Make secrets available to builds of forks".','Ensure "Build fork pull requests" is carefully controlled.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/repos#contributions-from-forks'
    }
    'Build Admin Count (Max 100)' = @{
        Steps = @('Navigate to Project Settings > Permissions.','Select "Build Administrators".','Review and remove unnecessary members to keep count reasonable.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/organizations/security/permissions'
    }
    'Settable URL Variables' = @{
        Steps = @('Open the build pipeline definition.','Review variables that accept URL values.','Remove the "Settable at queue time" flag from URL-type variables.','Hardcode trusted URLs or use service connections instead.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/inputs'
    }
    'Settable Variables at Release Time' = @{
        Steps = @('Open the release pipeline definition.','Go to Variables.','Review each variable marked as "Settable at release time".','Remove the settable flag from variables that should not be overridden.')
        DocUrl = 'https://learn.microsoft.com/en-us/azure/devops/pipelines/security/inputs'
    }
}
