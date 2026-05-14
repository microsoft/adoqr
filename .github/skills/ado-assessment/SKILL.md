---
name: ado-assessment
description: 'Review an Azure DevOps organization or project for adherence to Azure DevOps best practices. Use when: running an ADO Quick Review, evaluating org or project configuration, checking adoption of recommended settings, identifying improvement opportunities, ADO best practices, org review, project review.'
---

# Azure DevOps Quick Review

Review an Azure DevOps organization or project for adherence to **Azure DevOps best practices** by collecting settings via Azure CLI / REST API and evaluating them against documented Microsoft recommendations.

**This skill does NOT call AzSK.ADO.** It brings best-practice knowledge derived from those controls and uses native Azure CLI and REST API calls to collect and evaluate settings.

## Workflow

### Phase 1 — Collect Settings

Gather the current configuration of an ADO organization or project using `az devops` CLI commands and REST API calls. The reference files below contain the exact commands and API endpoints for each resource type.

### Phase 2 — Assess Against Best Practices

Compare collected settings against the best-practice controls documented in the reference files. Each control has a severity (High/Medium/Low), a rationale, and remediation guidance. Generate a report showing which best practices have been adopted and which remain as improvement opportunities.

## Prerequisites

```powershell
# Azure CLI 2.81.0+
az version

# Azure DevOps extension
az extension add --name azure-devops

# Login
az login

# Set defaults
az devops configure --defaults organization=https://dev.azure.com/<YourOrg> project=<YourProject>
```

## Authentication

```powershell
# Interactive login
az login

# PAT-based login (for automation)
$env:AZURE_DEVOPS_EXT_PAT = '<your-pat>'
az devops login

# Get REST API bearer token
$token = az account get-access-token --resource "499b84ac-1321-427f-aa17-267ca6975798" --query accessToken -o tsv
```

## Resource Types Covered

| Resource | Controls | Scope |
|---|---|---|
| Organization | 35+ controls | Auth, users, extensions, pipelines, feeds, audit |
| Project | 25+ controls | Visibility, admins, pipelines, permissions, credential scanning |
| Build Pipelines | 20+ controls | Secrets, permissions, forks, branches, task groups |
| Release Pipelines | 12+ controls | Secrets, approvals, permissions, task groups |
| Service Connections | 15+ controls | Auth, scope, access, permissions, branches |
| Agent Pools | 10+ controls | Permissions, auto-provision, patching, secrets |
| Repos / Feeds / Secure Files / Environments | 20+ controls | Access, permissions, branches, approvals |
| Variable Groups | 10+ controls | Secrets, permissions, access, branches |
| Users / PATs | 6+ controls | PAT scope, expiry, alternate credentials |

Each resource is evaluated against documented Microsoft best practices.

## Reference Files

Read the relevant reference file based on the user's assessment scope.

| File | Keywords | Covers |
|---|---|---|
| [references/org-settings.md](./references/org-settings.md) | organization, org, AAD, external users, public projects, extensions, audit, OAuth, SSH, feeds, conditional access, admin | Organization-level settings — collection commands and best-practice controls |
| [references/project-settings.md](./references/project-settings.md) | project, visibility, admin, credential scanner, permissions, pipeline scoping, inactive | Project-level settings — collection commands and best-practice controls |
| [references/build-controls.md](./references/build-controls.md) | build, pipeline, CI, secrets, fork, task group, variable, branch, YAML | Build pipeline best-practice controls — collection commands and assessments |
| [references/release-controls.md](./references/release-controls.md) | release, deployment, approval, CD, production, stage | Release pipeline best-practice controls — collection commands and assessments |
| [references/service-connection-controls.md](./references/service-connection-controls.md) | service connection, endpoint, SPN, certificate, subscription, ARM | Service connection best-practice controls — collection commands and assessments |
| [references/agent-pool-controls.md](./references/agent-pool-controls.md) | agent, pool, self-hosted, auto-provision, auto-update | Agent pool best-practice controls — collection commands and assessments |
| [references/repo-feed-environment-controls.md](./references/repo-feed-environment-controls.md) | repository, repo, feed, artifact, secure file, environment, branch protection | Repos, feeds, secure files, and environment best-practice controls |
| [references/variable-group-controls.md](./references/variable-group-controls.md) | variable group, secret, key vault, linked | Variable group best-practice controls |
| [references/user-pat-controls.md](./references/user-pat-controls.md) | user, PAT, personal access token, alternate credentials, inactive | User and PAT hygiene best-practice controls |
| [references/errors.md](./references/errors.md) | error, 401, 403, permission denied, troubleshoot | Common errors and troubleshooting |

## Assessment Output Format

When reporting results, use this format for each control:

```
| Status | Severity | Control | Finding |
|--------|----------|---------|---------|
| PASS   | High     | AAD authentication enabled | Organization uses AAD-backed auth |
| FAIL   | High     | External user access | 3 external users found with access |
| FAIL   | Medium   | Audit streaming | Audit streaming is not configured |
```

Summarize at the end with counts: `X PASS | Y FAIL | Z NOT CHECKED`

## Saving Results

After the assessment completes, save the results as Markdown files **in the workspace root**. Create separate files for the organization and each project:

| File | Contents |
|---|---|
| `{org-name}-org-assessment.md` | Organization-level controls (auth, users, extensions, pipelines, feeds, audit, agent pools, PATs) |
| `{org-name}-{project-name}-assessment.md` | Project-level controls (visibility, admins, pipeline settings, permissions) **plus** all project-scoped resources: build pipelines, release pipelines, service connections, repos, feeds, environments, variable groups, secure files |

### File naming

- Use the organization short name and project name, lowercased and with spaces replaced by hyphens.
- Examples for org `pbi-demo` with projects `eShop Web Demo` and `CL-DEMO`:
  - `pbi-demo-org-assessment.md`
  - `pbi-demo-eshop-web-demo-assessment.md`
  - `pbi-demo-cl-demo-assessment.md`

### File structure

Each file must include:

1. **Header** — assessment date, organization/project name, assessor
2. **Control results table** — the standard `Status | Severity | Control | Finding` table
3. **Summary counts** — `X PASS | Y FAIL | Z NOT CHECKED`
4. **Critical findings** — list of FAIL items sorted by severity (High first) with remediation steps

### When to write

Write the files at the end of Phase 2 (after all controls are assessed and results are shown to the user). Always create the files — do not ask for confirmation.
