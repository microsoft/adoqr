# Security

## Reporting a vulnerability

If you believe you've found a security issue in adoqr (`invoke-adoqr.ps1`,
the generated reports, the JSON schema, or the Copilot skill), please **do
not** file a public GitHub issue. Reports are handled privately so users have
time to update before details are made public.

Please report security issues through one of the following channels:

- **GitHub Security Advisories**: [Open a draft advisory](https://github.com/microsoft/adoqr/security/advisories/new) on this repository.
- **Email**: For Microsoft-affiliated reporters, follow the
  [Microsoft Security Response Center (MSRC) process](https://www.microsoft.com/msrc).

When reporting, please include:

- A description of the issue and the impact you observed.
- The version (commit SHA or release tag) you tested against.
- Steps to reproduce, including any sample inputs or commands.
- Whether the issue can be exploited without organization-admin access.

We aim to acknowledge new reports within five business days and to provide a
status update at least every fortnight until a resolution is shipped.

## Scope

In scope:

- Defects in the assessment script that could leak credentials, tokens, or
  privileged data.
- Defects in the JSON / HTML / Markdown report writers that could enable
  cross-site scripting or content injection in downstream consumers.
- Supply-chain risks in the workflow files under `.github/workflows/`.

Out of scope:

- False-positive or false-negative best-practice findings (please open a
  regular issue or PR for these).
- Misconfiguration of the *target* Azure DevOps organization being scanned
  — those are the findings the tool is designed to surface.

## Disclosure

We follow a [coordinated disclosure model](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):
fixes ship before details are made public, and reporters are credited in the
release notes unless they prefer anonymity.
