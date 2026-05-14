# Contributing to adoqr

Thanks for your interest in improving Azure DevOps Quick Review (adoqr).
This document covers the contributor workflow, repository conventions, and
how to add or modify best-practice checks.

## Quick start

1. **Fork** the repository on GitHub.
2. **Clone** your fork:
   ```powershell
   git clone https://github.com/<you>/adoqr.git
   cd adoqr
   ```
3. **Install prerequisites** (PowerShell 7.4+, Azure CLI, Azure DevOps extension):
   ```powershell
   az extension add --name azure-devops
   ```
4. **Install dev modules** (PSScriptAnalyzer + Pester 5+):
   ```powershell
   Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
   Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -SkipPublisherCheck -Force
   ```
5. **Run the test suite**:
   ```powershell
   Invoke-Pester -Path ./tests -Output Detailed
   ```

## Running the tool locally

```powershell
az login
.\invoke-adoqr.ps1 -Organization "MyOrg" -OutputFormat all
```

Use `-Project` to scope to one or more projects, `-MaxParallel 5` to speed up
multi-project runs, and `-Verbose` for deep diagnostics.

## Repository layout

| Path | Purpose |
|---|---|
| `invoke-adoqr.ps1` | Main script. All helpers, control checks, and reporters live here. |
| `schemas/scan.schema.json` | JSON Schema (draft-07) for the optional JSON output. |
| `tests/` | Pester suites for pure helpers. |
| `assessments/` | Default `-OutputPath`. Generated reports land here; safe to delete. |
| `.github/skills/` | Companion Copilot skill packaging. |

## Adding a new control

1. **Pick an Id and category.** Use an existing prefix where possible — the
   prefix table in `Get-ControlCategory` auto-maps to one of the nine
   ADO-native categories. For a new area, add the prefix to
   `Get-ControlCategory` and the matching `BeforeAll`/`It` cases in
   `tests/Helpers.Tests.ps1`.
2. **Add the check inside an existing `Test-*` function** (or create a new
   one and wire it into both the sequential and parallel code paths near
   the bottom of the script).
3. **Emit results** with `New-ControlResult` — `-Category` is optional and
   auto-derived from `-Id`.
4. **Status values**: `PASS`, `FAIL`, or `NOT CHECKED`.
5. **Severity values**: `High`, `Medium`, or `Low`.
6. **Finding text** should include counts, affected names, and a concrete
   remediation action. The HTML remediation report parses this verbatim.

## Style and quality gates

- **PowerShell 7+ idioms.** Approved verbs, full cmdlet names (no aliases).
- **PSScriptAnalyzer** must report zero errors:
  ```powershell
  Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
  ```
- **Pester suites** must remain green:
  ```powershell
  Invoke-Pester -Path ./tests
  ```
- The CI workflow in [.github/workflows/build.yml](.github/workflows/build.yml)
  runs both on every push and pull request, on both Windows and Linux.

## Commit and PR conventions

- Branch from `main`. Use short, descriptive branch names.
- Keep PRs focused. Mix doc-only and code changes only when they're tightly
  related.
- New controls should include test coverage where the logic is non-trivial
  (e.g. policy scope matching).

## Reporting security issues

Please **do not** open public issues for security-sensitive problems.
See [SECURITY.md](SECURITY.md) for the disclosure process.
