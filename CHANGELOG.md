# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog,
and this project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Executive summary now includes an Organization Extensions section that lists all extensions with Installed vs Default classification and installed-first ordering.
- Top navigation now includes an Extensions anchor placed before Run Comparison for faster access to extension findings.

### Fixed
- `-OutputPath` now falls back to the `ADOQR_OUTPUT_PATH` environment variable when it is not supplied, so the Docker image's `ENV ADOQR_OUTPUT_PATH=/reports` (previously read by nothing) is honored. Reports generated from the container now land on the mounted `/reports` volume by default instead of an ephemeral in-container folder that was discarded on `--rm`. An explicit `-OutputPath` still takes precedence.
- Auto-opening the executive HTML report at the end of a run now uses the platform-native opener (`open` on macOS, `xdg-open` on Linux, `Start-Process` on Windows) instead of `Start-Process` for all platforms, which raised `Permission denied` on macOS/Linux because PowerShell tried to execute the `.html` file as a binary.
- Pipeline Authorization Scope checks now evaluate effective scope using project/org pipeline settings (`enforceJobAuthScope` and `enforceJobAuthScopeForReleases`) before pipeline-level values, preventing false positives when scope is enforced at project level.
- Organization policy checks now evaluate policy `value` (with safe casing/boolean normalization) and include the new helper functions in parallel runspace serialization, fixing false results for `OAUTH-02` (SSH Access Disabled) and aligning `OAUTH-01` with the actual policy state.

## [1.1.4] - 2026-05-19

### Added
- Initial release baseline for adoqr.
- Semantic versioning scaffolding with a root `VERSION` file and changelog tracking.

### Fixed
- Executive summary counts now update locally when accepted remediation controls are excluded from active improvement opportunities.
- Top 5 Remediation Actions now keeps its active-item counts and empty-state message in sync with accepted controls.
- Accepted controls now expose a clear "Undo acceptance" action to move a control back into the active remediation list.
- README guidance now reflects the current `-MaxParallel` default, automatic Azure DevOps CLI extension installation, and accepted-control workflow.
