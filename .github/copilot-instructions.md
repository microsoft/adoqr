## Versioning

This repository uses Semantic Versioning.

For deployable or user-visible changes:
- Update the root `VERSION` file using `X.Y.Z` format only.
- Update `CHANGELOG.md` under `## [Unreleased]` using Keep a Changelog categories: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
- Choose the bump level as follows:
	- `MAJOR` for breaking changes or required migration.
	- `MINOR` for backward-compatible features or enhancements.
	- `PATCH` for bug fixes, documentation updates, refactors, and non-breaking maintenance.
- If the correct bump level is ambiguous, ask before changing `VERSION`.
- Do not describe or rely on versioning behaviors that are not implemented in this repository.

When making version-related edits, keep changelog entries user-facing rather than implementation-focused.

## Entry-point parity (PowerShell + Bash)

`invoke-adoqr.ps1` and `invoke-adoqr.sh` must stay feature-equivalent. Apply
any behavior change to both in the same change set:

- **CLI** — keep flags aligned (PS `-PascalCase`, bash `--kebab-case` + short
  flag where applicable). Update `print_help` and the PS param block together.
- **Defaults & validation** — must match (e.g. `MaxParallel = 3`, output path,
  formats).
- **Reports** — same files, same `assessments/<org>-<timestamp>/` layout, same
  content shape.
- **Auto-open** — use the platform-native opener; honor `ADOQR_NO_OPEN`. Never
  use `Start-Process` to open `.html` on non-Windows hosts.
- **Settings** — both scripts read `adoqr.settings.psd1`; wire new keys into
  both loaders.
- **Docs** — update `README.md` (both usage sections + flag-mapping table) and
  `CHANGELOG.md`.

If a change can't be ported, call out the asymmetry in the changelog and
README.
