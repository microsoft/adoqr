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
