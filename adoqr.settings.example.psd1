# adoqr settings file — example / template
#
# Copy this file to adoqr.settings.psd1 in the same directory as
# invoke-adoqr.ps1 to override default values.
#
# All settings are optional. Any key that is omitted keeps its built-in default.
# adoqr.settings.psd1 is git-ignored so your local overrides are never committed.

@{
    # Number of days without a commit before a repository or project is
    # flagged as inactive (controls REPO-01 and PROJ-16 checks).
    # Default: 180
    # InactiveRepoDays = 180
}
