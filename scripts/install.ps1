<#
.SYNOPSIS
    adoqr installer for Windows.

.DESCRIPTION
    Downloads invoke-adoqr.ps1 (and schemas/scan.schema.json) into a
    local install directory and adds it to the per-user PATH so 'adoqr' can be
    invoked from anywhere.

    One-liner:
        Set-ExecutionPolicy Bypass -Scope Process -Force; `
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; `
        iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/microsoft/adoqr/main/scripts/install.ps1'))

.PARAMETER Ref
    Git ref / tag to install from. Defaults to 'main'.

.PARAMETER InstallDir
    Install directory. Defaults to $env:LOCALAPPDATA\adoqr.

.PARAMETER NoPath
    Skip PATH update.
#>
[CmdletBinding()]
param(
    [string]$Ref = 'main',
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'adoqr'),
    [switch]$NoPath
)

$ErrorActionPreference = 'Stop'

function Write-Header { param([string]$Text) Write-Host $Text -ForegroundColor Cyan }
function Write-Info   { param([string]$Text) Write-Host "  $Text" }
function Write-Warn   { param([string]$Text) Write-Host "  $Text" -ForegroundColor Yellow }

$rawBase    = "https://raw.githubusercontent.com/microsoft/adoqr/$Ref"
$scriptName = 'invoke-adoqr.ps1'
$schemaPath = 'schemas/scan.schema.json'

Write-Header 'adoqr installer'
Write-Info  "Ref         : $Ref"
Write-Info  "Install dir : $InstallDir"

# --- Prerequisites -----------------------------------------------------------
$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if ($pwsh) {
    $pwshVer = (& pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')
    Write-Info "PowerShell  : $pwshVer"
}
else {
    Write-Warn 'PowerShell 7+ (pwsh) was not found. adoqr requires PowerShell 7 for parallel execution.'
    Write-Warn 'Install it from https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows'
}

$az = Get-Command az -ErrorAction SilentlyContinue
if ($az) {
    $azVer = (& az version --query '"azure-cli"' -o tsv 2>$null)
    Write-Info "Azure CLI   : $azVer"
}
else {
    Write-Warn 'Azure CLI (az) was not found on PATH.'
    Write-Warn 'Install it from https://learn.microsoft.com/cli/azure/install-azure-cli-windows'
}

# --- Download ----------------------------------------------------------------
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallDir 'schemas') -Force | Out-Null

Write-Info "Downloading $scriptName..."
Invoke-WebRequest -UseBasicParsing -Uri "$rawBase/$scriptName" -OutFile (Join-Path $InstallDir $scriptName)

try {
    Write-Info "Downloading remediation-steps.psd1..."
    Invoke-WebRequest -UseBasicParsing -Uri "$rawBase/remediation-steps.psd1" -OutFile (Join-Path $InstallDir 'remediation-steps.psd1')
}
catch {
    Write-Warn "remediation-steps.psd1 not found at $Ref (older release?); continuing."
}

try {
    Write-Info "Downloading $schemaPath..."
    Invoke-WebRequest -UseBasicParsing -Uri "$rawBase/$schemaPath" -OutFile (Join-Path $InstallDir $schemaPath)
}
catch {
    Write-Warn "scan.schema.json not found at $Ref (older release?); continuing."
}

# --- adoqr.cmd launcher shim -------------------------------------------------
$launcher = Join-Path $InstallDir 'adoqr.cmd'
$launcherBody = @'
@echo off
pwsh -NoProfile -File "%~dp0invoke-adoqr.ps1" %*
'@
Set-Content -Path $launcher -Value $launcherBody -Encoding ASCII

Write-Header 'Installed.'
Write-Info "Script    : $(Join-Path $InstallDir $scriptName)"
Write-Info "Launcher  : $launcher"

# --- PATH wiring -------------------------------------------------------------
if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    $entries  = if ($userPath) { $userPath -split ';' } else { @() }
    if ($entries -contains $InstallDir) {
        Write-Info "PATH      : already includes $InstallDir"
    }
    else {
        $newPath = ($entries + $InstallDir | Where-Object { $_ }) -join ';'
        [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
        $env:PATH = "$($env:PATH);$InstallDir"
        Write-Info "PATH      : added $InstallDir to the user PATH (open a new shell to activate)"
    }
}

Write-Header 'Run:'
Write-Info '  adoqr -Organization MyOrg'
Write-Info '  adoqr -Organization MyOrg -OutputFormat all'
