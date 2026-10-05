<#
.SYNOPSIS
    One-time lab setup: verify the environment and fetch Nuclei templates.

.DESCRIPTION
    Checks every dependency the lab needs and reports what is missing with exact
    setup instructions. Optionally fetches the Nuclei template set and builds the
    curated lab profile.

    This script NEVER installs software. It only:
      * verifies Python, Docker and the target
      * pulls the container images the documented Docker transport uses
      * downloads Nuclei template definitions
      * builds the curated template profile

    Every step is verified after it runs; nothing is reported as successful
    unless it actually succeeded.

.PARAMETER SkipImages
    Do not pull container images.

.PARAMETER SkipTemplates
    Do not download Nuclei templates.

.PARAMETER Force
    Re-verify even when everything already looks ready.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipImages,
    [switch]$SkipTemplates,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path -Parent $PSScriptRoot
$failures = @()

function Write-Head($text) {
    Write-Host ""
    Write-Host "=============================================================="
    Write-Host " $text"
    Write-Host "=============================================================="
}

function Write-Ok($text) { Write-Host "[ OK ] $text" -ForegroundColor Green }
function Write-Warn2($text) { Write-Host "[WARN] $text" -ForegroundColor Yellow }
function Write-Fail($text) { Write-Host "[FAIL] $text" -ForegroundColor Red; $script:failures += $text }

Write-Head 'BCSSL CYBERSECURITY ASSESSMENT LAB - SETUP'
Write-Host "AUTHORIZED TARGET"
Write-Host "  http://localhost:3001"
Write-Host ""
Write-Host "This script installs no software. It verifies the environment and"
Write-Host "fetches the data (container images, Nuclei templates) the lab needs."
Write-Host ""

# --- Python ---------------------------------------------------------------
Write-Host "== Python ==" -ForegroundColor Cyan
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Fail 'python not found on PATH. Install Python 3.10+ from https://python.org'
} else {
    $version = (python --version 2>&1) -replace 'Python ', ''
    if ($version -match '^(\d+)\.(\d+)') {
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
            Write-Fail "Python $version is too old; the lab requires 3.10 or newer"
        } else {
            Write-Ok "Python $version"
        }
    }
}

# --- Docker ---------------------------------------------------------------
Write-Host "== Docker ==" -ForegroundColor Cyan
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Fail 'docker CLI not found. Install Docker Desktop: https://docker.com/desktop'
} else {
    $engine = docker info --format '{{.ServerVersion}}' 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Docker engine $engine"
    } else {
        Write-Fail 'Docker engine is not reachable. Start Docker Desktop.'
    }
}

# --- Target ---------------------------------------------------------------
Write-Host "== Authorized target ==" -ForegroundColor Cyan
$container = docker ps --filter "name=bcssl-juiceshop" --format "{{.Status}}" 2>$null
if ($container) {
    Write-Ok "container bcssl-juiceshop: $container"
} else {
    Write-Warn2 'target container not running. Start it with:'
    Write-Host '       powershell -ExecutionPolicy Bypass -File scripts/start-target.ps1'
}
try {
    $probe = Invoke-WebRequest -Uri 'http://localhost:3001' -TimeoutSec 12 -UseBasicParsing
    if ($probe.StatusCode -eq 200) { Write-Ok 'target answers HTTP 200' }
    else { Write-Warn2 "target answered HTTP $($probe.StatusCode)" }
} catch {
    Write-Warn2 "target did not respond yet ($($_.Exception.Message))"
}

# --- Container images -----------------------------------------------------
if (-not $SkipImages) {
    Write-Host "== Container images ==" -ForegroundColor Cyan
    $images = @(
        @{ Name = 'bkimminich/juice-shop'; Purpose = 'training target' },
        @{ Name = 'instrumentisto/nmap';   Purpose = 'Nmap runner fallback' },
        @{ Name = 'alpine/nikto';          Purpose = 'Nikto runner fallback' },
        @{ Name = 'projectdiscovery/nuclei'; Purpose = 'Nuclei runner fallback' },
        @{ Name = 'ghcr.io/zaproxy/zaproxy:stable'; Purpose = 'OWASP ZAP runner fallback' }
    )
    foreach ($image in $images) {
        docker image inspect $image.Name *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "$($image.Name) present ($($image.Purpose))"
        } else {
            Write-Host "       pulling $($image.Name) ... ($($image.Purpose))" -ForegroundColor DarkGray
            docker pull $image.Name *> $null
            if ($LASTEXITCODE -eq 0) { Write-Ok "$($image.Name) pulled" }
            else { Write-Warn2 "could not pull $($image.Name); that tool will report TOOL NOT INSTALLED" }
        }
    }
}

# --- Nuclei templates -----------------------------------------------------
if (-not $SkipTemplates) {
    Write-Host "== Nuclei templates ==" -ForegroundColor Cyan
    $profileCount = (Get-ChildItem (Join-Path $projectRoot 'tools\nuclei\templates-lab') -Recurse -Filter *.yaml -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($profileCount -gt 0 -and -not $Force) {
        Write-Ok "lab template profile already built ($profileCount templates)"
    } else {
        Push-Location $projectRoot
        try {
            $env:PYTHONPATH = $projectRoot
            $output = python -m bcssl update-templates 2>&1
            if ($LASTEXITCODE -eq 0) { Write-Ok 'nuclei templates downloaded' }
            else { Write-Warn2 "template download failed: $($output -join ' ')" }

            $output = python -m bcssl build-template-profile 2>&1
            if ($LASTEXITCODE -eq 0) { Write-Ok 'lab template profile built' }
            else { Write-Warn2 "profile build failed: $($output -join ' ')" }
        } finally { Pop-Location }
    }
}

# --- Summary --------------------------------------------------------------
Write-Head 'SETUP SUMMARY'
if ($failures.Count -eq 0) {
    Write-Host "Setup checks passed. Run the full preflight for detail:" -ForegroundColor Green
    Write-Host "  python -m bcssl preflight"
    exit 0
}
Write-Host "Outstanding problems:" -ForegroundColor Yellow
foreach ($failure in $failures) { Write-Host "  - $failure" -ForegroundColor Yellow }
exit 1
