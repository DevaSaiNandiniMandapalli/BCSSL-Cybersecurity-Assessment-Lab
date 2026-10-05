<#
.SYNOPSIS
    Start the authorized lab target (OWASP Juice Shop) on http://localhost:3001.

.DESCRIPTION
    Brings up the container defined in target/docker-compose.yml, bound to the
    loopback interface only, then waits until it actually answers HTTP before
    reporting success. Startup can take 30-90 seconds while Juice Shop
    initialises its database, so this script polls instead of assuming.

    Nothing is installed by this script. Docker Desktop must already be running.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/start-target.ps1
#>
[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 180,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $projectRoot 'target\docker-compose.yml'

function Write-Step($message) {
    if (-not $Quiet) { Write-Host "==> $message" }
}

Write-Host ""
Write-Host "=============================================================="
Write-Host " BCSSL CYBERSECURITY ASSESSMENT LAB - TARGET"
Write-Host "=============================================================="
Write-Host "AUTHORIZED TARGET"
Write-Host "  http://localhost:3001"
Write-Host ""

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[FAIL] Docker CLI not found on PATH." -ForegroundColor Red
    Write-Host "       Install Docker Desktop: https://docker.com/desktop" -ForegroundColor Yellow
    exit 2
}

docker info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Docker engine is not reachable." -ForegroundColor Red
    Write-Host "       Start Docker Desktop and wait for it to report ready." -ForegroundColor Yellow
    exit 2
}
$engine = docker info --format '{{.ServerVersion}}'
Write-Step "Docker engine $engine"

Write-Step "Starting container from target\docker-compose.yml"
Push-Location $projectRoot
try {
    docker compose -f $composeFile up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] docker compose failed to start the target." -ForegroundColor Red
        Pop-Location
        exit 2
    }
} finally {
    Pop-Location
}

$existing = docker ps --filter "name=bcssl-juiceshop" --format "{{.Status}} {{.Ports}}"
Write-Step "Container state: $existing"

Write-Step "Waiting for http://localhost:3001 to answer (timeout ${TimeoutSeconds}s)"
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $response = Invoke-WebRequest -Uri 'http://localhost:3001' -TimeoutSec 10 -UseBasicParsing
        if ($response.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    Start-Sleep -Seconds 5
}

if (-not $ready) {
    Write-Host ""
    Write-Host "[FAIL] Target did not answer within ${TimeoutSeconds}s." -ForegroundColor Red
    Write-Host "       Recent container log:" -ForegroundColor Yellow
    docker logs --tail 20 bcssl-juiceshop 2>&1 | ForEach-Object { Write-Host "       $_" }
    exit 1
}

Write-Host ""
Write-Host "[ OK ] Target is up." -ForegroundColor Green
Write-Host "       AUTHORIZED TARGET: http://localhost:3001"
Write-Host ""
Write-Host "Next: python -m bcssl preflight" -ForegroundColor Cyan
exit 0
