<#
.SYNOPSIS
    Stop the authorized lab target container.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/stop-target.ps1
#>
[CmdletBinding()]
param(
    [switch]$RemoveVolumes
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $projectRoot 'target\docker-compose.yml'

Write-Host ""
Write-Host "Stopping the authorized lab target..."

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[WARN] Docker CLI not found; nothing to stop." -ForegroundColor Yellow
    exit 0
}

Push-Location $projectRoot
try {
    if ($RemoveVolumes) {
        docker compose -f $composeFile down -v
    } else {
        docker compose -f $composeFile down
    }
} finally {
    Pop-Location
}

$remaining = docker ps --filter "name=bcssl-juiceshop" --format "{{.Names}}"
if ($remaining) {
    Write-Host "[FAIL] Container still running: $remaining" -ForegroundColor Red
    exit 1
}

Write-Host "[ OK ] Target stopped. http://localhost:3001 is no longer served." -ForegroundColor Green
exit 0
