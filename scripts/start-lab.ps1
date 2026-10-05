<#
.SYNOPSIS
    Start the lab: the authorized target, then the local web dashboard.

.DESCRIPTION
    Brings up http://localhost:3001 and starts the dashboard on
    http://127.0.0.1:8765 so a student can see real state only. No fake scan
    results are ever displayed.

.PARAMETER Port
    Dashboard port (default 8765).

.PARAMETER NoTarget
    Skip starting the training target.

.PARAMETER Background
    Start the dashboard as a detached process and return immediately.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/start-lab.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 8765,
    [switch]$NoTarget,
    [switch]$Background,
    [switch]$Open
)

$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not $NoTarget) {
    Write-Host "Starting the authorized target..."
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'start-target.ps1')
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARN] Target did not start; scans will report TARGET UNREACHABLE." -ForegroundColor Yellow
    }
}

$env:PYTHONPATH = $projectRoot
$dashboardUrl = "http://127.0.0.1:$Port"

Write-Host ""
Write-Host "=============================================================="
Write-Host " BCSSL CYBERSECURITY ASSESSMENT LAB"
Write-Host "=============================================================="
Write-Host "AUTHORIZED TARGET"
Write-Host "  http://localhost:3001"
Write-Host ""
Write-Host "Dashboard : $dashboardUrl"
Write-Host ""

if ($Background) {
    $logDir = Join-Path $projectRoot 'state'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $log = Join-Path $logDir 'dashboard.log'
    Start-Process -FilePath 'python' `
        -ArgumentList @('-m', 'bcssl', 'web', '--port', "$Port") `
        -WorkingDirectory $projectRoot `
        -RedirectStandardOutput $log `
        -RedirectStandardError "$log.err" `
        -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "[ OK ] Dashboard starting in the background (log: state/dashboard.log)" -ForegroundColor Green
    exit 0
}

if ($Open) { Start-Process $dashboardUrl }
Write-Host "Press Ctrl+C to stop the dashboard." -ForegroundColor DarkGray
Push-Location $projectRoot
try { & python -m bcssl web --port $Port --open } finally { Pop-Location }
