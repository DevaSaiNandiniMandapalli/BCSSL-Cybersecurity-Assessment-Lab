<#
.SYNOPSIS
    Stop the lab: dashboard, target container and any scan still running.

.DESCRIPTION
    Shuts down the dashboard process, stops the authorized target container and
    reports anything left behind. Safe to run more than once.

.PARAMETER KeepTarget
    Leave the training target running.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/stop-lab.ps1
#>
[CmdletBinding()]
param(
    [switch]$KeepTarget
)

$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "Stopping the lab..."

# --- dashboard ------------------------------------------------------------
$dashboard = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'bcssl\s+web' }
if ($dashboard) {
    foreach ($process in $dashboard) {
        Write-Host "  stopping dashboard PID $($process.ProcessId)"
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "  no dashboard process running"
}

# --- target ---------------------------------------------------------------
if ($KeepTarget) {
    Write-Host "  leaving the training target running (per -KeepTarget)"
} else {
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'stop-target.ps1')
}

# --- leftover scans -------------------------------------------------------
$scans = Get-CimInstance Win32_Process -Filter "Name='docker.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'zaproxy|nuclei|nikto|instrumentisto/nmap' }
if ($scans) {
    Write-Host "  warning: $($scans.Count) scan container(s) still running" -ForegroundColor Yellow
    Write-Host "  stop them with: docker ps --filter ancestor=ghcr.io/zaproxy/zaproxy:stable" -ForegroundColor DarkGray
}

Write-Host "[ OK ] Lab stopped." -ForegroundColor Green
exit 0
