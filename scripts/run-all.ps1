<#
.SYNOPSIS
    Run the safe full assessment: all five tools, then the consolidated report.

.DESCRIPTION
    Workflow:
      1. validate the authorized target
      2. run preflight
      3. run Nmap, Nikto, Nuclei, ZAP and the custom Project #08 scanner
      4. parse, normalize and correlate the results
      5. store evidence with SHA-256 hashes
      6. generate the HTML, JSON and Markdown reports

    A tool that is unavailable or that fails is recorded as such and the run
    continues. The final report states exactly which tools succeeded and which
    did not. No result is ever fabricated.

.PARAMETER Tools
    Comma-separated subset to run (default: all).

.PARAMETER SkipPreflight
    Do not stop when preflight reports blocking problems.

.PARAMETER Open
    Open the HTML report when finished.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/run-all.ps1
#>
[CmdletBinding()]
param(
    [string]$Tools = '',
    [switch]$SkipPreflight,
    [switch]$Open
)

$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = $projectRoot

Write-Host ""
Write-Host "=============================================================="
Write-Host " BCSSL CYBERSECURITY ASSESSMENT LAB - SAFE FULL ASSESSMENT"
Write-Host "=============================================================="
Write-Host "AUTHORIZED TARGET"
Write-Host "  http://localhost:3001"
Write-Host ""

Push-Location $projectRoot
try {
    Write-Host "-- 1/4 target authorization --" -ForegroundColor Cyan
    & python -m bcssl validate-target
    $targetCode = $LASTEXITCODE
    if ($targetCode -ne 0) {
        Write-Host "[FAIL] Target is not authorized. Aborting without running any tool." -ForegroundColor Red
        exit 2
    }

    if (-not $SkipPreflight) {
        Write-Host ""
        Write-Host "-- 2/4 preflight --" -ForegroundColor Cyan
        & python -m bcssl preflight
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[WARN] Preflight reported blocking problems; continuing where safe." -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "-- 3/4 running tools --" -ForegroundColor Cyan
    $runArgs = @('-m', 'bcssl', 'run-all')
    if ($Tools) { $runArgs += @('--tools', $Tools) }
    & python @runArgs
    $runCode = $LASTEXITCODE

    Write-Host ""
    Write-Host "-- 4/4 report --" -ForegroundColor Cyan
    $reportArgs = @('-m', 'bcssl', 'report', '--format', 'html,json,md', '--correlation-view')
    if ($Open) { $reportArgs += '--open' }
    & python @reportArgs
    $reportCode = $LASTEXITCODE

    Write-Host ""
    if ($reportCode -eq 0) {
        Write-Host "[ OK ] Assessment complete. Reports are in reports\final\." -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Report generation failed." -ForegroundColor Red
    }
    if ($runCode -ne 0) {
        Write-Host "      Note: one or more tools did not complete. The report records exactly which." -ForegroundColor Yellow
    }
    exit $reportCode
} finally {
    Pop-Location
}
