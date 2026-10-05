<#
.SYNOPSIS
    Run the professional lab preflight (Component | Status | Version | Details).

.PARAMETER Json
    Emit machine-readable JSON instead of the formatted table.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/preflight.ps1
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$NoTools
)

$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = $projectRoot

$arguments = @('-m', 'bcssl', 'preflight')
if ($Json) { $arguments += '--json' }
if ($NoTools) { $arguments += '--no-tools' }

Push-Location $projectRoot
try {
    & python @arguments
    $code = $LASTEXITCODE
} finally { Pop-Location }
exit $code
