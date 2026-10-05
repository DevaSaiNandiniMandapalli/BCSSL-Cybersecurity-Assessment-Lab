<#
.SYNOPSIS
    Remove generated scan artifacts from the lab.

.DESCRIPTION
    Deletes raw tool output, normalized findings, consolidated reports,
    evidence records and student progress. Source code, configuration,
    exercises and documentation are never touched, and .gitkeep files are
    preserved so the directory skeleton survives.

    -Force skips the confirmation prompt. Without it you are asked to type
    'yes', and anything else aborts.

.PARAMETER KeepEvidence
    Keep evidence records (raw output and reports are still removed).

.PARAMETER KeepProgress
    Keep student acknowledgements.

.PARAMETER WhatIf
    Supported via -WhatIf for a dry run.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/clean.ps1 -Force
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$KeepEvidence,
    [switch]$KeepProgress,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not $Force -and -not $WhatIfPreference) {
    $answer = Read-Host "This removes generated scan artifacts. Type 'yes' to continue"
    if ($answer -ne 'yes') {
        Write-Host "Cancelled. Nothing was removed."
        exit 0
    }
}

$targets = @(
    @{ Path = 'reports\raw';       Label = 'raw tool output' },
    @{ Path = 'reports\normalized'; Label = 'normalized findings' },
    @{ Path = 'reports\final';      Label = 'consolidated reports' }
)
if (-not $KeepEvidence) {
    $targets += @{ Path = 'evidence'; Label = 'evidence records' }
}
if (-not $KeepProgress) {
    $targets += @{ Path = 'state'; Label = 'run index and student progress' }
}

function Remove-TreeContents {
    param([string]$Root)

    $removed = 0
    if (-not (Test-Path $Root)) { return 0 }

    $items = @()
    foreach ($dir in (Get-ChildItem -Path $Root -Recurse -Directory -Force -ErrorAction SilentlyContinue)) {
        $items += $dir
    }
    foreach ($file in (Get-ChildItem -Path $Root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ($file.Name -ne '.gitkeep') { $items += $file }
    }
    # Deepest paths first so directories are empty when removed.
    $items = $items | Sort-Object { $_.FullName.Length } -Descending

    foreach ($item in $items) {
        if ($item.Name -eq '.gitkeep') { continue }
        try {
            Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
            $script:removedCount++
            $removed++
        } catch {
            Write-Verbose "could not remove $($item.FullName): $($_.Exception.Message)"
        }
    }
    return $removed
}

$script:removedCount = 0

foreach ($target in $targets) {
    $full = Join-Path $projectRoot $target.Path
    if (-not (Test-Path $full)) { continue }
    if ($PSCmdlet.ShouldProcess($target.Path, "remove $($target.Label)")) {
        $count = Remove-TreeContents -Root $full
        Write-Host ("  cleaned {0,-22} {1} item(s)" -f $target.Label, $count)
    }
}

# Python bytecode caches
$cacheDirs = @(Get-ChildItem -Path $projectRoot -Recurse -Directory -Filter '__pycache__' -Force -ErrorAction SilentlyContinue)
foreach ($dir in $cacheDirs) {
    if ($PSCmdlet.ShouldProcess($dir.FullName, 'remove __pycache__')) {
        try {
            Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop
            $script:removedCount++
        } catch { }
    }
}

Write-Host ""
if ($WhatIfPreference) {
    Write-Host "[WHATIF] No files were removed." -ForegroundColor Cyan
    exit 0
}
Write-Host "[ OK ] Removed $script:removedCount item(s). The lab has no scan results." -ForegroundColor Green
Write-Host "      The dashboard shows 'No scan results available.' until you run a scan."
exit 0
