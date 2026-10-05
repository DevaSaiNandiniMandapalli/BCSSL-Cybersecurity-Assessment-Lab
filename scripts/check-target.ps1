<#
.SYNOPSIS
    Verify the authorized target: container state, port and HTTP response.

.DESCRIPTION
    Checks four things and reports each separately, because they fail for
    different reasons:
      1. Docker container state
      2. Port 3001 is bound
      3. HTTP response and status code
      4. Server identity from the response

    Exits non-zero when the target is not usable, so it can gate a CI step or a
    lesson that requires the target.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/check-target.ps1
#>
[CmdletBinding()]
param(
    [switch]$Json
)

$ErrorActionPreference = 'Continue'
$projectRoot = Split-Path -Parent $PSScriptRoot
$targetUrl = 'http://localhost:3001'

$result = [ordered]@{
    target            = $targetUrl
    docker_cli        = $false
    container_running = $false
    container_status  = ''
    port_open         = $false
    http_reachable    = $false
    http_status       = $null
    server_header     = ''
    title             = ''
    authorized        = $true
    ok                = $false
    problems          = @()
}

if (Get-Command docker -ErrorAction SilentlyContinue) {
    $result.docker_cli = $true
    $state = docker ps --filter "name=bcssl-juiceshop" --format "{{.Status}}|{{.Ports}}"
    if ($state) {
        $result.container_running = $true
        $parts = $state -split '\|'
        $result.container_status = $parts[0]
        if ($parts.Count -gt 1 -and $parts[1] -match '127\.0\.0\.1:3001') {
            $result.problems += 'Port mapping is not loopback-only; expected 127.0.0.1:3001'
        }
    } else {
        $result.problems += 'Container bcssl-juiceshop is not running (run scripts/start-target.ps1)'
    }
} else {
    $result.problems += 'Docker CLI not found on PATH'
}

try {
    $tcp = Test-NetConnection -ComputerName 127.0.0.1 -Port 3001 -InformationLevel Quiet -WarningAction SilentlyContinue
    $result.port_open = [bool]$tcp
} catch {
    $result.port_open = $false
}
if (-not $result.port_open) {
    $result.problems += 'Nothing is listening on port 3001'
}

try {
    $response = Invoke-WebRequest -Uri $targetUrl -TimeoutSec 15 -UseBasicParsing
    $result.http_reachable = $true
    $result.http_status = $response.StatusCode
    $result.server_header = [string]$response.Headers['Server']
    if ($response.Content -match '<title>([^<]+)</title>') { $result.title = $Matches[1] }
    if ($response.Content -match 'Juice\s*Shop') { $result.authorized = $true }
    else {
        $result.authorized = $false
        $result.problems += 'The service on port 3001 does not identify itself as Juice Shop'
    }
} catch {
    $result.http_reachable = $false
    $result.problems += "No HTTP response: $($_.Exception.Message)"
}

$result.ok = $result.http_reachable -and $result.authorized -and $result.container_running

if ($Json) {
    $result | ConvertTo-Json -Depth 4
    if ($result.ok) { exit 0 } else { exit 1 }
}

Write-Host ""
Write-Host "=============================================================="
Write-Host " AUTHORIZED TARGET CHECK"
Write-Host "=============================================================="
Write-Host "AUTHORIZED TARGET"
Write-Host "  $targetUrl"
Write-Host ""
function Line($name, $value) { "{0,-22} {1}" -f $name, $value }
Write-Host (Line 'Docker CLI'          $(if ($result.docker_cli) { 'available' } else { 'NOT INSTALLED' }))
Write-Host (Line 'Container running'   $(if ($result.container_running) { $result.container_status } else { 'NO' }))
Write-Host (Line 'Port 3001 open'      $(if ($result.port_open) { 'yes' } else { 'NO' }))
Write-Host (Line 'HTTP reachable'      $(if ($result.http_reachable) { "yes (HTTP $($result.http_status))" } else { 'NO' }))
Write-Host (Line 'Identifies as Juice' $(if ($result.authorized) { 'yes' } else { 'NO' }))
if ($result.title) { Write-Host (Line 'Page title' $result.title) }
Write-Host ""
if ($result.ok) {
    Write-Host "[ OK ] Target is authorized and reachable." -ForegroundColor Green
    exit 0
}
foreach ($problem in $result.problems) {
    Write-Host "[FAIL] $problem" -ForegroundColor Red
}
Write-Host ""
Write-Host "Fix: powershell -ExecutionPolicy Bypass -File scripts/start-target.ps1" -ForegroundColor Yellow
exit 1
