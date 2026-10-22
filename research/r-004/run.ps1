# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Run R-004 on one target from a clean baseline.

Recreates pakomichi-r004-<Target> from its digest-verified image, installs
systemd and the tools (stage 1), restarts the distribution so systemd is
PID 1, copies the harness and the r004-snapshotd binary into the target
(so edits to the checkout cannot change a run in progress), prepares it,
and runs the scenario areas. Raw output: .research-local\r-004\runs\<Target>.
Build the binary first: research/r-004/build.sh in pakomichi-r004-build.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12', 'alma9', 'fedora44')][string]$Target,
    [string[]]$Areas = @('env', 'socket', 'gen', 'cas', 'http', 'db', 'measure', 'third'),
    # Reuse an existing stage-1 distribution instead of recreating it.
    [switch]$Reuse
)

# Continue: Windows PowerShell 5.1 turns harmless native stderr lines into
# terminating errors under 'Stop'; exit codes are checked explicitly.
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

# `powershell -File ... -Areas a,b` passes one string; split it.
$Areas = @($Areas | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$name = "pakomichi-r004-$Target"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
$binary = 'C:\temp\pakomichi\r004\bin\r004-snapshotd'
if (-not (Test-Path -LiteralPath $binary)) { throw "missing $binary; run research/r-004/build.sh first" }
$runs = Join-Path $projectRoot ".research-local\r-004\runs\$Target"

function Invoke-Target([string[]]$Arguments) {
    wsl.exe -d $name -u root --cd /tmp -- @Arguments
    if ($LASTEXITCODE -ne 0) { throw "command in $name failed: $($Arguments -join ' ')" }
}

# WSL2 distributions share one network namespace: stop the other R-004
# targets so their loopback services (18080, 18090) cannot answer for us.
$others = @(wsl.exe -l -q | ForEach-Object { ($_ -replace "`0", '').Trim() } |
        Where-Object { $_ -match '^pakomichi-r004-' -and $_ -ne $name -and $_ -ne 'pakomichi-r004-build' })
foreach ($other in $others) { wsl.exe --terminate $other | Out-Null }

if (-not $Reuse) {
    & powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'wsl-import.ps1') -Name $name -Image $Target
    if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }
    Invoke-Target @('bash', "$linuxRoot/research/r-004/setup-target.sh")
    wsl.exe --terminate $name | Out-Null
    Start-Sleep -Seconds 2
}

# Boot (or reach) systemd and wait until it has finished starting.
$state = ''
for ($i = 0; $i -lt 60; $i++) {
    $state = (wsl.exe -d $name -u root --cd /tmp -- systemctl is-system-running 2>$null | Out-String).Trim()
    if ($state -in 'running', 'degraded') { break }
    Start-Sleep -Seconds 2
}
if ($state -notin 'running', 'degraded') { throw "systemd in $name did not start (state: $state)" }

Invoke-Target @('rm', '-rf', '/opt/r004')
Invoke-Target @('cp', '-r', "$linuxRoot/research/r-004", '/opt/r004')
Invoke-Target @('cp', '/mnt/c/temp/pakomichi/r004/bin/r004-snapshotd', '/opt/r004/r004-snapshotd')
Invoke-Target @('bash', '/opt/r004/prepare.sh')

New-Item -ItemType Directory -Force -Path $runs | Out-Null
Get-ChildItem -Force -LiteralPath $runs | Remove-Item -Recurse -Force
$out = "$linuxRoot/.research-local/r-004/runs/$Target"
wsl.exe -d $name -u root --cd /tmp -- env "R004_OUT=$out" bash /opt/r004/scenarios.sh @Areas
if ($LASTEXITCODE -ne 0) { throw "scenarios in $name failed" }
Get-Content -LiteralPath (Join-Path $runs 'results.tsv')
