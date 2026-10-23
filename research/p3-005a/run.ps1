# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Run the P3-005a acceptance on one target from a clean baseline.

Recreates pakomichi-r004-p3005a-<Target> from its digest-verified image
(research/r-004/wsl-import.ps1, research/r-004/setup-target.sh: systemd and
tools), restarts it so systemd is PID 1, copies the harness, the binaries
and research/r-004/make_repo.py into the target (edits to the checkout
cannot change a run in progress), prepares it, and runs scenarios.sh. Raw
output: .research-local\p3-005a\runs\<Target>. Build first:
research/p3-005a/build.sh in pakomichi-r004-build.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12', 'alma9', 'fedora44')][string]$Target,
    [switch]$Reuse
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

$name = "pakomichi-r004-p3005a-$Target"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
foreach ($binary in 'pakomichi-reader', 'p3005a-publish') {
    if (-not (Test-Path -LiteralPath "C:\temp\pakomichi\p3-005a\bin\$binary")) { throw "missing $binary; run research/p3-005a/build.sh first" }
}
$runs = Join-Path $projectRoot ".research-local\p3-005a\runs\$Target"

function Invoke-Target([string[]]$Arguments) {
    wsl.exe -d $name -u root --cd /tmp -- @Arguments
    if ($LASTEXITCODE -ne 0) { throw "command in $name failed: $($Arguments -join ' ')" }
}

# WSL2 distributions share one network namespace: stop the other research
# targets so their loopback services cannot answer for ours.
$others = @(wsl.exe -l -q | ForEach-Object { ($_ -replace "`0", '').Trim() } |
        Where-Object { $_ -match '^pakomichi-r004-' -and $_ -ne $name -and $_ -ne 'pakomichi-r004-build' })
foreach ($other in $others) { wsl.exe --terminate $other | Out-Null }

if (-not $Reuse) {
    & powershell.exe -NoProfile -File (Join-Path $projectRoot 'research\r-004\wsl-import.ps1') -Name $name -Image $Target
    if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }
    Invoke-Target @('bash', "$linuxRoot/research/r-004/setup-target.sh")
    wsl.exe --terminate $name | Out-Null
    Start-Sleep -Seconds 2
}

$state = ''
for ($i = 0; $i -lt 60; $i++) {
    $state = (wsl.exe -d $name -u root --cd /tmp -- systemctl is-system-running 2>$null | Out-String).Trim()
    if ($state -in 'running', 'degraded') { break }
    Start-Sleep -Seconds 2
}
if ($state -notin 'running', 'degraded') { throw "systemd in $name did not start (state: $state)" }

Invoke-Target @('rm', '-rf', '/opt/p3005a')
Invoke-Target @('cp', '-r', "$linuxRoot/research/p3-005a", '/opt/p3005a')
Invoke-Target @('rm', '-rf', '/opt/p3005a/publish-tool')
Invoke-Target @('cp', "$linuxRoot/research/r-004/make_repo.py", '/opt/p3005a/make_repo.py')
Invoke-Target @('mkdir', '-p', '/opt/p3005a/bin')
Invoke-Target @('cp', '/mnt/c/temp/pakomichi/p3-005a/bin/pakomichi-reader', '/mnt/c/temp/pakomichi/p3-005a/bin/p3005a-publish', '/opt/p3005a/bin/')
Invoke-Target @('bash', '/opt/p3005a/prepare.sh')

New-Item -ItemType Directory -Force -Path $runs | Out-Null
Get-ChildItem -Force -LiteralPath $runs | Remove-Item -Recurse -Force
$out = "$linuxRoot/.research-local/p3-005a/runs/$Target"
wsl.exe -d $name -u root --cd /tmp -- env "P3005A_OUT=$out" bash /opt/p3005a/scenarios.sh
$status = $LASTEXITCODE
Get-Content -LiteralPath (Join-Path $runs 'results.tsv')
if ($status -ne 0) { throw "scenarios in $name failed" }
