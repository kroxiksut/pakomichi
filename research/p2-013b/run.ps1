# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Run the P2-013b acceptance (ADR-035 process layout) on one target from a clean baseline.

Recreates pakomichi-r004-p2013b-<Target> from its digest-verified image
(research/r-004/wsl-import.ps1, research/r-004/setup-target.sh: systemd,
gpg, gpgv), restarts it so systemd is PID 1, copies the harness, the
binaries and the P3-005a reader units into the target (edits to the
checkout cannot change a run in progress), prepares it, runs
scenarios.sh, and unregisters it afterwards. Raw output:
.research-local\p2-013b\runs\<Target>. Build first: research/p2-013b/build.sh.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12', 'debian13', 'ubuntu2404')][string]$Target,
    [switch]$Keep
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

$name = "pakomichi-r004-p2013b-$Target"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
foreach ($binary in 'pakomichi-reader', 'pakomichi-state', 'pakomichi-signer', 'pakomichi-inspector', 'p3001-publish', 'p3005b-fetch', 'p2013b-call') {
    if (-not (Test-Path -LiteralPath "C:\temp\pakomichi\p2-013b\bin\$binary")) { throw "missing $binary; run research/p2-013b/build.sh first" }
}
$runs = Join-Path $projectRoot ".research-local\p2-013b\runs\$Target"

function Invoke-Target([string[]]$Arguments) {
    wsl.exe -d $name -u root --cd /tmp -- @Arguments
    if ($LASTEXITCODE -ne 0) { throw "command in $name failed: $($Arguments -join ' ')" }
}

# One heavy job at a time, and WSL2 distributions share one network
# namespace: nothing else of ours may be running.
$running = @(wsl.exe -l --running -q | ForEach-Object { ($_ -replace "`0", '').Trim() } |
        Where-Object { $_ -match '^pakomichi-' -and $_ -ne $name })
if ($running) { throw "other research distributions are running: $($running -join ', ')" }

& powershell.exe -NoProfile -File (Join-Path $projectRoot 'research\r-004\wsl-import.ps1') -Name $name -Image $Target
if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }
$status = 1
try {
    Invoke-Target @('bash', "$linuxRoot/research/r-004/setup-target.sh")
    wsl.exe --terminate $name | Out-Null
    Start-Sleep -Seconds 2
    $state = ''
    for ($i = 0; $i -lt 60; $i++) {
        $state = (wsl.exe -d $name -u root --cd /tmp -- systemctl is-system-running 2>$null | Out-String).Trim()
        if ($state -in 'running', 'degraded') { break }
        Start-Sleep -Seconds 2
    }
    if ($state -notin 'running', 'degraded') { throw "systemd in $name did not start (state: $state)" }

    Invoke-Target @('rm', '-rf', '/opt/p2013b')
    Invoke-Target @('cp', '-r', "$linuxRoot/research/p2-013b", '/opt/p2013b')
    Invoke-Target @('rm', '-rf', '/opt/p2013b/call-tool')
    Invoke-Target @('cp', "$linuxRoot/research/p3-005a/units/pakomichi-reader.socket", "$linuxRoot/research/p3-005a/units/pakomichi-reader.service", '/opt/p2013b/units/')
    Invoke-Target @('mkdir', '-p', '/opt/p2013b/bin')
    Invoke-Target @('cp', '-r', '/mnt/c/temp/pakomichi/p2-013b/bin/.', '/opt/p2013b/bin/')
    Invoke-Target @('bash', '/opt/p2013b/prepare.sh')

    New-Item -ItemType Directory -Force -Path $runs | Out-Null
    Get-ChildItem -Force -LiteralPath $runs | Remove-Item -Recurse -Force
    $out = "$linuxRoot/.research-local/p2-013b/runs/$Target"
    wsl.exe -d $name -u root --cd /tmp -- env "P2013B_OUT=$out" bash /opt/p2013b/scenarios.sh
    $status = $LASTEXITCODE
    Get-Content -LiteralPath (Join-Path $runs 'results.tsv')
}
finally {
    wsl.exe --terminate $name | Out-Null
    if (-not $Keep) {
        wsl.exe --unregister $name | Out-Null
        Remove-Item -Recurse -Force -LiteralPath (Join-Path $projectRoot ".vm-local\wsl\$name") -ErrorAction SilentlyContinue
    }
}
if ($status -ne 0) { throw "scenarios in $name failed (exit $status)" }
Write-Output "$Target PASS; raw output in $runs"
