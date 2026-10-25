# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Run N-034 (loopback port takeover while the socket is down; ADR-024 point 6,
ADR-036 point 2) on one target from a clean baseline.

Recreates pakomichi-r004-n034-<Target> from its digest-verified image
(research/r-004/wsl-import.ps1, research/r-004/setup-target.sh: systemd,
python3), restarts it so systemd is PID 1, copies the harness into the
target, runs scenarios.sh, and unregisters it afterwards. Raw output:
.research-local\n-034\runs\<Target>.

WSL2 distributions share one kernel: ip_unprivileged_port_start and user
namespaces are the WSL kernel's, recorded in facts.txt.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12', 'debian13', 'ubuntu2404')][string]$Target,
    [switch]$Keep
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

$name = "pakomichi-r004-n034-$Target"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
$runs = Join-Path $projectRoot ".research-local\n-034\runs\$Target"

function Invoke-Target([string[]]$Arguments) {
    wsl.exe -d $name -u root --cd /tmp -- @Arguments
    if ($LASTEXITCODE -ne 0) { throw "command in $name failed: $($Arguments -join ' ')" }
}

# WSL2 distributions share one network namespace: a listener of another
# running distribution would answer for ours.
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

    Invoke-Target @('rm', '-rf', '/opt/n034')
    Invoke-Target @('cp', '-r', "$linuxRoot/research/n-034", '/opt/n034')

    New-Item -ItemType Directory -Force -Path $runs | Out-Null
    Get-ChildItem -Force -LiteralPath $runs | Remove-Item -Recurse -Force
    $out = "$linuxRoot/.research-local/n-034/runs/$Target"
    wsl.exe -d $name -u root --cd /tmp -- env "N034_OUT=$out" bash /opt/n034/scenarios.sh
    $status = $LASTEXITCODE
    Get-Content -LiteralPath (Join-Path $runs 'facts.txt')
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
