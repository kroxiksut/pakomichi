# SPDX-License-Identifier: MIT OR Apache-2.0
<#
P3-007a (E2E-01 GitHub -> APT) on one target from a clean baseline.

The P4-001a bed (every process with its real units, the root applier) on
the default loopback port 879: research/p4-001a/prepare.sh with
PAKOMICHI_PORT=879. Phase 1 adds, synchronizes, and activates
kroxiksut/pchi-test and installs its current release; another source then
offers a higher version of the name (N-027). The host then dispatches the
test repository's release workflow with -NewVersion (owner permission of
2026-10-25 for the test repositories), waits for the release and its
attestation, and phase 2 checks the ordinary update command. A version
that was ever published is refused: the new release must be new.

Raw output: .research-local\p3-007a\runs\<Target>. Build first:
research/p4-001a/build.sh. Needs `gh` authenticated on the host.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12')][string]$Target,
    [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$NewVersion,
    # Stop before the release: a dry run of the bed that publishes nothing.
    [switch]$Phase1Only,
    [switch]$Keep
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

$name = "pakomichi-r004-p3007a-$Target"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
foreach ($binary in 'pakomichi-state', 'pakomichi-reader', 'pakomichi-signer', 'pakomichi-inspector', 'pakomichi-applier', 'pchi') {
    if (-not (Test-Path -LiteralPath "C:\temp\pakomichi\p4-001a\bin\$binary")) { throw "missing $binary; run research/p4-001a/build.sh first" }
}
$runs = Join-Path $projectRoot ".research-local\p3-007a\runs\$Target"

& (Join-Path $PSScriptRoot 'publish-release.ps1') -NewVersion $NewVersion -RunDir $env:TEMP -CheckOnly

function Invoke-Target([string[]]$Arguments) {
    wsl.exe -d $name -u root --cd /tmp -- @Arguments
    if ($LASTEXITCODE -ne 0) { throw "command in $name failed: $($Arguments -join ' ')" }
}

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

    Invoke-Target @('rm', '-rf', '/opt/p4001a', '/opt/p3007a')
    Invoke-Target @('cp', '-r', "$linuxRoot/research/p4-001a", '/opt/p4001a')
    Invoke-Target @('cp', '-r', "$linuxRoot/research/p3-007a", '/opt/p3007a')
    Invoke-Target @('mkdir', '-p', '/opt/p4001a/bin')
    Invoke-Target @('cp', '-r', '/mnt/c/temp/pakomichi/p4-001a/bin/.', '/opt/p4001a/bin/')
    Invoke-Target @('env', 'PAKOMICHI_PORT=879', 'bash', '/opt/p4001a/prepare.sh')

    # A previous run is kept under its own name, never wiped: a run that
    # released a version cannot be repeated with the same version.
    if (Test-Path -LiteralPath $runs) {
        Rename-Item -LiteralPath $runs -NewName ("$Target-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) -ErrorAction Stop
    }
    New-Item -ItemType Directory -Force -Path $runs | Out-Null
    $out = "$linuxRoot/.research-local/p3-007a/runs/$Target"
    wsl.exe -d $name -u root --cd /tmp -- env "P3007A_OUT=$out" "NEW_VERSION=$NewVersion" bash /opt/p3007a/phase1.sh
    if ($LASTEXITCODE -ne 0) { throw "phase 1 in $name failed" }
    if ($Phase1Only) { Write-Output "$Target phase 1 PASS (nothing released); raw output in $runs"; return }

    $sha256 = & (Join-Path $PSScriptRoot 'publish-release.ps1') -NewVersion $NewVersion -RunDir $runs | Select-Object -Last 1
    if ($sha256 -notmatch '^[0-9a-f]{64}$') { throw "the release step gave no digest" }

    wsl.exe -d $name -u root --cd /tmp -- env "P3007A_OUT=$out" "NEW_VERSION=$NewVersion" "EXPECTED_SHA256=$sha256" bash /opt/p3007a/phase2.sh
    $status = $LASTEXITCODE
}
finally {
    wsl.exe --terminate $name | Out-Null
    if (-not $Keep) {
        wsl.exe --unregister $name | Out-Null
        Remove-Item -Recurse -Force -LiteralPath (Join-Path $projectRoot ".vm-local\wsl\$name") -ErrorAction SilentlyContinue
    }
}
if ($status -ne 0) { throw "phase 2 in $name failed (exit $status)" }
Write-Output "$Target PASS; raw output in $runs"
