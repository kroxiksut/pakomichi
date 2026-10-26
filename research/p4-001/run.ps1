# SPDX-License-Identifier: MIT OR Apache-2.0
<#
P4-001 `pchi doctor` on one target from a clean baseline: the P4-001a bed
(research/p4-001a/prepare.sh, reader on the default port 879) without a
source, then research/p4-001/doctor.sh. No GitHub request is made. Raw
output: .research-local\p4-001\runs\<Target> (an earlier run is renamed,
never wiped). Build first: research/p4-001a/build.sh.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12', 'debian13', 'ubuntu2404')][string]$Target,
    # The binaries to install (research/p4-001a/build.sh, P4001A_BIN).
    [string]$BinDir = 'C:\temp\pakomichi\p4-001a\bin'
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

$name = "pakomichi-r004-p4001-$Target"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
foreach ($binary in 'pakomichi-state', 'pakomichi-reader', 'pakomichi-signer', 'pakomichi-inspector', 'pakomichi-applier', 'pchi') {
    if (-not (Test-Path -LiteralPath (Join-Path $BinDir $binary))) { throw "missing $binary in $BinDir; run research/p4-001a/build.sh first" }
}
$runs = Join-Path $projectRoot ".research-local\p4-001\runs\$Target"

function Invoke-Target([string[]]$Arguments) {
    wsl.exe -d $name -u root --cd /tmp -- @Arguments
    if ($LASTEXITCODE -ne 0) { throw "command in $name failed: $($Arguments -join ' ')" }
}

# WSL2 distributions share one network namespace: nothing else of ours may run.
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
    Invoke-Target @('rm', '-rf', '/opt/p4001a', '/opt/p4001')
    Invoke-Target @('cp', '-r', "$linuxRoot/research/p4-001a", '/opt/p4001a')
    Invoke-Target @('cp', '-r', "$linuxRoot/research/p4-001", '/opt/p4001')
    Invoke-Target @('mkdir', '-p', '/opt/p4001a/bin')
    $binLinux = '/mnt/' + $BinDir.Substring(0, 1).ToLowerInvariant() + ($BinDir.Substring(2) -replace '\\', '/')
    Invoke-Target @('cp', '-r', "$binLinux/.", '/opt/p4001a/bin/')
    Invoke-Target @('env', 'PAKOMICHI_PORT=879', 'bash', '/opt/p4001a/prepare.sh')
    if (Test-Path -LiteralPath $runs) {
        Rename-Item -LiteralPath $runs -NewName ("$Target-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) -ErrorAction Stop
    }
    New-Item -ItemType Directory -Force -Path $runs | Out-Null
    wsl.exe -d $name -u root --cd /tmp -- env "P4001_OUT=$linuxRoot/.research-local/p4-001/runs/$Target" bash /opt/p4001/doctor.sh
    $status = $LASTEXITCODE
}
finally {
    wsl.exe --terminate $name | Out-Null
    wsl.exe --unregister $name | Out-Null
    Remove-Item -Recurse -Force -LiteralPath (Join-Path $projectRoot ".vm-local\wsl\$name") -ErrorAction SilentlyContinue
}
if ($status -ne 0) { throw "doctor scenarios in $name failed (exit $status)" }
Write-Output "$Target PASS; raw output in $runs"
