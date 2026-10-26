# SPDX-License-Identifier: MIT OR Apache-2.0
<#
P2-008b live run on one target from a clean, digest-verified baseline.

Recreates pakomichi-r004-p2008b-<Target> from its image
(research/r-004/wsl-import.ps1), copies the test binary built by
research/p2-008b/build.sh into it (an edit or rebuild cannot change a run in
progress), runs research/p2-008b/target.sh, and unregisters the distribution
afterwards. Raw output: .research-local\p2-008b\runs\<Target>.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12', 'debian13', 'ubuntu2404', 'alma9', 'fedora44')][string]$Target,
    # Another source: a vendor repository (pgdg, debian12 only), or a copy
    # of the distribution's own archive signed by an unowned copy of its
    # keyring, which must not count as the distribution (copy, APT targets).
    [ValidateSet('', 'pgdg', 'copy')][string]$Vendor = ''
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

$name = "pakomichi-r004-p2008b-$Target"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
$binary = 'C:\temp\pakomichi\p2-008b\bin\pakomichi-lib-tests'
if (-not (Test-Path -LiteralPath $binary)) { throw "missing $binary; run research/p2-008b/build.sh first" }
$run = if ($Vendor) { "$Target-$Vendor" } else { $Target }
$runs = Join-Path $projectRoot ".research-local\p2-008b\runs\$run"

# One heavy job at a time, and WSL2 distributions share one network namespace.
$running = @(wsl.exe -l --running -q | ForEach-Object { ($_ -replace "`0", '').Trim() } |
        Where-Object { $_ -match '^pakomichi-' -and $_ -ne $name })
if ($running) { throw "other research distributions are running: $($running -join ', ')" }

& powershell.exe -NoProfile -File (Join-Path $projectRoot 'research\r-004\wsl-import.ps1') -Name $name -Image $Target
if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }
try {
    wsl.exe -d $name -u root --cd /tmp -- mkdir -p /opt/p2008b
    wsl.exe -d $name -u root --cd /tmp -- cp /mnt/c/temp/pakomichi/p2-008b/bin/pakomichi-lib-tests "$linuxRoot/research/p2-008b/target.sh" /opt/p2008b/
    New-Item -ItemType Directory -Force -Path $runs | Out-Null
    Get-ChildItem -Force -LiteralPath $runs | Remove-Item -Recurse -Force
    wsl.exe -d $name -u root --cd /tmp -- env "P2008B_OUT=$linuxRoot/.research-local/p2-008b/runs/$run" "P2008B_VENDOR=$Vendor" bash /opt/p2008b/target.sh
    $status = $LASTEXITCODE
}
finally {
    wsl.exe --terminate $name | Out-Null
    wsl.exe --unregister $name | Out-Null
    Remove-Item -Recurse -Force -LiteralPath (Join-Path $projectRoot ".vm-local\wsl\$name") -ErrorAction SilentlyContinue
}
if ($status -ne 0) { throw "live run in $name failed (exit $status)" }
Write-Output "$run PASS; raw output in $runs"
