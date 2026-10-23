# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Run the P3-002a pin check on one WSL platform from a clean baseline.

Recreates pakomichi-r001-p3002a-<Platform> from its digest-verified R-001
image, copies the harness into the target so that edits to the checkout
cannot change a run in progress, and runs scenarios.sh as root with the
platform's ordinary update commands. The repository server must already be
listening on 127.0.0.1:18082 (repo-server.py in the R-001 DEB builder,
serving .research-local/p3-002a/repos). The target is removed afterwards.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12', 'debian13', 'ubuntu2404')][string]$Platform,
    [switch]$Keep
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$name = "pakomichi-r001-p3002a-$Platform"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')

& powershell.exe -NoProfile -File (Join-Path $projectRoot 'research\r-001\wsl-import.ps1') -Name $name -Image $Platform
if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }

$env:WSL_UTF8 = '1'
try {
    wsl.exe -d $name -u root --cd /tmp -- cp -r "$linuxRoot/research/p3-002a" /tmp/pakomichi-p3002a-harness
    if ($LASTEXITCODE -ne 0) { throw "copying the harness into $name failed" }
    wsl.exe -d $name -u root --cd /tmp -- env "P3002A_ROOT=$linuxRoot/.research-local/p3-002a" "P3002A_KEYS=$linuxRoot/.research-local/r-001/keys" `
        bash /tmp/pakomichi-p3002a-harness/scenarios.sh $Platform 'apt upgrade' 'apt full-upgrade'
    if ($LASTEXITCODE -ne 0) { throw "scenarios on $name failed" }
}
finally {
    if (-not $Keep) { wsl.exe --unregister $name | Out-Null }
}
