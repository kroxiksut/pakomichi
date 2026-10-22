# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Run the R-001 matrix for one platform from a clean baseline.

Recreates pakomichi-r001-<Platform> from its verified image, copies the
harness into the target so that edits to the checkout cannot change a run in
progress, and runs the APT or DNF scenarios as root. The repository server
(repo-server.py in the DEB builder) must already be listening.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12', 'debian13', 'ubuntu2404', 'alma9', 'alma10', 'fedora44')][string]$Platform,
    # Run with R001_ISOLATE=1 as on a shared target; results go to <Platform>-isolated.
    [switch]$Isolate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$kind = if ($Platform -in 'alma9', 'alma10', 'fedora44') { 'dnf' } else { 'apt' }
$name = "pakomichi-r001-$Platform"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$runName = if ($Isolate) { "$Platform-isolated" } else { $Platform }
$isolateFlag = if ($Isolate) { '1' } else { '0' }
$runs = Join-Path $projectRoot ".research-local\r-001\runs\$runName"
# Empty the directory instead of deleting it: a shell whose working directory
# is still inside it would block the deletion.
if (Test-Path -LiteralPath $runs) { Get-ChildItem -Force -LiteralPath $runs | Remove-Item -Recurse -Force }

& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'wsl-import.ps1') -Name $name -Image $Platform
if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }

$env:WSL_UTF8 = '1'
# The checkout as seen from WSL, built without backslash escapes.
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
wsl.exe -d $name -u root --cd /tmp -- cp -r "$linuxRoot/research/r-001" /tmp/pakomichi-r001-harness
if ($LASTEXITCODE -ne 0) { throw "copying the harness into $name failed" }
wsl.exe -d $name -u root --cd /tmp -- env "R001_ROOT=$linuxRoot/.research-local/r-001" "R001_ISOLATE=$isolateFlag" bash "/tmp/pakomichi-r001-harness/$kind-scenarios.sh" $runName
if ($LASTEXITCODE -ne 0) { throw "$kind scenarios on $name failed" }
