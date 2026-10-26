# SPDX-License-Identifier: MIT OR Apache-2.0
<#
P3-007a (E2E-01) on Astra Linux 1.8.6 over SSH: phase 1, the new release,
phase 2, with `apt-get dist-upgrade` as the ordinary update command
(ADR-022 point 4). The VM, its lease and snapshot are handled outside this
script (local rules); the SSH target and the sudo password file are
parameters only and never written to the repository. SSH runs from the
owner's WSL distribution Ubuntu-24.04, where the key is.

  run-astra.ps1 -SshTarget <user@host> -PassFile <WSL path> -NewVersion x.y.z -Label astra186-orel
#>
param(
    [Parameter(Mandatory = $true)][string]$SshTarget,
    [Parameter(Mandatory = $true)][string]$PassFile,
    [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$NewVersion,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9-]+$')][string]$Label
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
$runs = Join-Path $projectRoot ".research-local\p3-007a\runs\$Label"
$script = "$linuxRoot/research/p3-007a/run-astra.sh"

& (Join-Path $PSScriptRoot 'publish-release.ps1') -NewVersion $NewVersion -RunDir $env:TEMP -CheckOnly

function Invoke-Phase([string]$Phase, [string[]]$Extra) {
    $environment = @("P3007A_TARGET=$SshTarget", "P3007A_SUDO_PASS_FILE=$PassFile", "NEW_VERSION=$NewVersion") + $Extra
    wsl.exe -d Ubuntu-24.04 --cd /tmp -- env @environment bash $script $Phase $Label | Out-Host
    return $LASTEXITCODE
}

if ((Invoke-Phase 'phase1' @()) -ne 0) { throw "phase 1 on $Label failed; nothing was released" }
$sha256 = & (Join-Path $PSScriptRoot 'publish-release.ps1') -NewVersion $NewVersion -RunDir $runs | Select-Object -Last 1
if ($sha256 -notmatch '^[0-9a-f]{64}$') { throw "the release step gave no digest" }
if ((Invoke-Phase 'phase2' @("EXPECTED_SHA256=$sha256")) -ne 0) { throw "phase 2 on $Label failed" }
Write-Output "$Label PASS; raw output in $runs"
