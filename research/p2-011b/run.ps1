# SPDX-License-Identifier: MIT OR Apache-2.0
<#
P2-011b (E2E-07 Pinned source, ADR-027, N-037...N-040) on one target from a
clean baseline.

The P4-001a bed (every process with its real units, the root applier) on
the default loopback port 879: research/p4-001a/prepare.sh with
PAKOMICHI_PORT=879. The source is the test repository
pchi-test-org/pchi-pinned-test, whose releases carry no attestation. The
host runs its workflows as its owner would (owner permission of 2026-10-25
for the test repositories):

  1. `pinned-release` with -FirstVersion, then phase 1 (add, consent,
     approval, install);
  2. `pinned-release` with -SecondVersion, then phase 2 (held until
     approved, then `apt upgrade`);
  3. `r003-replace-asset` for the second release with -Variant (other bytes
     under the same asset name), then phase 3 (`E_ASSET_MUTATED`, the
     approved bytes stay).

Each workflow run is recorded in the runs directory (release-first.json,
release-second.json, release-second-replaced.json): run URL, tag, release
ID, asset ID, and the SHA-256 GitHub states for the asset; the phases get
the digests and release IDs through the environment. A version that was
ever published is refused: both versions must be new, and the second higher.

Raw output: .research-local\p2-011b\runs\<Target> (an earlier run is
renamed, never wiped). Build first: research/p4-001a/build.sh. Needs `gh`
authenticated on the host with the right to run the test repository's
workflows.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('debian12')][string]$Target,
    [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$FirstVersion,
    [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$SecondVersion,
    # The binaries to install (research/p4-001a/build.sh, P4001A_BIN).
    [string]$BinDir = 'C:\temp\pakomichi\p4-001a\bin',
    # The payload marker of the replacement asset (replace-asset.yml input).
    [ValidatePattern('^[a-z0-9-]{1,32}$')][string]$Variant = 'e2e07-replaced',
    # Keep the distribution afterwards (stopped) for inspection.
    [switch]$Keep
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

$repository = 'pchi-test-org/pchi-pinned-test'
$sourceUrl = "https://github.com/$repository"
$releaseWorkflow = 'pinned-release'
$replaceWorkflow = 'r003-replace-asset'
$package = 'pakomichi-r003-fixture'
$helper = Join-Path $PSScriptRoot 'release-workflow.ps1'

if ([version]$SecondVersion -le [version]$FirstVersion) { throw "-SecondVersion $SecondVersion must be higher than -FirstVersion $FirstVersion" }
$name = "pakomichi-r004-p2011b-$Target"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
foreach ($binary in 'pakomichi-state', 'pakomichi-reader', 'pakomichi-signer', 'pakomichi-inspector', 'pakomichi-applier', 'pchi') {
    if (-not (Test-Path -LiteralPath (Join-Path $BinDir $binary))) { throw "missing $binary in $BinDir; run research/p4-001a/build.sh first" }
}
$binLinux = '/mnt/' + $BinDir.Substring(0, 1).ToLowerInvariant() + ($BinDir.Substring(2) -replace '\\', '/')
$runs = Join-Path $projectRoot ".research-local\p2-011b\runs\$Target"
$out = "$linuxRoot/.research-local/p2-011b/runs/$Target"

# Both versions must be new before anything is published.
foreach ($version in $FirstVersion, $SecondVersion) {
    & $helper -Repository $repository -Tag "v$version-mutable" -CheckFree
}

function Invoke-Target([string[]]$Arguments) {
    wsl.exe -d $name -u root --cd /tmp -- @Arguments
    if ($LASTEXITCODE -ne 0) { throw "command in $name failed: $($Arguments -join ' ')" }
}

function Invoke-Phase([string]$Phase, [string[]]$Environment) {
    $common = @("P2011B_OUT=$out", "SOURCE_URL=$sourceUrl")
    wsl.exe -d $name -u root --cd /tmp -- env @common @Environment bash "/opt/p2011b/$Phase.sh" | Out-Host
    return $LASTEXITCODE
}

function Read-Record([string]$File) {
    $record = Get-Content -Raw -LiteralPath $File | ConvertFrom-Json
    if ("$($record.sha256)" -notmatch '^[0-9a-f]{64}$' -or "$($record.release_id)" -notmatch '^[1-9][0-9]*$') {
        throw "$File names no digest or release ID"
    }
    return $record
}

# Publishes v<Version>-mutable with the release workflow; returns its record.
function Publish-Release([string]$Version, [string]$Label) {
    $file = Join-Path $runs "release-$Label.json"
    & $helper -Repository $repository -Workflow $releaseWorkflow -Inputs @{ version = $Version } `
        -Tag "v$Version-mutable" -Asset "${package}_${Version}_all.deb" -NewTag -OutFile $file | Out-Host
    return (Read-Record $file)
}

# WSL2 distributions share one network namespace: nothing else of ours may run.
$running = @(wsl.exe -l --running -q | ForEach-Object { ($_ -replace "`0", '').Trim() } |
        Where-Object { $_ -match '^pakomichi-' -and $_ -ne $name })
if ($running) { throw "other research distributions are running: $($running -join ', ')" }

& powershell.exe -NoProfile -File (Join-Path $projectRoot 'research\r-004\wsl-import.ps1') -Name $name -Image $Target
if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }
$failed = $null
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

    Invoke-Target @('rm', '-rf', '/opt/p4001a', '/opt/p2011b')
    Invoke-Target @('cp', '-r', "$linuxRoot/research/p4-001a", '/opt/p4001a')
    Invoke-Target @('cp', '-r', "$linuxRoot/research/p2-011b", '/opt/p2011b')
    Invoke-Target @('mkdir', '-p', '/opt/p4001a/bin')
    Invoke-Target @('cp', '-r', "$binLinux/.", '/opt/p4001a/bin/')
    Invoke-Target @('env', 'PAKOMICHI_PORT=879', 'bash', '/opt/p4001a/prepare.sh')

    # A previous run is kept under its own name, never wiped: a run that
    # released a version cannot be repeated with the same version.
    if (Test-Path -LiteralPath $runs) {
        Rename-Item -LiteralPath $runs -NewName ("$Target-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) -ErrorAction Stop
    }
    New-Item -ItemType Directory -Force -Path $runs | Out-Null

    $first = Publish-Release $FirstVersion 'first'
    $status = Invoke-Phase 'phase1' @("FIRST_VERSION=$FirstVersion", "FIRST_RELEASE_ID=$($first.release_id)", "FIRST_SHA256=$($first.sha256)")
    if ($status -ne 0) { throw "phase 1 in $name failed (exit $status); v$FirstVersion-mutable is spent" }

    $second = Publish-Release $SecondVersion 'second'
    $status = Invoke-Phase 'phase2' @("FIRST_VERSION=$FirstVersion", "FIRST_RELEASE_ID=$($first.release_id)",
        "SECOND_VERSION=$SecondVersion", "SECOND_RELEASE_ID=$($second.release_id)", "SECOND_SHA256=$($second.sha256)")
    if ($status -ne 0) { throw "phase 2 in $name failed (exit $status); both versions are spent" }

    # Other bytes under the approved asset's name, in the same release.
    $file = Join-Path $runs 'release-second-replaced.json'
    $secondTag = "v$SecondVersion-mutable"
    & $helper -Repository $repository -Workflow $replaceWorkflow `
        -Inputs @{ tag = $secondTag; version = $SecondVersion; variant = $Variant } `
        -Tag $secondTag -Asset "${package}_${SecondVersion}_all.deb" -OutFile $file | Out-Host
    $replaced = Read-Record $file
    if ("$($replaced.release_id)" -ne "$($second.release_id)") { throw "the replacement changed the release ID ($($second.release_id) -> $($replaced.release_id))" }
    $status = Invoke-Phase 'phase3' @("SECOND_VERSION=$SecondVersion", "SECOND_RELEASE_ID=$($second.release_id)",
        "SECOND_SHA256=$($second.sha256)", "REPLACED_SHA256=$($replaced.sha256)")
    if ($status -ne 0) { throw "phase 3 in $name failed (exit $status)" }
}
catch {
    $failed = $_
}
finally {
    wsl.exe --terminate $name | Out-Null
    if (-not $Keep) {
        wsl.exe --unregister $name | Out-Null
        Remove-Item -Recurse -Force -LiteralPath (Join-Path $projectRoot ".vm-local\wsl\$name") -ErrorAction SilentlyContinue
    }
}
if ($failed) { throw $failed }
Write-Output "$Target PASS; raw output in $runs"
