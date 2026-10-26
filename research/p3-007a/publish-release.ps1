# SPDX-License-Identifier: MIT OR Apache-2.0
<#
P3-007a: publish the new release of the test repository kroxiksut/pchi-test
with its own workflow, as its owner would (owner permission of 2026-10-25
for the test repositories), wait for it, write release.json into -RunDir,
and print the SHA-256 GitHub states for the asset. Refuses a version that
was ever published.
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$NewVersion,
    [Parameter(Mandatory = $true)][string]$RunDir,
    # Only check that the version is still free.
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$repository = 'kroxiksut/pchi-test'
$workflow = 'r003-mutable-attested'
$tag = "v$NewVersion-mutable"
$asset = "pakomichi-r003-fixture_${NewVersion}_all.deb"

gh release view $tag --repo $repository --json tagName 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { throw "$repository already has $tag; choose a version that was never published" }
if ($CheckOnly) { return }

$dispatched = (Get-Date).ToUniversalTime()
gh workflow run $workflow --repo $repository -f "version=$NewVersion"
if ($LASTEXITCODE -ne 0) { throw "dispatch of $workflow failed" }
$run = $null
for ($i = 0; $i -lt 80; $i++) {
    Start-Sleep -Seconds 15
    $listed = gh run list --repo $repository --workflow $workflow --event workflow_dispatch --limit 5 --json databaseId,status,conclusion,createdAt,url | ConvertFrom-Json
    $run = @($listed | Where-Object { [datetime]::Parse($_.createdAt).ToUniversalTime() -ge $dispatched.AddSeconds(-30) }) | Select-Object -First 1
    if ($run -and $run.status -eq 'completed') { break }
}
if (-not $run -or $run.status -ne 'completed') { throw "the release workflow did not finish in 20 minutes" }
if ($run.conclusion -ne 'success') { throw "the release workflow ended with $($run.conclusion): $($run.url)" }
$release = gh release view $tag --repo $repository --json tagName,publishedAt,assets | ConvertFrom-Json
$published = @($release.assets | Where-Object { $_.name -eq $asset }) | Select-Object -First 1
if (-not $published -or $published.digest -notmatch '^sha256:([0-9a-f]{64})$') { throw "release $tag has no digest for $asset" }
$sha256 = $Matches[1]
[ordered]@{ workflow_run = $run.url; tag = $release.tagName; published_at = $release.publishedAt; asset = $asset; sha256 = $sha256 } |
    ConvertTo-Json | Out-File -Encoding utf8 (Join-Path $RunDir 'release.json')
Write-Output $sha256
