# SPDX-License-Identifier: MIT OR Apache-2.0
<#
P2-011b: run one workflow of a test repository that publishes or changes a
release, as its owner would (owner permission of 2026-10-25 for the test
repositories), wait for it, and write what GitHub then states for the
release asset into -OutFile (JSON: workflow run, tag, release ID, asset ID,
SHA-256 from the API `digest`, and the asset as it was before the run when
the release existed). A generalized research/p3-007a/publish-release.ps1.

  -NewTag     the run creates the release: refuse when the tag exists.
  -CheckFree  only check that the tag is free (implies -NewTag semantics).
Without -NewTag the release must exist (a run that changes its asset).

  release-workflow.ps1 -Repository owner/name -Workflow pinned-release `
      -Inputs @{ version = '1.2.3' } -Tag v1.2.3-mutable `
      -Asset pakomichi-r003-fixture_1.2.3_all.deb -NewTag -OutFile release.json
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository,
    [Parameter(Mandatory = $true)][string]$Tag,
    [string]$Workflow,
    [hashtable]$Inputs = @{},
    [string]$Asset,
    [string]$OutFile,
    [switch]$NewTag,
    [switch]$CheckFree,
    [int]$TimeoutMinutes = 20
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

# A tag reference or a release under the tag. Only reads.
function Test-TagTaken {
    gh api "repos/$Repository/git/ref/tags/$Tag" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { return $true }
    gh release view $Tag --repo $Repository --json tagName 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Get-Release {
    $text = gh api "repos/$Repository/releases/tags/$Tag" 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($text | Out-String | ConvertFrom-Json)
}

# A field the API may leave out, without tripping strict mode.
function Get-Field($Object, [string]$Field) {
    $property = $Object.PSObject.Properties[$Field]
    if ($property) { return $property.Value }
    return $null
}

function Get-Sha256($AssetObject) {
    if ("$(Get-Field $AssetObject 'digest')" -match '^sha256:([0-9a-f]{64})$') { return $Matches[1] }
    return $null
}

function Get-Asset($Release) {
    $found = @($Release.assets | Where-Object { $_.name -eq $Asset })
    if ($found.Count -ne 1) { throw "release $Tag has $($found.Count) assets named $Asset" }
    return $found[0]
}

$taken = Test-TagTaken
if ($CheckFree) {
    if ($taken) { throw "$Repository already has $Tag; choose a version that was never published" }
    return
}
if (-not $Workflow -or -not $Asset -or -not $OutFile) { throw '-Workflow, -Asset, and -OutFile are required' }
if ($NewTag -and $taken) { throw "$Repository already has $Tag; choose a version that was never published" }

$before = $null
if (-not $NewTag) {
    $existing = Get-Release
    if (-not $existing) { throw "$Repository has no release $Tag to change" }
    $before = Get-Asset $existing
}

$fields = @()
foreach ($key in $Inputs.Keys) { $fields += @('-f', "$key=$($Inputs[$key])") }
$dispatched = (Get-Date).ToUniversalTime()
gh workflow run $Workflow --repo $Repository @fields | Out-Host
if ($LASTEXITCODE -ne 0) { throw "dispatch of $Workflow failed" }

$run = $null
$deadline = $dispatched.AddMinutes($TimeoutMinutes)
while ((Get-Date).ToUniversalTime() -lt $deadline) {
    Start-Sleep -Seconds 15
    $listed = gh run list --repo $Repository --workflow $Workflow --event workflow_dispatch --limit 5 `
        --json databaseId,status,conclusion,createdAt,url | Out-String | ConvertFrom-Json
    $run = @($listed | Where-Object { [datetime]::Parse($_.createdAt).ToUniversalTime() -ge $dispatched.AddSeconds(-30) }) |
        Select-Object -Last 1
    if ($run -and $run.status -eq 'completed') { break }
}
if (-not $run -or $run.status -ne 'completed') { throw "$Workflow did not finish in $TimeoutMinutes minutes" }
if ($run.conclusion -ne 'success') { throw "$Workflow ended with $($run.conclusion): $($run.url)" }

$release = Get-Release
if (-not $release) { throw "$Repository has no release $Tag after $($run.url)" }
$published = Get-Asset $release
$sha256 = Get-Sha256 $published
if (-not $sha256) { throw "release $Tag states no SHA-256 for $Asset" }
$record = [ordered]@{
    repository        = $Repository
    workflow          = $Workflow
    inputs            = $Inputs
    workflow_run      = $run.url
    workflow_run_id   = $run.databaseId
    tag               = $release.tag_name
    release_id        = $release.id
    immutable         = Get-Field $release 'immutable'
    published_at      = Get-Field $release 'published_at'
    asset             = $published.name
    asset_id          = $published.id
    sha256            = $sha256
    previous_asset_id = if ($before) { $before.id } else { $null }
    previous_sha256   = if ($before) { Get-Sha256 $before } else { $null }
}
$record | ConvertTo-Json | Out-File -Encoding utf8 -LiteralPath $OutFile
Write-Host "$Workflow -> $Tag release $($release.id) asset $($published.id) sha256 $sha256"
