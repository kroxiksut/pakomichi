# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Create, or recreate from the clean baseline, one R-004 WSL distribution.

Uses the digest-verified R-001 image layers (research/r-001/fetch-images.py)
and refuses names outside the pakomichi-r004-* namespace. Recreating a
distribution is the restore step between test blocks.
#>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Image
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$imageDir = Join-Path $projectRoot '.vm-local\r-001\images'
$diskRoot = Join-Path $projectRoot '.vm-local\wsl'

if ($Name -notmatch '^pakomichi-r004-[a-z0-9-]+$') {
    throw "refusing to manage a distribution outside the pakomichi-r004-* namespace: $Name"
}

$layer = Join-Path $imageDir "$Image.layer.tar.gz"
if (-not (Test-Path -LiteralPath $layer)) { throw "missing baseline layer $layer; run research/r-001/fetch-images.py first" }

$lock = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'research\r-001\images.lock.json') | ConvertFrom-Json
$expected = $lock.$Image.layer_digest
$actual = 'sha256:' + (Get-FileHash -Algorithm SHA256 -LiteralPath $layer).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "baseline $layer is $actual, lock expects $expected" }

# Same mutex as R-001: concurrent `wsl --import`/`--unregister` calls fail.
$mutex = New-Object System.Threading.Mutex($false, 'Global\pakomichi-r001-wsl-import')
[void]$mutex.WaitOne()
try {
    $existing = @(wsl.exe -l -q | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ })
    if ($existing -contains $Name) {
        wsl.exe --unregister $Name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "wsl --unregister $Name failed" }
    }
    $disk = Join-Path $diskRoot $Name
    New-Item -ItemType Directory -Force -Path $disk | Out-Null
    wsl.exe --import $Name $disk $layer --version 2
    if ($LASTEXITCODE -ne 0) { throw "wsl --import $Name failed" }
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}

Write-Output "$Name imported from $Image ($actual)"
