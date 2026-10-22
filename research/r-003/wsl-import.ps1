# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Create, recreate, or remove the R-003 WSL distribution.

Uses the digest-verified R-001 image layers (research/r-001/fetch-images.py,
research/r-001/images.lock.json) and refuses names outside the
pakomichi-r003-* namespace, so it can never touch the owner's personal
distribution or another project's distributions.
#>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Image = 'fedora44',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$imageDir = Join-Path $projectRoot '.vm-local\r-001\images'
$diskRoot = Join-Path $projectRoot '.vm-local\wsl'

if ($Name -notmatch '^pakomichi-r003-[a-z0-9-]+$') {
    throw "refusing to manage a distribution outside the pakomichi-r003-* namespace: $Name"
}

function Get-WslNames {
    @(wsl.exe -l -q | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ })
}

# Concurrent `wsl --import`/`--unregister` calls from research tasks fail.
$mutex = New-Object System.Threading.Mutex($false, 'Global\pakomichi-research-wsl-import')
[void]$mutex.WaitOne()
try {
    $disk = Join-Path $diskRoot $Name
    if ($Remove) {
        if ((Get-WslNames) -contains $Name) {
            wsl.exe --unregister $Name | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "wsl --unregister $Name failed" }
        }
        if (Test-Path -LiteralPath $disk) { Remove-Item -LiteralPath $disk -Recurse -Force }
        Write-Output "$Name removed"
        return
    }

    $layer = Join-Path $imageDir "$Image.layer.tar.gz"
    if (-not (Test-Path -LiteralPath $layer)) {
        throw "missing baseline layer $layer; run research/r-001/fetch-images.py first"
    }
    $lock = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'research\r-001\images.lock.json') | ConvertFrom-Json
    $imageLock = $lock.$Image
    if (-not $imageLock) { throw "image '$Image' is absent from images.lock.json" }
    $expected = $imageLock.layer_digest
    $actual = 'sha256:' + (Get-FileHash -Algorithm SHA256 -LiteralPath $layer).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "baseline $layer is $actual, lock expects $expected" }

    if ((Get-WslNames) -contains $Name) {
        wsl.exe --unregister $Name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "wsl --unregister $Name failed" }
    }
    New-Item -ItemType Directory -Force -Path $disk | Out-Null
    wsl.exe --import $Name $disk $layer --version 2
    if ($LASTEXITCODE -ne 0) { throw "wsl --import $Name failed" }
    Write-Output "$Name imported from $Image ($actual, manifest $($imageLock.manifest_digest))"
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
