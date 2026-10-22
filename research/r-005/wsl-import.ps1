# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Create or recreate an R-005 WSL distribution from an R-001 digest-pinned image.

The R-001 importer deliberately owns only the pakomichi-r001-* namespace. This
task-local copy keeps the destructive unregister operation constrained to
pakomichi-r005-* while reusing the same verified image lock and global mutex.
#>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Image,
    [string]$ImageDir,
    [string]$DiskRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $ImageDir) { $ImageDir = Join-Path $projectRoot '.vm-local\r-001\images' }
if (-not $DiskRoot) { $DiskRoot = Join-Path $projectRoot '.vm-local\wsl' }

if ($Name -notmatch '^pakomichi-r005-[a-z0-9-]+$') {
    throw "refusing to manage a distribution outside the pakomichi-r005-* namespace: $Name"
}

$layer = Join-Path $ImageDir "$Image.layer.tar.gz"
if (-not (Test-Path -LiteralPath $layer)) {
    throw "missing baseline layer $layer; prepare the digest-pinned R-001 images first"
}

$lockPath = Join-Path $projectRoot 'research\r-001\images.lock.json'
$lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
$imageLock = $lock.$Image
if (-not $imageLock) { throw "image '$Image' is absent from $lockPath" }

$expected = $imageLock.layer_digest
$actual = 'sha256:' + (Get-FileHash -Algorithm SHA256 -LiteralPath $layer).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "baseline $layer is $actual, lock expects $expected" }

# WSL import/unregister is unreliable when two research tasks invoke it at once.
$mutex = New-Object System.Threading.Mutex($false, 'Global\pakomichi-research-wsl-import')
[void]$mutex.WaitOne()
try {
    $existing = @(wsl.exe -l -q | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ })
    if ($existing -contains $Name) {
        wsl.exe --unregister $Name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "wsl --unregister $Name failed" }
    }

    $disk = Join-Path $DiskRoot $Name
    New-Item -ItemType Directory -Force -Path $disk | Out-Null
    wsl.exe --import $Name $disk $layer --version 2
    if ($LASTEXITCODE -ne 0) { throw "wsl --import $Name failed" }
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}

Write-Output "$Name imported from $Image ($actual)"
