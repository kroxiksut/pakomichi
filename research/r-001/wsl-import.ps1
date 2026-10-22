# SPDX-License-Identifier: MIT OR Apache-2.0
<#
Create, or recreate from the clean baseline, one R-001 WSL distribution.

The baseline is the digest-verified root filesystem layer from
fetch-images.py. Recreating a distribution from that layer is the restore
step between test blocks, so every block starts from the same bytes.
#>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Image,
    [string]$ImageDir,
    [string]$DiskRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Windows PowerShell 5.1 leaves $PSScriptRoot empty inside parameter defaults.
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $ImageDir) { $ImageDir = Join-Path $projectRoot '.vm-local\r-001\images' }
if (-not $DiskRoot) { $DiskRoot = Join-Path $projectRoot '.vm-local\wsl' }

if ($Name -notmatch '^pakomichi-r001-[a-z0-9-]+$') {
    throw "refusing to manage a distribution outside the pakomichi-r001-* namespace: $Name"
}

$layer = Join-Path $ImageDir "$Image.layer.tar.gz"
if (-not (Test-Path -LiteralPath $layer)) { throw "missing baseline layer $layer; run fetch-images.py first" }

$lock = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'images.lock.json') | ConvertFrom-Json
$expected = $lock.$Image.layer_digest
$actual = 'sha256:' + (Get-FileHash -Algorithm SHA256 -LiteralPath $layer).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "baseline $layer is $actual, lock expects $expected" }

# Concurrent `wsl --import`/`--unregister` calls fail, so serialize them.
$mutex = New-Object System.Threading.Mutex($false, 'Global\pakomichi-r001-wsl-import')
[void]$mutex.WaitOne()
try {
    # `wsl -l -q` prints UTF-16; strip the NUL bytes before comparing names.
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
