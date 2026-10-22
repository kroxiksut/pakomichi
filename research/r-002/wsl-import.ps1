# SPDX-License-Identifier: MIT OR Apache-2.0
<# Import a clean digest-pinned R-002 WSL target from the R-001 image cache. #>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][ValidateSet('alma9', 'fedora44')][string]$Image,
    [string]$ImageDir,
    [string]$DiskRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $ImageDir) { $ImageDir = Join-Path $projectRoot '.vm-local\r-001\images' }
if (-not $DiskRoot) { $DiskRoot = Join-Path $projectRoot '.vm-local\wsl' }
if ($Name -notmatch '^pakomichi-r002-[a-z0-9-]+$') {
    throw "refusing to manage a distribution outside pakomichi-r002-*: $Name"
}

$layer = Join-Path $ImageDir "$Image.layer.tar.gz"
$lockPath = Join-Path $projectRoot 'research\r-001\images.lock.json'
if (-not (Test-Path -LiteralPath $layer)) { throw "missing baseline layer: $layer" }
$lock = Get-Content -Raw -LiteralPath $lockPath | ConvertFrom-Json
$expected = $lock.$Image.layer_digest
$actual = 'sha256:' + (Get-FileHash -Algorithm SHA256 -LiteralPath $layer).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "baseline digest mismatch: got $actual, expected $expected" }

$mutex = New-Object System.Threading.Mutex($false, 'Global\pakomichi-r001-wsl-import')
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
