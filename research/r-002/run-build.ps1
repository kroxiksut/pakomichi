# SPDX-License-Identifier: MIT OR Apache-2.0
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$name = 'pakomichi-r001-build-rpm'
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
$env:WSL_UTF8 = '1'

try {
    wsl.exe -d $name -u root --cd /tmp -- bash "$linuxRoot/research/r-002/make-keys.sh"
    if ($LASTEXITCODE -ne 0) { throw 'R-002 key generation failed' }
    wsl.exe -d $name -u root --cd /tmp -- bash "$linuxRoot/research/r-002/build-fixtures.sh"
    if ($LASTEXITCODE -ne 0) { throw 'R-002 fixture build failed' }
    wsl.exe -d $name -u root --cd /tmp -- bash "$linuxRoot/research/r-002/key-recovery.sh"
    if ($LASTEXITCODE -ne 0) { throw 'R-002 key recovery experiment failed' }
}
finally {
    wsl.exe --terminate $name
    if ($LASTEXITCODE -ne 0) { throw 'failed to stop the RPM builder' }
}
