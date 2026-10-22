# SPDX-License-Identifier: MIT OR Apache-2.0
param(
    [Parameter(Mandatory = $true)][ValidateSet('alma9', 'fedora44')][string]$Platform
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$name = "pakomichi-r002-$Platform"
$runDir = Join-Path $projectRoot ".research-local\r-002\runs\$Platform"
if (Test-Path -LiteralPath $runDir) {
    Get-ChildItem -Force -LiteralPath $runDir | Remove-Item -Recurse -Force
}

& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'wsl-import.ps1') -Name $name -Image $Platform
if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }

$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
$env:WSL_UTF8 = '1'
try {
    wsl.exe -d $name -u root --cd /tmp -- env "R002_ROOT=$linuxRoot/.research-local/r-002" "R002_RESULTS=$linuxRoot/research/r-002/results" bash "$linuxRoot/research/r-002/target-scenarios.sh" $Platform
    if ($LASTEXITCODE -ne 0) { throw "R-002 matrix failed on $Platform" }
}
finally {
    $mutex = New-Object System.Threading.Mutex($false, 'Global\pakomichi-r001-wsl-import')
    [void]$mutex.WaitOne()
    try {
        wsl.exe --unregister $name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "failed to unregister $name" }
    }
    finally {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
