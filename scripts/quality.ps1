# SPDX-License-Identifier: MIT OR Apache-2.0

# Runs under PowerShell 7 (CI) and Windows PowerShell 5.1 (local Windows host).

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot

# Native tools report progress on stderr. Windows PowerShell 5.1 turns that
# into terminating errors under "Stop", so a step fails only by exit code.
function Invoke-Step {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Command
    )

    Write-Output "==> $Name"
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Command
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }

    if ($exitCode -ne 0) { throw "$Name failed with exit code $exitCode" }
}

# $IsWindows exists only in PowerShell 6+; Windows PowerShell 5.1 runs only on Windows.
$onWindows = if (Test-Path Variable:IsWindows) { $IsWindows } else { $true }
$pythonName = if ($onWindows) { "python" } else { "python3" }
$python = Get-Command $pythonName -ErrorAction Stop

# Keep Python bytecode caches out of the checkout; restored afterwards.
$previousBytecode = $env:PYTHONDONTWRITEBYTECODE
$env:PYTHONDONTWRITEBYTECODE = "1"

try {
    Invoke-Step "secret signatures" { & "$PSScriptRoot/secret-check.ps1" }
    Invoke-Step "cargo fmt" { cargo fmt --check }
    Invoke-Step "cargo clippy" { cargo clippy --workspace --all-targets --all-features --locked -- -D warnings }
    Invoke-Step "cargo test" { cargo test --workspace --all-targets --all-features --locked }
    Invoke-Step "schema migration tests" {
        & $python.Source -m unittest discover -s tests -p "test_*.py" -v
    }
    Invoke-Step "cargo deny" { cargo deny check }
}
finally {
    $env:PYTHONDONTWRITEBYTECODE = $previousBytecode
    Pop-Location
}
