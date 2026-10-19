# SPDX-License-Identifier: MIT OR Apache-2.0

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
$patterns = @(
    @{ Label = "AWS access key"; Regex = [regex]'AKIA[0-9A-Z]{16}' },
    @{ Label = "GitHub token"; Regex = [regex]'gh[pousr]_[A-Za-z0-9]{30,}' },
    @{ Label = "GitHub fine-grained token"; Regex = [regex]'github_pat_[A-Za-z0-9_]{30,}' },
    @{ Label = "Google API key"; Regex = [regex]'AIza[0-9A-Za-z_-]{35}' },
    @{ Label = "Slack token"; Regex = [regex]'xox[baprs]-[A-Za-z0-9-]{20,}' },
    @{
        Label = "private key"
        Regex = [regex]('-----BEGIN ' + '(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----')
    },
    @{
        Label = "OpenPGP private key"
        Regex = [regex]('-----BEGIN ' + 'PGP PRIVATE KEY BLOCK-----')
    }
)
$forbiddenExtensions = @(".key", ".kbx", ".p12", ".pem", ".pfx")
# GnuPG home artifacts that hold or index secret key material.
$forbiddenLeafNames = @(".env", "secring.gpg", "trustdb.gpg")
$forbiddenDirectories = @("private-keys-v1.d", "openpgp-revocs.d")
$violations = [System.Collections.Generic.List[string]]::new()

Push-Location $projectRoot

try {
    $repositoryFiles = @(git ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw "git ls-files failed" }

    foreach ($relativePath in $repositoryFiles) {
        $extension = [System.IO.Path]::GetExtension($relativePath).ToLowerInvariant()
        $leafName = [System.IO.Path]::GetFileName($relativePath)

        $segments = $relativePath -split '/'
        $inForbiddenDirectory = @($segments | Where-Object { $forbiddenDirectories -contains $_ }).Count -gt 0
        if ($forbiddenExtensions -contains $extension -or $forbiddenLeafNames -contains $leafName -or $inForbiddenDirectory) {
            $violations.Add("$relativePath (forbidden credential file type)")
            continue
        }

        $absolutePath = Join-Path $projectRoot $relativePath
        $content = Get-Content -Raw -LiteralPath $absolutePath -ErrorAction SilentlyContinue
        if ($null -eq $content) { continue }

        foreach ($pattern in $patterns) {
            if ($pattern.Regex.IsMatch($content)) {
                $violations.Add("$relativePath ($($pattern.Label))")
            }
        }
    }
}
finally {
    Pop-Location
}

if ($violations.Count -gt 0) {
    # Report every violation before failing, instead of stopping at the first one.
    $violations | Sort-Object -Unique | ForEach-Object { [Console]::Error.WriteLine("secret signature: $_") }
    exit 1
}

Write-Output "secret signatures ok"
exit 0
