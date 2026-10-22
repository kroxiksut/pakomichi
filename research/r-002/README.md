<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# R-002 research harness

This directory implements the isolated DNF4/DNF5 signature matrix from
`docs/en/research/R-002-rpm-signatures.md`. It uses only synthetic RPMs and
keys whose user IDs contain `Pakomichi R-002 TEST ONLY`.

Private keys, packages, repository trees, and raw logs remain under the
ignored `.research-local/r-002/`. Only sanitized TSV evidence belongs in
`research/r-002/results/`.

## Build fixtures

The existing stopped AlmaLinux 9 RPM builder from R-001 supplies `rpmbuild`,
`rpmsign`, and `createrepo_c`. The PowerShell runner always stops it, including
after a failed build:

```powershell
powershell -NoProfile -File research/r-002/run-build.ps1
```

The builder creates signed and unsigned RPMs with the same payload digest, an
RPM with a corrupted embedded signature, separate attested and unconfirmed
unsigned bytes, valid and invalid `repomd.xml.asc` signatures, and a repository
whose RPM is modified after metadata generation. No fixture has scriptlets.

## Run clean targets

Each command imports a digest-pinned image from the R-001 cache, runs as root
inside that disposable WSL distribution, and unregisters it under the shared
R-001 WSL lifecycle mutex:

```powershell
powershell -NoProfile -File research/r-002/run-target.ps1 -Platform alma9
powershell -NoProfile -File research/r-002/run-target.ps1 -Platform fedora44
```

Repository metadata is served only on target loopback. Distribution sources
are used solely to install the test tooling; every matrix DNF command points
`reposdir` to the R-002 repository alone. The harness never writes global
`gpgcheck=0`. Its explicit attested cell uses a per-repository exception only
after exact-digest verification. The mandatory-policy cell separately proves
that the same unsigned bytes remain blocked: by `%_pkgverify_level=signature`
behind DNF4, and by DNF5's native `pkg_gpgcheck=1` setting.

## Validate sanitized evidence

```powershell
python -I research/r-002/validate-results.py research/r-002/results `
  --platform alma9 --platform fedora44
```
