# End-to-end E2E scenarios

**English** · [Русский](../../ru/testing/e2e.md)

## E2E-01 GitHub → APT

A Debian VM, a public test GitHub Release with 1.0 and 1.1 `.deb` files, and signed provenance. Pin the repo ID, `source add`, inspection, activate the family, run `apt update && apt install sampleapp`, a new Release → `apt update && apt upgrade`; verify the native version, the SHA, and the absence of changes to third-party sources.

## E2E-02 GitHub → DNF

The same on DNF4/DNF5, with a signed RPM and a repodata signature. For an unsigned RPM, a separate positive case only with explicit consent and a permitting policy; a mandatory signature blocks it.

## E2E-03 Multiple packages

Release `sampleapp`, `sampleapp-cli`, `sampleapp-service`. Native dependencies main→service; the 1.0→1.1 upgrade is consistent; a new `sampleapp-driver` is not added automatically.

## E2E-04 Installed program from another source

The system already has `sampleapp 1.0`; Git offers 1.1. First observing, then a user-approved migration in an admissible configuration. With an equal version and different SHAs, no automatic transition takes place.

## E2E-05 NetWatch (read-only external reference)

Examine `matthart1983/netwatch`: `netwatch` `.deb/.rpm`, APT on GitHub Pages, COPR native dynamic vs GitHub static RPM, Rust name `netwatch-tui`. Do not treat all build variants as identical. Do not modify a third-party repository and do not attempt to install a conflicting build on the development machine.

## E2E-06 Uninstall / offline

In a VM, install through our layer, cut the network, check the cache and freshness expiry; remove Pakomichi, make sure the program remains installed and other system sources are preserved.

In all cases, **actual commands, file hashes, and the package database state before/after** are mandatory evidence.
