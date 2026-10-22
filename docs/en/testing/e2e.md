# End-to-end E2E scenarios

**English** · [Русский](../../ru/testing/e2e.md)

Run only on distribution builds being admitted under ADR-026, with Pakomichi's own package; for AlmaLinux and Fedora on a VM with SELinux enforcing.

## E2E-01 GitHub → APT

A Debian VM, a public test GitHub Release with 1.0 and 1.1 `.deb` files, and signed provenance. Pin the repo ID, `source add`, inspection, activate the family, run `apt update && apt install sampleapp`, a new Release → `apt update` and the distribution's ordinary update command (`apt upgrade` on Debian and Ubuntu, `apt-get dist-upgrade` on Astra Linux, ADR-022); verify the native version, the SHA, and the absence of changes to third-party sources.

## E2E-02 GitHub → DNF

The same on DNF4/DNF5 with `dnf upgrade`, with a signed RPM and a repodata signature. For an unsigned RPM, a separate positive case only after R-003 and the production verifier: explicit consent, a permitting effective `%_pkgverify_level`, and a separate logical repository (ADR-023); a mandatory signature blocks it.

## E2E-03 Multiple packages

Release `sampleapp`, `sampleapp-cli`, `sampleapp-service`. Native dependencies main→service; the 1.0→1.1 upgrade is consistent; a new `sampleapp-driver` is not added automatically. Every family member keeps its publisher when another source offers a higher version (ADR-022).

## E2E-04 Installed program from another source

The system already has `sampleapp 1.0`; Git offers 1.1. First observing, then a user-approved migration in an admissible configuration. With an equal version and different SHAs, no automatic transition takes place. After activation, a higher version from the distribution or another source does not change the publisher under the ordinary update command, and `pchi status` shows the notice.

## E2E-05 NetWatch (read-only external reference)

Examine `matthart1983/netwatch`: `netwatch` `.deb/.rpm`, APT on GitHub Pages, COPR native dynamic vs GitHub static RPM, Rust name `netwatch-tui`. Do not treat all build variants as identical. Do not modify a third-party repository and do not attempt to install a conflicting build on the development machine.

## E2E-06 Uninstall / offline

In a VM, install through our layer, cut the network, check the cache and freshness expiry (APT: `Valid-Until`; DNF: the signed empty generation, ADR-024); stop the service and check that DNF names the Pakomichi repository and `pchi doctor` reports the recovery (ADR-021); remove Pakomichi, make sure the program remains installed, no Pakomichi repository file remains, and other system sources are preserved.

## E2E-07 Pinned source (ADR-027)

A test repository without attestations. `source allow-pinned` shows the risk and records consent; a new release is held with `E_RELEASE_APPROVAL_REQUIRED` until `release approve`; after approval it is served from the Pinned logical repository, which `apt policy`/`dnf repolist` show by its label; an asset changed after approval is `E_ASSET_MUTATED`; `--policy preferred` is refused.

In all cases, **actual commands, file hashes, and the package database state before/after** are mandatory evidence.
