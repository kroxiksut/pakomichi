# R-001 — APT/DNF: version, file instance, and publisher

**English** · [Русский](../../ru/research/R-001-source-selection.md)

The result of this protocol is required before implementing or promising `preferred` behavior for APT/DNF.

## Hypothesis

When versions differ, priority can be assigned specifically. With the *same version but different bytes*, APT does not guarantee selection of a specified instance through `apt_preferences`. DNF will require independent tests of `priority`, `includepkgs`, `excludepkgs`, the originating repo, and different build variants.

## Environments

APT on Debian 12 and 13, Ubuntu 24.04; DNF4 and DNF5 on corresponding isolated supported images. Record the apt, rpm, and dnf versions. No scenario may be run on the development machine.

## Fixtures

Build small **synthetic** DEB/RPM `sampleapp` packages for version `1.0-1` in two variants `A` and `B` with different SHAs; additional versions `0.9` and `1.1`; `sampleapp-helper (=1.1)`; a dummy `Provides`, and a safe test of "a dependency requires an unavailable library". Two repositories signed with dedicated laboratory keys, with separate pin/repo IDs.

## Protocol

1. Without Pakomichi, run ordinary `apt-cache policy sampleapp`, `apt-get -s install sampleapp`, an actual download-only, and reconcile the SHA with two sources, changing the order and the pin.
2. Check an explicit apt source preference with different versions and what changes with an equal version; confirm the documentation, and do not claim anything the experiment did not show.
3. For DNF4/DNF5: `repolist`, candidate info, package download, cache hash with priorities 10/90, with filters, and with --disableexcludes; do not install on the host at first.
4. Repeat for an installed version and `upgrade`, for removal of the first repository, and for the subsequent appearance of a system version.
5. Check dependencies between two packages of a package family, removal of the base package, and an upgrade of a system dependency; make sure that Pakomichi policy does not allow an implicit change of publisher (or formally state the limit).
6. Record which native config primitives support exactly the specified behavior; attach the files and artifact hashes.

## Acceptance criteria / decision

PASS if the selection mechanisms for supported conflicts are known, and for equal versions the safe `observing/hold` is deterministic and confirmed by tests. We do not require guaranteeing an inexpressible binding to a different instance.

**Fallback:** for a conflict that the native manager cannot resolve safely, do not publish the conflicting package in the active repo. Continue serving the other package families.

Sources: `docs/en/references.md`.
