# Product: purpose and boundaries of responsibility

**English** · [Русский](../../ru/product/vision.md)

## Problem

An author attaches valid `.deb`/`.rpm` files to Git Releases, but the user has to download every new file manually or add a separate APT/RPM repository that the author does not have. Creating a full signed repository requires maintaining indexes, signatures, keys, and publication.

## Solution

Pakomichi serves as a **bridge between the selected Git Release and the native mechanisms of package managers**, without replacing APT/DNF, without its own system dependency resolver, and without requiring the owner of every project to maintain a separate repository.

## Who benefits

1. User: adds a concrete Git URL and gets native installations and updates when verification succeeds.
2. Author: publishes to Releases as before; optionally adds a CI description of compatibility/package families.
3. Administrator: pins sources, checks conflicts, and maintains controlled updates.

## It is not

- A new package manager or a remote catalog of "all GitHub packages".
- An automatic finder of forks, mirrors, author repositories, or system dependencies on GitHub.
- A service that rates developer reputation or program maliciousness.
- A tool for partial distribution migration or for updating system libraries from arbitrary sources.
- A universal installer of archives and executable files.

## Usefulness verification metrics (not invented successes)

- 3 different external projects with release DEB/RPM files: at least 1 without its own APT/RPM repository.
- Installation and subsequent update with native commands on a supported Debian-like/Fedora-like system.
- 0 unauthorized publisher/package changes in negative tests.
- Measure: user setup time, the amount of change to the author's CI, the number of API requests, the percentage of compatible real releases, the cache size.
