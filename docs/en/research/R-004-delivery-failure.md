# R-004 — Socket activation, atomic snapshots, and failures

**English** · [Русский](../../ru/research/R-004-delivery-failure.md)

The result of this protocol is required before approving content-addressed storage (CAS), HTTP snapshots, and offline/freshness behavior.

## Hypothesis

A single loopback HTTP service activated by a systemd socket can reliably serve separate signed logical APT/RPM repositories under parallel access by native managers. Immutable generations and CAS prevent mixing metadata of different versions.

## Research

1. In a container/VM with systemd (socket tests require a real init environment), prepare an `Accept=no` handler; check cold/parallel GET, restart, timeout, and startup after a process crash.
2. Create two generations of indexes, simulate switching during `apt update` and package download; compare the digest of the received index/package. Repeat for DNF4/DNF5.
3. Check APT `Acquire-By-Hash` and `Valid-Until`, signed `InRelease`; ensure that a `304` from GitHub is treated as confirmation only with a correct conditional check.
4. Simulate a network break in the middle of a download, download timeout, wrong SHA, disk exhaustion, process termination during staging/rename/fsync, corrupted SQLite, loss of the signing key.
5. Record idle RAM, startup time, request performance, and cache size — real measurements, without arbitrary promises.
6. Check that **third-party** APT/DNF repositories are not affected, and that the installed application does not disappear after the bridge service is stopped/removed.
7. Check HTTP protection against an invalid path, symlink, SSRF/private IP redirect, and the prohibition of POST/administrative commands.

## Acceptance criteria

PASS: every published snapshot is fully self-consistent; previously published bytes remain correct; on a source error there is no substitution or serving of a partial file; recovery is described reproducibly.

**Fallback:** an ordinary systemd service with the same HTTP protocol and file storage, if socket activation does not meet the requirements of a specific OS. For offline operation without an available package, an honest error, not an artificial substitution.
