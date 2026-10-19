# Delivery, snapshots, availability, and recovery

**English** · [Русский](../../ru/architecture/delivery-recovery.md)

## Main path

A loopback service with systemd socket activation (where supported). One process serves the *logical* APT/RPM repositories of each Git source. A separate administrative IPC. Do not consider local HTTP protected without cryptographically signed indexes.

## Immutable generations

1. Create a staging snapshot from verified `eligible` artifacts.
2. Write all packages/hashes/indexes; generate APT `Packages`, `Release`, `InRelease` and RPM `repodata` from the same files.
3. Sign the metadata *after* the complete build.
4. Run a self-check: paths, digests, dates, references, and signatures.
5. `fsync` the contents/directories, then atomically switch the active generation on the same FS.
6. Keep old generations while requests and references are possible; garbage collection is by reachability, not by the age of a single file.

For APT, enable `Acquire-By-Hash`; for RPM, keep `repomd.xml` and the associated metadata versions at unique URLs. Package file paths are immutable and content-addressed.

## Lazy fetch

If a package is not yet in CAS: obtain the **pinned asset** through the API/verified route, with limits on size, protocol, and DNS/redirects; recheck the address on every hop and exclude localhost/private/metadata endpoints; write to a temporary file; verify the hash and attestation against the accepted evidence; only then serve the bytes. If full buffering is impossible, do not stream unverified data as a finished trusted file.

## Freshness (initial proposed settings)

Regular check: every 6 h; manual `sync --force`; staleness warning after 24 h; maximum freshness of 7 days after the last successful confirmed synchronization. A `304`/conditional response may confirm the absence of changes if it is verified according to the API/policy. **No validity extension on a network error.** `Valid-Until` must match the actually confirmed freshness. The settings are configurable; the values are to be verified by R-004.

## Service failure

We do not touch third-party system sources or installed applications. APT/DNF may receive an error from our source; do not hide the failure. If GitHub is unavailable, already stored packages may be available while the snapshot is valid. If the key/DB/index is corrupted, fail closed for our source.

## Coordinating the DB and OS files

SQLite transaction + recording the intent in `AdminOperation` + staging of configuration files + atomic renames + verification + commit outcome. After a failure, compare the actual hashes and apply a safe rollback/finish. SQLite and `/etc/apt` are **not** a shared atomic transaction.

## Removal

We remove only Pakomichi-owned system config files and local keys/cache according to the removal mode; applications and third-party files remain. On a source purge, we leave no dangling repository files.
