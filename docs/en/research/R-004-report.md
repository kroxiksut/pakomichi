# R-004 report — Socket activation, atomic snapshots, and failures

**English** · [Русский](../../ru/research/R-004-report.md)

- **Date / performed by:** 2026-10-20, programming agent at the project owner's request; protocol: [R-004](R-004-delivery-failure.md).
- **Outcome:** **PASS** for Debian 12 (APT 2.6), AlmaLinux 9 (DNF 4.14), and Fedora 44 (DNF5 5.4) in WSL2 with systemd as PID 1, plus three hard power-offs of an Astra Linux 1.8.6 VM, with the design changes listed under "Conclusions". SELinux/AppArmor enforcement, a TLS upstream, and the other supported distributions are not covered (see "Not covered").
- **Main facts:** with immutable generations, content-addressed index and package paths, and retained old generations, no native client accepted mixed metadata, including about 2,700 parallel updates across the three targets during repeated generation switches. Every source error ended with an error status and never with a partial or substituted file. DNF needs two extra safeguards that APT does not: the detached `repomd.xml.asc` can mismatch `repomd.xml` during a switch, and DNF accepts older signed metadata served again (APT does not).

## Environment

| Target | systemd | Package manager | Other |
|---|---|---|---|
| Debian 12 | 252.39-1~deb12u2 | APT 2.6.1, dpkg 1.21.23 | glibc 2.36, GnuPG 2.2.40 |
| AlmaLinux 9.8 | 252-67.el9_8.6 | DNF 4.14.0, RPM 4.16.1.3, createrepo_c 0.20.1 | glibc 2.34, GnuPG 2.3.3, SQLite 3.34.1 |
| Fedora 44 | 259.9-1.fc44 | DNF5 5.4.3.0, RPM 6.0.2, createrepo_c 1.2.1 | glibc 2.43, GnuPG 2.4.9, SQLite 3.51.2 |

Each target is a separate WSL2 distribution (kernel 6.18.40.1-microsoft-standard-WSL2) created from the digest-pinned R-001 image layer, with systemd installed and enabled as PID 1; the same distribution runs the server and the native client. The distribution is recreated from the image for each full run. Third-party repositories are the distribution defaults (`deb.debian.org`, AlmaLinux and Fedora mirrors). WSL2 distributions share one network namespace, so the harness stops the other R-004 targets before a run. Raw logs: `.research-local/r-004/runs/<target>/`; result tables: `research/r-004/results/<target>.tsv`.

## Research server and harness

`research/r-004/snapshotd` is a research server in Rust 1.94.1 that uses only crates from the ADR-017 stack (Tokio, `listenfd`, `rusqlite` with the system SQLite, `sha2`, `libc`), built offline from the P0-004 cache on AlmaLinux 9 so that one binary runs on every target. It is research tooling, not production code. It implements the ADR-008 model:

- a content-addressed store `objects/<sha256>`; objects are written to a staging file, checked for size and SHA-256, `fsync`ed, made read-only, renamed, and the directory is `fsync`ed;
- immutable generations: one manifest per generation (path, digest, size, optional upstream URL) and an atomically replaced `current` pointer per logical repository; one process serves several logical repositories at `/<repo>/<path>`;
- a publisher that verifies the `InRelease` or `repomd.xml.asc` signature with `gpgv`, every reference from `Release`, `Packages`, `repomd.xml`, and `primary.xml` to the published bytes, and `Date`/`Valid-Until`, before it switches `current`;
- mutable paths (`InRelease`, `repomd.xml`, plain `Packages`) only from the current generation; content-addressed paths (`by-hash`, unique `repodata` names, `pool/<sha256>/`, `packages/<sha256>/`) from any retained generation;
- a read-only HTTP/1.1 reader with GET and HEAD only, a `Host` allowlist, a header and target size limit, refusal of request bodies, percent-decoding with refusal of `..`, `/`, `\`, and NUL in segments, `O_NOFOLLOW` opens, and SHA-256 verification of every object before sending (switchable for measurement);
- lazy fetch of a pinned object from an upstream URL: one download per digest, address policy checked on every redirect hop with the connection made to the vetted address, idle and total timeouts, size and digest checked before the object enters the store;
- SQLite state (`quick_check` before every publish) and a `reconcile` command that rebuilds the state from manifests and objects.

The upstream is `research/r-004/upstream.py`, a local fault-injecting HTTP server that stands in for the GitHub asset host. `research/r-004/run.ps1 -Target debian12|alma9|fedora44` recreates the target, runs `setup-target.sh` and `prepare.sh` (TEST ONLY Ed25519 key, fixture packages built on the target), and runs `scenarios.sh` by area (`socket gen cas http db measure third`). The research server combines the repository reader and the lazy downloader in one process; ADR-017 places them in separate roles, which does not change the tested file and HTTP protocol.

## Results

Final runs with one binary (SHA-256 `57590afb…`) and one harness revision: Debian 12 — 53 PASS, 10 OBSERVED; AlmaLinux 9 — 50 PASS, 12 OBSERVED; Fedora 44 — 50 PASS, 12 OBSERVED; no FAIL. "OBSERVED" marks controls and behaviour that is recorded rather than passed or failed. Earlier runs failed only because of harness defects, which were fixed: compressed APT lists in the Debian container image, a test that damaged an object the current generation did not serve, a port taken by another WSL2 distribution, and too short waits.

### Socket activation (step 1)

| ID | Case | Result on all three targets |
|---|---|---|
| S1 | GET with the service stopped and only the socket listening | 200; first response within about 0.1 s |
| S2 | 64 parallel GETs on a stopped service | 64 × 200, exactly one service start |
| S3 | `systemctl restart` twice during 20,000 GETs | 10–13 requests failed (connections that the old process had accepted); OBSERVED |
| S4 | Idle exit after 3 s, then GET | the service exits, the next GET starts a new process |
| S5 | `SIGKILL` while idle | the service is `failed`, the socket stays `active`, the next GET gets 200 |
| S6 | `SIGKILL` with a request in flight | that client gets an empty reply (curl 52), the next GET gets 200 |
| S7 | 10 crash-and-request cycles | after 5 starts systemd reports `Start request repeated too quickly`; the **socket** becomes `failed` (`service-start-limit-hit`) and stops listening; `systemctl reset-failed` and starting the socket restore it; OBSERVED |
| S8 | One slow client holding a partial header | others are served at once; the slow connection is closed after 10 s |
| S8b | 70 slow clients against the 64-connection limit | another GET waits about 10 s; OBSERVED |
| S9 | Fallback: ordinary service with its own loopback bind | 200; a `0.0.0.0` bind is refused at start |
| S10 | Socket-activated listener on `0.0.0.0` | the reader refuses to start |

### Generations and native clients (steps 2 and 3)

| ID | Case | APT (Debian 12) | DNF4 / DNF5 |
|---|---|---|---|
| G1 | Publish, update, install | PASS | PASS |
| G2 | Switch to a new generation after the client fetched `InRelease`/`repomd.xml` and before it fetched the referenced indexes | PASS: the client holds the complete old generation | PASS |
| G3 | Control: the client fetches a mutable index path (APT `Acquire::By-Hash=no`; RPM `--simple-md-filenames`) | `Hash Sum mismatch`, update fails | `checksum doesn't match`, update fails |
| G3p | G3 with the generation pinned per TCP connection | the update succeeds (APT used one connection) | still fails (librepo used 3–4 connections) |
| G4 | Control: by-hash/unique names, old generation not retained | the by-hash request gets 404, **APT falls back to the mutable `Packages.gz`** and fails with `File has unexpected size` | 404, update fails |
| G5 | Package of a superseded generation requested from old lists after the switch | PASS: downloaded from the retained generation; a later update and upgrade reach the new version | PASS: the old package path still serves the old bytes. DNF4 sometimes reread `repomd.xml` before installing despite `metadata_expire=-1` and then installed the new version consistently |
| G6 | 8 parallel isolated clients per round while generations are switched in a loop | PASS: 584 updates, 16 switches, all consistent | PASS for consistency: AlmaLinux 9 160 updates, 34 switches, no failure; Fedora 44 640 updates, 9 switches, 1 failed with `Bad PGP signature` |
| G6p | G6 with per-connection pinning | PASS | PASS for consistency; Fedora 44: 2 of 640 failed with `Bad PGP signature`, so pinning does not help |
| G7 | `Valid-Until` passing while served | PASS: `Release file … is expired`, update exit 100 | not applicable: no signed expiry in `repomd.xml` |
| G7b | Publisher with an expired `InRelease` or a `Date` in the future | refused | — |
| G8 | An older signed generation served again after a newer one | the client keeps the newer metadata, exit 0, no message; OBSERVED | **the client accepts the older metadata and offers the older version**; OBSERVED |
| G9 | Signing key lost; metadata signed by another key | signing fails (exit 3); `gpgv` refuses the foreign signature; `current` unchanged; clients keep updating from the previous generation | same |

Every Fedora G6/G6p failure had `repomd.xml` from one generation and `repomd.xml.asc` from the next: both paths are mutable, and the client fetched them in separate requests. No client that reported success held inconsistent metadata.

### Downloads, storage, and crashes (step 4)

| ID | Case | Result on all three targets |
|---|---|---|
| C1 | 8 parallel first requests for a lazy 20 MiB object | 8 correct bodies, one upstream download |
| C1b | Native installation of the lazily fetched package | PASS |
| C2 | Upstream closes after half the bytes | 502, no object, no staging file; the native client reports a download error |
| C3 | Upstream stalls (idle timeout 3 s) | 504 after 3 s, nothing stored |
| C4 | Upstream sends other bytes of the same length | 502, nothing stored |
| C5 | Upstream `Content-Length` differs from the pinned size | 502 before the body is read |
| C6 | 20 MiB object into a 12 MiB store | 507 (`No space left on device`); used space unchanged; stored objects still served |
| C6b | Publish on a full store | publish fails, `current` unchanged, no staging file, `check` clean |
| C7 | `SIGKILL` of the reader after writing, after `fsync`, and after renaming a fetched object | the client gets an empty reply; the next start removes the staging file; the next GET returns the correct digest; `check` clean |
| C8 | `SIGKILL` of the publisher after writing an object, after all objects, before and after switching `current` | clients always update consistently from the old or the new generation; `reconcile` removes the staging files; the same generation ID cannot be reused once its manifest exists |
| C9 | One bit flipped in a stored object | with verification on send: 500, the client fails; without it the corrupted bytes are sent, and APT (`Hash Sum mismatch`) and DNF (`checksum doesn't match`) refuse them; `reconcile` quarantines the object and a republish restores it |
| C10 | Stored object replaced by a symlink to `/etc/passwd` | 500, nothing leaked |
| C11 | Lazy URLs and redirects to `127.0.0.1:22`, `10.0.0.1`, `169.254.169.254`, `[::1]`, `localhost:22`, `https://`, URL credentials, a redirect loop | all refused with 502 by the address or URL policy; a relative redirect to the allowed upstream succeeds |

### Power loss (step 4)

`research/r-004/powerloss.ps1` ran on an existing Astra Linux 1.8.6 VM (kernel 6.12.77, systemd 252, ext4 with `relatime`) inside a dedicated VirtualBox snapshot, with the project owner's approval. Afterwards the VM was powered off, restored to the snapshot, and the snapshot was deleted. Inside the VM, `research/r-004/powerloss.sh load` published generations of four random files (256 KiB–2 MiB) in a loop with r004-snapshotd. After each successful publish it appended the generation ID to an acknowledgement file and `fsync`ed it. After 21–28 s the host cut the power with `VBoxManage controlvm poweroff`; the VM then booted and `powerloss.sh verify` ran. Three cycles:

| Cycle | Acknowledged generations | `current` | Damaged objects or manifests | Missing acknowledged generations | State database | `check` after `reconcile` |
|---|---|---|---|---|---|---|
| 1 | 82 | the last acknowledged | 0 | 0 | readable | clean |
| 2 | 124 | the last acknowledged | 0 | 0 | readable | clean |
| 3 | 169 | the last acknowledged | 0 | 0 | readable | clean |

The power cut lost unflushed data. The publisher's stderr log, appended without `fsync`, contained NUL bytes in its tail after cycles 2 and 3, while every `fsync`ed file was intact. This is a guest power loss: VirtualBox may not pass guest flushes to the host disk, so a failure of the host itself was not simulated.

### HTTP protection (step 7)

H1 (all targets): 24 crafted requests behaved as expected, and no response body contained file content: `..` in plain and percent-encoded form, encoded `/` and `\`, NUL, absolute-form targets, `//`, queries, `/admin` and `/sync` (404); POST, PUT, DELETE, and OPTIONS (405); a wrong, missing, or duplicate `Host`, request bodies, and chunked encoding (400); a 3,000-byte target (414); a 9,000-byte header (431); HEAD (200, no body). H2: a manifest replaced by a symlink makes the repository answer 503 (fail closed).

### State database and signing key (step 4)

| ID | Case | Result on all three targets |
|---|---|---|
| D1 | A damaged page in `state.db` | `quick_check` fails, publish refuses, `current` unchanged, clients keep updating |
| D2 | `reconcile` after D1 | the database is moved aside and rebuilt from the manifests; publishing works again |
| D3 | Zeroed database header (`file is not a database`) | publish refuses; after `reconcile` it works |

The reader does not use the database, so a corrupted database stops publication but not serving of the already published generation.

### Third-party repositories and removal (step 6)

| ID | Case | APT | DNF4 / DNF5 |
|---|---|---|---|
| T1 | Our service down (connection refused) | `apt-get update` exits 0 with a `W:` line for our source; Debian indexes are checked; installing from Debian works | with `skip_if_unavailable=False` (the R-001 recommendation) **every** `makecache` and the installation of a distribution package fail; with `True` both work |
| T2 | Our repository answers 503 | exit 0, `503 Service Unavailable` warning | exit 1 |
| T3a | Service and data removed, repository file left behind | exit 0 with a warning | exit 1 |
| T3 | Service, data, key, and repository file removed | exit 0, no warnings; the installed application still runs; third-party repository files unchanged | same, exit 0 |

### Measurements (step 5)

Measured in WSL2, with the benchmark client on the same machine; the numbers are indicative, not guarantees.

| Metric | Debian 12 | AlmaLinux 9 | Fedora 44 |
|---|---|---|---|
| Resident memory after activation (idle) | 4.0 MiB, 4 threads | 4.0 MiB, 4 threads | 4.3 MiB, 4 threads |
| Peak resident memory after the benchmarks | 8.5 MiB | 8.3 MiB | 8.7 MiB |
| Cold activation to first response (5 runs) | 63–93 ms | 61–92 ms | 56–95 ms |
| Small file (`InRelease`/`repomd.xml`), 8 connections | 7,599 requests/s, p99 2.6 ms | 7,656 requests/s, p99 2.2 ms | 7,733 requests/s, p99 1.8 ms |
| 20 MiB package, 4 connections, verified before sending | 174 MiB/s | 180 MiB/s | 182 MiB/s |
| Same without verification | 218 MiB/s | 226 MiB/s | 215 MiB/s |
| Publishing a generation with a 20 MiB package (hashing, copy, `gpgv`, `fsync`; signing excluded) | 3.3 s | 4.3 s | 3.7 s |
| Size of a generation manifest (4–6 paths) | 1,157 bytes | 1,068 bytes | 1,068 bytes |

The store holds every object once, regardless of how many generations reference it.

### GitHub conditional requests (step 3)

Six anonymous requests for `repos/cli/cli/releases/latest` (`research/r-004/github-304.sh`):

1. An unconditional GET returns 200 with a weak `ETag` and `Last-Modified`.
2. `If-None-Match` with that `ETag` returns 304.
3. A different `ETag` returns 200.
4. The same `ETag` on another URL (`releases?per_page=1`) returns 200 with its own `ETag`.
5. `If-Modified-Since` returns 304.
6. An anonymous 304 **still reduced** `x-ratelimit-remaining` (59 → 54 over the six requests).

## Not covered

- Power loss of the host and power loss during lazy fetch or with the reader serving. The power-loss cycles covered the publisher and the store on one guest file system (ext4) only.
- SELinux and AppArmor enforcement. WSL2 runs neither, and the hardening directives of the unit were not checked at run time.
- A TLS upstream and the real GitHub asset host. The address policy was tested with plain HTTP to a local mock. Authenticated rate limiting of 304 responses was not tested.
- Astra Linux, RED OS, Ubuntu, and ALT; packaging Pakomichi itself as DEB/RPM and removing it with the package manager. Removal was simulated by deleting the units, data, and repository files.
- The separation of reader, downloader, and state owner into processes (ADR-017); privileged ports and port squatting while the socket is down (see conclusion 3) were not tested.
- Long runs, many logical repositories at once, and garbage collection under load. `gc` exists in the harness but was not part of the scenarios.

## Conclusions and required decision changes

1. **ADR-007 holds** on systemd 252 and 259: the `Accept=no` socket starts exactly one process for parallel cold requests, survives crashes and idle exit, and the ordinary-service fallback works with the same protocol. The reader must refuse non-loopback listeners (shown).
2. **A crash loop disables the socket.** After 5 failed starts within the default start-limit interval, systemd puts the socket into `failed`, and it stops listening until `systemctl reset-failed` and a socket start. Pakomichi needs a health check and a documented recovery command (`doctor`/admin path), and must avoid exiting with an error on recoverable conditions.
3. **While the socket is down, the port is free.** Any local user could then bind `127.0.0.1:<port>` and answer in its place. APT bounds a replay with `Valid-Until`, and DNF does not (see 6). Consider a privileged port (below 1024) bound by systemd, so that unprivileged users cannot take it over. This is a proposal from analysis and was not tested.
4. **Restarts break in-flight requests** (10–13 of 20,000). The reader needs a graceful drain on `SIGTERM` (stop accepting, finish in-flight responses) before upgrades. A slow-client limit with 64 connections lets 70 local slow clients delay others by about 10 s. A per-client limit and a shorter header timeout are needed, although the exposure is local only.
5. **ADR-008 is confirmed with two mandatory details.** (a) Content-addressed index names (`Acquire-By-Hash: yes`; unique `repodata` names) are required: without them, a switch produces hash mismatches (G3). (b) Old generations must stay reachable for at least the longest client update. Without retention APT does not just fail: it falls back to the mutable plain path and mixes generations, which its own hash check then rejects (G4). Garbage collection must be by reachability plus a time window, not by generation count alone.
6. **DNF needs server-side freshness and rollback protection.** `repomd.xml` has no signed expiry, and DNF accepted older signed metadata served again after newer metadata, offering the older version (G8). APT ignored the replay and enforces `Valid-Until` (G7). For DNF, Pakomichi must stop serving a generation (503) after the maximum freshness of the delivery-recovery design, and must never move `current` back to an older generation.
7. **The detached `repomd.xml.asc` can mismatch during a switch.** On Fedora 44, 1–3 of 640 parallel updates per run failed with `Bad PGP signature` while generations switched every few seconds. The failure is fail-closed. Per-connection pinning does not help, because librepo uses several connections. Pakomichi should switch RPM generations rarely (the 6-hour check, not on every poll), and its own `sync` should treat a signature failure right after a switch as retryable. Generations must not be switched faster than clients update.
8. **R-001's `skip_if_unavailable=False` conflicts with availability.** With it, an unavailable Pakomichi source blocks every DNF operation on the system, including distribution updates (T1, T2, T3a). The decision in P1-005 must weigh this against R-001's reason for `False` (no silent fallback to another instance). Whatever is chosen, removal must delete the repository file (T3a), and the socket must stay listening (conclusion 2).
9. **APT exit codes are not a health signal:** `apt-get update` exits 0 when our source is unreachable or answers 503 (T1, T2), which matches R-001.
10. **CAS write protocol confirmed:** staging, digest check, `fsync`, rename, directory `fsync`, with staging cleanup at start, survives kills at every step and three guest power cuts during continuous publishing. After each cut, `current` was the last acknowledged generation, and nothing acknowledged was lost. Lazy fetch never publishes a partial, substituted, or oversized object; it maps failures to 502/504/507; it downloads each digest once. Verifying objects before sending catches on-disk corruption at a cost of 15–20% of large-file throughput. APT and DNF also catch it themselves, so verification on send (or a periodic scrub) is recommended rather than required.
11. **SSRF:** resolving each hop once, checking every resolved address, and connecting to the vetted address blocks redirects to loopback, private, link-local, metadata, and IPv6 loopback addresses. The production downloader must keep this with HTTPS and must reject a redirect to a non-HTTPS URL.
12. **ADR-013 confirmed:** manifests and objects are the source of truth. A corrupted SQLite database stops publication but not serving, and `reconcile` rebuilds it.
13. **Signing key loss** stops publication honestly. APT clients fail after `Valid-Until`, and DNF clients need conclusion 6. Signing keys and Valid-Until settings must be chosen so that expiry is noticed before it blocks users (the 24-hour staleness warning in the delivery-recovery design).
14. **GitHub 304:** a 304 confirms "unchanged" only when the request carried `If-None-Match` with the `ETag` from an earlier verified 200 for the same URL and credentials. The `ETag` is weak and bound to the URL. A 304 never confirms asset bytes. Anonymous 304 responses consume the rate limit, so anonymous polling does not get cheaper with conditional requests.
15. **Side finding for ADR-017:** AlmaLinux 9 ships SQLite 3.34.1, older than the 3.37 that ADR-017 requires for `STRICT` tables. EL9-family support needs a decision: bundled SQLite for that family, no `STRICT` tables, or no EL9 in 0.1. The project owner chose no `STRICT` tables: see ADR-020.

The fallback of the protocol was not needed: socket activation met the requirements on every tested target.
