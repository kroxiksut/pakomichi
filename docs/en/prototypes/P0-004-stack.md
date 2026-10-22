# P0-004 implementation-stack prototype report

**English** · [Русский](../../ru/prototypes/P0-004-stack.md)

**Date:** 2026-10-19  
**Result:** PASS for the bounded prototype; ADR-017 accepted by the project owner. This report does not complete R-001 through R-004 or claim a supported Linux matrix.

## Environment

- Provider: WSL2 VM, Ubuntu 24.04, x86_64.
- Kernel: `6.18.40.1-microsoft-standard-WSL2`.
- systemd: `255.4-1ubuntu8.18`, running.
- Rust: `rustc 1.94.1`, `cargo 1.94.1`, installed without root by `setup-rust.sh` after SHA-256 verification of `rustup-init`.
- System SQLite: 3.45.1 through `pkg-config`/`libsqlite3`; no bundled SQLite feature was enabled.
- Native tools used without installation or repository changes: `gpg`, `gpgv`, `dpkg-deb`, `systemd-socket-activate`, `systemd-analyze`, `curl`, and Python 3.
- Raw downloads, keys, logs, packages, and verification JSON stayed under ignored `.research-local/p0-004/`. Temporary DEB trees used the WSL filesystem and were removed.

The environment manifest is reproduced from the repository root with:

```sh
wsl -d Ubuntu-24.04 -- bash prototypes/p0-004/environment-manifest.sh
```

The scripts resolve the repository root from their own location, so the checkout path does not matter. To repeat the run from a clean environment, in order:

```sh
bash prototypes/p0-004/setup-rust.sh
bash prototypes/p0-004/fetch-dependencies.sh
bash prototypes/p0-004/run-cargo.sh test --all-targets --locked
```

`fetch-dependencies.sh` is the only step after `setup-rust.sh` that uses the network. All other steps build offline from that dependency cache. `prototypes/p0-004/paths.sh` keeps build outputs and the cache outside the checkout (under `C:\temp\pakomichi\p0-004` in WSL, otherwise under the system temp directory). `verify-packaging.sh` accepts `P0004_OUTPUT_ROOT` so that a repeat run does not overwrite the packages recorded below.

## Results

| Contract | Command | Positive result | Negative result | Boundary |
|---|---|---|---|---|
| APT/RPM metadata signatures | `bash prototypes/p0-004/verify-repository-signatures.sh` | `gpgv` accepted a clearsigned `InRelease` and detached `repomd.xml` signature | modified `repomd.xml` produced `BAD signature` | Test-only Ed25519 key; no package re-signing |
| DEB inspection | `bash prototypes/p0-004/verify-deb-inspection.sh` | `dpkg-deb --field/--info` read a synthetic package | truncated DEB rejected; embedded `preinst` did not run; `/var/lib/dpkg/status` hash unchanged | No install, no root, no package DB write |
| RPM and SQLite libraries | `cargo test --all-targets --locked` in `prototypes/p0-004` | `rpm` read name/scriptlet metadata; `rusqlite` applied migration 0001 using system SQLite and completed an online backup | truncated RPM rejected without executing `%pre`; invalid SQLite FK rejected | `rpm 0.30.2` with only payload/gzip in the fixture builder; `rusqlite 0.40.2` without bundled SQLite |
| Tokio, socket activation, and sandbox | `cargo test --all-targets --locked`; `bash prototypes/p0-004/verify-systemd-runtime.sh` | semaphore limited parallel work; health completed while a two-second blocking job ran through `spawn_blocking`; inherited loopback listener returned 200; unit exposure score 3.3 `OK` | missing activation and `0.0.0.0` listener rejected; POST returned 405 | Tokio only for the network process; no root; offline unit analysis; full lifecycle remains R-004 |
| Native packaging | `bash prototypes/p0-004/verify-packaging.sh` | release binary and units were assembled into DEB and RPM and metadata round-tripped | neither package was installed; DEB maintainer scripts and RPM `%pre` were absent | Direct `dpkg-deb` assembly plus Rust `rpm` builder; package manager behavior remains R-001/R-002/R-004 |
| GitHub provenance | `GH_BIN=... bash prototypes/p0-004/verify-github-attestation.sh` | GitHub CLI 2.95.0 verified Sigstore/SLSA provenance for SHA-256 `25d1…3d8c`, repository ID `212613049`, workflow path, and hosted runner | one appended byte caused verification failure | Public `cli/cli` fixture; the verifier is a reference oracle, not yet a runtime dependency |

The Rust checks completed with two async runtime tests, two integration tests, and Clippy with `-D warnings`. The generated package hashes for the accepted Tokio packaging run were:

```text
7f56f9780dda75511963b894a51924651fdea05c3e96b4c49ece9f06ca65b62f  pakomichi-stack-probe_0.0.0_amd64.deb
c323ea556f674d0b091636dd006a01df209059b9b55c565819187f8a62c60ba9  pakomichi-stack-probe-0.0.0-1.x86_64.rpm
```

These are run artifacts, not release checksums or reproducibility claims.

## Dependency observations

- Runtime candidates proven here: `tokio 1.53.3` with selected features, `listenfd 1.0.2`, `rusqlite 0.40.2`, and metadata-only `rpm 0.30.2`.
- Tokio is mandatory only for the long-lived network process. SQLite remains behind one synchronous owner; package inspection, signing, and privileged apply remain process boundaries. Concurrency uses bounded semaphores/channels and blocking work must not occupy Tokio workers.
- Every license expression in the fixture/build graph used only MIT, Apache-2.0 (including `WITH LLVM-exception`), Unicode-3.0, Unlicense, and Zlib; `zlib-rs` was the only crate licensed solely under Zlib. The graph contained no Git dependency.
- `gpgv` and `dpkg-deb` remain process boundaries so untrusted package bytes are not parsed by a privileged Pakomichi process.
- GitHub CLI is suitable as an independent reference oracle for R-003. This prototype does not approve it as a mandatory installed runtime or approve the experimental Rust `sigstore` crate.

## Limitations and required follow-up

- WSL2 is sufficient for this non-root prototype, but it is not evidence for the distro support matrix, DNF4/DNF5, service installation, SELinux/AppArmor, power loss, disk full, concurrency, or boot lifecycle.
- The test key lived in an ignored DrvFS directory, for which GnuPG warned about broad emulated permissions. Production keys must live on a native Linux filesystem with enforced ownership/mode; R-004 verifies that path.
- The verifier binary used for the fully WSL-contained attestation rerun was supplied through `GH_BIN`; a production verifier implementation remains gated by R-003.
- `systemd-analyze security --offline=yes` validates hardening directives but does not prove runtime enforcement. The installed-unit and failure tests belong to R-004.
- Tokio cancellation, overload behavior, concurrent lazy downloads, and shutdown ordering still require the fault scenarios in R-004; the P0 test proves the runtime boundary, not those system-level properties.

