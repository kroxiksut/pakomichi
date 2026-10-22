# Rust engineering rules

**English** · [Русский](../../ru/process/rust-engineering.md)

**Document status:** mandatory baseline following the approval of Rust and the initial toolchain in ADR-015. The initial runtime, libraries, packaging, and process model were approved by ADR-017 after P0-004; dependent integrations are still going through R-001…R-004.

This document adapts transferable experience from another Rust project to Pakomichi's boundaries. It does not carry over that project's architecture, Windows/Qt decisions, dependency versions, or former licensing policy.

**Verified baseline as of 2026-10-19:** the local Windows quality gate uses `rustc 1.94.1`, `cargo 1.94.1`, `rustfmt 1.8.0-stable`, `clippy 0.1.94`, `cargo-deny 0.19.0`; P0-004 reproduced Rust 1.94.1 on Ubuntu 24.04 WSL2 and verified the ADR-017 stack. This is not evidence of package manager behavior or of a supported Linux matrix.

## Reproducible toolchain

- Pin the Rust version in `rust-toolchain.toml`; update it deliberately, with a full quality gate run.
- For the application, commit `Cargo.lock` and verify the build from a clean environment.
- The workspace, profiles, and shared lint settings have a single source of truth in the root `Cargo.toml`.
- Do not create the main Cargo workspace until the dependencies and acceptance criteria set by the local tracker are met. The confirmed pin is used as the starting point for prototypes and may be deliberately updated by a separate documented change.

## Minimum quality gate

Once the workspace exists, a single local command and CI must run at least:

```text
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
```

The exact set of flags is approved after cost and compatibility are checked. Test the whole crate, not only `--lib`: integration tests lie outside the library target boundary. Network, package, and system scenarios from R-001…R-004 are still run in containers/VMs and are not replaced by Cargo unit tests.

## Baseline lints

Recommended workspace starting point:

- `unsafe_code = "deny"` and `unused_must_use = "deny"`;
- Clippy `dbg_macro = "deny"`, `unwrap_used = "deny"`;
- `expect_used`, `todo`, and `unimplemented` at least as warnings, with a plan for tightening them.

`unsafe` is permitted only where a system API or FFI genuinely offers no safe alternative. The permission is localized to the smallest possible section and is accompanied by `// SAFETY:` with a verifiable contract and a safe outer wrapper. The first `unsafe` in a previously safe crate is a separate review subject, not an incidental detail of a change.

## Untrusted data

The GitHub API, release assets, DEB/RPM files, local IPC requests, and data from user-modifiable files are treated as hostile.

- Parsers have explicit limits on size, count, depth, and time.
- A failure is confined to a single request, file, or operation and must not cause a panic.
- The exact bytes and the stored evidence are verified before system application.
- In-house parsers are provided with property tests and fuzz targets that call the real production entry point with production limits.
- Negative cases check not only the error code but also that no partial snapshot is published, no policy is weakened, and no third-party sources are modified.

## Crate and privilege boundaries

- The dependency direction follows `docs/en/architecture/overview.md` and the ADRs, not the convenience of the first prototype.
- Prohibited transitive dependencies are checked against the resolved `cargo metadata` graph; searching `Cargo.toml` alone does not prove that a dependency is absent from the binary.
- The network client and the inspector of third-party packages do not receive root or the local repository's private key.
- The IPC, storage, and serialized-decision formats have an explicit version and a single normative type; `Debug`/`Display` are not used as a stable wire/storage format. Serialization uses serde and serde_json under the field, version, and size rules of [ADR-019](../decisions/ADR-019.md).
- The OS mechanism is separated from policy. An unconfirmed capability of a specific system is expressed as a capability/fallback, not as a fictitious generic implementation.

## Dependencies and licenses

- Only registry dependencies from the approved source; Git dependencies and wildcard versions are prohibited without a separate decision.
- Check advisories, yanked crates, duplicate versions, and licenses for all supported target graphs.
- `cargo deny` sees the licenses of Rust crates but does not prove the terms of a native library behind `*-sys`/FFI; verify its provenance and license separately.
- A dependency being permitted does not make its source code part of Pakomichi under `MIT OR Apache-2.0`.

## Code and comments

- The public surface is narrow; the implementation stays private until the external contract is proven by a consumer.
- A comment explains a reason or an invariant rather than restating the code.
- Task numbers, phases, dates, and change history are not placed in source comments. Working status lives in `TASKS_RU.md`, an architectural decision in an ADR, and a research fact in an R report.
- A defect fix includes a test that fails without the fix, if such a test is technically possible and actually exercises the mechanism.

## Mandatory prototype checks

P0-004 checked OpenPGP/repository signatures, DEB/RPM parsing without running scripts, GitHub attestations through a reference oracle, SQLite, Tokio with bounded concurrency, systemd/socket activation, sandboxing, DEB/RPM packaging, and the toolchain; the protocol is in `docs/en/prototypes/P0-004-stack.md`. This confirms the initial ADR-017 stack but does not replace R-001…R-004 and their VM matrix.
