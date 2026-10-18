# Pakomichi — a package bridge from Git releases to native package managers

<div align="center">

[![Rust 1.94.1](https://img.shields.io/badge/Rust-1.94.1-000000?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Code: MIT OR Apache-2.0](https://img.shields.io/badge/code-MIT%20OR%20Apache--2.0-blue.svg)](LICENSING.md)
[![Docs: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey.svg)](LICENSE-DOCS)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)

**English** · [Русский](README.ru.md)

</div>

> **Status:** requirements baseline for the design and development of 0.1 alpha, dated 2026-10-18. This repository currently contains documentation, **not a working program**. Pakomichi is the agreed project name. The primary CLI command is `pchi`; `pakomichi` is its full-name alias.

Pakomichi connects a **specific Git repository** that publishes ready-made `.deb` or `.rpm` files in Releases and exposes selected, verified packages through local APT/DNF repositories. Users continue to run `apt install`, `apt upgrade`, `dnf install`, and `dnf upgrade`; Pakomichi does not implement its own system dependency resolver.

**Intended users:** Linux users who found a ready-made package in Git Releases but were not given a convenient update repository; developers who do not want to maintain separate APT/RPM indexes; and, later, administrators of multiple machines.

## Core rules

1. **One source means one pinned repository with a stable ID.** Do not discover other projects owned by the same account, forks, packages with similar names, or mirrors as update sources.
2. **One Git repository may release several system packages** (for example, the main application, a CLI, a service, and a shared component), including from one CI workflow. Allowed package sets are recorded explicitly.
3. **Do not deliver system libraries from unrelated Git projects.** APT/DNF resolves dependencies normally from existing OS sources; Pakomichi must not initiate a dangerous partial system migration.
4. **Do not displace system repositories automatically.** Detect a conflict first, then ask the user to decide. Equal versions containing different bytes are not a safely resolved source switch.
5. **Verify provenance and exact bytes.** Strict and Attested modes, repository binding, SHA-256 verification, and an immutable history of accepted artifacts are part of the design.
6. **Use signed local indexes, atomic snapshots, and immutable artifact URLs.** The system must not trust content merely because it is served from `localhost`.
7. **Installed software remains after Pakomichi is removed.** Updates through the bridge stop, but applications are not removed.

## Example workflow (proposed CLI, not implemented yet)

```bash
pchi source add https://github.com/matthart1983/netwatch
pchi source list
pchi source inspect <source-id>
pchi source activate <source-id> --packages netwatch
pchi sync
sudo apt update
sudo apt install netwatch
```

`pchi` is the primary command used in documentation and interactive examples. `pakomichi` is the full command and must expose the same CLI; for example, `pakomichi status` and `pchi status` are equivalent. None of these commands is implemented by the current documentation bundle.

## Reading order

1. [AGENTS.md](AGENTS.md) — constraints for programming agents.
2. [Documentation map](docs/INDEX.md) — recommended reading order.
3. [0.1 requirements and scope](docs/product/scope-0.1.md).
4. [Architecture](docs/architecture/overview.md) and [data model](docs/architecture/data-model.md).
5. [ADRs](docs/decisions/INDEX.md) — rationale for binding decisions.
6. [Research tasks R-001…R-004](docs/research/INDEX.md) — blocking experiments.
7. [Roadmap and release sequence](docs/roadmap.md).
8. [Alpha release gate](docs/testing/release-gate.md).

## Project status

The concept and Rust implementation language are agreed. Rust 1.94.1 is the pinned initial toolchain under [ADR-015](docs/decisions/ADR-015.md), while library, packaging, and process-model prototypes remain required before those choices are approved. Package-manager behavior has **not been confirmed by experiments**. Do not present the architecture as implemented. GitHub is the first adapter; GitLab, Forgejo, and Gitea come later. WinGet remains a research direction and does not block the Linux alpha. A GUI is not planned for 0.1.

## Licensing

Original Pakomichi source code and code-like material—including code blocks, commands, configuration examples, schemas, and test fixtures—are offered under **MIT OR Apache-2.0**. The full texts are in [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

Original documentation prose and diagrams are licensed under **CC BY 4.0**; its full text is in [LICENSE-DOCS](LICENSE-DOCS). This separation keeps code examples reusable in software and future books without applying a Creative Commons license to code.

See [LICENSING.md](LICENSING.md) for details about the license choice, third-party materials, and trademarks. This licensing policy does not imply that the software has already been implemented, tested, or released.
