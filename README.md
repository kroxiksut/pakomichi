<h1 align="center">Pakomichi</h1>

<p align="center">
  <img src="assets/readme/pakomichi-header-en.svg" alt="Pakomichi — Every package finds its way, from GitHub Releases to native OS packages." width="100%" />
</p>

<div align="center">

[![Rust 1.94.1](https://img.shields.io/badge/Rust-1.94.1-000000?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Code: MIT OR Apache-2.0](https://img.shields.io/badge/code-MIT%20OR%20Apache--2.0-blue.svg)](LICENSING.md)
[![Docs: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey.svg)](LICENSE-DOCS)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)

**English** · [Русский](README.ru.md)

</div>

> **Status:** requirements baseline and a minimal, non-functional Rust repository scaffold for the design and development of 0.1 alpha, dated 2026-10-18. Pakomichi is the agreed project name. The primary CLI command is `pchi`; `pakomichi` is its full-name alias.

Pakomichi connects a **specific Git repository** that publishes ready-made `.deb` or `.rpm` files in Releases and exposes selected, verified packages through local APT/DNF repositories. Users continue to run `apt install`, `apt upgrade`, `dnf install`, and `dnf upgrade`; Pakomichi does not implement its own system dependency resolver.

**Intended users:** Linux users who found a ready-made package in Git Releases but were not given a convenient update repository; developers who do not want to maintain separate APT/RPM indexes; and, later, administrators of multiple machines.

## Core rules

1. **One source means one pinned repository with a stable ID.** Do not discover other projects owned by the same account, forks, packages with similar names, or mirrors as update sources.
2. **One Git repository may release several system packages** (for example, the main application, a CLI, a service, and a shared component), including from one CI workflow. Allowed package sets are recorded explicitly.
3. **Do not deliver system libraries from unrelated Git projects.** APT/DNF resolves dependencies normally from existing OS sources; Pakomichi must not initiate a dangerous partial system migration.
4. **Do not displace system repositories automatically.** Detect a conflict first, then ask the user to decide. Equal versions containing different bytes are not a safely resolved source switch.
5. **Verify provenance and exact bytes.** Strict and Attested modes, repository binding, SHA-256 verification, and an immutable history of accepted artifacts are part of the design. A source's provenance level never drops silently. A source without cryptographic provenance (Pinned) is allowed only after explicit consent for that source and manual approval of every release, and never displaces a distribution package.
6. **Use signed local indexes, atomic snapshots, and immutable artifact URLs.** The system must not trust content merely because it is served from `localhost`.
7. **Installed software remains after Pakomichi is removed.** Updates through the bridge stop, but applications are not removed.

## How Pakomichi differs

Pakomichi is not a new package format or an app store. It is designed to turn the Releases of one repository you chose into an ordinary update source for APT or DNF.

| If you want… | Better fit | Where Pakomichi fits instead |
|---|---|---|
| A ready-made catalog of popular apps | `deb-get` | No catalog: you connect the exact repository you trust, and its updates arrive with plain `apt upgrade` or `dnf upgrade` rather than a separate command |
| A single binary in `~/.local/bin` | `eget`, `aqua` | Native `.deb`/`.rpm`, so the package manager tracks files, dependencies, and removal |
| Sandboxed desktop apps independent of the distribution | Flatpak, AppImage | The publisher's native package with your distribution's own dependencies |
| The publisher already runs a repository | PPA, COPR, OBS, vendor repository | Use that repository; Pakomichi is for projects that publish packages only in Releases |

Compared with downloading a package by hand, Pakomichi is designed to:

- pin the source by its permanent repository ID, so a renamed, transferred, or re-created repository cannot silently take its place;
- check each file against the publisher's cryptographic provenance and its exact SHA-256, and never accept a replaced file;
- never replace system libraries or your distribution's packages without your decision;
- leave installed applications in place if Pakomichi itself is removed.

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
2. [Documentation map](docs/README.md) — recommended reading order.
3. [0.1 requirements and scope](docs/en/product/scope-0.1.md).
4. [Architecture](docs/en/architecture/overview.md) and [data model](docs/en/architecture/data-model.md).
5. [ADRs](docs/en/decisions/INDEX.md) — rationale for binding decisions.
6. [Research tasks R-001…R-006](docs/en/research/INDEX.md) — blocking experiments and their reports.
7. [Roadmap and release sequence](docs/en/roadmap.md).
8. [Alpha release gate](docs/en/testing/release-gate.md).

## Project status

The concept, Rust implementation language, and initial operational stack are agreed. Rust 1.94.1 is pinned under [ADR-015](docs/en/decisions/ADR-015.md); [ADR-017](docs/en/decisions/ADR-017.md) defines the bounded Tokio network runtime, synchronous/process isolation boundaries, and native packaging path backed by the [P0-004 prototype](docs/en/prototypes/P0-004-stack.md). The repository still does not implement product behavior. Research R-001, R-002, R-004, R-005, and R-006 is complete and reflected in ADR-021 through ADR-027; R-003 (GitHub provenance) is complete only for its read-only part. No distribution is supported yet: ADR-026 lists the first targets and what each still needs. Do not present the architecture as implemented. GitHub is the first adapter; GitLab, Forgejo, and Gitea come later. WinGet remains a research direction and does not block the Linux alpha. A GUI is not planned for 0.1.

## Development

Install the pinned Rust toolchain from `rust-toolchain.toml`, Python 3, PowerShell (7, or Windows PowerShell 5.1), and `cargo-deny` 0.19.0. Run the same quality gate used by CI:

```powershell
cargo install cargo-deny --version 0.19.0 --locked
./scripts/quality.ps1
```

The gate checks common secret signatures, formatting, Clippy warnings, all workspace tests, SQLite migrations, dependency advisories, licenses, and dependency sources. Package-manager and network experiments remain restricted to the isolated environments described in [docs/en/process/test-environments.md](docs/en/process/test-environments.md).

## Licensing

Original Pakomichi source code and code-like material—including code blocks, commands, configuration examples, schemas, and test fixtures—are offered under **MIT OR Apache-2.0**. The full texts are in [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

Original documentation prose and diagrams are licensed under **CC BY 4.0**; its full text is in [LICENSE-DOCS](LICENSE-DOCS). This separation keeps code examples reusable in software and future books without applying a Creative Commons license to code.

See [LICENSING.md](LICENSING.md) for details about the license choice, third-party materials, and trademarks. This licensing policy does not imply that the software has already been implemented, tested, or released.
