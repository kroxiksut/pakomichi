# AGENTS.md — mandatory workflow for Pakomichi

Read this file **before any implementation work**. These instructions apply to every programming agent, including agents that automatically create or close tasks.

## Document precedence

1. Direct decisions by the project owner.
2. Accepted ADRs in `docs/en/decisions/`.
3. Requirements in `docs/en/product/`, specifications in `docs/en/specifications/`, and architecture in `docs/en/architecture/`.
4. Test criteria and research decisions in `docs/en/research/`.
5. The local task tracker `TASKS_RU.md` for execution order, dependencies, and completion state.

When documents conflict, stop **only the dependent work** and record a question or proposed ADR. Never change the architecture silently merely to make a test pass.

## Documentation language

- Canonical root-level project documents are written in English.
- `README.ru.md` is the maintained Russian localization of the primary English `README.md`.
- Documentation under `docs/` lives in two mirrored trees: `docs/en/` is canonical, and `docs/ru/` is its maintained Russian localization with the same relative paths. The indexes are `docs/README.md` and `docs/README.ru.md`.
- Every page starts with its H1 followed by a language switcher line linking to its counterpart.
- When editing a paired document (`README.md` ↔ `README.ru.md`, `docs/en/<path>` ↔ `docs/ru/<path>`), update both in the same change, English first. Never add a page to only one tree.
- A difference between language versions is a translation defect: fix the translation against the original text; a translation never changes a requirement or decision.
- Task files may be written in Russian when their name or purpose identifies them as task material, including the ignored local `TASKS_RU.md`.
- This language policy does not make a translation more authoritative than the document precedence above.

## Licensing

- Original Pakomichi source code and code-like material are licensed as `MIT OR Apache-2.0`; original documentation prose and diagrams are licensed as `CC-BY-4.0`, as defined by ADR-016 and `LICENSING.md`.
- Code blocks, commands, configuration examples, schemas, machine-readable examples, and test fixtures use the code license even when embedded in documentation.
- Do not independently change this split to GPL, BSD-only, Apache-only, MIT-only, ShareAlike, or any other licensing model.
- Do not accept third-party code that is incompatible with the chosen dual licensing, and do not remove required third-party notices.
- Mark new source files with `SPDX-License-Identifier: MIT OR Apache-2.0` using the correct comment syntax. Use `CC-BY-4.0` only for metadata describing documentation prose alone; mixed documents refer to `LICENSING.md`.
- Licensing rules may change only through a separate owner decision that accounts for the rights of every affected copyright holder.

## Prohibited without a separate architectural decision

- Do not scan all repositories owned by a user or organization, forks, or similarly named projects, and do not propose automatic updates from them.
- Do not add unrelated Git sources to satisfy dependencies or deliver system libraries from Git projects.
- Do not replace native system packages, perform a partial OS migration, or modify third-party repositories to make our own test pass.
- Do not repackage or re-sign RPM/DEB files, and do not rewrite native package versions to gain priority.
- Do not silently disable global GPG verification, APT Valid-Until, or other security checks.
- Do not treat a Git hash, package name, or Releases label as sufficient provenance evidence by itself.
- Do not execute installation scripts from downloaded DEB/RPM files while inspecting metadata.
- Do not give a network-facing parser of third-party packages root privileges, and do not expose the control API on an external interface.
- Do not install global hooks into every APT/DNF operation in the baseline mode.
- Do not add a GUI, make WinGet mandatory for 0.1, automatically convert `.tar.gz` archives into `.deb`, or support every forge in the first release.
- Do not create or close tasks at your own discretion without following `docs/en/process/agent-workflow.md`.

## Required before the main implementation

1. Follow the Rust language decision in ADR-015 and the initial runtime, library, packaging, and process model accepted in ADR-017 after the P0-004 prototype. Crates not named there (for example HTTP, GitHub API, and the production attestation verifier) are decided by their dependent tasks.
2. Complete research tasks R-001 through R-004, possibly in parallel, with **logs and reproducible commands from isolated environments**.
3. Keep architectural decisions distinct from confirmed facts. If a hypothesis is not confirmed, use its documented fallback instead of weakening the requirement.
4. Implement small vertical slices. The first slice is GitHub connection → verification → APT → ordinary `apt upgrade`.

Use `docs/en/process/rust-engineering.md` as the accepted Rust engineering baseline. It is not a ready-made `Cargo.toml`, and the ADR-017 stack does not replace the R-001 through R-004 evidence.

## Isolated environments and secrets

- Follow `docs/en/process/test-environments.md`; never run APT/DNF, systemd, root, or network experiments on the development host.
- Keep credentials, private keys, VM disks and snapshots, and raw logs only in ignored `.env`, `.vm-local/`, and `.research-local/` locations.
- Publish only sanitized, reproducible commands and evidence; keep laboratory keys separate from release keys.
- `TASKS_RU.md` is the sole task tracker and is deliberately excluded from Git. Public documents define requirements, decisions, protocols, and evidence; they do not mirror task status.

## Task workflow

- Before starting a task, check its `Зависит от` field in `TASKS_RU.md` and the required research protocols.
- Mark a task complete only when its acceptance criteria, negative tests, documentation, and saved verification artifacts are complete.
- When blocked, record the observation, reproduction, suspected cause, available options, and exact dependency; continue independent tasks.
- When a decision changes, create a superseding ADR. Never rewrite the old ADR retroactively.
- Test every network or package-manager integration in a container or VM; do not experiment with the host's system repositories.
- Never replace an explicit user confirmation for a risky transition with an automatic `yes`.
- Never claim that a command, experiment, or test ran when it did not.

## Commit messages

- Keep the complete commit message at or below 200 characters, including its subject and any body.

## Agent report for every task

`Task ID; status; changed files; checks (command + output); negative tests; risks/deviations; related ADR/R; next step.`

## Alpha criterion

Follow `docs/en/testing/release-gate.md`. Without evidence on the key systems, there is no readiness claim. It is acceptable to reduce the 0.1 support matrix honestly, but never present an untested combination as supported.
