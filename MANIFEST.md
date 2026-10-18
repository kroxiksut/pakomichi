# Repository manifest

This bundle contains **the project documentation and repository policy**, but no implementation code, completed R research, or real release keys. Research documents are deliberately written as reproducible protocols, not as fabricated reports.

The imported `temp/` directory, local `CLAUDE.md` and `TASKS_RU.md`, VM state, credentials, and raw research artifacts are not part of the public repository.

Previously accepted principles are recorded in ADR-001 through ADR-016. Execution state and dependencies are maintained only in the ignored local `TASKS_RU.md`; they are intentionally excluded from the public repository. Public documents record decisions, requirements, protocols, and evidence without duplicating task status.

Original source code and code-like material are licensed as `MIT OR Apache-2.0`; original documentation prose and diagrams are licensed as `CC-BY-4.0` under ADR-016. The full texts are in `LICENSE-MIT`, `LICENSE-APACHE`, and `LICENSE-DOCS`. The project owner approved `pchi` as the primary short command and `pakomichi` as the full command exposing the same CLI. Do **not** use `gitbridge` as a project or command name because that name conflicts with existing uses.

The primary English `README.md` and Russian `README.ru.md` explain how to use the repository. Release checksums will be generated for release artifacts when a release pipeline exists; a mutable repository-wide checksum list is intentionally not maintained.
