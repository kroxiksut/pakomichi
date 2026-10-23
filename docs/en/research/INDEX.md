# Research before dependent implementation

**English** · [Русский](../../ru/research/INDEX.md)

These are **not test results** but reproducible technical assignments. An actual conclusion is recorded only in a completed report with logs and commands; progress is tracked in the local `TASKS_RU.md`.

- [R-001: APT/DNF priorities and conflicts](R-001-source-selection.md); completed: [R-001 report](R-001-report.md)
- [R-002: RPM signatures and DNF policy](R-002-rpm-signatures.md); [R-002 report](R-002-report.md) (PASS on AlmaLinux 9 and Fedora 44)
- [R-003: GitHub immutable releases and attestations](R-003-github-provenance.md); [R-003 report](R-003-report.md) (PASS; read-only external subjects and the owner's test repository)
- [R-004: local delivery and snapshots](R-004-delivery-failure.md); [R-004 report](R-004-report.md) (PASS for Debian 12, AlmaLinux 9, and Fedora 44)
- [R-005: provenance evidence published by real repositories](R-005-provenance-survey.md) (input for the proposed ADR-018); [R-005 report](R-005-report.md) (protocol PASS; 100 repositories and a verified 20-repository subset)
- [R-006: Astra Linux protected security levels](R-006-astra-protected-modes.md); [R-006 report](R-006-report.md) (PASS for Astra Linux 1.8.6)
- [R-007: Windows — MSI packages through a local WinGet source](R-007-windows-msi-winget.md) (does not block 0.1; read-only part run on 2026-10-22, no report yet)
- [R-008: package sources — where developers publish, and what that means for the architecture](R-008-package-sources.md) (does not block 0.1); [R-008 report](R-008-report.md) (phase A complete; not yet PASS)
- [Plan of synthetic test artifacts](test-fixtures-plan.md)
- [Report template](RESULT-TEMPLATE.md)

Research tasks may be performed in parallel. If expectations are not confirmed, apply the documented fallback mode, separately proposing an ADR change when necessary. A test must not be adjusted to fit the desired answer.
