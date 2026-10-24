# Pakomichi 0.1 alpha roadmap

**English** · [Русский](../ru/roadmap.md)

**Stage 00 — preparation:** structure, Rust baseline, SQLite model, tooling, and licensing. Rust 1.94.1 was approved by ADR-015; the initial runtime, libraries, packaging, and process model were approved by ADR-017 based on the results of the P0-004 prototype.

**Stage 01 — verification of blocking hypotheses:** R-001 APT/DNF, R-002 RPM checks, R-003 GitHub proof, R-004 socket/snapshots. Dependent components may be built once the individual results are in; 01 does not block all other work.

**Stage 02 — core:** pinned GitHub repo identity, Releases discovery, metadata, Strict/Attested verification, safe DEB/RPM inspection, CAS, family policy.

**Stage 03 — Linux native:** signed APT/RPM indexes, separate source-selection policies, a single HTTP gateway, and the full install/upgrade path through native tools.

**Stage 04 — operations:** CLI, read-only API, privileged apply/reconcile, freshness, offline, uninstall/recovery, malicious input.

**Stage 05 — alpha:** E2E on the pinned distributions, real projects (NetWatch and others), user guide, Pakomichi package, release gate.

## Critical path

`Rust prototypes → repository scaffold → GitHub provenance → Strict/Attested → policy engine → APT/RPM metadata → HTTP snapshots → native upgrade E2E → platform matrix → alpha gate`. The research on source selection, RPM signatures, and failure-tolerant delivery may be carried out in parallel; the path depends on the acceptable fallbacks.

## Do not expand 0.1

A GUI, WinGet, GitLab/Forgejo/Gitea, public package catalogs, automatically discovered forks, and a standalone dependency solver are separate future epics. WinGet starts from [R-007](research/R-007-windows-msi-winget.md), which works through a concrete MSI example. Bitbucket Cloud is not planned by the project itself: since 2025 its free workspaces cannot host release files (Downloads), and the project does not take a paid plan to test it ([R-008](research/R-008-report.md)). A contribution of a Bitbucket source with reproducible tests on a paid workspace is welcome.

## Milestone artifacts

- After stage 01: four research reports and updated ADRs/OS matrix.
- After stage 02: reproducible verification of third-party assets + state DB.
- After stage 03: E2E apt/dnf install+upgrade, including conflicts.
- After stage 04: crash recovery, removal, and diagnostics.
- After stage 05: signed builds of the bridge package, alpha notes, support matrix, and release evidence.
