# 0.1 alpha release conditions

**English** · [Русский](../../ru/testing/release-gate.md)

The criteria below are mandatory. The boundaries of the supported distributions may be changed by a separate decision; hiding a failure is not allowed.

## Research

- R-001, R-002, R-003, R-004, and R-006 must have reproducible PASS reports or a documented fallback and a limitation of the feature. R-001, R-002, R-004, R-005, and R-006 are reflected in ADR-021 through ADR-027; R-003 is complete only for its read-only part.
- ADRs must reflect the results without contradictions between the implementation and the documents.
- Every listed distribution build meets the admission rule of ADR-026 point 1 on that exact build; the first targets are Debian 12, AlmaLinux 9, Fedora 44, and Astra Linux 1.8.6 at `base(orel)`. A build without that evidence is listed as "not tested", never as supported.

## User path

- One specific GitHub repo ID is pinned; its DEB/RPM packages are discovered; allowed names are selected explicitly.
- Native APT/DNF commands in a supported environment perform install and upgrade with the distribution's ordinary update command (ADR-022 point 4); the exact bytes are verified.
- With matching versions from a third-party vendor, no undeclared substitution occurs; a higher version from another source does not change the publisher of an activated name.
- There is no automatic fork/owner-wide discovery; system libraries from Git are not connected.
- Strict/Attested work only under proven cryptographic conditions (R-003 complete and the production verifier selected), or the mode is restricted and honestly described. The RPM Attested exception waits for the same.
- Pinned works only behind per-source consent and approval of every release, in `supplemental` mode; Signed and the Pinned quarantine are not part of 0.1 (ADR-027).

## Security and reliability

- APT/DNF verify the signature of local indexes; the global signature policy is not weakened.
- `N-001..N-040` must be executed on every listed build where they apply, or a documented, justified scope reduction is required.
- The cache and snapshots withstand concurrent requests, disk-full, offline, restart, and corruption of a temporary download.
- Privilege separation is observed; the status API is read-only; the inspector of third-party packages does not receive root.
- Removing Pakomichi does not remove installed software and does not damage third-party system sources.

## Release

- Code and code-like material are licensed as `MIT OR Apache-2.0`; documentation prose and diagrams as `CC-BY-4.0`; `LICENSE-MIT`, `LICENSE-APACHE`, `LICENSE-DOCS`, and consistent contribution rules according to ADR-016 are mandatory.
- The native package provides the primary command `pchi` and the full command `pakomichi`; both pass the same set of CLI tests and do not diverge in behavior.
- The user guide, troubleshooting, the supported distribution matrix, limitations, and recovery scenarios are part of the release.
- Real CI/E2E logs are attached to the release; there are no promises such as "everything is supported" or "100% secure".
- A history of migrations and refusal reasons is available; release notes reflect the limitations, among them: an unavailable Pakomichi DNF repository blocks DNF metadata operations on the system until recovery or removal, with the recovery command (ADR-021); an activated name keeps its publisher, so distribution security updates of that name need an explicit migration (ADR-022); a consented Pinned source can still deliver a malicious release that the administrator approves (ADR-027); and the R-005 finding that only a minority of sampled repositories publish Strict or Attested evidence (ADR-026).
