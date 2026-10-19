# 0.1 alpha release conditions

**English** · [Русский](../../ru/testing/release-gate.md)

The criteria below are mandatory. The boundaries of the supported distributions may be changed by a separate decision; hiding a failure is not allowed.

## Research

- R-001, R-002, R-003, and R-004 must have reproducible PASS reports or a documented fallback and a limitation of the feature.
- ADRs must reflect the results without contradictions between the implementation and the documents.

## User path

- One specific GitHub repo ID is pinned; its DEB/RPM packages are discovered; allowed names are selected explicitly.
- Native APT/DNF commands in a supported environment perform install and upgrade; the exact bytes are verified.
- With matching versions from a third-party vendor, no undeclared substitution occurs.
- There is no automatic fork/owner-wide discovery; system libraries from Git are not connected.
- Strict/Attested work only under proven cryptographic conditions, or the mode is restricted and honestly described.

## Security and reliability

- APT/DNF verify the signature of local indexes; the global signature policy is not weakened.
- `N-001..N-025` must be executed, or a documented, justified scope reduction is required.
- The cache and snapshots withstand concurrent requests, disk-full, offline, restart, and corruption of a temporary download.
- Privilege separation is observed; the status API is read-only; the inspector of third-party packages does not receive root.
- Removing Pakomichi does not remove installed software and does not damage third-party system sources.

## Release

- Code and code-like material are licensed as `MIT OR Apache-2.0`; documentation prose and diagrams as `CC-BY-4.0`; `LICENSE-MIT`, `LICENSE-APACHE`, `LICENSE-DOCS`, and consistent contribution rules according to ADR-016 are mandatory.
- The native package provides the primary command `pchi` and the full command `pakomichi`; both pass the same set of CLI tests and do not diverge in behavior.
- The user guide, troubleshooting, the supported distribution matrix, limitations, and recovery scenarios are part of the release.
- Real CI/E2E logs are attached to the release; there are no promises such as "everything is supported" or "100% secure".
- A history of migrations and refusal reasons is available; release notes reflect the limitations.
