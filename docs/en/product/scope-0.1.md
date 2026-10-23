# Version 0.1 alpha: scope and explicitly deferred features

**English** · [Русский](../../ru/product/scope-0.1.md)

## Required capabilities

- GitHub Releases of **public** repositories, with exact binding to the GitHub repository ID and owner ID.
- DEB/APT and RPM/DNF4/DNF5 only on distribution builds admitted by ADR-026. The first targets are Debian 12, AlmaLinux 9, Fedora 44, and Astra Linux 1.8.6 at `base(orel)`; each is claimed only after the evidence of ADR-026 point 1 exists for that exact build.
- Connecting a concrete URL, package discovery, selection of an admitted package family, activation / observation / disabling.
- Two verifiable methods of confirming provenance — Strict (immutable release + a suitable check) and Attested (a cryptographically verified attestation of the specific artifact); supported only if the R-003 implementation is confirmed.
- The Pinned level (ADR-027): no cryptographic provenance, only behind explicit per-source consent and manual approval of every release, and only in `supplemental` mode. The ratchet (a source's level never drops silently) and the visible level labels apply to every source.
- Preflight checks of architecture, native metadata, dependencies, conflicts, and installed sources.
- Signed logical local repositories, verified snapshot generations, SHA-256/immutable content paths, on-demand download where it is permissible.
- Prohibition of ambiguous automatic transitions; no automatic search for Git dependencies and no replacement of system libraries.
- A minimal CLI for source add/inspect/activate/list/sync/remove and `pchi doctor`; a read-only status API only.
- Rollback of a failed configuration-change operation; installed programs remain independent of Pakomichi removal.
- Recovery documents, logs of admission/rejection reasons, reproducible negative tests.

## Not included in 0.1 alpha

- GitLab/Gitea/Forgejo as implemented adapters (the interfaces are being prepared).
- WinGet, a GUI, a public web catalog, automatic fork recommendations.
- A cross-platform rebuilder of archives into native system packages.
- Automatic OS recovery after an erroneous installation of a third-party application; full isolation of its installation scripts.
- Automatic trusted revocation notifications with our own infrastructure; a full TUF implementation.
- Automatic execution of application installation commands from the local API.
- A hard guarantee that malicious code is absent or that a third-party binary works on any related OS.
- The Signed provenance level and the time-based quarantine for Pinned (deferred to 0.2 by ADR-027).
- Astra Linux with the closed software environment on, Astra Linux 1.7 at any level (ADR-025, ADR-026), ALT Linux, arm64 and aarch64 (ADR-026).

## Blocking research tasks

`R-001` version/source selection; `R-002` RPM checks; `R-003` GitHub attestation/immutable; `R-004` local delivery and snapshots; `R-006` Astra Linux protected levels. R-001, R-002, R-004, R-005, and R-006 are complete and reflected in ADR-021 through ADR-027; R-003 is complete (PASS, with the owner's test repository) and reflected in ADR-030 and ADR-031. Research tasks block **only their own dependent components**; other work may proceed in parallel.

## Release conditions

See `docs/en/testing/release-gate.md`. Do not publish generalized claims such as "works on all Debian/Fedora/Astra" if only part of the matrix is confirmed.
