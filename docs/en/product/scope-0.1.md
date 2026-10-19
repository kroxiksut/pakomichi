# Version 0.1 alpha: scope and explicitly deferred features

**English** · [Русский](../../ru/product/scope-0.1.md)

## Required capabilities

- GitHub Releases of **public** repositories, with exact binding to the GitHub repository ID and owner ID.
- DEB/APT (Debian/Ubuntu in the tested matrix), RPM/DNF4 and DNF5 in tested environments.
- Connecting a concrete URL, package discovery, selection of an admitted package family, activation / observation / disabling.
- Two verifiable methods of confirming provenance — Strict (immutable release + a suitable check) and Attested (a cryptographically verified attestation of the specific artifact); supported only if the R-003 implementation is confirmed.
- Preflight checks of architecture, native metadata, dependencies, conflicts, and installed sources.
- Signed logical local repositories, verified snapshot generations, SHA-256/immutable content paths, on-demand download where it is permissible.
- Prohibition of ambiguous automatic transitions; no automatic search for Git dependencies and no replacement of system libraries.
- A minimal CLI for source add/inspect/activate/list/sync/diagnose/remove; a read-only status API only.
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

## Blocking research tasks

`R-001` version/source selection; `R-002` RPM checks; `R-003` GitHub attestation/immutable; `R-004` local delivery and snapshots. Research tasks block **only their own dependent components**; other work may proceed in parallel.

## Release conditions

See `docs/en/testing/release-gate.md`. Do not publish generalized claims such as "works on all Debian/Fedora/Astra" if only part of the matrix is confirmed.
