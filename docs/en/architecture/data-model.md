# Data model — semantic specification

**English** · [Русский](../../ru/architecture/data-model.md)

The tables below describe meaning; physical columns, indexes, and migrations are designed separately. All identifiers from incoming Git data are untrusted input until verified.

| Entity | Required fields and invariants |
|---|---|
| `ForgeRepository` | internal UUID, forge, **persistent repo ID**, owner ID, canonical URL, first_seen, last_verified, state, previous addresses; `(forge,repo_id)` is unique |
| `PackageFamily` | UUID, repository UUID, name/purpose, allowed names in a specific ecosystem, current revision of the set, user consent |
| `PackageIdentity` | family UUID, ecosystem (`deb`/`rpm`), native name, allowed arches; Git tag and native version must strictly never be confused |
| `ReleaseRecord` | release ID, tag, commit (verified value), date, channel under a separate policy, immutable claim, verified state |
| `Artifact` | asset ID, native package tuple, exact filename, SHA-256, size, release ID, source ID, build variant (`unknown` is allowed), verification evidence ID |
| `TrustEvidence` | Strict/Attested type, trusted root chain, signer, source repo ID, verified SHA, predicate, verification time, verifier version; append-only audit only |
| `SourcePolicy` | repo ID, family/package, observing/active/suspended mode, allowed channel, accepted trust modes, selected native source, native constraints |
| `InstalledObservation` | native package, version, arch, reported repository if proven, confidence, time, actual package manager data; **not the primary source of truth** |
| `OSInventory` | distro ID/version, manager/version, arch, enabled repos, installed packages, apt/dnf priority, timestamp; recalculated on changes |
| `ArtifactCache` | content SHA, bytes path, verified state, refcount/pins, download state; never use the filename as identity |
| `Snapshot` | generation, repo, native backend, list manifests, hashes, signatures, valid_from/until, state staged/published/retired, reserved CAS refs |
| `DecisionLog` | event ID, object ID, rule/version, allow/hold/deny, human-readable reason, evidence, timestamp; reproducibility of decisions |
| `AdminOperation` | ID, desired state, previous hashes, staged files, apply/rollback status; recovery after an interruption between SQLite and configuration |

## Key relationships

`ForgeRepository 1 → N PackageFamily 1 → N PackageIdentity`; `ForgeRepository 1 → N ReleaseRecord 1 → N Artifact`; each `Artifact` is linked to an allowed `PackageIdentity` and `TrustEvidence`; a Snapshot references exactly determined artifacts by hash.

A family is **not** a wildcard over a name prefix. Two different packages from the same release may belong to different families. Native `Provides`, `Obsoletes`, and `Replaces` do not mean permission to distribute an arbitrary new system package.

## Consistency and uniqueness

- A `source` is never reassigned to another `repo ID`. An ownership transfer requires separate approval.
- The key of a pinned record is `(forge, repository_id, release_id, asset_id, verified_digest)`; an existing record is not overwritten when the digest changes.
- An artifact references only evidence whose subject is its own digest. Before verification it has no evidence and cannot be `verified`, `eligible`, `published`, or `retired`; once attached, the evidence is not replaced or removed.
- Do not declare `source_of_installed_package=Git` from a name/version match. If the installation history is not proven, use `unknown`.
- A new Snapshot must not be made `published` until all of its indexes, signatures, and file reservations are consistent.
- A user choice is applied successfully only after reconciliation with the actual APT/DNF settings.
- On an irrecoverable DB error, do not reconstruct trust from an arbitrary repeated API fetch; a trusted backup configuration or reconfirmation is required.

## DB indexes / scaling

Index repo ID, family/name/backend, native version (compared with the native comparator, **not lexicographically**), release ID, SHA256, and state. The log/history is kept separate from cached API responses.
