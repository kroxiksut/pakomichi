# Data model — semantic specification

**English** · [Русский](../../ru/architecture/data-model.md)

The tables below describe meaning; physical columns, indexes, and migrations are designed separately. All identifiers from incoming Git data are untrusted input until verified.

| Entity | Required fields and invariants |
|---|---|
| `ForgeRepository` | internal UUID, forge, **persistent repo ID**, owner ID, canonical URL, first_seen, last_verified, state, previous addresses, trust floor (`pinned`/`attested`/`strict`, never lowered), time of Pinned consent; `(forge,repo_id)` is unique |
| `PackageFamily` | UUID, repository UUID, name/purpose, allowed names in a specific ecosystem, current revision of the set, user consent |
| `PackageIdentity` | family UUID, ecosystem (`deb`/`rpm`), native name, allowed arches; Git tag and native version must strictly never be confused |
| `ReleaseRecord` | release ID, tag, commit (verified value), date, channel under a separate policy, immutable claim, verified state |
| `Artifact` | asset ID, native package tuple, exact filename, SHA-256, size, release ID, source ID, build variant (`unknown` is allowed), verification evidence ID **or** release approval ID (never both), RPM package trust mode (Native or the Attested exception, ADR-023) |
| `TrustEvidence` | Strict/Attested type, trusted root chain, signer, source repo ID, verified SHA, predicate, verification time, verifier version, digests of the stored bundles (ADR-034); append-only audit only |
| `ReleaseApproval` | source, release, approved SHA-256, time, record; the administrator's approval of one release of a Pinned source (ADR-027); requires Pinned consent for the source; append-only |
| `SourcePolicy` | repo ID, family/package, observing/active/suspended mode, allowed channel, accepted trust modes, selected native source, native constraints |
| `InstalledObservation` | native package, version, arch, reported repository if proven, confidence, time, actual package manager data; **not the primary source of truth** |
| `OSInventory` | distro ID/version, manager/version, arch, enabled repos, installed packages, apt/dnf priority, timestamp; recalculated on changes |
| `ArtifactCache` | content SHA, bytes path, verified state, refcount/pins, download state; never use the filename as identity |
| `Snapshot` | generation (monotonic, never reused), repo, native backend, list manifests, hashes, signatures, valid_from/until, state staged/published/retired, reserved CAS refs, retention deadline |
| `DecisionLog` | event ID, object ID, rule/version, allow/hold/deny, human-readable reason, evidence, timestamp; reproducibility of decisions. Append-only; the evidence is the canonical facts JSON of `policy::Facts`; an `allow` has an empty reason code; a decision equal to the object's latest one from the same facts is not written again; replaying a row decides its facts again and reports a different outcome, a changed rule version, or unreadable facts (P2-009b) |
| `NameActivation` | source, ecosystem, native name, activated at, ended at; the activation journal (migration 0003). A name is open in at most one source; a row only ends, once, and is never deleted; "activated earlier" of the admission decision is an open row of the source (P2-009b) |
| `FamilyOutsider` | family, ecosystem, native name (migration 0005, ADR-036 point 3): a name of the source with an identity row that is not a family member, because it was seen outside the family or dropped from it while artifacts still name it. Only a confirmed family removes the mark |
| `AttestedSigner` | source, workflow path, ref rule (`tag` or `refs/heads/<branch>`), confirmed at (migration 0004, ADR-036 point 1). Append-only; the latest row of a source is its signer, and a source without one is admitted at Strict or Pinned only |
| `AdminOperation` | ID, desired state, previous hashes, staged files, apply/rollback status; recovery after an interruption between SQLite and configuration. For APT: `planned` → `verified`, `rolled_back`, or `failed`, and `reconciled` after recovery (`delivery-recovery.md`) |

## Key relationships

`ForgeRepository 1 → N PackageFamily 1 → N PackageIdentity`; `ForgeRepository 1 → N ReleaseRecord 1 → N Artifact`; each `Artifact` is linked to an allowed `PackageIdentity` and `TrustEvidence`; a Snapshot references exactly determined artifacts by hash.

A family is **not** a wildcard over a name prefix. Two different packages from the same release may belong to different families. Native `Provides`, `Obsoletes`, and `Replaces` do not mean permission to distribute an arbitrary new system package.

## Consistency and uniqueness

- A `source` is never reassigned to another `repo ID`. An ownership transfer requires separate approval.
- The key of a pinned record is `(forge, repository_id, release_id, asset_id, verified_digest)`; an existing record is not overwritten when the digest changes.
- An artifact references only evidence whose subject is its own digest. Before verification it has no evidence and cannot be `verified`, `eligible`, `published`, or `retired`; once attached, the evidence is not replaced or removed.
- The bundles named by evidence stay in the blob store for as long as the evidence exists; evidence belongs to one source, and an artifact of another source with the same digest needs its own (ADR-034).
- For a Pinned source, a release approval takes the place of evidence: it covers exactly the approved digests of that release and requires the source's Pinned consent. The Pinned level is not a `TrustEvidence` type, because it has no cryptographic evidence.
- Do not declare `source_of_installed_package=Git` from a name/version match. If the installation history is not proven, use `unknown`.
- A new Snapshot must not be made `published` until all of its indexes, signatures, and file reservations are consistent.
- A user choice is applied successfully only after reconciliation with the actual APT/DNF settings.
- On an irrecoverable DB error, do not reconstruct trust from an arbitrary repeated API fetch; a trusted backup configuration or reconfirmation is required.

## DB indexes / scaling

Index repo ID, family/name/backend, native version (compared with the native comparator, **not lexicographically**), release ID, SHA256, and state. The log/history is kept separate from cached API responses.
