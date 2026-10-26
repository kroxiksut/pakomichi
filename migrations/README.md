# Database migrations

Pakomichi uses ordered, forward-only SQLite migrations. A deployment must back
up the database before applying a new migration and restore that backup if an
upgrade cannot complete. Down migrations are deliberately unsupported because
destructive schema reversal cannot generally preserve evidence and audit data.

The state owner (`src/state`) applies them in order from `PRAGMA user_version` and refuses a database written by a newer build. Each migration is safe to re-run after an interrupted attempt. Application
code must enable `PRAGMA foreign_keys = ON` on every connection; the migration
files also enable it for the connection that applies them. Large package bytes
never belong in SQLite and remain in the content-addressed file store described
by ADR-013.

Migrations target the distribution SQLite library, version 3.34.1 or newer
(ADR-020, which supersedes point 2 of ADR-017). Tables are not `STRICT`:
every column instead starts with a `CHECK (typeof(...))` constraint for its
declared type, and nullable columns also accept `'null'`. A migration must not
use SQLite features newer than 3.34.1, such as `RETURNING`, `DROP COLUMN`,
`STRICT`, `unixepoch()`, or `->>`. The supported Linux package matrix is
still decided by R-001 through R-004 and the release gate.

Integrity rules that protect trust live in the schema itself, not only in
application code: repository identity, artifact identity and digest, and
attached evidence are immutable; an artifact may reference only evidence for
its own digest; evidence and decision records are append-only.

The Pinned level (ADR-018) has no cryptographic evidence, so it is not a
`trust_evidence` type. A Pinned artifact instead references a
`release_approval`: the user's append-only approval of exactly its digest in
exactly its release, recordable and attachable only while the source has
`pinned_consent_at`. An artifact carries evidence or an approval, never both,
and neither is replaced once attached. `forge_repository.trust_floor` is the
ratchet: it only rises, from `pinned` to `attested` to `strict`.

Migration 0002 keeps the confirmed owner IDs of a source in
`repository_owner_confirmation`. A transfer changes the owner ID, and
attestations made earlier keep the owner ID of their time (R-003), so every
confirmed owner stays acceptable. Each row is one append-only confirmation:

- adding a source records a `pinned` row for its owner, and sources that
  existed before the migration get one from `first_seen_at`;
- an administrator's `transfer` confirmation moves
  `forge_repository.owner_id` to the confirmed owner.

The owner ID changes in no other way, so the current owner is always the
owner of the source's latest confirmation. A move back to an earlier owner is
recorded as a transfer again. Like `trust_evidence`, confirmations keep their
source row: a source that has confirmations cannot be deleted.

Migration 0003 adds the activation journal `name_activation` (ADR-022 point
3): one row per activation of a name by a source, open until the name is
deactivated. A partial unique index keeps a name open in at most one source,
and triggers let a row only end, once, and never be deleted. The admission
decision reads "activated earlier" from it (`architecture/policy-engine.md`).

Migration 0004 adds `attested_signer` (ADR-036 point 1): the workflow and
ref rule an Attested provenance of the source must come from. Each row is one
append-only confirmation by the administrator, and the latest row of a source
is its signer; a source without a row has none and is admitted at Strict or
Pinned only. The schema accepts only a file directly under
`.github/workflows/` and a ref rule `tag` or `refs/heads/<branch>`.

Migration 0005 adds `family_outsider` (ADR-036 point 3): a name of
`package_identity` that is not a family member. An artifact row needs an
identity row, so a name seen outside the family, or dropped from it while
artifacts still name it, keeps its row with this mark; its artifacts are held
with `E_FAMILY_UNAPPROVED`. Only saving a confirmed family removes the mark.
Rows written before the migration were all members.

Migration 0006 adds `evidence_full_check` (ADR-037 point 1): when the evidence
of a source was last checked in full with the forge. Between full checks a
synchronization reuses the recorded evidence of the same bytes of the same
asset; a full check runs when there is no row, when the row is 24 hours old or
older, or in the future (a clock set back), and on `pchi sync --force`. One
row per source, replaced by every full check.

Migration 0007 adds `evidence_bundle` (ADR-034 point 1): the SHA-256 of each
attestation bundle a `trust_evidence` row was verified from, at most 16 per
row (ADR-030). The bundle bytes stay in the blob store as received, so the
evidence can be verified again offline, and the blob store's collector keeps
every bundle named here. A row references evidence of its own source, accepts
only a lowercase hex digest, and is never changed or removed. Evidence
recorded before the migration names no bundle, because its bytes were not
kept.

The prose in this file is covered by the documentation terms described in
`LICENSING.md`; SQL and other code-like material use `MIT OR Apache-2.0`.
