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

The prose in this file is covered by the documentation terms described in
`LICENSING.md`; SQL and other code-like material use `MIT OR Apache-2.0`.
