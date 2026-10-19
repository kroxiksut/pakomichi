# Database migrations

Pakomichi uses ordered, forward-only SQLite migrations. A deployment must back
up the database before applying a new migration and restore that backup if an
upgrade cannot complete. Down migrations are deliberately unsupported because
destructive schema reversal cannot generally preserve evidence and audit data.

Each migration is safe to re-run after an interrupted attempt. Application
code must enable `PRAGMA foreign_keys = ON` on every connection; the migration
files also enable it for the connection that applies them. Large package bytes
never belong in SQLite and remain in the content-addressed file store described
by ADR-013.

The initial migration uses SQLite `STRICT` tables and therefore requires SQLite
3.37.0 or newer. ADR-017 selects `rusqlite` with the distribution SQLite
library; the supported Linux package matrix is still decided by R-001 through
R-004 and the release gate.

Integrity rules that protect trust live in the schema itself, not only in
application code: repository identity, artifact identity and digest, and
attached evidence are immutable; an artifact may reference only evidence for
its own digest; evidence and decision records are append-only.

The prose in this file is covered by the documentation terms described in
`LICENSING.md`; SQL and other code-like material use `MIT OR Apache-2.0`.
