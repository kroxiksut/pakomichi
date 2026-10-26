-- SPDX-License-Identifier: MIT OR Apache-2.0

-- When the evidence of a source was last checked in full (ADR-037 point 1).
--
-- Between full checks a synchronization reuses the recorded evidence of the
-- same bytes instead of asking the forge again; a full check runs when the
-- last one is 24 hours old or older, when there is none, and on
-- `pchi sync --force`. One row per source, replaced by every full check.
-- A source without a row gets a full check at its next synchronization, so
-- rows are never needed for data written before this migration.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS evidence_full_check (
    source_id TEXT PRIMARY KEY CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    checked_at TEXT NOT NULL CHECK (typeof(checked_at) = 'text')
);

INSERT OR IGNORE INTO schema_migrations(version, name)
VALUES (6, 'evidence_full_check');

PRAGMA user_version = 6;

COMMIT;
