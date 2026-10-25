-- SPDX-License-Identifier: MIT OR Apache-2.0

-- The Attested signer of a source (ADR-036 point 1, ADR-030 point 5).
--
-- An Attested provenance must come from the workflow and ref the
-- administrator confirmed for the source. Every confirmation is a row;
-- the latest row of a source is its signer, and a source without a row has
-- none (its releases can be Strict or Pinned only). A change is a new
-- confirmed row, never an update, so the history of who could sign stays.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS attested_signer (
    id INTEGER PRIMARY KEY CHECK (typeof(id) = 'integer'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    -- One file directly under .github/workflows/ of the source repository.
    workflow TEXT NOT NULL CHECK (typeof(workflow) = 'text')
        CHECK (workflow LIKE '.github/workflows/_%'
            AND substr(workflow, 19) NOT LIKE '%/%'
            AND (workflow LIKE '%.yml' OR workflow LIKE '%.yaml')),
    -- 'tag' (the tag of the release being verified) or refs/heads/<branch>.
    signer_ref TEXT NOT NULL CHECK (typeof(signer_ref) = 'text')
        CHECK (signer_ref = 'tag' OR signer_ref LIKE 'refs/heads/_%'),
    confirmed_at TEXT NOT NULL CHECK (typeof(confirmed_at) = 'text')
);

CREATE INDEX IF NOT EXISTS attested_signer_source_idx
    ON attested_signer(source_id, id);

CREATE TRIGGER IF NOT EXISTS attested_signer_is_append_only
BEFORE UPDATE ON attested_signer
BEGIN
    SELECT RAISE(ABORT, 'signer confirmations are append-only');
END;

CREATE TRIGGER IF NOT EXISTS attested_signer_is_kept
BEFORE DELETE ON attested_signer
BEGIN
    SELECT RAISE(ABORT, 'signer confirmations are append-only');
END;

INSERT OR IGNORE INTO schema_migrations(version, name)
VALUES (4, 'attested_signer');

PRAGMA user_version = 4;

COMMIT;
