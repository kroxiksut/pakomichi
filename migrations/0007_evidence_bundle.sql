-- SPDX-License-Identifier: MIT OR Apache-2.0

-- The attestation bundles each piece of evidence was verified from
-- (ADR-034 point 1).
--
-- The bundle bytes stay in the blob store under their SHA-256, as received;
-- this table names them, so that the evidence can be verified again offline
-- and the blob store's collector keeps every bundle named here. Like the
-- evidence itself, a row is never changed or removed, and it belongs to the
-- source of its evidence. ADR-030 bounds a digest to 16 bundles, so one
-- piece of evidence names at most 16. Evidence recorded before this
-- migration names no bundle, because its bytes were not kept.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS evidence_bundle (
    evidence_id TEXT NOT NULL CHECK (typeof(evidence_id) = 'text'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text'),
    bundle_sha256 TEXT NOT NULL CHECK (typeof(bundle_sha256) = 'text')
        CHECK (length(bundle_sha256) = 64 AND bundle_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (evidence_id, bundle_sha256),
    FOREIGN KEY (evidence_id, source_id)
        REFERENCES trust_evidence(id, source_id) ON DELETE RESTRICT
);

-- AFTER INSERT, so that type and key constraints are reported first; a row
-- that is already recorded and ignored is not counted again.
CREATE TRIGGER IF NOT EXISTS evidence_bundle_is_bounded
AFTER INSERT ON evidence_bundle
FOR EACH ROW
WHEN (SELECT COUNT(*) FROM evidence_bundle WHERE evidence_id = NEW.evidence_id) > 16
BEGIN
    SELECT RAISE(ABORT, 'evidence names at most 16 bundles');
END;

CREATE TRIGGER IF NOT EXISTS evidence_bundle_is_append_only_update
BEFORE UPDATE ON evidence_bundle
BEGIN
    SELECT RAISE(ABORT, 'evidence bundles are append-only');
END;

CREATE TRIGGER IF NOT EXISTS evidence_bundle_is_append_only_delete
BEFORE DELETE ON evidence_bundle
BEGIN
    SELECT RAISE(ABORT, 'evidence bundles are append-only');
END;

INSERT OR IGNORE INTO schema_migrations(version, name)
VALUES (7, 'evidence_bundle');

PRAGMA user_version = 7;

COMMIT;
