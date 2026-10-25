-- SPDX-License-Identifier: MIT OR Apache-2.0

-- The activation journal (P2-009b, ADR-022 point 3, ADR-012).
--
-- An activated name keeps its publisher when the distribution or another
-- source later offers it: the admission decision reads "activated earlier"
-- from here. One row per activation of a name by a source, from the moment
-- the apply that published its pin was verified until it is deactivated.
-- `source_policy.mode` is not enough: a suspended source keeps its names.
--
-- The schema itself keeps two promises: a name is open in at most one
-- source at a time (two publishers would let the higher version decide),
-- and a row only ever ends, once; nothing else in it changes, and no row is
-- deleted.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS name_activation (
    id INTEGER PRIMARY KEY CHECK (typeof(id) = 'integer'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    ecosystem TEXT NOT NULL CHECK (typeof(ecosystem) = 'text') CHECK (ecosystem IN ('deb', 'rpm')),
    native_name TEXT NOT NULL CHECK (typeof(native_name) = 'text') CHECK (native_name <> ''),
    activated_at TEXT NOT NULL CHECK (typeof(activated_at) = 'text'),
    ended_at TEXT CHECK (typeof(ended_at) IN ('text', 'null'))
);

CREATE UNIQUE INDEX IF NOT EXISTS name_activation_one_open
    ON name_activation(ecosystem, native_name) WHERE ended_at IS NULL;

CREATE INDEX IF NOT EXISTS name_activation_source_idx
    ON name_activation(source_id, ecosystem, native_name);

CREATE TRIGGER IF NOT EXISTS name_activation_only_ends_once
BEFORE UPDATE ON name_activation
FOR EACH ROW
WHEN OLD.ended_at IS NOT NULL
    OR NEW.ended_at IS NULL
    OR NEW.id IS NOT OLD.id
    OR NEW.source_id IS NOT OLD.source_id
    OR NEW.ecosystem IS NOT OLD.ecosystem
    OR NEW.native_name IS NOT OLD.native_name
    OR NEW.activated_at IS NOT OLD.activated_at
BEGIN
    SELECT RAISE(ABORT, 'an activation only ends, once');
END;

CREATE TRIGGER IF NOT EXISTS name_activation_is_kept
BEFORE DELETE ON name_activation
BEGIN
    SELECT RAISE(ABORT, 'activations are kept');
END;

INSERT OR IGNORE INTO schema_migrations(version, name)
VALUES (3, 'name_activation');

PRAGMA user_version = 3;

COMMIT;
