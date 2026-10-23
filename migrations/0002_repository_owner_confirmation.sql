-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Confirmed owner IDs of a source (R-003; specifications/github.md point 1).
-- A transfer changes the owner ID, and attestations made earlier keep the
-- owner ID of their time, so every confirmed owner stays acceptable. Each row
-- is one confirmation: 'pinned' when the source is added, 'transfer' when an
-- administrator confirms a transfer. Rows are append-only.
--
-- The current owner (forge_repository.owner_id) is always the owner of the
-- source's latest row: adding a source records its 'pinned' row, recording a
-- 'transfer' row moves the current owner, and the owner ID changes in no
-- other way. Validation runs in AFTER INSERT triggers, so a wrong storage
-- type is reported by the column check first.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS repository_owner_confirmation (
    id INTEGER PRIMARY KEY CHECK (typeof(id) = 'integer'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL CHECK (typeof(owner_id) = 'text') CHECK (owner_id <> ''),
    kind TEXT NOT NULL CHECK (typeof(kind) = 'text') CHECK (kind IN ('pinned', 'transfer')),
    confirmed_at TEXT NOT NULL CHECK (typeof(confirmed_at) = 'text')
);

-- Sources added before this migration: their pinned owner is the current one.
INSERT INTO repository_owner_confirmation(source_id, owner_id, kind, confirmed_at)
SELECT source.id, source.owner_id, 'pinned', source.first_seen_at
FROM forge_repository AS source
WHERE NOT EXISTS (
    SELECT 1 FROM repository_owner_confirmation AS confirmation
    WHERE confirmation.source_id = source.id
);

CREATE TRIGGER IF NOT EXISTS repository_owner_pinned_once
AFTER INSERT ON repository_owner_confirmation
FOR EACH ROW
WHEN NEW.kind = 'pinned'
BEGIN
    SELECT RAISE(ABORT, 'a source is pinned once')
    WHERE EXISTS (
        SELECT 1 FROM repository_owner_confirmation
        WHERE source_id = NEW.source_id AND id <> NEW.id
    );
    SELECT RAISE(ABORT, 'the pinned owner is the current owner')
    WHERE NEW.owner_id IS NOT (SELECT owner_id FROM forge_repository WHERE id = NEW.source_id);
END;

CREATE TRIGGER IF NOT EXISTS repository_owner_transfer_moves_current_owner
AFTER INSERT ON repository_owner_confirmation
FOR EACH ROW
WHEN NEW.kind = 'transfer'
BEGIN
    SELECT RAISE(ABORT, 'a transfer needs a pinned source')
    WHERE NOT EXISTS (
        SELECT 1 FROM repository_owner_confirmation
        WHERE source_id = NEW.source_id AND kind = 'pinned'
    );
    SELECT RAISE(ABORT, 'a transfer confirms another owner')
    WHERE NEW.owner_id = (SELECT owner_id FROM forge_repository WHERE id = NEW.source_id);
    UPDATE forge_repository SET owner_id = NEW.owner_id WHERE id = NEW.source_id;
END;

CREATE TRIGGER IF NOT EXISTS repository_owner_confirmation_is_append_only_update
BEFORE UPDATE ON repository_owner_confirmation
BEGIN
    SELECT RAISE(ABORT, 'owner confirmations are append-only');
END;

CREATE TRIGGER IF NOT EXISTS repository_owner_confirmation_is_append_only_delete
BEFORE DELETE ON repository_owner_confirmation
BEGIN
    SELECT RAISE(ABORT, 'owner confirmations are append-only');
END;

CREATE TRIGGER IF NOT EXISTS forge_repository_records_pinned_owner
AFTER INSERT ON forge_repository
FOR EACH ROW
BEGIN
    INSERT INTO repository_owner_confirmation(source_id, owner_id, kind, confirmed_at)
    VALUES (NEW.id, NEW.owner_id, 'pinned', NEW.first_seen_at);
END;

CREATE TRIGGER IF NOT EXISTS forge_repository_owner_follows_confirmation
BEFORE UPDATE OF owner_id ON forge_repository
FOR EACH ROW
WHEN NEW.owner_id IS NOT OLD.owner_id
    AND NEW.owner_id IS NOT (
        SELECT owner_id FROM repository_owner_confirmation
        WHERE source_id = NEW.id
        ORDER BY id DESC
        LIMIT 1
    )
BEGIN
    SELECT RAISE(ABORT, 'the owner changes only through a confirmed transfer');
END;

CREATE INDEX IF NOT EXISTS repository_owner_confirmation_source_idx
    ON repository_owner_confirmation(source_id, id);

INSERT OR IGNORE INTO schema_migrations(version, name)
VALUES (2, 'repository_owner_confirmation');

PRAGMA user_version = 2;

COMMIT;
