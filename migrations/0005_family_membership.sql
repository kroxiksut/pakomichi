-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Family membership is explicit (ADR-036 point 3, families-compatibility.md).
--
-- `package_identity` holds every name an artifact of the source may carry:
-- an artifact row needs one. Until now every row was a member, and a name
-- dropped from the family kept its row while artifacts named it, so the
-- family came back with it as a member. A row in `family_outsider` marks a
-- name of `package_identity` that is not a member: seen outside the
-- family, or dropped from it. Its artifacts are held with
-- `E_FAMILY_UNAPPROVED`. Only a confirmed family (`save_family`) removes
-- the mark. Rows written before this migration were all members, so none
-- needs a mark.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS family_outsider (
    family_id TEXT NOT NULL CHECK (typeof(family_id) = 'text'),
    ecosystem TEXT NOT NULL CHECK (typeof(ecosystem) = 'text'),
    native_name TEXT NOT NULL CHECK (typeof(native_name) = 'text'),
    PRIMARY KEY (family_id, ecosystem, native_name),
    FOREIGN KEY (family_id, ecosystem, native_name)
        REFERENCES package_identity(family_id, ecosystem, native_name) ON DELETE CASCADE
);

INSERT OR IGNORE INTO schema_migrations(version, name)
VALUES (5, 'family_membership');

PRAGMA user_version = 5;

COMMIT;
