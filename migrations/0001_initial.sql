-- SPDX-License-Identifier: MIT OR Apache-2.0

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS forge_repository (
    id TEXT PRIMARY KEY,
    forge TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_verified_at TEXT,
    state TEXT NOT NULL DEFAULT 'registered'
        CHECK (state IN ('discovered', 'registered', 'observing', 'active', 'suspended', 'disabled')),
    UNIQUE (forge, repository_id),
    UNIQUE (id, repository_id)
) STRICT;

CREATE TRIGGER IF NOT EXISTS forge_repository_identity_is_immutable
BEFORE UPDATE OF id, forge, repository_id ON forge_repository
FOR EACH ROW
WHEN NEW.id <> OLD.id OR NEW.forge <> OLD.forge OR NEW.repository_id <> OLD.repository_id
BEGIN
    SELECT RAISE(ABORT, 'forge repository identity is immutable');
END;

CREATE TABLE IF NOT EXISTS repository_previous_address (
    id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES forge_repository(id) ON DELETE CASCADE,
    canonical_url TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE (source_id, canonical_url)
) STRICT;

CREATE TABLE IF NOT EXISTS package_family (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES forge_repository(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    user_approved INTEGER NOT NULL DEFAULT 0 CHECK (user_approved IN (0, 1)),
    UNIQUE (source_id, name),
    UNIQUE (id, source_id)
) STRICT;

CREATE TABLE IF NOT EXISTS package_identity (
    family_id TEXT NOT NULL REFERENCES package_family(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL CHECK (ecosystem IN ('deb', 'rpm')),
    native_name TEXT NOT NULL,
    allowed_arches_json TEXT NOT NULL,
    PRIMARY KEY (family_id, ecosystem, native_name)
) STRICT;

CREATE TABLE IF NOT EXISTS release_record (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES forge_repository(id) ON DELETE RESTRICT,
    forge_release_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    commit_sha TEXT,
    published_at TEXT NOT NULL,
    channel TEXT NOT NULL,
    immutable_claim INTEGER NOT NULL DEFAULT 0 CHECK (immutable_claim IN (0, 1)),
    verification_state TEXT NOT NULL DEFAULT 'discovered'
        CHECK (verification_state IN ('discovered', 'candidate', 'verified', 'rejected', 'revoked')),
    UNIQUE (source_id, forge_release_id),
    UNIQUE (id, source_id)
) STRICT;

CREATE TABLE IF NOT EXISTS trust_evidence (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL CHECK (evidence_type IN ('strict', 'attested')),
    root_chain_json TEXT NOT NULL,
    signer_identity TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    subject_sha256 TEXT NOT NULL CHECK (length(subject_sha256) = 64),
    predicate_type TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    verifier_version TEXT NOT NULL,
    record_json TEXT NOT NULL,
    FOREIGN KEY (source_id, repository_id)
        REFERENCES forge_repository(id, repository_id) ON DELETE RESTRICT,
    UNIQUE (id, source_id),
    UNIQUE (id, source_id, subject_sha256)
) STRICT;

CREATE TRIGGER IF NOT EXISTS trust_evidence_is_append_only_update
BEFORE UPDATE ON trust_evidence
BEGIN
    SELECT RAISE(ABORT, 'trust evidence is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trust_evidence_is_append_only_delete
BEFORE DELETE ON trust_evidence
BEGIN
    SELECT RAISE(ABORT, 'trust evidence is append-only');
END;

CREATE TABLE IF NOT EXISTS artifact (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES forge_repository(id) ON DELETE RESTRICT,
    release_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    family_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    native_name TEXT NOT NULL,
    native_version TEXT NOT NULL,
    architecture TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
    build_variant TEXT NOT NULL DEFAULT 'unknown',
    -- Evidence is attached on verification. States that claim verification
    -- or serve bytes require it; blocking states may occur before it.
    evidence_id TEXT,
    state TEXT NOT NULL DEFAULT 'discovered'
        CHECK (state IN ('discovered', 'candidate', 'verified', 'eligible', 'published', 'retired', 'held', 'rejected', 'revoked')),
    CHECK (evidence_id IS NOT NULL OR state IN ('discovered', 'candidate', 'held', 'rejected', 'revoked')),
    FOREIGN KEY (release_id, source_id)
        REFERENCES release_record(id, source_id) ON DELETE RESTRICT,
    FOREIGN KEY (family_id, source_id)
        REFERENCES package_family(id, source_id) ON DELETE RESTRICT,
    -- The evidence must cover exactly these bytes.
    FOREIGN KEY (evidence_id, source_id, sha256)
        REFERENCES trust_evidence(id, source_id, subject_sha256) ON DELETE RESTRICT,
    FOREIGN KEY (family_id, ecosystem, native_name)
        REFERENCES package_identity(family_id, ecosystem, native_name) ON DELETE RESTRICT,
    UNIQUE (source_id, release_id, asset_id, sha256),
    UNIQUE (id, sha256)
) STRICT;

-- An accepted artifact record is never rebound to other bytes or another
-- release; a changed upstream asset becomes a separate, rejected record.
CREATE TRIGGER IF NOT EXISTS artifact_identity_is_immutable
BEFORE UPDATE ON artifact
FOR EACH ROW
WHEN NEW.id IS NOT OLD.id
    OR NEW.source_id IS NOT OLD.source_id
    OR NEW.release_id IS NOT OLD.release_id
    OR NEW.asset_id IS NOT OLD.asset_id
    OR NEW.family_id IS NOT OLD.family_id
    OR NEW.ecosystem IS NOT OLD.ecosystem
    OR NEW.native_name IS NOT OLD.native_name
    OR NEW.native_version IS NOT OLD.native_version
    OR NEW.architecture IS NOT OLD.architecture
    OR NEW.filename IS NOT OLD.filename
    OR NEW.sha256 IS NOT OLD.sha256
    OR NEW.byte_size IS NOT OLD.byte_size
    OR (OLD.evidence_id IS NOT NULL AND NEW.evidence_id IS NOT OLD.evidence_id)
BEGIN
    SELECT RAISE(ABORT, 'artifact identity and accepted evidence are immutable');
END;

CREATE TABLE IF NOT EXISTS source_policy (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES forge_repository(id) ON DELETE RESTRICT,
    family_id TEXT NOT NULL REFERENCES package_family(id) ON DELETE RESTRICT,
    ecosystem TEXT NOT NULL CHECK (ecosystem IN ('deb', 'rpm')),
    native_name TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'observing'
        CHECK (mode IN ('observing', 'supplemental', 'preferred', 'suspended')),
    allowed_channel TEXT NOT NULL,
    accepted_trust_modes_json TEXT NOT NULL,
    selected_native_source TEXT,
    restrictions_json TEXT NOT NULL,
    user_approved INTEGER NOT NULL DEFAULT 0 CHECK (user_approved IN (0, 1)),
    updated_at TEXT NOT NULL,
    FOREIGN KEY (family_id, source_id)
        REFERENCES package_family(id, source_id) ON DELETE RESTRICT,
    FOREIGN KEY (family_id, ecosystem, native_name)
        REFERENCES package_identity(family_id, ecosystem, native_name) ON DELETE RESTRICT,
    UNIQUE (source_id, family_id, ecosystem, native_name)
) STRICT;

CREATE TABLE IF NOT EXISTS installed_observation (
    id TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL CHECK (ecosystem IN ('deb', 'rpm')),
    native_name TEXT NOT NULL,
    native_version TEXT NOT NULL,
    architecture TEXT NOT NULL,
    reported_repository TEXT,
    confidence TEXT NOT NULL CHECK (confidence IN ('unknown', 'inferred', 'proven')),
    observed_at TEXT NOT NULL,
    manager_record_json TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS os_inventory (
    id TEXT PRIMARY KEY,
    distro_id TEXT NOT NULL,
    distro_version TEXT NOT NULL,
    manager TEXT NOT NULL CHECK (manager IN ('apt', 'dnf4', 'dnf5')),
    manager_version TEXT NOT NULL,
    architecture TEXT NOT NULL,
    enabled_repositories_json TEXT NOT NULL,
    installed_packages_json TEXT NOT NULL,
    priorities_json TEXT NOT NULL,
    observed_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS artifact_cache (
    sha256 TEXT PRIMARY KEY CHECK (length(sha256) = 64),
    bytes_path TEXT NOT NULL UNIQUE,
    verification_state TEXT NOT NULL DEFAULT 'unverified'
        CHECK (verification_state IN ('unverified', 'verified', 'rejected')),
    ref_count INTEGER NOT NULL DEFAULT 0 CHECK (ref_count >= 0),
    pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    download_state TEXT NOT NULL DEFAULT 'absent'
        CHECK (download_state IN ('absent', 'downloading', 'complete', 'failed'))
) STRICT;

CREATE TABLE IF NOT EXISTS snapshot (
    id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK (generation > 0),
    source_id TEXT NOT NULL REFERENCES forge_repository(id) ON DELETE RESTRICT,
    native_backend TEXT NOT NULL CHECK (native_backend IN ('apt', 'dnf4', 'dnf5')),
    manifests_json TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64),
    signature_sha256 TEXT CHECK (signature_sha256 IS NULL OR length(signature_sha256) = 64),
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'building'
        CHECK (state IN ('building', 'signed', 'verified', 'staged', 'published', 'retired', 'collected', 'failed')),
    UNIQUE (source_id, native_backend, generation)
) STRICT;

CREATE TABLE IF NOT EXISTS snapshot_artifact (
    snapshot_id TEXT NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL,
    sha256 TEXT NOT NULL REFERENCES artifact_cache(sha256) ON DELETE RESTRICT,
    PRIMARY KEY (snapshot_id, artifact_id),
    FOREIGN KEY (artifact_id, sha256) REFERENCES artifact(id, sha256) ON DELETE RESTRICT
) STRICT;

CREATE TABLE IF NOT EXISTS decision_log (
    event_id TEXT PRIMARY KEY,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL CHECK (rule_version > 0),
    outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'hold', 'deny')),
    reason_code TEXT NOT NULL,
    reason_text TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER IF NOT EXISTS decision_log_is_append_only_update
BEFORE UPDATE ON decision_log
BEGIN
    SELECT RAISE(ABORT, 'decision log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS decision_log_is_append_only_delete
BEFORE DELETE ON decision_log
BEGIN
    SELECT RAISE(ABORT, 'decision log is append-only');
END;

CREATE TABLE IF NOT EXISTS admin_operation (
    id TEXT PRIMARY KEY,
    desired_state_json TEXT NOT NULL,
    previous_hashes_json TEXT NOT NULL,
    staged_files_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'planned'
        CHECK (status IN ('planned', 'staged', 'verified', 'applied', 'reconciled', 'rolling_back', 'rolled_back', 'failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS forge_repository_state_idx
    ON forge_repository(state);
CREATE INDEX IF NOT EXISTS package_family_source_name_idx
    ON package_family(source_id, name);
CREATE INDEX IF NOT EXISTS package_identity_name_backend_idx
    ON package_identity(native_name, ecosystem);
CREATE INDEX IF NOT EXISTS release_record_source_release_idx
    ON release_record(source_id, forge_release_id);
CREATE INDEX IF NOT EXISTS release_record_state_idx
    ON release_record(verification_state);
CREATE INDEX IF NOT EXISTS trust_evidence_source_digest_idx
    ON trust_evidence(source_id, subject_sha256);
CREATE INDEX IF NOT EXISTS artifact_release_idx
    ON artifact(release_id);
CREATE INDEX IF NOT EXISTS artifact_digest_idx
    ON artifact(sha256);
CREATE INDEX IF NOT EXISTS artifact_native_version_idx
    ON artifact(ecosystem, native_name, architecture, native_version);
CREATE INDEX IF NOT EXISTS artifact_state_idx
    ON artifact(state);
CREATE INDEX IF NOT EXISTS source_policy_mode_idx
    ON source_policy(mode);
CREATE INDEX IF NOT EXISTS installed_observation_name_idx
    ON installed_observation(ecosystem, native_name, architecture);
CREATE INDEX IF NOT EXISTS os_inventory_observed_idx
    ON os_inventory(observed_at);
CREATE INDEX IF NOT EXISTS snapshot_source_state_idx
    ON snapshot(source_id, native_backend, state);
CREATE INDEX IF NOT EXISTS decision_log_object_idx
    ON decision_log(object_type, object_id, created_at);
CREATE INDEX IF NOT EXISTS admin_operation_status_idx
    ON admin_operation(status, updated_at);

INSERT OR IGNORE INTO schema_migrations(version, name)
VALUES (1, 'initial');

PRAGMA user_version = 1;

COMMIT;
