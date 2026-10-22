-- SPDX-License-Identifier: MIT OR Apache-2.0

-- Column types are enforced by CHECK (typeof(...)) constraints instead of
-- STRICT tables, so the schema runs on SQLite 3.34.1 (ADR-020). Declared
-- types keep their affinity: as in a STRICT table, a value that converts
-- losslessly (5 into TEXT, '5' into INTEGER) is stored in the declared type,
-- and any other value (a BLOB in TEXT, 'abc' or 1.5 in INTEGER) is rejected.
-- Nullable columns also accept 'null'. The type check comes first in each
-- column, so a wrong type is reported before any other constraint.

PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY CHECK (typeof(version) = 'integer') CHECK (version > 0),
    name TEXT NOT NULL UNIQUE CHECK (typeof(name) = 'text'),
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK (typeof(applied_at) = 'text')
);

CREATE TABLE IF NOT EXISTS forge_repository (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    forge TEXT NOT NULL CHECK (typeof(forge) = 'text'),
    repository_id TEXT NOT NULL CHECK (typeof(repository_id) = 'text'),
    owner_id TEXT NOT NULL CHECK (typeof(owner_id) = 'text'),
    canonical_url TEXT NOT NULL CHECK (typeof(canonical_url) = 'text'),
    first_seen_at TEXT NOT NULL CHECK (typeof(first_seen_at) = 'text'),
    last_verified_at TEXT CHECK (typeof(last_verified_at) IN ('text', 'null')),
    state TEXT NOT NULL DEFAULT 'registered' CHECK (typeof(state) = 'text')
        CHECK (state IN ('discovered', 'registered', 'observing', 'active', 'suspended', 'disabled')),
    -- Ratchet (ADR-018): the weakest trust level a new release of this
    -- source may have, ordered pinned < attested < strict. NULL until the
    -- first admission; it only rises.
    trust_floor TEXT CHECK (typeof(trust_floor) IN ('text', 'null'))
        CHECK (trust_floor IS NULL OR trust_floor IN ('pinned', 'attested', 'strict')),
    -- Explicit consent to the Pinned level for this source; NULL means none
    -- (never granted or revoked).
    pinned_consent_at TEXT CHECK (typeof(pinned_consent_at) IN ('text', 'null')),
    UNIQUE (forge, repository_id),
    UNIQUE (id, repository_id)
);

CREATE TRIGGER IF NOT EXISTS forge_repository_identity_is_immutable
BEFORE UPDATE OF id, forge, repository_id ON forge_repository
FOR EACH ROW
WHEN NEW.id <> OLD.id OR NEW.forge <> OLD.forge OR NEW.repository_id <> OLD.repository_id
BEGIN
    SELECT RAISE(ABORT, 'forge repository identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS forge_repository_trust_floor_never_drops
BEFORE UPDATE OF trust_floor ON forge_repository
FOR EACH ROW
WHEN OLD.trust_floor IS NOT NULL
    AND (CASE NEW.trust_floor WHEN 'strict' THEN 3 WHEN 'attested' THEN 2 WHEN 'pinned' THEN 1 ELSE 0 END)
      < (CASE OLD.trust_floor WHEN 'strict' THEN 3 WHEN 'attested' THEN 2 WHEN 'pinned' THEN 1 ELSE 0 END)
BEGIN
    SELECT RAISE(ABORT, 'trust floor never drops');
END;

CREATE TABLE IF NOT EXISTS repository_previous_address (
    id INTEGER PRIMARY KEY CHECK (typeof(id) = 'integer'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE CASCADE,
    canonical_url TEXT NOT NULL CHECK (typeof(canonical_url) = 'text'),
    observed_at TEXT NOT NULL CHECK (typeof(observed_at) = 'text'),
    UNIQUE (source_id, canonical_url)
);

CREATE TABLE IF NOT EXISTS package_family (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (typeof(name) = 'text'),
    purpose TEXT NOT NULL CHECK (typeof(purpose) = 'text'),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (typeof(revision) = 'integer') CHECK (revision > 0),
    user_approved INTEGER NOT NULL DEFAULT 0 CHECK (typeof(user_approved) = 'integer')
        CHECK (user_approved IN (0, 1)),
    UNIQUE (source_id, name),
    UNIQUE (id, source_id)
);

CREATE TABLE IF NOT EXISTS package_identity (
    family_id TEXT NOT NULL CHECK (typeof(family_id) = 'text')
        REFERENCES package_family(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL CHECK (typeof(ecosystem) = 'text') CHECK (ecosystem IN ('deb', 'rpm')),
    native_name TEXT NOT NULL CHECK (typeof(native_name) = 'text'),
    allowed_arches_json TEXT NOT NULL CHECK (typeof(allowed_arches_json) = 'text'),
    PRIMARY KEY (family_id, ecosystem, native_name)
);

CREATE TABLE IF NOT EXISTS release_record (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    forge_release_id TEXT NOT NULL CHECK (typeof(forge_release_id) = 'text'),
    tag TEXT NOT NULL CHECK (typeof(tag) = 'text'),
    commit_sha TEXT CHECK (typeof(commit_sha) IN ('text', 'null')),
    published_at TEXT NOT NULL CHECK (typeof(published_at) = 'text'),
    channel TEXT NOT NULL CHECK (typeof(channel) = 'text'),
    immutable_claim INTEGER NOT NULL DEFAULT 0 CHECK (typeof(immutable_claim) = 'integer')
        CHECK (immutable_claim IN (0, 1)),
    verification_state TEXT NOT NULL DEFAULT 'discovered' CHECK (typeof(verification_state) = 'text')
        CHECK (verification_state IN ('discovered', 'candidate', 'verified', 'rejected', 'revoked')),
    UNIQUE (source_id, forge_release_id),
    UNIQUE (id, source_id)
);

CREATE TABLE IF NOT EXISTS trust_evidence (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text'),
    evidence_type TEXT NOT NULL CHECK (typeof(evidence_type) = 'text')
        CHECK (evidence_type IN ('strict', 'attested')),
    root_chain_json TEXT NOT NULL CHECK (typeof(root_chain_json) = 'text'),
    signer_identity TEXT NOT NULL CHECK (typeof(signer_identity) = 'text'),
    repository_id TEXT NOT NULL CHECK (typeof(repository_id) = 'text'),
    subject_sha256 TEXT NOT NULL CHECK (typeof(subject_sha256) = 'text')
        CHECK (length(subject_sha256) = 64),
    predicate_type TEXT NOT NULL CHECK (typeof(predicate_type) = 'text'),
    verified_at TEXT NOT NULL CHECK (typeof(verified_at) = 'text'),
    verifier_version TEXT NOT NULL CHECK (typeof(verifier_version) = 'text'),
    record_json TEXT NOT NULL CHECK (typeof(record_json) = 'text'),
    FOREIGN KEY (source_id, repository_id)
        REFERENCES forge_repository(id, repository_id) ON DELETE RESTRICT,
    UNIQUE (id, source_id),
    UNIQUE (id, source_id, subject_sha256)
);

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

-- The Pinned level (ADR-018) has no cryptographic evidence, so it is not a
-- trust_evidence type. Instead the user approves the exact bytes of one
-- release; the approval stands in for evidence and is append-only.
CREATE TABLE IF NOT EXISTS release_approval (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text'),
    release_id TEXT NOT NULL CHECK (typeof(release_id) = 'text'),
    subject_sha256 TEXT NOT NULL CHECK (typeof(subject_sha256) = 'text')
        CHECK (length(subject_sha256) = 64),
    approved_at TEXT NOT NULL CHECK (typeof(approved_at) = 'text'),
    record_json TEXT NOT NULL CHECK (typeof(record_json) = 'text'),
    FOREIGN KEY (release_id, source_id)
        REFERENCES release_record(id, source_id) ON DELETE RESTRICT,
    UNIQUE (id, source_id, release_id, subject_sha256)
);

-- AFTER triggers, so that type and key constraints are reported first.
CREATE TRIGGER IF NOT EXISTS release_approval_requires_pinned_consent
AFTER INSERT ON release_approval
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM forge_repository
    WHERE id = NEW.source_id AND pinned_consent_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'pinned level requires consent for the source');
END;

CREATE TRIGGER IF NOT EXISTS release_approval_is_append_only_update
BEFORE UPDATE ON release_approval
BEGIN
    SELECT RAISE(ABORT, 'release approval is append-only');
END;

CREATE TRIGGER IF NOT EXISTS release_approval_is_append_only_delete
BEFORE DELETE ON release_approval
BEGIN
    SELECT RAISE(ABORT, 'release approval is append-only');
END;

CREATE TABLE IF NOT EXISTS artifact (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    release_id TEXT NOT NULL CHECK (typeof(release_id) = 'text'),
    asset_id TEXT NOT NULL CHECK (typeof(asset_id) = 'text'),
    family_id TEXT NOT NULL CHECK (typeof(family_id) = 'text'),
    ecosystem TEXT NOT NULL CHECK (typeof(ecosystem) = 'text'),
    native_name TEXT NOT NULL CHECK (typeof(native_name) = 'text'),
    native_version TEXT NOT NULL CHECK (typeof(native_version) = 'text'),
    architecture TEXT NOT NULL CHECK (typeof(architecture) = 'text'),
    filename TEXT NOT NULL CHECK (typeof(filename) = 'text'),
    sha256 TEXT NOT NULL CHECK (typeof(sha256) = 'text') CHECK (length(sha256) = 64),
    byte_size INTEGER NOT NULL CHECK (typeof(byte_size) = 'integer') CHECK (byte_size >= 0),
    build_variant TEXT NOT NULL DEFAULT 'unknown' CHECK (typeof(build_variant) = 'text'),
    -- Evidence (Strict/Attested) or a Pinned approval is attached on
    -- verification, never both. States that claim verification or serve
    -- bytes require one; blocking states may occur before it.
    evidence_id TEXT CHECK (typeof(evidence_id) IN ('text', 'null')),
    approval_id TEXT CHECK (typeof(approval_id) IN ('text', 'null')),
    state TEXT NOT NULL DEFAULT 'discovered' CHECK (typeof(state) = 'text')
        CHECK (state IN ('discovered', 'candidate', 'verified', 'eligible', 'published', 'retired', 'held', 'rejected', 'revoked')),
    CHECK (evidence_id IS NULL OR approval_id IS NULL),
    CHECK (evidence_id IS NOT NULL OR approval_id IS NOT NULL
        OR state IN ('discovered', 'candidate', 'held', 'rejected', 'revoked')),
    FOREIGN KEY (release_id, source_id)
        REFERENCES release_record(id, source_id) ON DELETE RESTRICT,
    FOREIGN KEY (family_id, source_id)
        REFERENCES package_family(id, source_id) ON DELETE RESTRICT,
    -- The evidence must cover exactly these bytes.
    FOREIGN KEY (evidence_id, source_id, sha256)
        REFERENCES trust_evidence(id, source_id, subject_sha256) ON DELETE RESTRICT,
    -- The approval must cover exactly these bytes in this release.
    FOREIGN KEY (approval_id, source_id, release_id, sha256)
        REFERENCES release_approval(id, source_id, release_id, subject_sha256) ON DELETE RESTRICT,
    FOREIGN KEY (family_id, ecosystem, native_name)
        REFERENCES package_identity(family_id, ecosystem, native_name) ON DELETE RESTRICT,
    UNIQUE (source_id, release_id, asset_id, sha256),
    UNIQUE (id, sha256)
);

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
    OR (OLD.approval_id IS NOT NULL AND NEW.approval_id IS NOT OLD.approval_id)
BEGIN
    SELECT RAISE(ABORT, 'artifact identity and accepted evidence are immutable');
END;

-- Attaching a Pinned approval admits bytes, so consent must still hold.
CREATE TRIGGER IF NOT EXISTS artifact_pinned_insert_requires_consent
AFTER INSERT ON artifact
FOR EACH ROW
WHEN NEW.approval_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM forge_repository
    WHERE id = NEW.source_id AND pinned_consent_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'pinned level requires consent for the source');
END;

CREATE TRIGGER IF NOT EXISTS artifact_pinned_attach_requires_consent
AFTER UPDATE OF approval_id ON artifact
FOR EACH ROW
WHEN NEW.approval_id IS NOT NULL AND OLD.approval_id IS NULL AND NOT EXISTS (
    SELECT 1 FROM forge_repository
    WHERE id = NEW.source_id AND pinned_consent_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'pinned level requires consent for the source');
END;

CREATE TABLE IF NOT EXISTS source_policy (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    family_id TEXT NOT NULL CHECK (typeof(family_id) = 'text')
        REFERENCES package_family(id) ON DELETE RESTRICT,
    ecosystem TEXT NOT NULL CHECK (typeof(ecosystem) = 'text') CHECK (ecosystem IN ('deb', 'rpm')),
    native_name TEXT NOT NULL CHECK (typeof(native_name) = 'text'),
    mode TEXT NOT NULL DEFAULT 'observing' CHECK (typeof(mode) = 'text')
        CHECK (mode IN ('observing', 'supplemental', 'preferred', 'suspended')),
    allowed_channel TEXT NOT NULL CHECK (typeof(allowed_channel) = 'text'),
    accepted_trust_modes_json TEXT NOT NULL CHECK (typeof(accepted_trust_modes_json) = 'text'),
    selected_native_source TEXT CHECK (typeof(selected_native_source) IN ('text', 'null')),
    restrictions_json TEXT NOT NULL CHECK (typeof(restrictions_json) = 'text'),
    user_approved INTEGER NOT NULL DEFAULT 0 CHECK (typeof(user_approved) = 'integer')
        CHECK (user_approved IN (0, 1)),
    updated_at TEXT NOT NULL CHECK (typeof(updated_at) = 'text'),
    FOREIGN KEY (family_id, source_id)
        REFERENCES package_family(id, source_id) ON DELETE RESTRICT,
    FOREIGN KEY (family_id, ecosystem, native_name)
        REFERENCES package_identity(family_id, ecosystem, native_name) ON DELETE RESTRICT,
    UNIQUE (source_id, family_id, ecosystem, native_name)
);

CREATE TABLE IF NOT EXISTS installed_observation (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    ecosystem TEXT NOT NULL CHECK (typeof(ecosystem) = 'text') CHECK (ecosystem IN ('deb', 'rpm')),
    native_name TEXT NOT NULL CHECK (typeof(native_name) = 'text'),
    native_version TEXT NOT NULL CHECK (typeof(native_version) = 'text'),
    architecture TEXT NOT NULL CHECK (typeof(architecture) = 'text'),
    reported_repository TEXT CHECK (typeof(reported_repository) IN ('text', 'null')),
    confidence TEXT NOT NULL CHECK (typeof(confidence) = 'text')
        CHECK (confidence IN ('unknown', 'inferred', 'proven')),
    observed_at TEXT NOT NULL CHECK (typeof(observed_at) = 'text'),
    manager_record_json TEXT NOT NULL CHECK (typeof(manager_record_json) = 'text')
);

CREATE TABLE IF NOT EXISTS os_inventory (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    distro_id TEXT NOT NULL CHECK (typeof(distro_id) = 'text'),
    distro_version TEXT NOT NULL CHECK (typeof(distro_version) = 'text'),
    manager TEXT NOT NULL CHECK (typeof(manager) = 'text') CHECK (manager IN ('apt', 'dnf4', 'dnf5')),
    manager_version TEXT NOT NULL CHECK (typeof(manager_version) = 'text'),
    architecture TEXT NOT NULL CHECK (typeof(architecture) = 'text'),
    enabled_repositories_json TEXT NOT NULL CHECK (typeof(enabled_repositories_json) = 'text'),
    installed_packages_json TEXT NOT NULL CHECK (typeof(installed_packages_json) = 'text'),
    priorities_json TEXT NOT NULL CHECK (typeof(priorities_json) = 'text'),
    observed_at TEXT NOT NULL CHECK (typeof(observed_at) = 'text')
);

CREATE TABLE IF NOT EXISTS artifact_cache (
    sha256 TEXT PRIMARY KEY CHECK (typeof(sha256) = 'text') CHECK (length(sha256) = 64),
    bytes_path TEXT NOT NULL UNIQUE CHECK (typeof(bytes_path) = 'text'),
    verification_state TEXT NOT NULL DEFAULT 'unverified' CHECK (typeof(verification_state) = 'text')
        CHECK (verification_state IN ('unverified', 'verified', 'rejected')),
    ref_count INTEGER NOT NULL DEFAULT 0 CHECK (typeof(ref_count) = 'integer') CHECK (ref_count >= 0),
    pinned INTEGER NOT NULL DEFAULT 0 CHECK (typeof(pinned) = 'integer') CHECK (pinned IN (0, 1)),
    download_state TEXT NOT NULL DEFAULT 'absent' CHECK (typeof(download_state) = 'text')
        CHECK (download_state IN ('absent', 'downloading', 'complete', 'failed'))
);

CREATE TABLE IF NOT EXISTS snapshot (
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer') CHECK (generation > 0),
    source_id TEXT NOT NULL CHECK (typeof(source_id) = 'text')
        REFERENCES forge_repository(id) ON DELETE RESTRICT,
    native_backend TEXT NOT NULL CHECK (typeof(native_backend) = 'text')
        CHECK (native_backend IN ('apt', 'dnf4', 'dnf5')),
    manifests_json TEXT NOT NULL CHECK (typeof(manifests_json) = 'text'),
    manifest_sha256 TEXT NOT NULL CHECK (typeof(manifest_sha256) = 'text')
        CHECK (length(manifest_sha256) = 64),
    signature_sha256 TEXT CHECK (typeof(signature_sha256) IN ('text', 'null'))
        CHECK (signature_sha256 IS NULL OR length(signature_sha256) = 64),
    valid_from TEXT NOT NULL CHECK (typeof(valid_from) = 'text'),
    valid_until TEXT NOT NULL CHECK (typeof(valid_until) = 'text'),
    state TEXT NOT NULL DEFAULT 'building' CHECK (typeof(state) = 'text')
        CHECK (state IN ('building', 'signed', 'verified', 'staged', 'published', 'retired', 'collected', 'failed')),
    UNIQUE (source_id, native_backend, generation)
);

CREATE TABLE IF NOT EXISTS snapshot_artifact (
    snapshot_id TEXT NOT NULL CHECK (typeof(snapshot_id) = 'text')
        REFERENCES snapshot(id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL CHECK (typeof(artifact_id) = 'text'),
    sha256 TEXT NOT NULL CHECK (typeof(sha256) = 'text')
        REFERENCES artifact_cache(sha256) ON DELETE RESTRICT,
    PRIMARY KEY (snapshot_id, artifact_id),
    FOREIGN KEY (artifact_id, sha256) REFERENCES artifact(id, sha256) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS decision_log (
    event_id TEXT PRIMARY KEY CHECK (typeof(event_id) = 'text'),
    object_type TEXT NOT NULL CHECK (typeof(object_type) = 'text'),
    object_id TEXT NOT NULL CHECK (typeof(object_id) = 'text'),
    rule_id TEXT NOT NULL CHECK (typeof(rule_id) = 'text'),
    rule_version INTEGER NOT NULL CHECK (typeof(rule_version) = 'integer') CHECK (rule_version > 0),
    outcome TEXT NOT NULL CHECK (typeof(outcome) = 'text') CHECK (outcome IN ('allow', 'hold', 'deny')),
    reason_code TEXT NOT NULL CHECK (typeof(reason_code) = 'text'),
    reason_text TEXT NOT NULL CHECK (typeof(reason_text) = 'text'),
    evidence_json TEXT NOT NULL CHECK (typeof(evidence_json) = 'text'),
    created_at TEXT NOT NULL CHECK (typeof(created_at) = 'text')
);

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
    id TEXT PRIMARY KEY CHECK (typeof(id) = 'text'),
    desired_state_json TEXT NOT NULL CHECK (typeof(desired_state_json) = 'text'),
    previous_hashes_json TEXT NOT NULL CHECK (typeof(previous_hashes_json) = 'text'),
    staged_files_json TEXT NOT NULL CHECK (typeof(staged_files_json) = 'text'),
    status TEXT NOT NULL DEFAULT 'planned' CHECK (typeof(status) = 'text')
        CHECK (status IN ('planned', 'staged', 'verified', 'applied', 'reconciled', 'rolling_back', 'rolled_back', 'failed')),
    created_at TEXT NOT NULL CHECK (typeof(created_at) = 'text'),
    updated_at TEXT NOT NULL CHECK (typeof(updated_at) = 'text')
);

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
CREATE INDEX IF NOT EXISTS release_approval_source_release_idx
    ON release_approval(source_id, release_id, subject_sha256);
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
