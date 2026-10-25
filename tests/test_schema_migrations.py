# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INITIAL_MIGRATION = PROJECT_ROOT / "migrations" / "0001_initial.sql"
OWNER_MIGRATION = PROJECT_ROOT / "migrations" / "0002_repository_owner_confirmation.sql"
ACTIVATION_MIGRATION = PROJECT_ROOT / "migrations" / "0003_name_activation.sql"
SIGNER_MIGRATION = PROJECT_ROOT / "migrations" / "0004_attested_signer.sql"
MEMBERSHIP_MIGRATION = PROJECT_ROOT / "migrations" / "0005_family_membership.sql"
MIGRATIONS = (
    INITIAL_MIGRATION,
    OWNER_MIGRATION,
    ACTIVATION_MIGRATION,
    SIGNER_MIGRATION,
    MEMBERSHIP_MIGRATION,
)
SCHEMA_VERSION = len(MIGRATIONS)
ZERO_DIGEST = "0" * 64


def apply_migrations(connection: sqlite3.Connection, migrations=MIGRATIONS) -> None:
    for migration in migrations:
        connection.executescript(migration.read_text(encoding="utf-8"))


def migrated_database(path: str = ":memory:", migrations=MIGRATIONS) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    apply_migrations(connection, migrations)
    return connection


def insert_source(
    connection: sqlite3.Connection,
    *,
    source_id: str = "source-1",
    repository_id: str = "1001",
) -> None:
    connection.execute(
        """
        INSERT INTO forge_repository(
            id, forge, repository_id, owner_id, canonical_url, first_seen_at
        ) VALUES (?, 'github', ?, 'owner-1', 'https://example.invalid/repository', '2026-10-18T00:00:00Z')
        """,
        (source_id, repository_id),
    )


OTHER_DIGEST = "1" * 64


def insert_artifact_prerequisites(connection: sqlite3.Connection) -> None:
    """Source, family, identity, release, and evidence for ZERO_DIGEST."""
    insert_source(connection)
    connection.executescript(
        f"""
        INSERT INTO package_family(id, source_id, name, purpose)
        VALUES ('family-1', 'source-1', 'example', 'test');
        INSERT INTO package_identity(family_id, ecosystem, native_name, allowed_arches_json)
        VALUES ('family-1', 'deb', 'example', '["amd64"]');
        INSERT INTO release_record(
            id, source_id, forge_release_id, tag, published_at, channel
        ) VALUES ('release-1', 'source-1', '10', 'v1.0.0', '2026-10-18T00:00:00Z', 'stable');
        INSERT INTO trust_evidence(
            id, source_id, evidence_type, root_chain_json, signer_identity,
            repository_id, subject_sha256, predicate_type, verified_at,
            verifier_version, record_json
        ) VALUES (
            'evidence-1', 'source-1', 'attested', '[]', 'test-signer',
            '1001', '{ZERO_DIGEST}', 'test-predicate', '2026-10-18T00:00:00Z', '0.0.0', '{{}}'
        );
        """
    )


def insert_artifact(
    connection: sqlite3.Connection,
    *,
    artifact_id: str = "artifact-1",
    sha256: str = ZERO_DIGEST,
    evidence_id: str | None = None,
    state: str = "discovered",
    approval_id: str | None = None,
    release_id: str = "release-1",
) -> None:
    connection.execute(
        """
        INSERT INTO artifact(
            id, source_id, release_id, asset_id, family_id, ecosystem,
            native_name, native_version, architecture, filename, sha256,
            byte_size, evidence_id, approval_id, state
        ) VALUES (?, 'source-1', ?, ?, 'family-1', 'deb', 'example',
                  '1.0.0', 'amd64', 'example_1.0.0_amd64.deb', ?, 1, ?, ?, ?)
        """,
        (
            artifact_id,
            release_id,
            f"asset-{artifact_id}",
            sha256,
            evidence_id,
            approval_id,
            state,
        ),
    )


def set_pinned_consent(
    connection: sqlite3.Connection, granted: bool, source_id: str = "source-1"
) -> None:
    connection.execute(
        "UPDATE forge_repository SET pinned_consent_at = ? WHERE id = ?",
        ("2026-10-20T00:00:00Z" if granted else None, source_id),
    )


def insert_release_approval(
    connection: sqlite3.Connection,
    *,
    approval_id: str = "approval-1",
    source_id: str = "source-1",
    release_id: str = "release-1",
    sha256: str = ZERO_DIGEST,
) -> None:
    connection.execute(
        """
        INSERT INTO release_approval(
            id, source_id, release_id, subject_sha256, approved_at, record_json
        ) VALUES (?, ?, ?, ?, '2026-10-20T00:00:00Z', '{}')
        """,
        (approval_id, source_id, release_id, sha256),
    )


def insert_row_in_every_table(connection: sqlite3.Connection) -> None:
    """One valid row per table, with NULL in every nullable column."""
    insert_artifact_prerequisites(connection)
    insert_artifact(connection)
    # An approval needs consent when it is recorded; revoking the consent
    # afterwards keeps the approval and leaves the column NULL.
    set_pinned_consent(connection, True)
    insert_release_approval(connection)
    set_pinned_consent(connection, False)
    connection.executescript(
        f"""
        INSERT INTO repository_previous_address(source_id, canonical_url, observed_at)
        VALUES ('source-1', 'https://example.invalid/old', '2026-10-18T00:00:00Z');
        INSERT INTO name_activation(source_id, ecosystem, native_name, activated_at)
        VALUES ('source-1', 'deb', 'example', '2026-10-18T00:00:00Z');
        INSERT INTO attested_signer(source_id, workflow, signer_ref, confirmed_at)
        VALUES ('source-1', '.github/workflows/release.yml', 'tag', '2026-10-18T00:00:00Z');
        INSERT INTO family_outsider(family_id, ecosystem, native_name)
        VALUES ('family-1', 'deb', 'example');
        INSERT INTO source_policy(
            id, source_id, family_id, ecosystem, native_name, allowed_channel,
            accepted_trust_modes_json, restrictions_json, updated_at
        ) VALUES (
            'policy-1', 'source-1', 'family-1', 'deb', 'example', 'stable',
            '[]', '{{}}', '2026-10-18T00:00:00Z'
        );
        INSERT INTO installed_observation(
            id, ecosystem, native_name, native_version, architecture,
            confidence, observed_at, manager_record_json
        ) VALUES (
            'observation-1', 'deb', 'example', '1.0.0', 'amd64',
            'unknown', '2026-10-18T00:00:00Z', '{{}}'
        );
        INSERT INTO os_inventory(
            id, distro_id, distro_version, manager, manager_version,
            architecture, enabled_repositories_json, installed_packages_json,
            priorities_json, observed_at
        ) VALUES (
            'inventory-1', 'debian', '12', 'apt', '2.6.1',
            'amd64', '[]', '[]', '{{}}', '2026-10-18T00:00:00Z'
        );
        INSERT INTO artifact_cache(sha256, bytes_path)
        VALUES ('{ZERO_DIGEST}', 'objects/{ZERO_DIGEST}');
        INSERT INTO snapshot(
            id, generation, source_id, native_backend, manifests_json,
            manifest_sha256, valid_from, valid_until
        ) VALUES (
            'snapshot-1', 1, 'source-1', 'apt', '[]',
            '{OTHER_DIGEST}', '2026-10-18T00:00:00Z', '2026-10-25T00:00:00Z'
        );
        INSERT INTO snapshot_artifact(snapshot_id, artifact_id, sha256)
        VALUES ('snapshot-1', 'artifact-1', '{ZERO_DIGEST}');
        INSERT INTO decision_log(
            event_id, object_type, object_id, rule_id, rule_version,
            outcome, reason_code, reason_text, evidence_json, created_at
        ) VALUES (
            'decision-1', 'source', 'source-1', 'identity', 1,
            'hold', 'E_REPO_ID_CHANGED', 'repository mismatch', '{{}}',
            '2026-10-18T00:00:00Z'
        );
        INSERT INTO admin_operation(
            id, desired_state_json, previous_hashes_json, staged_files_json,
            created_at, updated_at
        ) VALUES (
            'operation-1', '{{}}', '{{}}', '[]',
            '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z'
        );
        """
    )


def table_names(connection: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name"
        )
    ]


def table_columns(
    connection: sqlite3.Connection, table: str
) -> list[tuple[str, str, bool, int]]:
    """(name, declared type, NOT NULL, primary-key position) per column."""
    return [
        (row[1], row[2].upper(), bool(row[3]), row[5])
        for row in connection.execute(f'PRAGMA table_info("{table}")')
    ]


# Values that a STRICT column of the declared type also rejects. A lossless
# value (5 into TEXT, '5' into INTEGER) is converted by column affinity before
# the CHECK runs, exactly as in a STRICT table.
WRONG_TYPED_VALUES = {
    "TEXT": (b"\x00",),
    "INTEGER": ("not-an-integer", 1.5, b"\x00"),
}


class InitialMigrationTests(unittest.TestCase):
    def test_creates_expected_schema_and_version(self) -> None:
        connection = migrated_database()
        expected_tables = {
            "admin_operation",
            "artifact",
            "artifact_cache",
            "attested_signer",
            "decision_log",
            "family_outsider",
            "forge_repository",
            "installed_observation",
            "name_activation",
            "os_inventory",
            "package_family",
            "package_identity",
            "release_approval",
            "release_record",
            "repository_owner_confirmation",
            "repository_previous_address",
            "schema_migrations",
            "snapshot",
            "snapshot_artifact",
            "source_policy",
            "trust_evidence",
        }
        actual_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }

        self.assertEqual(expected_tables, actual_tables)
        self.assertEqual(
            SCHEMA_VERSION, connection.execute("PRAGMA user_version").fetchone()[0]
        )
        self.assertEqual(
            [
                (1, "initial"),
                (2, "repository_owner_confirmation"),
                (3, "name_activation"),
                (4, "attested_signer"),
                (5, "family_membership"),
            ],
            connection.execute(
                "SELECT version, name FROM schema_migrations ORDER BY version"
            ).fetchall(),
        )

    def test_foreign_keys_are_enforced(self) -> None:
        connection = migrated_database()

        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO package_family(id, source_id, name, purpose)
                VALUES ('family-1', 'missing-source', 'example', 'test')
                """
            )

    def test_cross_source_relationships_are_rejected(self) -> None:
        connection = migrated_database()
        insert_source(connection, source_id="source-1", repository_id="1001")
        insert_source(connection, source_id="source-2", repository_id="2002")
        connection.execute(
            """
            INSERT INTO package_family(id, source_id, name, purpose)
            VALUES ('family-1', 'source-1', 'example', 'test')
            """
        )
        connection.execute(
            """
            INSERT INTO package_identity(family_id, ecosystem, native_name, allowed_arches_json)
            VALUES ('family-1', 'deb', 'example', '["amd64"]')
            """
        )

        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO source_policy(
                    id, source_id, family_id, ecosystem, native_name,
                    allowed_channel, accepted_trust_modes_json,
                    restrictions_json, updated_at
                ) VALUES (
                    'policy-1', 'source-2', 'family-1', 'deb', 'example',
                    'stable', '[]', '{}', '2026-10-18T00:00:00Z'
                )
                """
            )

        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO trust_evidence(
                    id, source_id, evidence_type, root_chain_json,
                    signer_identity, repository_id, subject_sha256,
                    predicate_type, verified_at, verifier_version, record_json
                ) VALUES (
                    'evidence-1', 'source-1', 'strict', '[]', 'test-signer',
                    '2002', ?, 'test-predicate', '2026-10-18T00:00:00Z',
                    '0.0.0', '{}'
                )
                """,
                (ZERO_DIGEST,),
            )

    def test_repository_uuid_cannot_be_rebound(self) -> None:
        connection = migrated_database()
        insert_source(connection)

        with self.assertRaises(sqlite3.IntegrityError):
            insert_source(connection, source_id="source-1", repository_id="2002")

        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "forge repository identity is immutable"
        ):
            connection.execute(
                "UPDATE forge_repository SET repository_id = '2002' WHERE id = 'source-1'"
            )

        self.assertEqual(
            "1001",
            connection.execute(
                "SELECT repository_id FROM forge_repository WHERE id = 'source-1'"
            ).fetchone()[0],
        )

    def test_trust_is_never_enabled_by_default(self) -> None:
        connection = migrated_database()
        insert_source(connection)
        connection.execute(
            """
            INSERT INTO package_family(id, source_id, name, purpose)
            VALUES ('family-1', 'source-1', 'example', 'test')
            """
        )
        connection.execute(
            """
            INSERT INTO package_identity(family_id, ecosystem, native_name, allowed_arches_json)
            VALUES ('family-1', 'deb', 'example', '["amd64"]')
            """
        )
        connection.execute(
            """
            INSERT INTO source_policy(
                id, source_id, family_id, ecosystem, native_name, allowed_channel,
                accepted_trust_modes_json, restrictions_json, updated_at
            ) VALUES (
                'policy-1', 'source-1', 'family-1', 'deb', 'example', 'stable',
                '[]', '{}', '2026-10-18T00:00:00Z'
            )
            """
        )

        source_state = connection.execute(
            "SELECT state FROM forge_repository WHERE id = 'source-1'"
        ).fetchone()[0]
        family_approved = connection.execute(
            "SELECT user_approved FROM package_family WHERE id = 'family-1'"
        ).fetchone()[0]
        policy_mode, policy_approved = connection.execute(
            "SELECT mode, user_approved FROM source_policy WHERE id = 'policy-1'"
        ).fetchone()
        column_names = {
            row[1]
            for table in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
            for row in connection.execute(f'PRAGMA table_info("{table[0]}")')
        }

        trust_floor, pinned_consent = connection.execute(
            "SELECT trust_floor, pinned_consent_at FROM forge_repository WHERE id = 'source-1'"
        ).fetchone()

        self.assertEqual("registered", source_state)
        self.assertEqual((None, None), (trust_floor, pinned_consent))
        self.assertEqual(0, family_approved)
        self.assertEqual(("observing", 0), (policy_mode, policy_approved))
        self.assertNotIn("trusted", column_names)

    def test_append_only_records_reject_changes(self) -> None:
        connection = migrated_database()
        insert_source(connection)
        connection.execute(
            """
            INSERT INTO trust_evidence(
                id, source_id, evidence_type, root_chain_json, signer_identity,
                repository_id, subject_sha256, predicate_type, verified_at,
                verifier_version, record_json
            ) VALUES (
                'evidence-1', 'source-1', 'strict', '[]', 'test-signer',
                '1001', ?, 'test-predicate', '2026-10-18T00:00:00Z', '0.0.0', '{}'
            )
            """,
            (ZERO_DIGEST,),
        )
        connection.execute(
            """
            INSERT INTO decision_log(
                event_id, object_type, object_id, rule_id, rule_version,
                outcome, reason_code, reason_text, evidence_json, created_at
            ) VALUES (
                'decision-1', 'source', 'source-1', 'identity', 1,
                'hold', 'E_REPO_ID_CHANGED', 'repository mismatch', '{}',
                '2026-10-18T00:00:00Z'
            )
            """
        )

        for statement in (
            "UPDATE trust_evidence SET signer_identity = 'other' WHERE id = 'evidence-1'",
            "DELETE FROM trust_evidence WHERE id = 'evidence-1'",
            "UPDATE decision_log SET outcome = 'allow' WHERE event_id = 'decision-1'",
            "DELETE FROM decision_log WHERE event_id = 'decision-1'",
        ):
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(statement)

    def test_reapplication_and_backup_restore_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_path = root / "source.sqlite3"
            backup_path = root / "backup.sqlite3"
            restored_path = root / "restored.sqlite3"

            source = migrated_database(str(source_path))
            insert_source(source)
            source.commit()
            apply_migrations(source)
            self.assertEqual(
                SCHEMA_VERSION,
                source.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0],
            )
            self.assertEqual(
                1,
                source.execute(
                    "SELECT COUNT(*) FROM repository_owner_confirmation"
                ).fetchone()[0],
            )

            backup = sqlite3.connect(backup_path)
            source.backup(backup)
            backup.close()
            source.close()

            restored = sqlite3.connect(restored_path)
            restored.execute("PRAGMA foreign_keys = ON")
            backup = sqlite3.connect(backup_path)
            backup.backup(restored)
            backup.backup(restored)
            backup.close()

            self.assertEqual(
                "ok", restored.execute("PRAGMA integrity_check").fetchone()[0]
            )
            self.assertEqual(
                ("source-1", "1001"),
                restored.execute(
                    "SELECT id, repository_id FROM forge_repository"
                ).fetchone(),
            )
            self.assertEqual(
                SCHEMA_VERSION,
                restored.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0],
            )
            restored.close()


    def test_artifact_evidence_must_cover_the_same_digest(self) -> None:
        connection = migrated_database()
        insert_artifact_prerequisites(connection)

        insert_artifact(connection, evidence_id="evidence-1", state="verified")
        with self.assertRaises(sqlite3.IntegrityError):
            insert_artifact(
                connection,
                artifact_id="artifact-2",
                sha256=OTHER_DIGEST,
                evidence_id="evidence-1",
                state="verified",
            )

    def test_artifact_without_evidence_cannot_pass_verification(self) -> None:
        connection = migrated_database()
        insert_artifact_prerequisites(connection)

        insert_artifact(connection)
        connection.execute(
            "UPDATE artifact SET state = 'candidate' WHERE id = 'artifact-1'"
        )
        for state in ("verified", "eligible", "published", "retired"):
            with self.assertRaises(sqlite3.IntegrityError, msg=state):
                connection.execute(
                    "UPDATE artifact SET state = ? WHERE id = 'artifact-1'", (state,)
                )

        for state in ("held", "revoked", "candidate"):
            connection.execute(
                "UPDATE artifact SET state = ? WHERE id = 'artifact-1'", (state,)
            )
        connection.execute(
            "UPDATE artifact SET evidence_id = 'evidence-1', state = 'verified' "
            "WHERE id = 'artifact-1'"
        )
        self.assertEqual(
            ("evidence-1", "verified"),
            connection.execute(
                "SELECT evidence_id, state FROM artifact WHERE id = 'artifact-1'"
            ).fetchone(),
        )

    def test_accepted_artifact_identity_and_evidence_are_immutable(self) -> None:
        connection = migrated_database()
        insert_artifact_prerequisites(connection)
        insert_artifact(connection, evidence_id="evidence-1", state="verified")

        for statement in (
            f"UPDATE artifact SET sha256 = '{OTHER_DIGEST}' WHERE id = 'artifact-1'",
            "UPDATE artifact SET asset_id = 'asset-other' WHERE id = 'artifact-1'",
            "UPDATE artifact SET native_version = '2.0.0' WHERE id = 'artifact-1'",
            "UPDATE artifact SET byte_size = 2 WHERE id = 'artifact-1'",
            "UPDATE artifact SET evidence_id = NULL, state = 'candidate' WHERE id = 'artifact-1'",
        ):
            with self.assertRaises(sqlite3.IntegrityError, msg=statement):
                connection.execute(statement)

        connection.execute(
            "UPDATE artifact SET state = 'eligible' WHERE id = 'artifact-1'"
        )
        self.assertEqual(
            (ZERO_DIGEST, "eligible"),
            connection.execute(
                "SELECT sha256, state FROM artifact WHERE id = 'artifact-1'"
            ).fetchone(),
        )

    def test_every_column_rejects_a_wrong_storage_type(self) -> None:
        connection = migrated_database()
        insert_row_in_every_table(connection)

        checked_tables = set()
        for table in table_names(connection):
            columns = table_columns(connection, table)
            column_list = ", ".join(f'"{name}"' for name, _, _, _ in columns)
            primary_key = [name for name, _, _, position in columns if position]
            for column, declared_type, _, _ in columns:
                self.assertIn(declared_type, WRONG_TYPED_VALUES, f"{table}.{column}")
                # An INTEGER PRIMARY KEY is the rowid; SQLite itself refuses
                # any non-integer value before the CHECK runs.
                expected = (
                    "datatype mismatch"
                    if primary_key == [column] and declared_type == "INTEGER"
                    else rf"CHECK constraint failed: typeof\({column}\)"
                )
                # Copy an existing valid row and replace one column, so the
                # type check is the only constraint that can fail first.
                select_list = ", ".join(
                    "?" if name == column else f'"{name}"' for name, _, _, _ in columns
                )
                statement = (
                    f'INSERT INTO "{table}"({column_list}) '
                    f'SELECT {select_list} FROM "{table}" LIMIT 1'
                )
                for value in WRONG_TYPED_VALUES[declared_type]:
                    with self.assertRaisesRegex(
                        sqlite3.IntegrityError,
                        expected,
                        msg=f"{table}.{column} = {value!r}",
                    ):
                        connection.execute(statement, (value,))
            checked_tables.add(table)

        self.assertEqual(21, len(checked_tables))

    def test_nullable_columns_accept_null(self) -> None:
        connection = migrated_database()
        insert_row_in_every_table(connection)

        nullable_columns = []
        for table in table_names(connection):
            self.assertEqual(
                SCHEMA_VERSION if table == "schema_migrations" else 1,
                connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0],
                table,
            )
            for column, _, not_null, position in table_columns(connection, table):
                if not not_null and not position:
                    nullable_columns.append(f"{table}.{column}")
                    self.assertIsNone(
                        connection.execute(
                            f'SELECT "{column}" FROM "{table}"'
                        ).fetchone()[0],
                        f"{table}.{column}",
                    )

        self.assertEqual(
            [
                "artifact.evidence_id",
                "artifact.approval_id",
                "forge_repository.last_verified_at",
                "forge_repository.trust_floor",
                "forge_repository.pinned_consent_at",
                "installed_observation.reported_repository",
                "name_activation.ended_at",
                "release_record.commit_sha",
                "snapshot.signature_sha256",
                "source_policy.selected_native_source",
            ],
            nullable_columns,
        )

    def test_lossless_values_are_stored_in_the_declared_type(self) -> None:
        connection = migrated_database()
        connection.execute(
            """
            INSERT INTO forge_repository(
                id, forge, repository_id, owner_id, canonical_url, first_seen_at
            ) VALUES ('source-1', 'github', ?, 'owner-1', 'https://example.invalid/repository', '2026-10-18T00:00:00Z')
            """,
            (1001,),
        )
        connection.execute(
            """
            INSERT INTO package_family(id, source_id, name, purpose, revision)
            VALUES ('family-1', 'source-1', 'example', 'test', ?)
            """,
            ("2",),
        )

        self.assertEqual(
            ("1001", "text"),
            connection.execute(
                "SELECT repository_id, typeof(repository_id) FROM forge_repository"
            ).fetchone(),
        )
        self.assertEqual(
            (2, "integer"),
            connection.execute(
                "SELECT revision, typeof(revision) FROM package_family"
            ).fetchone(),
        )


class PinnedLevelTests(unittest.TestCase):
    """The Pinned level of ADR-018: consent, approval, and the ratchet."""

    def setUp(self) -> None:
        self.connection = migrated_database()
        insert_artifact_prerequisites(self.connection)
        self.connection.execute(
            """
            INSERT INTO release_record(
                id, source_id, forge_release_id, tag, published_at, channel
            ) VALUES ('release-2', 'source-1', '20', 'v2.0.0', '2026-10-19T00:00:00Z', 'stable')
            """
        )

    def artifact_row(self, artifact_id: str = "artifact-1") -> tuple:
        return self.connection.execute(
            "SELECT evidence_id, approval_id, state FROM artifact WHERE id = ?",
            (artifact_id,),
        ).fetchone()

    def test_pinned_is_not_a_kind_of_cryptographic_evidence(self) -> None:
        with self.assertRaisesRegex(sqlite3.IntegrityError, "evidence_type IN"):
            self.connection.execute(
                """
                INSERT INTO trust_evidence(
                    id, source_id, evidence_type, root_chain_json,
                    signer_identity, repository_id, subject_sha256,
                    predicate_type, verified_at, verifier_version, record_json
                ) VALUES (
                    'evidence-2', 'source-1', 'pinned', '[]', 'none', '1001',
                    ?, 'none', '2026-10-20T00:00:00Z', '0.0.0', '{}'
                )
                """,
                (OTHER_DIGEST,),
            )

    def test_approval_requires_consent_and_is_append_only(self) -> None:
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "pinned level requires consent"
        ):
            insert_release_approval(self.connection)

        set_pinned_consent(self.connection, True)
        insert_release_approval(self.connection)
        for statement in (
            f"UPDATE release_approval SET subject_sha256 = '{OTHER_DIGEST}' WHERE id = 'approval-1'",
            "UPDATE release_approval SET release_id = 'release-2' WHERE id = 'approval-1'",
            "DELETE FROM release_approval WHERE id = 'approval-1'",
        ):
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "release approval is append-only", msg=statement
            ):
                self.connection.execute(statement)

        set_pinned_consent(self.connection, False)
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "pinned level requires consent"
        ):
            insert_release_approval(self.connection, approval_id="approval-2")
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM release_approval"
            ).fetchone()[0],
        )

    def test_approved_artifact_is_admitted_through_every_serving_state(self) -> None:
        set_pinned_consent(self.connection, True)
        insert_release_approval(self.connection)

        insert_artifact(self.connection, state="held")
        self.connection.execute(
            "UPDATE artifact SET approval_id = 'approval-1', state = 'verified' "
            "WHERE id = 'artifact-1'"
        )
        for state in ("eligible", "published", "retired"):
            self.connection.execute(
                "UPDATE artifact SET state = ? WHERE id = 'artifact-1'", (state,)
            )
        self.assertEqual((None, "approval-1", "retired"), self.artifact_row())

    def test_approval_covers_only_its_own_bytes_release_and_source(self) -> None:
        insert_source(self.connection, source_id="source-2", repository_id="2002")
        self.connection.execute(
            """
            INSERT INTO release_record(
                id, source_id, forge_release_id, tag, published_at, channel
            ) VALUES ('release-3', 'source-2', '30', 'v1.0.0', '2026-10-19T00:00:00Z', 'stable')
            """
        )
        set_pinned_consent(self.connection, True)
        set_pinned_consent(self.connection, True, source_id="source-2")
        insert_release_approval(self.connection)
        insert_release_approval(
            self.connection,
            approval_id="approval-other-source",
            source_id="source-2",
            release_id="release-3",
        )

        cases = (
            # Same release, other bytes (a new asset uploaded after approval).
            {"artifact_id": "artifact-2", "sha256": OTHER_DIGEST, "approval_id": "approval-1"},
            # Same bytes in another release of the same source.
            {"artifact_id": "artifact-3", "release_id": "release-2", "approval_id": "approval-1"},
            # Same bytes approved for another source.
            {"artifact_id": "artifact-4", "approval_id": "approval-other-source"},
            # An approval that does not exist.
            {"artifact_id": "artifact-5", "approval_id": "approval-missing"},
        )
        for case in cases:
            with self.assertRaises(sqlite3.IntegrityError, msg=case):
                insert_artifact(self.connection, state="verified", **case)
            with self.assertRaises(sqlite3.IntegrityError, msg=case):
                insert_artifact(self.connection, state="held", **case)

        self.assertEqual(
            0, self.connection.execute("SELECT COUNT(*) FROM artifact").fetchone()[0]
        )

    def test_pinned_cannot_bypass_evidence_invariants(self) -> None:
        set_pinned_consent(self.connection, True)
        insert_release_approval(self.connection)

        # Never both evidence and an approval.
        with self.assertRaises(sqlite3.IntegrityError):
            insert_artifact(
                self.connection,
                evidence_id="evidence-1",
                approval_id="approval-1",
                state="verified",
            )

        # An attested artifact cannot gain an approval.
        insert_artifact(self.connection, evidence_id="evidence-1", state="verified")
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE artifact SET approval_id = 'approval-1' WHERE id = 'artifact-1'"
            )

        # A pinned artifact cannot drop, replace, or trade its approval.
        insert_release_approval(self.connection, approval_id="approval-2")
        insert_artifact(
            self.connection,
            artifact_id="artifact-2",
            approval_id="approval-1",
            state="verified",
        )
        for statement in (
            "UPDATE artifact SET approval_id = NULL, state = 'candidate' WHERE id = 'artifact-2'",
            "UPDATE artifact SET approval_id = 'approval-2' WHERE id = 'artifact-2'",
            "UPDATE artifact SET approval_id = NULL, evidence_id = 'evidence-1' WHERE id = 'artifact-2'",
            "UPDATE artifact SET evidence_id = 'evidence-1' WHERE id = 'artifact-2'",
        ):
            with self.assertRaises(sqlite3.IntegrityError, msg=statement):
                self.connection.execute(statement)
        self.assertEqual((None, "approval-1", "verified"), self.artifact_row("artifact-2"))

    def test_revoked_consent_blocks_attaching_an_earlier_approval(self) -> None:
        set_pinned_consent(self.connection, True)
        insert_release_approval(self.connection)
        insert_artifact(self.connection, state="held")
        set_pinned_consent(self.connection, False)

        for statement in (
            "UPDATE artifact SET approval_id = 'approval-1', state = 'verified' WHERE id = 'artifact-1'",
            "UPDATE artifact SET approval_id = 'approval-1' WHERE id = 'artifact-1'",
        ):
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "pinned level requires consent", msg=statement
            ):
                self.connection.execute(statement)
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "pinned level requires consent"
        ):
            insert_artifact(
                self.connection,
                artifact_id="artifact-2",
                approval_id="approval-1",
                state="verified",
            )
        self.assertEqual((None, None, "held"), self.artifact_row())

    def test_trust_floor_only_rises(self) -> None:
        def floor() -> str | None:
            return self.connection.execute(
                "SELECT trust_floor FROM forge_repository WHERE id = 'source-1'"
            ).fetchone()[0]

        with self.assertRaisesRegex(sqlite3.IntegrityError, "trust_floor IN"):
            self.connection.execute(
                "UPDATE forge_repository SET trust_floor = 'signed' WHERE id = 'source-1'"
            )

        for level in ("pinned", "pinned", "attested", "strict"):
            self.connection.execute(
                "UPDATE forge_repository SET trust_floor = ? WHERE id = 'source-1'",
                (level,),
            )
            self.assertEqual(level, floor())

        for level in ("attested", "pinned", None, "unknown"):
            with self.assertRaises(sqlite3.IntegrityError, msg=level):
                self.connection.execute(
                    "UPDATE forge_repository SET trust_floor = ? WHERE id = 'source-1'",
                    (level,),
                )
        self.assertEqual("strict", floor())

        # Consent does not touch the floor, and the floor does not need it.
        set_pinned_consent(self.connection, True)
        set_pinned_consent(self.connection, False)
        self.assertEqual("strict", floor())


class OwnerConfirmationTests(unittest.TestCase):
    """Migration 0002: the confirmed owner IDs of a source (R-003)."""

    def setUp(self) -> None:
        self.connection = migrated_database()
        insert_source(self.connection)

    def confirmations(self, source_id: str = "source-1") -> list[tuple[str, str]]:
        return self.connection.execute(
            "SELECT owner_id, kind FROM repository_owner_confirmation "
            "WHERE source_id = ? ORDER BY id",
            (source_id,),
        ).fetchall()

    def current_owner(self, source_id: str = "source-1") -> str:
        return self.connection.execute(
            "SELECT owner_id FROM forge_repository WHERE id = ?", (source_id,)
        ).fetchone()[0]

    def confirm(self, owner_id: str, kind: str = "transfer", source_id: str = "source-1") -> None:
        self.connection.execute(
            "INSERT INTO repository_owner_confirmation(source_id, owner_id, kind, confirmed_at) "
            "VALUES (?, ?, ?, '2026-10-22T06:10:00Z')",
            (source_id, owner_id, kind),
        )

    def test_adding_a_source_records_its_pinned_owner(self) -> None:
        self.assertEqual([("owner-1", "pinned")], self.confirmations())
        self.assertEqual(
            "2026-10-18T00:00:00Z",
            self.connection.execute(
                "SELECT confirmed_at FROM repository_owner_confirmation"
            ).fetchone()[0],
        )

    def test_a_confirmed_transfer_moves_the_owner_and_keeps_the_earlier_one(self) -> None:
        # R-003 step 4: kroxiksut (2264172) -> pchi-test-org (346117935).
        self.confirm("owner-2")
        self.assertEqual("owner-2", self.current_owner())
        self.assertEqual(
            [("owner-1", "pinned"), ("owner-2", "transfer")], self.confirmations()
        )
        # A move back is a transfer again and is recorded as one.
        self.confirm("owner-1")
        self.assertEqual("owner-1", self.current_owner())
        self.assertEqual(
            {"owner-1", "owner-2"},
            {owner for owner, _ in self.confirmations()},
        )
        self.assertEqual(3, len(self.confirmations()))

    def test_the_owner_never_changes_without_a_confirmation(self) -> None:
        with self.assertRaisesRegex(sqlite3.IntegrityError, "confirmed transfer"):
            self.connection.execute(
                "UPDATE forge_repository SET owner_id = 'owner-2' WHERE id = 'source-1'"
            )
        # An earlier confirmed owner is no shortcut either: the latest
        # confirmation names the current owner.
        self.confirm("owner-2")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "confirmed transfer"):
            self.connection.execute(
                "UPDATE forge_repository SET owner_id = 'owner-1' WHERE id = 'source-1'"
            )
        self.assertEqual("owner-2", self.current_owner())
        # Rewriting the same value is not a change.
        self.connection.execute(
            "UPDATE forge_repository SET owner_id = 'owner-2', state = 'active' "
            "WHERE id = 'source-1'"
        )

    def test_invalid_confirmations_are_refused_and_change_nothing(self) -> None:
        cases = (
            ("owner-1", "transfer", "source-1", "another owner"),
            ("owner-2", "pinned", "source-1", "pinned once"),
            # The trigger refuses before the foreign key is checked.
            ("owner-2", "transfer", "source-missing", "pinned source"),
            ("", "transfer", "source-1", "owner_id <> ''"),
            ("owner-2", "adopted", "source-1", "kind IN"),
        )
        for owner_id, kind, source_id, message in cases:
            with self.assertRaisesRegex(sqlite3.IntegrityError, message, msg=(owner_id, kind)):
                self.confirm(owner_id, kind, source_id)
        self.assertEqual([("owner-1", "pinned")], self.confirmations())
        self.assertEqual("owner-1", self.current_owner())

    def test_confirmations_are_append_only_and_keep_their_source(self) -> None:
        self.confirm("owner-2")
        for statement in (
            "UPDATE repository_owner_confirmation SET owner_id = 'owner-3'",
            "UPDATE repository_owner_confirmation SET confirmed_at = 'later'",
            "DELETE FROM repository_owner_confirmation",
            "DELETE FROM forge_repository WHERE id = 'source-1'",
        ):
            with self.assertRaises(sqlite3.IntegrityError, msg=statement):
                self.connection.execute(statement)
        self.assertEqual(2, len(self.confirmations()))

    def test_upgrading_from_0001_records_existing_owners(self) -> None:
        connection = migrated_database(migrations=(INITIAL_MIGRATION,))
        insert_source(connection)
        insert_source(connection, source_id="source-2", repository_id="1002")
        connection.execute(
            "UPDATE forge_repository SET owner_id = 'owner-9' WHERE id = 'source-2'"
        )
        apply_migrations(connection, (OWNER_MIGRATION,))
        apply_migrations(connection, (OWNER_MIGRATION,))
        self.assertEqual(
            [
                ("source-1", "owner-1", "pinned", "2026-10-18T00:00:00Z"),
                ("source-2", "owner-9", "pinned", "2026-10-18T00:00:00Z"),
            ],
            connection.execute(
                "SELECT source_id, owner_id, kind, confirmed_at "
                "FROM repository_owner_confirmation ORDER BY source_id"
            ).fetchall(),
        )
        self.assertEqual(
            2, connection.execute("PRAGMA user_version").fetchone()[0]
        )


class NameActivationTests(unittest.TestCase):
    """Migration 0003: the activation journal (ADR-022 point 3)."""

    def setUp(self) -> None:
        self.connection = migrated_database()
        insert_source(self.connection)
        insert_source(self.connection, source_id="source-2", repository_id="1002")

    def activate(self, source_id: str = "source-1", name: str = "sampleapp") -> None:
        self.connection.execute(
            "INSERT INTO name_activation(source_id, ecosystem, native_name, activated_at) "
            "VALUES (?, 'deb', ?, '2026-10-24T00:00:00Z')",
            (source_id, name),
        )

    def end(self, source_id: str = "source-1", name: str = "sampleapp") -> None:
        self.connection.execute(
            "UPDATE name_activation SET ended_at = '2026-10-25T00:00:00Z' "
            "WHERE source_id = ? AND native_name = ? AND ended_at IS NULL",
            (source_id, name),
        )

    def test_a_name_is_open_in_one_source_at_a_time(self) -> None:
        # Two 990 pins for one name would let the higher version decide.
        self.activate()
        for source_id in ("source-1", "source-2"):
            with self.assertRaises(sqlite3.IntegrityError, msg=source_id):
                self.activate(source_id)
        # The same name of the other ecosystem is another package.
        self.connection.execute(
            "INSERT INTO name_activation(source_id, ecosystem, native_name, activated_at) "
            "VALUES ('source-2', 'rpm', 'sampleapp', '2026-10-24T00:00:00Z')"
        )
        self.end()
        self.activate("source-2")
        self.assertEqual(
            [("source-1", 1), ("source-2", 0)],
            self.connection.execute(
                "SELECT source_id, ended_at IS NOT NULL FROM name_activation "
                "WHERE ecosystem = 'deb' ORDER BY id"
            ).fetchall(),
        )

    def test_an_activation_only_ends_once_and_is_never_rewritten(self) -> None:
        self.activate()
        for statement in (
            "UPDATE name_activation SET source_id = 'source-2'",
            "UPDATE name_activation SET native_name = 'other'",
            "UPDATE name_activation SET activated_at = '2020-01-01T00:00:00Z'",
            "DELETE FROM name_activation",
            "DELETE FROM forge_repository WHERE id = 'source-1'",
        ):
            with self.assertRaises(sqlite3.IntegrityError, msg=statement):
                self.connection.execute(statement)
        self.end()
        for statement in (
            "UPDATE name_activation SET ended_at = NULL",
            "UPDATE name_activation SET ended_at = '2027-01-01T00:00:00Z'",
        ):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "only ends, once", msg=statement):
                self.connection.execute(statement)

    def test_upgrading_from_0002_keeps_the_data(self) -> None:
        connection = migrated_database(migrations=(INITIAL_MIGRATION, OWNER_MIGRATION))
        insert_source(connection)
        apply_migrations(connection, (ACTIVATION_MIGRATION,))
        apply_migrations(connection, (ACTIVATION_MIGRATION,))
        self.assertEqual(3, connection.execute("PRAGMA user_version").fetchone()[0])
        self.assertEqual(
            1, connection.execute("SELECT COUNT(*) FROM forge_repository").fetchone()[0]
        )


class AttestedSignerTests(unittest.TestCase):
    """Migration 0004: the confirmed Attested signer (ADR-036 point 1)."""

    def setUp(self) -> None:
        self.connection = migrated_database()
        insert_source(self.connection)

    def confirm(self, workflow: str, signer_ref: str = "tag") -> None:
        self.connection.execute(
            "INSERT INTO attested_signer(source_id, workflow, signer_ref, confirmed_at) "
            "VALUES ('source-1', ?, ?, '2026-10-24T00:00:00Z')",
            (workflow, signer_ref),
        )

    def test_only_a_workflow_file_and_a_ref_rule_are_stored(self) -> None:
        self.confirm(".github/workflows/release.yml")
        self.confirm(".github/workflows/release.yaml", "refs/heads/main")
        for workflow, signer_ref in (
            (".github/workflows/", "tag"),
            (".github/workflows/a/b.yml", "tag"),
            (".github/workflows/release", "tag"),
            ("release.yml", "tag"),
            (".github/workflows/release.yml", "refs/tags/v1.0"),
            (".github/workflows/release.yml", "refs/heads/"),
            (".github/workflows/release.yml", "main"),
        ):
            with self.assertRaises(sqlite3.IntegrityError, msg=(workflow, signer_ref)):
                self.confirm(workflow, signer_ref)

    def test_a_confirmation_is_never_rewritten_or_removed(self) -> None:
        # Rewriting the signer in place would hide who could sign before.
        self.confirm(".github/workflows/release.yml")
        for statement in (
            "UPDATE attested_signer SET workflow = '.github/workflows/evil.yml'",
            "UPDATE attested_signer SET signer_ref = 'refs/heads/dev'",
            "DELETE FROM attested_signer",
            "DELETE FROM forge_repository WHERE id = 'source-1'",
        ):
            with self.assertRaises(sqlite3.IntegrityError, msg=statement):
                self.connection.execute(statement)

    def test_upgrading_from_0003_keeps_the_data(self) -> None:
        connection = migrated_database(migrations=MIGRATIONS[:3])
        insert_source(connection)
        apply_migrations(connection, (SIGNER_MIGRATION,))
        apply_migrations(connection, (SIGNER_MIGRATION,))
        self.assertEqual(4, connection.execute("PRAGMA user_version").fetchone()[0])
        self.assertEqual(
            0, connection.execute("SELECT COUNT(*) FROM attested_signer").fetchone()[0]
        )


class FamilyOutsiderTests(unittest.TestCase):
    """Migration 0005: names outside the family (ADR-036 point 3)."""

    def setUp(self) -> None:
        self.connection = migrated_database()
        insert_artifact_prerequisites(self.connection)

    def test_only_a_known_name_can_be_marked_and_the_mark_goes_with_it(self) -> None:
        # A mark for a name the family has no row for would point nowhere.
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO family_outsider(family_id, ecosystem, native_name) "
                "VALUES ('family-1', 'deb', 'unknown')"
            )
        self.connection.execute(
            "INSERT INTO family_outsider(family_id, ecosystem, native_name) "
            "VALUES ('family-1', 'deb', 'example')"
        )
        self.connection.execute("DELETE FROM package_identity WHERE native_name = 'example'")
        self.assertEqual(
            0, self.connection.execute("SELECT COUNT(*) FROM family_outsider").fetchone()[0]
        )

    def test_upgrading_from_0004_keeps_every_name_a_member(self) -> None:
        connection = migrated_database(migrations=MIGRATIONS[:4])
        insert_artifact_prerequisites(connection)
        apply_migrations(connection, (MEMBERSHIP_MIGRATION,))
        apply_migrations(connection, (MEMBERSHIP_MIGRATION,))
        self.assertEqual(
            SCHEMA_VERSION, connection.execute("PRAGMA user_version").fetchone()[0]
        )
        self.assertEqual(
            0, connection.execute("SELECT COUNT(*) FROM family_outsider").fetchone()[0]
        )


if __name__ == "__main__":
    unittest.main()
