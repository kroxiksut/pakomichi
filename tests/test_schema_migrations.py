# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INITIAL_MIGRATION = PROJECT_ROOT / "migrations" / "0001_initial.sql"
ZERO_DIGEST = "0" * 64


def migrated_database(path: str = ":memory:") -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(INITIAL_MIGRATION.read_text(encoding="utf-8"))
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
) -> None:
    connection.execute(
        """
        INSERT INTO artifact(
            id, source_id, release_id, asset_id, family_id, ecosystem,
            native_name, native_version, architecture, filename, sha256,
            byte_size, evidence_id, state
        ) VALUES (?, 'source-1', 'release-1', ?, 'family-1', 'deb', 'example',
                  '1.0.0', 'amd64', 'example_1.0.0_amd64.deb', ?, 1, ?, ?)
        """,
        (artifact_id, f"asset-{artifact_id}", sha256, evidence_id, state),
    )


class InitialMigrationTests(unittest.TestCase):
    def test_creates_expected_schema_and_version(self) -> None:
        connection = migrated_database()
        expected_tables = {
            "admin_operation",
            "artifact",
            "artifact_cache",
            "decision_log",
            "forge_repository",
            "installed_observation",
            "os_inventory",
            "package_family",
            "package_identity",
            "release_record",
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
        self.assertEqual(1, connection.execute("PRAGMA user_version").fetchone()[0])
        self.assertEqual(
            (1, "initial"),
            connection.execute(
                "SELECT version, name FROM schema_migrations"
            ).fetchone(),
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

        self.assertEqual("registered", source_state)
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
        migration_sql = INITIAL_MIGRATION.read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_path = root / "source.sqlite3"
            backup_path = root / "backup.sqlite3"
            restored_path = root / "restored.sqlite3"

            source = migrated_database(str(source_path))
            insert_source(source)
            source.commit()
            source.executescript(migration_sql)
            self.assertEqual(
                1,
                source.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0],
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
                1,
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

if __name__ == "__main__":
    unittest.main()
