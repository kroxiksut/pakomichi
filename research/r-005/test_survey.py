#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0

import io
import argparse
import csv
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import survey
import phase_b
import aggregate


class SurveyTests(unittest.TestCase):
    def test_github_client_retries_remote_disconnect(self):
        class Reply:
            status = 200
            headers = {"Content-Length": "2"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _maximum):
                return b"{}"

        with tempfile.TemporaryDirectory() as directory:
            client = survey.GitHubClient(Path(directory), token=None)
            with (
                mock.patch.object(
                    survey.urllib.request,
                    "urlopen",
                    side_effect=[survey.http.client.RemoteDisconnected("transient"), Reply()],
                ),
                mock.patch.object(survey.time, "sleep") as sleep,
            ):
                response = client._request("https://api.github.com/example", {})
        self.assertEqual(response.status, 200)
        sleep.assert_called_once_with(1)

    def test_attestation_404_is_a_completed_negative_observation(self):
        missing = subprocess.CompletedProcess(
            [], 1, "", "HTTP 404: Not Found (https://api.github.com/repos/a/b/attestations/sha256:abc)"
        )
        transport_failure = subprocess.CompletedProcess([], 1, "", "connection reset")
        self.assertTrue(phase_b.attestation_not_found(missing))
        self.assertFalse(phase_b.attestation_not_found(transport_failure))

    def test_rpm_signature_inspection_does_not_trust_an_unknown_key(self):
        completed = subprocess.CompletedProcess(
            [], 1, "package.rpm: Header OpenPGP V4 RSA/SHA256 signature: NOKEY", ""
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(phase_b, "run_completed", return_value=completed):
                state = phase_b.inspect_rpm_signature(root / "package.rpm", root, [])
        self.assertEqual(state, "present-untrusted")

    def test_claimed_level_precedence(self):
        self.assertEqual(
            survey.highest_claimed_level(
                immutable=True,
                has_attestation=True,
                digest_unknown=False,
                signatures=["SHA256SUMS.sig"],
                checksums=["SHA256SUMS"],
            ),
            "Strict-claimed",
        )
        self.assertEqual(
            survey.highest_claimed_level(
                immutable=False,
                has_attestation=True,
                digest_unknown=False,
                signatures=["x.asc"],
                checksums=[],
            ),
            "Attested-claimed",
        )
        self.assertEqual(
            survey.highest_claimed_level(
                immutable=False,
                has_attestation=False,
                digest_unknown=False,
                signatures=["x.asc"],
                checksums=[],
            ),
            "Signed-claimed",
        )
        self.assertEqual(
            survey.highest_claimed_level(
                immutable=False,
                has_attestation=False,
                digest_unknown=False,
                signatures=[],
                checksums=["SHA256SUMS"],
            ),
            "Checksums-only",
        )
        self.assertEqual(
            survey.highest_claimed_level(
                immutable=False,
                has_attestation=False,
                digest_unknown=True,
                signatures=["SHA256SUMS.asc"],
                checksums=["SHA256SUMS"],
            ),
            "Unknown-attestation",
        )

    def test_deb_get_parser_uses_only_relevant_files(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            self.add_file(
                archive,
                "deb-get-deadbeef/01-main/packages/example",
                'GITHUB_REPO="example/project"\nURL=https://github.com/second/tool/releases\n',
            )
            self.add_file(
                archive,
                "deb-get-deadbeef/unrelated.txt",
                "https://github.com/ignored/project\n",
            )
        parsed = survey.repositories_from_deb_get_tarball(stream.getvalue())
        self.assertEqual(set(parsed), {"example/project", "second/tool"})

    def test_phase_b_selection_is_deterministic_and_uses_latest_release(self):
        rows = [
            {"repository": "b/two", "repository_id": 2, "release_rank": 1},
            {"repository": "a/one", "repository_id": 1, "release_rank": 2},
            {"repository": "a/one", "repository_id": 1, "release_rank": 1},
        ]
        first = survey.deterministic_phase_b(rows, 2, "2026-10-20")
        second = survey.deterministic_phase_b(list(reversed(rows)), 2, "2026-10-20")
        self.assertEqual(first, second)
        self.assertTrue(all(row["release_rank"] == 1 for row in first))

    def test_phase_b_prefers_native_x86_64_asset_per_format(self):
        packages = [
            {"name": "app-aarch64.deb"},
            {"name": "app-amd64.deb"},
            {"name": "app-noarch.rpm"},
            {"name": "app-x86_64.rpm"},
        ]
        selected = phase_b.preferred_assets(packages)
        self.assertEqual([item["name"] for item in selected], ["app-amd64.deb", "app-x86_64.rpm"])

    def test_checksum_parser_binds_exact_asset_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            checksums = Path(directory) / "SHA256SUMS"
            checksums.write_text("a" * 64 + "  nested/app.deb\n" + "b" * 64 + "  other.deb\n", encoding="utf-8")
            self.assertEqual(phase_b.checksum_for_asset(checksums, "app.deb"), "a" * 64)
            self.assertIsNone(phase_b.checksum_for_asset(checksums, "missing.deb"))

    def test_url_validation_rejects_loopback(self):
        with self.assertRaisesRegex(RuntimeError, "non-global address"):
            phase_b.validate_url("https://127.0.0.1/private")

    def test_wsl_synthetic_dns_opt_in_does_not_allow_loopback(self):
        previous = os.environ.get("PAKOMICHI_WSL_SYNTHETIC_DNS")
        os.environ["PAKOMICHI_WSL_SYNTHETIC_DNS"] = "1"
        try:
            with self.assertRaisesRegex(RuntimeError, "non-global address"):
                phase_b.validate_url("https://127.0.0.1/private")
        finally:
            if previous is None:
                os.environ.pop("PAKOMICHI_WSL_SYNTHETIC_DNS", None)
            else:
                os.environ["PAKOMICHI_WSL_SYNTHETIC_DNS"] = previous

    def test_regression_does_not_rank_unknown_attestation(self):
        self.assertEqual(aggregate.transition("Attested-claimed", "Signed-claimed"), "regression")
        self.assertEqual(aggregate.transition("Unknown-attestation", "Nothing-observed"), "unknown")

    def test_pinned_coverage_is_explicitly_theoretical(self):
        result = aggregate.coverage(["Nothing-observed", "Signed-claimed"], verified=False)
        self.assertEqual(result["with_pinned_theoretical_eligibility"]["percent"], 100.0)
        self.assertIn("eligibility only", result["with_pinned_theoretical_eligibility"]["qualification"])

    def test_protocol_pass_requires_twenty_fully_verified_repositories(self):
        phase_a = []
        phase_b = []
        for index in range(100):
            phase_a.append(
                {
                    "repository": f"owner/repo-{index}",
                    "repository_id": str(index),
                    "selection_sources": "deb-get" if index < 50 else "github-search",
                    "release_rank": "1",
                    "tag": "v1",
                    "claimed_level": "Nothing-observed",
                }
            )
        for index in range(20):
            phase_b.append(
                {
                    "repository": f"owner/repo-{index}",
                    "exit_code": "1",
                    "verified_level": "Unverified",
                }
            )
        _, _, summary = aggregate.aggregate(phase_a, phase_b)
        self.assertEqual(summary["phase_b_repository_count"], 20)
        self.assertEqual(summary["phase_b_fully_verified_repository_count"], 0)
        self.assertEqual(summary["protocol_status"], "INCONCLUSIVE")

    def test_failure_details_stay_in_ignored_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.tsv"
            results = root / "results.tsv"
            row = {field: "" for field in phase_b.PLAN_FIELDS}
            row.update(
                {
                    "repository": "example/project",
                    "repository_id": "1",
                    "tag": "v1",
                    "asset_name": "app.deb",
                    "method": "unresolved",
                }
            )
            phase_b.write_tsv(plan, phase_b.PLAN_FIELDS, [row])
            status = phase_b.verify(
                argparse.Namespace(
                    plan=plan,
                    downloads=root / "downloads",
                    run_dir=root / "raw",
                    results=results,
                    token_file=None,
                )
            )
            self.assertEqual(status, 2)
            with results.open(encoding="utf-8", newline="") as stream:
                result = next(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(result["failure_reason"], "plan-or-verification-error")
            self.assertNotIn("unresolved rows", result["log"])
            self.assertIn("unresolved rows", (root / "raw" / result["log"]).read_text(encoding="utf-8"))

    @staticmethod
    def add_file(archive, name, text):
        payload = text.encode("utf-8")
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))


if __name__ == "__main__":
    unittest.main()
