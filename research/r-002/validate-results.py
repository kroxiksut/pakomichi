#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validate the sanitized R-002 evidence before writing the report."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


CELLS = {
    "signed-valid-required",
    "unsigned-valid-required",
    "attested-explicit-permitted",
    "attested-required-policy",
    "unconfirmed-refused-before-dnf",
    "corrupted-rpm",
    "invalid-repomd-signature",
    "rpm-replaced-after-metadata",
    "global-gpgcheck-disable-refused",
    "metadata-key-a-baseline",
    "metadata-key-b-before-trust",
    "metadata-key-b-after-trust",
}


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--platform", action="append", required=True)
    args = parser.parse_args()

    fixtures = {row["fixture"]: row for row in rows(args.results / "fixture-manifest.tsv")}
    require(fixtures["signed.rpm"]["payload_digest"] == fixtures["unsigned.rpm"]["payload_digest"],
            "signed and unsigned fixtures do not have identical payloads")
    require(fixtures["attested.rpm"]["sha256"] != fixtures["unconfirmed.rpm"]["sha256"],
            "unconfirmed fixture accidentally matches the attested digest")
    require(all(row["scriptlets"] == "none" for row in fixtures.values()), "a fixture contains scriptlets")
    require(all(row["matches_signed_fixture"] == "true" for row in rows(args.results / "metadata-signer-invariance.tsv")),
            "metadata signing changed an RPM")
    recovery = rows(args.results / "key-recovery.tsv")
    require(len(recovery) == 1 and recovery[0]["verdict"] == "PASS", "metadata key recovery failed")

    for platform in args.platform:
        matrix_path = args.results / f"{platform}.tsv"
        matrix = rows(matrix_path)
        require({row["cell"] for row in matrix} == CELLS, f"{platform}: incomplete or extra matrix cells")
        require(all(row["verdict"] == "PASS" for row in matrix), f"{platform}: matrix contains failures")
        required_unsigned = next(row for row in matrix if row["cell"] == "unsigned-valid-required")
        required_attested = next(row for row in matrix if row["cell"] == "attested-required-policy")
        require(required_unsigned["actual"] == "block" and required_attested["actual"] == "block",
                f"{platform}: mandatory policy accepted an unsigned RPM")
        require(any(row["setting"] == "%_pkgverify_level" for row in rows(args.results / f"{platform}-effective-config.tsv")),
                f"{platform}: RPM verification policy was not recorded")

    for path in args.results.iterdir():
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            require("/mnt/" not in text and "C:\\Users\\" not in text and "D:\\Projects\\" not in text,
                    f"unsanitized absolute path in {path.name}")
    print(f"PASS: validated R-002 results for {', '.join(args.platform)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
