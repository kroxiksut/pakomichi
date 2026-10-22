#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validate sanitized R-005 evidence and protocol acceptance invariants."""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


LOCAL_OR_SECRET = re.compile(r"github_pat_|authorization:|[A-Z]:\\|/mnt/[a-z]/", re.I)


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    root = args.results

    candidates = read_tsv(root / "candidates.tsv")
    phase_a = read_tsv(root / "phase-a.tsv")
    sample = read_tsv(root / "phase-b-sample.tsv")
    plan = read_tsv(root / "phase-b-plan.tsv")
    phase_b = read_tsv(root / "phase-b.tsv")
    repositories = read_tsv(root / "repositories.tsv")
    aggregate = json.loads((root / "aggregate.json").read_text(encoding="utf-8"))

    candidate_names = {row["repository"] for row in candidates}
    sources = {
        source
        for row in candidates
        for source in row["selection_sources"].split(";")
        if source
    }
    require(len(candidates) == len(candidate_names) == 100, "expected 100 unique candidates")
    require(sources == {"deb-get", "github-search"}, f"unexpected source set: {sources}")
    require(len({row["repository"] for row in phase_a}) == 100, "Phase A does not cover 100 repositories")
    require(len(sample) == 20, "Phase B sample must contain 20 repositories")
    require(len({row["repository"] for row in sample}) == 20, "Phase B sample contains duplicate repositories")
    require(len(plan) == len(phase_b) == 30, "Phase B plan/results must contain 30 asset rows")
    require(all(row["method"] != "unresolved" for row in plan), "Phase B plan contains unresolved rows")

    identity = lambda row: (row["repository"], row["tag"], row["asset_name"])
    require({identity(row) for row in plan} == {identity(row) for row in phase_b}, "Phase B results differ from plan")
    require(all(row["exit_code"] == "0" for row in phase_b), "Phase B contains verifier or plan failures")
    require(len({row["repository"] for row in phase_b}) == 20, "Phase B results do not cover 20 repositories")
    rpm_rows = [row for row in phase_b if row["asset_name"].casefold().endswith(".rpm")]
    require(len(rpm_rows) == 10, "expected 10 selected RPM rows")
    require(
        all(row["rpm_signature_state"] not in {"", "not-rpm", "not-checked"} for row in rpm_rows),
        "an RPM row lacks rpmkeys inspection",
    )

    require(len(repositories) == 100, "repository aggregate must contain 100 rows")
    require(aggregate["protocol_status"] == "PASS", "aggregate protocol status is not PASS")
    require(aggregate["phase_b_repository_count"] == 20, "aggregate Phase B count is not 20")
    require(aggregate["phase_b_fully_verified_repository_count"] == 20, "not all sampled repositories were classified")

    for path in root.iterdir():
        if path.is_file() and path.suffix in {".tsv", ".json"}:
            require(not LOCAL_OR_SECRET.search(path.read_text(encoding="utf-8")), f"local path or secret marker in {path}")

    print("PASS: validated R-005 results for 100 repositories and 20 Phase B repositories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
