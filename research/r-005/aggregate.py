#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Aggregate R-005 claimed and verified evidence without overstating coverage."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


CLAIMED_RANK = {
    "Nothing-observed": 0,
    "Checksums-only": 1,
    "Signed-claimed": 2,
    "Attested-claimed": 3,
    "Strict-claimed": 4,
}
VERIFIED_RANK = {
    "Nothing-observed": 0,
    "Checksums-only": 1,
    "Signed": 2,
    "Attested": 3,
    "Strict": 4,
}
REPOSITORY_FIELDS = [
    "repository", "repository_id", "selection_sources", "releases_checked",
    "tags_oldest_to_newest", "claimed_levels_oldest_to_newest",
    "latest_claimed_level", "phase_b_status", "verified_level",
]
REGRESSION_FIELDS = [
    "repository", "older_tag", "older_level", "newer_tag", "newer_level", "transition",
]


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def write_tsv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in fieldnames})
    atomic_write(path, stream.getvalue())


def percentage(numerator: int, denominator: int) -> float | None:
    return round(numerator * 100 / denominator, 1) if denominator else None


def count_levels(levels: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(levels).items()))


def transition(older: str, newer: str) -> str:
    if older not in CLAIMED_RANK or newer not in CLAIMED_RANK:
        return "unknown"
    delta = CLAIMED_RANK[newer] - CLAIMED_RANK[older]
    if delta < 0:
        return "regression"
    if delta > 0:
        return "improvement"
    return "stable"


def coverage(levels: list[str], *, verified: bool) -> dict[str, Any]:
    strict = "Strict" if verified else "Strict-claimed"
    attested = "Attested" if verified else "Attested-claimed"
    signed = "Signed" if verified else "Signed-claimed"
    denominator = len(levels)
    strict_attested = sum(level in {strict, attested} for level in levels)
    with_signed = sum(level in {strict, attested, signed} for level in levels)
    return {
        "denominator_repositories": denominator,
        "strict_plus_attested": {
            "repositories": strict_attested,
            "percent": percentage(strict_attested, denominator),
        },
        "strict_plus_attested_plus_signed": {
            "repositories": with_signed,
            "percent": percentage(with_signed, denominator),
        },
        "with_pinned_theoretical_eligibility": {
            "repositories": denominator,
            "percent": percentage(denominator, denominator),
            "qualification": "eligibility only; quarantine behavior was not measured by R-005",
        },
    }


def aggregate(phase_a: list[dict[str, str]], phase_b: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    by_repository: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in phase_a:
        by_repository[row["repository"]].append(row)
    verification_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in phase_b:
        verification_rows[row["repository"]].append(row)

    repositories: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    for name in sorted(by_repository, key=str.casefold):
        newest_first = sorted(by_repository[name], key=lambda item: int(item["release_rank"]))
        oldest_first = list(reversed(newest_first))
        for older, newer in zip(oldest_first, oldest_first[1:]):
            regressions.append({
                "repository": name,
                "older_tag": older["tag"], "older_level": older["claimed_level"],
                "newer_tag": newer["tag"], "newer_level": newer["claimed_level"],
                "transition": transition(older["claimed_level"], newer["claimed_level"]),
            })

        checks = verification_rows.get(name, [])
        successful = [
            row for row in checks
            if row.get("exit_code") == "0" and row.get("verified_level") in VERIFIED_RANK
        ]
        if not checks:
            phase_b_status, verified_level = "not-sampled", ""
        elif len(successful) == len(checks):
            phase_b_status = "fully-verified"
            verified_level = max((row["verified_level"] for row in successful), key=VERIFIED_RANK.__getitem__)
        elif successful:
            phase_b_status = "partial"
            verified_level = max((row["verified_level"] for row in successful), key=VERIFIED_RANK.__getitem__)
        else:
            phase_b_status, verified_level = "failed", "Unverified"

        latest = newest_first[0]
        repositories.append({
            "repository": name,
            "repository_id": latest["repository_id"],
            "selection_sources": latest["selection_sources"],
            "releases_checked": len(newest_first),
            "tags_oldest_to_newest": json.dumps([row["tag"] for row in oldest_first], ensure_ascii=False),
            "claimed_levels_oldest_to_newest": json.dumps(
                [row["claimed_level"] for row in oldest_first], ensure_ascii=False
            ),
            "latest_claimed_level": latest["claimed_level"],
            "phase_b_status": phase_b_status,
            "verified_level": verified_level,
        })

    latest_claimed = [row["latest_claimed_level"] for row in repositories]
    verified = [row["verified_level"] for row in repositories if row["phase_b_status"] == "fully-verified"]
    sources = sorted({
        source for row in repositories for source in row["selection_sources"].split(";") if source
    })
    phase_b_repositories = sum(row["phase_b_status"] != "not-sampled" for row in repositories)
    summary = {
        "protocol_status": (
            "PASS" if len(repositories) >= 100 and len(sources) >= 2 and len(verified) >= 20
            else "INCONCLUSIVE"
        ),
        "repository_count": len(repositories),
        "source_types": sources,
        "phase_b_repository_count": phase_b_repositories,
        "phase_b_fully_verified_repository_count": len(verified),
        "claimed_latest_counts": count_levels(latest_claimed),
        "verified_counts": count_levels(verified),
        "transition_counts": count_levels(row["transition"] for row in regressions),
        "claimed_coverage": coverage(latest_claimed, verified=False),
        "verified_subset_coverage": coverage(verified, verified=True),
        "limitations": [
            "Phase A names evidence but does not prove signatures or attestations.",
            "Phase B is a deterministic subset; verified percentages are not whole-sample estimates.",
            "Pinned is theoretical eligibility only; R-005 does not observe a quarantine period or mutation response.",
            "Unknown-attestation is not ranked for regression because a missing API digest prevents the attestation query.",
        ],
    }
    return repositories, regressions, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase-a", type=Path, required=True)
    parser.add_argument("--phase-b", type=Path)
    parser.add_argument("--repositories", type=Path, required=True)
    parser.add_argument("--regressions", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    phase_b = read_tsv(args.phase_b) if args.phase_b and args.phase_b.exists() else []
    repositories, regressions, summary = aggregate(read_tsv(args.phase_a), phase_b)
    write_tsv(args.repositories, REPOSITORY_FIELDS, repositories)
    write_tsv(args.regressions, REGRESSION_FIELDS, regressions)
    atomic_write(args.summary, json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(
        f"aggregated {summary['repository_count']} repositories; "
        f"phase_b={summary['phase_b_repository_count']}; status={summary['protocol_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
