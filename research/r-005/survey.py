#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Collect reproducible, read-only GitHub provenance evidence for R-005."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import http.client
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


API_VERSION = "2026-03-10"
USER_AGENT = "Pakomichi-R-005-research"
DEB_GET_REPOSITORY = "wimpysworld/deb-get"
SEARCH_QUERIES = (
    "topic:linux stars:>=100 archived:false fork:false",
    "topic:cli stars:>=100 archived:false fork:false",
    "topic:desktop stars:>=100 archived:false fork:false",
)
PACKAGE_SUFFIXES = (".deb", ".rpm")
SIGNATURE_PATTERNS = (
    re.compile(r"\.sig$", re.I),
    re.compile(r"\.pem$", re.I),
    re.compile(r"\.bundle$", re.I),
    re.compile(r"\.sigstore\.json$", re.I),
    re.compile(r"\.asc$", re.I),
    re.compile(r"\.minisig$", re.I),
)
CHECKSUM_PATTERNS = (
    re.compile(r"^sha256sums", re.I),
    re.compile(r"^checksums.*\.txt$", re.I),
)
GITHUB_URL = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.I,
)
GITHUB_REPO_ASSIGNMENT = re.compile(
    r"(?:GITHUB_REPO|GITHUB_PROJECT|REPO)\s*=\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)",
    re.I,
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(data, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def write_tsv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name, "") for name in fieldnames})
    atomic_write(path, stream.getvalue())


def load_token(token_file: Path | None) -> str | None:
    for name in ("PAKOMICHI_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    if token_file is None or not token_file.exists():
        return None
    is_wsl_drvfs = sys.platform == "linux" and str(token_file.resolve()).startswith("/mnt/")
    if os.name != "nt" and not is_wsl_drvfs and token_file.stat().st_mode & 0o077:
        raise RuntimeError(f"token file permissions are too broad: {token_file}")
    value = token_file.read_text(encoding="utf-8").strip()
    return value or None


@dataclass
class Response:
    status: int
    body: bytes
    headers: dict[str, str]


class GitHubClient:
    def __init__(self, raw_dir: Path, token: str | None) -> None:
        self.raw_dir = raw_dir
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.token = token

    def _cache_paths(self, url: str) -> tuple[Path, Path]:
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.raw_dir / f"{key}.json", self.raw_dir / f"{key}.meta.json"

    def get_json(self, url: str, *, allow_not_found: bool = False) -> Any | None:
        if not url.startswith("https://api.github.com/"):
            raise ValueError(f"refusing non-GitHub API URL: {url}")
        body_path, meta_path = self._cache_paths(url)
        meta: dict[str, Any] = {}
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if meta.get("etag") and body_path.exists():
            headers["If-None-Match"] = str(meta["etag"])

        response = self._request(url, headers, allow_not_found=allow_not_found)
        if response.status == 304:
            return json.loads(body_path.read_text(encoding="utf-8"))
        if response.status == 404 and allow_not_found:
            return None

        parsed = json.loads(response.body.decode("utf-8"))
        atomic_write(body_path, json.dumps(parsed, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        public_meta = {
            "url": url,
            "fetched_at": utc_now(),
            "status": response.status,
            "etag": response.headers.get("etag"),
            "x-ratelimit-limit": response.headers.get("x-ratelimit-limit"),
            "x-ratelimit-remaining": response.headers.get("x-ratelimit-remaining"),
            "x-ratelimit-reset": response.headers.get("x-ratelimit-reset"),
            "x-ratelimit-resource": response.headers.get("x-ratelimit-resource"),
        }
        atomic_write(meta_path, json.dumps(public_meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        return parsed

    def get_bytes(self, url: str, *, maximum: int = 50 * 1024 * 1024) -> Response:
        if not url.startswith("https://codeload.github.com/"):
            raise ValueError(f"refusing non-codeload URL: {url}")
        return self._request(url, {"User-Agent": USER_AGENT}, maximum=maximum)

    def _request(
        self,
        url: str,
        headers: dict[str, str],
        *,
        allow_not_found: bool = False,
        maximum: int = 10 * 1024 * 1024,
    ) -> Response:
        for attempt in range(6):
            request = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(request, timeout=45) as reply:
                    length = int(reply.headers.get("Content-Length", "0") or 0)
                    if length > maximum:
                        raise RuntimeError(f"response too large ({length} bytes): {url}")
                    body = reply.read(maximum + 1)
                    if len(body) > maximum:
                        raise RuntimeError(f"response exceeded {maximum} bytes: {url}")
                    return Response(reply.status, body, {key.lower(): value for key, value in reply.headers.items()})
            except urllib.error.HTTPError as error:
                response_headers = {key.lower(): value for key, value in error.headers.items()}
                if error.code == 304:
                    return Response(304, b"", response_headers)
                if error.code == 404 and allow_not_found:
                    return Response(404, error.read(), response_headers)
                if error.code not in (403, 429) or attempt == 5:
                    detail = error.read(4096).decode("utf-8", "replace")
                    raise RuntimeError(f"GitHub request failed ({error.code}) for {url}: {detail}") from error
                delay = retry_delay(response_headers, attempt)
                print(f"rate limited; retrying in {delay}s", file=sys.stderr)
                time.sleep(delay)
            except (urllib.error.URLError, http.client.HTTPException) as error:
                if attempt == 5:
                    raise RuntimeError(f"GitHub request failed for {url}: {error}") from error
                time.sleep(min(2**attempt, 30))
        raise AssertionError("unreachable")


def retry_delay(headers: dict[str, str], attempt: int) -> int:
    if headers.get("retry-after", "").isdigit():
        return min(max(int(headers["retry-after"]), 1), 300)
    if headers.get("x-ratelimit-remaining") == "0" and headers.get("x-ratelimit-reset", "").isdigit():
        return min(max(int(headers["x-ratelimit-reset"]) - int(time.time()) + 2, 1), 300)
    return min(2 ** (attempt + 1), 60)


@dataclass
class Candidate:
    repository: str
    sources: set[str] = field(default_factory=set)
    source_details: set[str] = field(default_factory=set)

    def add(self, source: str, detail: str) -> None:
        self.sources.add(source)
        self.source_details.add(detail)


def normalize_repository(owner: str, repository: str) -> str | None:
    repository = repository.rstrip("/.,;:'\"")
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not owner or not repository or "$" in owner or "$" in repository:
        return None
    return f"{owner}/{repository}"


def repositories_from_deb_get_tarball(payload: bytes) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive.getmembers():
            normalized = member.name.replace("\\", "/")
            if not member.isfile() or member.size > 2 * 1024 * 1024:
                continue
            if "/01-main/" not in normalized and not normalized.endswith("/deb-get"):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", "replace")
            found: set[str] = set()
            for owner, repository in GITHUB_URL.findall(text):
                value = normalize_repository(owner, repository)
                if value:
                    found.add(value)
            for owner_repo in GITHUB_REPO_ASSIGNMENT.findall(text):
                owner, repository = owner_repo.split("/", 1)
                value = normalize_repository(owner, repository)
                if value:
                    found.add(value)
            for repository in found:
                if repository.casefold() == DEB_GET_REPOSITORY.casefold():
                    continue
                result.setdefault(repository, set()).add(normalized)
    return result


def fetch_deb_get_candidates(client: GitHubClient, raw_dir: Path) -> tuple[str, dict[str, set[str]]]:
    commit = client.get_json(f"https://api.github.com/repos/{DEB_GET_REPOSITORY}/commits/main")
    if not isinstance(commit, dict) or not isinstance(commit.get("sha"), str):
        raise RuntimeError("deb-get commit response has no sha")
    sha = commit["sha"]
    url = f"https://codeload.github.com/{DEB_GET_REPOSITORY}/tar.gz/{sha}"
    response = client.get_bytes(url)
    tarball_path = raw_dir / f"deb-get-{sha}.tar.gz"
    tarball_path.write_bytes(response.body)
    digest = hashlib.sha256(response.body).hexdigest()
    atomic_write(
        raw_dir / "deb-get-source.json",
        json.dumps(
            {"repository": DEB_GET_REPOSITORY, "commit": sha, "sha256": digest, "fetched_at": utc_now()},
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    return sha, repositories_from_deb_get_tarball(response.body)


def fetch_search_candidates(client: GitHubClient, pages_per_query: int) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for query in SEARCH_QUERIES:
        for page in range(1, pages_per_query + 1):
            parameters = urllib.parse.urlencode(
                {"q": query, "sort": "stars", "order": "desc", "per_page": 100, "page": page}
            )
            response = client.get_json(f"https://api.github.com/search/repositories?{parameters}")
            items = response.get("items", []) if isinstance(response, dict) else []
            if not items:
                break
            for item in items:
                repository = item.get("full_name")
                if isinstance(repository, str) and repository not in seen:
                    seen.add(repository)
                    result.append((repository, f"{query};page={page}"))
    return result


def package_assets(release: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        asset
        for asset in release.get("assets", [])
        if isinstance(asset, dict)
        and isinstance(asset.get("name"), str)
        and asset["name"].casefold().endswith(PACKAGE_SUFFIXES)
    ]


def named_assets(release: dict[str, Any], patterns: tuple[re.Pattern[str], ...]) -> list[str]:
    names = [asset.get("name", "") for asset in release.get("assets", []) if isinstance(asset, dict)]
    return sorted({name for name in names if isinstance(name, str) and any(p.search(name) for p in patterns)})


def named_asset_details(release: dict[str, Any], patterns: tuple[re.Pattern[str], ...]) -> list[dict[str, Any]]:
    details = []
    for asset in release.get("assets", []):
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            continue
        if any(pattern.search(asset["name"]) for pattern in patterns):
            details.append(
                {
                    "name": asset["name"],
                    "size": asset.get("size"),
                    "digest": asset.get("digest"),
                    "browser_download_url": asset.get("browser_download_url"),
                }
            )
    return sorted(details, key=lambda item: item["name"].casefold())


def highest_claimed_level(
    *,
    immutable: bool,
    has_attestation: bool,
    digest_unknown: bool,
    signatures: list[str],
    checksums: list[str],
) -> str:
    if immutable:
        return "Strict-claimed"
    if has_attestation:
        return "Attested-claimed"
    # Artifact attestations cannot be queried without the subject digest. A
    # signature/checksum name is still recorded as a lower bound, but it must
    # not turn the unknown higher level into a false negative.
    if digest_unknown:
        return "Unknown-attestation"
    return observed_lower_bound(signatures=signatures, checksums=checksums)


def observed_lower_bound(*, signatures: list[str], checksums: list[str]) -> str:
    if signatures:
        return "Signed-claimed"
    if checksums:
        return "Checksums-only"
    return "Nothing-observed"


def inspect_repository(client: GitHubClient, candidate: Candidate) -> tuple[dict[str, Any] | None, list[dict[str, Any]], str | None]:
    repository = candidate.repository
    metadata = client.get_json(f"https://api.github.com/repos/{repository}", allow_not_found=True)
    if metadata is None:
        return None, [], "repository-not-found"
    if metadata.get("fork"):
        return metadata, [], "fork"
    if metadata.get("archived"):
        return metadata, [], "archived"

    releases = client.get_json(f"https://api.github.com/repos/{repository}/releases?per_page=30&page=1")
    stable = [
        release
        for release in releases
        if isinstance(release, dict) and not release.get("draft") and not release.get("prerelease")
    ]
    relevant = [release for release in stable if package_assets(release)][:3]
    if not relevant:
        return metadata, [], "no-deb-or-rpm-in-30-recent-releases"

    rows: list[dict[str, Any]] = []
    for release_index, release in enumerate(relevant, start=1):
        packages = package_assets(release)
        signatures = named_assets(release, SIGNATURE_PATTERNS)
        checksums = named_assets(release, CHECKSUM_PATTERNS)
        signature_details = named_asset_details(release, SIGNATURE_PATTERNS)
        checksum_details = named_asset_details(release, CHECKSUM_PATTERNS)
        attestations_found = False
        digest_unknown = False
        package_details: list[dict[str, Any]] = []
        for asset in packages:
            digest = asset.get("digest")
            attestation_count: int | None = None
            if isinstance(digest, str) and digest.startswith("sha256:"):
                encoded = urllib.parse.quote(digest, safe=":")
                response = client.get_json(
                    f"https://api.github.com/repos/{repository}/attestations/{encoded}", allow_not_found=True
                )
                if response is None:
                    attestation_count = 0
                else:
                    attestations = response.get("attestations", []) if isinstance(response, dict) else []
                    attestation_count = len(attestations)
                    attestations_found = attestations_found or attestation_count > 0
            else:
                digest_unknown = True
            package_details.append(
                {
                    "name": asset.get("name"),
                    "size": asset.get("size"),
                    "digest": digest,
                    "browser_download_url": asset.get("browser_download_url"),
                    "attestation_count": attestation_count,
                }
            )

        immutable = bool(release.get("immutable"))
        rows.append(
            {
                "repository": repository,
                "repository_id": metadata.get("id"),
                "selection_sources": ";".join(sorted(candidate.sources)),
                "release_rank": release_index,
                "tag": release.get("tag_name"),
                "release_id": release.get("id"),
                "published_at": release.get("published_at"),
                "immutable": str(immutable).lower(),
                "packages": json.dumps(package_details, ensure_ascii=False, separators=(",", ":")),
                "signature_assets": ";".join(signatures),
                "checksum_assets": ";".join(checksums),
                "signature_asset_details": json.dumps(
                    signature_details, ensure_ascii=False, separators=(",", ":")
                ),
                "checksum_asset_details": json.dumps(
                    checksum_details, ensure_ascii=False, separators=(",", ":")
                ),
                "artifact_attestation_observed": str(attestations_found).lower(),
                "digest_unknown": str(digest_unknown).lower(),
                "observed_lower_bound": observed_lower_bound(signatures=signatures, checksums=checksums),
                "claimed_level": highest_claimed_level(
                    immutable=immutable,
                    has_attestation=attestations_found,
                    digest_unknown=digest_unknown,
                    signatures=signatures,
                    checksums=checksums,
                ),
            }
        )
    return metadata, rows, None


def deterministic_phase_b(rows: list[dict[str, Any]], size: int, selected_at: str) -> list[dict[str, Any]]:
    latest = [row for row in rows if row["release_rank"] == 1]
    ordered = sorted(
        latest,
        key=lambda row: hashlib.sha256(
            f"{selected_at}|{row['repository_id']}|{row['repository']}".encode("utf-8")
        ).hexdigest(),
    )
    return ordered[:size]


def collect(args: argparse.Namespace) -> int:
    token = load_token(args.token_file)
    if not token and not args.allow_unauthenticated:
        raise RuntimeError(
            "no GitHub token: set PAKOMICHI_GITHUB_TOKEN or provide --token-file; "
            "use --allow-unauthenticated only for a small dry run"
        )

    selected_at = utc_now()
    client = GitHubClient(args.raw_dir, token)
    deb_get_commit, deb_get = fetch_deb_get_candidates(client, args.raw_dir)
    search = fetch_search_candidates(client, args.search_pages)

    candidates: dict[str, Candidate] = {}
    for repository, files in sorted(deb_get.items(), key=lambda item: item[0].casefold()):
        candidate = candidates.setdefault(repository, Candidate(repository))
        for filename in sorted(files):
            candidate.add("deb-get", f"{deb_get_commit}:{filename}")
    for repository, detail in search:
        candidates.setdefault(repository, Candidate(repository)).add("github-search", detail)

    ordered = sorted(
        candidates.values(),
        key=lambda item: (
            0 if "deb-get" in item.sources else 1,
            item.repository.casefold(),
        ),
    )
    accepted: list[dict[str, Any]] = []
    release_rows: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    source_counts = {"deb-get": 0, "github-search": 0}

    # First secure the minimum contribution from both sources, then fill the total.
    deferred: list[Candidate] = []
    for candidate in ordered:
        needs_source = any(
            source in candidate.sources and source_counts[source] < args.minimum_per_source
            for source in source_counts
        )
        if not needs_source:
            deferred.append(candidate)
            continue
        metadata, rows, reason = inspect_repository(client, candidate)
        if reason:
            exclusions.append({"repository": candidate.repository, "reason": reason, "sources": ";".join(sorted(candidate.sources))})
            continue
        accepted.append(candidate_row(candidate, metadata, selected_at))
        release_rows.extend(rows)
        for source in source_counts:
            if source in candidate.sources:
                source_counts[source] += 1
        if all(count >= args.minimum_per_source for count in source_counts.values()):
            break

    accepted_names = {row["repository"] for row in accepted}
    inspected_names = accepted_names | {row["repository"] for row in exclusions}
    remaining = deferred + [candidate for candidate in ordered if candidate.repository not in inspected_names and candidate not in deferred]
    for candidate in remaining:
        if len(accepted) >= args.target:
            break
        if candidate.repository in inspected_names:
            continue
        inspected_names.add(candidate.repository)
        metadata, rows, reason = inspect_repository(client, candidate)
        if reason:
            exclusions.append({"repository": candidate.repository, "reason": reason, "sources": ";".join(sorted(candidate.sources))})
            continue
        accepted.append(candidate_row(candidate, metadata, selected_at))
        release_rows.extend(rows)

    accepted.sort(key=lambda row: row["repository"].casefold())
    release_rows.sort(key=lambda row: (row["repository"].casefold(), row["release_rank"]))
    exclusions.sort(key=lambda row: row["repository"].casefold())
    phase_b = deterministic_phase_b(release_rows, args.phase_b_size, selected_at[:10])

    write_tsv(
        args.candidates,
        ["repository", "repository_id", "selection_sources", "source_details", "selected_at", "fork", "archived"],
        accepted,
    )
    write_tsv(
        args.results,
        [
            "repository",
            "repository_id",
            "selection_sources",
            "release_rank",
            "tag",
            "release_id",
            "published_at",
            "immutable",
            "packages",
            "signature_assets",
            "checksum_assets",
            "signature_asset_details",
            "checksum_asset_details",
            "artifact_attestation_observed",
            "digest_unknown",
            "observed_lower_bound",
            "claimed_level",
        ],
        release_rows,
    )
    write_tsv(args.exclusions, ["repository", "reason", "sources"], exclusions)
    write_tsv(
        args.phase_b_sample,
        [
            "repository",
            "repository_id",
            "selection_sources",
            "tag",
            "release_id",
            "packages",
            "signature_asset_details",
            "checksum_asset_details",
            "claimed_level",
        ],
        phase_b,
    )

    summary = {
        "selected_at": selected_at,
        "deb_get_commit": deb_get_commit,
        "search_queries": SEARCH_QUERIES,
        "candidate_count": len(accepted),
        "release_row_count": len(release_rows),
        "exclusion_count": len(exclusions),
        "phase_b_sample_count": len(phase_b),
        "source_counts": {
            source: sum(source in row["selection_sources"].split(";") for row in accepted)
            for source in source_counts
        },
        "authenticated": bool(token),
    }
    atomic_write(args.summary, json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if len(accepted) >= args.target and len(phase_b) >= args.phase_b_size else 2


def candidate_row(candidate: Candidate, metadata: dict[str, Any], selected_at: str) -> dict[str, Any]:
    return {
        "repository": candidate.repository,
        "repository_id": metadata.get("id"),
        "selection_sources": ";".join(sorted(candidate.sources)),
        "source_details": ";".join(sorted(candidate.source_details)),
        "selected_at": selected_at,
        "fork": str(bool(metadata.get("fork"))).lower(),
        "archived": str(bool(metadata.get("archived"))).lower(),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("collect", help="collect candidate and Phase A metadata")
    command.add_argument("--raw-dir", type=Path, required=True)
    command.add_argument("--token-file", type=Path)
    command.add_argument("--allow-unauthenticated", action="store_true")
    command.add_argument("--target", type=int, default=100)
    command.add_argument("--minimum-per-source", type=int, default=20)
    command.add_argument("--search-pages", type=int, default=2)
    command.add_argument("--phase-b-size", type=int, default=20)
    command.add_argument("--candidates", type=Path, required=True)
    command.add_argument("--results", type=Path, required=True)
    command.add_argument("--exclusions", type=Path, required=True)
    command.add_argument("--phase-b-sample", type=Path, required=True)
    command.add_argument("--summary", type=Path, required=True)
    command.set_defaults(function=collect)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.function(args))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
