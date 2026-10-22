# SPDX-License-Identifier: MIT OR Apache-2.0
"""R-003 read-only harness: GitHub release metadata, assets, attestations.

Stage `collect` spends a small, fixed number of anonymous GitHub API requests
(no token is ever sent), downloads the package assets, and stores the
attestation bundles. Stage `checks` runs the GitHub CLI reference oracle
(ADR-017 point 9) offline and online, including the negative cases, and
writes sanitized TSV results. Raw data stays in the work directory, which the
runner copies into the ignored `.research-local/r-003/`.

Run with `python3 -I`. Downloaded files are only hashed, never executed,
installed, or unpacked.
"""

from __future__ import annotations

import argparse
import base64
import copy
import csv
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
USER_AGENT = "pakomichi-r003-research (read-only)"
TOKEN_VARIABLES = (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
)
PACKAGE_SUFFIXES = (".deb", ".rpm")
SLSA_V1 = "https://slsa.dev/provenance/v1"
# Predicate observed in GitHub release attestations (cli/cli v2.95.0, P0-004).
RELEASE_V02 = "https://in-toto.io/attestation/release/v0.2"
GITHUB_OIDC = "https://token.actions.githubusercontent.com"
MAX_API_REQUESTS = 20
HERE = pathlib.Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent


def die(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def load_snappy_decoder():
    """Reuse the P0-004 Snappy decoder instead of copying it."""
    path = PROJECT_ROOT / "prototypes" / "p0-004" / "fetch-attestation-bundles.py"
    spec = importlib.util.spec_from_file_location("p0004_bundles", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.decode_snappy


# --------------------------------------------------------------------------
# Anonymous HTTP


class NoAuthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.HTTPError(newurl, code, "non-HTTPS redirect refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(NoAuthRedirect())


class Api:
    def __init__(self, raw: pathlib.Path) -> None:
        self.raw = raw
        self.count = 0
        self.log = raw / "requests.tsv"
        if not self.log.exists():
            self.log.write_text("time\tmethod\turl\tstatus\tratelimit_remaining\tratelimit_resource\n")

    def _record(self, url: str, status: object, headers) -> None:
        remaining = headers.get("X-RateLimit-Remaining", "") if headers else ""
        resource = headers.get("X-RateLimit-Resource", "") if headers else ""
        stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        with self.log.open("a") as handle:
            handle.write(f"{stamp}\tGET\t{url}\t{status}\t{remaining}\t{resource}\n")

    def get(self, path: str, save_as: str, counted: bool = True) -> tuple[int, object]:
        if counted:
            if self.count >= MAX_API_REQUESTS:
                die(f"refusing to exceed the API budget of {MAX_API_REQUESTS} requests")
            self.count += 1
        url = API + path
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with OPENER.open(request, timeout=60) as response:
                body = response.read()
                status = response.status
                self._record(url, status, response.headers)
        except urllib.error.HTTPError as error:
            body = error.read()
            status = error.code
            self._record(url, status, error.headers)
        (self.raw / save_as).write_bytes(body)
        try:
            data = json.loads(body) if body else None
        except json.JSONDecodeError:
            data = None
        return status, data


def download(url: str, target: pathlib.Path) -> tuple[str, int]:
    if urllib.parse.urlsplit(url).scheme != "https":
        die(f"refusing non-HTTPS download {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"})
    digest = hashlib.sha256()
    size = 0
    part = target.with_suffix(target.suffix + ".part")
    with OPENER.open(request, timeout=300) as response, part.open("wb") as handle:
        while chunk := response.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
            handle.write(chunk)
    part.replace(target)
    return digest.hexdigest(), size


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Minimal DER reader for an independent look at the Fulcio certificate.
# This is reconciliation of claims, not signature verification.


def der_read(data: bytes, pos: int) -> tuple[int, int, int, int]:
    """Return (tag, value_start, value_end, next_pos)."""
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        width = length & 0x7F
        length = int.from_bytes(data[pos : pos + width], "big")
        pos += width
    return tag, pos, pos + length, pos + length


def der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    children = []
    pos = start
    while pos < end:
        tag, value_start, value_end, pos = der_read(data, pos)
        children.append((tag, value_start, value_end))
    return children


def der_oid(raw: bytes) -> str:
    first = raw[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(part) for part in parts)


FULCIO = "1.3.6.1.4.1.57264.1."
FULCIO_NAMES = {
    "1": "issuer_v1",
    "8": "issuer",
    "9": "build_signer_uri",
    "10": "build_signer_digest",
    "11": "runner_environment",
    "12": "source_repository_uri",
    "13": "source_repository_digest",
    "14": "source_repository_ref",
    "15": "source_repository_identifier",
    "16": "source_repository_owner_uri",
    "17": "source_repository_owner_identifier",
    "18": "build_config_uri",
    "19": "build_config_digest",
    "20": "build_trigger",
    "21": "run_invocation_uri",
    "22": "source_repository_visibility",
}


def certificate_claims(der: bytes) -> dict[str, str]:
    _, cert_start, cert_end, _ = der_read(der, 0)
    tbs_tag, tbs_start, tbs_end = der_children(der, cert_start, cert_end)[0]
    claims: dict[str, str] = {}
    for tag, start, end in der_children(der, tbs_start, tbs_end):
        if tag != 0xA3:
            continue
        _, seq_start, seq_end, _ = der_read(der, start)
        for _, ext_start, ext_end in der_children(der, seq_start, seq_end):
            parts = der_children(der, ext_start, ext_end)
            oid = der_oid(der[parts[0][1] : parts[0][2]])
            value = der[parts[-1][1] : parts[-1][2]]
            if oid == "2.5.29.17":
                _, san_start, san_end, _ = der_read(value, 0)
                uris = [
                    value[s:e].decode("utf-8", "replace")
                    for t, s, e in der_children(value, san_start, san_end)
                    if t == 0x86
                ]
                claims["san_uri"] = " ".join(uris)
            elif oid.startswith(FULCIO):
                suffix = oid[len(FULCIO) :]
                name = FULCIO_NAMES.get(suffix, "fulcio_" + suffix)
                if suffix == "1" or (suffix.isdigit() and int(suffix) < 8):
                    text = value.decode("utf-8", "replace")
                else:
                    inner_tag, inner_start, inner_end, _ = der_read(value, 0)
                    text = value[inner_start:inner_end].decode("utf-8", "replace")
                claims[name] = text
    return claims


def bundle_summary(bundle: dict) -> dict[str, object]:
    material = bundle.get("verificationMaterial", {})
    raw_cert = material.get("certificate", {}).get("rawBytes")
    if raw_cert is None:
        chain = material.get("x509CertificateChain", {}).get("certificates", [])
        raw_cert = chain[0]["rawBytes"] if chain else None
    claims = certificate_claims(base64.b64decode(raw_cert)) if raw_cert else {}
    envelope = bundle.get("dsseEnvelope", {})
    statement = json.loads(base64.b64decode(envelope.get("payload", ""))) if envelope else {}
    tlog = material.get("tlogEntries", [])
    return {
        "media_type": bundle.get("mediaType", ""),
        "predicate_type": statement.get("predicateType", ""),
        "predicate": statement.get("predicate", {}),
        "subjects": [
            {
                "name": subject.get("name", "") or subject.get("uri", ""),
                "sha256": subject.get("digest", {}).get("sha256", ""),
                "sha1": subject.get("digest", {}).get("sha1", ""),
            }
            for subject in statement.get("subject", [])
        ],
        "claims": claims,
        "tlog_entries": len(tlog),
        "tlog_log_index": ",".join(str(entry.get("logIndex", "")) for entry in tlog),
        "rfc3161_timestamps": len(material.get("timestampVerificationData", {}).get("rfc3161Timestamps", [])),
    }


# --------------------------------------------------------------------------
# Stage 1: collect


def fetch_bundles(response: dict, decode_snappy) -> list[dict]:
    bundles = []
    for attestation in response.get("attestations", []) if isinstance(response, dict) else []:
        bundle = attestation.get("bundle")
        if bundle is None and attestation.get("bundle_url"):
            url = attestation["bundle_url"]
            if urllib.parse.urlsplit(url).scheme != "https":
                die("refusing non-HTTPS bundle URL")
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with OPENER.open(request, timeout=60) as remote:
                body = remote.read()
                if remote.headers.get_content_type() == "application/x-snappy":
                    body = decode_snappy(body)
            bundle = json.loads(body)
        if bundle is not None:
            bundles.append({"repository_id": attestation.get("repository_id"), "bundle": bundle})
    return bundles


def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]", "_", name)


def collect_release(api, decode_snappy, work, repo_full, tag, select, prefix) -> dict:
    """Record one release: repository and owner IDs, release facts, tag commit,
    attestations addressed by the tag commit and by each selected asset digest."""
    raw_prefix = prefix + "-"
    downloads = work / "downloads" / prefix
    bundles_dir = work / "bundles" / prefix
    downloads.mkdir(parents=True, exist_ok=True)
    bundles_dir.mkdir(parents=True, exist_ok=True)
    owner, repo = repo_full.split("/", 1)

    status, repository = api.get(f"/repos/{owner}/{repo}", raw_prefix + "repository.json")
    if status != 200:
        die(f"{repo_full}: repository lookup failed with HTTP {status}")
    status, release = api.get(f"/repos/{owner}/{repo}/releases/tags/{tag}", raw_prefix + "release.json")
    if status != 200:
        die(f"{repo_full}: release lookup failed with HTTP {status}")

    status, ref = api.get(f"/repos/{owner}/{repo}/git/ref/tags/{urllib.parse.quote(tag)}", raw_prefix + "tag-ref.json")
    tag_object = (ref or {}).get("object", {})
    commit = tag_object.get("sha", "")
    tag_object_type = tag_object.get("type", "")
    if tag_object_type == "tag":
        status, tag_data = api.get(f"/repos/{owner}/{repo}/git/tags/{commit}", raw_prefix + "tag-object.json")
        commit = (tag_data or {}).get("object", {}).get("sha", "")

    # Release attestations of immutable releases also list the tag commit (sha1).
    commit_status, commit_attestations = api.get(
        f"/repos/{owner}/{repo}/attestations/sha1:{commit}?per_page=100", raw_prefix + "attestations-sha1-commit.json"
    )
    commit_bundles = fetch_bundles(commit_attestations, decode_snappy) if commit_status == 200 else []
    with (bundles_dir / "release-commit.jsonl").open("w") as handle:
        for item in commit_bundles:
            handle.write(json.dumps(item["bundle"], separators=(",", ":")) + "\n")

    assets = []
    for asset in release.get("assets", []):
        name = asset["name"]
        if not select(name):
            continue
        local = downloads / f"{asset['id']}-{safe_name(name)}"
        downloaded, size = download(asset["browser_download_url"], local)
        api_digest = asset.get("digest") or ""
        lookup = api_digest if api_digest.startswith("sha256:") else f"sha256:{downloaded}"
        status, response = api.get(
            f"/repos/{owner}/{repo}/attestations/{lookup}?per_page=100",
            raw_prefix + f"attestations-{asset['id']}.json",
        )
        bundles = fetch_bundles(response, decode_snappy) if status == 200 else []
        bundle_file = bundles_dir / f"{asset['id']}.jsonl"
        with bundle_file.open("w") as handle:
            for item in bundles:
                handle.write(json.dumps(item["bundle"], separators=(",", ":")) + "\n")
        assets.append(
            {
                "asset_id": asset["id"],
                "name": name,
                "size_api": asset.get("size"),
                "size_downloaded": size,
                "api_digest": api_digest,
                "downloaded_sha256": downloaded,
                "local": f"{prefix}/{local.name}",
                "attestation_http_status": status,
                "attestation_repository_ids": sorted({str(item["repository_id"]) for item in bundles}),
                "bundle_file": f"{prefix}/{bundle_file.name}",
                "bundle_count": len(bundles),
            }
        )

    return {
        "repo": repo_full,
        "tag": tag,
        "repository_id": repository.get("id"),
        "repository_full_name": repository.get("full_name"),
        "owner_id": repository.get("owner", {}).get("id"),
        "owner_login": repository.get("owner", {}).get("login"),
        "fork": repository.get("fork"),
        "release_id": release.get("id"),
        "release_tag": release.get("tag_name"),
        "release_immutable": release.get("immutable"),
        "release_draft": release.get("draft"),
        "release_prerelease": release.get("prerelease"),
        "release_published_at": release.get("published_at"),
        "release_target_commitish": release.get("target_commitish"),
        "tag_object_type": tag_object_type,
        "tag_commit": commit,
        "release_commit_attestation_status": commit_status,
        "release_commit_bundle_count": len(commit_bundles),
        "release_commit_bundle_file": f"{prefix}/release-commit.jsonl",
        "all_release_asset_digests": sorted(a.get("digest") or "" for a in release.get("assets", [])),
        "assets": assets,
    }


def collect(args: argparse.Namespace) -> int:
    for variable in TOKEN_VARIABLES:
        if os.environ.get(variable):
            die(f"{variable} is set; this read-only stage runs anonymously by design")
    work = pathlib.Path(args.work)
    raw = work / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    api = Api(raw)
    decode_snappy = load_snappy_decoder()

    status, limits = api.get("/rate_limit", "rate_limit_before.json", counted=False)
    remaining = (limits or {}).get("resources", {}).get("core", {}).get("remaining", 0)
    if status != 200 or remaining < 16:
        die(f"anonymous core rate limit too low or unavailable (status {status}, remaining {remaining}); retry later")

    summary = collect_release(
        api, decode_snappy, work, args.repo, args.tag, lambda name: name.endswith(PACKAGE_SUFFIXES), "subject"
    )
    # Second read-only reference: an immutable release with a release attestation.
    summary["strict_reference"] = collect_release(
        api, decode_snappy, work, args.strict_repo, args.strict_tag, lambda name: name == args.strict_asset, "strict"
    )
    api.get("/rate_limit", "rate_limit_after.json", counted=False)
    summary["collected_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    summary["api_requests_counted"] = api.count
    (work / "collect.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"collected {len(summary['assets'])} package assets with {api.count} counted API requests")
    return 0


# --------------------------------------------------------------------------
# Stage 2: checks


class Runner:
    def __init__(self, work: pathlib.Path, gh: str) -> None:
        self.work = work
        self.gh = gh
        self.logs = work / "gh-logs"
        self.logs.mkdir(exist_ok=True)
        home = work / "home"
        config = work / "gh-config"
        home.mkdir(exist_ok=True)
        config.mkdir(exist_ok=True)
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "GH_CONFIG_DIR": str(config),
            "GH_NO_UPDATE_NOTIFIER": "1",
            "GH_PROMPT_DISABLED": "1",
            "NO_COLOR": "1",
            "LANG": "C.UTF-8",
        }
        self.rows: list[dict[str, str]] = []

    def sanitize(self, text: str) -> str:
        text = text.replace(str(self.work), "$WORK").replace(str(PROJECT_ROOT), ".")
        return text.replace(self.gh, "gh")

    def run(
        self,
        case: str,
        description: str,
        argv: list[str],
        expect_success: bool | None,
        offline_namespace: bool = False,
        json_out: bool = False,
    ) -> subprocess.CompletedProcess:
        command = [self.gh, *argv]
        if offline_namespace:
            command = ["unshare", "--user", "--map-root-user", "--net", "--", *command]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=300)
        (self.logs / f"{case}.stdout").write_text(result.stdout)
        (self.logs / f"{case}.stderr").write_text(result.stderr)
        (self.logs / f"{case}.argv").write_text(json.dumps(command) + "\n")
        stderr_lines = [line.strip() for line in result.stderr.splitlines() if line.strip()]
        note = " | ".join(stderr_lines[-3:]) if stderr_lines else ""
        lowered = result.stderr.lower()
        needs_auth = "yes" if ("gh auth login" in lowered or "gh_token" in lowered) else "no"
        succeeded = result.returncode == 0
        if needs_auth == "yes" and not succeeded:
            outcome = "AUTH_REQUIRED"
        elif expect_success is None:
            outcome = "OBSERVED"
        else:
            outcome = "AS_EXPECTED" if succeeded == expect_success else "UNEXPECTED"
        self.rows.append(
            {
                "case": case,
                "description": description,
                "command": self.sanitize(" ".join(["gh", *argv]) + (" [no-network namespace]" if offline_namespace else "")),
                "expected": "observe" if expect_success is None else ("success" if expect_success else "failure"),
                "exit_code": str(result.returncode),
                "outcome": outcome,
                "needs_auth": needs_auth,
                "note": self.sanitize(note)[:400].replace("\t", " "),
            }
        )
        return result


def reconcile(case: str, verification: list, expected: dict) -> list[dict[str, str]]:
    """Match the oracle's JSON against API facts by ID, digest, ref, and commit."""
    rows = []
    for index, result in enumerate(verification):
        vr = result.get("verificationResult", {})
        cert = vr.get("signature", {}).get("certificate", {})
        statement = vr.get("statement", {})
        subjects = [s.get("digest", {}).get("sha256", "") for s in statement.get("subject", [])]
        checks = {
            "repo_id": str(cert.get("sourceRepositoryIdentifier", "")) == str(expected["repository_id"]),
            "owner_id": str(cert.get("sourceRepositoryOwnerIdentifier", "")) == str(expected["owner_id"]),
            "asset_sha256": expected["sha256"] in subjects,
            "api_digest": expected["api_digest"] in ("", "sha256:" + expected["sha256"]),
            "source_ref": cert.get("sourceRepositoryRef", "") == expected["source_ref"],
            "source_commit": cert.get("sourceRepositoryDigest", "") == expected["commit"],
            "hosted_runner": cert.get("runnerEnvironment", "") == "github-hosted",
            "oidc_issuer": cert.get("issuer", "") == GITHUB_OIDC,
        }
        rows.append(
            {
                "case": case,
                "result_index": str(index),
                "predicate_type": statement.get("predicateType", ""),
                "source_repository_uri": cert.get("sourceRepositoryURI", ""),
                "source_repository_identifier": str(cert.get("sourceRepositoryIdentifier", "")),
                "source_repository_owner_identifier": str(cert.get("sourceRepositoryOwnerIdentifier", "")),
                "source_repository_ref": cert.get("sourceRepositoryRef", ""),
                "source_repository_digest": cert.get("sourceRepositoryDigest", ""),
                "build_signer_uri": cert.get("buildSignerURI", ""),
                "runner_environment": cert.get("runnerEnvironment", ""),
                **{f"match_{key}": "yes" if value else "NO" for key, value in checks.items()},
                "all_match": "yes" if all(checks.values()) else "NO",
            }
        )
    return rows


def write_tsv(path: pathlib.Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def tampered_copy(source: pathlib.Path, target: pathlib.Path) -> None:
    data = bytearray(source.read_bytes())
    data[len(data) // 2] ^= 0x01
    target.write_bytes(bytes(data))


def checks(args: argparse.Namespace) -> int:
    for variable in TOKEN_VARIABLES:
        os.environ.pop(variable, None)
    work = pathlib.Path(args.work)
    results = pathlib.Path(args.results)
    results.mkdir(parents=True, exist_ok=True)
    summary = json.loads((work / "collect.json").read_text())
    runner = Runner(work, args.gh)
    repo = summary["repo"]
    owner = repo.split("/")[0]
    tag = summary["tag"]
    commit = summary["tag_commit"]
    source_ref = f"refs/tags/{tag}"
    downloads = work / "downloads"
    bundles_dir = work / "bundles"
    negatives = work / "negatives"
    negatives.mkdir(exist_ok=True)

    targets = [("subject", summary), ("strict", summary["strict_reference"])]

    # Independent view of every stored bundle (reconciliation, not verification).
    attestation_rows = []
    for label, target in targets:
        sources = [(asset, asset["bundle_file"]) for asset in target["assets"]]
        sources.append(({"asset_id": "tag-commit", "name": "sha1:" + target["tag_commit"], "downloaded_sha256": ""},
                        target["release_commit_bundle_file"]))
        for asset, bundle_name in sources:
            for line_number, line in enumerate((bundles_dir / bundle_name).read_text().splitlines()):
                info = bundle_summary(json.loads(line))
                claims = info["claims"]
                predicate = info["predicate"] if info["predicate_type"].startswith("https://in-toto.io/attestation/release/") else {}
                sha1s = [s["sha1"] for s in info["subjects"] if s["sha1"]]
                attestation_rows.append(
                    {
                        "target": label,
                        "repo": target["repo"],
                        "asset_id": str(asset["asset_id"]),
                        "asset": asset["name"],
                        "bundle_index": str(line_number),
                        "media_type": info["media_type"],
                        "predicate_type": info["predicate_type"],
                        "subject_count": str(len(info["subjects"])),
                        "asset_in_subjects": ("yes" if any(s["sha256"] == asset["downloaded_sha256"] for s in info["subjects"]) else "NO")
                        if asset["downloaded_sha256"] else "n/a",
                        "commit_in_subjects": "yes" if target["tag_commit"] in sha1s else ("NO" if sha1s else "n/a"),
                        "san_uri": claims.get("san_uri", ""),
                        "issuer": claims.get("issuer", ""),
                        "build_signer_uri": claims.get("build_signer_uri", ""),
                        "runner_environment": claims.get("runner_environment", ""),
                        "source_repository_uri": claims.get("source_repository_uri", ""),
                        "source_repository_identifier": claims.get("source_repository_identifier", ""),
                        "source_repository_owner_identifier": claims.get("source_repository_owner_identifier", ""),
                        "source_repository_ref": claims.get("source_repository_ref", ""),
                        "source_repository_digest": claims.get("source_repository_digest", ""),
                        "build_trigger": claims.get("build_trigger", ""),
                        "source_repository_visibility": claims.get("source_repository_visibility", ""),
                        "release_predicate_repository_id": str(predicate.get("repositoryId", "")),
                        "release_predicate_owner_id": str(predicate.get("ownerId", "")),
                        "release_predicate_release_id": str(predicate.get("databaseId", "")),
                        "release_predicate_tag": str(predicate.get("tag", "")),
                        "repo_id_matches_api": "yes"
                        if str(target["repository_id"]) in (claims.get("source_repository_identifier"), str(predicate.get("repositoryId")))
                        else "NO",
                        "release_id_matches_api": ("yes" if str(predicate.get("databaseId")) == str(target["release_id"]) else "NO")
                        if predicate else "n/a",
                        "tlog_entries": str(info["tlog_entries"]),
                        "rfc3161_timestamps": str(info["rfc3161_timestamps"]),
                    }
                )
    write_tsv(results / "attestations.tsv", attestation_rows)

    # Release and asset facts from the API.
    release_rows = []
    for label, target in targets:
        for key in (
            "repo", "repository_full_name", "repository_id", "owner_login", "owner_id", "fork",
            "release_id", "release_tag", "release_immutable", "release_draft", "release_prerelease",
            "release_published_at", "release_target_commitish", "tag_object_type", "tag_commit",
            "release_commit_attestation_status", "release_commit_bundle_count",
        ):
            release_rows.append({"target": label, "field": key, "value": "" if target[key] is None else str(target[key])})
    for key in ("api_requests_counted", "collected_at"):
        release_rows.append({"target": "run", "field": key, "value": str(summary[key])})
    write_tsv(results / "release.tsv", release_rows)
    asset_rows = [
        {
            "target": label,
            "asset_id": str(asset["asset_id"]),
            "name": asset["name"],
            "size_api": str(asset["size_api"]),
            "size_downloaded": str(asset["size_downloaded"]),
            "api_digest": asset["api_digest"],
            "downloaded_sha256": asset["downloaded_sha256"],
            "digest_match": "yes" if asset["api_digest"] == "sha256:" + asset["downloaded_sha256"] else "NO",
            "attestation_http_status": str(asset["attestation_http_status"]),
            "bundle_count": str(asset["bundle_count"]),
            "attestation_repository_ids": ",".join(asset["attestation_repository_ids"]),
        }
        for label, target in targets
        for asset in target["assets"]
    ]
    write_tsv(results / "assets.tsv", asset_rows)

    attested = [asset for asset in summary["assets"] if asset["bundle_count"] > 0]
    if not attested:
        die("no package asset has an attestation bundle; nothing to verify")

    trusted_root = work / "trusted-root.jsonl"
    result = runner.run(
        "trusted-root",
        "fetch the Sigstore trusted root through TUF for offline verification",
        ["attestation", "trusted-root"],
        expect_success=True,
    )
    trusted_root.write_text(result.stdout)
    if result.returncode != 0 or not result.stdout.strip():
        write_tsv(results / "checks.tsv", runner.rows)
        die("gh attestation trusted-root failed; offline cases cannot run")
    root = ["--custom-trusted-root", str(trusted_root)]

    reconcile_rows: list[dict[str, str]] = []
    first_signer = ""
    for asset in attested:
        file = downloads / asset["local"]
        bundle = bundles_dir / asset["bundle_file"]
        case = f"P-repo-{asset['asset_id']}"
        result = runner.run(
            case,
            f"offline verify {asset['name']} with --repo only (name binding)",
            ["attestation", "verify", str(file), "--repo", repo, "--bundle", str(bundle), *root, "--format", "json"],
            expect_success=True,
        )
        expected = {
            "repository_id": summary["repository_id"],
            "owner_id": summary["owner_id"],
            "sha256": asset["downloaded_sha256"],
            "api_digest": asset["api_digest"],
            "source_ref": source_ref,
            "commit": commit,
        }
        if result.returncode == 0:
            reconcile_rows += reconcile(case, json.loads(result.stdout), expected)
        claims = [row for row in attestation_rows if row["asset_id"] == str(asset["asset_id"]) and row["predicate_type"] == SLSA_V1]
        signer = claims[0]["build_signer_uri"] if claims else ""
        signer_workflow = signer.split("@", 1)[0].removeprefix("https://github.com/")
        first_signer = first_signer or signer
        case = f"P-strict-{asset['asset_id']}"
        result = runner.run(
            case,
            f"offline verify {asset['name']} with repo, signer workflow, ref, commit, issuer, predicate, hosted runner pinned",
            [
                "attestation", "verify", str(file), "--repo", repo, "--bundle", str(bundle), *root,
                "--signer-workflow", signer_workflow,
                "--source-ref", source_ref,
                "--source-digest", commit,
                "--cert-oidc-issuer", GITHUB_OIDC,
                "--predicate-type", SLSA_V1,
                "--deny-self-hosted-runners",
                "--format", "json",
            ],
            expect_success=True,
        )
        if result.returncode == 0:
            reconcile_rows += reconcile(case, json.loads(result.stdout), expected)

    asset = attested[0]
    file = downloads / asset["local"]
    bundle = bundles_dir / asset["bundle_file"]
    base = ["attestation", "verify"]
    offline = ["--bundle", str(bundle), *root]
    signer_workflow = first_signer.split("@", 1)[0].removeprefix("https://github.com/")
    signer_ref = first_signer.split("@", 1)[1] if "@" in first_signer else source_ref

    runner.run("P-offline-netns", "offline verify inside a network namespace without any network",
               [*base, str(file), "--repo", repo, *offline], expect_success=True, offline_namespace=True)
    runner.run("O-name-case", "observation: repository name given in a different letter case",
               [*base, str(file), "--repo", repo.upper(), *offline], expect_success=None)

    changed = negatives / ("changed-byte-" + pathlib.Path(asset["local"]).name)
    tampered_copy(file, changed)
    runner.run("N-changed-byte", "one flipped byte in the asset",
               [*base, str(changed), "--repo", repo, *offline], expect_success=False)
    runner.run("N-repo-fork-name", "expected repository set to a fork-like name under the same owner",
               [*base, str(file), "--repo", f"{repo}-fork", *offline], expect_success=False)
    runner.run("N-repo-other-owner", "expected repository set to the same name under another owner",
               [*base, str(file), "--repo", f"pakomichi-r003-nonexistent/{repo.split('/')[1]}", *offline], expect_success=False)
    runner.run("N-owner-other", "expected owner set to another owner",
               [*base, str(file), "--owner", "pakomichi-r003-nonexistent", *offline], expect_success=False)
    runner.run("N-signer-workflow", "wrong signer workflow path",
               [*base, str(file), "--repo", repo, "--signer-workflow", f"{repo}/.github/workflows/pakomichi-r003-other.yml", *offline],
               expect_success=False)
    runner.run("N-signer-repo", "signer workflow required from another repository",
               [*base, str(file), "--repo", repo, "--signer-repo", f"{repo}-fork", *offline], expect_success=False)
    runner.run("N-cert-identity", "exact certificate identity with a different ref",
               [*base, str(file), "--repo", repo, "--cert-identity", f"https://github.com/{signer_workflow}@refs/heads/pakomichi-r003-other", *offline],
               expect_success=False)
    runner.run("P-cert-identity", "exact certificate identity as observed (control for N-cert-identity)",
               [*base, str(file), "--repo", repo, "--cert-identity", f"https://github.com/{signer_workflow}@{signer_ref}", *offline],
               expect_success=True)
    runner.run("N-oidc-issuer", "wrong OIDC issuer",
               [*base, str(file), "--repo", repo, "--cert-oidc-issuer", "https://token.actions.githubusercontent.com/pakomichi-r003", *offline],
               expect_success=False)
    runner.run("N-source-ref", "wrong source ref",
               [*base, str(file), "--repo", repo, "--source-ref", "refs/tags/v0.0.0-pakomichi-r003", *offline], expect_success=False)
    runner.run("N-source-digest", "wrong source commit",
               [*base, str(file), "--repo", repo, "--source-digest", "0" * 40, *offline], expect_success=False)
    runner.run("N-predicate-release", "release-attestation predicate required for a mutable release",
               [*base, str(file), "--repo", repo, "--predicate-type", RELEASE_V02, *offline], expect_success=False)

    foreign = negatives / "not-in-release.deb"
    foreign.write_bytes(b"pakomichi-r003: bytes that are not a release asset\n")
    foreign_digest = "sha256:" + sha256_file(foreign)
    in_release = foreign_digest in summary["all_release_asset_digests"]
    runner.run("N-digest-not-in-release", f"artifact whose digest is not a release asset digest (in release: {'yes' if in_release else 'no'})",
               [*base, str(foreign), "--repo", repo, *offline], expect_success=False)

    empty = negatives / "empty.jsonl"
    empty.write_text("")
    runner.run("N-missing-provenance", "empty bundle file (no provenance)",
               [*base, str(file), "--repo", repo, "--bundle", str(empty), *root], expect_success=False)

    # A bundle whose DSSE payload claims the tampered digest: the signature must fail.
    original = json.loads(bundle.read_text().splitlines()[0])
    forged = copy.deepcopy(original)
    statement = json.loads(base64.b64decode(forged["dsseEnvelope"]["payload"]))
    changed_digest = sha256_file(changed)
    for subject in statement.get("subject", []):
        if subject.get("digest", {}).get("sha256") == asset["downloaded_sha256"]:
            subject["digest"]["sha256"] = changed_digest
    forged["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    forged_file = negatives / "forged-subject.jsonl"
    forged_file.write_text(json.dumps(forged, separators=(",", ":")) + "\n")
    runner.run("N-forged-payload", "DSSE payload rewritten to the changed asset digest (signature no longer matches)",
               [*base, str(changed), "--repo", repo, "--bundle", str(forged_file), *root], expect_success=False)

    # Trusted root without certificate authorities: the Fulcio chain is untrusted.
    roots = [json.loads(line) for line in trusted_root.read_text().splitlines() if line.strip()]
    no_ca = negatives / "trusted-root-no-ca.jsonl"
    with no_ca.open("w") as handle:
        for item in roots:
            item = copy.deepcopy(item)
            item["certificateAuthorities"] = []
            handle.write(json.dumps(item, separators=(",", ":")) + "\n")
    runner.run("N-untrusted-root", "custom trusted root without the Fulcio certificate authorities",
               [*base, str(file), "--repo", repo, "--bundle", str(bundle), "--custom-trusted-root", str(no_ca)], expect_success=False)

    if len(attested) > 1:
        other = attested[1]
        other_bundle = bundles_dir / other["bundle_file"]
        shares = any(
            subject["sha256"] == asset["downloaded_sha256"]
            for line in other_bundle.read_text().splitlines()
            if line.strip()
            for subject in bundle_summary(json.loads(line))["subjects"]
        )
        runner.run("O-other-asset-bundle", f"bundle fetched for another asset (bundle also lists this asset: {'yes' if shares else 'no'})",
                   [*base, str(file), "--repo", repo, "--bundle", str(other_bundle), *root], expect_success=shares)

    # Online modes: the API lookup and the release commands.
    runner.run("A-attestation-online", "online verify without a bundle (API lookup by digest)",
               [*base, str(file), "--repo", repo, "--format", "json"], expect_success=True)
    runner.run("A-attestation-online-netns", "online verify without a bundle and without network",
               [*base, str(file), "--repo", repo], expect_success=False, offline_namespace=True)
    runner.run("A-release-verify", "gh release verify for a mutable release",
               ["release", "verify", tag, "--repo", repo, "--format", "json"], expect_success=False)
    runner.run("A-release-verify-asset", "gh release verify-asset for a mutable release",
               ["release", "verify-asset", tag, str(file), "--repo", repo, "--format", "json"], expect_success=False)

    # Strict reference: an immutable release (cli/cli) with a GitHub release attestation.
    strict = summary["strict_reference"]
    if strict["assets"]:
        s_asset = strict["assets"][0]
        s_file = downloads / s_asset["local"]
        s_bundle = bundles_dir / s_asset["bundle_file"]
        s_repo = strict["repo"]
        s_tag = strict["tag"]
        s_bundles = [json.loads(line) for line in s_bundle.read_text().splitlines() if line.strip()]
        by_predicate: dict[str, pathlib.Path] = {}
        for item in s_bundles:
            predicate_type = json.loads(base64.b64decode(item["dsseEnvelope"]["payload"])).get("predicateType", "")
            path = negatives / ("strict-" + re.sub(r"[^a-z0-9]+", "-", predicate_type.lower()).strip("-") + ".jsonl")
            with path.open("a") as handle:
                handle.write(json.dumps(item, separators=(",", ":")) + "\n")
            by_predicate[predicate_type] = path
        release_only = by_predicate.get(RELEASE_V02)
        slsa_only = by_predicate.get(SLSA_V1)
        s_offline = [*root]
        if release_only:
            runner.run("S-release-default-policy", "release attestation, default --repo policy (workflow SAN expected)",
                       ["attestation", "verify", str(s_file), "--repo", s_repo, "--bundle", str(release_only), *s_offline,
                        "--predicate-type", RELEASE_V02, "--format", "json"], expect_success=None)
            runner.run("S-release-cert-identity", "release attestation pinned to the GitHub releases signer identity",
                       ["attestation", "verify", str(s_file), "--repo", s_repo, "--bundle", str(release_only), *s_offline,
                        "--predicate-type", RELEASE_V02, "--cert-identity", "https://dotcom.releases.github.com",
                        "--format", "json"], expect_success=None)
        if slsa_only:
            s_signer = next((row["build_signer_uri"] for row in attestation_rows
                             if row["target"] == "strict" and row["predicate_type"] == SLSA_V1), "")
            s_workflow = s_signer.split("@", 1)[0].removeprefix("https://github.com/")
            runner.run("S-provenance", "artifact attestation of the immutable-release asset, signer workflow pinned",
                       ["attestation", "verify", str(s_file), "--repo", s_repo, "--bundle", str(slsa_only), *s_offline,
                        "--signer-workflow", s_workflow, "--deny-self-hosted-runners", "--predicate-type", SLSA_V1,
                        "--format", "json"], expect_success=True)
            s_changed = negatives / ("changed-byte-" + pathlib.Path(s_asset["local"]).name)
            tampered_copy(s_file, s_changed)
            runner.run("SN-changed-byte", "immutable-release asset with one flipped byte",
                       ["attestation", "verify", str(s_changed), "--repo", s_repo, "--bundle", str(s_bundle), *s_offline],
                       expect_success=False)
            runner.run("SN-repo-fork-name", "immutable-release asset, expected repository set to a fork-like name",
                       ["attestation", "verify", str(s_file), "--repo", f"{s_repo}-fork", "--bundle", str(s_bundle), *s_offline],
                       expect_success=False)
        runner.run("SA-release-verify", "gh release verify for an immutable release",
                   ["release", "verify", s_tag, "--repo", s_repo, "--format", "json"], expect_success=True)
        runner.run("SA-release-verify-asset", "gh release verify-asset for an immutable release",
                   ["release", "verify-asset", s_tag, str(s_file), "--repo", s_repo, "--format", "json"], expect_success=True)
        runner.run("SAN-release-verify-asset-changed", "gh release verify-asset with an asset not in the release",
                   ["release", "verify-asset", s_tag, str(foreign), "--repo", s_repo, "--format", "json"], expect_success=False)

    write_tsv(results / "checks.tsv", runner.rows)
    write_tsv(results / "reconcile.tsv", reconcile_rows)
    unexpected = [row["case"] for row in runner.rows if row["outcome"] == "UNEXPECTED"]
    auth = [row["case"] for row in runner.rows if row["outcome"] == "AUTH_REQUIRED"]
    mismatched = [row["case"] for row in reconcile_rows if row["all_match"] != "yes"]
    print(
        f"cases={len(runner.rows)} unexpected={','.join(unexpected) or 'none'} "
        f"auth_required={','.join(auth) or 'none'} reconcile_mismatch={','.join(mismatched) or 'none'}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="stage", required=True)
    one = sub.add_parser("collect")
    one.add_argument("--work", required=True)
    one.add_argument("--repo", default="matthart1983/netwatch")
    one.add_argument("--tag", default="v0.35.4")
    one.add_argument("--strict-repo", default="cli/cli")
    one.add_argument("--strict-tag", default="v2.95.0")
    one.add_argument("--strict-asset", default="gh_2.95.0_linux_amd64.tar.gz")
    two = sub.add_parser("checks")
    two.add_argument("--work", required=True)
    two.add_argument("--results", required=True)
    two.add_argument("--gh", required=True)
    args = parser.parse_args()
    return collect(args) if args.stage == "collect" else checks(args)


if __name__ == "__main__":
    raise SystemExit(main())
