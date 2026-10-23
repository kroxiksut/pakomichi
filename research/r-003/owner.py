# SPDX-License-Identifier: MIT OR Apache-2.0
"""R-003 owner-repository steps: protocol step 1 (Strict, immutable release).

Reuses the read-only harness `r003.py` for collection, certificate parsing,
and the GitHub CLI oracle. API collection stays anonymous. Only the `gh`
cases marked online receive the read-only token, through the environment and
never on a command line. After the run every file in the work and results
directories is scanned for the token.

Run with `python3 -I`. Downloaded files are only hashed, never executed,
installed, or unpacked.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import importlib.util
import json
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent


def load_harness():
    spec = importlib.util.spec_from_file_location("r003", HERE / "r003.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


r = load_harness()


def read_token(path: pathlib.Path) -> str:
    token = path.read_text(encoding="utf-8-sig").strip()
    if not re.fullmatch(r"github_pat_[A-Za-z0-9_]{20,}", token):
        r.die("token file does not hold a single fine-grained token")
    return token


def predicate_of(bundle: dict) -> str:
    return json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"])).get("predicateType", "")


def split_by_predicate(source: pathlib.Path, target_dir: pathlib.Path, prefix: str) -> dict[str, pathlib.Path]:
    """Write one JSONL file per predicate type found in a bundle file."""
    files: dict[str, pathlib.Path] = {}
    for line in source.read_text().splitlines():
        if not line.strip():
            continue
        bundle = json.loads(line)
        kind = predicate_of(bundle)
        path = target_dir / f"{prefix}-{re.sub(r'[^a-z0-9]+', '-', kind.lower()).strip('-')}.jsonl"
        if kind not in files:
            path.write_text("")
        with path.open("a") as handle:
            handle.write(json.dumps(bundle, separators=(",", ":")) + "\n")
        files[kind] = path
    return files


def attestation_rows(target: dict, bundles_dir: pathlib.Path) -> list[dict[str, str]]:
    rows = []
    sources = [(a["asset_id"], a["name"], a["downloaded_sha256"], a["bundle_file"]) for a in target["assets"]]
    sources.append(("tag-commit", "sha1:" + target["tag_commit"], "", target["release_commit_bundle_file"]))
    for asset_id, name, sha256, bundle_name in sources:
        for index, line in enumerate((bundles_dir / bundle_name).read_text().splitlines()):
            info = r.bundle_summary(json.loads(line))
            claims = info["claims"]
            is_release = info["predicate_type"].startswith("https://in-toto.io/attestation/release/")
            predicate = info["predicate"] if is_release else {}
            sha1s = [s["sha1"] for s in info["subjects"] if s["sha1"]]
            checks = {
                "asset_in_subjects": any(s["sha256"] == sha256 for s in info["subjects"]) if sha256 else None,
                "commit_in_subjects": (target["tag_commit"] in sha1s) if sha1s else None,
                "repo_id": str(target["repository_id"])
                in (claims.get("source_repository_identifier"), str(predicate.get("repositoryId"))),
                "owner_id": str(target["owner_id"])
                in (claims.get("source_repository_owner_identifier"), str(predicate.get("ownerId"))),
                "release_id": (str(predicate.get("databaseId")) == str(target["release_id"])) if predicate else None,
                "release_tag": (str(predicate.get("tag")) == target["release_tag"]) if predicate else None,
            }
            rows.append(
                {
                    "asset_id": str(asset_id),
                    "lookup": name,
                    "bundle_index": str(index),
                    "predicate_type": info["predicate_type"],
                    "subject_count": str(len(info["subjects"])),
                    "san_uri": claims.get("san_uri", ""),
                    "issuer": claims.get("issuer", ""),
                    "build_signer_uri": claims.get("build_signer_uri", ""),
                    "source_repository_identifier": claims.get("source_repository_identifier", ""),
                    "source_repository_owner_identifier": claims.get("source_repository_owner_identifier", ""),
                    "source_repository_ref": claims.get("source_repository_ref", ""),
                    "source_repository_digest": claims.get("source_repository_digest", ""),
                    "runner_environment": claims.get("runner_environment", ""),
                    "build_trigger": claims.get("build_trigger", ""),
                    "predicate_repository_id": str(predicate.get("repositoryId", "")),
                    "predicate_owner_id": str(predicate.get("ownerId", "")),
                    "predicate_release_id": str(predicate.get("databaseId", "")),
                    "predicate_tag": str(predicate.get("tag", "")),
                    **{f"match_{k}": "n/a" if v is None else ("yes" if v else "NO") for k, v in checks.items()},
                    "tlog_entries": str(info["tlog_entries"]),
                    "rfc3161_timestamps": str(info["rfc3161_timestamps"]),
                }
            )
    return rows


def release_verify_rows(case: str, stdout: str, target: dict, asset: dict) -> list[dict[str, str]]:
    """Reconcile the statement returned by `gh release verify*` with API facts."""
    try:
        results = json.loads(stdout)
    except json.JSONDecodeError:
        return [{"case": case, "result_index": "-", "predicate_type": "unparsed output", "all_match": "NO"}]
    if isinstance(results, dict):
        results = [results]
    rows = []
    for index, item in enumerate(results):
        statement = item.get("verificationResult", item).get("statement", {})
        predicate = statement.get("predicate", {})
        subjects = statement.get("subject", [])
        sha256s = {s.get("digest", {}).get("sha256", "") for s in subjects}
        sha1s = {s.get("digest", {}).get("sha1", "") for s in subjects}
        checks = {
            "repo_id": str(predicate.get("repositoryId", "")) == str(target["repository_id"]),
            "owner_id": str(predicate.get("ownerId", "")) == str(target["owner_id"]),
            "release_id": str(predicate.get("databaseId", "")) == str(target["release_id"]),
            "tag": str(predicate.get("tag", "")) == target["release_tag"],
            "commit": target["tag_commit"] in sha1s,
            "asset_sha256": asset["downloaded_sha256"] in sha256s,
        }
        rows.append(
            {
                "case": case,
                "result_index": str(index),
                "predicate_type": statement.get("predicateType", ""),
                "predicate_repository_id": str(predicate.get("repositoryId", "")),
                "predicate_owner_id": str(predicate.get("ownerId", "")),
                "predicate_release_id": str(predicate.get("databaseId", "")),
                "predicate_tag": str(predicate.get("tag", "")),
                **{f"match_{k}": "yes" if v else "NO" for k, v in checks.items()},
                "all_match": "yes" if all(checks.values()) else "NO",
            }
        )
    return rows


def scan_for_token(token: str, roots: list[pathlib.Path]) -> list[str]:
    needle = token.encode()
    hits = []
    for root in roots:
        for path in root.rglob("*"):
            if path.is_file() and needle in path.read_bytes():
                hits.append(str(path))
    return hits


RELEASE_FIELDS = (
    "repo", "repository_full_name", "repository_id", "owner_login", "owner_id", "fork",
    "release_id", "release_tag", "release_immutable", "release_draft", "release_prerelease",
    "release_published_at", "release_target_commitish", "tag_object_type", "tag_commit",
    "release_commit_attestation_status", "release_commit_bundle_count",
)


def asset_row(asset: dict) -> dict[str, str]:
    return {
        "asset_id": str(asset["asset_id"]), "name": asset["name"], "size_api": str(asset["size_api"]),
        "size_downloaded": str(asset["size_downloaded"]), "api_digest": asset["api_digest"],
        "downloaded_sha256": asset["downloaded_sha256"],
        "digest_match": "yes" if asset["api_digest"] == "sha256:" + asset["downloaded_sha256"] else "NO",
        "attestation_http_status": str(asset["attestation_http_status"]), "bundle_count": str(asset["bundle_count"]),
        "attestation_repository_ids": ",".join(asset["attestation_repository_ids"]),
    }


def finish(runner, token: str, work: pathlib.Path, results: pathlib.Path, step: str,
           reconcile_rows: list, release_rows: list) -> int:
    hits = scan_for_token(token, [work, results])
    runner.rows.append({
        "case": "N-token-not-logged", "description": "no file in the work or results directories contains the token",
        "command": "scan", "expected": "failure", "exit_code": str(len(hits)),
        "outcome": "AS_EXPECTED" if not hits else "UNEXPECTED", "needs_auth": "no",
        "note": "no hits" if not hits else f"{len(hits)} files (paths withheld)",
    })
    r.write_tsv(results / f"owner-{step}-checks.tsv", runner.rows)
    r.write_tsv(results / f"owner-{step}-reconcile.tsv", reconcile_rows)
    if release_rows:
        r.write_tsv(results / f"owner-{step}-release-verify.tsv", release_rows)
    unexpected = [row["case"] for row in runner.rows if row["outcome"] == "UNEXPECTED"]
    mismatched = [row["case"] for row in reconcile_rows + release_rows if row.get("all_match") != "yes"]
    print(f"cases={len(runner.rows)} unexpected={','.join(unexpected) or 'none'} "
          f"reconcile_mismatch={','.join(mismatched) or 'none'} token_hits={len(hits)}")
    return 0


def step2(args: argparse.Namespace) -> int:
    """Protocol step 2: mutable release with build provenance; v0.1.0 stays immutable."""
    for variable in r.TOKEN_VARIABLES:
        os.environ.pop(variable, None)
    work = pathlib.Path(args.work)
    results = pathlib.Path(args.results)
    raw = work / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    token = read_token(pathlib.Path(args.token_file))
    repo, tag = args.repo, args.tag or "v0.2.0-mutable"
    signer_workflow = args.signer_workflow or f"{repo}/.github/workflows/mutable-attested.yml"
    other_workflow = f"{repo}/.github/workflows/immutable-release.yml"
    other_repo = f"{args.other_owner}/{repo.split('/')[1]}"

    api = r.Api(raw)
    status, limits = api.get("/rate_limit", "rate_limit_before.json", counted=False)
    remaining = (limits or {}).get("resources", {}).get("core", {}).get("remaining", 0)
    if status != 200 or remaining < 14:
        r.die(f"anonymous core rate limit too low (status {status}, remaining {remaining})")
    decode = r.load_snappy_decoder()
    target = r.collect_release(api, decode, work, repo, tag, lambda n: n.endswith(".deb"), "s2")
    # The step 1 release, recorded again after immutability was disabled.
    previous = r.collect_release(api, decode, work, repo, args.previous_tag, lambda n: False, "s1-after")
    status, immutability = api.get(f"/repos/{repo}/immutable-releases", "immutable-releases.json")
    api.get("/rate_limit", "rate_limit_after.json", counted=False)
    target["previous_release"] = previous
    target["immutable_setting_anonymous_status"] = status
    target["collected_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    target["api_requests_counted"] = api.count
    (work / "collect.json").write_text(json.dumps(target, indent=2) + "\n")
    if len(target["assets"]) != 1:
        r.die(f"expected exactly one .deb asset, found {len(target['assets'])}")
    asset = target["assets"][0]

    rows = [{"target": "s2", "field": k, "value": "" if target[k] is None else str(target[k])} for k in RELEASE_FIELDS]
    rows += [{"target": "s1-after", "field": k, "value": "" if previous[k] is None else str(previous[k])}
             for k in ("release_id", "release_tag", "release_immutable", "all_release_asset_digests")]
    rows += [{"target": "run", "field": k, "value": str(target[k])}
             for k in ("immutable_setting_anonymous_status", "api_requests_counted", "collected_at")]
    r.write_tsv(results / "owner-step2-release.tsv", rows)
    r.write_tsv(results / "owner-step2-assets.tsv", [asset_row(asset)])
    r.write_tsv(results / "owner-step2-attestations.tsv", attestation_rows(target, work / "bundles"))

    downloads = work / "downloads"
    negatives = work / "negatives"
    negatives.mkdir(exist_ok=True)
    file = downloads / asset["local"]
    by_kind = split_by_predicate(work / "bundles" / asset["bundle_file"], negatives, "asset")
    slsa = by_kind.get(r.SLSA_V1)
    runner = r.Runner(work, args.gh)

    def online(case, description, argv, expect_success, offline_namespace=False):
        runner.env["GH_TOKEN"] = token
        try:
            return runner.run(case, description, argv, expect_success, offline_namespace=offline_namespace)
        finally:
            runner.env.pop("GH_TOKEN", None)

    result = runner.run("trusted-root", "fetch the Sigstore trusted root through TUF",
                        ["attestation", "trusted-root"], expect_success=True)
    trusted_root = work / "trusted-root.jsonl"
    trusted_root.write_text(result.stdout)
    if result.returncode != 0 or not result.stdout.strip() or not slsa:
        r.write_tsv(results / "owner-step2-checks.tsv", runner.rows)
        r.die("trusted root unavailable or the asset has no build provenance")
    root = ["--custom-trusted-root", str(trusted_root)]
    base = ["attestation", "verify"]
    offline = ["--bundle", str(slsa), *root]
    commit = target["tag_commit"]
    expected = {
        "repository_id": target["repository_id"], "owner_id": target["owner_id"],
        "sha256": asset["downloaded_sha256"], "api_digest": asset["api_digest"],
        "source_ref": args.source_ref, "commit": commit,
    }
    reconcile_rows: list[dict[str, str]] = []
    changed = negatives / ("changed-byte-" + file.name)
    r.tampered_copy(file, changed)
    signer_uri = f"https://github.com/{signer_workflow}@{args.source_ref}"

    result = runner.run("P2-provenance-strict", "offline: repo, signer workflow, ref, commit, issuer, predicate, hosted runner pinned",
                        [*base, str(file), "--repo", repo, *offline, "--signer-workflow", signer_workflow,
                         "--source-ref", args.source_ref, "--source-digest", commit, "--cert-oidc-issuer", r.GITHUB_OIDC,
                         "--predicate-type", r.SLSA_V1, "--deny-self-hosted-runners", "--format", "json"], expect_success=True)
    if result.returncode == 0:
        reconcile_rows += r.reconcile("P2-provenance-strict", json.loads(result.stdout), expected)
    runner.run("P2-offline-netns", "offline verify inside a namespace without network",
               [*base, str(file), "--repo", repo, *offline], expect_success=True, offline_namespace=True)
    runner.run("P2-cert-identity", "exact certificate identity as observed (control for N2-cert-identity)",
               [*base, str(file), "--repo", repo, *offline, "--cert-identity", signer_uri], expect_success=True)
    runner.run("N2-changed-byte", "one flipped byte in the asset",
               [*base, str(changed), "--repo", repo, *offline], expect_success=False)
    runner.run("N2-repo-fork-name", "expected repository set to a fork-like name under the same owner",
               [*base, str(file), "--repo", f"{repo}-fork", *offline], expect_success=False)
    runner.run("N2-repo-other-owner", "same repository name under the test organization",
               [*base, str(file), "--repo", other_repo, *offline], expect_success=False)
    runner.run("N2-owner-other", "expected owner set to the test organization",
               [*base, str(file), "--owner", args.other_owner, *offline], expect_success=False)
    runner.run("N2-signer-other-workflow", "signer workflow set to the repository's immutable-release workflow",
               [*base, str(file), "--repo", repo, *offline, "--signer-workflow", other_workflow], expect_success=False)
    runner.run("N2-signer-repo", "signer workflow required from the organization's repository",
               [*base, str(file), "--repo", repo, *offline, "--signer-repo", other_repo], expect_success=False)
    runner.run("N2-cert-identity", "exact certificate identity with another ref",
               [*base, str(file), "--repo", repo, *offline, "--cert-identity",
                f"https://github.com/{signer_workflow}@refs/heads/pakomichi-r003-other"], expect_success=False)
    runner.run("N2-oidc-issuer", "wrong OIDC issuer",
               [*base, str(file), "--repo", repo, *offline, "--cert-oidc-issuer",
                "https://token.actions.githubusercontent.com/pakomichi-r003"], expect_success=False)
    runner.run("N2-source-ref-tag", "source ref set to the release tag (the run was dispatched on a branch)",
               [*base, str(file), "--repo", repo, *offline, "--source-ref", f"refs/tags/{tag}"], expect_success=False)
    runner.run("N2-source-digest", "wrong source commit",
               [*base, str(file), "--repo", repo, *offline, "--source-digest", "0" * 40], expect_success=False)
    runner.run("N2-predicate-release", "release-attestation predicate required for a mutable release",
               [*base, str(file), "--repo", repo, *offline, "--predicate-type", r.RELEASE_V02], expect_success=False)

    foreign = negatives / "not-in-release.deb"
    foreign.write_bytes(b"pakomichi-r003: bytes that are not a release asset\n")
    runner.run("N2-digest-not-in-release", "artifact whose digest is not a release asset digest",
               [*base, str(foreign), "--repo", repo, *offline], expect_success=False)
    empty = negatives / "empty.jsonl"
    empty.write_text("")
    runner.run("N2-missing-provenance", "empty bundle file (no provenance)",
               [*base, str(file), "--repo", repo, "--bundle", str(empty), *root], expect_success=False)
    original = json.loads(slsa.read_text().splitlines()[0])
    forged = json.loads(json.dumps(original))
    statement = json.loads(base64.b64decode(forged["dsseEnvelope"]["payload"]))
    changed_digest = r.sha256_file(changed)
    for subject in statement.get("subject", []):
        if subject.get("digest", {}).get("sha256") == asset["downloaded_sha256"]:
            subject["digest"]["sha256"] = changed_digest
    forged["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    forged_file = negatives / "forged-subject.jsonl"
    forged_file.write_text(json.dumps(forged, separators=(",", ":")) + "\n")
    runner.run("N2-forged-payload", "DSSE payload rewritten to the changed asset digest",
               [*base, str(changed), "--repo", repo, "--bundle", str(forged_file), *root], expect_success=False)
    no_ca = negatives / "trusted-root-no-ca.jsonl"
    with no_ca.open("w") as handle:
        for line in trusted_root.read_text().splitlines():
            if line.strip():
                item = json.loads(line)
                item["certificateAuthorities"] = []
                handle.write(json.dumps(item, separators=(",", ":")) + "\n")
    runner.run("N2-untrusted-root", "custom trusted root without the Fulcio certificate authorities",
               [*base, str(file), "--repo", repo, "--bundle", str(slsa), "--custom-trusted-root", str(no_ca)],
               expect_success=False)

    result = online("A2-attestation-online", "online: API lookup by digest, signer workflow pinned",
                    [*base, str(file), "--repo", repo, "--signer-workflow", signer_workflow,
                     "--predicate-type", r.SLSA_V1, "--format", "json"], expect_success=True)
    if result.returncode == 0:
        reconcile_rows += r.reconcile("A2-attestation-online", json.loads(result.stdout), expected)
    online("A2-attestation-online-netns", "online verify with the token but without network",
           [*base, str(file), "--repo", repo], expect_success=False, offline_namespace=True)
    online("AN2-release-verify", "online: gh release verify for a mutable release (no release attestation)",
           ["release", "verify", tag, "--repo", repo, "--format", "json"], expect_success=False)
    online("AN2-release-verify-asset", "online: gh release verify-asset for a mutable release",
           ["release", "verify-asset", tag, str(file), "--repo", repo, "--format", "json"], expect_success=False)
    online("AN2-verify-asset-cross-release", "online: the v0.2.0 asset checked against the immutable v0.1.0 release",
           ["release", "verify-asset", args.previous_tag, str(file), "--repo", repo, "--format", "json"],
           expect_success=False)
    online("A2-previous-release-verify", "online: v0.1.0 still verifies after immutability was disabled",
           ["release", "verify", args.previous_tag, "--repo", repo, "--format", "json"], expect_success=True)
    return finish(runner, token, work, results, "step2", reconcile_rows, [])


def step3(args: argparse.Namespace) -> int:
    """Protocol step 3: the step 2 asset was replaced by a rebuilt file without attestation."""
    for variable in r.TOKEN_VARIABLES:
        os.environ.pop(variable, None)
    work = pathlib.Path(args.work)
    results = pathlib.Path(args.results)
    raw = work / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    token = read_token(pathlib.Path(args.token_file))
    repo, tag = args.repo, args.tag or "v0.2.0-mutable"
    baseline_dir = pathlib.Path(args.baseline)
    baseline = json.loads((baseline_dir / "collect.json").read_text())
    if baseline["release_tag"] != tag or len(baseline["assets"]) != 1:
        r.die("baseline does not describe the step 2 release")
    old = baseline["assets"][0]
    old_file = baseline_dir / "downloads" / old["local"]
    old_bundle = baseline_dir / "bundles" / old["bundle_file"]
    if r.sha256_file(old_file) != old["downloaded_sha256"]:
        r.die("baseline asset no longer matches its recorded digest")

    api = r.Api(raw)
    status, limits = api.get("/rate_limit", "rate_limit_before.json", counted=False)
    remaining = (limits or {}).get("resources", {}).get("core", {}).get("remaining", 0)
    if status != 200 or remaining < 10:
        r.die(f"anonymous core rate limit too low (status {status}, remaining {remaining})")
    target = r.collect_release(api, r.load_snappy_decoder(), work, repo, tag, lambda n: n.endswith(".deb"), "s3")
    old_status, _ = api.get(f"/repos/{repo}/releases/assets/{old['asset_id']}", "old-asset.json")
    old_att_status, old_att = api.get(f"/repos/{repo}/attestations/{old['api_digest']}?per_page=100",
                                      "old-digest-attestations.json")
    api.get("/rate_limit", "rate_limit_after.json", counted=False)
    target["collected_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    target["api_requests_counted"] = api.count
    (work / "collect.json").write_text(json.dumps(target, indent=2) + "\n")
    if len(target["assets"]) != 1:
        r.die(f"expected exactly one .deb asset, found {len(target['assets'])}")
    new = target["assets"][0]
    release_json = json.loads((raw / "s3-release.json").read_text())
    meta = {a["id"]: a for a in release_json.get("assets", [])}.get(new["asset_id"], {})
    old_bundles = len((old_att or {}).get("attestations", [])) if isinstance(old_att, dict) else 0

    comparison = [
        ("release_id", baseline["release_id"], target["release_id"], target["release_id"] == baseline["release_id"]),
        ("release_immutable", baseline["release_immutable"], target["release_immutable"], target["release_immutable"] is False),
        ("tag_commit", baseline["tag_commit"], target["tag_commit"], target["tag_commit"] == baseline["tag_commit"]),
        ("asset_name", old["name"], new["name"], new["name"] == old["name"]),
        ("asset_id", old["asset_id"], new["asset_id"], new["asset_id"] != old["asset_id"]),
        ("asset_sha256", old["downloaded_sha256"], new["downloaded_sha256"], new["downloaded_sha256"] != old["downloaded_sha256"]),
        ("api_digest_matches_download", "", new["api_digest"], new["api_digest"] == "sha256:" + new["downloaded_sha256"]),
        ("expected_rebuild_sha256", args.expected_sha256, new["downloaded_sha256"],
         new["downloaded_sha256"] == args.expected_sha256 if args.expected_sha256 else None),
        ("new_asset_attestations", "", new["bundle_count"], new["bundle_count"] == 0),
        ("new_asset_uploader", "", (meta.get("uploader") or {}).get("login", ""), None),
        ("new_asset_created_at", "", meta.get("created_at", ""), None),
        ("old_asset_lookup_http", "", old_status, old_status == 404),
        ("old_digest_attestation_http", "", old_att_status, None),
        ("old_digest_attestations_remaining", old["bundle_count"], old_bundles, None),
    ]
    r.write_tsv(results / "owner-step3-replacement.tsv", [
        {"field": name, "step2": "" if before is None else str(before), "step3": "" if after is None else str(after),
         "expected": "observe" if ok is None else ("yes" if ok else "NO")}
        for name, before, after, ok in comparison
    ])
    r.write_tsv(results / "owner-step3-assets.tsv", [asset_row(new)])

    negatives = work / "negatives"
    negatives.mkdir(exist_ok=True)
    file = work / "downloads" / new["local"]
    runner = r.Runner(work, args.gh)

    def online(case, description, argv, expect_success):
        runner.env["GH_TOKEN"] = token
        try:
            return runner.run(case, description, argv, expect_success)
        finally:
            runner.env.pop("GH_TOKEN", None)

    result = runner.run("trusted-root", "fetch the Sigstore trusted root through TUF",
                        ["attestation", "trusted-root"], expect_success=True)
    trusted_root = work / "trusted-root.jsonl"
    trusted_root.write_text(result.stdout)
    if result.returncode != 0 or not result.stdout.strip():
        r.write_tsv(results / "owner-step3-checks.tsv", runner.rows)
        r.die("gh attestation trusted-root failed")
    root = ["--custom-trusted-root", str(trusted_root)]
    signer_workflow = f"{repo}/.github/workflows/mutable-attested.yml"

    runner.run("N3-new-with-old-bundle", "offline: replaced asset against the step 2 bundle",
               ["attestation", "verify", str(file), "--repo", repo, "--bundle", str(old_bundle), *root],
               expect_success=False)
    runner.run("P3-old-with-old-bundle", "offline: step 2 asset against its own bundle still verifies",
               ["attestation", "verify", str(old_file), "--repo", repo, "--bundle", str(old_bundle), *root,
                "--signer-workflow", signer_workflow], expect_success=True)
    online("AN3-new-online", "online: replaced asset by API lookup (no attestation exists)",
           ["attestation", "verify", str(file), "--repo", repo, "--format", "json"], expect_success=False)
    online("O3-old-online", "online: the removed step 2 asset by API lookup (does its attestation outlive the asset?)",
           ["attestation", "verify", str(old_file), "--repo", repo, "--signer-workflow", signer_workflow,
            "--format", "json"], expect_success=None)
    online("AN3-release-verify-asset", "online: verify-asset on the mutable release with the replaced asset",
           ["release", "verify-asset", tag, str(file), "--repo", repo, "--format", "json"], expect_success=False)
    return finish(runner, token, work, results, "step3", [], [])


ORIGINAL_REPO = "kroxiksut/pchi-test"
ORIGINAL_ID = 1429109739


def prepare(args: argparse.Namespace, min_remaining: int):
    for variable in r.TOKEN_VARIABLES:
        os.environ.pop(variable, None)
    work = pathlib.Path(args.work)
    results = pathlib.Path(args.results)
    raw = work / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    token = read_token(pathlib.Path(args.token_file))
    api = r.Api(raw)
    status, limits = api.get("/rate_limit", "rate_limit_before.json", counted=False)
    remaining = (limits or {}).get("resources", {}).get("core", {}).get("remaining", 0)
    if status != 200 or remaining < min_remaining:
        r.die(f"anonymous core rate limit too low (status {status}, remaining {remaining}, need {min_remaining})")
    runner = r.Runner(work, args.gh)
    return work, results, raw, token, api, runner


def online_runner(runner, token):
    def online(case, description, argv, expect_success):
        runner.env["GH_TOKEN"] = token
        try:
            return runner.run(case, description, argv, expect_success)
        finally:
            runner.env.pop("GH_TOKEN", None)
    return online


def fetch_root(runner, work: pathlib.Path, results: pathlib.Path, step: str) -> list[str]:
    result = runner.run("trusted-root", "fetch the Sigstore trusted root through TUF",
                        ["attestation", "trusted-root"], expect_success=True)
    path = work / "trusted-root.jsonl"
    path.write_text(result.stdout)
    if result.returncode != 0 or not result.stdout.strip():
        r.write_tsv(results / f"owner-{step}-checks.tsv", runner.rows)
        r.die("gh attestation trusted-root failed")
    return ["--custom-trusted-root", str(path)]


def name_row(api, label: str, name: str, cert_repo_id: int, cert_owner_id: int) -> dict[str, str]:
    status, data = api.get(f"/repos/{name}", f"name-{safe(name)}.json")
    data = data if isinstance(data, dict) else {}
    current_id = data.get("id")
    owner_id = (data.get("owner") or {}).get("id")
    return {
        "label": label,
        "requested_name": name,
        "http_status": str(status),
        "resolved_full_name": str(data.get("full_name", "")),
        "resolved_repository_id": "" if current_id is None else str(current_id),
        "resolved_owner_id": "" if owner_id is None else str(owner_id),
        "fork": str(data.get("fork", "")),
        "parent_repository_id": str((data.get("parent") or {}).get("id", "")),
        "redirected": "yes" if data.get("full_name") and data["full_name"].lower() != name.lower() else "no",
        "same_repository_as_certificate": ("yes" if current_id == cert_repo_id else "NO") if current_id else "n/a",
        "same_owner_as_certificate": ("yes" if owner_id == cert_owner_id else "NO") if owner_id else "n/a",
    }


def safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def step4(args: argparse.Namespace) -> int:
    """Protocol step 4: the same cases after rename, name reuse, and transfer."""
    phase = args.phase
    if phase not in ("rename", "reuse", "transfer", "transfer-back", "capture"):
        r.die("step4 needs --phase rename|reuse|transfer|transfer-back|capture")
    if phase == "capture":
        return step4_capture(args)
    step = f"step4-{phase}"
    work, results, raw, token, api, runner = prepare(args, 7)
    online = online_runner(runner, token)
    step1_dir = pathlib.Path(args.step1_run)
    s1 = json.loads((step1_dir / "collect.json").read_text())
    s1_asset = s1["assets"][0]
    s1_file = step1_dir / "downloads" / s1_asset["local"]
    s1_slsa = step1_dir / "negatives" / "asset-https-slsa-dev-provenance-v1.jsonl"
    if r.sha256_file(s1_file) != s1_asset["downloaded_sha256"] or not s1_slsa.is_file():
        r.die("step 1 evidence is missing or changed")
    cert_repo_id, cert_owner_id = s1["repository_id"], s1["owner_id"]

    status, by_id = api.get(f"/repositories/{cert_repo_id}", "repository-by-id.json")
    by_id = by_id if isinstance(by_id, dict) else {}
    current = by_id.get("full_name", "")
    if not current:
        r.die(f"repository {cert_repo_id} not resolvable by ID (HTTP {status})")
    release_status, release = api.get(f"/repositories/{cert_repo_id}/releases/tags/{s1['release_tag']}",
                                      "release-by-id.json")
    release = release if isinstance(release, dict) else {}
    names = [("original name", ORIGINAL_REPO), ("current name", current)]
    if args.extra_name:
        names.append(("extra name", args.extra_name))
    rows = [name_row(api, label, name, cert_repo_id, cert_owner_id) for label, name in names]
    rows.append({
        "label": "by repository ID", "requested_name": f"/repositories/{cert_repo_id}", "http_status": str(status),
        "resolved_full_name": current, "resolved_repository_id": str(by_id.get("id", "")),
        "resolved_owner_id": str((by_id.get("owner") or {}).get("id", "")), "fork": str(by_id.get("fork", "")),
        "parent_repository_id": "", "redirected": "n/a",
        "same_repository_as_certificate": "yes" if by_id.get("id") == cert_repo_id else "NO",
        "same_owner_as_certificate": "yes" if (by_id.get("owner") or {}).get("id") == cert_owner_id else "NO",
    })
    rows.append({
        "label": "step 1 release by repository ID", "requested_name": s1["release_tag"],
        "http_status": str(release_status), "resolved_full_name": "",
        "resolved_repository_id": str(release.get("id", "")), "resolved_owner_id": "",
        "fork": "", "parent_repository_id": "", "redirected": "n/a",
        "same_repository_as_certificate": "n/a",
        "same_owner_as_certificate": f"immutable={release.get('immutable')}",
    })
    api.get("/rate_limit", "rate_limit_after.json", counted=False)
    r.write_tsv(results / f"owner-{step}-names.tsv", rows)

    root = fetch_root(runner, work, results, step)
    offline = ["--bundle", str(s1_slsa), *root]
    for label, name in names:
        key = "old" if name == ORIGINAL_REPO else ("current" if name == current else "extra")
        runner.run(f"O4-offline-{key}-name", f"offline: step 1 provenance with --repo {label} ({name})",
                   ["attestation", "verify", str(s1_file), "--repo", name, *offline], expect_success=None)
    runner.run("O4-offline-current-signer", "offline: signer workflow under the current name",
               ["attestation", "verify", str(s1_file), "--repo", ORIGINAL_REPO, *offline,
                "--signer-workflow", f"{current}/.github/workflows/immutable-release.yml"], expect_success=None)
    for label, name in names:
        key = "old" if name == ORIGINAL_REPO else ("current" if name == current else "extra")
        online(f"O4-online-{key}-name", f"online: attestation lookup with --repo {label} ({name})",
               ["attestation", "verify", str(s1_file), "--repo", name, "--format", "json"], expect_success=None)
        online(f"O4-release-verify-{key}-name", f"online: gh release verify {s1['release_tag']} -R {label} ({name})",
               ["release", "verify", s1["release_tag"], "--repo", name, "--format", "json"], expect_success=None)
    return finish(runner, token, work, results, step, [], [])


def step4_capture(args: argparse.Namespace) -> int:
    """Step 4, name capture: the repository that took the old name publishes its own attested release.

    A source pinned by name accepts it; only the repository ID of the original pin rejects it.
    """
    step = "step4-capture"
    work, results, raw, token, api, runner = prepare(args, 10)
    online = online_runner(runner, token)
    s1 = json.loads((pathlib.Path(args.step1_run) / "collect.json").read_text())
    pin_repo_id, pin_owner_id = s1["repository_id"], s1["owner_id"]
    holder, tag = args.repo, args.tag
    target = r.collect_release(api, r.load_snappy_decoder(), work, holder, tag, lambda n: n.endswith(".deb"), "s4c")
    status, original = api.get(f"/repositories/{pin_repo_id}", "original-by-id.json")
    original = original if isinstance(original, dict) else {}
    status, holder_data = api.get(f"/repos/{holder}", "holder-repository.json")
    holder_data = holder_data if isinstance(holder_data, dict) else {}
    api.get("/rate_limit", "rate_limit_after.json", counted=False)
    (work / "collect.json").write_text(json.dumps(target, indent=2) + "\n")
    if len(target["assets"]) != 1:
        r.die(f"expected exactly one .deb asset, found {len(target['assets'])}")
    asset = target["assets"][0]
    original_name = original.get("full_name", "")
    facts = [
        ("pinned_name", ORIGINAL_REPO),
        ("pinned_repository_id", pin_repo_id),
        ("pinned_owner_id", pin_owner_id),
        ("holder_full_name", holder_data.get("full_name")),
        ("holder_repository_id", holder_data.get("id")),
        ("holder_owner_id", (holder_data.get("owner") or {}).get("id")),
        ("holder_fork_flag", holder_data.get("fork")),
        ("original_current_name", original_name),
        ("original_current_owner_id", (original.get("owner") or {}).get("id")),
        ("holder_release_id", target["release_id"]),
        ("holder_release_tag", target["release_tag"]),
        ("holder_tag_commit", target["tag_commit"]),
        ("api_requests_counted", api.count),
    ]
    r.write_tsv(results / f"owner-{step}-release.tsv", [{"field": k, "value": "" if v is None else str(v)} for k, v in facts])
    r.write_tsv(results / f"owner-{step}-assets.tsv", [asset_row(asset)])
    r.write_tsv(results / f"owner-{step}-attestations.tsv", attestation_rows(target, work / "bundles"))

    negatives = work / "negatives"
    negatives.mkdir(exist_ok=True)
    file = work / "downloads" / asset["local"]
    slsa = split_by_predicate(work / "bundles" / asset["bundle_file"], negatives, "asset").get(r.SLSA_V1)
    root = fetch_root(runner, work, results, step)
    if not slsa:
        r.write_tsv(results / f"owner-{step}-checks.tsv", runner.rows)
        r.die("the holder's asset has no build provenance")
    offline = ["--bundle", str(slsa), *root]
    reconcile_rows: list[dict[str, str]] = []
    pin_rows: list[dict[str, str]] = []
    result = runner.run("C4-pinned-name", f"offline: the holder's asset with --repo {ORIGINAL_REPO}, the name pinned at admission",
                        ["attestation", "verify", str(file), "--repo", ORIGINAL_REPO, *offline, "--format", "json"],
                        expect_success=None)
    if result.returncode == 0:
        verification = json.loads(result.stdout)
        # Against the holder's own facts every field must match: it is genuinely its build.
        reconcile_rows += r.reconcile("C4-holder-own-ids", verification, {
            "repository_id": holder_data.get("id"), "owner_id": (holder_data.get("owner") or {}).get("id"),
            "sha256": asset["downloaded_sha256"], "api_digest": asset["api_digest"],
            "source_ref": args.source_ref, "commit": target["tag_commit"],
        })
        # Against the original pin: the repository ID must fail; the owner ID is the same account.
        pin_rows += r.reconcile("C4-holder-vs-pin", verification, {
            "repository_id": pin_repo_id, "owner_id": pin_owner_id,
            "sha256": asset["downloaded_sha256"], "api_digest": asset["api_digest"],
            "source_ref": args.source_ref, "commit": target["tag_commit"],
        })
    runner.run("C4-pinned-signer-workflow", "offline: signer workflow path of the original under the pinned name",
               ["attestation", "verify", str(file), "--repo", ORIGINAL_REPO, *offline,
                "--signer-workflow", f"{ORIGINAL_REPO}/.github/workflows/mutable-attested.yml"], expect_success=None)
    runner.run("C4-owner-only", "offline: --owner of the pinned name (owner-only binding)",
               ["attestation", "verify", str(file), "--owner", ORIGINAL_REPO.split("/")[0], *offline], expect_success=None)
    if original_name:
        runner.run("N4C-original-current-name", f"offline: the holder's asset with --repo of the original ({original_name})",
                   ["attestation", "verify", str(file), "--repo", original_name, *offline], expect_success=False)
    online("A4C-online-pinned-name", f"online: attestation lookup with --repo {ORIGINAL_REPO}",
           ["attestation", "verify", str(file), "--repo", ORIGINAL_REPO, "--format", "json"], expect_success=None)
    # Expected to mismatch on the repository ID: written apart from finish().
    r.write_tsv(results / f"owner-{step}-reconcile-vs-pin.tsv", pin_rows)
    return finish(runner, token, work, results, step, reconcile_rows, [])


def step5(args: argparse.Namespace) -> int:
    """Protocol step 5: a fork publishes a higher version with the same asset name."""
    step = "step5"
    work, results, raw, token, api, runner = prepare(args, 9)
    online = online_runner(runner, token)
    fork, tag = args.repo, args.tag
    target = r.collect_release(api, r.load_snappy_decoder(), work, fork, tag, lambda n: n.endswith(".deb"), "s5")
    status, original = api.get(f"/repositories/{ORIGINAL_ID}", "original-by-id.json")
    original = original if isinstance(original, dict) else {}
    status, fork_data = api.get(f"/repos/{fork}", "fork-repository.json")
    fork_data = fork_data if isinstance(fork_data, dict) else {}
    api.get("/rate_limit", "rate_limit_after.json", counted=False)
    (work / "collect.json").write_text(json.dumps(target, indent=2) + "\n")
    if len(target["assets"]) != 1:
        r.die(f"expected exactly one .deb asset, found {len(target['assets'])}")
    asset = target["assets"][0]
    original_name = original.get("full_name", "")
    facts = [
        ("fork_full_name", fork_data.get("full_name")),
        ("fork_repository_id", fork_data.get("id")),
        ("fork_owner_id", (fork_data.get("owner") or {}).get("id")),
        ("fork_flag", fork_data.get("fork")),
        ("fork_parent_id", (fork_data.get("parent") or {}).get("id")),
        ("fork_source_id", (fork_data.get("source") or {}).get("id")),
        ("original_full_name", original_name),
        ("original_repository_id", original.get("id")),
        ("original_owner_id", (original.get("owner") or {}).get("id")),
        ("fork_release_id", target["release_id"]),
        ("fork_release_tag", target["release_tag"]),
        ("fork_tag_commit", target["tag_commit"]),
        ("api_requests_counted", api.count),
    ]
    r.write_tsv(results / "owner-step5-release.tsv", [{"field": k, "value": "" if v is None else str(v)} for k, v in facts])
    r.write_tsv(results / "owner-step5-assets.tsv", [asset_row(asset)])
    r.write_tsv(results / "owner-step5-attestations.tsv", attestation_rows(target, work / "bundles"))

    negatives = work / "negatives"
    negatives.mkdir(exist_ok=True)
    file = work / "downloads" / asset["local"]
    slsa = split_by_predicate(work / "bundles" / asset["bundle_file"], negatives, "asset").get(r.SLSA_V1)
    root = fetch_root(runner, work, results, step)
    if not slsa:
        r.write_tsv(results / "owner-step5-checks.tsv", runner.rows)
        r.die("the fork asset has no build provenance")
    offline = ["--bundle", str(slsa), *root]
    reconcile_rows: list[dict[str, str]] = []
    result = runner.run("P5-fork-own-repo", "offline: the fork asset against the fork itself (it is genuinely the fork's build)",
                        ["attestation", "verify", str(file), "--repo", fork, *offline, "--format", "json"], expect_success=True)
    if result.returncode == 0:
        # Reconcile against the ORIGINAL repository: every ID check must fail.
        reconcile_rows += r.reconcile("P5-fork-vs-original-ids", json.loads(result.stdout), {
            "repository_id": ORIGINAL_ID, "owner_id": (original.get("owner") or {}).get("id"),
            "sha256": asset["downloaded_sha256"], "api_digest": asset["api_digest"],
            "source_ref": args.source_ref, "commit": target["tag_commit"],
        })
    for case, name in (("N5-original-current-name", original_name), ("N5-original-old-name", ORIGINAL_REPO)):
        runner.run(case, f"offline: the fork asset with --repo {name}",
                   ["attestation", "verify", str(file), "--repo", name, *offline], expect_success=False)
    runner.run("N5-original-signer-workflow", "offline: signer workflow of the original repository",
               ["attestation", "verify", str(file), "--repo", fork, *offline,
                "--signer-workflow", f"{original_name}/.github/workflows/mutable-attested.yml"], expect_success=False)
    runner.run("N5-original-owner", "offline: --owner of the original repository",
               ["attestation", "verify", str(file), "--owner", original_name.split("/")[0], *offline], expect_success=False)
    runner.run("O5-fork-owner-only", "offline: --owner of the fork (owner-only binding accepts the fork)",
               ["attestation", "verify", str(file), "--owner", fork.split("/")[0], *offline], expect_success=None)
    online("AN5-online-original", "online: the fork asset with --repo of the original",
           ["attestation", "verify", str(file), "--repo", original_name, "--format", "json"], expect_success=False)
    online("AN5-release-verify-asset-original", "online: the fork asset against the original's immutable v0.1.0",
           ["release", "verify-asset", "v0.1.0", str(file), "--repo", original_name, "--format", "json"], expect_success=False)
    # Expected to mismatch on repository and owner ID: written apart from finish().
    r.write_tsv(results / "owner-step5-reconcile-vs-original.tsv", reconcile_rows)
    return finish(runner, token, work, results, step, [], [])


def step1(args: argparse.Namespace) -> int:
    for variable in r.TOKEN_VARIABLES:
        os.environ.pop(variable, None)
    work = pathlib.Path(args.work)
    results = pathlib.Path(args.results)
    raw = work / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    token = read_token(pathlib.Path(args.token_file))
    repo, tag = args.repo, args.tag
    signer_workflow = args.signer_workflow or f"{repo}/.github/workflows/immutable-release.yml"
    other_workflow = f"{repo}/.github/workflows/mutable-attested.yml"

    # Anonymous collection.
    api = r.Api(raw)
    status, limits = api.get("/rate_limit", "rate_limit_before.json", counted=False)
    remaining = (limits or {}).get("resources", {}).get("core", {}).get("remaining", 0)
    if status != 200 or remaining < 10:
        r.die(f"anonymous core rate limit too low (status {status}, remaining {remaining})")
    target = r.collect_release(api, r.load_snappy_decoder(), work, repo, tag, lambda n: n.endswith(".deb"), "s1")
    api.get("/rate_limit", "rate_limit_after.json", counted=False)
    target["collected_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    target["api_requests_counted"] = api.count
    (work / "collect.json").write_text(json.dumps(target, indent=2) + "\n")
    if len(target["assets"]) != 1:
        r.die(f"expected exactly one .deb asset, found {len(target['assets'])}")
    asset = target["assets"][0]

    downloads = work / "downloads"
    bundles_dir = work / "bundles"
    negatives = work / "negatives"
    negatives.mkdir(exist_ok=True)
    file = downloads / asset["local"]

    release_fields = (
        "repo", "repository_full_name", "repository_id", "owner_login", "owner_id", "fork",
        "release_id", "release_tag", "release_immutable", "release_draft", "release_prerelease",
        "release_published_at", "release_target_commitish", "tag_object_type", "tag_commit",
        "release_commit_attestation_status", "release_commit_bundle_count", "api_requests_counted", "collected_at",
    )
    r.write_tsv(results / "owner-step1-release.tsv",
                [{"field": k, "value": "" if target[k] is None else str(target[k])} for k in release_fields])
    r.write_tsv(results / "owner-step1-assets.tsv", [{
        "asset_id": str(asset["asset_id"]), "name": asset["name"], "size_api": str(asset["size_api"]),
        "size_downloaded": str(asset["size_downloaded"]), "api_digest": asset["api_digest"],
        "downloaded_sha256": asset["downloaded_sha256"],
        "digest_match": "yes" if asset["api_digest"] == "sha256:" + asset["downloaded_sha256"] else "NO",
        "attestation_http_status": str(asset["attestation_http_status"]), "bundle_count": str(asset["bundle_count"]),
        "attestation_repository_ids": ",".join(asset["attestation_repository_ids"]),
    }])
    r.write_tsv(results / "owner-step1-attestations.tsv", attestation_rows(target, bundles_dir))

    by_kind = split_by_predicate(bundles_dir / asset["bundle_file"], negatives, "asset")
    commit_kind = split_by_predicate(bundles_dir / target["release_commit_bundle_file"], negatives, "commit")
    slsa = by_kind.get(r.SLSA_V1)
    release_bundle = by_kind.get(r.RELEASE_V02) or commit_kind.get(r.RELEASE_V02)

    runner = r.Runner(work, args.gh)

    def online(case, description, argv, expect_success):
        runner.env["GH_TOKEN"] = token
        try:
            return runner.run(case, description, argv, expect_success)
        finally:
            runner.env.pop("GH_TOKEN", None)

    result = runner.run("trusted-root", "fetch the Sigstore trusted root through TUF",
                        ["attestation", "trusted-root"], expect_success=True)
    trusted_root = work / "trusted-root.jsonl"
    trusted_root.write_text(result.stdout)
    if result.returncode != 0 or not result.stdout.strip():
        r.write_tsv(results / "owner-step1-checks.tsv", runner.rows)
        r.die("gh attestation trusted-root failed")
    root = ["--custom-trusted-root", str(trusted_root)]
    changed = negatives / ("changed-byte-" + file.name)
    r.tampered_copy(file, changed)
    commit = target["tag_commit"]
    expected = {
        "repository_id": target["repository_id"], "owner_id": target["owner_id"],
        "sha256": asset["downloaded_sha256"], "api_digest": asset["api_digest"],
        "source_ref": args.source_ref, "commit": commit,
    }
    reconcile_rows: list[dict[str, str]] = []
    release_rows: list[dict[str, str]] = []

    if slsa:
        strict = ["--repo", repo, "--bundle", str(slsa), *root, "--signer-workflow", signer_workflow,
                  "--source-ref", args.source_ref, "--source-digest", commit, "--cert-oidc-issuer", r.GITHUB_OIDC,
                  "--predicate-type", r.SLSA_V1, "--deny-self-hosted-runners", "--format", "json"]
        result = runner.run("P1-provenance-strict", "offline: build provenance with repo, signer workflow, ref, commit, issuer, predicate, hosted runner pinned",
                            ["attestation", "verify", str(file), *strict], expect_success=True)
        if result.returncode == 0:
            reconcile_rows += r.reconcile("P1-provenance-strict", json.loads(result.stdout), expected)
        runner.run("P1-provenance-netns", "offline build provenance inside a namespace without network",
                   ["attestation", "verify", str(file), "--repo", repo, "--bundle", str(slsa), *root],
                   expect_success=True, offline_namespace=True)
        runner.run("N1-changed-byte", "offline: one flipped byte in the asset",
                   ["attestation", "verify", str(changed), "--repo", repo, "--bundle", str(slsa), *root], expect_success=False)
        runner.run("N1-signer-other-workflow", "offline: signer workflow set to the repository's mutable workflow",
                   ["attestation", "verify", str(file), "--repo", repo, "--bundle", str(slsa), *root,
                    "--signer-workflow", other_workflow], expect_success=False)
        runner.run("N1-source-ref-tag", "offline: source ref set to the release tag (the run was dispatched on a branch)",
                   ["attestation", "verify", str(file), "--repo", repo, "--bundle", str(slsa), *root,
                    "--source-ref", f"refs/tags/{tag}"], expect_success=False)
        runner.run("N1-repo-other-owner", "offline: same repository name under the test organization",
                   ["attestation", "verify", str(file), "--repo", f"{args.other_owner}/{repo.split('/')[1]}",
                    "--bundle", str(slsa), *root], expect_success=False)
    if release_bundle:
        runner.run("O1-release-default-policy", "offline: release attestation with the default --repo policy",
                   ["attestation", "verify", str(file), "--repo", repo, "--bundle", str(release_bundle), *root,
                    "--predicate-type", r.RELEASE_V02, "--format", "json"], expect_success=None)
        runner.run("O1-release-cert-identity", "offline: release attestation pinned to the GitHub releases signer identity",
                   ["attestation", "verify", str(file), "--repo", repo, "--bundle", str(release_bundle), *root,
                    "--predicate-type", r.RELEASE_V02, "--cert-identity", "https://dotcom.releases.github.com",
                    "--format", "json"], expect_success=None)

    runner.run("O1-release-verify-anonymous", "gh release verify without a token (does it need authentication?)",
               ["release", "verify", tag, "--repo", repo, "--format", "json"], expect_success=None)
    result = online("A1-release-verify", "online, read-only token: gh release verify",
                    ["release", "verify", tag, "--repo", repo, "--format", "json"], expect_success=True)
    if result.returncode == 0:
        release_rows += release_verify_rows("A1-release-verify", result.stdout, target, asset)
    result = online("A1-release-verify-asset", "online, read-only token: gh release verify-asset",
                    ["release", "verify-asset", tag, str(file), "--repo", repo, "--format", "json"], expect_success=True)
    if result.returncode == 0:
        release_rows += release_verify_rows("A1-release-verify-asset", result.stdout, target, asset)
    online("AN1-release-verify-asset-changed", "online: verify-asset with one flipped byte",
           ["release", "verify-asset", tag, str(changed), "--repo", repo, "--format", "json"], expect_success=False)
    online("AN1-release-verify-other-owner", "online: gh release verify against the same name under the test organization",
           ["release", "verify", tag, "--repo", f"{args.other_owner}/{repo.split('/')[1]}", "--format", "json"],
           expect_success=False)
    result = online("A1-attestation-online", "online: attestation verify by API lookup, signer workflow pinned",
                    ["attestation", "verify", str(file), "--repo", repo, "--signer-workflow", signer_workflow,
                     "--predicate-type", r.SLSA_V1, "--format", "json"], expect_success=True)
    if result.returncode == 0:
        reconcile_rows += r.reconcile("A1-attestation-online", json.loads(result.stdout), expected)

    # Negative test of the task: the token must not reach any log or result.
    hits = scan_for_token(token, [work, results])
    runner.rows.append({
        "case": "N1-token-not-logged", "description": "no file in the work or results directories contains the token",
        "command": "scan", "expected": "failure", "exit_code": str(len(hits)),
        "outcome": "AS_EXPECTED" if not hits else "UNEXPECTED", "needs_auth": "no",
        "note": "no hits" if not hits else f"{len(hits)} files (paths withheld)",
    })

    r.write_tsv(results / "owner-step1-checks.tsv", runner.rows)
    r.write_tsv(results / "owner-step1-reconcile.tsv", reconcile_rows)
    r.write_tsv(results / "owner-step1-release-verify.tsv", release_rows)
    unexpected = [row["case"] for row in runner.rows if row["outcome"] == "UNEXPECTED"]
    mismatched = [row["case"] for row in reconcile_rows + release_rows if row.get("all_match") != "yes"]
    print(f"cases={len(runner.rows)} unexpected={','.join(unexpected) or 'none'} "
          f"reconcile_mismatch={','.join(mismatched) or 'none'} token_hits={len(hits)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="stage", required=True)
    for name, default_tag in (("step1", "v0.1.0"), ("step2", "v0.2.0-mutable"), ("step3", "v0.2.0-mutable"),
                              ("step4", "v0.1.0"), ("step5", "v0.3.0-mutable")):
        stage = sub.add_parser(name)
        stage.add_argument("--work", required=True)
        stage.add_argument("--results", required=True)
        stage.add_argument("--gh", required=True)
        stage.add_argument("--token-file", required=True)
        stage.add_argument("--repo", default="kroxiksut/pchi-test")
        stage.add_argument("--tag", default=default_tag)
        stage.add_argument("--previous-tag", default="v0.1.0")
        stage.add_argument("--source-ref", default="refs/heads/main")
        stage.add_argument("--signer-workflow", default="")
        stage.add_argument("--other-owner", default="pchi-test-org")
        stage.add_argument("--baseline", default="", help="step3: raw directory of the step 2 run")
        stage.add_argument("--expected-sha256", default="", help="step3: digest of the local rebuild")
        stage.add_argument("--phase", default="", help="step4: rename|reuse|transfer|transfer-back|capture")
        stage.add_argument("--step1-run", default="", help="step4: raw directory of the step 1 run")
        stage.add_argument("--extra-name", default="", help="step4: another repository name to resolve")
    args = parser.parse_args()
    return {"step1": step1, "step2": step2, "step3": step3, "step4": step4, "step5": step5}[args.stage](args)


if __name__ == "__main__":
    sys.exit(main())
