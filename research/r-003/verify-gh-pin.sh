#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Verify a new GitHub CLI tarball before it becomes the R-003 oracle pin.
# Runs as root inside a bootstrapped pakomichi-r003-* distribution, uses the
# gh already installed there (the previous, verified pin) and anonymous API
# requests only; no token.
#
#   bash research/r-003/verify-gh-pin.sh 2.103.0
#
# Checks: the downloaded SHA-256 equals the release asset's API digest and its
# line in gh_<version>_checksums.txt; the SLSA build provenance verifies
# offline (--bundle, --custom-trusted-root); the verified certificate names
# cli/cli by ID, the exact deployment workflow and source ref, case-sensitively,
# the tag commit as the source digest,
# and a GitHub-hosted runner (gh <= 2.101.0 matches --signer-workflow as a
# prefix and --source-ref case-insensitively, GHSA-wjmr-j3rp-mh2g and
# GHSA-4mq3-hpgx-9cx8, so these are compared here); a changed byte fails.
# The release attestation is recorded (predicate IDs, tag, asset subject);
# gh has no offline path for it, so its signature is not checked here.
# Output: research/r-003/results/gh-pin-verify-<version>.tsv, raw files in
# .research-local/r-003/gh-pin/<version>/.
set -euo pipefail

readonly version="${1:?usage: verify-gh-pin.sh VERSION}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad version $version" >&2; exit 2; }
readonly gh="/opt/r003-gh/bin/gh"
readonly repository="cli/cli"
readonly repository_id="212613049"
readonly owner_id="59704711"
readonly workflow="https://github.com/cli/cli/.github/workflows/deployment.yml"
# cli/cli builds a release by a manual run of deployment.yml on trunk, so the
# signed source ref is the branch; the signed commit must be the tag commit.
readonly source_ref="refs/heads/trunk"
readonly tag="v$version"
readonly asset_name="gh_${version}_linux_amd64.tar.gz"

if [[ "$(id -u)" -ne 0 || "${WSL_DISTRO_NAME:-}" != pakomichi-r003-* ]]; then
    echo "run as root inside a pakomichi-r003-* distribution" >&2
    exit 2
fi
test -x "$gh"

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
readonly tools="$project_root/.research-local/r-003/tools"
readonly raw="$project_root/.research-local/r-003/gh-pin/$version"
readonly out="$project_root/research/r-003/results/gh-pin-verify-$version.tsv"
work="$(mktemp -d /tmp/pakomichi-r003-ghpin-XXXXXX)"
readonly work
trap 'rm -rf "$work"' EXIT
mkdir -p "$tools" "$raw"

api() {
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        --header 'Accept: application/vnd.github+json' \
        --header 'X-GitHub-Api-Version: 2022-11-28' \
        --output "$2" "https://api.github.com/$1"
}
download() {
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        --output "$2.part" "https://github.com/$repository/releases/download/$tag/$1"
    mv "$2.part" "$2"
}

api "repos/$repository/releases/tags/$tag" "$raw/release.json"
api "repos/$repository/git/ref/tags/$tag" "$raw/tag-ref.json"
tarball="$tools/$asset_name"
# A kept download is still checked against the API digest and checksums below.
[[ -f "$tarball" ]] || download "$asset_name" "$tarball"
download "gh_${version}_checksums.txt" "$raw/checksums.txt"
actual="$(sha256sum "$tarball" | awk '{print $1}')"
api "repos/$repository/attestations/sha256:$actual" "$raw/attestations-asset.json"
tag_ref="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["object"]["sha"])' "$raw/tag-ref.json")"
tag_type="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["object"]["type"])' "$raw/tag-ref.json")"
tag_commit="$tag_ref"
if [[ "$tag_type" == "tag" ]]; then
    api "repos/$repository/git/tags/$tag_ref" "$raw/tag-object.json"
    tag_commit="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["object"]["sha"])' "$raw/tag-object.json")"
fi
api "repos/$repository/attestations/sha1:$tag_ref?predicate_type=release" "$raw/attestations-release.json"

# Bundles for offline verification. The API may give `bundle_url` (Snappy)
# instead of an inline bundle; the P0-004 helper handles both.
readonly fetch_bundles="$project_root/prototypes/p0-004/fetch-attestation-bundles.py"
python3 -I "$fetch_bundles" "$raw/attestations-asset.json" "$raw/bundles.jsonl"
python3 -I "$fetch_bundles" "$raw/attestations-release.json" "$raw/release-bundles.jsonl"
export HOME="$work/home" XDG_CONFIG_HOME="$work/config" GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1
mkdir -p "$HOME" "$XDG_CONFIG_HOME"
"$gh" attestation trusted-root > "$raw/trusted-root.jsonl"
verify_status=0
"$gh" attestation verify "$tarball" --repo "$repository" \
    --signer-workflow "cli/cli/.github/workflows/deployment.yml" \
    --source-ref "$source_ref" --source-digest "$tag_commit" --deny-self-hosted-runners \
    --bundle "$raw/bundles.jsonl" --custom-trusted-root "$raw/trusted-root.jsonl" \
    --format json > "$raw/verification.json" 2> "$raw/verification.stderr" || verify_status=$?

cp "$tarball" "$work/changed.tar.gz"
printf '\001' | dd of="$work/changed.tar.gz" bs=1 seek=1000 conv=notrunc status=none
changed_status=0
"$gh" attestation verify "$work/changed.tar.gz" --repo "$repository" \
    --bundle "$raw/bundles.jsonl" --custom-trusted-root "$raw/trusted-root.jsonl" \
    > /dev/null 2>&1 || changed_status=$?

python3 -I - "$raw" "$out" "$version" "$actual" "$verify_status" "$changed_status" \
    "$repository_id" "$owner_id" "$workflow" "$tag" "$asset_name" "$tag_ref" \
    "$source_ref" "$tag_commit" \
    "$("$gh" --version | head -n 1)" <<'PY'
import base64, json, sys
(raw, out, version, actual, verify_status, changed_status, repository_id, owner_id,
 workflow, tag, asset_name, tag_ref, source_ref, tag_commit, oracle) = sys.argv[1:]
load = lambda name: json.load(open(f"{raw}/{name}", encoding="utf-8"))
release = load("release.json")
asset = next(a for a in release["assets"] if a["name"] == asset_name)
checksums = {}
for line in open(f"{raw}/checksums.txt", encoding="utf-8"):
    digest, name = line.split()
    checksums[name] = digest
rows = [("version", version), ("oracle", oracle), ("release_id", release["id"]),
        ("release_immutable", release.get("immutable")), ("asset_id", asset["id"]),
        ("tarball_sha256", actual), ("api_digest_match", asset.get("digest") == "sha256:" + actual),
        ("checksums_match", checksums.get(asset_name) == actual),
        ("gh_verify_exit", verify_status), ("changed_byte_exit", changed_status)]
exact = False
if verify_status == "0":
    for result in json.load(open(f"{raw}/verification.json", encoding="utf-8")):
        cert = result["verificationResult"]["signature"]["certificate"]
        subjects = result["verificationResult"]["statement"]["subject"]
        checks = {
            "cert_repository_id": cert.get("sourceRepositoryIdentifier") == repository_id,
            "cert_owner_id": cert.get("sourceRepositoryOwnerIdentifier") == owner_id,
            "cert_workflow_exact": cert.get("buildSignerURI", "").split("@", 1)
            == [workflow, source_ref],
            "cert_source_ref_exact": cert.get("sourceRepositoryRef") == source_ref,
            "cert_source_digest_is_tag_commit": cert.get("sourceRepositoryDigest") == tag_commit,
            "cert_hosted_runner": cert.get("runnerEnvironment") == "github-hosted",
            "subject_digest": any(s.get("digest", {}).get("sha256") == actual for s in subjects),
        }
        if all(checks.values()):
            exact = True
            rows += list(checks.items())
            rows.append(("cert_signer_uri", cert.get("buildSignerURI")))
            break
rows.append(("provenance_exact_match", exact))
bundles = [json.loads(line) for line in open(f"{raw}/release-bundles.jsonl", encoding="utf-8")
           if line.strip()]
rows.append(("release_attestations", len(bundles)))
for bundle in bundles:
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    predicate = statement["predicate"]
    rows += [("release_predicate_type", statement["predicateType"]),
             ("release_repository_id", predicate.get("repositoryId")),
             ("release_owner_id", predicate.get("ownerId")),
             ("release_database_id", predicate.get("databaseId")),
             ("release_tag", predicate.get("tag")),
             ("release_tag_ref_subject", any(s.get("digest", {}).get("sha1") == tag_ref
                                             for s in statement["subject"])),
             ("release_asset_subject", any(s.get("name") == asset_name
                                           and s.get("digest", {}).get("sha256") == actual
                                           for s in statement["subject"]))]
ok = (exact and changed_status != "0" and release.get("immutable") is True
      and asset.get("digest") == "sha256:" + actual and checksums.get(asset_name) == actual)
rows.append(("pin_ok", ok))
with open(out, "w", encoding="utf-8", newline="\n") as handle:
    handle.write("field\tvalue\n")
    for key, value in rows:
        handle.write(f"{key}\t{value}\n")
print(open(out, encoding="utf-8").read())
sys.exit(0 if ok else 1)
PY
