#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
# shellcheck source=paths.sh
source "$project_root/prototypes/p0-004/paths.sh"
readonly work="$project_root/.research-local/p0-004/github-attestation"
readonly version="2.95.0"
readonly expected_digest="25d1e4729e8808c9ed3d613e96ebd3f3e44446f2d368c89d878a71a36ddb3d8c"
readonly expected_repository_id="212613049"
readonly asset="$work/gh_${version}_linux_amd64.tar.gz"
readonly gh_bin="${GH_BIN:-gh}"

mkdir -p "$work"
command -v "$gh_bin" >/dev/null 2>&1 || test -x "$gh_bin"
curl --proto '=https' --tlsv1.2 --fail --location --output "$asset" \
    "https://github.com/cli/cli/releases/download/v${version}/gh_${version}_linux_amd64.tar.gz"
test "$(sha256sum "$asset" | awk '{print $1}')" = "$expected_digest"

curl --proto '=https' --tlsv1.2 --fail --location \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    --output "$work/api-response.json" \
    "https://api.github.com/repos/cli/cli/attestations/sha256:$expected_digest"
python3 "$project_root/prototypes/p0-004/fetch-attestation-bundles.py" \
    "$work/api-response.json" "$work/bundles.jsonl"
"$gh_bin" attestation trusted-root > "$work/trusted-root.jsonl"
"$gh_bin" attestation verify "$asset" \
    --repo cli/cli \
    --signer-workflow cli/cli/.github/workflows/deployment.yml \
    --deny-self-hosted-runners \
    --bundle "$work/bundles.jsonl" \
    --custom-trusted-root "$work/trusted-root.jsonl" \
    --format json > "$work/verification.json"

python3 - "$work/verification.json" "$expected_digest" "$expected_repository_id" <<'PY'
import json
import sys

results = json.load(open(sys.argv[1], encoding="utf-8"))
expected_digest = sys.argv[2]
expected_repository_id = sys.argv[3]
assert results
for result in results:
    certificate = result["verificationResult"]["signature"]["certificate"]
    if certificate["sourceRepositoryIdentifier"] != expected_repository_id:
        continue
    subjects = result["verificationResult"]["statement"]["subject"]
    if any(subject["digest"].get("sha256") == expected_digest for subject in subjects):
        break
else:
    raise SystemExit("verified result did not bind the expected repo ID and digest")
PY

cp "$asset" "$work/tampered.tar.gz"
printf 'tampered' >> "$work/tampered.tar.gz"
if "$gh_bin" attestation verify "$work/tampered.tar.gz" \
    --repo cli/cli --bundle "$work/bundles.jsonl" \
    --custom-trusted-root "$work/trusted-root.jsonl" > /dev/null 2>&1; then
    printf 'FAIL: tampered artifact passed attestation verification\n' >&2
    exit 1
fi

printf 'PASS: GitHub attestation binds digest, repository ID, workflow, and hosted runner; tampering rejected\n'
