#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Cross-check the P1-003c probe's Attested cases with the gh oracle
# (`gh attestation verify`, offline: --bundle, --custom-trusted-root, inside
# `unshare -n`). gh has no offline Strict path, so Strict cases are not
# cross-checked. Runs as root in pakomichi-r004-build after
# verifier-probe-cases.sh. Fetches the pinned gh tarball once (network).
# Output: .research-local/p1-003c/probe/oracle.tsv and
# research/r-003/results/verifier-probe-oracle.tsv.
set -uo pipefail

readonly gh_version=2.103.0
# From gh_2.103.0_checksums.txt of the cli/cli v2.103.0 release.
readonly gh_sha256=fdd768eb70f6409f80fcfa9f3a1c0adf0fc98d827ab3ce0bed2ac22762c5d786
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
tools=/mnt/c/temp/pakomichi/p1-003c/tools
run="$project_root/.research-local/r-003/run-20261020T104417Z"
step1="$project_root/.research-local/r-003/owner-step1-20261022T050816Z"
out_dir="$project_root/.research-local/p1-003c/probe"
cases="$out_dir/cases.tsv"
work="$(mktemp -d /tmp/pakomichi-p1003c-oracle-XXXXXX)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$tools"
tarball="$tools/gh_${gh_version}_linux_amd64.tar.gz"
if [[ ! -f "$tarball" ]]; then
    curl -fsSL --retry 3 -o "$tarball.part" \
        "https://github.com/cli/cli/releases/download/v${gh_version}/gh_${gh_version}_linux_amd64.tar.gz" &&
        mv "$tarball.part" "$tarball" || exit 3
fi
actual="$(sha256sum "$tarball" | cut -d' ' -f1)"
if [[ "$actual" != "$gh_sha256" ]]; then
    echo "gh tarball $actual does not match pin $gh_sha256" >&2
    exit 3
fi
echo "gh_tarball_sha256=$actual"
tar -C "$work" -xzf "$tarball"
gh="$work/gh_${gh_version}_linux_amd64/bin/gh"
mkdir -p "$work/home" "$work/config"
gh_env=(env -i PATH=/usr/bin:/bin HOME="$work/home" GH_CONFIG_DIR="$work/config" GH_NO_UPDATE_NOTIFIER=1
    GH_PROMPT_DISABLED=1 NO_COLOR=1 LANG=C.UTF-8)
"${gh_env[@]}" "$gh" --version | head -1

python3 -I "$project_root/research/r-003/verifier-probe-inputs.py" "$run" "$step1" "$work/in" > /dev/null || exit 3
in="$work/in"
roots="$run/trusted-root.jsonl"
nw=matthart1983/netwatch
nw_bundle() { echo "$run/bundles/subject/$1.jsonl"; }
nw_asset() { ls "$run/downloads/subject/$1-"*; }
nw_x86="$(nw_asset 649038819)"
cli_bundle="$run/bundles/strict/450525940.jsonl"
cli_asset="$run/downloads/strict/450525940-gh_2.95.0_linux_amd64.tar.gz"

table="$out_dir/oracle.tsv"
printf 'case\tdescription\tgh_exit\tgh\tprobe\tagreement\tgh_note\n' > "$table"
disagree=0

# check CASE DESCRIPTION EXPECTED_AGREEMENT(same|differs) gh-args...
check() {
    local id="$1" description="$2" agreement_expected="$3"
    shift 3
    local status note gh_word probe_word agreement
    unshare -n -- "${gh_env[@]}" "$gh" attestation verify "$@" > "$work/$id.out" 2> "$work/$id.err"
    status=$?
    note="$(grep -v '^\s*$' "$work/$id.err" | tail -2 | tr '\t\n' '  ' | sed "s#$work#\$WORK#g; s#$project_root#.#g")"
    gh_word=$([[ $status -eq 0 ]] && echo accept || echo reject)
    probe_word="$(awk -F'\t' -v id="$id" '$1 == id { print ($4 == "PASS" ? "accept" : "reject") }' "$cases")"
    probe_word="${probe_word:-n/a}"
    if [[ "$gh_word" == "$probe_word" ]]; then agreement=same; else agreement=differs; fi
    [[ "$agreement" == "$agreement_expected" ]] || disagree=$((disagree + 1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$description" "$status" "$gh_word" "$probe_word" \
        "$agreement" "${note:0:300}" >> "$table"
    printf '%-5s gh=%-6s probe=%-6s %-7s %s\n' "$id" "$gh_word" "$probe_word" "$agreement" "$description"
}

C=(--custom-trusted-root "$roots")
check P1 "netwatch x86_64.rpm" same "$nw_x86" --repo $nw --bundle "$(nw_bundle 649038819)" "${C[@]}"
check P2 "netwatch amd64.deb" same "$(nw_asset 649038825)" --repo $nw --bundle "$(nw_bundle 649038825)" "${C[@]}"
check P3 "netwatch aarch64.rpm" same "$(nw_asset 649038828)" --repo $nw --bundle "$(nw_bundle 649038828)" "${C[@]}"
check P4 "netwatch arm64.deb" same "$(nw_asset 649038829)" --repo $nw --bundle "$(nw_bundle 649038829)" "${C[@]}"
check P5 "cli/cli SLSA provenance" same "$cli_asset" --repo cli/cli --bundle "$cli_bundle" "${C[@]}"
check P10 "pchi-test SLSA provenance" same "$step1/downloads/s1/664728438-pakomichi-r003-fixture_0.1.0_all.deb" \
    --repo kroxiksut/pchi-test --bundle "$step1/bundles/s1/664728438.jsonl" "${C[@]}"
check O1 "renamed repository: gh binds by name, probe by ID" differs "$nw_x86" --repo someone/netwatch-renamed --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N1 "changed byte" same "$run/negatives/changed-byte-649038828-netwatch-0.35.4-1.aarch64.rpm" --repo $nw --bundle "$(nw_bundle 649038828)" "${C[@]}"
check N3 "bytes not in the release" same "$run/negatives/not-in-release.deb" --repo $nw --bundle "$(nw_bundle 649038825)" "${C[@]}"
check N6 "forged payload" same "$run/negatives/changed-byte-649038828-netwatch-0.35.4-1.aarch64.rpm" --repo $nw --bundle "$run/negatives/forged-subject.jsonl" "${C[@]}"
check N7 "root without CAs" same "$nw_x86" --repo $nw --bundle "$(nw_bundle 649038819)" --custom-trusted-root "$run/negatives/trusted-root-no-ca.jsonl"
check N10 "other repository (gh: by name)" same "$nw_x86" --repo $nw-fork --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N11 "other owner (gh: by name)" same "$nw_x86" --owner pakomichi-r003-nonexistent --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N12 "other workflow" same "$nw_x86" --repo $nw --signer-workflow $nw/.github/workflows/other.yml --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N13 "workflow prefix (GHSA-wjmr-j3rp-mh2g)" same "$nw_x86" --repo $nw --signer-workflow $nw/.github/workflows/rel --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N14 "workflow as regex (GHSA-mm27-mwq9-fr5g)" same "$nw_x86" --repo $nw --signer-workflow "$nw/.github/workflows/release.ym." --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N15 "other OIDC issuer" same "$nw_x86" --repo $nw --cert-oidc-issuer https://token.actions.githubusercontent.com/pakomichi-r003 --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N16 "other ref" same "$nw_x86" --repo $nw --source-ref refs/tags/v0.35.3 --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N17 "ref in other case (GHSA-4mq3-hpgx-9cx8)" same "$nw_x86" --repo $nw --source-ref refs/tags/V0.35.4 --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N18 "other commit" same "$nw_x86" --repo $nw --source-digest 0000000000000000000000000000000000000000 --bundle "$(nw_bundle 649038819)" "${C[@]}"
check N28 "inclusion proof hash changed" same "$nw_x86" --repo $nw --bundle "$in/n28-inclusion-proof.jsonl" "${C[@]}"
check N29 "checkpoint signature changed" same "$nw_x86" --repo $nw --bundle "$in/n29-checkpoint.jsonl" "${C[@]}"
check N30 "integratedTime moved" same "$nw_x86" --repo $nw --bundle "$in/n30-integrated-time.jsonl" "${C[@]}"
check N31 "log entry of the cli/cli bundle" same "$nw_x86" --repo $nw --bundle "$in/n31-foreign-tlog.jsonl" "${C[@]}"
check N32 "leaf certificate of the cli/cli bundle" same "$nw_x86" --repo $nw --bundle "$in/n32-swapped-leaf.jsonl" "${C[@]}"
check N36b "CT log keys swapped in the root" same "$nw_x86" --repo $nw --bundle "$(nw_bundle 649038819)" --custom-trusted-root "$in/root-public-good-ct-keys-swapped.json"
check N37 "two DSSE signatures" same "$nw_x86" --repo $nw --bundle "$in/n37-two-signatures.jsonl" "${C[@]}"

cp "$table" "$project_root/research/r-003/results/verifier-probe-oracle.tsv"
echo "unexpected agreement: $disagree"
[[ $disagree -eq 0 ]]
