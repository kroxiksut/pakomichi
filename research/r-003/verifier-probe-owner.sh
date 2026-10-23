#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P1-003c cross-check on the owner's test repository after R-003 steps 4-5
# (rename, reuse of the old name, transfer, fork) and the step 4 name capture.
# Rename and transfer create
# no new attestations, so the recorded v0.1.0 bundles are verified against
# what Pakomichi would expect after each event; the fork has its own bundle.
# Each probe case is paired, where gh can express it, with the gh 2.103.0
# oracle (offline, by name). Runs as root in pakomichi-r004-build after
# verifier-probe.sh build and verifier-probe-oracle.sh (which fetched gh).
# Output: .research-local/p1-003c/probe/owner.tsv and
# research/r-003/results/verifier-probe-owner.tsv.
set -uo pipefail

readonly gh_version=2.103.0
readonly gh_sha256=fdd768eb70f6409f80fcfa9f3a1c0adf0fc98d827ab3ce0bed2ac22762c5d786
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
probe=/mnt/c/temp/pakomichi/p1-003c/bin/verifier-probe
tarball=/mnt/c/temp/pakomichi/p1-003c/tools/gh_${gh_version}_linux_amd64.tar.gz
r003="$project_root/.research-local/r-003"
step1="$r003/owner-step1-20261022T050816Z"
step5="$r003/owner-step5-20261022T060919Z"
capture="$r003/owner-step4-capture-20261023T010251Z"
out_dir="$project_root/.research-local/p1-003c/probe"
work="$(mktemp -d /tmp/pakomichi-p1003c-owner-XXXXXX)"
trap 'rm -rf "$work"' EXIT

[[ "$(sha256sum "$tarball" | cut -d' ' -f1)" == "$gh_sha256" ]] || { echo "gh tarball missing or changed" >&2; exit 3; }
tar -C "$work" -xzf "$tarball"
gh="$work/gh_${gh_version}_linux_amd64/bin/gh"
mkdir -p "$work/home" "$work/config"
gh_env=(env -i PATH=/usr/bin:/bin HOME="$work/home" GH_CONFIG_DIR="$work/config" GH_NO_UPDATE_NOTIFIER=1
    GH_PROMPT_DISABLED=1 NO_COLOR=1 LANG=C.UTF-8)

roots="$r003/run-20261020T104417Z/trusted-root.jsonl"
python3 -I - "$roots" "$work" << 'EOF'
import json, pathlib, sys
lines = [l for l in pathlib.Path(sys.argv[1]).read_text().splitlines() if l.strip()]
pathlib.Path(sys.argv[2], "pg.json").write_text(lines[0] + "\n")
pathlib.Path(sys.argv[2], "gh.json").write_text(lines[1] + "\n")
EOF
A=("$probe" --mode attested --root "$work/pg.json")
S=("$probe" --mode strict --root "$work/gh.json")

# v0.1.0 of the original repository (step 1), release attestation + SLSA.
v1_bundle="$step1/bundles/s1/664728438.jsonl"
v1_asset="$step1/downloads/s1/664728438-pakomichi-r003-fixture_0.1.0_all.deb"
orig_id=1429109739 user_owner=2264172 org_owner=346117935 reuse_id=1429307950
v1_strict() { # repo-id owner-id repo-name
    echo --expect repo-id="$1" --expect owner-id="$2" --expect repo-name="$3" --expect release-id=420324447 \
        --expect tag=v0.1.0 --expect commit=6ee0f9f53e5a296bd19904188d055608f32ffd82 \
        --expect asset-name=pakomichi-r003-fixture_0.1.0_all.deb
}
v1_attested() { # repo-id owner-id repo-name
    echo --expect repo-id="$1" --expect owner-id="$2" --expect repo-name="$3" \
        --expect workflow=.github/workflows/immutable-release.yml --expect ref=refs/heads/main \
        --expect commit=6ee0f9f53e5a296bd19904188d055608f32ffd82
}
# v0.3.0-mutable of the fork kroxiksut/pchi-test-fork (step 5), SLSA only.
fork_bundle="$step5/bundles/s5/664845902.jsonl"
fork_asset="$step5/downloads/s5/664845902-pakomichi-r003-fixture_0.3.0_all.deb"
fork_id=1429309242
fork_attested() { # repo-id owner-id repo-name
    echo --expect repo-id="$1" --expect owner-id="$2" --expect repo-name="$3" \
        --expect workflow=.github/workflows/mutable-attested.yml --expect ref=refs/heads/main \
        --expect commit=31c0b80f18969c5f8b70912bbba18dae9bdeea02
}
# v0.3.0-mutable of the repository that took the old name (step 4 capture), SLSA only.
cap_bundle="$capture/bundles/s4c/667564280.jsonl"
cap_asset="$capture/downloads/s4c/667564280-pakomichi-r003-fixture_0.3.0_all.deb"
cap_attested() { # repo-id owner-id repo-name
    echo --expect repo-id="$1" --expect owner-id="$2" --expect repo-name="$3" \
        --expect workflow=.github/workflows/mutable-attested.yml --expect ref=refs/heads/main \
        --expect commit=a12bcac035afcfbab2838660c3fe636a59677a61
}

table="$out_dir/owner.tsv"
printf 'case\tdescription\texpected\tverdict\treason\tnotes\tstatus\tgh\tgh_note\n' > "$table"
unexpected=0

# owner_case ID DESCRIPTION EXPECTED GH_EXPECTED(accept|reject|-) "GH_ARGS" PROBE_ARGS...
owner_case() {
    local id="$1" description="$2" expected="$3" gh_expected="$4" gh_args="$5"
    shift 5
    local output verdict reason notes detail ok=UNEXPECTED gh_word=- gh_note=-
    output="$("$@" 2> /dev/null)"
    IFS=$'\t' read -r verdict reason notes detail <<< "$output"
    case "$expected" in
    PASS+*) [[ "$verdict" == PASS && ",$notes," == *",${expected#PASS+}"* ]] && ok=OK ;;
    PASS) [[ "$verdict" == PASS ]] && ok=OK ;;
    *) [[ "$verdict:$reason" == "$expected" ]] && ok=OK ;;
    esac
    if [[ "$gh_expected" != - ]]; then
        # shellcheck disable=SC2086 # gh_args is a fixed word list without spaces in values
        unshare -n -- "${gh_env[@]}" "$gh" attestation verify $gh_args --custom-trusted-root "$roots" \
            > /dev/null 2> "$work/$id.err" && gh_word=accept || gh_word=reject
        gh_note="$(grep -v '^\s*$' "$work/$id.err" | tail -1 | tr '\t' ' ' | sed "s#$work#\$WORK#g")"
        [[ "$gh_word" == "$gh_expected" ]] || ok=UNEXPECTED
    fi
    [[ $ok == OK ]] || unexpected=$((unexpected + 1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$description" "$expected" "${verdict:-}" \
        "${reason:-}" "${notes:-}" "$ok" "$gh_word" "${gh_note:0:200}" >> "$table"
    printf '%-4s %-10s %-30s gh=%-6s %s\n' "$id" "$ok" "${verdict:-}:${reason:-}" "$gh_word" "$description"
}

# shellcheck disable=SC2046 # the helpers print fixed --expect words
{
owner_case R1 "after rename: Strict, same IDs, new name" PASS+name_changed - "" \
    "${S[@]}" --bundle "$v1_bundle" --artifact "$v1_asset" $(v1_strict $orig_id $user_owner kroxiksut/pchi-test-renamed)
owner_case R2 "after rename: Attested, same IDs, new name (gh binds the old name)" PASS+name_changed reject \
    "$v1_asset --repo kroxiksut/pchi-test-renamed --bundle $v1_bundle" \
    "${A[@]}" --bundle "$v1_bundle" --artifact "$v1_asset" $(v1_attested $orig_id $user_owner kroxiksut/pchi-test-renamed)
owner_case U1 "name reused: new kroxiksut/pchi-test (ID $reuse_id) offered the original's bundle, Strict" \
    INVALID:RepositoryIdMismatch - "" \
    "${S[@]}" --bundle "$v1_bundle" --artifact "$v1_asset" $(v1_strict $reuse_id $user_owner kroxiksut/pchi-test)
owner_case U2 "name reused: same, Attested (gh accepts by name)" INVALID:RepositoryIdMismatch accept \
    "$v1_asset --repo kroxiksut/pchi-test --bundle $v1_bundle" \
    "${A[@]}" --bundle "$v1_bundle" --artifact "$v1_asset" $(v1_attested $reuse_id $user_owner kroxiksut/pchi-test)
owner_case T1 "after transfer: Strict, owner ID re-pinned to the organization" INVALID:OwnerIdMismatch - "" \
    "${S[@]}" --bundle "$v1_bundle" --artifact "$v1_asset" $(v1_strict $orig_id $org_owner pchi-test-org/pchi-test-renamed)
owner_case T2 "after transfer: Attested, owner ID re-pinned to the organization" INVALID:OwnerIdMismatch reject \
    "$v1_asset --repo pchi-test-org/pchi-test-renamed --bundle $v1_bundle" \
    "${A[@]}" --bundle "$v1_bundle" --artifact "$v1_asset" $(v1_attested $orig_id $org_owner pchi-test-org/pchi-test-renamed)
owner_case T3 "after transfer: Strict, owner ID of the release time kept" PASS+name_changed - "" \
    "${S[@]}" --bundle "$v1_bundle" --artifact "$v1_asset" $(v1_strict $orig_id $user_owner pchi-test-org/pchi-test-renamed)
owner_case F1 "fork bundle against the original's pin (same owner ID)" INVALID:RepositoryIdMismatch reject \
    "$fork_asset --repo kroxiksut/pchi-test-renamed --bundle $fork_bundle" \
    "${A[@]}" --bundle "$fork_bundle" --artifact "$fork_asset" $(fork_attested $orig_id $user_owner kroxiksut/pchi-test-renamed)
owner_case F2 "fork bundle against the fork's own pin" PASS accept \
    "$fork_asset --repo kroxiksut/pchi-test-fork --bundle $fork_bundle" \
    "${A[@]}" --bundle "$fork_bundle" --artifact "$fork_asset" $(fork_attested $fork_id $user_owner kroxiksut/pchi-test-fork)
owner_case F3 "fork's mutable release under Strict: no release attestation" DOWNGRADE:ReleaseAttestationMissing - "" \
    "${S[@]}" --bundle "$fork_bundle" --artifact "$fork_asset" --expect repo-id=$fork_id --expect owner-id=$user_owner \
    --expect release-id=420357583 --expect tag=v0.3.0-mutable --expect commit=31c0b80f18969c5f8b70912bbba18dae9bdeea02 \
    --expect asset-name=pakomichi-r003-fixture_0.3.0_all.deb
owner_case C1 "name capture: the holder's own release against the original's pin, Attested (gh accepts by name)" \
    INVALID:RepositoryIdMismatch accept \
    "$cap_asset --repo kroxiksut/pchi-test --bundle $cap_bundle" \
    "${A[@]}" --bundle "$cap_bundle" --artifact "$cap_asset" $(cap_attested $orig_id $user_owner kroxiksut/pchi-test)
owner_case C2 "name capture: the holder's release against its own pin" PASS accept \
    "$cap_asset --repo kroxiksut/pchi-test --bundle $cap_bundle" \
    "${A[@]}" --bundle "$cap_bundle" --artifact "$cap_asset" $(cap_attested $reuse_id $user_owner kroxiksut/pchi-test)
owner_case C3 "name capture: the holder's mutable release under Strict: no release attestation" DOWNGRADE:ReleaseAttestationMissing - "" \
    "${S[@]}" --bundle "$cap_bundle" --artifact "$cap_asset" --expect repo-id=$reuse_id --expect owner-id=$user_owner \
    --expect release-id=421346102 --expect tag=v0.3.0-mutable --expect commit=a12bcac035afcfbab2838660c3fe636a59677a61 \
    --expect asset-name=pakomichi-r003-fixture_0.3.0_all.deb
}

cp "$table" "$project_root/research/r-003/results/verifier-probe-owner.tsv"
echo "unexpected: $unexpected"
[[ $unexpected -eq 0 ]]
