#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run the P1-003c verifier probe cases offline against recorded R-003
# evidence. Runs as root in pakomichi-r004-build (for `unshare -n`).
# Tampered inputs live only in a fresh /tmp/pakomichi-p1003c-* directory.
# Output: .research-local/p1-003c/probe/cases.tsv and
# research/r-003/results/verifier-probe-cases.tsv.
# Expectation syntax: PASS, PASS+note, INVALID:Reason, DOWNGRADE:Reason,
# INVALID:* (frozen: any rejection, observed reason recorded), PANIC.
set -uo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
probe=/mnt/c/temp/pakomichi/p1-003c/bin/verifier-probe
run="$project_root/.research-local/r-003/run-20261020T104417Z"
step1="$project_root/.research-local/r-003/owner-step1-20261022T050816Z"
out_dir="$project_root/.research-local/p1-003c/probe"
work="$(mktemp -d /tmp/pakomichi-p1003c-XXXXXX)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out_dir"

python3 -I "$project_root/research/r-003/verifier-probe-inputs.py" "$run" "$step1" "$work/in" > /dev/null || exit 3
in="$work/in"
pg="$in/root-public-good.json"
gh="$in/root-github.json"

# netwatch (Attested, public-good Sigstore)
nw_id=1158138526 nw_owner=13101478 nw_commit=9c249f576766a164108103cdd0da627a7f00229b
nw_expect=(--expect repo-id=$nw_id --expect owner-id=$nw_owner --expect workflow=.github/workflows/release.yml
    --expect ref=refs/tags/v0.35.4 --expect commit=$nw_commit --expect repo-name=matthart1983/netwatch)
nw_bundle() { echo "$run/bundles/subject/$1.jsonl"; }
nw_asset() { ls "$run/downloads/subject/$1-"*; }
nw_x86="$(nw_asset 649038819)"

# cli/cli v2.95.0 (Strict release attestation and Attested SLSA)
cli_bundle="$run/bundles/strict/450525940.jsonl"
cli_asset="$run/downloads/strict/450525940-gh_2.95.0_linux_amd64.tar.gz"
cli_commit=70bb306bd25eb407f90eabefd98824aed62cf519
cli_strict=(--expect repo-id=212613049 --expect owner-id=59704711 --expect release-id=341013769
    --expect tag=v2.95.0 --expect commit=$cli_commit --expect asset-name=gh_2.95.0_linux_amd64.tar.gz
    --expect repo-name=cli/cli)
cli_attested=(--expect repo-id=212613049 --expect owner-id=59704711 --expect workflow=.github/workflows/deployment.yml
    --expect ref=refs/heads/trunk --expect commit=$cli_commit --expect repo-name=cli/cli)

# kroxiksut/pchi-test v0.1.0 (owner's test repository, step 1)
pt_bundle="$step1/bundles/s1/664728438.jsonl"
pt_asset="$step1/downloads/s1/664728438-pakomichi-r003-fixture_0.1.0_all.deb"
pt_commit=6ee0f9f53e5a296bd19904188d055608f32ffd82
pt_strict=(--expect repo-id=1429109739 --expect owner-id=2264172 --expect release-id=420324447
    --expect tag=v0.1.0 --expect commit=$pt_commit --expect asset-name=pakomichi-r003-fixture_0.1.0_all.deb
    --expect repo-name=kroxiksut/pchi-test)
pt_attested=(--expect repo-id=1429109739 --expect owner-id=2264172 --expect workflow=.github/workflows/immutable-release.yml
    --expect ref=refs/heads/main --expect commit=$pt_commit --expect repo-name=kroxiksut/pchi-test)

table="$out_dir/cases.tsv"
printf 'case\tdescription\texpected\tverdict\treason\tnotes\texit\tstatus\tdetail\n' > "$table"
unexpected=0

case_run() {
    local id="$1" description="$2" expected="$3"
    shift 3
    local output status verdict reason notes detail ok=UNEXPECTED
    output="$("$@" 2> "$work/$id.stderr")"
    status=$?
    IFS=$'\t' read -r verdict reason notes detail <<< "$output"
    case "$expected" in
    PANIC) [[ $status -eq 101 ]] && ok=OK && verdict=PANIC && reason=- ;;
    PASS) [[ "$verdict" == PASS ]] && ok=OK ;;
    PASS+*) [[ "$verdict" == PASS && ",$notes," == *",${expected#PASS+}"* ]] && ok=OK ;;
    *:\*) [[ "$verdict" == "${expected%%:*}" ]] && ok=OK ;;
    *) [[ "$verdict:$reason" == "$expected" ]] && ok=OK ;;
    esac
    [[ $ok == OK ]] || unexpected=$((unexpected + 1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$description" "$expected" "${verdict:-}" \
        "${reason:-}" "${notes:-}" "$status" "$ok" "${detail:-}" >> "$table"
    printf '%-4s %-10s %-34s %s\n' "$id" "$ok" "${verdict:-}:${reason:-}" "$description"
}

A=("$probe" --mode attested --root "$pg")
S=("$probe" --mode strict --root "$gh")

case_run P1 "netwatch x86_64.rpm Attested" PASS "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}"
case_run P2 "netwatch amd64.deb Attested" PASS "${A[@]}" --bundle "$(nw_bundle 649038825)" --artifact "$(nw_asset 649038825)" "${nw_expect[@]}"
case_run P3 "netwatch aarch64.rpm Attested" PASS "${A[@]}" --bundle "$(nw_bundle 649038828)" --artifact "$(nw_asset 649038828)" "${nw_expect[@]}"
case_run P4 "netwatch arm64.deb Attested" PASS "${A[@]}" --bundle "$(nw_bundle 649038829)" --artifact "$(nw_asset 649038829)" "${nw_expect[@]}"
case_run P5 "cli/cli SLSA provenance Attested (release line skipped)" PASS "${A[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_attested[@]}"
case_run P6 "cli/cli release attestation Strict (GitHub root, TSA, no tlog)" PASS "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}"
case_run P7a "P1 inside unshare -n" PASS unshare -n -- "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}"
case_run P7b "P6 inside unshare -n" PASS unshare -n -- "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}"
case_run P8 "P1 from a SHA-256 digest (CAS) instead of bytes" PASS "${A[@]}" --bundle "$(nw_bundle 649038819)" --sha256 "$(sha256sum "$nw_x86" | cut -d' ' -f1)" "${nw_expect[@]}"
case_run P9 "pchi-test release attestation Strict" PASS "${S[@]}" --bundle "$pt_bundle" --artifact "$pt_asset" "${pt_strict[@]}"
case_run P10 "pchi-test SLSA provenance Attested" PASS "${A[@]}" --bundle "$pt_bundle" --artifact "$pt_asset" "${pt_attested[@]}"
case_run P11 "P6 from a SHA-256 digest" PASS "${S[@]}" --bundle "$cli_bundle" --sha256 "$(sha256sum "$cli_asset" | cut -d' ' -f1)" "${cli_strict[@]}"
case_run O1 "Attested: same IDs, other expected name" PASS+name_changed "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect repo-name=someone/netwatch-renamed
case_run O2 "Strict: same IDs, other expected name" PASS+name_changed "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}" --expect repo-name=cli/cli-renamed

case_run N1 "changed byte in aarch64.rpm" INVALID:ArtifactDigestMismatch "${A[@]}" --bundle "$(nw_bundle 649038828)" --artifact "$run/negatives/changed-byte-649038828-netwatch-0.35.4-1.aarch64.rpm" "${nw_expect[@]}"
case_run N2 "changed byte in gh tar.gz (Strict)" INVALID:ArtifactDigestMismatch "${S[@]}" --bundle "$cli_bundle" --artifact "$run/negatives/changed-byte-450525940-gh_2.95.0_linux_amd64.tar.gz" "${cli_strict[@]}"
case_run N3 "bytes not in the release" INVALID:ArtifactDigestMismatch "${A[@]}" --bundle "$(nw_bundle 649038825)" --artifact "$run/negatives/not-in-release.deb" "${nw_expect[@]}"
case_run N4 "empty bundle file" DOWNGRADE:BundleMissing "${A[@]}" --bundle "$run/negatives/empty.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N5 "bundle over 256 KiB" INVALID:BundleTooLarge "${A[@]}" --bundle "$in/n05-too-large.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N5b "17 bundles for one digest" INVALID:TooManyBundles "${A[@]}" --bundle "$in/n05b-too-many.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N6 "payload rewritten to the changed digest" INVALID:SignatureInvalid "${A[@]}" --bundle "$run/negatives/forged-subject.jsonl" --artifact "$run/negatives/changed-byte-649038828-netwatch-0.35.4-1.aarch64.rpm" "${nw_expect[@]}"
case_run N7 "public-good root without CAs" INVALID:* "${A[@]/$pg/$in/root-public-good-no-ca.json}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N8 "SLSA provenance against the GitHub root" INVALID:* "$probe" --mode attested --root "$gh" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_attested[@]}"
case_run N9 "release attestation against the public-good root" INVALID:* "$probe" --mode strict --root "$pg" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}"
case_run N10 "Attested: other repository ID" INVALID:RepositoryIdMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect repo-id=1158138527
case_run N11 "Attested: other owner ID" INVALID:OwnerIdMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect owner-id=13101479
case_run N12 "Attested: other workflow" INVALID:WorkflowMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect workflow=.github/workflows/other.yml
case_run N13 "Attested: workflow prefix only" INVALID:WorkflowMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect workflow=.github/workflows/rel
case_run N14 "Attested: workflow as a regex" INVALID:WorkflowMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect 'workflow=.github/workflows/release.ym.'
case_run N15 "Attested: other OIDC issuer" INVALID:IssuerMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect issuer=https://token.actions.githubusercontent.com/pakomichi-r003
case_run N16 "Attested: other ref" INVALID:RefMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect ref=refs/tags/v0.35.3
case_run N17 "Attested: ref in other letter case" INVALID:RefMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect ref=refs/tags/V0.35.4
case_run N18 "Attested: other commit" INVALID:CommitMismatch "${A[@]}" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}" --expect commit=0000000000000000000000000000000000000000
case_run N19 "Attested: only a release attestation present" DOWNGRADE:ProvenanceMissing "${A[@]}" --bundle "$run/negatives/strict-https-in-toto-io-attestation-release-v0-2.jsonl" --artifact "$cli_asset" "${cli_attested[@]}"
case_run N20 "Strict: only SLSA provenance present" DOWNGRADE:ReleaseAttestationMissing "${S[@]}" --bundle "$run/negatives/strict-https-slsa-dev-provenance-v1.jsonl" --artifact "$cli_asset" "${cli_strict[@]}"
case_run N21 "Strict: other repository ID" INVALID:RepositoryIdMismatch "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}" --expect repo-id=212613050
case_run N22 "Strict: other owner ID" INVALID:OwnerIdMismatch "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}" --expect owner-id=59704712
case_run N23 "Strict: other release ID" INVALID:ReleaseIdMismatch "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}" --expect release-id=341013770
case_run N24 "Strict: other tag" INVALID:TagMismatch "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}" --expect tag=v2.94.0
case_run N25 "Strict: other tag commit" INVALID:CommitSubjectMismatch "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}" --expect commit=0000000000000000000000000000000000000000
case_run N26 "Strict: asset under another name" INVALID:SubjectNameMismatch "${S[@]}" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}" --expect asset-name=gh_2.95.0_linux_386.tar.gz
case_run N27 "Attested: transparency log entry removed" INVALID:* "${A[@]}" --bundle "$in/n27-no-tlog.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N28 "Attested: inclusion proof hash changed" INVALID:TlogInclusionProof "${A[@]}" --bundle "$in/n28-inclusion-proof.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N29 "Attested: checkpoint signature changed" INVALID:TlogCheckpoint "${A[@]}" --bundle "$in/n29-checkpoint.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N30 "Attested: integratedTime moved back an hour" INVALID:TlogInclusionPromise "${A[@]}" --bundle "$in/n30-integrated-time.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N31 "Attested: log entry of the cli/cli bundle" INVALID:* "${A[@]}" --bundle "$in/n31-foreign-tlog.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N32 "Attested: leaf certificate of the cli/cli bundle" INVALID:* "${A[@]}" --bundle "$in/n32-swapped-leaf.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N33 "Strict: one byte of the TSA token changed" INVALID:TimestampInvalid "${S[@]}" --bundle "$in/n33-tsa-byte.jsonl" --artifact "$cli_asset" "${cli_strict[@]}"
case_run N34 "Strict: timestamp data removed (structural check)" INVALID:BundleInvalid "${S[@]}" --bundle "$in/n34-no-timestamp.jsonl" --artifact "$cli_asset" "${cli_strict[@]}"
case_run N35 "Strict: every GitHub CA window ended at its start" INVALID:NoValidAuthority "$probe" --mode strict --root "$in/root-github-ca-ended.json" --bundle "$cli_bundle" --artifact "$cli_asset" "${cli_strict[@]}"
case_run N36 "Attested: root without CT logs (trust root defect)" INVALID:TrustRootInvalid "$probe" --mode attested --root "$in/root-public-good-no-ctlogs.json" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N36b "Attested: CT log keys swapped in the root" INVALID:SctInvalid "$probe" --mode attested --root "$in/root-public-good-ct-keys-swapped.json" --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N37 "two DSSE signatures" INVALID:BundleMalformed "${A[@]}" --bundle "$in/n37-two-signatures.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N38 "payloadType text/plain" INVALID:UnsupportedContent "${A[@]}" --bundle "$in/n38-payload-type.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N39 "statement _type changed (payload re-encoded)" INVALID:SignatureInvalid "${A[@]}" --bundle "$in/n39-statement-type.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N40 "bundle mediaType v0.1" INVALID:* "${A[@]}" --bundle "$in/n40-media-type.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N41 "messageSignature instead of DSSE" INVALID:UnsupportedContent "${A[@]}" --bundle "$in/n41-message-signature.jsonl" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N42 "no CryptoProvider installed" PANIC "${A[@]}" --no-provider --bundle "$(nw_bundle 649038819)" --artifact "$nw_x86" "${nw_expect[@]}"
case_run N43 "pchi-test release attestation, cli/cli IDs expected" INVALID:RepositoryIdMismatch "${S[@]}" --bundle "$pt_bundle" --artifact "$pt_asset" "${pt_strict[@]}" --expect repo-id=212613049

cp "$table" "$project_root/research/r-003/results/verifier-probe-cases.tsv"
echo "unexpected: $unexpected"
[[ $unexpected -eq 0 ]]
