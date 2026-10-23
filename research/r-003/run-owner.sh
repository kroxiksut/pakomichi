#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# R-003 owner-repository steps inside the disposable pakomichi-r003-* WSL
# distribution. Runs as root only to drop to the unprivileged `r003` user, to
# hand it the read-only token as a 0600 file, and to copy results.
#
#   bash research/r-003/run-owner.sh step1|step2|step3|step5
#   bash research/r-003/run-owner.sh step4 rename|reuse|transfer
#
# step3 compares against the recorded step 2 run (R003_STEP2_RUN, a directory
# name under .research-local/r-003/) and the digest of the local rebuild of
# the replacement (R003_REBUILD_SHA256). step4 reuses the step 1 evidence
# (R003_STEP1_RUN) and may resolve one more name (R003_EXTRA_NAME). step5
# checks the fork R003_FORK.
set -euo pipefail

stage="${1:-}"
phase="${2:-}"
readonly gh="/opt/r003-gh/bin/gh"
readonly work="/var/tmp/pakomichi-r003-owner"
readonly token_copy="/home/r003/.r003-token"
readonly step1_run="${R003_STEP1_RUN:-owner-step1-20261022T050816Z}"
readonly step2_run="${R003_STEP2_RUN:-owner-step2-20261022T053242Z}"
readonly rebuild_sha256="${R003_REBUILD_SHA256:-a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9}"
readonly fork="${R003_FORK:-kroxiksut/pchi-test-fork}"

case "$stage" in
    step1|step2|step3|step5) label="$stage" ;;
    step4)
        case "$phase" in
            rename|reuse|transfer) label="step4-$phase" ;;
            *) echo "usage: run-owner.sh step4 rename|reuse|transfer" >&2; exit 2 ;;
        esac
        ;;
    *) echo "usage: run-owner.sh step1|step2|step3|step5 or step4 PHASE" >&2; exit 2 ;;
esac
if [[ "$(id -u)" -ne 0 ]]; then
    echo "run-owner.sh must run as root inside the research distribution" >&2
    exit 2
fi
if [[ "${WSL_DISTRO_NAME:-}" != pakomichi-r003-* ]]; then
    echo "refusing to run outside a pakomichi-r003-* distribution (${WSL_DISTRO_NAME:-unset})" >&2
    exit 2
fi
for variable in GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN; do
    if [[ -n "${!variable:-}" ]]; then
        echo "$variable is set; the token is read from the secrets file only" >&2
        exit 2
    fi
done
test -x "$gh"

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
readonly local_root="$project_root/.research-local/r-003"
readonly token_file="$local_root/secrets/github-token"
readonly results="$project_root/research/r-003/results"
readonly script="$project_root/research/r-003/owner.py"
test -f "$token_file"

cleanup() { rm -f "$token_copy"; }
trap cleanup EXIT
install -m 0600 -o r003 -g r003 "$token_file" "$token_copy"

as_r003() {
    runuser -u r003 -- env -i PATH=/usr/bin:/bin HOME=/home/r003 LANG=C.UTF-8 "$@"
}

rm -rf "$work"
mkdir -p "$work/results"
chown -R r003:r003 "$work"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
extra=()
case "$stage" in
    step3)
        test -f "$local_root/$step2_run/collect.json"
        extra=(--baseline "$local_root/$step2_run" --expected-sha256 "$rebuild_sha256")
        ;;
    step4)
        test -f "$local_root/$step1_run/collect.json"
        extra=(--phase "$phase" --step1-run "$local_root/$step1_run")
        if [[ -n "${R003_EXTRA_NAME:-}" ]]; then extra+=(--extra-name "$R003_EXTRA_NAME"); fi
        ;;
    step5)
        extra=(--repo "$fork")
        ;;
esac
as_r003 python3 -I -B "$script" "$stage" --work "$work" --results "$work/results" --gh "$gh" \
    --token-file "$token_copy" "${extra[@]}"

{
    printf 'key\tvalue\n'
    . /etc/os-release
    printf 'distribution\t%s\n' "$WSL_DISTRO_NAME"
    printf 'os\t%s\n' "$PRETTY_NAME"
    printf 'base_image\tlibrary/fedora:44 (research/r-001/images.lock.json fedora44)\n'
    printf 'kernel\t%s\n' "$(uname -srm)"
    printf 'python\t%s\n' "$(python3 --version 2>&1)"
    printf 'gh\t%s\n' "$("$gh" --version | head -n 1)"
    printf 'gh_tarball_sha256\t%s\n' "$(cat /opt/r003-gh/TARBALL-SHA256)"
    printf 'github_auth\tanonymous API collection; fine-grained read-only token (public repositories, no permissions) only for cases marked online\n'
    printf 'run_stage\t%s\n' "$label"
    printf 'run_utc\t%s\n' "$stamp"
} > "$work/results/owner-$label-environment.tsv"
cp "$work/raw/requests.tsv" "$work/results/owner-$label-api-requests.tsv"

mkdir -p "$results"
cp "$work/results"/owner-*.tsv "$results/"
dest="$local_root/owner-$label-$stamp"
mkdir -p "$dest"
cp -r "$work/." "$dest/"
echo "results=$results raw=$dest"
