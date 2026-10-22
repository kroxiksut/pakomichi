#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# R-003 read-only run inside the disposable pakomichi-r003-* WSL distribution.
# Runs as root only to drop to the unprivileged `r003` user and to copy
# results; collection and verification run as `r003`.
#
#   bash research/r-003/run.sh all      # collect (anonymous API) + checks
#   bash research/r-003/run.sh checks   # rerun checks on the last collection
set -euo pipefail

stage="${1:-all}"
readonly gh="/opt/r003-gh/bin/gh"
readonly work="/var/tmp/pakomichi-r003"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "run.sh must run as root inside the research distribution" >&2
    exit 2
fi
if [[ "${WSL_DISTRO_NAME:-}" != pakomichi-r003-* ]]; then
    echo "refusing to run outside a pakomichi-r003-* distribution (${WSL_DISTRO_NAME:-unset})" >&2
    exit 2
fi
for variable in GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN; do
    if [[ -n "${!variable:-}" ]]; then
        echo "$variable is set; R-003 read-only stage runs anonymously" >&2
        exit 2
    fi
done
test -x "$gh"

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
readonly local_root="$project_root/.research-local/r-003"
readonly results="$project_root/research/r-003/results"
readonly script="$project_root/research/r-003/r003.py"

as_r003() {
    runuser -u r003 -- env -i PATH=/usr/bin:/bin HOME=/home/r003 LANG=C.UTF-8 "$@"
}

mkdir -p "$work" "$local_root"
chown r003:r003 "$work"

case "$stage" in
    all)
        rm -rf "${work:?}"/*
        as_r003 python3 -I -B "$script" collect --work "$work"
        ;;
    checks)
        if [[ ! -f "$work/collect.json" ]]; then
            previous="$local_root/$(cat "$local_root/latest")"
            test -f "$previous/collect.json"
            cp -r "$previous/." "$work/"
        fi
        rm -rf "$work/gh-logs" "$work/negatives" "$work/home" "$work/gh-config" "$work/trusted-root.jsonl" "$work/results"
        chown -R r003:r003 "$work"
        ;;
    *)
        echo "usage: run.sh all|checks" >&2
        exit 2
        ;;
esac

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp_results="$work/results"
as_r003 mkdir -p "$tmp_results"
as_r003 python3 -I -B "$script" checks --work "$work" --results "$tmp_results" --gh "$gh"

{
    printf 'key\tvalue\n'
    . /etc/os-release
    printf 'distribution\t%s\n' "$WSL_DISTRO_NAME"
    printf 'os\t%s\n' "$PRETTY_NAME"
    printf 'base_image\tlibrary/fedora:44 (research/r-001/images.lock.json fedora44)\n'
    printf 'kernel\t%s\n' "$(uname -srm)"
    printf 'python\t%s\n' "$(python3 --version 2>&1)"
    printf 'curl\t%s\n' "$(curl --version | head -n 1 | cut -d' ' -f1-2)"
    printf 'gh\t%s\n' "$("$gh" --version | head -n 1)"
    printf 'gh_tarball_sha256\t%s\n' "$(sha256sum "$local_root/tools/gh_2.95.0_linux_amd64.tar.gz" | awk '{print $1}')"
    printf 'unshare\t%s\n' "$(unshare --version)"
    for host in api.github.com github.com release-assets.githubusercontent.com tuf-repo-cdn.sigstore.dev; do
        printf 'resolve_%s\t%s\n' "$host" "$(getent ahostsv4 "$host" | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ $//')"
    done
    printf 'github_auth\tnone (no token configured; GH_CONFIG_DIR empty)\n'
    printf 'run_stage\t%s\n' "$stage"
    printf 'run_utc\t%s\n' "$stamp"
} > "$tmp_results/environment.tsv"

mkdir -p "$results"
cp "$tmp_results"/*.tsv "$results/"
cp "$work/raw/requests.tsv" "$results/api-requests.tsv"

dest="$local_root/run-$stamp"
mkdir -p "$dest"
cp -r "$work/." "$dest/"
printf 'run-%s\n' "$stamp" > "$local_root/latest"
echo "results=$results raw=$dest"
