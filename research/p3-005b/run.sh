#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P3-005b live check against GitHub: build p3005b-fetch in the builder
# pakomichi-r004-build (offline, P3-005a dependency cache), then fetch real
# assets of the public R-003 test repository (ID 1429109739) through the
# production lazy fetcher with rustls, the system resolver, and public
# addresses only. Anonymous requests (6 of the 60 per hour). Results:
# research/p3-005b/results/live.tsv; raw output .research-local/p3-005b/.
#
#   wsl.exe -d pakomichi-r004-build -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/p3-005b/run.sh
set -uo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
export CARGO_HOME=/mnt/c/temp/pakomichi/p3-005a/cargo-home
export CARGO_TARGET_DIR=/mnt/c/temp/pakomichi/p3-001/tool-target
export CARGO_NET_OFFLINE=true
export PATH="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"
tool=$project_root/research/p3-005b/fetch-tool
raw=$project_root/.research-local/p3-005b
results=$project_root/research/p3-005b/results/live.tsv
cas=/tmp/pakomichi-p3005b-cas

cd "$project_root" || exit 1
[[ -f $tool/Cargo.lock ]] || cargo generate-lockfile --offline --manifest-path "$tool/Cargo.toml"
cargo clippy --locked --release --manifest-path "$tool/Cargo.toml" -- -D warnings || exit 1
cargo build --locked --release --manifest-path "$tool/Cargo.toml" || exit 1
fetch="$CARGO_TARGET_DIR/release/p3005b-fetch"

mkdir -p "$raw" "$(dirname "$results")"
printf 'id\tcase\texit\toutput\tverdict\n' >"$results"
REPO=1429109739
CURRENT=664806807
DELETED=664783235
SHA=a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9
OTHER=0000000000000000000000000000000000000000000000000000000000000001

# case ID DESCRIPTION EXPECTED-REGEX ARGS...
case_() {
    local id=$1 description=$2 expected=$3; shift 3
    rm -rf "$cas"
    local output code verdict
    output=$("$fetch" --cas "$cas" --repository "$REPO" "$@" 2>&1); code=$?
    printf '%s\n' "$output" >"$raw/$id.log"
    verdict=FAIL
    [[ $output =~ $expected ]] && verdict=PASS
    if [[ $id == L1 && $verdict == PASS ]]; then
        [[ "$(sha256sum "$cas/objects/$SHA" | cut -d' ' -f1)" == "$SHA" ]] || verdict=FAIL
    elif [[ $id != L1 ]]; then
        [[ -z "$(ls -A "$cas/objects" 2>/dev/null)" ]] || verdict=FAIL
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$description" "$code" "${output//$'\n'/ }" "$verdict" >>"$results"
    printf 'RESULT\t%s\t%s\t%s\n' "$id" "$verdict" "$output"
}

# This host's DNS answers the asset host from the fake-IP range of a local
# traffic router (198.18.0.0/15): refused by default (L0); the other cases
# allow that range explicitly, as an operator of such a system would.
FAKE=198.18.0.0/15
case_ L0 "current asset, default address policy, fake-IP DNS on this host" "^failed 502 resolved address is not public" --asset "$CURRENT" --sha256 "$SHA" --size 800
case_ L1 "current asset, pinned digest and size" "^stored $SHA" --asset "$CURRENT" --sha256 "$SHA" --size 800 --allow-range "$FAKE"
case_ L2 "current asset, another pinned digest (same size)" "^failed 502 digest mismatch" --asset "$CURRENT" --sha256 "$OTHER" --size 800 --allow-range "$FAKE"
case_ L3 "asset deleted in R-003 step 3 (N-014)" "^failed 502 asset is gone \(HTTP 404\)" --asset "$DELETED" --sha256 "$OTHER" --size 800 --allow-range "$FAKE"
case_ L4 "current asset, another pinned size" "^failed 502 announced 800 bytes, pinned 799" --asset "$CURRENT" --sha256 "$SHA" --size 799 --allow-range "$FAKE"
case_ L5 "no asset host allowed: the redirect target is named and refused" "^failed 502 redirect to a host that is not an asset host: [a-z0-9.-]+" --asset "$CURRENT" --sha256 "$SHA" --size 800 --asset-hosts none
rm -rf "$cas"
fails=$(grep -c $'\tFAIL$' "$results")
echo "P3-005b live: $((6 - fails)) PASS, $fails FAIL"
[[ $fails -eq 0 ]]
