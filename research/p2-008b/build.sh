#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P2-008b: build the library test binary offline in the stopped builder
# pakomichi-r004-build (AlmaLinux 9, glibc 2.34) with the P0-004 toolchain,
# run clippy and the whole library test suite there (the Linux-only code:
# the collector and the execution-policy reader), and copy the test binary
# to C:\temp\pakomichi\p2-008b\bin for the live runs on the targets. The
# dependency cache is the one of P3-005a (same crate, same Cargo.lock).
#
#   wsl.exe -d pakomichi-r004-build -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/p2-008b/build.sh
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=/mnt/c/temp/pakomichi/p2-008b
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
export CARGO_HOME=/mnt/c/temp/pakomichi/p3-005a/cargo-home
export CARGO_TARGET_DIR="$scratch/target"
export CARGO_NET_OFFLINE=true
export PATH="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"

cd "$project_root"
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --lib
binary=$(cargo test --locked --lib --no-run --message-format=json 2>/dev/null |
    python3 -I -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m.get("executable"):
        print(m["executable"])' | tail -1)
[[ -x "$binary" ]] || { echo "no test binary" >&2; exit 1; }
mkdir -p "$scratch/bin"
install -m 0755 "$binary" "$scratch/bin/pakomichi-lib-tests"
newest=$(readelf -V "$scratch/bin/pakomichi-lib-tests" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
[[ "$(printf '%s\n' "$newest" GLIBC_2.34 | sort -V | tail -1)" == GLIBC_2.34 ]] ||
    { echo "the test binary needs $newest" >&2; exit 1; }
sha256sum "$scratch/bin/pakomichi-lib-tests"
