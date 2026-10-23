#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build pakomichi-reader and the P3-005a publish tool offline in the stopped
# builder pakomichi-r004-build (AlmaLinux 9, glibc 2.34) with the P0-004
# toolchain. The dependency cache C:\temp\pakomichi\p3-005a\cargo-home must
# already hold the crate's dependencies (cargo fetch --locked of the main
# crate). Output: C:\temp\pakomichi\p3-005a\bin (outside the checkout).
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=/mnt/c/temp/pakomichi/p3-005a
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
export CARGO_HOME="$scratch/cargo-home"
export CARGO_TARGET_DIR="$scratch/target"
export CARGO_NET_OFFLINE=true
export PATH="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"

cd "$project_root"
cargo build --locked --release --bin pakomichi-reader
cd research/p3-005a/publish-tool
[[ -f Cargo.lock ]] || cargo generate-lockfile --offline
cargo build --locked --release
cargo clippy --locked --release -- -D warnings

mkdir -p "$scratch/bin"
install -m 0755 "$CARGO_TARGET_DIR/release/pakomichi-reader" "$scratch/bin/pakomichi-reader"
install -m 0755 "$CARGO_TARGET_DIR/release/pakomichi-p3005a-publish" "$scratch/bin/p3005a-publish"
# Both binaries must run on every target (oldest: glibc 2.34, AlmaLinux 9).
for binary in "$scratch"/bin/*; do
    newest=$(readelf -V "$binary" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
    [[ "$(printf '%s\n' "$newest" GLIBC_2.34 | sort -V | tail -1)" == GLIBC_2.34 ]] ||
        { echo "$binary needs $newest" >&2; exit 1; }
done
sha256sum "$scratch"/bin/*
