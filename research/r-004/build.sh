#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build r004-snapshotd offline in pakomichi-r004-build (AlmaLinux 9, glibc
# 2.34) with the P0-004 toolchain and dependency cache. Output:
# C:\temp\pakomichi\r004\bin\r004-snapshotd (outside the checkout).
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=/mnt/c/temp/pakomichi
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
export CARGO_HOME="$scratch/p0-004/cargo-home"
export CARGO_TARGET_DIR="$scratch/r004/target"
export CARGO_NET_OFFLINE=true
export PATH="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"

cd "$project_root/research/r-004/snapshotd"
cargo test --locked --release "$@"
cargo clippy --locked --release --all-targets -- -D warnings
cargo build --locked --release
# The binary must run on every target (oldest: glibc 2.34 on AlmaLinux 9).
newest=$(readelf -V "$CARGO_TARGET_DIR/release/pakomichi-r004-snapshotd" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
if [[ "$(printf '%s\n' "$newest" GLIBC_2.34 | sort -V | tail -1)" != GLIBC_2.34 ]]; then
    echo "binary needs $newest; rebuild in pakomichi-r004-build" >&2
    exit 1
fi
mkdir -p "$scratch/r004/bin"
install -m 0755 "$CARGO_TARGET_DIR/release/pakomichi-r004-snapshotd" "$scratch/r004/bin/r004-snapshotd"
sha256sum "$scratch/r004/bin/r004-snapshotd"
