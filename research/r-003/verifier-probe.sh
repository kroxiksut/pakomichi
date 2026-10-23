#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build the P1-003c verifier probe in the stopped builder pakomichi-r004-build
# (AlmaLinux 9) with the P0-004 toolchain. Outputs stay outside the checkout:
# C:\temp\pakomichi\p1-003c\{cargo-home,target,bin}.
#   verifier-probe.sh fetch   resolve Cargo.lock and fill the cache (network)
#   verifier-probe.sh build   offline build, clippy, and dependency gates
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=/mnt/c/temp/pakomichi/p1-003c
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
export CARGO_HOME="$scratch/cargo-home"
export CARGO_TARGET_DIR="$scratch/target"
export PATH="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"
cd "$project_root/research/r-003/verifier-probe"

case "${1:-}" in
fetch)
    [[ -f Cargo.lock ]] || cargo generate-lockfile
    cargo fetch --locked
    ;;
build)
    export CARGO_NET_OFFLINE=true
    cargo build --locked --release
    cargo clippy --locked --release --all-targets -- -D warnings
    echo "== aws-lc in the graph (must be empty)"
    for crate in aws-lc-rs aws-lc-sys; do
        if cargo tree --locked -e normal -i "$crate" 2> /dev/null; then
            echo "FAIL: $crate is in the dependency graph" >&2
            exit 1
        fi
    done
    echo "none"
    echo "== duplicate crates"
    cargo tree --locked -e normal -d || true
    echo "== normal dependency count"
    cargo tree --locked -e normal --prefix none > "$scratch/tree.txt"
    sed 's/ (\*)$//' "$scratch/tree.txt" | sort -u > "$scratch/crates.txt"
    wc -l < "$scratch/crates.txt"
    mkdir -p "$scratch/bin"
    install -m 0755 "$CARGO_TARGET_DIR/release/pakomichi-r003-verifier-probe" "$scratch/bin/verifier-probe"
    echo "== binary"
    stat -c '%s bytes' "$scratch/bin/verifier-probe"
    sha256sum "$scratch/bin/verifier-probe"
    ;;
*)
    echo "usage: $0 fetch|build" >&2
    exit 2
    ;;
esac
