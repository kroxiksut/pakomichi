#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P4-001a: in the stopped builder pakomichi-r004-build (AlmaLinux 9, glibc
# 2.34), with the P0-004 toolchain and the P3-005a dependency cache, build
# every process binary and the CLI into C:\temp\pakomichi\p4-001a\bin.
#
#   wsl.exe -d pakomichi-r004-build -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/p4-001a/build.sh
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=/mnt/c/temp/pakomichi/p4-001a
build=/mnt/c/temp/pakomichi/p3-001
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
export CARGO_HOME=/mnt/c/temp/pakomichi/p3-005a/cargo-home
export CARGO_TARGET_DIR="$build/target"
export CARGO_NET_OFFLINE=true
export PATH="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"

binaries=(pakomichi-state pakomichi-reader pakomichi-signer pakomichi-inspector pakomichi-applier pchi)
cd "$project_root"
args=()
for binary in "${binaries[@]}"; do args+=(--bin "$binary"); done
cargo build --locked --release "${args[@]}"
rm -rf "$scratch/bin"
mkdir -p "$scratch/bin"
for binary in "${binaries[@]}"; do
    install -m 0755 "$CARGO_TARGET_DIR/release/$binary" "$scratch/bin/"
done
for binary in "$scratch"/bin/*; do
    newest=$(readelf -V "$binary" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
    [[ "$(printf '%s\n' "$newest" GLIBC_2.34 | sort -V | tail -1)" == GLIBC_2.34 ]] ||
        { echo "$binary needs $newest" >&2; exit 1; }
done
sha256sum "$scratch"/bin/*
