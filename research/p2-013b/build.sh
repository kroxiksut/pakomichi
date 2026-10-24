#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P2-013b: in the stopped builder pakomichi-r004-build (AlmaLinux 9, glibc
# 2.34), with the P0-004 toolchain and the P3-005a dependency cache, run
# clippy and the library tests, then build the process binaries of
# ADR-035 and the research tools into C:\temp\pakomichi\p2-013b\bin.
#
#   wsl.exe -d pakomichi-r004-build -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/p2-013b/build.sh
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=/mnt/c/temp/pakomichi/p2-013b
build=/mnt/c/temp/pakomichi/p3-001
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
export CARGO_HOME=/mnt/c/temp/pakomichi/p3-005a/cargo-home
export CARGO_TARGET_DIR="$build/target"
export CARGO_NET_OFFLINE=true
export PATH="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"

cd "$project_root"
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --lib
cargo build --locked --release --bins
mkdir -p "$scratch/bin"
for binary in pakomichi-reader pakomichi-state pakomichi-signer pakomichi-inspector; do
    install -m 0755 "$CARGO_TARGET_DIR/release/$binary" "$scratch/bin/"
done
for tool in research/p3-001/publish-tool research/p3-005b/fetch-tool research/p2-013b/call-tool; do
    [[ -f $tool/Cargo.lock ]] || cargo generate-lockfile --offline --manifest-path "$tool/Cargo.toml"
    cargo clippy --locked --release --manifest-path "$tool/Cargo.toml" --target-dir "$build/tool-target" -- -D warnings
    cargo build --locked --release --manifest-path "$tool/Cargo.toml" --target-dir "$build/tool-target"
done
for tool in p3001-publish p3005b-fetch p2013b-call; do
    install -m 0755 "$build/tool-target/release/$tool" "$scratch/bin/"
done
for binary in "$scratch"/bin/*; do
    newest=$(readelf -V "$binary" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
    [[ "$(printf '%s\n' "$newest" GLIBC_2.34 | sort -V | tail -1)" == GLIBC_2.34 ]] ||
        { echo "$binary needs $newest" >&2; exit 1; }
done
sha256sum "$scratch"/bin/*
