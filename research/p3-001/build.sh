#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P3-001: in the stopped builder pakomichi-r004-build (AlmaLinux 9, glibc
# 2.34), with the P0-004 toolchain and the P3-005a dependency cache, run
# clippy and the library tests (the signer and the APT publisher need
# /usr/bin/gpg and /usr/bin/gpgv), then build the reader and the research
# publisher tool for the live runs into C:\temp\pakomichi\p3-001\bin.
#
#   wsl.exe -d pakomichi-r004-build -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/p3-001/build.sh [TEST-FILTER]
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch=/mnt/c/temp/pakomichi/p3-001
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
export CARGO_HOME=/mnt/c/temp/pakomichi/p3-005a/cargo-home
export CARGO_TARGET_DIR="$scratch/target"
export CARGO_NET_OFFLINE=true
export PATH="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin:/usr/local/bin:/usr/bin:/bin"

cd "$project_root"
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --lib -- "${1:-}"
if [[ -z ${1:-} ]]; then
    cargo build --locked --release --bin pakomichi-reader
    tool=research/p3-001/publish-tool
    [[ -f $tool/Cargo.lock ]] || cargo generate-lockfile --offline --manifest-path $tool/Cargo.toml
    cargo clippy --locked --release --manifest-path $tool/Cargo.toml \
        --target-dir "$scratch/tool-target" -- -D warnings
    cargo build --locked --release --manifest-path $tool/Cargo.toml --target-dir "$scratch/tool-target"
    mkdir -p "$scratch/bin"
    install -m 0755 "$CARGO_TARGET_DIR/release/pakomichi-reader" "$scratch/bin/"
    install -m 0755 "$scratch/tool-target/release/p3001-publish" "$scratch/bin/"
    for binary in "$scratch"/bin/*; do
        newest=$(readelf -V "$binary" | grep -o 'GLIBC_2\.[0-9]*' | sort -uV | tail -1)
        [[ "$(printf '%s\n' "$newest" GLIBC_2.34 | sort -V | tail -1)" == GLIBC_2.34 ]] ||
            { echo "$binary needs $newest" >&2; exit 1; }
    done
    sha256sum "$scratch"/bin/*
fi
