#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
readonly research_root="$project_root/.research-local/p0-004"
readonly tool_root="$research_root/toolchain"
readonly rustup_init="$research_root/rustup-init"
readonly rustup_sha="$research_root/rustup-init.sha256"
readonly rustup_url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"

mkdir -p "$research_root" "$tool_root/cargo" "$tool_root/rustup"

if [[ ! -x "$rustup_init" ]]; then
    curl --proto '=https' --tlsv1.2 --fail --location \
        --output "$rustup_init" "$rustup_url"
    curl --proto '=https' --tlsv1.2 --fail --location \
        --output "$rustup_sha" "$rustup_url.sha256"
    (
        cd "$research_root"
        sed 's|  rustup-init$|  rustup-init|' rustup-init.sha256 | sha256sum --check --strict
    )
    chmod 0755 "$rustup_init"
fi

export CARGO_HOME="$tool_root/cargo"
export RUSTUP_HOME="$tool_root/rustup"
export PATH="$CARGO_HOME/bin:$PATH"

"$rustup_init" -y --no-modify-path --profile minimal \
    --default-toolchain 1.94.1 --component rustfmt,clippy

sha256sum "$rustup_init"
rustc --version
cargo --version
