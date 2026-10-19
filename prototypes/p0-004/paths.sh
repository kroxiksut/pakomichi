# SPDX-License-Identifier: MIT OR Apache-2.0
# Sourced by the P0-004 scripts after they set project_root.
#
# Build outputs and the dependency cache stay outside the checkout: under
# C:\temp\pakomichi\p0-004 in WSL, under the system temp directory elsewhere.

if [[ -d /mnt/c ]]; then
    p0004_scratch_root="/mnt/c/temp/pakomichi/p0-004"
else
    p0004_scratch_root="${TMPDIR:-/tmp}/pakomichi/p0-004"
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$p0004_scratch_root/target}"
# Filled once by fetch-dependencies.sh; every other script builds offline.
export CARGO_HOME="${P0004_CARGO_HOME:-$p0004_scratch_root/cargo-home}"
export RUSTUP_HOME="$project_root/.research-local/p0-004/toolchain/rustup"
p0004_toolchain_bin="$RUSTUP_HOME/toolchains/1.94.1-x86_64-unknown-linux-gnu/bin"
export PATH="$p0004_toolchain_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PYTHONDONTWRITEBYTECODE=1
