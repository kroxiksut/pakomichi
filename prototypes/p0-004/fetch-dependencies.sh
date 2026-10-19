#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
# shellcheck source=paths.sh
source "$project_root/prototypes/p0-004/paths.sh"

# The only P0-004 step that needs the network: download the locked dependency
# graph (prototype and its RPM builder example) into CARGO_HOME.
test -x "$p0004_toolchain_bin/cargo" || {
    printf 'FAIL: run setup-rust.sh first
' >&2
    exit 1
}
mkdir -p "$CARGO_HOME"
cd "$project_root/prototypes/p0-004"
cargo fetch --locked
printf 'PASS: dependencies cached in %s
' "$CARGO_HOME"
