#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
# shellcheck source=paths.sh
source "$project_root/prototypes/p0-004/paths.sh"

# Runs cargo for the prototype offline with the lab toolchain, for example:
#   bash prototypes/p0-004/run-cargo.sh test --all-targets --locked
export CARGO_NET_OFFLINE=true
cd "$project_root/prototypes/p0-004"
exec cargo "$@"
