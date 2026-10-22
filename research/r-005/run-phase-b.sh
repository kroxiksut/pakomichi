#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "${script_dir}/../.." && pwd)"
local_root="${project_root}/.research-local/r-005"
results_dir="${project_root}/research/r-005/results"
raw_dir="${local_root}/raw/phase-b"
token_file="${local_root}/secrets/github-token"

if [[ "${1:-}" == "dry-run" ]]; then
    results_dir="${local_root}/dry-run/results"
    raw_dir="${local_root}/dry-run/raw/phase-b"
elif [[ -n "${1:-}" ]]; then
    echo "usage: run-phase-b.sh [dry-run]" >&2
    exit 2
fi

download_dir="$(mktemp -d /tmp/pakomichi-r005-phase-b.XXXXXX)"
cleanup() {
    case "${download_dir}" in
        /tmp/pakomichi-r005-phase-b.*) rm -rf -- "${download_dir}" ;;
        *) echo "refusing to remove unexpected path: ${download_dir}" >&2 ;;
    esac
}
trap cleanup EXIT

mkdir -p -- "${raw_dir}"
args=(
    verify
    --plan "${results_dir}/phase-b-plan.tsv"
    --downloads "${download_dir}"
    --run-dir "${raw_dir}"
    --results "${results_dir}/phase-b.tsv"
)
if [[ -f "${token_file}" ]]; then
    args+=(--token-file "${token_file}")
fi

# This disposable WSL network maps public destinations into 198.18.0.0/15.
export PAKOMICHI_WSL_SYNTHETIC_DNS=1
python3 -I "${script_dir}/phase_b.py" "${args[@]}"
