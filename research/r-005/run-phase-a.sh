#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "${script_dir}/../.." && pwd)"
local_root="${project_root}/.research-local/r-005"
raw_dir="${local_root}/raw"
results_dir="${project_root}/research/r-005/results"
token_file="${local_root}/secrets/github-token"

if [[ "${1:-}" == "dry-run" ]]; then
    raw_dir="${local_root}/dry-run/raw"
    results_dir="${local_root}/dry-run/results"
    export R005_TARGET=2
    export R005_MINIMUM_PER_SOURCE=1
    export R005_SEARCH_PAGES=1
    export R005_PHASE_B_SIZE=2
    export R005_ALLOW_UNAUTHENTICATED=1
elif [[ -n "${1:-}" ]]; then
    echo "usage: run-phase-a.sh [dry-run]" >&2
    exit 2
fi

mkdir -p -- "${raw_dir}" "${results_dir}"

args=(
    collect
    --raw-dir "${raw_dir}"
    --target "${R005_TARGET:-100}"
    --minimum-per-source "${R005_MINIMUM_PER_SOURCE:-20}"
    --search-pages "${R005_SEARCH_PAGES:-2}"
    --phase-b-size "${R005_PHASE_B_SIZE:-20}"
    --candidates "${results_dir}/candidates.tsv"
    --results "${results_dir}/phase-a.tsv"
    --exclusions "${results_dir}/exclusions.tsv"
    --phase-b-sample "${results_dir}/phase-b-sample.tsv"
    --summary "${results_dir}/summary.json"
)

if [[ -f "${token_file}" ]]; then
    args+=(--token-file "${token_file}")
elif [[ "${R005_ALLOW_UNAUTHENTICATED:-0}" == "1" ]]; then
    args+=(--allow-unauthenticated)
fi

exec python3 -I "${script_dir}/survey.py" "${args[@]}"
