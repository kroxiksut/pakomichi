#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "probe-verifiers.sh must run as root" >&2
    exit 2
fi

for package in gh cosign minisign gnupg2 rpm; do
    echo "=== ${package} ==="
    dnf repoquery --available --queryformat '%{name}\t%{evr}\t%{repoid}' "${package}" || true
done
