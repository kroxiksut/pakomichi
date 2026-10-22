#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "bootstrap-wsl.sh must run as root" >&2
    exit 2
fi

if [[ ! -r /etc/os-release ]]; then
    echo "missing /etc/os-release" >&2
    exit 2
fi

. /etc/os-release
if [[ "${ID:-}" != "fedora" || "${VERSION_ID:-}" != "44" ]]; then
    echo "expected the digest-pinned Fedora 44 research image, got ${ID:-?} ${VERSION_ID:-?}" >&2
    exit 2
fi

dnf install -y --setopt=install_weak_deps=False python3 ca-certificates

if ! id r005 >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash r005
fi

echo "os=${PRETTY_NAME}"
echo "kernel=$(uname -srmo)"
echo "python=$(python3 --version 2>&1)"
echo "dnf=$(dnf5 --version 2>&1 | head -n 1)"
echo "rpm=$(rpm --version)"
echo "research_user=$(id r005)"
