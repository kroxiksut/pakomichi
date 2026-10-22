#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "bootstrap-verifiers.sh must run as root" >&2
    exit 2
fi

dnf install -y --setopt=install_weak_deps=False gh minisign gnupg2 rpm

gh --version | head -n 1
gpg --version | head -n 1
minisign -v 2>&1 | head -n 1
rpmkeys --version

if command -v cosign >/dev/null 2>&1; then
    cosign version
else
    echo "cosign=not-installed; install a pinned, independently verified release before cosign Phase B cells"
fi
