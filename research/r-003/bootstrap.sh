#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare the disposable pakomichi-r003-* WSL distribution: base tools, an
# unprivileged research user, and a pinned, checksum-verified GitHub CLI
# (the ADR-017 reference oracle). Runs as root inside the distribution only.
set -euo pipefail

readonly gh_version="2.95.0"
# Same pin as prototypes/p0-004/verify-github-attestation.sh, where this
# tarball was itself verified against its cli/cli build attestation.
readonly gh_sha256="25d1e4729e8808c9ed3d613e96ebd3f3e44446f2d368c89d878a71a36ddb3d8c"
readonly gh_prefix="/opt/r003-gh"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "bootstrap.sh must run as root" >&2
    exit 2
fi
. /etc/os-release
if [[ "${ID:-}" != "fedora" || "${VERSION_ID:-}" != "44" ]]; then
    echo "expected the digest-pinned Fedora 44 research image, got ${ID:-?} ${VERSION_ID:-?}" >&2
    exit 2
fi
if [[ "${WSL_DISTRO_NAME:-}" != pakomichi-r003-* ]]; then
    echo "refusing to bootstrap outside a pakomichi-r003-* distribution (${WSL_DISTRO_NAME:-unset})" >&2
    exit 2
fi

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
readonly tools="$project_root/.research-local/r-003/tools"

dnf install -y --setopt=install_weak_deps=False \
    python3 ca-certificates curl tar gzip util-linux findutils

if ! id r003 >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash r003
fi

mkdir -p "$tools"
tarball="$tools/gh_${gh_version}_linux_amd64.tar.gz"
if [[ ! -f "$tarball" ]] || [[ "$(sha256sum "$tarball" | awk '{print $1}')" != "$gh_sha256" ]]; then
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        --output "$tarball.part" \
        "https://github.com/cli/cli/releases/download/v${gh_version}/gh_${gh_version}_linux_amd64.tar.gz"
    mv "$tarball.part" "$tarball"
fi
actual="$(sha256sum "$tarball" | awk '{print $1}')"
if [[ "$actual" != "$gh_sha256" ]]; then
    echo "gh tarball digest $actual does not match pin $gh_sha256" >&2
    exit 1
fi
rm -rf "$gh_prefix"
mkdir -p "$gh_prefix"
tar -xzf "$tarball" -C "$gh_prefix" --strip-components=1 --no-same-owner
chmod -R go-w "$gh_prefix"

echo "os=${PRETTY_NAME}"
echo "kernel=$(uname -srmo)"
echo "python=$(python3 --version 2>&1)"
echo "curl=$(curl --version | head -n 1)"
echo "gh=$("$gh_prefix/bin/gh" --version | head -n 1)"
echo "gh_tarball_sha256=$actual"
echo "research_user=$(id r003)"
