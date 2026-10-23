#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare the disposable pakomichi-r003-* WSL distribution: base tools, an
# unprivileged research user, and a pinned, checksum-verified GitHub CLI
# (the ADR-017 reference oracle). Runs as root inside the distribution only.
set -euo pipefail

readonly gh_version="2.103.0"
# Verified on 2026-10-22 by verify-gh-pin.sh with the previous pin (2.95.0)
# against its cli/cli build provenance and release attestation
# (results/gh-pin-verify-2.103.0.tsv). 2.95.0 had attestation-matching flaws
# fixed in 2.97.0 (GHSA-mm27-mwq9-fr5g) and 2.102.0 (GHSA-wjmr-j3rp-mh2g,
# GHSA-4mq3-hpgx-9cx8); the same pin as verifier-probe-oracle.sh.
readonly gh_sha256="fdd768eb70f6409f80fcfa9f3a1c0adf0fc98d827ab3ce0bed2ac22762c5d786"
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
printf '%s\n' "$actual" > "$gh_prefix/TARBALL-SHA256"
chmod -R go-w "$gh_prefix"

echo "os=${PRETTY_NAME}"
echo "kernel=$(uname -srmo)"
echo "python=$(python3 --version 2>&1)"
echo "curl=$(curl --version | head -n 1)"
echo "gh=$("$gh_prefix/bin/gh" --version | head -n 1)"
echo "gh_tarball_sha256=$actual"
echo "research_user=$(id r003)"
