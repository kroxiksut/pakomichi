#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
# shellcheck source=paths.sh
source "$project_root/prototypes/p0-004/paths.sh"
readonly probe_root="$project_root/prototypes/p0-004"
readonly output_root="${P0004_OUTPUT_ROOT:-$project_root/.research-local/p0-004/packages}"
readonly deb_root="/tmp/pakomichi-p0-004-deb-package"
export CARGO_NET_OFFLINE=true

rm -rf "$deb_root"
trap 'rm -rf "$deb_root"' EXIT
mkdir -p "$output_root" "$deb_root/DEBIAN" "$deb_root/usr/bin" \
    "$deb_root/usr/lib/systemd/system"

cd "$probe_root"
cargo build --release --locked
install -m 0755 "$CARGO_TARGET_DIR/release/pakomichi-stack-probe" \
    "$deb_root/usr/bin/pakomichi-stack-probe"
install -m 0644 pakomichi-stack-probe.service pakomichi-stack-probe.socket \
    "$deb_root/usr/lib/systemd/system/"
printf 'Package: pakomichi-stack-probe\nVersion: 0.0.0\nArchitecture: amd64\nMaintainer: Pakomichi test fixture <noreply@example.invalid>\nSection: utils\nPriority: optional\nDescription: Disposable Pakomichi P0-004 packaging probe\n' \
    > "$deb_root/DEBIAN/control"

readonly deb="$output_root/pakomichi-stack-probe_0.0.0_amd64.deb"
readonly rpm="$output_root/pakomichi-stack-probe-0.0.0-1.x86_64.rpm"
dpkg-deb --build --root-owner-group "$deb_root" "$deb"
test "$(dpkg-deb --field "$deb" Package)" = "pakomichi-stack-probe"
if dpkg-deb --ctrl-tarfile "$deb" | tar -tf - | grep -Eq '^\./(pre|post)(inst|rm)$'; then
    printf 'FAIL: probe DEB unexpectedly contains maintainer scripts\n' >&2
    exit 1
fi

cargo run --quiet --locked --example build_rpm -- "$rpm" "$CARGO_TARGET_DIR/release/pakomichi-stack-probe"
sha256sum "$deb" "$rpm"
printf 'PASS: native DEB/RPM packages built and inspected without installation\n'
