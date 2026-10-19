#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly work="/tmp/pakomichi-p0-004-deb-inspection"
readonly tree="$work/tree"
readonly marker="$work/maintainer-script-ran"
readonly package="$work/pakomichi-probe_1.0.0_amd64.deb"
readonly status_before="$(sha256sum /var/lib/dpkg/status | awk '{print $1}')"

rm -rf "$work"
trap 'rm -rf "$work"' EXIT
mkdir -p "$tree/DEBIAN" "$tree/usr/share/pakomichi-probe"
printf 'Package: pakomichi-probe\nVersion: 1.0.0\nArchitecture: amd64\nMaintainer: Pakomichi test fixture <noreply@example.invalid>\nDescription: P0-004 metadata inspection fixture\n' > "$tree/DEBIAN/control"
printf '#!/bin/sh\ntouch %s\n' "$marker" > "$tree/DEBIAN/preinst"
chmod 0755 "$tree/DEBIAN/preinst"
printf 'fixture\n' > "$tree/usr/share/pakomichi-probe/fixture.txt"

dpkg-deb --build --root-owner-group "$tree" "$package"
test "$(dpkg-deb --field "$package" Package)" = "pakomichi-probe"
dpkg-deb --info "$package" | grep -q preinst
test ! -e "$marker"

head -c 48 "$package" > "$work/malformed.deb"
if dpkg-deb --info "$work/malformed.deb"; then
    printf 'FAIL: malformed DEB was accepted\n' >&2
    exit 1
fi
test ! -e "$marker"
test "$(sha256sum /var/lib/dpkg/status | awk '{print $1}')" = "$status_before"
printf 'PASS: DEB metadata inspection did not execute scripts or change dpkg state\n'
