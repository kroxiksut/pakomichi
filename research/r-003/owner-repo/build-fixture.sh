#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Template for the owner's R-003 test repository (copy to `scripts/` there).
# Builds a tiny, inert `.deb` fixture whose payload is only a version file.
# No maintainer scripts are included, so installing it runs no code.
set -euo pipefail

version="${1:?usage: build-fixture.sh VERSION OUTPUT_DIR}"
output="${2:?usage: build-fixture.sh VERSION OUTPUT_DIR}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "version must be MAJOR.MINOR.PATCH" >&2
    exit 2
fi

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/DEBIAN" "$root/usr/share/pakomichi-r003-fixture" "$output"
cat > "$root/DEBIAN/control" <<EOF
Package: pakomichi-r003-fixture
Version: ${version}
Architecture: all
Maintainer: Pakomichi R-003 fixture <noreply@example.invalid>
Description: inert R-003 provenance test fixture
EOF
printf '%s\n' "$version" > "$root/usr/share/pakomichi-r003-fixture/version"
export SOURCE_DATE_EPOCH=0
dpkg-deb --root-owner-group -Zxz --build "$root" "$output/pakomichi-r003-fixture_${version}_all.deb"
sha256sum "$output"/*.deb
