#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Template for the owner's R-003 test repository (copy to `scripts/` there).
# Builds a tiny, inert `.deb` fixture whose payload is only a version file.
# No maintainer scripts are included, so installing it runs no code.
# The optional VARIANT adds a marker file so that a rebuild of the same
# version has different bytes (R-003 step 3); without it the output is
# unchanged.
set -euo pipefail

usage="usage: build-fixture.sh VERSION OUTPUT_DIR [VARIANT]"
version="${1:?$usage}"
output="${2:?$usage}"
variant="${3:-}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "version must be MAJOR.MINOR.PATCH" >&2
    exit 2
fi
if [[ -n "$variant" && ! "$variant" =~ ^[a-z0-9-]{1,32}$ ]]; then
    echo "variant must be 1-32 characters of [a-z0-9-]" >&2
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
if [[ -n "$variant" ]]; then
    printf '%s\n' "$variant" > "$root/usr/share/pakomichi-r003-fixture/variant"
fi
export SOURCE_DATE_EPOCH=0
dpkg-deb --root-owner-group -Zxz --build "$root" "$output/pakomichi-r003-fixture_${version}_all.deb"
sha256sum "$output"/*.deb
