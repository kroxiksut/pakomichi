#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build the P3-002a DEB fixtures and their signed flat APT repositories.
# Runs in the R-001 DEB builder distribution, never in a target. Reuses the
# R-001 TEST ONLY keys; writes only under .research-local/p3-002a.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readonly root="${P3002A_ROOT:-$project_root/.research-local/p3-002a}"
readonly keys="$project_root/.research-local/r-001/keys"
readonly out="$root/fixtures" repos="$root/repos/p3002a"
export SOURCE_DATE_EPOCH=1760832000

work="$(mktemp -d /tmp/pakomichi-p3002a-build.XXXXXX)"
export GNUPGHOME="$work/gnupg"
mkdir -m 0700 "$GNUPGHOME"
trap 'rm -rf "$work"' EXIT
for key in alpha beta system; do
    gpg --batch --quiet --import "$keys/$key.sec.asc"
done

rm -rf "$out" "$root/repos"
mkdir -p "$out"
while IFS='|' read -r id name version publisher depends; do
    [[ -z "$id" || "$id" == \#* ]] && continue
    pkg="$work/pkg/$id"
    mkdir -p "$pkg/DEBIAN" "$pkg/usr/share/$name"
    printf '%s %s publisher=%s fixture=p3-002a\n' "$name" "$version" "$publisher" > "$pkg/usr/share/$name/marker"
    {
        printf 'Package: %s\nVersion: %s\nArchitecture: all\n' "$name" "$version"
        printf 'Maintainer: Pakomichi P3-002a TEST ONLY %s <p3002a-%s@pakomichi.test>\n' "$publisher" "$publisher"
        [[ -n "$depends" ]] && printf 'Depends: %s\n' "$depends"
        printf 'Section: misc\nPriority: optional\n'
        printf 'Description: Pakomichi P3-002a synthetic fixture %s (TEST ONLY)\n' "$id"
    } > "$pkg/DEBIAN/control"
    find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    mkdir -p "$out/$id"
    dpkg-deb --build --root-owner-group -Zxz "$pkg" "$out/$id/${name}_${version}_all.deb" > /dev/null
done < "$script_dir/fixtures.txt"
(cd "$out" && find . -name '*.deb' | sort | xargs sha256sum) > "$out/SHA256SUMS"

while IFS='|' read -r repo key origin label ids; do
    [[ -z "$repo" || "$repo" == \#* ]] && continue
    dir="$repos/$repo"
    mkdir -p "$dir"
    for id in $ids; do cp "$out/$id"/*.deb "$dir/"; done
    (
        cd "$dir"
        apt-ftparchive packages . > Packages
        gzip -9nk Packages
        apt-ftparchive \
            -o APT::FTPArchive::Release::Origin="$origin" \
            -o APT::FTPArchive::Release::Label="$label" \
            -o APT::FTPArchive::Release::Suite="$label" \
            -o APT::FTPArchive::Release::Codename="$label" \
            release . > Release
        uid="r001-$key@pakomichi.test"
        gpg --batch --yes --digest-algo SHA512 --local-user "$uid" --clearsign -o InRelease Release
    )
done < "$script_dir/repos.txt"

cat "$out/SHA256SUMS"
echo "PASS: P3-002a fixtures and repositories in $root"
