#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build the R-001 DEB fixtures and the signed flat APT repositories of every
# layout. Runs in the DEB builder distribution, never in a target.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readonly root="${R001_ROOT:-$project_root/.research-local/r-001}"
readonly out="$root/fixtures/deb" layouts="$root/layouts/deb"
# Fixed timestamps keep rebuilt packages byte-identical.
export SOURCE_DATE_EPOCH=1760832000

work="$(mktemp -d /tmp/pakomichi-r001-deb.XXXXXX)"
export GNUPGHOME="$work/gnupg"
mkdir -m 0700 "$GNUPGHOME"
trap 'rm -rf "$work"' EXIT
for repo in alpha beta system; do
    gpg --batch --quiet --import "$root/keys/$repo.sec.asc"
done

# "name OP version; name" -> "name (OP version), name"
deb_relations() {
    local list="${1//@GLIBC@/libc6}" item result=()
    IFS=';' read -ra items <<< "$list"
    for item in "${items[@]}"; do
        item="$(echo "$item" | xargs)"
        [[ -z "$item" ]] && continue
        read -r name op version <<< "$item"
        if [[ -n "${op:-}" ]]; then result+=("$name ($op $version)"); else result+=("$name"); fi
    done
    local IFS=','
    echo "${result[*]}" | sed 's/,/, /g'
}

rm -rf "$out" "$layouts"
mkdir -p "$out"
while IFS='|' read -r id name version release variant publisher depends provides; do
    [[ -z "$id" || "$id" == \#* ]] && continue
    pkg="$work/pkg/$id"
    mkdir -p "$pkg/DEBIAN" "$pkg/usr/share/$name"
    printf '%s %s-%s variant=%s publisher=%s fixture=r-001\n' \
        "$name" "$version" "$release" "$variant" "$publisher" > "$pkg/usr/share/$name/marker"
    if [[ "$name" == sampleapp ]]; then
        mkdir -p "$pkg/usr/bin"
        printf '#!/bin/sh\ncat /usr/share/sampleapp/marker\n' > "$pkg/usr/bin/sampleapp"
        chmod 0755 "$pkg/usr/bin/sampleapp"
    fi
    {
        printf 'Package: %s\nVersion: %s-%s\nArchitecture: all\n' "$name" "$version" "$release"
        printf 'Maintainer: Pakomichi R-001 TEST ONLY %s <r001-%s@pakomichi.test>\n' "$publisher" "$publisher"
        [[ -n "$depends" ]] && printf 'Depends: %s\n' "$(deb_relations "$depends")"
        [[ -n "$provides" ]] && printf 'Provides: %s\n' "$(deb_relations "$provides")"
        printf 'Section: misc\nPriority: optional\n'
        printf 'Description: Pakomichi R-001 synthetic fixture %s (TEST ONLY)\n' "$id"
    } > "$pkg/DEBIAN/control"
    find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    mkdir -p "$out/$id"
    dpkg-deb --build --root-owner-group -Zxz "$pkg" "$out/$id/${name}_${version}-${release}_all.deb" >/dev/null
    if dpkg-deb --ctrl-tarfile "$out/$id"/*.deb | tar -tf - | grep -Eq '(pre|post)(inst|rm)$'; then
        echo "FAIL: $id contains maintainer scripts" >&2
        exit 1
    fi
done < "$script_dir/fixtures.txt"

(cd "$out" && find . -name '*.deb' | sort | xargs sha256sum) > "$out/SHA256SUMS"

while IFS='|' read -r layout repo ids; do
    [[ -z "$layout" || "$layout" == \#* ]] && continue
    dir="$layouts/$layout/$repo"
    mkdir -p "$dir"
    for id in $ids; do cp "$out/$id"/*.deb "$dir/"; done
    (
        cd "$dir"
        apt-ftparchive packages . > Packages
        gzip -9nk Packages
        apt-ftparchive \
            -o APT::FTPArchive::Release::Origin="Pakomichi R-001 TEST ONLY $repo" \
            -o APT::FTPArchive::Release::Label="pakomichi-r001-$repo" \
            -o APT::FTPArchive::Release::Suite="pakomichi-r001-$repo" \
            -o APT::FTPArchive::Release::Codename="pakomichi-r001-$repo" \
            release . > Release
        uid="r001-$repo@pakomichi.test"
        gpg --batch --yes --digest-algo SHA512 --local-user "$uid" --clearsign -o InRelease Release
        gpg --batch --yes --digest-algo SHA512 --local-user "$uid" -abs -o Release.gpg Release
    )
done < "$script_dir/layouts.txt"

cat "$out/SHA256SUMS"
echo "PASS: DEB fixtures and signed layouts in $root"
