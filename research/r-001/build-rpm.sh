#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build the R-001 RPM fixtures and the signed DNF repositories of every
# layout. Runs in the RPM builder distribution (rpm 4.16, so the v4 packages
# are readable by DNF4 and DNF5 targets), never in a target.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readonly root="${R001_ROOT:-$project_root/.research-local/r-001}"
readonly out="$root/fixtures/rpm" layouts="$root/layouts/rpm"
export SOURCE_DATE_EPOCH=1760832000

work="$(mktemp -d /tmp/pakomichi-r001-rpm.XXXXXX)"
export GNUPGHOME="$work/gnupg"
mkdir -m 0700 "$GNUPGHOME"
trap 'rm -rf "$work"' EXIT
for repo in alpha beta system; do
    gpg --batch --quiet --import "$root/keys/$repo.sec.asc"
done

# "name OP version; name" -> one RPM dependency per line for a tag.
rpm_relations() {
    local tag="$1" list="${2//@GLIBC@/glibc}" item
    IFS=';' read -ra items <<< "$list"
    for item in "${items[@]}"; do
        item="$(echo "$item" | xargs)"
        [[ -n "$item" ]] && printf '%s: %s\n' "$tag" "$item"
    done
}

rm -rf "$out" "$layouts"
mkdir -p "$out"
while IFS='|' read -r id name version release variant publisher depends provides; do
    [[ -z "$id" || "$id" == \#* ]] && continue
    top="$work/top/$id"
    mkdir -p "$top"/{SPECS,RPMS,BUILD,BUILDROOT}
    {
        printf 'Name: %s\nVersion: %s\nRelease: %s\nSummary: Pakomichi R-001 synthetic fixture %s (TEST ONLY)\n' \
            "$name" "$version" "$release" "$id"
        printf 'License: MIT OR Apache-2.0\nBuildArch: noarch\nVendor: Pakomichi R-001 TEST ONLY %s\n' "$publisher"
        printf 'Packager: Pakomichi R-001 TEST ONLY %s <r001-%s@pakomichi.test>\n' "$publisher" "$publisher"
        rpm_relations Requires "$depends"
        rpm_relations Provides "$provides"
        printf '\n%%description\nSynthetic R-001 fixture; no scripts.\n\n%%install\n'
        printf 'mkdir -p %%{buildroot}/usr/share/%s\n' "$name"
        printf "echo '%s %s-%s variant=%s publisher=%s fixture=r-001' > %%{buildroot}/usr/share/%s/marker\n" \
            "$name" "$version" "$release" "$variant" "$publisher" "$name"
        if [[ "$name" == sampleapp ]]; then
            printf 'mkdir -p %%{buildroot}/usr/bin\n'
            printf "printf '#!/bin/sh\\\\ncat /usr/share/sampleapp/marker\\\\n' > %%{buildroot}/usr/bin/sampleapp\n"
            printf 'chmod 0755 %%{buildroot}/usr/bin/sampleapp\n'
        fi
        printf '\n%%files\n/usr/share/%s\n' "$name"
        [[ "$name" == sampleapp ]] && printf '/usr/bin/sampleapp\n'
    } > "$top/SPECS/$id.spec"
    rpmbuild --quiet -bb --define "_topdir $top" --define "_buildhost r001.pakomichi.test" \
        --define "use_source_date_epoch_as_buildtime 1" --define "clamp_mtime_to_source_date_epoch 1" \
        "$top/SPECS/$id.spec"
    rpmfile="$(find "$top/RPMS" -name '*.rpm')"
    if [[ -n "$(rpm -qp --scripts "$rpmfile")" ]]; then
        echo "FAIL: $id contains scriptlets" >&2
        exit 1
    fi
    rpmsign --addsign --define "_gpg_name r001-$publisher@pakomichi.test" \
        --define "_gpg_digest_algo sha256" "$rpmfile" >/dev/null
    mkdir -p "$out/$id"
    cp "$rpmfile" "$out/$id/"
done < "$script_dir/fixtures.txt"

(cd "$out" && find . -name '*.rpm' | sort | xargs sha256sum) > "$out/SHA256SUMS"

while IFS='|' read -r layout repo ids; do
    [[ -z "$layout" || "$layout" == \#* ]] && continue
    dir="$layouts/$layout/$repo"
    mkdir -p "$dir"
    for id in $ids; do cp "$out/$id"/*.rpm "$dir/"; done
    createrepo_c --quiet --revision "$SOURCE_DATE_EPOCH" --set-timestamp-to-revision "$dir"
    gpg --batch --yes --digest-algo SHA512 --local-user "r001-$repo@pakomichi.test" \
        --armor --detach-sign -o "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml"
done < "$script_dir/layouts.txt"

cat "$out/SHA256SUMS"
echo "PASS: RPM fixtures and signed layouts in $root"
