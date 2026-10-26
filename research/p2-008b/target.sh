#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P2-008b live run inside one disposable target (pakomichi-r004-p2008b-*):
# as root, refresh the distribution's native metadata (the only network
# step) and create an unprivileged user; then, as that user, run the live
# collector test, which reads the system namespace, the versions of the
# system's packages, and the execution policy without root, and checks
# N-009 against the C library the system really has.
#
#   P2008B_OUT=/mnt/d/.../runs/<target> bash target.sh
set -euo pipefail

out="${P2008B_OUT:?}"
binary=/opt/p2008b/pakomichi-lib-tests
test_name=namespace::collect::system::tests::live_namespace_of_this_system
mkdir -p "$out"

{
    . /etc/os-release
    printf 'os\t%s\n' "$PRETTY_NAME"
    printf 'kernel\t%s\n' "$(uname -srm)"
    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get -q update >/dev/null
        # The binary links the system SQLite (ADR-020).
        apt-get -q -y install --no-install-recommends libsqlite3-0 >/dev/null
        printf 'dpkg\t%s\n' "$(dpkg --version | head -1)"
        printf 'libc6\t%s\n' "$(dpkg-query -W -f '${Version}' libc6)"
    else
        dnf -q makecache >/dev/null
        # The binary links the system SQLite; the container image of Fedora
        # lacks runuser and useradd.
        for package in sqlite-libs util-linux shadow-utils; do
            rpm -q "$package" >/dev/null || dnf -y -q install "$package" >/dev/null
        done
        printf 'rpm\t%s\n' "$(rpm --version)"
        printf 'glibc\t%s\n' "$(rpm -q --qf '%{EVR}' glibc)"
    fi
    printf 'binary_sha256\t%s\n' "$(sha256sum "$binary" | cut -d' ' -f1)"
} >"$out/environment.tsv"

vendor_env=()
if [[ "${P2008B_VENDOR:-}" == pgdg ]]; then
    # A real vendor repository (PostgreSQL PGDG) as another source. Its key
    # is checked against the fingerprint the project publishes before APT
    # may trust it; only this disposable distribution changes.
    apt-get -q -y install --no-install-recommends gpg ca-certificates curl >/dev/null
    install -d -m 0755 /etc/apt/keyrings
    curl -fsS https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /etc/apt/keyrings/pgdg.asc
    fingerprint=$(gpg --show-keys --with-colons /etc/apt/keyrings/pgdg.asc | awk -F: '$1 == "fpr" { print $10; exit }')
    [[ "$fingerprint" == B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8 ]] ||
        { echo "unexpected PGDG key $fingerprint" >&2; exit 3; }
    echo "deb [signed-by=/etc/apt/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        >/etc/apt/sources.list.d/pgdg.list
    apt-get -q update >/dev/null
    printf 'vendor\tPGDG bookworm-pgdg, key %s\n' "$fingerprint" >>"$out/environment.tsv"
    printf 'libpq5\t%s\n' "$(apt-cache policy libpq5 | tr -s ' ' | grep -E '^ (\*\*\* )?[0-9]' | tr '\n' ';')" >>"$out/environment.tsv"
    vendor_env=(PAKOMICHI_EXPECT_OTHER_SOURCE=apt.postgresql.org
        "PAKOMICHI_VENDOR_ONLY=postgresql-16"
        "PAKOMICHI_VENDOR_NEWER=libpq5 (>= 17)")
fi

if [[ "${P2008B_VENDOR:-}" == copy ]]; then
    # The distribution's own archive from another mirror, signed by a copy of
    # the distribution keyring that no package owns (P2-014): the names and
    # the key are the distribution's, the ownership is not.
    . /etc/os-release
    case "$ID" in
    debian) mirror=http://ftp.debian.org/debian keyring=/usr/share/keyrings/debian-archive-keyring.gpg ;;
    ubuntu) mirror=http://mirrors.edge.kernel.org/ubuntu keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg ;;
    *) echo "no copy source for $ID" >&2; exit 3 ;;
    esac
    install -d -m 0755 /etc/apt/keyrings
    cp "$keyring" /etc/apt/keyrings/copy-of-distribution.gpg
    printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: main\nSigned-By: /etc/apt/keyrings/copy-of-distribution.gpg\n' \
        "$mirror" "$VERSION_CODENAME" >/etc/apt/sources.list.d/copy-of-distribution.sources
    apt-get -q update >/dev/null
    printf 'vendor\tcopy %s %s, keyring copied from %s\n' "$mirror" "$VERSION_CODENAME" "$keyring" >>"$out/environment.tsv"
    vendor_env=("PAKOMICHI_NS_EXPECT_FOREIGN=${mirror#http://}")
fi

getent passwd p2008b >/dev/null || useradd --create-home --shell /bin/bash p2008b
chmod 0755 "$binary"
status=0
runuser -u p2008b -- env -i PATH=/usr/bin:/bin HOME=/home/p2008b LANG=C.UTF-8 "${vendor_env[@]}" \
    "$binary" --ignored --exact "$test_name" --nocapture >"$out/live.log" 2>&1 || status=$?
echo "exit=$status" >>"$out/live.log"
cat "$out/live.log"
exit "$status"
