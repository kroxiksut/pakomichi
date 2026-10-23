#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare a P3-005a target (stage 2, systemd running): install the reader,
# the publish tool and the units, create the writer and reader users, the
# TEST ONLY signing key and the fixture packages, and start the socket.
# Run as root inside the target with the harness copied to /opt/p3005a.
set -euo pipefail
# shellcheck source=lib.sh
source /opt/p3005a/lib.sh

[[ "$(ps -o comm= -p 1)" == systemd ]] || { echo "systemd is not PID 1" >&2; exit 1; }

install -m 0755 /opt/p3005a/bin/pakomichi-reader /opt/p3005a/bin/p3005a-publish /usr/local/bin/
install -m 0644 /opt/p3005a/units/pakomichi-reader.socket /opt/p3005a/units/pakomichi-reader.service /etc/systemd/system/

# The writer owns the stores; the reader reads them only through the
# writer's group and has no write access anywhere.
getent group pakomichi >/dev/null || groupadd --system pakomichi
getent passwd pakomichi >/dev/null ||
    useradd --system --gid pakomichi --home-dir /nonexistent --shell /usr/sbin/nologin pakomichi
getent group pakomichi-reader >/dev/null || groupadd --system pakomichi-reader
getent passwd pakomichi-reader >/dev/null ||
    useradd --system --gid pakomichi-reader --groups pakomichi --home-dir /nonexistent \
        --shell /usr/sbin/nologin pakomichi-reader
rm -rf "$STATE"
install -d -o pakomichi -g pakomichi -m 0750 "$STATE"
install -d -m 0755 "$GENS" /etc/p3005a
install -d -m 0700 "$WORK" "$SIGNER"

if ! gpg --homedir "$SIGNER" --list-secret-keys "$KEY_UID" >/dev/null 2>&1; then
    gpg --homedir "$SIGNER" --batch --pinentry-mode loopback --passphrase '' \
        --quick-generate-key "$KEY_UID" ed25519 sign 1y 2>/dev/null
fi
gpg --homedir "$SIGNER" --export "$KEY_UID" >"$KEYRING"
chmod 0644 "$KEYRING"

pkg="$WORK/pkg"
rm -rf "$pkg" && mkdir -p "$pkg"
name=p3005a-sampleapp
for version in 1.0 2.0 3.0; do
    if [[ $FAMILY == apt ]]; then
        tree="$pkg/$name-$version"
        mkdir -p "$tree/DEBIAN" "$tree/usr/bin"
        printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: P3-005a TEST ONLY <noreply@example.invalid>\nDescription: P3-005a TEST ONLY fixture\n' \
            "$name" "$version" >"$tree/DEBIAN/control"
        printf '#!/bin/sh\necho "%s %s"\n' "$name" "$version" >"$tree/usr/bin/$name"
        chmod 0755 "$tree/usr/bin/$name"
        dpkg-deb --root-owner-group -Zgzip -z1 --build "$tree" "$pkg/${name}_${version}_all.deb" >/dev/null
    else
        top="$pkg/rpmbuild-$version"
        mkdir -p "$top/SPECS"
        cat >"$top/SPECS/$name.spec" <<EOF
Name: $name
Version: $version
Release: 1
Summary: P3-005a TEST ONLY fixture
License: MIT
BuildArch: noarch
%description
P3-005a TEST ONLY fixture.
%install
mkdir -p %{buildroot}/usr/bin
printf '#!/bin/sh\necho "$name $version"\n' > %{buildroot}/usr/bin/$name
chmod 0755 %{buildroot}/usr/bin/$name
%files
/usr/bin/$name
EOF
        rpmbuild --quiet --define "_topdir $top" --define '_binary_payload w1.gzdio' \
            --define '__brp_strip /bin/true' -bb "$top/SPECS/$name.spec" >/dev/null 2>&1
        cp "$top"/RPMS/noarch/*.rpm "$pkg/"
    fi
done
sha256sum "$pkg"/*."$PKG_EXT"

systemctl daemon-reload
systemctl enable --now pakomichi-reader.socket
systemctl is-active --quiet pakomichi-reader.socket || { echo "socket 18080 did not start" >&2; exit 1; }
echo "prepared $(hostname) family=$FAMILY backend=$BACKEND"
