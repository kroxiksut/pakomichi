#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare a P3-001 target (systemd running): install the reader, the
# publisher tool and the units, create the writer and reader users, two
# TEST ONLY metadata keys (the signer's and another one), the keyrings, and
# the fixture packages, and start the reader socket. Run as root inside the
# target with the harness copied to /opt/p3001.
set -euo pipefail
# shellcheck source=lib.sh
source /opt/p3001/lib.sh

[[ "$(ps -o comm= -p 1)" == systemd ]] || { echo "systemd is not PID 1" >&2; exit 1; }

install -m 0755 /opt/p3001/bin/pakomichi-reader /opt/p3001/bin/p3001-publish /usr/local/bin/
install -m 0644 /opt/p3001/units/pakomichi-reader.socket /opt/p3001/units/pakomichi-reader.service \
    /etc/systemd/system/

getent group pakomichi >/dev/null || groupadd --system pakomichi
getent passwd pakomichi >/dev/null ||
    useradd --system --gid pakomichi --home-dir /nonexistent --shell /usr/sbin/nologin pakomichi
getent group pakomichi-reader >/dev/null || groupadd --system pakomichi-reader
getent passwd pakomichi-reader >/dev/null ||
    useradd --system --gid pakomichi-reader --groups pakomichi --home-dir /nonexistent \
        --shell /usr/sbin/nologin pakomichi-reader
rm -rf "$STATE"
install -d -o pakomichi -g pakomichi -m 0750 "$STATE" "$CAS"
install -d -o pakomichi -g pakomichi -m 0700 "$SIGNER" "$OTHER_SIGNER"
install -d -m 0755 /etc/apt/keyrings /etc/p3001
install -d -m 0755 "$WORK"

for home in "$SIGNER" "$OTHER_SIGNER"; do
    runuser -u pakomichi -- gpg --homedir "$home" --batch --pinentry-mode loopback --passphrase '' \
        --quick-generate-key "Pakomichi P3-001 TEST ONLY $(basename "$home") <p3001@example.invalid>" \
        ed25519 sign 1y 2>/dev/null
done
runuser -u pakomichi -- gpg --homedir "$SIGNER" --batch --export "$(fingerprint "$SIGNER")" >"$KEYRING"
runuser -u pakomichi -- gpg --homedir "$OTHER_SIGNER" --batch --export "$(fingerprint "$OTHER_SIGNER")" \
    >"$OTHER_KEYRING"
chmod 0644 "$KEYRING" "$OTHER_KEYRING"

pkg="$WORK/pkg"
rm -rf "$pkg" && mkdir -p "$pkg"
for version in 1.0 2.0 3.0 4.0; do
    tree="$pkg/$NAME-$version"
    mkdir -p "$tree/DEBIAN" "$tree/usr/bin"
    printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: P3-001 TEST ONLY <noreply@example.invalid>\nDescription: P3-001 TEST ONLY fixture\n' \
        "$NAME" "$version" >"$tree/DEBIAN/control"
    printf '#!/bin/sh\necho "%s %s"\n' "$NAME" "$version" >"$tree/usr/bin/$NAME"
    chmod 0755 "$tree/usr/bin/$NAME"
    dpkg-deb --root-owner-group -Zgzip -z1 --build "$tree" "$pkg/${NAME}_${version}_all.deb" >/dev/null
done
chmod 0755 "$WORK" "$pkg"
chmod 0644 "$pkg"/*.deb
sha256sum "$pkg"/*.deb

systemctl daemon-reload
systemctl enable --now pakomichi-reader.socket
systemctl is-active --quiet pakomichi-reader.socket || { echo "socket 18080 did not start" >&2; exit 1; }
echo "prepared $(hostname)"
