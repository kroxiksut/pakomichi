#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare an R-004 target (stage 2, systemd running): install the research
# binary and units, create the TEST ONLY signing key, build fixture packages,
# and start the fault-injecting upstream. Run as root inside the target with
# the harness already copied to /opt/r004 (run.ps1 does this).
set -euo pipefail
# shellcheck source=lib.sh
source /opt/r004/lib.sh

[[ "$(ps -o comm= -p 1)" == systemd ]] || { echo "systemd is not PID 1" >&2; exit 1; }

install -m 0755 /opt/r004/r004-snapshotd "$BIN"
install -m 0644 /opt/r004/units/r004-snapshotd.socket /opt/r004/units/r004-snapshotd.service /etc/systemd/system/
install -d -o pakomichi-r004 -g pakomichi-r004 -m 0750 "$ROOT"
install -d -m 0755 "$GENS" /etc/r004
install -d -m 0700 "$WORK" "$SIGNER"

# TEST ONLY Ed25519 signing key, kept on the target's native filesystem.
if ! gpg --homedir "$SIGNER" --list-secret-keys "$KEY_UID" >/dev/null 2>&1; then
    gpg --homedir "$SIGNER" --batch --pinentry-mode loopback --passphrase '' \
        --quick-generate-key "$KEY_UID" ed25519 sign 1y 2>/dev/null
fi
gpg --homedir "$SIGNER" --export "$KEY_UID" >"$KEYRING"
chmod 0644 "$KEYRING"

# Fixture packages: sampleapp 1.0/2.0/3.0 (a script) and bigapp (20 MiB of
# random bytes, used for lazy fetch and throughput).
pkg="$WORK/pkg"
rm -rf "$pkg" && mkdir -p "$pkg" "$WORK/upstream"
head -c $((20 * 1024 * 1024)) /dev/urandom >"$pkg/blob"
if [[ "$FAMILY" == apt ]]; then
    build_deb() { # name version payload-command
        local name=$1 version=$2 tree="$pkg/$1-$2"
        mkdir -p "$tree/DEBIAN" "$tree/usr/bin" "$tree/usr/share/$name"
        printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: R-004 TEST ONLY <noreply@example.invalid>\nDescription: R-004 TEST ONLY fixture\n' \
            "$name" "$version" >"$tree/DEBIAN/control"
        printf '#!/bin/sh\necho "%s %s"\n' "$name" "$version" >"$tree/usr/bin/$name"
        chmod 0755 "$tree/usr/bin/$name"
        [[ "$name" == r004-bigapp ]] && cp "$pkg/blob" "$tree/usr/share/$name/blob"
        dpkg-deb --root-owner-group -Zgzip -z1 --build "$tree" "$pkg/${name}_${version}_all.deb" >/dev/null
    }
    for v in 1.0 2.0 3.0; do build_deb r004-sampleapp "$v"; done
    build_deb r004-bigapp 1.0
else
    build_rpm() { # name version
        local name=$1 version=$2 top="$pkg/rpmbuild-$1-$2"
        mkdir -p "$top/SPECS"
        cat >"$top/SPECS/$name.spec" <<EOF
Name: $name
Version: $version
Release: 1
Summary: R-004 TEST ONLY fixture
License: MIT
BuildArch: noarch
%description
R-004 TEST ONLY fixture.
%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/share/$name
printf '#!/bin/sh\necho "$name $version"\n' > %{buildroot}/usr/bin/$name
chmod 0755 %{buildroot}/usr/bin/$name
[ "$name" = r004-bigapp ] && cp $pkg/blob %{buildroot}/usr/share/$name/blob || true
%files
/usr/bin/$name
/usr/share/$name
EOF
        rpmbuild --quiet --define "_topdir $top" --define '_binary_payload w1.gzdio' \
            --define '__brp_strip /bin/true' -bb "$top/SPECS/$name.spec" >/dev/null 2>&1
        cp "$top"/RPMS/noarch/*.rpm "$pkg/"
    }
    for v in 1.0 2.0 3.0; do build_rpm r004-sampleapp "$v"; done
    build_rpm r004-bigapp 1.0
fi
rm -f "$pkg/blob"
cp "$pkg"/r004-bigapp*."$PKG_EXT" "$WORK/upstream/"
sha256sum "$pkg"/*."$PKG_EXT"

systemctl daemon-reload
systemctl enable --now r004-snapshotd.socket
systemctl reset-failed r004-upstream.service 2>/dev/null || true
systemctl stop r004-upstream.service 2>/dev/null || true
systemd-run --quiet --unit=r004-upstream python3 -I /opt/r004/upstream.py "$WORK/upstream" 18090
# The ports are shared by all WSL2 distributions: make sure ours answer.
big=$(basename "$(ls "$WORK"/upstream/r004-bigapp*."$PKG_EXT")")
for _ in $(seq 30); do
    [[ "$(curl -s -o /dev/null -w '%{http_code}' "$UPSTREAM/files/$big")" == 200 ]] && break
    sleep 0.5
done
[[ "$(curl -s -o /dev/null -w '%{http_code}' "$UPSTREAM/files/$big")" == 200 ]] ||
    { echo "upstream on 18090 is not ours (another distribution running?)" >&2; exit 1; }
systemctl is-active --quiet r004-snapshotd.socket || { echo "socket 18080 did not start" >&2; exit 1; }
echo "prepared $(hostname) family=$FAMILY"
