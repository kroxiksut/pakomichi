#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare a P3-002 target (systemd running, disposable): hide the
# distribution's own sources (this distribution is thrown away after the
# run), install the reader, the publisher tool, the adapter tool and the
# units, create the writer and reader users and the TEST ONLY keys, build
# the fixtures, publish the Pakomichi repositories (strict and pinned), and
# serve two other signed repositories: "distro" (a security update of the
# helper and the distribution's own distapp) and "other" (another
# publisher). Run as root with the harness in /opt/p3002.
set -euo pipefail
# shellcheck source=lib.sh
source /opt/p3002/lib.sh

[[ "$(ps -o comm= -p 1)" == systemd ]] || { echo "systemd is not PID 1" >&2; exit 1; }

mkdir -p /root/system-sources
mv /etc/apt/sources.list.d/* /root/system-sources/ 2>/dev/null || true
[[ -f /etc/apt/sources.list ]] && mv /etc/apt/sources.list /root/system-sources/sources.list
rm -rf /var/lib/apt/lists/*

install -m 0755 /opt/p3002/bin/pakomichi-reader /opt/p3002/bin/p3001-publish /opt/p3002/bin/p3002-apt \
    /usr/local/bin/
install -m 0644 /opt/p3002/units/pakomichi-reader.socket /opt/p3002/units/pakomichi-reader.service \
    /etc/systemd/system/
getent group pakomichi >/dev/null || groupadd --system pakomichi
getent passwd pakomichi >/dev/null ||
    useradd --system --gid pakomichi --home-dir /nonexistent --shell /usr/sbin/nologin pakomichi
getent group pakomichi-reader >/dev/null || groupadd --system pakomichi-reader
getent passwd pakomichi-reader >/dev/null ||
    useradd --system --gid pakomichi-reader --groups pakomichi --home-dir /nonexistent \
        --shell /usr/sbin/nologin pakomichi-reader
rm -rf "$STATE" /srv/p3002 "$OTHER_HOME" "$ADAPTER_STATE"
install -d -o pakomichi -g pakomichi -m 0750 "$STATE" "$CAS"
install -d -o pakomichi -g pakomichi -m 0700 "$SIGNER"
install -d -m 0755 /srv/p3002 "$WORK" "$OTHERS"
install -d -m 0700 "$OTHER_HOME"

runuser -u pakomichi -- gpg --homedir "$SIGNER" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "Pakomichi P3-002 TEST ONLY <p3002@example.invalid>" ed25519 sign 1y 2>/dev/null
runuser -u pakomichi -- gpg --homedir "$SIGNER" --batch --export "$(fingerprint "$SIGNER")" >"$KEYRING"
chmod 0644 "$KEYRING"
gpg --homedir "$OTHER_HOME" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "P3-002 TEST ONLY other repositories <p3002-other@example.invalid>" ed25519 sign 1y 2>/dev/null
other_key=$(gpg --homedir "$OTHER_HOME" --batch --with-colons --list-secret-keys | awk -F: '/^fpr/ {print $10; exit}')
gpg --homedir "$OTHER_HOME" --batch --export "$other_key" >/srv/p3002/others.gpg
chmod 0644 /srv/p3002/others.gpg

# name|version|publisher|depends
while IFS='|' read -r name version publisher depends; do
    [[ -z $name || $name == \#* ]] && continue
    tree="$WORK/tree-$name-$version-$publisher"
    mkdir -p "$tree/DEBIAN" "$tree/usr/share/$name" "$WORK/$publisher"
    {
        printf 'Package: %s\nVersion: %s\nArchitecture: all\n' "$name" "$version"
        [[ -n $depends ]] && printf 'Depends: %s\n' "$depends"
        printf 'Maintainer: P3-002 TEST ONLY <noreply@example.invalid>\nDescription: P3-002 TEST ONLY fixture (%s)\n' "$publisher"
    } >"$tree/DEBIAN/control"
    printf 'publisher=%s\n' "$publisher" >"$tree/usr/share/$name/marker"
    dpkg-deb --root-owner-group -Zgzip -z1 --build "$tree" "$(deb "$name" "$version" "$publisher")" >/dev/null
done </opt/p3002/fixtures.txt
chmod -R a+rX "$WORK"

for repo in distro other; do
    args=()
    for file in "$WORK/$repo"/*.deb; do args+=(--deb "$file"); done
    python3 -I /opt/p3002/make_repo.py apt "$OTHERS/$repo" --homedir "$OTHER_HOME" --key "$other_key" \
        "${args[@]}" >/dev/null
    printf 'Types: deb\nURIs: http://127.0.0.1:18090/%s\nSuites: stable\nComponents: main\nSigned-By: /srv/p3002/others.gpg\n' \
        "$repo" >"/etc/apt/sources.list.d/p3002-$repo.sources"
done
gpgconf --homedir "$OTHER_HOME" --kill all 2>/dev/null || true
systemd-run --quiet --unit=p3002-others python3 -m http.server --bind 127.0.0.1 --directory "$OTHERS" 18090

systemctl daemon-reload
systemctl enable --now pakomichi-reader.socket
systemctl is-active --quiet pakomichi-reader.socket || { echo "socket 18080 did not start" >&2; exit 1; }

strict=()
for file in "$WORK/strict"/*.deb; do strict+=("$file"); done
publish "$STRICT" "${strict[@]}"
publish "$PINNED" "$WORK"/pinned/*.deb
runuser -u pakomichi -- gpgconf --homedir "$SIGNER" --kill all 2>/dev/null || true
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/18090) 2>/dev/null && break; sleep 0.1; done
echo "prepared $(hostname)"
