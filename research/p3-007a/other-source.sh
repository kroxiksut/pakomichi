#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P3-007a, N-027: another enabled source that offers a higher version of
# the activated name, added after the activation, as a third-party
# repository would be. A signed flat repository on the target's disk with
# its own TEST ONLY key; nothing of Pakomichi is involved.
set -euo pipefail
# shellcheck source=lib.sh
source /opt/p3007a/lib.sh

rm -rf "$OTHER"
install -d -m 0755 "$OTHER" "$OTHER/build/DEBIAN"
cat >"$OTHER/build/DEBIAN/control" <<CONTROL
Package: $PACKAGE
Version: $OTHER_VERSION
Architecture: all
Maintainer: P3-007a TEST ONLY <p3007a@example.invalid>
Description: higher version of the same name from another publisher (N-027)
CONTROL
deb="${PACKAGE}_${OTHER_VERSION}_all.deb"
dpkg-deb --root-owner-group --build "$OTHER/build" "$OTHER/$deb" >/dev/null
rm -rf "$OTHER/build"

{
    cat <<PARAGRAPH
Package: $PACKAGE
Version: $OTHER_VERSION
Architecture: all
Maintainer: P3-007a TEST ONLY <p3007a@example.invalid>
Filename: ./$deb
Size: $(stat -c %s "$OTHER/$deb")
SHA256: $(sha256sum "$OTHER/$deb" | cut -d' ' -f1)
Description: higher version of the same name from another publisher (N-027)
PARAGRAPH
} >"$OTHER/Packages"
{
    printf 'Origin: P3007A-Other\nLabel: P3007A-Other\nSuite: stable\nCodename: other\n'
    printf 'Date: %s\n' "$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S UTC')"
    printf 'SHA256:\n %s %s Packages\n' "$(sha256sum "$OTHER/Packages" | cut -d' ' -f1)" \
        "$(stat -c %s "$OTHER/Packages")"
} >"$OTHER/Release"

home=$(mktemp -d)
gpg --homedir "$home" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "P3-007a other source TEST ONLY <other@example.invalid>" ed25519 sign 1d 2>/dev/null
gpg --homedir "$home" --batch --yes --clearsign -o "$OTHER/InRelease" "$OTHER/Release"
gpg --homedir "$home" --batch --export >"$OTHER/key.gpg"
gpgconf --homedir "$home" --kill all 2>/dev/null || true
rm -rf "$home"
chmod -R a+rX "$OTHER"

cat >/etc/apt/sources.list.d/p3007a-other.sources <<SOURCES
Types: deb
URIs: file:$OTHER
Suites: ./
Signed-By: $OTHER/key.gpg
SOURCES
echo "other source $OTHER offers $PACKAGE $OTHER_VERSION"
