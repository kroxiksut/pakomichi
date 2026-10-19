#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
readonly work="$project_root/.research-local/p0-004/signatures"
readonly home="$work/gnupg"
readonly marker="Pakomichi P0-004 TEST ONLY"

rm -rf "$work"
mkdir -p -m 0700 "$home"
export GNUPGHOME="$home"

gpg --batch --passphrase '' --quick-generate-key "$marker <test@example.invalid>" ed25519 sign 0
readonly fingerprint="$(gpg --batch --with-colons --list-secret-keys "$marker" | awk -F: '$1 == "fpr" { print $10; exit }')"
test -n "$fingerprint"
gpg --batch --export "$fingerprint" > "$work/test-only-keyring.gpg"

printf 'Origin: Pakomichi P0-004 TEST ONLY\nSuite: stable\nSHA256:\n' > "$work/Release"
printf '<repomd><revision>p0-004</revision></repomd>\n' > "$work/repomd.xml"
gpg --batch --local-user "$fingerprint" --clearsign --output "$work/InRelease" "$work/Release"
gpg --batch --local-user "$fingerprint" --detach-sign --output "$work/repomd.xml.asc" "$work/repomd.xml"
gpgv --keyring "$work/test-only-keyring.gpg" "$work/InRelease"
gpgv --keyring "$work/test-only-keyring.gpg" "$work/repomd.xml.asc" "$work/repomd.xml"

printf '<repomd><revision>tampered</revision></repomd>\n' > "$work/repomd.xml"
if gpgv --keyring "$work/test-only-keyring.gpg" "$work/repomd.xml.asc" "$work/repomd.xml"; then
    printf 'FAIL: tampered repository metadata verified\n' >&2
    exit 1
fi

printf 'PASS: OpenPGP APT/RPM metadata verification and tamper rejection\n'
