#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Create the R-001 laboratory signing keys once. TEST ONLY: never use them
# outside the R-001 laboratory. The private keys stay in .research-local.
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly key_dir="${R001_ROOT:-$project_root/.research-local/r-001}/keys"
mkdir -p "$key_dir"

GNUPGHOME="$(mktemp -d /tmp/pakomichi-r001-gnupg.XXXXXX)"
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT

for repo in alpha beta system; do
    if [[ -s "$key_dir/$repo.sec.asc" ]]; then
        printf '%s: key exists, kept\n' "$repo"
        continue
    fi
    uid="Pakomichi R-001 TEST ONLY $repo <r001-$repo@pakomichi.test>"
    gpg --batch --pinentry-mode loopback --passphrase '' \
        --quick-generate-key "$uid" rsa3072 sign 1y
    gpg --batch --armor --export "$uid" > "$key_dir/$repo.pub.asc"
    gpg --batch --pinentry-mode loopback --passphrase '' --armor \
        --export-secret-keys "$uid" > "$key_dir/$repo.sec.asc"
    printf '%s: %s\n' "$repo" "$(gpg --batch --with-colons --fingerprint "$uid" | awk -F: '/^fpr/ {print $10; exit}')"
done
