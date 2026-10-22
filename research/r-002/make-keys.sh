#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "${script_dir}/../.." && pwd)"
root="${R002_ROOT:-${project_root}/.research-local/r-002}"
key_dir="${root}/keys"
mkdir -p -- "${key_dir}"

gnupg_home="$(mktemp -d /tmp/pakomichi-r002-keys.XXXXXX)"
cleanup() {
    case "${gnupg_home}" in
        /tmp/pakomichi-r002-keys.*) rm -rf -- "${gnupg_home}" ;;
        *) echo "refusing to remove unexpected path: ${gnupg_home}" >&2 ;;
    esac
}
trap cleanup EXIT
export GNUPGHOME="${gnupg_home}"

for role in publisher metadata-a metadata-b; do
    if [[ -s "${key_dir}/${role}.sec.asc" && -s "${key_dir}/${role}.pub.asc" ]]; then
        printf '%s\tkept\n' "${role}"
        continue
    fi
    uid="Pakomichi R-002 TEST ONLY ${role} <r002-${role}@pakomichi.test>"
    gpg --batch --pinentry-mode loopback --passphrase '' \
        --quick-generate-key "${uid}" rsa3072 sign 1y
    gpg --batch --armor --export "${uid}" > "${key_dir}/${role}.pub.asc"
    gpg --batch --pinentry-mode loopback --passphrase '' --armor \
        --export-secret-keys "${uid}" > "${key_dir}/${role}.sec.asc"
    fingerprint="$(gpg --batch --with-colons --fingerprint "${uid}" | awk -F: '/^fpr/ {print $10; exit}')"
    printf '%s\t%s\n' "${role}" "${fingerprint}"
done
