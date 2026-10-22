#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "${script_dir}/../.." && pwd)"
root="${R002_ROOT:-${project_root}/.research-local/r-002}"
secret="${root}/keys/metadata-a.sec.asc"
public="${root}/keys/metadata-a.pub.asc"
existing="${root}/repositories/rotation-a/repodata/repomd.xml"
existing_sig="${existing}.asc"
result="${project_root}/research/r-002/results/key-recovery.tsv"
raw="${root}/runs/key-recovery.log"
mkdir -p -- "$(dirname -- "${raw}")" "$(dirname -- "${result}")"
: > "${raw}"

work="$(mktemp -d /tmp/pakomichi-r002-key-recovery.XXXXXX)"
backup="${work}/metadata-a.sec.asc.backup"
cleanup() {
    if [[ ! -f "${secret}" && -f "${backup}" ]]; then cp -- "${backup}" "${secret}"; fi
    case "${work}" in
        /tmp/pakomichi-r002-key-recovery.*) rm -rf -- "${work}" ;;
        *) echo "refusing to remove unexpected path: ${work}" >&2 ;;
    esac
}
trap cleanup EXIT
cp -- "${secret}" "${backup}"
rm -- "${secret}"

verify_home="${work}/verify-home"
missing_home="${work}/missing-home"
mkdir -m 0700 -- "${verify_home}" "${missing_home}"
GNUPGHOME="${verify_home}" gpg --batch --import "${public}" >> "${raw}" 2>&1
set +e
GNUPGHOME="${verify_home}" gpg --batch --verify "${existing_sig}" "${existing}" >> "${raw}" 2>&1
existing_exit=$?
GNUPGHOME="${missing_home}" gpg --batch --import "${secret}" >> "${raw}" 2>&1
missing_exit=$?
set -e

cp -- "${backup}" "${secret}"
restore_home="${work}/restore-home"
mkdir -m 0700 -- "${restore_home}"
GNUPGHOME="${restore_home}" gpg --batch --import "${secret}" >> "${raw}" 2>&1
cp -- "${existing}" "${work}/repomd.xml"
GNUPGHOME="${restore_home}" gpg --batch --yes --armor --detach-sign \
    --local-user 'r002-metadata-a@pakomichi.test' \
    -o "${work}/repomd.xml.asc" "${work}/repomd.xml" >> "${raw}" 2>&1
set +e
GNUPGHOME="${verify_home}" gpg --batch --verify \
    "${work}/repomd.xml.asc" "${work}/repomd.xml" >> "${raw}" 2>&1
restored_exit=$?
set -e

verdict=PASS
[[ ${existing_exit} -eq 0 && ${missing_exit} -ne 0 && ${restored_exit} -eq 0 ]] || verdict=FAIL
printf 'existing_snapshot_after_loss_exit\tnew_signing_without_key_exit\trestored_signing_verify_exit\tverdict\n' > "${result}"
printf '%s\t%s\t%s\t%s\n' "${existing_exit}" "${missing_exit}" "${restored_exit}" "${verdict}" >> "${result}"
printf '%s: existing=%s missing=%s restored=%s\n' "${verdict}" "${existing_exit}" "${missing_exit}" "${restored_exit}"
[[ "${verdict}" == PASS ]]
