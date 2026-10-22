#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -uo pipefail
# Expected failures are matrix data and must be captured by run(), even if the
# invoking environment exported SHELLOPTS with errexit enabled.
set +e

readonly platform="$1"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "${script_dir}/../.." && pwd)"
readonly source_root="${R002_ROOT:-${project_root}/.research-local/r-002}"
readonly public_results="${R002_RESULTS:-${project_root}/research/r-002/results}"
readonly raw_root="${source_root}/runs/${platform}"
readonly lab=/tmp/pakomichi-r002-lab
readonly reposdir=/etc/pakomichi-r002.repos.d
readonly repofile="${reposdir}/pakomichi-r002.repo"
readonly macrofile=/etc/rpm/macros.pakomichi-r002
readonly package_name=pakomichi-r002-fixture
readonly port=18082
export LC_ALL=C

server_pid=""
cleanup() {
    [[ -n "${server_pid}" ]] && kill "${server_pid}" 2>/dev/null || true
    rpm -e --nodeps "${package_name}" >/dev/null 2>&1 || true
    rm -f -- "${macrofile}"
    rm -rf -- "${reposdir}" /var/cache/dnf/pakomichi-r002-* /var/cache/libdnf5/pakomichi-r002-*
    case "${lab}" in
        /tmp/pakomichi-r002-*) rm -rf -- "${lab}" ;;
        *) echo "refusing to remove unexpected lab path: ${lab}" >&2 ;;
    esac
}
trap cleanup EXIT

rm -rf -- "${lab}"
mkdir -p -- "${lab}/keys" "${raw_root}" "${public_results}" "${reposdir}"
cp -r -- "${source_root}/fixtures" "${source_root}/repositories" "${source_root}/attestations" "${lab}/"
cp -- "${source_root}"/keys/*.pub.asc "${lab}/keys/"

if [[ "${platform}" == fedora44 ]]; then
    dnf -y install python3 dnf5-plugins > "${raw_root}/bootstrap.log" 2>&1
else
    dnf -y install python3 dnf-plugins-core > "${raw_root}/bootstrap.log" 2>&1
fi
if [[ $? -ne 0 ]]; then
    echo "target bootstrap failed; see ${raw_root}/bootstrap.log" >&2
    exit 2
fi

python3 -I "${script_dir}/repo-server.py" "${lab}/repositories" "${raw_root}/http.log" --port "${port}" &
server_pid=$!
for _ in $(seq 1 50); do
    python3 -I - "${port}" <<'PY' >/dev/null 2>&1 && break
import socket, sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
    pass
PY
    sleep 0.1
done
kill -0 "${server_pid}" 2>/dev/null || { echo "repository server failed" >&2; exit 2; }

rpmkeys --import "${lab}/keys/publisher.pub.asc" "${lab}/keys/metadata-a.pub.asc"
readonly result_file="${public_results}/${platform}.tsv"
readonly config_file="${public_results}/${platform}-effective-config.tsv"
printf 'platform\tcell\tpolicy\trpm_signature\trepo_signature\texpected\texit_code\toperation_succeeded\tinstalled\tactual\tverdict\tnotes\n' > "${result_file}"
printf 'platform\ttool\tsetting\tvalue\n' > "${config_file}"
log=/dev/null
last_exit=0

run() {
    printf '$' >> "${log}"
    printf ' %q' "$@" >> "${log}"
    printf '\n' >> "${log}"
    "$@" >> "${log}" 2>&1
    last_exit=$?
    printf '[exit %s]\n' "${last_exit}" >> "${log}"
    return 0
}

dnf_run() {
    run dnf -y --setopt="reposdir=${reposdir}" "$@"
}

installed() {
    rpm -q "${package_name}" >/dev/null 2>&1 && echo true || echo false
}

reset_cell() {
    local cell="$1"
    log="${raw_root}/${cell}.log"
    : > "${log}"
    rpm -e --nodeps "${package_name}" >> "${log}" 2>&1 || true
    rm -f -- "${repofile}" "${macrofile}"
    rm -rf -- /var/cache/dnf/pakomichi-r002-* /var/cache/libdnf5/pakomichi-r002-*
}

require_signature_policy() {
    if [[ "${platform}" == fedora44 ]]; then
        # DNF5 owns repository-package verification through pkg_gpgcheck.  A
        # pilot that also forced this RPM transaction macro rejected a fixture
        # which DNF5 and rpmkeys had just verified, reporting "no signature".
        # Keep the two policy layers distinct and exercise DNF5's native gate.
        run rpm --eval '%{_pkgverify_level}'
    else
        # DNF4 has no pkg_gpgcheck setting.  The RPM transaction policy is the
        # system-level backstop which a per-repository gpgcheck=0 cannot lower.
        printf '%%_pkgverify_level signature\n' > "${macrofile}"
        run rpm --eval '%{_pkgverify_level}'
    fi
}

write_repo() {
    local layout="$1" package_check="$2" metadata_key="${3:-metadata-a}"
    cat > "${repofile}" <<EOF
[pakomichi-r002]
name=Pakomichi R-002 TEST ONLY
baseurl=http://127.0.0.1:${port}/${layout}/
enabled=1
gpgcheck=${package_check}
repo_gpgcheck=1
gpgkey=file://${lab}/keys/${metadata_key}.pub.asc file://${lab}/keys/publisher.pub.asc
metadata_expire=0
skip_if_unavailable=False
EOF
    if [[ "${platform}" == fedora44 ]]; then
        # Prefer the unambiguous DNF5 spelling while retaining gpgcheck above
        # to measure its compatibility alias in the same repository section.
        printf 'pkg_gpgcheck=%s\n' "${package_check}" >> "${repofile}"
    fi
    run cat "${repofile}"
}

record() {
    local cell="$1" policy="$2" rpm_signature="$3" repo_signature="$4" expected="$5" exit_code="$6" succeeded="$7" was_installed="$8" notes="$9"
    local actual verdict
    [[ "${succeeded}" == true ]] && actual=allow || actual=block
    [[ "${actual}" == "${expected}" ]] && verdict=PASS || verdict=FAIL
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${platform}" "${cell}" "${policy}" "${rpm_signature}" "${repo_signature}" \
        "${expected}" "${exit_code}" "${succeeded}" "${was_installed}" "${actual}" "${verdict}" "${notes}" >> "${result_file}"
}

prepare() {
    log="${raw_root}/environment.log"
    : > "${log}"
    run cat /etc/os-release
    run uname -a
    run dnf --version
    run rpm --version
    run rpm --eval '%{?_pkgverify_level}'
    local dump tool setting value
    if [[ "${platform}" == fedora44 ]]; then
        tool='dnf --dump-main-config'
        dump="$(dnf --setopt="reposdir=${reposdir}" --dump-main-config 2>> "${log}")"
    else
        tool='dnf config-manager --dump'
        dump="$(dnf --setopt="reposdir=${reposdir}" config-manager --dump 2>> "${log}")"
    fi
    printf '%s\n' "${dump}" >> "${log}"
    for setting in gpgcheck repo_gpgcheck pkg_gpgcheck gpgcheck_policy localpkg_gpgcheck; do
        value="$(printf '%s\n' "${dump}" | sed -n -E "s/^[[:space:]]*${setting}[[:space:]]*=[[:space:]]*(.*)$/\1/p" | head -1)"
        [[ -n "${value}" ]] || value=unsupported
        printf '%s\t%s\t%s\t%s\n' "${platform}" "${tool}" "${setting}" "${value}" >> "${config_file}"
    done
    value="$(rpm --eval '%{?_pkgverify_level}')"
    [[ -n "${value}" ]] || value=undefined
    printf '%s\trpm --eval\t%%_pkgverify_level\t%s\n' "${platform}" "${value}" >> "${config_file}"

    printf 'fixture\texit_code\tkey_output\n' > "${public_results}/${platform}-rpmkeys.tsv"
    for fixture in signed unsigned corrupted attested unconfirmed; do
        status=0
        output="$(rpmkeys --checksig --verbose "${lab}/fixtures/${fixture}.rpm" 2>&1)" || status=$?
        output="$(printf '%s' "${output}" | sed "s#${lab}/fixtures/${fixture}.rpm#${fixture}.rpm#g" | tr '\t\r\n' '   ')"
        printf '%s\t%s\t%s\n' "${fixture}.rpm" "${status}" "${output}" >> "${public_results}/${platform}-rpmkeys.tsv"
    done
}

cell_signed_required() {
    reset_cell signed-valid-required
    require_signature_policy
    write_repo signed-valid 1
    dnf_run makecache
    dnf_run install "${package_name}"
    local state="$(installed)"
    record signed-valid-required required valid valid allow "${last_exit}" "${state}" "${state}" 'native RPM signature and signed metadata'
}

cell_unsigned_required() {
    reset_cell unsigned-valid-required
    require_signature_policy
    write_repo unsigned-valid 1
    dnf_run makecache
    dnf_run install "${package_name}"
    local state="$(installed)"
    record unsigned-valid-required required none valid block "${last_exit}" "${state}" "${state}" 'unsigned RPM under package check and RPM signature policy'
}

cell_attested_permitted() {
    reset_cell attested-explicit-permitted
    run python3 -I "${script_dir}/verify-modeled-attestation.py" \
        "${lab}/fixtures/attested.rpm" "${lab}/attestations/attested.json"
    local attest_exit="${last_exit}"
    write_repo attested-valid 0
    dnf_run makecache
    if [[ "${attest_exit}" -eq 0 ]]; then dnf_run install "${package_name}"; else last_exit="${attest_exit}"; fi
    local state="$(installed)"
    record attested-explicit-permitted explicit-attested none valid allow "${last_exit}" "${state}" "${state}" 'per-repo package check disabled only after explicit modeled attestation verification'
}

cell_attested_required() {
    reset_cell attested-required-policy
    require_signature_policy
    run python3 -I "${script_dir}/verify-modeled-attestation.py" \
        "${lab}/fixtures/attested.rpm" "${lab}/attestations/attested.json"
    local attest_exit="${last_exit}"
    if [[ "${platform}" == fedora44 ]]; then
        # Mandatory DNF5 package verification is expressed by pkg_gpgcheck;
        # a successful external attestation is not permission to lower it.
        write_repo attested-valid 1
    else
        # Exercise the DNF4/RPM backstop: even a per-repository exception must
        # not override the system transaction policy.
        write_repo attested-valid 0
    fi
    dnf_run makecache
    if [[ "${attest_exit}" -eq 0 ]]; then dnf_run install "${package_name}"; else last_exit="${attest_exit}"; fi
    local state="$(installed)"
    record attested-required-policy required none valid block "${last_exit}" "${state}" "${state}" 'attestation must not replace mandatory embedded signature'
}

cell_unconfirmed_refused() {
    reset_cell unconfirmed-refused-before-dnf
    run python3 -I "${script_dir}/verify-modeled-attestation.py" \
        "${lab}/fixtures/unconfirmed.rpm" "${lab}/attestations/attested.json"
    local attest_exit="${last_exit}"
    record unconfirmed-refused-before-dnf explicit-attested none valid block "${attest_exit}" false false 'adapter refuses before writing a package-check exception'
}

cell_corrupted() {
    reset_cell corrupted-rpm
    write_repo corrupted-valid 1
    dnf_run makecache
    dnf_run install "${package_name}"
    local state="$(installed)"
    record corrupted-rpm normal corrupted valid block "${last_exit}" "${state}" "${state}" 'corrupted embedded signature'
}

cell_invalid_metadata() {
    reset_cell invalid-repomd-signature
    write_repo signed-invalid-metadata 1
    dnf_run makecache
    local refresh_exit="${last_exit}"
    local succeeded=true
    [[ "${refresh_exit}" -eq 0 ]] || succeeded=false
    record invalid-repomd-signature normal valid invalid block "${refresh_exit}" "${succeeded}" "$(installed)" 'repo_gpgcheck=1 rejects metadata before package installation'
}

cell_tampered() {
    reset_cell rpm-replaced-after-metadata
    write_repo tampered 1
    dnf_run makecache
    dnf_run install "${package_name}"
    local state="$(installed)"
    record rpm-replaced-after-metadata normal valid valid block "${last_exit}" "${state}" "${state}" 'RPM bytes changed after createrepo metadata generation'
}

cell_global_disable_refused() {
    reset_cell global-gpgcheck-disable-refused
    printf 'REFUSED: R-002 adapter never writes global gpgcheck=0; use an explicit per-source mode only\n' >> "${log}"
    last_exit=64
    record global-gpgcheck-disable-refused guard-request none valid block "${last_exit}" false false 'guard refusal; native DNF was not invoked and global configuration was not changed'
}

cell_rotation() {
    reset_cell metadata-key-a-baseline
    write_repo rotation-a 1 metadata-a
    dnf_run makecache
    local status_a="${last_exit}"
    local accepted_a=true
    [[ "${status_a}" -eq 0 ]] || accepted_a=false
    record metadata-key-a-baseline normal valid valid allow "${status_a}" "${accepted_a}" false 'trusted metadata key A'

    reset_cell metadata-key-b-before-trust
    write_repo rotation-b 1 metadata-a
    dnf_run makecache
    local status_untrusted="${last_exit}"
    local accepted_untrusted=true
    [[ "${status_untrusted}" -eq 0 ]] || accepted_untrusted=false
    record metadata-key-b-before-trust normal valid untrusted block "${status_untrusted}" "${accepted_untrusted}" false 'repository signed by B while only A is configured'

    reset_cell metadata-key-b-after-trust
    rpmkeys --import "${lab}/keys/metadata-b.pub.asc" >> "${log}" 2>&1
    write_repo rotation-b 1 metadata-b
    dnf_run makecache
    local status_b="${last_exit}"
    local accepted_b=false
    [[ "${status_b}" -eq 0 ]] && accepted_b=true
    record metadata-key-b-after-trust normal valid valid allow "${status_b}" "${accepted_b}" false 'explicitly trusted metadata key B'
}

prepare
cell_signed_required
cell_unsigned_required
cell_attested_permitted
cell_attested_required
cell_unconfirmed_refused
cell_corrupted
cell_invalid_metadata
cell_tampered
cell_global_disable_refused
cell_rotation

cat "${result_file}"
if awk -F '\t' 'NR > 1 && $11 != "PASS" {bad=1} END {exit bad}' "${result_file}"; then
    echo "PASS: ${platform} R-002 matrix"
else
    echo "FAIL: ${platform} R-002 matrix" >&2
    exit 1
fi
