#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "${script_dir}/../.." && pwd)"
root="${R002_ROOT:-${project_root}/.research-local/r-002}"
fixture_dir="${root}/fixtures"
repo_dir="${root}/repositories"
result_dir="${project_root}/research/r-002/results"
export SOURCE_DATE_EPOCH=1760918400

work="$(mktemp -d /tmp/pakomichi-r002-build.XXXXXX)"
cleanup() {
    case "${work}" in
        /tmp/pakomichi-r002-build.*) rm -rf -- "${work}" ;;
        *) echo "refusing to remove unexpected path: ${work}" >&2 ;;
    esac
}
trap cleanup EXIT
export GNUPGHOME="${work}/gnupg"
mkdir -m 0700 -- "${GNUPGHOME}"
for role in publisher metadata-a metadata-b; do
    gpg --batch --quiet --import "${root}/keys/${role}.sec.asc"
done

rm -rf -- "${fixture_dir}" "${repo_dir}"
mkdir -p -- "${fixture_dir}" "${repo_dir}" "${result_dir}" "${work}/top"/{SPECS,RPMS,BUILD,BUILDROOT}
cat > "${work}/top/SPECS/fixture.spec" <<'SPEC'
Name: pakomichi-r002-fixture
Version: 1.0
Release: 1
Summary: Pakomichi R-002 TEST ONLY signature fixture
License: MIT OR Apache-2.0
BuildArch: noarch
Vendor: Pakomichi R-002 TEST ONLY
Packager: Pakomichi R-002 TEST ONLY <r002@pakomichi.test>

%description
Synthetic R-002 fixture with no scriptlets.

%install
mkdir -p %{buildroot}/usr/share/pakomichi-r002-fixture
echo 'identical payload for signed and unsigned R-002 fixtures' > %{buildroot}/usr/share/pakomichi-r002-fixture/marker

%files
/usr/share/pakomichi-r002-fixture/marker
SPEC

rpmbuild --quiet -bb --define "_topdir ${work}/top" \
    --define "_buildhost r002.pakomichi.test" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    "${work}/top/SPECS/fixture.spec"
unsigned_source="$(find "${work}/top/RPMS" -name '*.rpm' -print -quit)"
if [[ -n "$(rpm -qp --scripts "${unsigned_source}")" ]]; then
    echo "fixture unexpectedly contains scriptlets" >&2
    exit 1
fi
cp -- "${unsigned_source}" "${fixture_dir}/unsigned.rpm"
cp -- "${unsigned_source}" "${fixture_dir}/signed.rpm"
rpmsign --addsign \
    --define '_gpg_name r002-publisher@pakomichi.test' \
    --define '_gpg_digest_algo sha256' "${fixture_dir}/signed.rpm" >/dev/null
python3 -I "${script_dir}/corrupt-rpm-signature.py" \
    "${fixture_dir}/signed.rpm" "${fixture_dir}/corrupted.rpm"
cp -- "${fixture_dir}/unsigned.rpm" "${fixture_dir}/attested.rpm"

# A distinct unsigned package proves that the modeled attestation is bound to
# exact bytes rather than merely to the package name.
mkdir -p -- "${work}/unconfirmed"/{SPECS,RPMS,BUILD,BUILDROOT}
sed \
    -e 's/^Release: 1$/Release: 2/' \
    -e 's/identical payload for signed and unsigned R-002 fixtures/unconfirmed R-002 payload/' \
    "${work}/top/SPECS/fixture.spec" > "${work}/unconfirmed/SPECS/fixture.spec"
rpmbuild --quiet -bb --define "_topdir ${work}/unconfirmed" \
    --define "_buildhost r002.pakomichi.test" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    "${work}/unconfirmed/SPECS/fixture.spec"
unconfirmed_source="$(find "${work}/unconfirmed/RPMS" -name '*.rpm' -print -quit)"
if [[ -n "$(rpm -qp --scripts "${unconfirmed_source}")" ]]; then
    echo "unconfirmed fixture unexpectedly contains scriptlets" >&2
    exit 1
fi
cp -- "${unconfirmed_source}" "${fixture_dir}/unconfirmed.rpm"

attested_sha="$(sha256sum "${fixture_dir}/attested.rpm" | cut -d' ' -f1)"
mkdir -p -- "${root}/attestations"
printf '{"fixture":"attested.rpm","sha256":"%s","verified":true,"note":"TEST ONLY modeled provenance"}\n' \
    "${attested_sha}" > "${root}/attestations/attested.json"

sign_metadata() {
    local directory="$1" role="$2"
    createrepo_c --quiet --revision "${SOURCE_DATE_EPOCH}" --set-timestamp-to-revision "${directory}"
    gpg --batch --yes --digest-algo SHA512 \
        --local-user "r002-${role}@pakomichi.test" --armor --detach-sign \
        -o "${directory}/repodata/repomd.xml.asc" "${directory}/repodata/repomd.xml"
}

make_repo() {
    local name="$1" fixture="$2" role="${3:-metadata-a}"
    local destination=pakomichi-r002-fixture-1.0-1.noarch.rpm
    [[ "${fixture}" == unconfirmed.rpm ]] && destination=pakomichi-r002-fixture-1.0-2.noarch.rpm
    mkdir -p -- "${repo_dir}/${name}"
    cp -- "${fixture_dir}/${fixture}" "${repo_dir}/${name}/${destination}"
    sign_metadata "${repo_dir}/${name}" "${role}"
}

make_repo signed-valid signed.rpm
make_repo unsigned-valid unsigned.rpm
make_repo attested-valid attested.rpm
make_repo unconfirmed-valid unconfirmed.rpm
make_repo corrupted-valid corrupted.rpm
make_repo signed-invalid-metadata signed.rpm
python3 -I "${script_dir}/corrupt-armored-signature.py" \
    "${repo_dir}/signed-invalid-metadata/repodata/repomd.xml.asc"
make_repo tampered signed.rpm
printf 'tampered-after-metadata\n' >> "${repo_dir}/tampered/pakomichi-r002-fixture-1.0-1.noarch.rpm"
make_repo rotation-a signed.rpm metadata-a
make_repo rotation-b signed.rpm metadata-b

manifest="${result_dir}/fixture-manifest.tsv"
printf 'fixture\tsha256\tpayload_digest\tsignature_check\tscriptlets\n' > "${manifest}"
for fixture in signed unsigned corrupted attested unconfirmed; do
    path="${fixture_dir}/${fixture}.rpm"
    set +e
    signature_output="$(rpmkeys --checksig --verbose "${path}" 2>&1)"
    signature_exit=$?
    set -e
    signature_output="$(printf '%s' "${signature_output}" | sed "s#${path}#${fixture}.rpm#g" | tr '\t\r\n' '   ')"
    scripts="$(rpm -qp --scripts "${path}")"
    printf '%s\t%s\t%s\texit=%s %s\t%s\n' \
        "${fixture}.rpm" "$(sha256sum "${path}" | cut -d' ' -f1)" \
        "$(rpm -qp --qf '%{PAYLOADDIGEST}' "${path}")" "${signature_exit}" \
        "${signature_output}" "$([[ -z "${scripts}" ]] && echo none || echo present)" >> "${manifest}"
done

(cd "${repo_dir}" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "${result_dir}/repository-files.sha256"
signed_fixture_sha="$(sha256sum "${fixture_dir}/signed.rpm" | cut -d' ' -f1)"
printf 'location\tsha256\tmatches_signed_fixture\n' > "${result_dir}/metadata-signer-invariance.tsv"
for name in signed-valid signed-invalid-metadata rotation-a rotation-b; do
    package="${repo_dir}/${name}/pakomichi-r002-fixture-1.0-1.noarch.rpm"
    package_sha="$(sha256sum "${package}" | cut -d' ' -f1)"
    printf '%s\t%s\t%s\n' "${name}" "${package_sha}" \
        "$([[ "${package_sha}" == "${signed_fixture_sha}" ]] && echo true || echo false)" \
        >> "${result_dir}/metadata-signer-invariance.tsv"
done
printf 'PASS: R-002 fixtures built; TEST ONLY keys remain under %s\n' "${root}/keys"
