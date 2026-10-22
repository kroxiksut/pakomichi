# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings and helpers for the R-004 target scripts (sourced).

BIN=/usr/local/bin/r004-snapshotd
ROOT=/var/lib/pakomichi-r004
GENS=/srv/r004-gens
WORK=/root/r004-work
SIGNER=/root/r004-signer
KEY_UID='Pakomichi R-004 TEST ONLY <r004-test@example.invalid>'
KEYRING=/etc/r004/r004-test.gpg
UNIT=r004-snapshotd.service
BASE=http://127.0.0.1:18080
UPSTREAM=http://127.0.0.1:18090
GATE=/run/r004-gate
DROPIN=/run/systemd/system/r004-snapshotd.service.d
if command -v apt-get >/dev/null; then FAMILY=apt PKG_EXT=deb; else FAMILY=rpm PKG_EXT=rpm; fi
OUT=${R004_OUT:-/tmp/r004-out}

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# result ID PASS|FAIL|OBSERVED NOTE
result() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/results.tsv"
    printf 'RESULT\t%s\t%s\t%s\n' "$1" "$2" "$3" >&2
}

# expect ID CONDITION-EXIT-CODE NOTE: PASS when the previous test held.
expect() { if [[ $2 -eq 0 ]]; then result "$1" PASS "$3"; else result "$1" FAIL "$3"; fi; }

key_id() { gpg --homedir "$SIGNER" --list-secret-keys --with-colons "$KEY_UID" | awk -F: '/^fpr/ {print $10; exit}'; }

# gen_apt NAME VERSION... [-- extra make_repo args]: generation with sampleapp versions.
gen_apt() {
    local name=$1; shift
    local args=() extra=()
    while [[ $# -gt 0 && $1 != -- ]]; do args+=(--deb "$WORK/pkg/r004-sampleapp_${1}_all.deb"); shift; done
    [[ ${1:-} == -- ]] && { shift; extra=("$@"); }
    python3 -I /opt/r004/make_repo.py apt "$GENS/$name" --homedir "$SIGNER" --key "$(key_id)" "${args[@]}" "${extra[@]}" >/dev/null
}

gen_rpm() {
    local name=$1; shift
    local args=() extra=()
    while [[ $# -gt 0 && $1 != -- ]]; do args+=(--rpm "$(ls "$WORK"/pkg/r004-sampleapp-"$1"-1.noarch.rpm)"); shift; done
    [[ ${1:-} == -- ]] && { shift; extra=("$@"); }
    python3 -I /opt/r004/make_repo.py rpm "$GENS/$name" --homedir "$SIGNER" --key "$(key_id)" "${args[@]}" "${extra[@]}" >/dev/null
}

gen() { if [[ $FAMILY == apt ]]; then gen_apt "$@"; else gen_rpm "$@"; fi; }

# publish REPO GENERATION: publish $GENS/GENERATION as the service user.
publish() {
    local lazy=()
    [[ -s "$GENS/$2.lazy.tsv" ]] && lazy=(--lazy "$GENS/$2.lazy.tsv")
    runuser -u pakomichi-r004 -- "$BIN" publish "$ROOT" "$1" "$2" "$GENS/$2" --keyring "$KEYRING" "${lazy[@]}"
}

# service_env 'KEY=value' ...: scenario settings through a runtime drop-in.
service_env() {
    mkdir -p "$DROPIN"
    { echo '[Service]'; for kv in "$@"; do echo "Environment=$kv"; done; } >"$DROPIN/r004.conf"
    systemctl daemon-reload
    systemctl stop "$UNIT" 2>/dev/null || true
    systemctl reset-failed "$UNIT" r004-snapshotd.socket 2>/dev/null || true
    systemctl start r004-snapshotd.socket
}

service_reset() { rm -f "$DROPIN/r004.conf" "$GATE"; service_env; }

main_pid() { systemctl show -p MainPID --value "$UNIT"; }

# journal_wait SINCE PATTERN [SECONDS]: wait until the unit journal shows it.
journal_wait() {
    local since=$1 pattern=$2 limit=${3:-60} i
    for ((i = 0; i < limit * 10; i++)); do
        journalctl -q -u "$UNIT" --since "@$since" -o cat 2>/dev/null | grep -q -- "$pattern" && return 0
        sleep 0.1
    done
    return 1
}

journal_since() { journalctl -q -u "$UNIT" --since "@$1" -o cat 2>/dev/null; }

http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time "${2:-30}" "$1"; }

fresh_root() {
    systemctl stop "$UNIT" 2>/dev/null || true
    rm -rf "${ROOT:?}"/* "$GENS"/*
    install -d -o pakomichi-r004 -g pakomichi-r004 -m 0750 "$ROOT"
}

# Client configuration for repository "alpha" (our source only).
client_setup() {
    if [[ $FAMILY == apt ]]; then
        install -d /etc/apt/keyrings
        cp "$KEYRING" /etc/apt/keyrings/r004-test.gpg
        printf 'Types: deb\nURIs: %s/alpha\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/r004-test.gpg\n' \
            "$BASE" >/etc/apt/sources.list.d/r004.sources
    else
        cp "$KEYRING" /etc/r004/r004-test.pub.gpg
        gpg --homedir "$SIGNER" --armor --export "$KEY_UID" >/etc/r004/r004-test.asc
        printf '[r004]\nname=R-004 TEST ONLY\nbaseurl=%s/alpha\nenabled=1\ngpgcheck=0\nrepo_gpgcheck=1\ngpgkey=file:///etc/r004/r004-test.asc\nmetadata_expire=0\nskip_if_unavailable=False\n' \
            "$BASE" >/etc/yum.repos.d/r004.repo
    fi
}

client_clean() {
    if [[ $FAMILY == apt ]]; then
        rm -f /var/lib/apt/lists/*127.0.0.1:18080* 2>/dev/null || true
        rm -rf /var/lib/apt/lists/partial/* 2>/dev/null || true
        apt-get clean
    else
        dnf -q clean all >/dev/null 2>&1 || true
    fi
}

# client_update [extra args]: refresh our source only.
client_update() {
    if [[ $FAMILY == apt ]]; then
        apt-get -q update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/r004.sources \
            -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 "$@"
    else
        dnf -y --repo r004 makecache --refresh "$@"
    fi
}

client_install() {
    if [[ $FAMILY == apt ]]; then
        apt-get -q -y install -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/r004.sources \
            -o Dir::Etc::sourceparts=- "$@"
    else
        dnf -y --repo r004 install "$@"
    fi
}

client_remove() {
    if [[ $FAMILY == apt ]]; then apt-get -q -y purge "$@"; else dnf -y remove "$@"; fi
}

# Digest of the metadata the client holds for our source.
client_metadata_digests() {
    if [[ $FAMILY == apt ]]; then
        apt_list_digests /var/lib/apt/lists
    else
        find /var/cache/dnf /var/cache/libdnf5 -path '*r004*' -name 'repomd.xml' -exec sha256sum {} + 2>/dev/null
    fi
}

# apt_list_digests DIR: digests of our InRelease and of the uncompressed
# Packages in an APT lists directory. The Debian container image sets
# Acquire::GzipIndexes, so lists may be stored compressed; apt-helper
# cat-file decompresses whatever form is stored.
apt_list_digests() {
    local inrelease packages
    inrelease=$(ls "$1"/*127.0.0.1:18080*InRelease 2>/dev/null | head -1)
    packages=$(ls "$1"/*127.0.0.1:18080*Packages* 2>/dev/null | head -1)
    [[ -n $inrelease ]] && sha256sum "$inrelease"
    [[ -n $packages ]] && printf '%s  %s\n' "$(/usr/lib/apt/apt-helper cat-file "$packages" | sha256sum | cut -d' ' -f1)" "$packages"
}

# apt_lists_consistent DIR: the stored Packages is the one its InRelease lists.
apt_lists_consistent() {
    local digests; digests=$(apt_list_digests "$1")
    [[ $(wc -l <<<"$digests") -eq 2 ]] || return 1
    grep -q " $(sed -n 2p <<<"$digests" | cut -d' ' -f1) " "$(sed -n 1p <<<"$digests" | awk '{print $2}')"
}

# The metadata file paths in a generation, for comparison.
gen_digests() {
    if [[ $FAMILY == apt ]]; then
        sha256sum "$GENS/$1/dists/stable/InRelease" "$GENS/$1/dists/stable/main/binary-amd64/Packages"
    else
        sha256sum "$GENS/$1/repodata/repomd.xml"
    fi
}

# HOLD: request substring that holds index downloads mid-update (after
# InRelease/repomd.xml). INDEX: the signed top-level metadata path.
if [[ $FAMILY == apt ]]; then
    HOLD=/binary-amd64/ INDEX=/alpha/dists/stable/InRelease
else
    HOLD=primary.xml INDEX=/alpha/repodata/repomd.xml
fi
