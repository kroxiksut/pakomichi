# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings and helpers of the P3-005a target scripts (sourced).

STATE=/var/lib/pakomichi
PUBLISH=$STATE/publish
CAS=$STATE/cas
GENS=/srv/p3005a-gens
WORK=/root/p3005a-work
SIGNER=/root/p3005a-signer
KEY_UID='Pakomichi P3-005a TEST ONLY <p3005a-test@example.invalid>'
KEYRING=/etc/p3005a/test.gpg
UNIT=pakomichi-reader.service
DROPIN=/run/systemd/system/pakomichi-reader.service.d
READER=127.0.0.1:18080
PROXY=127.0.0.1:18081
GATE=/run/p3005a-gate
PROXY_LOG=/run/p3005a-proxy.log
REPO=alpha
if command -v apt-get >/dev/null; then
    FAMILY=apt PKG_EXT=deb BACKEND=apt
else
    FAMILY=rpm PKG_EXT=rpm
    if dnf --version 2>/dev/null | grep -q '^dnf5'; then BACKEND=dnf5; else BACKEND=dnf4; fi
fi
OUT=${P3005A_OUT:-/tmp/p3005a-out}

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# result ID PASS|FAIL|OBSERVED NOTE
result() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/results.tsv"
    printf 'RESULT\t%s\t%s\t%s\n' "$1" "$2" "$3" >&2
}
expect() { if [[ $2 -eq 0 ]]; then result "$1" PASS "$3"; else result "$1" FAIL "$3"; fi; }

key_id() { gpg --homedir "$SIGNER" --list-secret-keys --with-colons "$KEY_UID" | awk -F: '/^fpr/ {print $10; exit}'; }

# gen NAME VERSION... [-- extra make_repo args]: a signed tree with sampleapp versions.
gen() {
    local name=$1; shift
    local args=() extra=() kind
    while [[ $# -gt 0 && $1 != -- ]]; do
        if [[ $FAMILY == apt ]]; then args+=(--deb "$WORK/pkg/p3005a-sampleapp_${1}_all.deb")
        else args+=(--rpm "$(ls "$WORK"/pkg/p3005a-sampleapp-"$1"-1.noarch.rpm)"); fi
        shift
    done
    [[ ${1:-} == -- ]] && { shift; extra=("$@"); }
    kind=$([[ $FAMILY == apt ]] && echo apt || echo rpm)
    rm -rf "${GENS:?}/$name"
    python3 -I /opt/p3005a/make_repo.py "$kind" "$GENS/$name" --homedir "$SIGNER" --key "$(key_id)" \
        "${args[@]}" "${extra[@]}" >/dev/null
}

# publish NAME: publish $GENS/NAME as the writer (never as the reader).
publish() {
    runuser -u pakomichi -- /usr/local/bin/p3005a-publish --publish-root "$PUBLISH" --cas-root "$CAS" \
        --repo "$REPO" --source src-1 --backend "$BACKEND" "$GENS/$1"
}

current() { cat "$PUBLISH/repos/$REPO/current" 2>/dev/null; }

# reader_args ARGS...: restart the reader with extra arguments (empty: defaults).
reader_args() {
    rm -rf "$DROPIN"
    if [[ $# -gt 0 ]]; then
        mkdir -p "$DROPIN"
        printf '[Service]\nExecStart=\nExecStart=/usr/local/bin/pakomichi-reader --publish-root %s --cas-root %s %s\n' \
            "$PUBLISH" "$CAS" "$*" >"$DROPIN/p3005a.conf"
    fi
    systemctl daemon-reload
    systemctl stop "$UNIT" 2>/dev/null || true
    systemctl reset-failed "$UNIT" pakomichi-reader.socket 2>/dev/null || true
    systemctl start pakomichi-reader.socket
}

journal_since() { journalctl -q -u "$UNIT" --since "@$1" -o cat 2>/dev/null; }

# client_setup ENDPOINT: point the client at the reader or at the hold proxy.
client_setup() {
    if [[ $FAMILY == apt ]]; then
        install -d /etc/apt/keyrings
        cp "$KEYRING" /etc/apt/keyrings/p3005a-test.gpg
        printf 'Types: deb\nURIs: http://%s/%s\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/p3005a-test.gpg\n' \
            "$1" "$REPO" >/etc/apt/sources.list.d/p3005a.sources
    else
        gpg --homedir "$SIGNER" --armor --export "$KEY_UID" >/etc/p3005a/test.asc
        printf '[p3005a]\nname=P3-005a TEST ONLY\nbaseurl=http://%s/%s\nenabled=1\ngpgcheck=0\nrepo_gpgcheck=1\ngpgkey=file:///etc/p3005a/test.asc\nmetadata_expire=0\nskip_if_unavailable=False\n' \
            "$1" "$REPO" >/etc/yum.repos.d/p3005a.repo
    fi
}

client_clean() {
    if [[ $FAMILY == apt ]]; then
        rm -f /var/lib/apt/lists/*127.0.0.1:1808* 2>/dev/null || true
        rm -rf /var/lib/apt/lists/partial/* 2>/dev/null || true
        apt-get clean
    else
        dnf -q clean all >/dev/null 2>&1 || true
    fi
}

client_update() {
    if [[ $FAMILY == apt ]]; then
        apt-get -q update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/p3005a.sources \
            -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 "$@"
    else
        dnf -y --repo p3005a makecache --refresh "$@"
    fi
}

client_install() {
    if [[ $FAMILY == apt ]]; then
        apt-get -q -y install -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/p3005a.sources \
            -o Dir::Etc::sourceparts=- "$@"
    else
        dnf -y --repo p3005a install "$@"
    fi
}

client_remove() { if [[ $FAMILY == apt ]]; then apt-get -q -y purge "$@"; else dnf -y remove "$@"; fi; }

installed_version() { /usr/bin/p3005a-sampleapp 2>/dev/null | awk '{print $2}'; }

# Digests of the signed metadata the client holds for our source.
client_metadata_digests() {
    if [[ $FAMILY == apt ]]; then
        local inrelease; inrelease=$(ls /var/lib/apt/lists/*127.0.0.1:1808*InRelease 2>/dev/null | head -1)
        [[ -n $inrelease ]] && sha256sum "$inrelease" | cut -d' ' -f1
    else
        find /var/cache/dnf /var/cache/libdnf5 -path '*p3005a*' -name 'repomd.xml' -exec sha256sum {} + 2>/dev/null |
            cut -d' ' -f1 | head -1
    fi
}

gen_metadata_digest() {
    if [[ $FAMILY == apt ]]; then sha256sum "$GENS/$1/dists/stable/InRelease" | cut -d' ' -f1
    else sha256sum "$GENS/$1/repodata/repomd.xml" | cut -d' ' -f1; fi
}

# apt_lists_consistent DIR: the stored Packages is the one its InRelease lists.
apt_lists_consistent() {
    local inrelease packages digest
    inrelease=$(ls "$1"/*InRelease 2>/dev/null | head -1)
    packages=$(ls "$1"/*Packages* 2>/dev/null | head -1)
    [[ -n $inrelease && -n $packages ]] || return 1
    digest=$(/usr/lib/apt/apt-helper cat-file "$packages" | sha256sum | cut -d' ' -f1)
    grep -q " $digest " "$inrelease"
}

# pkg_path NAME PACKAGE: repository path of a package file in a generation.
pkg_path() { (cd "$GENS/$1" && find pool packages -name "$2*.$PKG_EXT" 2>/dev/null | head -1); }

if [[ $FAMILY == apt ]]; then HOLD=/binary-amd64/; else HOLD=primary.xml; fi
