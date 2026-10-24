# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings and helpers of the P3-001 target scripts (sourced).

STATE=/var/lib/pakomichi
PUBLISH=$STATE/publish
CAS=$STATE/cas
SIGNER=$STATE/signer
OTHER_SIGNER=$STATE/other-signer
KEYRING=/etc/apt/keyrings/pakomichi-p3001.gpg
OTHER_KEYRING=/etc/p3001/other.gpg
WORK=/srv/p3001-work
LABEL=pakomichi-sampleapp-strict
SOURCE=src-1
READER=127.0.0.1:18080
PROXY=127.0.0.1:18081
CONTROL=/run/p3001-control.json
GATE=/run/p3001-gate
PROXY_LOG=/run/p3001-proxy.log
SOURCES=/etc/apt/sources.list.d/p3001.sources
NAME=p3001-sampleapp
OUT=${P3001_OUT:-/tmp/p3001-out}

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# result ID PASS|FAIL NOTE
result() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/results.tsv"
    printf 'RESULT\t%s\t%s\t%s\n' "$1" "$2" "$3" >&2
}
expect() { if [[ $2 -eq 0 ]]; then result "$1" PASS "$3"; else result "$1" FAIL "$3"; fi; }

fingerprint() {
    runuser -u pakomichi -- gpg --homedir "$1" --batch --with-colons --list-secret-keys 2>/dev/null |
        awk -F: '/^fpr/ {print $10; exit}'
}

# publish [--signer-home DIR] [--confirmed-ago S] [--max-freshness S] VERSION...:
# the production APT publisher, run as the writer (never as root).
publish() {
    local home=$SIGNER ago=600 max=604800 debs=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --signer-home) home=$2; shift 2 ;;
            --confirmed-ago) ago=$2; shift 2 ;;
            --max-freshness) max=$2; shift 2 ;;
            *) debs+=("$WORK/pkg/${NAME}_${1}_all.deb"); shift ;;
        esac
    done
    runuser -u pakomichi -- /usr/local/bin/p3001-publish --publish-root "$PUBLISH" --cas-root "$CAS" \
        --label "$LABEL" --source "$SOURCE" --signer-home "$home" --key "$(fingerprint "$home")" \
        --keyring "$KEYRING" --confirmed-ago "$ago" --max-freshness "$max" "${debs[@]}"
}

current() { cat "$PUBLISH/repos/$LABEL/current" 2>/dev/null; }

# client_setup ENDPOINT [KEYRING]: our source only, signed by our keyring.
client_setup() {
    printf 'Types: deb\nURIs: http://%s/%s\nSuites: %s\nComponents: main\nSigned-By: %s\n' \
        "$1" "$LABEL" "$LABEL" "${2:-$KEYRING}" >"$SOURCES"
}

apt_only() { apt-get -q -o Dir::Etc::sourcelist="$SOURCES" -o Dir::Etc::sourceparts=- "$@"; }

client_clean() {
    rm -f /var/lib/apt/lists/*127.0.0.1:1808* 2>/dev/null || true
    rm -rf /var/lib/apt/lists/partial/* 2>/dev/null || true
    apt-get clean
}

client_update() { apt_only -o APT::Get::List-Cleanup=0 update "$@"; }

installed_version() { dpkg-query -W -f '${Version}' "$NAME" 2>/dev/null; }

# Digest of the InRelease the client holds for our source.
held_inrelease() {
    local file; file=$(ls /var/lib/apt/lists/*127.0.0.1:1808*InRelease 2>/dev/null | head -1)
    [[ -n $file ]] && sha256sum "$file" | cut -d' ' -f1
}

# The stored Packages is the one its InRelease lists.
lists_consistent() {
    local inrelease packages digest
    inrelease=$(ls /var/lib/apt/lists/*127.0.0.1:1808*InRelease 2>/dev/null | head -1)
    packages=$(ls /var/lib/apt/lists/*127.0.0.1:1808*Packages* 2>/dev/null | head -1)
    [[ -n $inrelease && -n $packages ]] || return 1
    digest=$(/usr/lib/apt/apt-helper cat-file "$packages" | sha256sum | cut -d' ' -f1)
    grep -q " $digest " "$inrelease"
}

# set_control JSON: the proxy reads it on every request.
set_control() { printf '%s\n' "$1" >"$CONTROL"; }
