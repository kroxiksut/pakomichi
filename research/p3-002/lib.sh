# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings and helpers of the P3-002 target scripts (sourced).

STATE=/var/lib/pakomichi
PUBLISH=$STATE/publish
CAS=$STATE/cas
SIGNER=$STATE/signer
KEYRING=/srv/p3002/pakomichi.gpg
ADAPTER_STATE=/var/lib/p3002-adapter.state
OTHERS=/srv/p3002/others
OTHER_HOME=/root/p3002-other-gpg
WORK=/srv/p3002/work
STRICT=pakomichi-sampleapp-strict
PINNED=pakomichi-sampleapp-pinned
PORT=18080
OUT=${P3002_OUT:-/tmp/p3002-out}
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
result() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/results.tsv"
    printf 'RESULT\t%s\t%s\t%s\n' "$1" "$2" "$3" >&2
}
expect() { if [[ $2 -eq 0 ]]; then result "$1" PASS "$3"; else result "$1" FAIL "$3"; fi; }

fingerprint() {
    runuser -u pakomichi -- gpg --homedir "$1" --batch --with-colons --list-secret-keys 2>/dev/null |
        awk -F: '/^fpr/ {print $10; exit}'
}

deb() { printf '%s/%s_%s_all.deb' "$WORK/$3" "$1" "$2"; }

# publish LABEL DEB...: the production APT publisher, as the writer.
publish() {
    local label=$1; shift
    runuser -u pakomichi -- /usr/local/bin/p3001-publish --publish-root "$PUBLISH" --cas-root "$CAS" \
        --label "$label" --source src-1 --signer-home "$SIGNER" --key "$(fingerprint "$SIGNER")" \
        --keyring "$KEYRING" --confirmed-ago 600 "$@"
}

# adapter apply|check ARGS...: the production APT adapter, as root.
adapter() {
    local command=$1; shift
    if [[ $command == apply ]]; then
        /usr/local/bin/p3002-apt apply --state "$ADAPTER_STATE" --port "$PORT" --keyring "$KEYRING" \
            --source sampleapp "$@"
    else
        /usr/local/bin/p3002-apt check --port "$PORT" "$@"
    fi
}

version_of() { dpkg-query -W -f '${Version}' "$1" 2>/dev/null || echo absent; }
publisher_of() { sed -n 's/^publisher=//p' "/usr/share/$1/marker" 2>/dev/null || echo absent; }
state_of() { printf '%s=%s/%s' "$1" "$(version_of "$1")" "$(publisher_of "$1")"; }

# Digests of every file under /etc/apt except Pakomichi's own.
foreign_snapshot() {
    find /etc/apt -type f ! -name 'pakomichi-*' ! -name 'pakomichi.gpg' -print0 | sort -z |
        xargs -0 sha256sum
}
