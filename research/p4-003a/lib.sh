# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings of the P4-003a target scripts (sourced).

STATE=/var/lib/pakomichi
DB=$STATE/state/state.db
SOCKET=/run/pakomichi/apply.sock
CONFIGS=/opt/p4003a/configs
OURS=/etc/apt/sources.list.d/pakomichi-sampleapp.sources
PREFS=/etc/apt/preferences.d/pakomichi-sampleapp.pref
KEYRING=/etc/apt/keyrings/pakomichi.gpg
OUT=${P4003A_OUT:-/tmp/p4003a-out}
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

result() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/results.tsv"
    printf 'RESULT\t%s\t%s\t%s\n' "$1" "$2" "$3" >&2
}
expect() { if [[ $2 -eq 0 ]]; then result "$1" PASS "$3"; else result "$1" FAIL "$3"; fi; }
# The state owner's side runs as the state owner's user.
owner() { runuser -u pakomichi -- /usr/local/bin/p4003a-call "$@" 2>&1; }
# Digest of every managed file, one line each; "-" for a missing one.
snapshot() {
    for file in "$KEYRING" "$OURS" "$PREFS"; do
        if [[ -e $file ]]; then sha256sum "$file"; else echo "- $file"; fi
    done
}
