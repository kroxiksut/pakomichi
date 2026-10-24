# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings of the P2-013b target scripts (sourced).

STATE=/var/lib/pakomichi
PUBLISH=$STATE/publish
CAS=$STATE/cas
SIGNER_HOME=/var/lib/pakomichi-signer/gnupg
KEYRING=/etc/apt/keyrings/pakomichi.gpg
SOURCES=/etc/apt/sources.list.d/p2013b.sources
LABEL=pakomichi-fixture-strict
FIXTURE=/srv/p2013b/fixture.deb
# The public R-003 test repository and its current attested asset.
REPOSITORY=1429109739
ASSET=664806807
SHA=a59a5cfd27b6b5090de79452c96ca6526cfddda93b1b2fab559f08ac8bdf41f9
SIZE=800
OUT=${P2013B_OUT:-/tmp/p2013b-out}
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

result() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/results.tsv"
    printf 'RESULT\t%s\t%s\t%s\n' "$1" "$2" "$3" >&2
}
expect() { if [[ $2 -eq 0 ]]; then result "$1" PASS "$3"; else result "$1" FAIL "$3"; fi; }
call() { /usr/local/bin/p2013b-call "$@" 2>&1; }
