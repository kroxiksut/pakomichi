# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings of the P4-001a target scripts (sourced).

STATE=/var/lib/pakomichi
SIGNER_HOME=/var/lib/pakomichi-signer/gnupg
METADATA_KEY=/etc/pakomichi/metadata.gpg
# The owner's public test repository (E2E-01 source, owner decision of
# 2026-10-23) and the package its current release carries.
URL=https://github.com/kroxiksut/pchi-test
SOURCE=github-1429307950
PACKAGE=pakomichi-r003-fixture
OUT=${P4001A_OUT:-/tmp/p4001a-out}
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

result() {
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/results.tsv"
    printf 'RESULT\t%s\t%s\t%s\n' "$1" "$2" "$3" >&2
}
expect() { if [[ $2 -eq 0 ]]; then result "$1" PASS "$3"; else result "$1" FAIL "$3"; fi; }

# The administrator types `yes` at a terminal: `script` gives the CLI a
# pseudo-terminal and the answer arrives on it, as typed. Prints the
# output; returns the CLI's exit status.
confirm() { printf 'yes\n' | script -qec "$*" /dev/null; }
