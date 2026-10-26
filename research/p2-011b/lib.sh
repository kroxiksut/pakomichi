# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings and helpers of the P2-011b (E2E-07, Pinned source) target
# scripts (sourced). The bed is the P4-001a one (/opt/p4001a) with the
# reader on the default port 879; the source is a test repository whose
# releases carry no attestation.

# shellcheck source=../p4-001a/lib.sh
source /opt/p4001a/lib.sh
PORT=879
URL=${SOURCE_URL:-https://github.com/pchi-test-org/pchi-pinned-test}
OUT=${P2011B_OUT:-/tmp/p2011b-out}
log="$OUT/transcript.txt"
# What the Pinned consent accepts (ADR-027 point 4.1, cli-api.md).
RISK="a compromised publisher account, token, or CI can publish a malicious release that Pakomichi cannot detect"
asset() { printf '%s_%s_all.deb' "$PACKAGE" "$1"; } # version
tag() { printf 'v%s-mutable' "$1"; }                # version

run() { # name, command...: runs it, keeps the transcript, sets $out and $rc
    local name=$1
    shift
    out=$("$@" 2>&1)
    rc=$?
    printf '### %s (exit %s)\n$ %s\n%s\n\n' "$name" "$rc" "$*" "$out" >>"$log"
}

# APT's own diagnostics only; `apt` also warns that its CLI is not stable.
clean() { ! grep -qE '^(W|E|Err):' <<<"$out"; }

installed() { dpkg-query -W -f '${Version}' "$PACKAGE" 2>/dev/null; }

# The source ID of $URL as `pchi source list` names it (first column).
find_source() {
    pchi source list | awk -v url="${URL,,}" 'tolower($2) == url {print $1; exit}'
}

# Phases 2 and 3 take the source phase 1 added.
load_source() {
    SRC=$(cat "$OUT/source-id" 2>/dev/null)
    [[ -n $SRC ]] || { echo "no source-id from phase 1 in $OUT" >&2; exit 1; }
    set_source
}
set_source() {
    LABEL=pakomichi-$SRC-pinned
    SOURCES=/etc/apt/sources.list.d/pakomichi-$SRC.sources
    PREF=/etc/apt/preferences.d/pakomichi-$SRC.pref
}

# The source's line of `pchi status` and one field of it.
status_line() { pchi status 2>/dev/null | awk -v id="$SRC" '$1 == id'; }
field() { status_line | grep -o "$1=[^ ]*"; }

ours() { ls /etc/apt/sources.list.d/pakomichi-* /etc/apt/preferences.d/pakomichi-* 2>/dev/null; }
# A Pakomichi APT file that names the Pinned repository, or a pin at all.
pinned_published() { ours | xargs -r grep -l "$LABEL" 2>/dev/null; }

# The APT approve line a synchronization prints for a held Pinned release.
approve_line() { # tag, release id
    printf '%s: release %s waits for approval: pchi release approve %s %s' "$SRC" "$1" "$SRC" "$2"
}

# The `approve_release` lines of a plan; the CLI shows a digest by its
# first 12 hex digits (render_plan), the full one is what is confirmed.
approvals() { grep -E '^ +approve_release ' <<<"$out" | tr -d '\r'; }

# Evidence: the package database and Pakomichi's APT files at one point.
snapshot() { # name
    dpkg-query -W -f '${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' | sort >"$OUT/dpkg-$1.tsv"
    sha256sum /var/lib/dpkg/status >>"$OUT/dpkg-$1.tsv"
    { ours | xargs -r sha256sum; } >"$OUT/apt-$1.sha256"
}
# The lines of the package database that changed between two snapshots.
dpkg_change() { diff "$OUT/dpkg-$1.tsv" "$OUT/dpkg-$2.tsv" | grep -E '^[<>]' | grep -F "$PACKAGE" | tr '\t\n' '  '; }

# What APT checks a download against (the index SHA256) and the SHA-256 of
# the file the reader serves for $1, downloaded once more: `apt` removes
# its downloaded file after installing it, and dpkg keeps no digest.
served() { # version; sets $indexed and $downloaded
    local version=$1 dir
    run "show-$version" apt-cache show "$PACKAGE=$version"
    indexed=$(awk '/^SHA256:/ {print $2; exit}' <<<"$out")
    dir=$(mktemp -d)
    (cd "$dir" && apt-get download "$PACKAGE=$version" >/dev/null 2>&1)
    downloaded=$(sha256sum "$dir/$(asset "$version")" 2>/dev/null | cut -d' ' -f1)
    rm -rf "$dir"
}

# The APT source line under the pinned version line of `apt-cache policy`:
# APT prints the pin on the version line and the repository's own priority
# on the source line under it.
policy_source() { # version
    grep -A1 -E "^ +(\*\*\* )?$1 990\$" <<<"$out" | tail -1 | tr -s ' '
}

collect() { # phase
    journalctl -q -u pakomichi-state.service -o cat >"$OUT/state-$1.log"
    journalctl -q -u 'pakomichi-apply@*' -o cat >"$OUT/applier-$1.log"
    rm -rf "$OUT/apt-$1"
    mkdir -p "$OUT/apt-$1"
    cp -r /etc/apt/sources.list.d /etc/apt/preferences.d "$OUT/apt-$1/" 2>/dev/null
}

finish() { # phase
    collect "$1"
    cat "$OUT/results.tsv"
    ! grep -q FAIL "$OUT/results.tsv"
}
