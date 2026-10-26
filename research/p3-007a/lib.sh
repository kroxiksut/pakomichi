# SPDX-License-Identifier: MIT OR Apache-2.0
# Shared settings of the P3-007a target scripts (sourced). The bed is the
# P4-001a one (/opt/p4001a) with the reader on the default port 879.

# shellcheck source=../p4-001a/lib.sh
source /opt/p4001a/lib.sh
PORT=879
OUT=${P3007A_OUT:-/tmp/p3007a-out}
log="$OUT/transcript.txt"
# Another source that later offers a higher version of the activated name
# (N-027): a signed flat repository on the target's own disk.
OTHER=/srv/p3007a-other
OTHER_VERSION=9.9.9
# The distribution's ordinary update command (ADR-022 point 4): `apt
# upgrade` on Debian, `apt-get dist-upgrade` on Astra Linux. Split into
# words where it is used.
UPGRADE=${P3007A_UPGRADE:-apt upgrade -y}

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

# Every APT configuration file that is not Pakomichi's, with its digest.
foreign_config() {
    find /etc/apt -xdev -type f ! -name 'pakomichi*' -print0 | sort -z | xargs -0 sha256sum
}
