#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Run the R-001 matrix as root on a shared, non-disposable target (a test
# laptop or a long-lived VM) from the bundle that run-remote.sh unpacked.
# The repositories are served from the target's own loopback, the scenarios
# run with R001_ISOLATE=1, and every R-001 change is removed afterwards, even
# when a scenario fails.
# Usage: remote-run.sh PLATFORM apt|dnf
set -uo pipefail

readonly platform="$1" kind="$2" port=18081
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly here root="$here/root"
case "$kind" in apt | dnf) ;; *) echo "unknown kind: $kind" >&2; exit 2 ;; esac

mkdir -p "$root/served" "$root/logs" "$root/runs"
: > "$root/logs/http.log"
python3 -I "$here/harness/repo-server.py" "$root/served" "$root/logs/http.log" "$port" \
    > "$root/logs/server.out" 2>&1 < /dev/null &
server=$!

restore() {
    kill "$server" 2> /dev/null
    wait "$server" 2> /dev/null
    # The scenario scripts clean up on success; this also covers an abort.
    sed -i '/pakomichi\.test/d' /etc/hosts
    if [[ "$kind" == apt ]]; then
        rm -f /etc/apt/apt.conf.d/99pakomichi-r001-isolate /etc/apt/sources.list.d/pakomichi-r001.sources \
            /etc/apt/preferences.d/pakomichi-r001 /etc/apt/keyrings/pakomichi-r001-alpha.asc \
            /etc/apt/keyrings/pakomichi-r001-beta.asc /etc/apt/keyrings/pakomichi-r001-system.asc
        rm -f /var/lib/apt/lists/*pakomichi.test*
    else
        sed -i '\#^reposdir=/etc/pakomichi-r001\.repos\.d$#d' /etc/dnf/dnf.conf
        rm -rf /etc/pakomichi-r001.repos.d /var/cache/dnf/pakomichi-r001-*
        rm -f /etc/pki/rpm-gpg/pakomichi-r001-alpha.asc /etc/pki/rpm-gpg/pakomichi-r001-beta.asc \
            /etc/pki/rpm-gpg/pakomichi-r001-system.asc
    fi
    # Hand the results back to the account that started the run.
    [[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$here"
}
trap restore EXIT

for _ in $(seq 100); do
    (exec 3<> "/dev/tcp/127.0.0.1/$port") 2> /dev/null && break
    sleep 0.1
done
# A platform name ending in -noplugins runs DNF without its plugins.
noplugins=0
[[ "$platform" == *-noplugins ]] && noplugins=1
R001_ROOT="$root" R001_ISOLATE=1 R001_NOPLUGINS="$noplugins" bash "$here/harness/$kind-scenarios.sh" "$platform" < /dev/null
status=$?
echo "scenarios exit $status"
exit "$status"
