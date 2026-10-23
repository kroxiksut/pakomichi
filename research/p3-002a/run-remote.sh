#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Run the P3-002a pin check on a shared, non-disposable target over SSH.
# Bundles the harness, the built repositories, and the public keys (never
# the secret keys), serves the repositories on the target's own loopback,
# runs scenarios.sh as root with the given ordinary update commands, removes
# every change, and copies the logs back to
# .research-local/p3-002a/runs/PLATFORM. The target address comes only from
# the environment; the sudo password comes from a local file with minimal
# permissions outside the repository (never a command argument).
# Usage: P3002A_TARGET=user@host [P3002A_SUDO_PASS_FILE=path] run-remote.sh PLATFORM "COMMAND" ...
set -euo pipefail

readonly platform="$1"
shift
readonly target="${P3002A_TARGET:?set P3002A_TARGET=user@host}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readonly local_root="$project_root/.research-local/p3-002a"
readonly out="$local_root/runs/$platform"
readonly ssh_opts=(-o BatchMode=yes -o ServerAliveInterval=30 -o ConnectTimeout=15)

work="$(mktemp -d /tmp/pakomichi-p3002a-bundle.XXXXXX)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bundle/harness" "$work/bundle/root/keys" "$work/bundle/root/logs"
cp "$script_dir"/scenarios.sh "$project_root/research/r-001/repo-server.py" "$work/bundle/harness/"
cp -r "$local_root/repos" "$work/bundle/root/"
cp "$project_root"/.research-local/r-001/keys/*.pub.asc "$work/bundle/root/keys/"
cat > "$work/bundle/remote-run.sh" << 'EOF'
#!/usr/bin/env bash
# Runs as root on the target from the unpacked bundle.
set -uo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly here root="$here/root" port=18082
: > "$root/logs/http.log"
python3 -I "$here/harness/repo-server.py" "$root/repos" "$root/logs/http.log" "$port" \
    > "$root/logs/server.out" 2>&1 < /dev/null &
server=$!
restore() {
    kill "$server" 2> /dev/null
    wait "$server" 2> /dev/null
    rm -f /etc/apt/apt.conf.d/99pakomichi-p3002a-isolate /etc/apt/sources.list.d/pakomichi-p3002a.sources \
        /etc/apt/preferences.d/pakomichi-p3002a /etc/apt/keyrings/pakomichi-p3002a-alpha.asc \
        /etc/apt/keyrings/pakomichi-p3002a-beta.asc /etc/apt/keyrings/pakomichi-p3002a-system.asc
    rm -f /var/lib/apt/lists/*p3002a*
    [[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$here"
}
trap restore EXIT
for _ in $(seq 100); do
    (exec 3<> "/dev/tcp/127.0.0.1/$port") 2> /dev/null && break
    sleep 0.1
done
platform="$1"
shift
P3002A_ROOT="$root" P3002A_KEYS="$root/keys" bash "$here/harness/scenarios.sh" "$platform" "$@" < /dev/null
status=$?
echo "scenarios exit $status"
exit "$status"
EOF
tar -C "$work/bundle" -czf "$work/bundle.tar.gz" .

# The bundle runs as root, so stage it in a fresh private directory.
remote="$(ssh "${ssh_opts[@]}" "$target" 'mktemp -d /tmp/pakomichi-p3002a-remote.XXXXXXXX')"
[[ "$remote" =~ ^/tmp/pakomichi-p3002a-remote\.[A-Za-z0-9]{8}$ ]] || { echo "unexpected staging path: $remote" >&2; exit 1; }
scp -q "${ssh_opts[@]}" "$work/bundle.tar.gz" "$target:$remote/bundle.tar.gz"
ssh "${ssh_opts[@]}" "$target" "test -O $remote && chmod 0700 $remote && tar -C $remote -xzf $remote/bundle.tar.gz"

quoted=""
for command in "$@"; do quoted+=" '$command'"; done
status=0
if [[ "${target%%@*}" == root ]]; then
    ssh "${ssh_opts[@]}" "$target" "bash $remote/remote-run.sh $platform$quoted" || status=$?
else
    head -n 1 "${P3002A_SUDO_PASS_FILE:?set P3002A_SUDO_PASS_FILE for a non-root target}" |
        ssh "${ssh_opts[@]}" "$target" "sudo -S bash $remote/remote-run.sh $platform$quoted" || status=$?
fi

mkdir -p "$out"
find "$out" -mindepth 1 -delete
ssh "${ssh_opts[@]}" "$target" "tar -C $remote/root -cf - runs/$platform logs" | tar -C "$work" -xf -
cp -r "$work/runs/$platform/." "$out/"
cp "$work/logs/http.log" "$work/logs/server.out" "$out/"
ssh "${ssh_opts[@]}" "$target" "rm -rf $remote"
echo "run-remote: $platform scenarios exit $status; logs in $out"
exit "$status"
