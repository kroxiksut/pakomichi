#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Run the R-001 matrix on a shared, non-disposable target over SSH.
# Bundles the harness with the fixtures, layouts, and public keys (never the
# secret keys), runs remote-run.sh as root on the target, and copies the logs
# back to .research-local/r-001/runs/PLATFORM. The target address comes only
# from the environment; the sudo password comes from a local file with
# minimal permissions outside the repository (never a command argument).
# Usage: R001_TARGET=user@host [R001_SUDO_PASS_FILE=path] run-remote.sh PLATFORM apt|dnf
set -euo pipefail

readonly platform="$1" kind="$2"
readonly target="${R001_TARGET:?set R001_TARGET=user@host}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readonly local_root="$project_root/.research-local/r-001"
readonly out="$local_root/runs/$platform"
readonly ssh_opts=(-o BatchMode=yes -o ServerAliveInterval=30 -o ConnectTimeout=15)

work="$(mktemp -d /tmp/pakomichi-r001-bundle.XXXXXX)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bundle/harness" "$work/bundle/root/keys"
cp "$script_dir"/*.sh "$script_dir"/*.py "$script_dir"/*.txt "$work/bundle/harness/"
mv "$work/bundle/harness/remote-run.sh" "$work/bundle/"
cp -r "$local_root/fixtures" "$local_root/layouts" "$work/bundle/root/"
cp "$local_root"/keys/*.pub.asc "$work/bundle/root/keys/"
tar -C "$work/bundle" -czf "$work/bundle.tar.gz" .

# The bundle runs as root, so stage it in a fresh private directory that no
# other local user can have prepared or can change.
remote="$(ssh "${ssh_opts[@]}" "$target" 'mktemp -d /tmp/pakomichi-r001-remote.XXXXXXXX')"
[[ "$remote" =~ ^/tmp/pakomichi-r001-remote\.[A-Za-z0-9]{8}$ ]] || { echo "unexpected staging path: $remote" >&2; exit 1; }
scp -q "${ssh_opts[@]}" "$work/bundle.tar.gz" "$target:$remote/bundle.tar.gz"
ssh "${ssh_opts[@]}" "$target" "test -O $remote && chmod 0700 $remote && tar -C $remote -xzf $remote/bundle.tar.gz"

status=0
if [[ "${target%%@*}" == root ]]; then
    ssh "${ssh_opts[@]}" "$target" "bash $remote/remote-run.sh $platform $kind" || status=$?
else
    head -n 1 "${R001_SUDO_PASS_FILE:?set R001_SUDO_PASS_FILE for a non-root target}" |
        ssh "${ssh_opts[@]}" "$target" "sudo -S bash $remote/remote-run.sh $platform $kind" || status=$?
fi

mkdir -p "$out"
find "$out" -mindepth 1 -delete
ssh "${ssh_opts[@]}" "$target" "tar -C $remote/root -cf - runs/$platform logs" | tar -C "$work" -xf -
cp -r "$work/runs/$platform/." "$out/"
cp "$work/logs/http.log" "$work/logs/server.out" "$out/"
ssh "${ssh_opts[@]}" "$target" "rm -rf $remote"
echo "run-remote: $platform scenarios exit $status; logs in $out"
exit "$status"
