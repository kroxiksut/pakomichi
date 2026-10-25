#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Run the P4-003a Astra scenarios (astra-n036.sh) on a target over SSH,
# from WSL. The address and the sudo password file come only from the
# environment. Build first: research/p4-003a/build.sh.
#
# Usage: P4003A_TARGET=user@host P4003A_SUDO_PASS_FILE=path run-astra.sh LABEL
# Writes .research-local/p4-003a/runs/LABEL/ in the checkout.
set -euo pipefail

label="${1:?usage: run-astra.sh LABEL}"
target="${P4003A_TARGET:?set P4003A_TARGET=user@host}"
pass="${P4003A_SUDO_PASS_FILE:?set P4003A_SUDO_PASS_FILE}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
bin=/mnt/c/temp/pakomichi/p4-003a/bin
out="$root/.research-local/p4-003a/runs/$label"
ssh_opts=(-o BatchMode=yes -o ServerAliveInterval=30 -o ConnectTimeout=15 -o StrictHostKeyChecking=yes)

remote="$(ssh "${ssh_opts[@]}" "$target" 'mktemp -d /tmp/pakomichi-p4003a.XXXXXXXX')"
[[ "$remote" =~ ^/tmp/pakomichi-p4003a\.[A-Za-z0-9]{8}$ ]] || { echo "unexpected staging path: $remote" >&2; exit 1; }
tar -C "$here" -cf - lib.sh prepare.sh astra-n036.sh units configs |
    ssh "${ssh_opts[@]}" "$target" "mkdir -p $remote/h && tar -C $remote/h -xf -"
scp -q "${ssh_opts[@]}" "$bin/pakomichi-applier" "$bin/p4003a-call" "$target:$remote/h/"
mkdir -p "$out"
rm -f "$out"/*
# The root part travels as a file; nothing is quoted through ssh.
cat >"$out/remote.sh" <<REMOTE
set -u
rm -rf /opt/p4003a && mkdir -p /opt/p4003a/bin && cp -r $remote/h/. /opt/p4003a/
mv /opt/p4003a/pakomichi-applier /opt/p4003a/p4003a-call /opt/p4003a/bin/
bash /opt/p4003a/prepare.sh && P4003A_OUT=/tmp/p4003a-out bash /opt/p4003a/astra-n036.sh
status=\$?
tar -C /tmp/p4003a-out -cf $remote/out.tar .
chown "\$SUDO_USER" $remote/out.tar
exit \$status
REMOTE
scp -q "${ssh_opts[@]}" "$out/remote.sh" "$target:$remote/remote.sh"
set +e
head -n 1 "$pass" | ssh "${ssh_opts[@]}" "$target" "sudo -S -p '' bash $remote/remote.sh" 2>&1 | tee "$out/console.log"
status=${PIPESTATUS[1]}
set -e
ssh "${ssh_opts[@]}" "$target" "cat $remote/out.tar" | tar -C "$out" -xf -
head -n 1 "$pass" | ssh "${ssh_opts[@]}" "$target" "sudo -S -p '' rm -rf $remote" || true
cat "$out/results.tsv"
exit "$status"
