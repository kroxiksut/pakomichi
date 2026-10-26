#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# P3-007a on Astra Linux over SSH, from WSL: one phase per call, so that the
# host can publish the new release between them (run-astra.ps1). The
# address and the sudo password file come only from the environment.
#
#   P3007A_TARGET=user@host P3007A_SUDO_PASS_FILE=path NEW_VERSION=x.y.z \
#       run-astra.sh phase1 LABEL
#   ... EXPECTED_SHA256=<digest> run-astra.sh phase2 LABEL
#
# Phase 1 copies the P4-001a bed and the P3-007a scripts, prepares the
# target (reader on 879) and runs phase1.sh; phase 2 runs phase2.sh and
# removes the staging directory. The ordinary update command is
# `apt-get dist-upgrade` (ADR-022 point 4). Writes
# .research-local/p3-007a/runs/LABEL/ in the checkout.
set -euo pipefail

phase="${1:?usage: run-astra.sh phase1|phase2 LABEL}"
label="${2:?usage: run-astra.sh phase1|phase2 LABEL}"
target="${P3007A_TARGET:?set P3007A_TARGET=user@host}"
pass="${P3007A_SUDO_PASS_FILE:?set P3007A_SUDO_PASS_FILE}"
version="${NEW_VERSION:?set NEW_VERSION}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
bin=/mnt/c/temp/pakomichi/p4-001a/bin
out="$root/.research-local/p3-007a/runs/$label"
ssh_opts=(-o BatchMode=yes -o ServerAliveInterval=30 -o ConnectTimeout=15 -o StrictHostKeyChecking=yes)
upgrade='apt-get dist-upgrade -y'
remote_out=/var/tmp/p3007a-out

case "$phase" in
phase1)
    [[ ! -e $out ]] || { echo "$out exists; use a new label" >&2; exit 1; }
    mkdir -p "$out"
    remote="$(ssh "${ssh_opts[@]}" "$target" 'mktemp -d /tmp/pakomichi-p3007a.XXXXXXXX')"
    [[ "$remote" =~ ^/tmp/pakomichi-p3007a\.[A-Za-z0-9]{8}$ ]] || { echo "unexpected staging path: $remote" >&2; exit 1; }
    printf '%s\n' "$remote" >"$out/remote-dir"
    tar -C "$root/research" -cf - p4-001a/lib.sh p4-001a/prepare.sh p4-001a/units \
        p3-007a/lib.sh p3-007a/other-source.sh p3-007a/phase1.sh p3-007a/phase2.sh |
        ssh "${ssh_opts[@]}" "$target" "mkdir -p $remote/h && tar -C $remote/h -xf -"
    tar -C "$bin" -cf - . | ssh "${ssh_opts[@]}" "$target" "mkdir -p $remote/bin && tar -C $remote/bin -xf -"
    # The root part travels as a file; nothing is quoted through ssh.
    cat >"$out/remote-phase1.sh" <<REMOTE
set -u
rm -rf /opt/p4001a /opt/p3007a $remote_out
cp -r $remote/h/p4-001a /opt/p4001a && cp -r $remote/h/p3-007a /opt/p3007a
mkdir -p /opt/p4001a/bin && cp $remote/bin/* /opt/p4001a/bin/
PAKOMICHI_PORT=879 bash /opt/p4001a/prepare.sh || exit 1
P3007A_OUT=$remote_out NEW_VERSION=$version P3007A_UPGRADE='$upgrade' bash /opt/p3007a/phase1.sh
status=\$?
tar -C $remote_out -cf $remote/out.tar .
chown "\$SUDO_USER" $remote/out.tar
exit \$status
REMOTE
    script="$out/remote-phase1.sh"
    ;;
phase2)
    sha="${EXPECTED_SHA256:?set EXPECTED_SHA256}"
    remote="$(cat "$out/remote-dir")"
    cat >"$out/remote-phase2.sh" <<REMOTE
set -u
P3007A_OUT=$remote_out NEW_VERSION=$version EXPECTED_SHA256=$sha P3007A_UPGRADE='$upgrade' bash /opt/p3007a/phase2.sh
status=\$?
tar -C $remote_out -cf $remote/out.tar .
chown "\$SUDO_USER" $remote/out.tar
exit \$status
REMOTE
    script="$out/remote-phase2.sh"
    ;;
*)
    echo "unknown phase $phase" >&2
    exit 2
    ;;
esac

scp -q "${ssh_opts[@]}" "$script" "$target:$remote/remote.sh"
set +e
head -n 1 "$pass" | ssh "${ssh_opts[@]}" "$target" "sudo -S -p '' bash $remote/remote.sh" 2>&1 | tee "$out/console-$phase.log"
status=${PIPESTATUS[1]}
set -e
ssh "${ssh_opts[@]}" "$target" "cat $remote/out.tar" | tar -C "$out" -xf -
if [[ $phase == phase2 ]]; then
    head -n 1 "$pass" | ssh "${ssh_opts[@]}" "$target" "sudo -S -p '' rm -rf $remote" || true
fi
cat "$out/results.tsv"
exit "$status"
