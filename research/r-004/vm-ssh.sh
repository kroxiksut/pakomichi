#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# SSH helper for the R-004 power-loss run (from the WSL distribution that
# holds the SSH key). The target and the sudo password file are arguments;
# neither is stored in the repository.
#   vm-ssh.sh TARGET PASSFILE copy FILE...   copy files to /tmp on the VM
#   vm-ssh.sh TARGET PASSFILE root COMMAND   run COMMAND through sudo
#   vm-ssh.sh TARGET PASSFILE wait           wait until SSH answers
set -uo pipefail
target=$1 pass=$2 mode=$3
shift 3
o=(-o BatchMode=yes -o ServerAliveInterval=30 -o ConnectTimeout=15 -o StrictHostKeyChecking=yes)
case "$mode" in
copy) scp -q "${o[@]}" "$@" "$target:/tmp/" ;;
# The whole command line runs under sudo (not only its first command).
root) head -n1 "$pass" | ssh "${o[@]}" "$target" "sudo -S -p '' bash -c $(printf '%q' "$*")" ;;
wait)
    for _ in $(seq 90); do
        ssh "${o[@]}" -o ConnectTimeout=5 "$target" true 2>/dev/null && exit 0
        sleep 5
    done
    echo "SSH did not come up" >&2; exit 1 ;;
*) echo "usage: vm-ssh.sh TARGET PASSFILE copy|root|wait ..." >&2; exit 2 ;;
esac
