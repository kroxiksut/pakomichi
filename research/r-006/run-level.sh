#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Run one R-006 level check on an Astra Linux target over SSH.
# The address and the sudo password file come only from the environment.
#
# Usage: R006_TARGET=user@host R006_SUDO_PASS_FILE=path run-level.sh LABEL
# Writes .research-local/r-006/<LABEL>.log in the checkout.
set -euo pipefail

label="${1:?usage: run-level.sh LABEL}"
target="${R006_TARGET:?set R006_TARGET=user@host}"
pass="${R006_SUDO_PASS_FILE:?set R006_SUDO_PASS_FILE}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
debs="$root/.research-local/r-006/debs"
ssh_opts=(-o BatchMode=yes -o ServerAliveInterval=30 -o ConnectTimeout=15 -o StrictHostKeyChecking=yes)

remote="$(ssh "${ssh_opts[@]}" "$target" 'mktemp -d /tmp/pakomichi-r006.XXXXXXXX')"
[[ "$remote" =~ ^/tmp/pakomichi-r006\.[A-Za-z0-9]{8}$ ]] || { echo "unexpected staging path: $remote" >&2; exit 1; }
scp -q "${ssh_opts[@]}" "$here/level-check.sh" "$debs"/*.deb "$target:$remote/"
head -n 1 "$pass" | ssh "${ssh_opts[@]}" "$target" \
    "sudo -S -p '' bash $remote/level-check.sh $label $remote; rm -rf $remote" \
    | tee "$root/.research-local/r-006/$label.log"
