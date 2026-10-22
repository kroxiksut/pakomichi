#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# One R-006 matrix cell on an Astra Linux target, run as root through sudo.
# Records the security level as an unprivileged user and as root, installs
# the TEST ONLY fixtures with dpkg and apt, runs the unsigned ELF as the user
# and as root, checks the postinst marker, and purges both packages again.
#
# Usage: sudo bash level-check.sh LABEL DEBDIR
set -uo pipefail

label="${1:?usage: level-check.sh LABEL DEBDIR}"
debs="${2:?usage: level-check.sh LABEL DEBDIR}"
user="${SUDO_USER:?run through sudo}"
export LC_ALL=C PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin DEBIAN_FRONTEND=noninteractive

run() { echo "\$ $*"; timeout 120 "$@" 2>&1; echo "[exit $?]"; }
as_user() { echo "\$ (as $user) $*"; timeout 60 runuser -u "$user" -- "$@" 2>&1; echo "[exit $?]"; }
kernel_log() { echo "--- kernel log (digsig/parsec), last 15"; dmesg 2>/dev/null | grep -iE 'digsig|parsec|mic|ilev' | tail -n 15; }

echo "## R-006 $label $(date -u +%FT%TZ)"
echo "### level, unprivileged"
as_user astra-modeswitch get
as_user astra-modeswitch getname
as_user cat /etc/digsig/digsig_initramfs.conf
as_user cat /proc/cmdline
as_user pdp-id
as_user sh -c 'for f in /sys/module/digsig_verif/parameters/*; do echo "$f=$(cat "$f")"; done'
echo "### level, root"
for tool in astra-digsig-control astra-mic-control astra-mac-control astra-interpreters-lock \
            astra-nochmodx-lock astra-bash-lock astra-sudo-control astra-ptrace-lock; do
    command -v "$tool" >/dev/null && run "$tool" is-enabled
done
run pdp-id
run sh -c 'for f in /sys/module/digsig_verif/parameters/*; do echo "$f=$(cat "$f")"; done'
run sh -c 'ls /etc/digsig/keys /etc/digsig/xattr_keys'

echo "### dpkg -i unsigned ELF package"
dmesg -C 2>/dev/null || true
run dpkg -i "$debs/sampleapp-elf_1.0-1_amd64.deb"
run dpkg-query -W -f '${Status} ${Version}\n' sampleapp-elf
run sha256sum /usr/bin/sampleapp-elf
as_user /usr/bin/sampleapp-elf
run /usr/bin/sampleapp-elf
kernel_log

echo "### apt-get install package with postinst"
run apt-get install -y "$debs/sampleapp-script_1.0-1_all.deb"
run dpkg-query -W -f '${Status} ${Version}\n' sampleapp-script
run cat /var/lib/sampleapp-script/postinst-ran

echo "### purge"
run dpkg -P sampleapp-elf sampleapp-script
run sh -c 'ls /usr/bin/sampleapp-elf /var/lib/sampleapp-script 2>&1; dpkg-query -W "sampleapp*" 2>&1'
echo "## end $label"
