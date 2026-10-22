#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# R-006 cell: package installation from a low integrity level on Astra Linux
# with integrity control on. Runs as root through sudo; the TEST ONLY packages
# from build-deb.sh are in DEBDIR. pdp-exec -l 0:0 starts a process at
# integrity level 0 (sumic needs a graphical session, see the R-006 report).
# Everything this script installs or creates is removed at the end.
#
# Usage: sudo bash low-ilev-check.sh LABEL DEBDIR
set -uo pipefail

label="${1:?usage: low-ilev-check.sh LABEL DEBDIR}"
debs="${2:?usage: low-ilev-check.sh LABEL DEBDIR}"
export LC_ALL=C PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin DEBIAN_FRONTEND=noninteractive
exec < /dev/null

run() { echo "\$ $*"; timeout 120 "$@" 2>&1; echo "[exit $?]"; }
low() { run pdp-exec -l 0:0 -- "$@"; }
pkg="$debs/sampleapp-script_1.0-1_all.deb"
probes=(/etc/apt/sources.list.d/pakomichi-r006-probe.list /var/lib/pakomichi-r006-probe
        /var/cache/apt/archives/pakomichi-r006-probe)

echo "## R-006 $label $(date -u +%FT%TZ)"
echo "### level"
run astra-modeswitch getname
run cat /proc/cmdline
run pdp-id
echo "### integrity labels of the paths a package installation writes"
run pdp-ls -Md /etc /etc/apt /usr/bin /var/lib/dpkg /var/lib/apt/lists /var/cache/apt/archives /var/log /tmp

echo "### integrity level 0"
low /usr/bin/pdp-id
low /usr/bin/dpkg -i "$pkg"
run dpkg-query -W -f '${Status} ${Version}\n' sampleapp-script
low /usr/bin/apt-get install -y "$pkg"
run dpkg-query -W -f '${Status} ${Version}\n' sampleapp-script
low /usr/bin/apt-get update
for p in "${probes[@]}"; do low /usr/bin/touch "$p"; done
run ls -l "${probes[@]}"

echo "### control: the administrator's level"
run dpkg -i "$pkg"
run cat /var/lib/sampleapp-script/postinst-ran

echo "### systemd service level"
run systemd-run --wait --pipe --quiet /usr/bin/pdp-id
run systemd-run --wait --pipe --quiet -p DynamicUser=yes /usr/bin/pdp-id

echo "### cleanup"
dpkg -P sampleapp-script > /dev/null 2>&1
rm -f "${probes[@]}"
run sh -c 'dpkg-query -W "sampleapp*" 2>&1; ls /var/lib/sampleapp-script 2>&1'
echo "## end $label"
