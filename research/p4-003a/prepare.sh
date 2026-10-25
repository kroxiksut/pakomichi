#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare a P4-003a target (systemd running, disposable): the state
# owner's user and database, the applier units, and the APT directories
# the applier unit may write. Run as root with the harness in /opt/p4003a.
set -euo pipefail
# shellcheck source=lib.sh
source /opt/p4003a/lib.sh

[[ "$(ps -o comm= -p 1)" == systemd ]] || { echo "systemd is not PID 1" >&2; exit 1; }

install -m 0755 /opt/p4003a/bin/* /usr/local/bin/
install -m 0644 /opt/p4003a/units/* /etc/systemd/system/
getent group pakomichi >/dev/null || groupadd --system pakomichi
getent passwd pakomichi >/dev/null ||
    useradd --system --gid pakomichi --home-dir /nonexistent --shell /usr/sbin/nologin pakomichi
rm -rf "$STATE"
install -d -o pakomichi -g pakomichi -m 0750 "$STATE"
install -d -o pakomichi -g pakomichi -m 0700 "$STATE/state"
# ProtectSystem=strict needs every ReadWritePaths entry to exist.
install -d -m 0755 /etc/apt/keyrings /etc/apt/sources.list.d /etc/apt/preferences.d
# The distribution's lists, so apt-cache reads a real configuration.
apt-get -q update >/dev/null || echo "apt-get update failed; apt-cache reads the existing lists"

systemctl daemon-reload
systemctl enable --now pakomichi-apply.socket
[[ -S $SOCKET ]] || { echo "no apply.sock" >&2; exit 1; }
stat -c '%U %a' "$SOCKET"
# The state database, created by its owner.
owner status "$DB" >/dev/null
echo "prepared $(hostname)"
