#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

source /etc/os-release
printf 'os=%s %s\n' "$ID" "$VERSION_ID"
uname -srmo
printf 'uid=%s\n' "$(id -u)"
printf 'user=%s\n' "$(id -un)"
printf 'systemd=%s\n' "$(systemctl --version | head -n 1)"
printf 'system_state=%s\n' "$(systemctl is-system-running 2>/dev/null || true)"

commands=(
    rustc cargo gcc pkg-config gpg gpgv sq dpkg-deb dpkg rpm rpm2cpio
    bsdtar ar tar cpio sqlite3 python3 systemd-socket-activate systemd-run
    systemd-analyze bwrap unshare curl gh
)

for command_name in "${commands[@]}"; do
    if command -v "$command_name" >/dev/null 2>&1; then
        printf '%s=%s\n' "$command_name" "$(command -v "$command_name")"
    else
        printf '%s=NOT_FOUND\n' "$command_name"
    fi
done

printf 'sqlite_library=' 
python3 - <<'PY'
import sqlite3
print(sqlite3.sqlite_version)
PY
