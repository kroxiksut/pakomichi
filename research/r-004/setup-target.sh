#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare an R-004 target distribution (stage 1): install systemd and the
# tools the scenarios use, create the service user, enable systemd as PID 1.
# Run as root inside pakomichi-r004-<target>; then terminate and restart the
# distribution so systemd boots. Only this disposable distribution changes.
set -euo pipefail

if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -q update >/dev/null
    apt-get -q -y install --no-install-recommends systemd systemd-sysv dbus gpg gpgv gpg-agent \
        curl ca-certificates python3 procps iproute2 sqlite3 xz-utils zstd util-linux >/dev/null
else
    dnf -y -q install systemd dbus gnupg2 python3 procps-ng iproute sqlite xz zstd util-linux \
        rpm-build createrepo_c findutils >/dev/null
    command -v curl >/dev/null || dnf -y -q install curl >/dev/null
fi

getent group pakomichi-r004 >/dev/null || groupadd --system pakomichi-r004
getent passwd pakomichi-r004 >/dev/null ||
    useradd --system --gid pakomichi-r004 --home-dir /nonexistent --shell /usr/sbin/nologin pakomichi-r004

printf '[boot]\nsystemd=true\n' >/etc/wsl.conf
echo "stage 1 done; restart the distribution"
