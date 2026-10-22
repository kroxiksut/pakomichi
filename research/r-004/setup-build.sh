#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare the R-004 builder (pakomichi-r004-build, AlmaLinux 9). Run as root
# inside that distribution. AlmaLinux 9 has the oldest glibc (2.34) of the
# targets, so a binary linked here runs on every R-004 target.
set -euo pipefail

dnf -y -q install gcc sqlite-devel pkgconf-pkg-config findutils >/dev/null
rpm -q gcc sqlite-devel glibc
