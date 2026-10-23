#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check tests/data/native-versions.tsv against the native tools.

Run inside a disposable environment (never on the development host):

    python3 -I scripts/check-native-versions.py --dpkg tests/data/native-versions.tsv
    python3 -I scripts/check-native-versions.py --rpm  tests/data/native-versions.tsv

--dpkg uses `dpkg --compare-versions`; --rpm uses python3-rpm
(`rpm.labelCompare`, `rpm.ver`, `rpm.ds(...).Compare`). Prints one line per
vector and exits 1 on any mismatch. The same vectors are checked against
Pakomichi's comparators by `cargo test` (src/family/version_tests.rs).
"""

import argparse
import subprocess
import sys

SIGN = {-1: "<", 0: "=", 1: ">"}


def read_vectors(path):
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 4:
                raise SystemExit(f"{path}:{number}: expected 4 tab-separated fields")
            yield number, fields


def dpkg_compare(left, right):
    for op, sign in (("lt", "<"), ("eq", "="), ("gt", ">")):
        result = subprocess.run(
            ["dpkg", "--compare-versions", left, op, right],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in (0, 1):
            return "error", result.stderr.strip()
        if result.returncode == 0:
            return sign, result.stderr.strip()
    return "?", ""


def check_dpkg(kind, left, right):
    if kind == "deb":
        actual, _ = dpkg_compare(left, right)
        return actual
    # A refused version makes dpkg exit with an error; a warned one prints a
    # warning and still compares.
    actual, stderr = dpkg_compare(left, "0")
    if kind == "deb-invalid":
        return "error" if actual == "error" else actual
    return "error" if actual != "error" and "warning" in stderr else f"dpkg:{actual}"


def check_rpm(rpm, kind, left, right):
    if kind == "rpm":
        return SIGN[rpm.labelCompare(("0", left, "1"), ("0", right, "1"))]
    if kind == "rpm-evr":
        a, b = rpm.ver(left), rpm.ver(right)
        return "<" if a < b else ">" if a > b else "="
    flags = {
        "<": rpm.RPMSENSE_LESS,
        "<=": rpm.RPMSENSE_LESS | rpm.RPMSENSE_EQUAL,
        "=": rpm.RPMSENSE_EQUAL,
        ">=": rpm.RPMSENSE_GREATER | rpm.RPMSENSE_EQUAL,
        ">": rpm.RPMSENSE_GREATER,
    }
    (provide_op, provide), (require_op, require) = left.split(), right.split()
    provides = rpm.ds(("x", flags[provide_op], provide), rpm.RPMTAG_PROVIDENAME)
    requires = rpm.ds(("x", flags[require_op], require), rpm.RPMTAG_REQUIRENAME)
    return "1" if provides.Compare(requires) else "0"


def main():
    parser = argparse.ArgumentParser()
    tool = parser.add_mutually_exclusive_group(required=True)
    tool.add_argument("--dpkg", action="store_true")
    tool.add_argument("--rpm", action="store_true")
    parser.add_argument("vectors")
    args = parser.parse_args()
    rpm = None
    if args.rpm:
        import rpm  # noqa: PLC0415 - only present on RPM systems
    checked = mismatches = 0
    for number, (kind, left, right, expected) in read_vectors(args.vectors):
        if args.dpkg and not kind.startswith("deb"):
            continue
        if args.rpm and not kind.startswith("rpm"):
            continue
        actual = check_rpm(rpm, kind, left, right) if args.rpm else check_dpkg(kind, left, right)
        checked += 1
        status = "OK" if actual == expected else "MISMATCH"
        mismatches += status != "OK"
        print(f"{status}\t{number}\t{kind}\t{left}\t{right}\texpected={expected}\tactual={actual}")
    print(f"checked={checked} mismatches={mismatches}")
    return 1 if mismatches or not checked else 0


if __name__ == "__main__":
    sys.exit(main())
