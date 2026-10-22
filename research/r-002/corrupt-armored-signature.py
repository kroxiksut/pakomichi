#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Corrupt one base64 byte in an ASCII-armored detached signature."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    lines = args.path.read_text(encoding="ascii").splitlines()
    in_body = False
    for index, line in enumerate(lines):
        if not in_body:
            in_body = line == ""
            continue
        if line and not line.startswith("=") and not line.startswith("-----"):
            replacement = "A" if line[0] != "A" else "B"
            lines[index] = replacement + line[1:]
            with args.path.open("w", encoding="ascii", newline="\n") as stream:
                stream.write("\n".join(lines) + "\n")
            return 0
    raise RuntimeError("armored signature body not found")


if __name__ == "__main__":
    raise SystemExit(main())
