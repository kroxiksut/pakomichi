#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Verify the R-002 TEST ONLY sidecar against exact unsigned RPM bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rpm", type=Path)
    parser.add_argument("sidecar", type=Path)
    args = parser.parse_args()
    statement = json.loads(args.sidecar.read_text(encoding="utf-8"))
    actual = hashlib.sha256(args.rpm.read_bytes()).hexdigest()
    if statement.get("verified") is not True or statement.get("sha256") != actual:
        print(f"MODELED_ATTESTATION_INVALID expected={statement.get('sha256')} actual={actual}")
        return 1
    print(f"MODELED_ATTESTATION_VERIFIED sha256={actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
