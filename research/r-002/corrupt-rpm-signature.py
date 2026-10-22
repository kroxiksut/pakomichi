#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Flip one byte inside an RPM OpenPGP signature packet, leaving the payload intact."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


# Legacy PGP/GPG tags and the current DSAHEADER/RSAHEADER tags.
SIGNATURE_TAGS = {267, 268, 1002, 1005, 1006}


def corrupt(source: Path, destination: Path) -> None:
    data = bytearray(source.read_bytes())
    header = 96
    if data[header : header + 3] != b"\x8e\xad\xe8":
        raise RuntimeError("RPM signature header magic not found")
    count, data_size = struct.unpack(">II", data[header + 8 : header + 16])
    index_start = header + 16
    store_start = index_start + count * 16
    if store_start + data_size > len(data):
        raise RuntimeError("RPM signature header exceeds file size")
    for index in range(count):
        tag, value_type, offset, item_count = struct.unpack(
            ">IIII", data[index_start + index * 16 : index_start + (index + 1) * 16]
        )
        if tag in SIGNATURE_TAGS and value_type == 7 and item_count > 8:
            position = store_start + offset + item_count // 2
            data[position] ^= 0x01
            destination.write_bytes(data)
            return
    raise RuntimeError("no binary OpenPGP signature tag found")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    corrupt(args.source, args.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
