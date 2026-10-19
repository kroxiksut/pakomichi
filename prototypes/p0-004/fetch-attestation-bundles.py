# SPDX-License-Identifier: MIT OR Apache-2.0

import json
import pathlib
import sys
import urllib.request


def decode_snappy(data: bytes) -> bytes:
    position = 0
    expected_size = 0
    shift = 0
    while True:
        byte = data[position]
        position += 1
        expected_size |= (byte & 0x7F) << shift
        if byte < 0x80:
            break
        shift += 7

    output = bytearray()
    while position < len(data):
        tag = data[position]
        position += 1
        kind = tag & 0x03
        if kind == 0:
            encoded_length = tag >> 2
            if encoded_length < 60:
                length = encoded_length + 1
            else:
                width = encoded_length - 59
                length = int.from_bytes(data[position : position + width], "little") + 1
                position += width
            output.extend(data[position : position + length])
            position += length
            continue

        if kind == 1:
            length = 4 + ((tag >> 2) & 0x07)
            offset = ((tag & 0xE0) << 3) | data[position]
            position += 1
        elif kind == 2:
            length = 1 + (tag >> 2)
            offset = int.from_bytes(data[position : position + 2], "little")
            position += 2
        else:
            length = 1 + (tag >> 2)
            offset = int.from_bytes(data[position : position + 4], "little")
            position += 4
        if offset == 0 or offset > len(output):
            raise ValueError("invalid Snappy copy offset")
        for _ in range(length):
            output.append(output[-offset])

    if len(output) != expected_size:
        raise ValueError("Snappy size mismatch")
    return bytes(output)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: fetch-attestation-bundles.py API_RESPONSE OUTPUT", file=sys.stderr)
        return 2

    response_path = pathlib.Path(sys.argv[1])
    output_path = pathlib.Path(sys.argv[2])
    response = json.loads(response_path.read_text(encoding="utf-8"))
    bundles: list[str] = []
    for attestation in response.get("attestations", []):
        bundle = attestation.get("bundle")
        if bundle is None:
            with urllib.request.urlopen(attestation["bundle_url"], timeout=30) as remote:
                body = remote.read()
                if remote.headers.get_content_type() == "application/x-snappy":
                    body = decode_snappy(body)
                bundle = json.loads(body)
        bundles.append(json.dumps(bundle, separators=(",", ":")))

    if not bundles:
        print("no attestation bundles returned", file=sys.stderr)
        return 1
    output_path.write_text("\n".join(bundles) + "\n", encoding="utf-8")
    print(f"downloaded_bundles={len(bundles)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
