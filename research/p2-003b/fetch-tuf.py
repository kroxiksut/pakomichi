#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Record a snapshot of a TUF repository for the offline P2-003b tests.

  fetch-tuf.py BASE_URL BOOTSTRAP_ROOT OUT_DIR

Fetches the root chain after the bootstrap root (N.root.json until 404),
timestamp.json, the snapshot and top-level targets it names (consistent
snapshots), and the trusted_root.json target by its SHA-256 prefix, into
OUT_DIR with the repository's own relative paths. Nothing is verified here:
the tests verify everything through sigstore-tuf. Writes OUT_DIR/recorded.txt
with the fetch time (the tests evaluate expiry at that time).
"""

import hashlib
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

base, bootstrap, out = sys.argv[1].rstrip("/"), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
out.mkdir(parents=True, exist_ok=True)


def get(path):
    request = urllib.request.Request(f"{base}/{path}", headers={"User-Agent": "pakomichi-research"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if error.code in (403, 404):
            return None
        raise


def save(path, data):
    target = out / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    print(f"{path} {len(data)} sha256={hashlib.sha256(data).hexdigest()}")


version = json.loads(bootstrap.read_bytes())["signed"]["version"]
while True:
    version += 1
    data = get(f"{version}.root.json")
    if data is None:
        break
    save(f"{version}.root.json", data)

timestamp = get("timestamp.json")
save("timestamp.json", timestamp)
snapshot_version = json.loads(timestamp)["signed"]["meta"]["snapshot.json"]["version"]
snapshot = get(f"{snapshot_version}.snapshot.json")
save(f"{snapshot_version}.snapshot.json", snapshot)
targets_version = json.loads(snapshot)["signed"]["meta"]["targets.json"]["version"]
targets = get(f"{targets_version}.targets.json")
save(f"{targets_version}.targets.json", targets)
info = json.loads(targets)["signed"]["targets"]["trusted_root.json"]
digest = info["hashes"]["sha256"]
trusted_root = get(f"targets/{digest}.trusted_root.json")
save(f"targets/{digest}.trusted_root.json", trusted_root)
(out / "recorded.txt").write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n")
