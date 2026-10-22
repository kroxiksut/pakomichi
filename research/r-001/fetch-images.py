# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fetch digest-pinned official distribution images for R-001.

Each image is an official Docker Library image maintained by its
distribution. The script resolves a tag only with --update; otherwise it
downloads exactly the manifest and layer digests recorded in images.lock.json
and verifies the SHA-256 of every byte it receives. The single root
filesystem layer becomes the clean baseline imported into WSL.

Usage: python -I fetch-images.py OUTPUT_DIR [--update]
"""

import hashlib
import json
import pathlib
import sys
import urllib.request

REGISTRY = "https://registry-1.docker.io"
AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
INDEX_TYPES = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
LOCK = pathlib.Path(__file__).with_name("images.lock.json")

# Platform name -> official image reference.
IMAGES = {
    "debian12": "library/debian:12",
    "debian13": "library/debian:13",
    "ubuntu2404": "library/ubuntu:24.04",
    "alma9": "library/almalinux:9",
    # A newer DNF4 than AlmaLinux 9, to tell upstream DNF behavior from
    # distribution changes seen on RED OS 8.
    "alma10": "library/almalinux:10",
    "fedora44": "library/fedora:44",
}


def token(repo):
    with urllib.request.urlopen(AUTH.format(repo=repo), timeout=60) as response:
        return json.load(response)["token"]


def fetch(url, bearer, accept=None):
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer}"})
    if accept:
        request.add_header("Accept", accept)
    with urllib.request.urlopen(request, timeout=300) as response:
        return response.read(), response.headers


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def manifest(repo, reference, bearer):
    body, headers = fetch(f"{REGISTRY}/v2/{repo}/manifests/{reference}", bearer, INDEX_TYPES)
    digest = sha256(body)
    if reference.startswith("sha256:") and digest != reference:
        raise SystemExit(f"manifest digest mismatch for {repo}@{reference}: got {digest}")
    advertised = headers.get("Docker-Content-Digest")
    if advertised and advertised != digest:
        raise SystemExit(f"registry advertised {advertised} but body hashes to {digest}")
    return json.loads(body), digest


def resolve(reference):
    repo, tag = reference.rsplit(":", 1)
    bearer = token(repo)
    index, index_digest = manifest(repo, tag, bearer)
    entries = [
        entry
        for entry in index.get("manifests", [])
        if entry.get("platform", {}).get("os") == "linux"
        and entry.get("platform", {}).get("architecture") == "amd64"
    ]
    if len(entries) != 1:
        raise SystemExit(f"{reference}: expected one linux/amd64 manifest, found {len(entries)}")
    return {
        "reference": reference,
        "index_digest": index_digest,
        "manifest_digest": entries[0]["digest"],
    }


def download(name, entry, output):
    repo = entry["reference"].rsplit(":", 1)[0]
    bearer = token(repo)
    image, _ = manifest(repo, entry["manifest_digest"], bearer)
    layers = image["layers"]
    if len(layers) != 1 or layers[0]["mediaType"] not in LAYER_TYPES:
        raise SystemExit(f"{name}: expected one gzip root filesystem layer, got {layers}")
    blobs = {"config": image["config"]["digest"], "layer": layers[0]["digest"]}
    for kind, digest in blobs.items():
        if entry.get(f"{kind}_digest") not in (None, digest):
            raise SystemExit(f"{name}: {kind} digest {digest} differs from the lock")
        target = output / f"{name}.{kind}{'.tar.gz' if kind == 'layer' else '.json'}"
        if target.exists() and sha256(target.read_bytes()) == digest:
            continue
        data, _ = fetch(f"{REGISTRY}/v2/{repo}/blobs/{digest}", bearer)
        if sha256(data) != digest:
            raise SystemExit(f"{name}: {kind} blob does not match {digest}")
        target.write_bytes(data)
        entry[f"{kind}_digest"] = digest
        entry[f"{kind}_size"] = len(data)
    created = json.loads((output / f"{name}.config.json").read_text(encoding="utf-8")).get("created")
    entry["created"] = created
    print(f"{name}: {entry['reference']} layer {entry['layer_digest']} created {created}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    output = pathlib.Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    update = "--update" in sys.argv[2:]
    lock = json.loads(LOCK.read_text(encoding="utf-8")) if LOCK.exists() else {}
    for name, reference in IMAGES.items():
        if update or name not in lock:
            lock[name] = resolve(reference)
        download(name, lock[name], output)
    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
