#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build one signed APT or RPM generation tree for R-004 (TEST ONLY key).

  make_repo.py apt OUT --homedir H --key K [--valid SECS] [--date-offset SECS]
                       [--deb FILE ...] [--lazy-deb FILE=URL ...]
  make_repo.py rpm OUT --homedir H --key K [--simple-names]
                       [--rpm FILE ...] [--lazy-rpm FILE=URL ...]

Package files go to content-addressed paths (pool/<sha256>/<file>,
packages/<sha256>/<file>). Lazy packages are described in the generation
but left out of OUT and written to OUT.lazy.tsv (path, sha256, size, URL).
Exit code 3 means signing failed (used by the key-loss scenario).
"""

import argparse
import email.utils
import gzip
import hashlib
import pathlib
import shutil
import subprocess
import sys
import time


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sign(args, *gpg_args):
    command = ["gpg", "--homedir", args.homedir, "--batch", "--yes", "--quiet",
               "--pinentry-mode", "loopback", "--passphrase", "", "--local-user", args.key, *gpg_args]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write("signing failed: " + result.stderr)
        sys.exit(3)


def split_lazy(values):
    pairs = []
    for value in values:
        path, _, url = value.partition("=")
        pairs.append((pathlib.Path(path), url))
    return pairs


def build_apt(args, out):
    stanzas, lazy = [], []
    packages = [(pathlib.Path(p), None) for p in args.deb] + split_lazy(args.lazy_deb)
    for deb, url in packages:
        digest, size = sha256(deb), deb.stat().st_size
        relative = f"pool/{digest}/{deb.name}"
        control = subprocess.run(["dpkg-deb", "-f", str(deb)], check=True, capture_output=True, text=True).stdout
        stanzas.append(control.rstrip("\n") + f"\nFilename: {relative}\nSize: {size}\nSHA256: {digest}\n")
        if url:
            lazy.append(f"{relative}\t{digest}\t{size}\t{url}\n")
        else:
            target = out / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(deb, target)
    index_dir = out / "dists/stable/main/binary-amd64"
    index_dir.mkdir(parents=True, exist_ok=True)
    text = "\n".join(stanzas).encode()
    (index_dir / "Packages").write_bytes(text)
    (index_dir / "Packages.gz").write_bytes(gzip.compress(text, mtime=0))
    now = time.time() + args.date_offset
    lines = [
        "Origin: Pakomichi R-004 TEST ONLY",
        "Label: r004-test-only",
        "Suite: stable",
        "Codename: stable",
        "Date: " + email.utils.formatdate(now, usegmt=True).replace("GMT", "UTC"),
        "Valid-Until: " + email.utils.formatdate(now + args.valid, usegmt=True).replace("GMT", "UTC"),
        "Architectures: amd64",
        "Components: main",
        "Acquire-By-Hash: yes",
        "SHA256:",
    ]
    for name in ("Packages", "Packages.gz"):
        path = index_dir / name
        lines.append(f" {sha256(path)} {path.stat().st_size} main/binary-amd64/{name}")
    release = out / "dists/stable/Release"
    release.write_text("\n".join(lines) + "\n")
    sign(args, "--clearsign", "--output", str(out / "dists/stable/InRelease"), str(release))
    return lazy


def build_rpm(args, out):
    lazy = []
    packages = [(pathlib.Path(p), None) for p in args.rpm] + split_lazy(args.lazy_rpm)
    for rpm, url in packages:
        digest, size = sha256(rpm), rpm.stat().st_size
        relative = f"packages/{digest}/{rpm.name}"
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(rpm, target)
        if url:
            lazy.append((target, f"{relative}\t{digest}\t{size}\t{url}\n"))
    command = ["createrepo_c", "--quiet", "--no-database", "--checksum", "sha256",
               "--general-compress-type", "gz", str(out)]
    if args.simple_names:
        command.insert(1, "--simple-md-filenames")
    subprocess.run(command, check=True)
    for target, _ in lazy:
        target.unlink()
        target.parent.rmdir()
    sign(args, "--detach-sign", "--armor", "--output", str(out / "repodata/repomd.xml.asc"),
         str(out / "repodata/repomd.xml"))
    return [line for _, line in lazy]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=["apt", "rpm"])
    parser.add_argument("out")
    parser.add_argument("--homedir", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--valid", type=int, default=7 * 86400)
    parser.add_argument("--date-offset", type=int, default=0)
    parser.add_argument("--simple-names", action="store_true")
    parser.add_argument("--deb", action="append", default=[])
    parser.add_argument("--lazy-deb", action="append", default=[])
    parser.add_argument("--rpm", action="append", default=[])
    parser.add_argument("--lazy-rpm", action="append", default=[])
    args = parser.parse_args()
    out = pathlib.Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    lazy = build_apt(args, out) if args.kind == "apt" else build_rpm(args, out)
    pathlib.Path(str(out) + ".lazy.tsv").write_text("".join(lazy))
    print(f"built {args.kind} generation {out} lazy={len(lazy)}")


if __name__ == "__main__":
    main()
