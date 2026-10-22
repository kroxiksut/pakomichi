#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Prepare and execute the R-005 Phase B verification manifest."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable


PLAN_FIELDS = [
    "repository",
    "repository_id",
    "selection_sources",
    "tag",
    "release_id",
    "asset_name",
    "asset_url",
    "api_digest",
    "claimed_level",
    "method",
    "checksum_url",
    "signature_url",
    "certificate_url",
    "key_url",
    "identity",
    "issuer",
    "key_source_url",
    "notes",
]
RESULT_FIELDS = [
    "repository",
    "repository_id",
    "tag",
    "asset_name",
    "method",
    "sha256",
    "digest_match",
    "rpm_signature_state",
    "verified_level",
    "exit_code",
    "failure_reason",
    "log",
]
METHODS = {
    "strict-release",
    "github-attestation",
    "cosign-checksums",
    "openpgp-checksums",
    "openpgp-checksums-unbound",
    "openpgp-asset-unbound",
    "minisign-checksums",
    "rpm-signature",
    "checksums-only",
    "none-observed",
    "unresolved",
}
ARCH_PREFERENCE = ("x86_64", "amd64", "all", "noarch", "aarch64", "arm64")
HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
SYNTHETIC_WSL_NETWORK = ipaddress.ip_network("198.18.0.0/15")


def load_token(token_file: Path | None) -> str | None:
    for name in ("PAKOMICHI_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    if token_file is None or not token_file.exists():
        return None
    is_wsl_drvfs = sys.platform == "linux" and str(token_file.resolve()).startswith("/mnt/")
    if os.name != "nt" and not is_wsl_drvfs and token_file.stat().st_mode & 0o077:
        raise RuntimeError(f"token file permissions are too broad: {token_file}")
    value = token_file.read_text(encoding="utf-8").strip()
    return value or None


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def write_tsv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})
    os.replace(temporary, path)


def preferred_assets(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for suffix in (".deb", ".rpm"):
        matching = [item for item in packages if str(item.get("name", "")).casefold().endswith(suffix)]
        if not matching:
            continue

        def key(item: dict[str, Any]) -> tuple[int, str]:
            name = str(item.get("name", "")).casefold()
            rank = next((index for index, arch in enumerate(ARCH_PREFERENCE) if arch in name), len(ARCH_PREFERENCE))
            return rank, name

        selected.append(sorted(matching, key=key)[0])
    return selected


def prepare(args: argparse.Namespace) -> int:
    if args.output.exists() and not args.force:
        raise RuntimeError(f"refusing to overwrite an existing verification plan: {args.output}")
    rows: list[dict[str, Any]] = []
    for sample in read_tsv(args.sample):
        packages = json.loads(sample["packages"])
        for asset in preferred_assets(packages):
            rows.append(
                {
                    "repository": sample["repository"],
                    "repository_id": sample["repository_id"],
                    "selection_sources": sample["selection_sources"],
                    "tag": sample["tag"],
                    "release_id": sample["release_id"],
                    "asset_name": asset["name"],
                    "asset_url": asset["browser_download_url"],
                    "api_digest": asset.get("digest") or "",
                    "claimed_level": sample["claimed_level"],
                    "method": "unresolved",
                    "checksum_url": "",
                    "signature_url": "",
                    "certificate_url": "",
                    "key_url": "",
                    "identity": "",
                    "issuer": "",
                    "key_source_url": "",
                    "notes": "",
                }
            )
    write_tsv(args.output, PLAN_FIELDS, rows)
    print(f"prepared {len(rows)} asset rows from {len({row['repository'] for row in rows})} repositories")
    return 0


def validate_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError(f"refusing non-HTTPS or credential-bearing URL: {url}")
    if parsed.port not in (None, 443):
        raise RuntimeError(f"refusing non-HTTPS port: {url}")
    for result in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM):
        address = ipaddress.ip_address(result[4][0])
        synthetic_wsl_dns = (
            os.environ.get("PAKOMICHI_WSL_SYNTHETIC_DNS") == "1"
            and address.version == 4
            and address in SYNTHETIC_WSL_NETWORK
        )
        if synthetic_wsl_dns:
            continue
        if not address.is_global:
            raise RuntimeError(f"refusing non-global address for {parsed.hostname}: {address}")


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # noqa: ANN001
        validate_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download(url: str, destination: Path, maximum: int = 2 * 1024 * 1024 * 1024) -> str:
    validate_url(url)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    request = urllib.request.Request(url, headers={"User-Agent": "Pakomichi-R-005-research"})
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".part")
    digest = hashlib.sha256()
    total = 0
    try:
        with opener.open(request, timeout=60) as response, temporary.open("wb") as output:
            length = int(response.headers.get("Content-Length", "0") or 0)
            if length > maximum:
                raise RuntimeError(f"download is too large ({length} bytes): {url}")
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise RuntimeError(f"download exceeded {maximum} bytes: {url}")
                digest.update(block)
                output.write(block)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return digest.hexdigest()


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:160]


def expected_digest(value: str) -> str | None:
    if not value:
        return None
    algorithm, separator, digest = value.partition(":")
    if separator and algorithm.casefold() == "sha256" and HEX_SHA256.fullmatch(digest):
        return digest.casefold()
    raise RuntimeError(f"unsupported API digest: {value}")


def checksum_for_asset(checksum_path: Path, asset_name: str) -> str | None:
    result = None
    for line in checksum_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        gnu = re.match(r"^([0-9A-Fa-f]{64})\s+[ *](.+)$", stripped)
        bsd = re.match(r"^SHA256 \((.+)\) = ([0-9A-Fa-f]{64})$", stripped)
        if gnu:
            digest, name = gnu.group(1), gnu.group(2)
        elif bsd:
            name, digest = bsd.group(1), bsd.group(2)
        else:
            continue
        if Path(name).name == asset_name:
            if result is not None and result.casefold() != digest.casefold():
                raise RuntimeError(f"conflicting checksums for {asset_name}")
            result = digest.casefold()
    return result


def run_completed(
    arguments: list[str], log_lines: list[str], *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(arguments[0])
    if executable is None:
        raise RuntimeError(f"required verifier is not installed: {arguments[0]}")
    shown = [executable, *arguments[1:]]
    log_lines.append("$ " + " ".join(shown))
    completed = subprocess.run(
        shown,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    log_lines.append(f"exit={completed.returncode}")
    log_lines.append(completed.stdout)
    log_lines.append(completed.stderr)
    return completed


def run_command(arguments: list[str], log_lines: list[str], *, env: dict[str, str] | None = None) -> int:
    return run_completed(arguments, log_lines, env=env).returncode


def attestation_not_found(completed: subprocess.CompletedProcess[str]) -> bool:
    output = completed.stdout + completed.stderr
    return completed.returncode != 0 and "HTTP 404: Not Found" in output and "/attestations/sha256:" in output


def inspect_unbound_openpgp(signature: Path, signed: Path, log: list[str]) -> None:
    completed = run_completed(
        ["gpg", "--batch", "--status-fd=1", "--verify", str(signature), str(signed)],
        log,
    )
    if completed.returncode == 0:
        raise RuntimeError("signature unexpectedly verified without the plan's project-published identity")
    if "[GNUPG:] NO_PUBKEY " not in completed.stdout or "[GNUPG:] ERRSIG " not in completed.stdout:
        raise RuntimeError("OpenPGP signature was not a well-formed unbound signature")
    log.append("classification=no-project-published-key; signature is not provenance evidence")


def inspect_rpm_signature(package: Path, work: Path, log: list[str]) -> str:
    rpmdb = work / "rpmdb-inspection"
    rpmdb.mkdir()
    completed = run_completed(
        ["rpmkeys", "--dbpath", str(rpmdb), "--checksig", "--verbose", str(package)],
        log,
    )
    output = completed.stdout + completed.stderr
    if re.search(r"\bBAD\b", output, re.I):
        return "bad"
    if re.search(r"(?:OpenPGP|RSA|DSA).*\b(?:NOKEY|NOTTRUSTED)\b", output, re.I):
        return "present-untrusted"
    if re.search(r"(?:OpenPGP|RSA|DSA).*\bOK\b", output, re.I):
        return "valid-with-inspection-keyring"
    if re.search(r"(?:OpenPGP|RSA|DSA).*signature", output, re.I):
        return "present-unverified"
    return "none-observed"


def normalized_fingerprint(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value).upper()


def openpgp_fingerprints(key: Path, home: Path, log: list[str]) -> list[str]:
    completed = subprocess.run(
        ["gpg", "--batch", "--homedir", str(home), "--with-colons", "--import-options", "show-only", "--import", str(key)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    log.extend(["$ gpg --import-options show-only <key>", f"exit={completed.returncode}", completed.stderr])
    if completed.returncode != 0:
        return []
    return [line.split(":")[9].upper() for line in completed.stdout.splitlines() if line.startswith("fpr:")]


def verify_row(
    row: dict[str, str], downloads: Path, run_dir: Path, gh_environment: dict[str, str]
) -> dict[str, Any]:
    method = row["method"]
    if method not in METHODS:
        raise RuntimeError(f"unknown method {method!r}")
    if method == "unresolved":
        raise RuntimeError("verification plan still contains unresolved rows")

    prefix = safe_component(f"{row['repository']}-{row['tag']}-{row['asset_name']}")
    asset_path = downloads / prefix / Path(row["asset_name"]).name
    digest = download(row["asset_url"], asset_path)
    expected = expected_digest(row["api_digest"])
    digest_match = None if expected is None else digest == expected
    log: list[str] = [f"repository={row['repository']}", f"asset={row['asset_name']}", f"sha256={digest}"]
    if digest_match is False:
        raise RuntimeError(f"asset digest mismatch for {row['repository']} {row['asset_name']}")

    exit_code = 0
    verified_level = "Nothing-observed"
    rpm_signature_state = "not-rpm"
    with tempfile.TemporaryDirectory(prefix="pakomichi-r005-") as temporary:
        work = Path(temporary)
        if row["asset_name"].casefold().endswith(".rpm"):
            rpm_signature_state = inspect_rpm_signature(asset_path, work, log)
        if method == "strict-release":
            release_check = run_completed(
                ["gh", "release", "verify", row["tag"], "--repo", row["repository"]],
                log,
                env=gh_environment,
            )
            asset_check = run_completed(
                ["gh", "release", "verify-asset", row["tag"], str(asset_path), "--repo", row["repository"]],
                log,
                env=gh_environment,
            )
            if release_check.returncode == 0 and asset_check.returncode == 0:
                verified_level = "Strict"
            elif asset_check.returncode == 0:
                verified_level = "Attested"
            elif attestation_not_found(asset_check):
                verified_level = "Nothing-observed"
            else:
                exit_code = asset_check.returncode or release_check.returncode or 1
                verified_level = "Unverified"
        elif method == "github-attestation":
            completed = run_completed(
                ["gh", "attestation", "verify", str(asset_path), "--repo", row["repository"]],
                log,
                env=gh_environment,
            )
            if completed.returncode == 0:
                verified_level = "Attested"
            elif attestation_not_found(completed):
                verified_level = "Nothing-observed"
            else:
                exit_code = completed.returncode or 1
                verified_level = "Unverified"
        elif method in {
            "cosign-checksums", "openpgp-checksums", "openpgp-checksums-unbound",
            "minisign-checksums", "checksums-only",
        }:
            if not row["checksum_url"]:
                raise RuntimeError(f"{method} requires checksum_url")
            checksum_path = work / "checksums.txt"
            download(row["checksum_url"], checksum_path, maximum=50 * 1024 * 1024)
            listed = checksum_for_asset(checksum_path, row["asset_name"])
            if listed is None or listed != digest:
                raise RuntimeError(f"signed checksum file does not bind {row['asset_name']} to downloaded bytes")
            if method == "checksums-only":
                verified_level = "Checksums-only"
            elif method == "openpgp-checksums-unbound":
                if not row["signature_url"] or not row["notes"]:
                    raise RuntimeError("openpgp-checksums-unbound requires signature_url and review notes")
                signature_path = work / "signature"
                download(row["signature_url"], signature_path, maximum=50 * 1024 * 1024)
                inspect_unbound_openpgp(signature_path, checksum_path, log)
                verified_level = "Nothing-observed"
            else:
                if not row["signature_url"] or not row["identity"] or not row["key_source_url"]:
                    raise RuntimeError(f"{method} requires signature_url, identity, and key_source_url")
                signature_path = work / "signature"
                download(row["signature_url"], signature_path, maximum=50 * 1024 * 1024)
                if method == "cosign-checksums":
                    command = ["cosign", "verify-blob", "--certificate-identity", row["identity"]]
                    if row["issuer"]:
                        command += ["--certificate-oidc-issuer", row["issuer"]]
                    if row["certificate_url"]:
                        certificate_path = work / "certificate"
                        download(row["certificate_url"], certificate_path, maximum=10 * 1024 * 1024)
                        command += ["--signature", str(signature_path), "--certificate", str(certificate_path)]
                    else:
                        command += ["--bundle", str(signature_path)]
                    command.append(str(checksum_path))
                    exit_code = run_command(command, log)
                elif method == "openpgp-checksums":
                    if not row["key_url"]:
                        raise RuntimeError("openpgp-checksums requires key_url")
                    key_path = work / "publisher-key"
                    download(row["key_url"], key_path, maximum=10 * 1024 * 1024)
                    home = work / "gnupg"
                    home.mkdir(mode=0o700)
                    fingerprints = openpgp_fingerprints(key_path, home, log)
                    identity = normalized_fingerprint(row["identity"])
                    if identity not in fingerprints:
                        raise RuntimeError(f"published OpenPGP key does not match pinned fingerprint {identity}")
                    exit_code |= run_command(["gpg", "--batch", "--homedir", str(home), "--import", str(key_path)], log)
                    exit_code |= run_command(
                        ["gpg", "--batch", "--homedir", str(home), "--verify", str(signature_path), str(checksum_path)],
                        log,
                    )
                else:
                    if not row["key_url"]:
                        raise RuntimeError("minisign-checksums requires key_url")
                    key_path = work / "publisher-key"
                    download(row["key_url"], key_path, maximum=1024 * 1024)
                    public_keys = [line.strip() for line in key_path.read_text(encoding="utf-8").splitlines() if line and not line.startswith("untrusted comment:")]
                    if row["identity"] not in public_keys:
                        raise RuntimeError("published minisign key does not match pinned identity")
                    exit_code = run_command(
                        ["minisign", "-Vm", str(checksum_path), "-x", str(signature_path), "-P", row["identity"]],
                        log,
                    )
                verified_level = "Signed" if exit_code == 0 else "Unverified"
        elif method == "openpgp-asset-unbound":
            if not row["signature_url"] or not row["notes"]:
                raise RuntimeError("openpgp-asset-unbound requires signature_url and review notes")
            signature_path = work / "signature"
            download(row["signature_url"], signature_path, maximum=50 * 1024 * 1024)
            inspect_unbound_openpgp(signature_path, asset_path, log)
            verified_level = "Nothing-observed"
        elif method == "rpm-signature":
            if not row["asset_name"].casefold().endswith(".rpm"):
                raise RuntimeError("rpm-signature method requires an RPM asset")
            if not row["key_url"] or not row["identity"] or not row["key_source_url"]:
                raise RuntimeError("rpm-signature requires key_url, identity, and key_source_url")
            key_path = work / "publisher-key"
            download(row["key_url"], key_path, maximum=10 * 1024 * 1024)
            home = work / "gnupg"
            home.mkdir(mode=0o700)
            fingerprints = openpgp_fingerprints(key_path, home, log)
            identity = normalized_fingerprint(row["identity"])
            if identity not in fingerprints:
                raise RuntimeError(f"published RPM key does not match pinned fingerprint {identity}")
            rpmdb = work / "rpmdb"
            rpmdb.mkdir()
            exit_code |= run_command(["rpmkeys", "--dbpath", str(rpmdb), "--import", str(key_path)], log)
            exit_code |= run_command(["rpmkeys", "--dbpath", str(rpmdb), "--checksig", str(asset_path)], log)
            verified_level = "Signed" if exit_code == 0 else "Unverified"
        elif method == "none-observed":
            verified_level = "Nothing-observed"

    log_path = run_dir / f"{prefix}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("\n".join(log), encoding="utf-8", newline="\n")
    return {
        "repository": row["repository"],
        "repository_id": row["repository_id"],
        "tag": row["tag"],
        "asset_name": row["asset_name"],
        "method": method,
        "sha256": digest,
        "digest_match": "unknown" if digest_match is None else str(digest_match).lower(),
        "rpm_signature_state": rpm_signature_state,
        "verified_level": verified_level,
        "exit_code": exit_code,
        "failure_reason": "",
        "log": log_path.name,
    }


def failure_reason(error: BaseException) -> str:
    """Return a stable public category; detailed diagnostics stay in ignored logs."""
    if isinstance(error, subprocess.TimeoutExpired):
        return "verifier-timeout"
    if isinstance(error, urllib.error.URLError):
        return "download-error"
    if isinstance(error, subprocess.SubprocessError):
        return "verifier-error"
    if isinstance(error, OSError):
        return "io-error"
    if isinstance(error, (ValueError, json.JSONDecodeError)):
        return "data-error"
    return "plan-or-verification-error"


def verify(args: argparse.Namespace) -> int:
    rows = read_tsv(args.plan)
    missing = [field for field in PLAN_FIELDS if rows and field not in rows[0]]
    if missing:
        raise RuntimeError(f"verification plan lacks fields: {', '.join(missing)}")
    results = []
    failures = 0
    token = load_token(args.token_file)
    gh_environment = os.environ.copy()
    if token:
        gh_environment["GH_TOKEN"] = token
    for row in rows:
        try:
            result = verify_row(row, args.downloads, args.run_dir, gh_environment)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            failures += 1
            prefix = safe_component(
                f"{row.get('repository', 'unknown')}-{row.get('tag', 'unknown')}-{row.get('asset_name', 'unknown')}"
            )
            log_path = args.run_dir / f"{prefix}.failure.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(f"{type(error).__name__}: {error}\n", encoding="utf-8", newline="\n")
            result = {
                "repository": row.get("repository", ""),
                "repository_id": row.get("repository_id", ""),
                "tag": row.get("tag", ""),
                "asset_name": row.get("asset_name", ""),
                "method": row.get("method", ""),
                "sha256": "",
                "digest_match": "false",
                "rpm_signature_state": "not-checked",
                "verified_level": "Unverified",
                "exit_code": 1,
                "failure_reason": failure_reason(error),
                "log": log_path.name,
            }
        results.append(result)
        write_tsv(args.results, RESULT_FIELDS, results)
    print(f"verified {len(results) - failures}/{len(results)} asset rows; failures={failures}")
    return 0 if failures == 0 else 2


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    prepare_command = commands.add_parser("prepare")
    prepare_command.add_argument("--sample", type=Path, required=True)
    prepare_command.add_argument("--output", type=Path, required=True)
    prepare_command.add_argument("--force", action="store_true")
    prepare_command.set_defaults(function=prepare)

    verify_command = commands.add_parser("verify")
    verify_command.add_argument("--plan", type=Path, required=True)
    verify_command.add_argument("--downloads", type=Path, required=True)
    verify_command.add_argument("--run-dir", type=Path, required=True)
    verify_command.add_argument("--results", type=Path, required=True)
    verify_command.add_argument("--token-file", type=Path)
    verify_command.set_defaults(function=verify)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.function(args))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
