#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# R-007 question 3: which Authenticode fields of the Win32-OpenSSH MSI stay
# stable across releases. Read-only and anonymous: downloads the x64 MSI of
# several releases, checks SHA-256 against the GitHub API asset digest,
# extracts the Authenticode signature with osslsigncode/openssl, compares the
# MSI hash with the WinGet manifest, writes a TSV and deletes the MSIs.
# Never installs or executes the MSIs.
#
# Run as root inside a disposable Linux environment (tested in a Fedora 44
# WSL distribution):
#   bash research/r-007/authenticode-stability.sh
# Environment: R007_RAW (raw output dir), R007_TSV (TSV path).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
raw="${R007_RAW:-$repo/.research-local/r-007/authenticode}"
tsv="${R007_TSV:-$here/authenticode-stability.tsv}"
ua="pakomichi-r007-research"
api="https://api.github.com/repositories/42125787/releases"
winget_dir="https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/m/Microsoft/OpenSSH/Preview"
winget_raw="https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/m/Microsoft/OpenSSH/Preview"

command -v osslsigncode >/dev/null || dnf -y -q install osslsigncode openssl
command -v openssl >/dev/null || dnf -y -q install openssl

mkdir -p "$raw"
work="$(mktemp -d /tmp/pakomichi-r007.XXXXXX)"
trap 'rm -rf "$work"' EXIT

{ osslsigncode --version 2>&1 | head -1; openssl version; date -u +%FT%TZ; } > "$raw/tool-versions.txt"

# 1. Release list (three pages to reach the oldest MSI release).
for page in 1 2 3; do
  curl -fsSL -A "$ua" -H 'Accept: application/vnd.github+json' \
    "$api?per_page=30&page=$page" -o "$raw/releases-page$page.json"
done

# 2. Select releases: newest, 10.0.0.0p2, first 9.8.x, first 9.5.x, oldest with an x64 MSI.
python3 -I - "$raw" > "$raw/selected.tsv" <<'PY'
import json, re, sys, os
raw = sys.argv[1]
rels = []
for p in (1, 2, 3):
    rels += json.load(open(os.path.join(raw, f"releases-page{p}.json")))
rels.sort(key=lambda r: r["published_at"] or "", reverse=True)
def msi(r):
    for a in r.get("assets", []):
        n = a["name"]
        if re.search(r"win64", n, re.I) and n.lower().endswith(".msi"):
            return a
    return None
withmsi = [(r, msi(r)) for r in rels if msi(r)]
picks = []
def add(pred):
    for r, a in withmsi:
        if pred(r["tag_name"]) and r["tag_name"] not in [p[0]["tag_name"] for p in picks]:
            picks.append((r, a)); return
add(lambda t: True)
add(lambda t: "10.0.0.0p2" in t)
add(lambda t: t.lstrip("v").startswith("9.8"))
add(lambda t: t.lstrip("v").startswith("9.5"))
r, a = withmsi[-1]
if r["tag_name"] not in [p[0]["tag_name"] for p in picks]:
    picks.append((r, a))
for r, a in picks:
    print("\t".join([r["tag_name"], r["published_at"], a["name"], a["browser_download_url"],
                     (a.get("digest") or "").removeprefix("sha256:")]))
PY

# 3. WinGet installer manifests: map InstallerUrl -> InstallerSha256.
curl -fsSL -A "$ua" "$winget_dir" -o "$raw/winget-versions.json"
python3 -I -c 'import json,sys; [print(e["name"]) for e in json.load(open(sys.argv[1])) if e["type"]=="dir"]' \
  "$raw/winget-versions.json" > "$work/winget-versions.txt"
: > "$raw/winget-url-sha.tsv"
while read -r v; do
  f="$raw/winget-$v.installer.yaml"
  curl -fsSL -A "$ua" "$winget_raw/$v/Microsoft.OpenSSH.Preview.installer.yaml" -o "$f" || continue
  awk -v ver="$v" '/InstallerUrl:/{u=$2} /InstallerSha256:/{print ver "\t" u "\t" tolower($2)}' "$f" >> "$raw/winget-url-sha.tsv"
done < "$work/winget-versions.txt"

# 4. Per release: download, hash, extract signature, delete MSI.
while IFS=$'\t' read -r tag published asset url digest; do
  d="$raw/$tag"; mkdir -p "$d"
  m="$work/$asset"
  curl -fsSL -A "$ua" "$url" -o "$m"
  sha="$(sha256sum "$m" | cut -d' ' -f1)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$tag" "$published" "$asset" "$url" "$digest" "$sha" > "$d/meta.tsv"
  osslsigncode verify -in "$m" > "$d/verify.txt" 2>&1 || true
  osslsigncode extract-signature -pem -in "$m" -out "$d/signature.pem" > "$d/extract.txt" 2>&1 || true
  openssl pkcs7 -in "$d/signature.pem" -print_certs -out "$d/certs.pem" 2>"$d/pkcs7.err" || true
  openssl pkcs7 -in "$d/signature.pem" -print -noout > "$d/pkcs7-print.txt" 2>&1 || true
  # Per-certificate details from the top-level certificate bag.
  rm -f "$d"/cert-*.pem
  awk -v dir="$d" '/BEGIN CERT/{n++} n{print > (dir "/cert-" n ".pem")}' "$d/certs.pem"
  : > "$d/certs.txt"
  for c in "$d"/cert-*.pem; do
    [ -e "$c" ] || continue
    openssl x509 -in "$c" -noout -nameopt RFC2253 -subject -issuer -serial \
      -fingerprint -sha1 -startdate -enddate >> "$d/certs.txt"
    openssl x509 -in "$c" -noout -text | grep -A1 'Basic Constraints' >> "$d/certs.txt" || true
    echo '--' >> "$d/certs.txt"
  done
  rm -f "$m"
done < "$raw/selected.tsv"

# 5. TSV (LF, UTF-8 without BOM) from the raw outputs.
python3 -I - "$raw" "$tsv" <<'PY'
import os, re, sys
raw, tsv = sys.argv[1], sys.argv[2]
win = {}
for line in open(os.path.join(raw, "winget-url-sha.tsv"), encoding="utf-8"):
    p = [x.strip() for x in line.split("\t")]
    if len(p) == 3:
        win[p[1]] = p[2]
cols = ["release_tag", "asset", "sha256", "api_digest_match", "signer_subject", "issuer", "root",
        "leaf_thumbprint", "leaf_not_before", "leaf_not_after", "signing_time",
        "timestamp_authority", "winget_sha256_match"]
rows = []
for tag, published, asset, url, digest in (l.rstrip("\n").split("\t") for l in open(os.path.join(raw, "selected.tsv"), encoding="utf-8")):
    meta = os.path.join(raw, tag, "meta.tsv")
    if not os.path.exists(meta):
        continue
    sha = open(meta, encoding="utf-8").read().rstrip("\n").split("\t")[5]
    v = open(os.path.join(raw, tag, "verify.txt"), encoding="utf-8", errors="replace").read()
    certs = open(os.path.join(raw, tag, "certs.txt"), encoding="utf-8").read().split("--\n")
    info = []
    for c in certs:
        d = dict(re.findall(r"^(subject|issuer|serial|sha1 Fingerprint|notBefore|notAfter)=(.*)$", c, re.M))
        if d:
            d["ca"] = "CA:TRUE" in c
            info.append(d)
    leaf = next(d for d in info if not d["ca"])
    inter = next((d for d in info if d["subject"] == leaf["issuer"]), None)
    m = re.search(r"Countersignatures:.*?Timestamp time: (.*?)\n", v, re.S)
    ts = re.search(r"Failed timestamp certificate chain.*?Subject: CN=([^,]*)", v, re.S) or \
         re.search(r"Timestamp verified using:.*?Subject: CN=([^,]*)", v, re.S)
    nsig = len(re.findall(r"^Signature Index:", v, re.M))
    def cn(s):
        return re.search(r"CN=([^,]*)", s).group(1)
    rows.append([tag, asset, sha,
                 ("yes" if digest == sha else "no") if digest else "no_api_digest",
                 leaf["subject"], cn(leaf["issuer"]),
                 cn(inter["issuer"]) if inter else "unknown",
                 leaf["sha1 Fingerprint"].replace(":", ""), leaf["notBefore"], leaf["notAfter"],
                 (m.group(1) if m else "none") + f" (signatures={nsig})",
                 ts.group(1) if ts else "none",
                 ("yes" if win[url] == sha else "no") if url in win else "no_manifest"])
with open(tsv, "w", encoding="utf-8", newline="\n") as f:
    f.write("\t".join(cols) + "\n")
    for r in rows:
        f.write("\t".join(r) + "\n")
PY
echo "tsv: $tsv"

echo "raw outputs: $raw"
