# SPDX-License-Identifier: MIT OR Apache-2.0
# R-008 phase B: how APT treats repository metadata without Valid-Until.
# Run as root inside a DISPOSABLE Debian 12 WSL distribution only:
#   wsl.exe -d pakomichi-r008-apt -u root --cd /tmp -- bash <this> <out-dir>
# It installs gnupg/apt-utils/python3, then REMOVES the Debian sources and
# points APT at a local TEST ONLY repository on 127.0.0.1:18180.
set -u
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
OUT=${1:-/root/r008-out}
PORT=18180
REPO=/srv/r008-repo
mkdir -p "$OUT"
rm -f "$OUT"/*.log "$OUT"/*.tsv
TSV="$OUT/apt-freshness.tsv"
printf 'case\tapt_options\texit_code\toutcome\tmessage\n' >"$TSV"

{
  apt-get update && apt-get install -y --no-install-recommends gnupg apt-utils python3
} >"$OUT/00-setup.log" 2>&1 || { echo "setup failed"; exit 1; }
{
  echo "debian_version: $(cat /etc/debian_version)"
  apt --version
  echo "Valid-Until-Max/Date-Max-Future strings in libapt-pkg:"
  grep -a -o -h -E 'Valid-Until-Max|Date-Max-Future|Max-ValidTime|Max-FutureTime' /usr/lib/x86_64-linux-gnu/libapt-pkg.so.* | sort -u
} >"$OUT/01-versions.log" 2>&1
mkdir -p /root/r008-disabled-sources
mv /etc/apt/sources.list.d/*.sources /root/r008-disabled-sources/ 2>/dev/null
[ -f /etc/apt/sources.list ] && mv /etc/apt/sources.list /root/r008-disabled-sources/
rm -rf /var/lib/apt/lists/*

# TEST ONLY signing key, no passphrase.
export GNUPGHOME=/root/r008-gnupg
rm -rf "$GNUPGHOME"; mkdir -m 700 "$GNUPGHOME"
gpg --batch --passphrase '' --pinentry-mode loopback \
  --quick-gen-key 'Pakomichi R-008 TEST ONLY <r008-test@invalid>' rsa3072 sign 1y >"$OUT/02-key.log" 2>&1
FPR=$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr/ {print $10; exit}')
echo "fingerprint: $FPR" >>"$OUT/02-key.log"
mkdir -p /etc/apt/keyrings
gpg --batch --export "$FPR" >/etc/apt/keyrings/r008-lab.gpg
chmod 644 /etc/apt/keyrings/r008-lab.gpg

# Dummy packages, versions 1 and 2.
for v in 1 2; do
  d=/root/r008-build/dummy-$v
  mkdir -p "$d/DEBIAN" "$REPO/pool/v$v"
  cat >"$d/DEBIAN/control" <<EOF
Package: dummy
Version: $v
Architecture: all
Maintainer: R-008 TEST ONLY <r008-test@invalid>
Description: R-008 freshness lab dummy package
EOF
  dpkg-deb --root-owner-group --build "$d" "$REPO/pool/v$v/dummy_${v}_all.deb" >>"$OUT/03-build.log" 2>&1
done

# mkrepo VERSION DATE-STRING: rebuild dists/lab with exactly that Date and no Valid-Until.
mkrepo() {
  local v=$1 date=$2
  rm -rf "$REPO/dists"; mkdir -p "$REPO/dists/lab/main/binary-amd64"
  (cd "$REPO" && apt-ftparchive packages "pool/v$v" >dists/lab/main/binary-amd64/Packages)
  apt-ftparchive -o APT::FTPArchive::Release::Origin=r008-lab \
    -o APT::FTPArchive::Release::Label=r008-lab -o APT::FTPArchive::Release::Suite=lab \
    -o APT::FTPArchive::Release::Codename=lab -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Architectures=amd64 release "$REPO/dists/lab" >/tmp/r008-Release
  grep -v -E '^(Date|Valid-Until):' /tmp/r008-Release | sed "1a Date: $date" >"$REPO/dists/lab/Release"
  gpg --batch --yes --local-user "$FPR" --clearsign -o "$REPO/dists/lab/InRelease" "$REPO/dists/lab/Release"
}

# sources EXTRA-LINE...: write lab.sources with optional extra fields.
sources() {
  {
    echo "Types: deb"
    echo "URIs: http://127.0.0.1:$PORT/"
    echo "Suites: lab"
    echo "Components: main"
    echo "Signed-By: /etc/apt/keyrings/r008-lab.gpg"
    for l in "$@"; do echo "$l"; done
  } >/etc/apt/sources.list.d/lab.sources
}

rfc() { date -u -d "$1" '+%a, %d %b %Y %H:%M:%S UTC'; }

# run CASE "OPTS-LABEL" APT-ARGS...
run() {
  local c=$1 label=$2; shift 2
  local log="$OUT/case-$c.log"
  {
    echo "### case $c; options: $label"
    echo "### lab.sources:"; cat /etc/apt/sources.list.d/lab.sources
    echo "### served Release:"; cat "$REPO/dists/lab/Release"
    echo "### apt-get update $*"
  } >"$log"
  apt-get update "$@" >>"$log" 2>&1
  local rc=$?
  local pol; pol=$(apt-cache policy dummy 2>&1)
  local cand; cand=$(printf '%s\n' "$pol" | awk '/Candidate:/ {print $2}')
  {
    echo "### exit code: $rc"
    echo "### apt-cache policy dummy:"; echo "$pol"
    echo "### stored InRelease Date:"; grep -h '^Date:' /var/lib/apt/lists/*lab_InRelease 2>/dev/null
  } >>"$log"
  echo "### http requests so far:" >>"$log"; cat "$OUT/http.log" >>"$log"
  : >"$OUT/http.log"
  local msg; msg=$(grep -E '^(E|W|Err):' "$log" | tr '\t' ' ' | paste -sd'|' -)
  local outcome
  local served stored
  served=$(grep -h '^Date:' "$REPO/dists/lab/Release")
  stored=$(grep -h '^Date:' /var/lib/apt/lists/*lab_InRelease 2>/dev/null)
  if [ "$rc" -ne 0 ]; then outcome=refused
  elif [ "$served" != "$stored" ]; then outcome=ignored_silently_kept_stored
  elif grep -q '^W:' "$log"; then outcome=accepted_with_warning
  else outcome=accepted; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$c" "$label" "$rc" "$outcome; candidate=${cand:-none}" "${msg:-none}" >>"$TSV"
}

fresh() { rm -rf /var/lib/apt/lists/*; }

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$REPO" >>"$OUT/http.log" 2>&1 &
HTTP=$!
trap 'kill $HTTP 2>/dev/null' EXIT
sleep 2

# 1: Date now, no Valid-Until.
sources; fresh; mkrepo 2 "$(rfc now)"; run 1-now "default"

# 2: rollback A (now, v2) -> B (3 days old, v1).
sources; fresh
mkrepo 2 "$(rfc now)"; run 2a-rollback-A-now-v2 "default"
# http.server answers If-Modified-Since with 1-second resolution: without
# this pause B can be written in the same second and get a 304 for A.
sleep 2
mkrepo 1 "$(rfc '-3 days')"; run 2b-rollback-B-3d-old-v1 "default"

# 3: freeze, Date 10 days old.
D10=$(rfc '-10 days')
sources; fresh; mkrepo 2 "$D10"; run 3a-10d-old "default"
fresh; run 3b-10d-old "-o Acquire::Max-ValidTime=604800" -o Acquire::Max-ValidTime=604800
sources "Valid-Until-Max: 604800"; fresh; run 3c-10d-old "sources Valid-Until-Max: 604800"
sources

# 4: OBS-style non-RFC date.
sources; fresh; mkrepo 2 "Mon Sep 14 16:13:08 2026"; run 4a-obs-date "default"
fresh; run 4b-obs-date "-o Acquire::Max-ValidTime=604800" -o Acquire::Max-ValidTime=604800

# 5: Date in the future (+2 days).
sources; fresh; mkrepo 2 "$(rfc '+2 days')"; run 5a-future-2d "default"
sources "Date-Max-Future: 259200"; fresh; run 5b-future-2d "sources Date-Max-Future: 259200"
sources; fresh; run 5c-future-2d "-o Acquire::Max-FutureTime=259200" -o Acquire::Max-FutureTime=259200
sources; fresh; run 5d-future-2d "-o Acquire::Check-Date=false" -o Acquire::Check-Date=false

echo done >"$OUT/99-done.log"
