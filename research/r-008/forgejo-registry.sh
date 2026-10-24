#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Phase 3 (inside pakomichi-r008-forgejo): start Forgejo on 127.0.0.1:3300,
# create lab-only users and tokens (secrets stay in the ignored secrets dir),
# run forgejo-registry.py, stop the server and collect evidence.
set -euo pipefail
export LC_ALL=C
REPO=/mnt/d/Projects/pakomichi
SEC=$REPO/.research-local/r-008/secrets
STAMP=${R008_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}
OUT=$REPO/.research-local/r-008/forgejo-$STAMP
mkdir -p "$SEC" "$OUT" /tmp/r008
FJ="su forgejo -s /bin/bash -c"
CFG="--config /etc/forgejo/app.ini --work-path /var/lib/forgejo"

# fresh state on every run
rm -rf /var/lib/forgejo/* "$SEC"/forgejo-*
$FJ "cd /var/lib/forgejo && exec forgejo web $CFG" >/tmp/r008/server.log 2>&1 &
SERVER=$!
for i in $(seq 1 60); do
  curl -fs http://127.0.0.1:3300/api/healthz >/dev/null 2>&1 && break
  sleep 1
done
curl -fs http://127.0.0.1:3300/api/healthz | head -c 200; echo

mkuser() { # name adminflag secretfile tokenfile
  local name=$1 flag=$2 pwf=$3 tokf=$4
  $FJ "forgejo admin user create $CFG --username $name --email $name@example.invalid --random-password --random-password-length 32 --must-change-password=false $flag" >"$pwf.raw" 2>&1 || { echo "user create failed for $name"; sed 's/.*password.*/[redacted]/I' "$pwf.raw"; exit 1; }
  grep -io "password[^']*'[^']*'" "$pwf.raw" | sed "s/.*'\(.*\)'/\1/" >"$pwf"; rm -f "$pwf.raw"
  $FJ "forgejo admin user generate-access-token $CFG --username $name --scopes all --raw" >"$tokf"
}
if [ ! -s "$SEC/forgejo-token" ]; then
  mkuser lab --admin "$SEC/forgejo-admin" "$SEC/forgejo-token"
  mkuser other "" "$SEC/forgejo-other-pw" "$SEC/forgejo-token-other"
fi
echo "secrets: $(wc -c <"$SEC/forgejo-token") bytes token, admin pw file $(wc -c <"$SEC/forgejo-admin") bytes"

set +e
python3 -I "$REPO/research/r-008/forgejo-registry.py" "$OUT"
RC=$?
set -e

kill "$SERVER" 2>/dev/null || true
pkill -u forgejo -f "forgejo web" 2>/dev/null || true
sleep 2
cp /tmp/r008/server.log "$OUT/server.log"
grep -viE 'SECRET|TOKEN|PASSWORD|JWT' /etc/forgejo/app.ini >"$OUT/app.ini"
cp /tmp/r008/gpg-status.txt /tmp/r008/gpg-verify.txt "$OUT/" 2>/dev/null || true
cp "$REPO/research/r-008/forgejo.lock.json" "$OUT/"
cp "$OUT/forgejo-registry.tsv" "$REPO/research/r-008/forgejo-registry.tsv" 2>/dev/null || true
echo "python rc=$RC out=$OUT"
