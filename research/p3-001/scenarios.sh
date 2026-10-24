#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P3-001 acceptance on one APT target: generations built, signed, and
# checked by the production APT publisher (publish_apt), served by the
# production reader, consumed by the native APT client with Signed-By and
# without trusted=yes.
#   A1  publish, update, install; apt-cache policy shows o=Pakomichi,l=<label>
#   A2  every index is fetched by hash; no plain index path is requested
#   A3  N-012: a changed byte in InRelease is refused; the lists stay
#   A4  a changed Packages is refused (hash mismatch); the lists stay
#   A5  a changed .deb is refused on download; nothing is installed
#   A6  a source whose Signed-By is another key is refused
#   A7  R-004 G9 at the publisher: another signing key never becomes current
#   A8  a stale confirmation is not signed again; current stays
#   A9  R-004 G5: a package of the superseded generation after the switch,
#       then the ordinary `apt upgrade`
#   A10 R-004 G2: generation switch between InRelease and its index
#   A11 Valid-Until is the confirmed freshness: APT refuses after it
#   A12 N-033: a replayed older InRelease does not replace the newer one
# Run as root inside the target after prepare.sh.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p3001/lib.sh

mkdir -p "$OUT"
: >"$OUT/results.tsv"
{ grep PRETTY_NAME /etc/os-release; uname -r; apt-get --version | head -1
  command -v sqv >/dev/null && sqv --version 2>/dev/null | head -1
  command -v gpgv >/dev/null && gpgv --version | head -1
  sha256sum /usr/local/bin/pakomichi-reader /usr/local/bin/p3001-publish
} >"$OUT/environment.txt" 2>&1

start_proxy() {
    rm -f "$GATE" "$PROXY_LOG" "$CONTROL"
    systemctl stop p3001-proxy.service 2>/dev/null || true
    systemctl reset-failed p3001-proxy.service 2>/dev/null || true
    systemd-run --quiet --unit=p3001-proxy python3 -I /opt/p3001/tamper-proxy.py 18081 18080 \
        "$CONTROL" "$GATE" "$PROXY_LOG"
    for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/18081) 2>/dev/null && return 0; sleep 0.1; done
    return 1
}

dpkg -P "$NAME" >/dev/null 2>&1
start_proxy || { echo "proxy did not start" >&2; exit 1; }
grep -q 'trusted=yes\|Trusted: yes' "$SOURCES" 2>/dev/null && { echo "trusted=yes found" >&2; exit 1; }

# ---------------------------------------------------------------- A1
client_setup "$READER"; client_clean
g1=$(publish 1.0 2>"$OUT/A1.publish.log")
client_update >"$OUT/A1.log" 2>&1; urc=$?
apt_only -y install "$NAME" >>"$OUT/A1.log" 2>&1; irc=$?
{ apt-cache -o Dir::Etc::sourcelist="$SOURCES" -o Dir::Etc::sourceparts=- policy
  apt-cache policy "$NAME"; } >"$OUT/A1.policy" 2>&1
warnings=$(grep -cE '^(W|E|Err):' "$OUT/A1.log")
grep -q "o=Pakomichi" "$OUT/A1.policy" && grep -q "l=$LABEL" "$OUT/A1.policy"; pol=$?
! grep -qi 'trusted' "$SOURCES"; trusted=$?
[[ -n $g1 && $urc -eq 0 && $irc -eq 0 && $warnings -eq 0 && $(installed_version) == 1.0 && $pol -eq 0 && $trusted -eq 0 ]]
expect A1 $? "generation $g1; update rc=$urc install rc=$irc warnings=$warnings version=$(installed_version); policy o=/l= rc=$pol; Signed-By only"

# ---------------------------------------------------------------- A2
client_setup "$PROXY"; client_clean; : >"$PROXY_LOG"
client_update >"$OUT/A2.log" 2>&1; rc=$?
cp "$PROXY_LOG" "$OUT/A2.requests"
by_hash=$(grep -c '/by-hash/SHA256/' "$OUT/A2.requests")
plain=$(grep -cE 'binary-amd64/Packages(\.(gz|xz))? ' "$OUT/A2.requests")
[[ $rc -eq 0 && $by_hash -ge 1 && $plain -eq 0 ]]
expect A2 $? "update rc=$rc; by-hash requests=$by_hash; plain index requests=$plain"

# ---------------------------------------------------------------- A3
held=$(held_inrelease)
set_control '{"rules": [{"match": "/InRelease", "from": "Components: main", "to": "Components: mbin"}]}'
client_update >"$OUT/A3.log" 2>&1; rc=$?
set_control '{}'
sig=$(grep -ciE 'BADSIG|signatures were invalid|not signed|NOSPLIT|signature' "$OUT/A3.log")
[[ $sig -ge 1 && $(held_inrelease) == "$held" ]] && grep -q 'action=replaced' "$PROXY_LOG"
expect A3 $? "tampered InRelease: update rc=$rc, signature errors=$sig, client keeps the previous InRelease"

# ---------------------------------------------------------------- A4
client_clean
set_control '{"rules": [{"match": "/by-hash/SHA256/", "from": "Description:", "to": "Descriptiom:"}]}'
client_update >"$OUT/A4.log" 2>&1; rc=$?
set_control '{}'
mismatch=$(grep -ciE 'Hash Sum mismatch|unexpected size|Hashes of expected file' "$OUT/A4.log")
[[ $mismatch -ge 1 ]] && ! ls /var/lib/apt/lists/*127.0.0.1:18081*Packages* >/dev/null 2>&1
expect A4 $? "tampered Packages: update rc=$rc, mismatch errors=$mismatch, no index stored"

# ---------------------------------------------------------------- A5
client_clean; client_update >/dev/null 2>&1
set_control '{"rules": [{"match": ".deb", "from": "debian-binary", "to": "debian-binarz"}]}'
apt_only -y install --reinstall "$NAME" >"$OUT/A5.log" 2>&1; rc=$?
set_control '{}'
mismatch=$(grep -ciE 'Hash Sum mismatch|Hashes of expected file|unexpected size' "$OUT/A5.log")
[[ $rc -ne 0 && $mismatch -ge 1 && $(installed_version) == 1.0 ]]
expect A5 $? "tampered .deb: install rc=$rc, mismatch errors=$mismatch, installed $(installed_version)"

# ---------------------------------------------------------------- A6
client_setup "$READER" "$OTHER_KEYRING"; client_clean
client_update >"$OUT/A6.log" 2>&1; rc=$?
nokey=$(grep -ciE 'NO_PUBKEY|not signed|Missing key|signatures couldn.t be verified|signature' "$OUT/A6.log")
[[ $nokey -ge 1 && -z $(held_inrelease) ]]
expect A6 $? "Signed-By another key: update rc=$rc, key errors=$nokey, no InRelease stored"
client_setup "$READER"

# ---------------------------------------------------------------- A7
before=$(current)
publish --signer-home "$OTHER_SIGNER" 1.0 2.0 >"$OUT/A7.log" 2>&1; rc=$?
[[ $rc -eq 2 && $(current) == "$before" ]] && grep -q 'E_SNAPSHOT_INCONSISTENT' "$OUT/A7.log"
expect A7 $? "signer with another key: publish rc=$rc, current $before -> $(current)"

# ---------------------------------------------------------------- A8
before=$(current)
publish --confirmed-ago 691200 1.0 2.0 >"$OUT/A8.log" 2>&1; rc=$?
[[ $rc -eq 2 && $(current) == "$before" ]] && grep -q 'E_SOURCE_STALE' "$OUT/A8.log"
expect A8 $? "confirmation 8 days old: publish rc=$rc, current $before -> $(current)"

# ---------------------------------------------------------------- A9
client_clean; client_update >"$OUT/A9.log" 2>&1
g2=$(publish 2.0 2>>"$OUT/A9.log")
# The client still holds g1's lists: the g1 package must still be served.
apt_only -y install --reinstall "$NAME=1.0" >>"$OUT/A9.log" 2>&1; old=$?
client_update >>"$OUT/A9.log" 2>&1
apt -q -o Dir::Etc::sourcelist="$SOURCES" -o Dir::Etc::sourceparts=- -y upgrade >>"$OUT/A9.log" 2>&1; up=$?
[[ -n $g2 && $old -eq 0 && $up -eq 0 && $(installed_version) == 2.0 ]]
expect A9 $? "g1 package after the switch to $g2: rc=$old; apt upgrade rc=$up -> $(installed_version)"

# ---------------------------------------------------------------- A10
client_setup "$PROXY"; client_clean; rm -f "$GATE"; : >"$PROXY_LOG"
set_control '{"hold": "/binary-amd64/"}'
client_update >"$OUT/A10.log" 2>&1 & cpid=$!
for _ in $(seq 600); do grep -q 'event=hold' "$PROXY_LOG" && break; sleep 0.1; done
holds=$(grep -c 'event=hold' "$PROXY_LOG")
g3=$(publish 2.0 3.0 2>>"$OUT/A10.log")
touch "$GATE"; wait "$cpid"; rc=$?
set_control '{}'; rm -f "$GATE"
cp "$PROXY_LOG" "$OUT/A10.requests"
lists_consistent; consistent=$?
[[ $holds -ge 1 && $rc -eq 0 && $consistent -eq 0 && -n $g3 ]]
expect A10 $? "switch to $g3 while the index was held ($holds): update rc=$rc, lists consistent rc=$consistent"
client_setup "$READER"

# ---------------------------------------------------------------- A11
# Confirmed freshness ends 40 s from now; APT must refuse after it.
g4=$(publish --confirmed-ago 604760 3.0 2>"$OUT/A11.log")
client_clean; client_update >>"$OUT/A11.log" 2>&1; before=$?
sleep 45
client_clean; client_update >>"$OUT/A11.log" 2>&1; after=$?
expired=$(grep -ciE 'is expired|expired \(invalid since' "$OUT/A11.log")
publish --confirmed-ago 604815 3.0 >>"$OUT/A11.log" 2>&1; again=$?
g5=$(publish 3.0 4.0 2>>"$OUT/A11.log")
client_clean; client_update >>"$OUT/A11.log" 2>&1; fresh=$?
[[ -n $g4 && $before -eq 0 && $expired -ge 1 && $again -eq 2 && -n $g5 && $fresh -eq 0 ]]
expect A11 $? "valid 40 s: update rc=$before, after expiry errors=$expired; re-sign stale rc=$again; fresh $g5 rc=$fresh"

# ---------------------------------------------------------------- A12
client_setup "$PROXY"; client_clean
old_inrelease=$(mktemp)
curl -s "http://$READER/$LABEL/dists/$LABEL/InRelease" -o "$old_inrelease"
g6=$(publish 4.0 2>"$OUT/A12.log")
client_update >>"$OUT/A12.log" 2>&1
newer=$(held_inrelease)
set_control "{\"rules\": [{\"match\": \"/InRelease\", \"file\": \"$old_inrelease\"}]}"
client_update >>"$OUT/A12.log" 2>&1; rc=$?
set_control '{}'
apt-cache policy "$NAME" >"$OUT/A12.policy" 2>&1
[[ -n $g6 && $(held_inrelease) == "$newer" ]] && grep -q 'action=file' "$PROXY_LOG"
expect A12 $? "older InRelease replayed after $g6: update rc=$rc, client keeps the newer one"
rm -f "$old_inrelease"
client_setup "$READER"

systemctl stop p3001-proxy.service 2>/dev/null || true
for home in "$SIGNER" "$OTHER_SIGNER"; do
    runuser -u pakomichi -- gpgconf --homedir "$home" --kill all 2>/dev/null || true
done
cp -r "$PUBLISH/repos" "$OUT/repos" 2>/dev/null || true
fails=$(grep -c $'\tFAIL\t' "$OUT/results.tsv")
echo "P3-001 $(hostname): $(grep -c $'\tPASS\t' "$OUT/results.tsv") PASS, $fails FAIL"
[[ $fails -eq 0 ]]
