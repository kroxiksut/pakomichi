#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P3-005a acceptance on one target: the production reader (pakomichi-reader,
# socket-activated, unprivileged) serving generations published through the
# production GenerationStore, with the native APT or DNF client.
#   G1  publish, update, install
#   G2  switch between the signed top-level file and its indexes (PASS)
#   G3  control: without By-Hash (APT) / non-unique repodata names (RPM)
#   G4  control: retention window 0
#   G5  a package of a superseded generation after the switch (PASS)
#   G6  parallel clients while generations are published in a loop (PASS)
#   H1  N-025: no method but GET/HEAD; nothing changes
#   H2  Host check, traversal, request body
#   H3  N-017: a changed object is not served; the client fails closed
#   H4  the reader runs unprivileged and cannot write the stores
# Run as root inside the target after prepare.sh.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p3005a/lib.sh

mkdir -p "$OUT"
: >"$OUT/results.tsv"
{ grep PRETTY_NAME /etc/os-release; uname -r
  if [[ $FAMILY == apt ]]; then apt-get --version | head -1; else dnf --version | head -1; rpm --version; fi
  echo "backend=$BACKEND"; sha256sum /usr/local/bin/pakomichi-reader /usr/local/bin/p3005a-publish
} >"$OUT/environment.txt" 2>&1

sha_of() { sha256sum "$1" | cut -d' ' -f1; }
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 30 "$@"; }

start_proxy() {
    rm -f "$GATE" "$PROXY_LOG"
    systemctl stop p3005a-proxy.service 2>/dev/null || true
    systemctl reset-failed p3005a-proxy.service 2>/dev/null || true
    systemd-run --quiet --unit=p3005a-proxy python3 -I /opt/p3005a/hold-proxy.py 18081 18080 "$HOLD" "$GATE" "$PROXY_LOG"
    for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/18081) 2>/dev/null && return 0; sleep 0.1; done
    return 1
}

# switch_during_update OLD NEW [client args]: through the proxy, hold the
# index downloads after the signed top-level file, publish NEW, release.
switch_during_update() {
    local old=$1 new=$2 rc; shift 2
    client_clean; rm -f "$GATE"; : >"$PROXY_LOG"
    client_update "$@" >"$OUT/switch-$old-$new.log" 2>&1 & local cpid=$!
    for _ in $(seq 600); do grep -q 'event=hold' "$PROXY_LOG" 2>/dev/null && break; sleep 0.1; done
    grep -q 'event=hold' "$PROXY_LOG" || log "no hold seen for $old->$new"
    publish "$new" >/dev/null
    touch "$GATE"; wait "$cpid"; rc=$?
    rm -f "$GATE"
    cp "$PROXY_LOG" "$OUT/switch-$old-$new.requests"
    return $rc
}

reader_args
client_remove p3005a-sampleapp >/dev/null 2>&1
start_proxy || { echo "proxy did not start" >&2; exit 1; }
rc=0

# ---------------------------------------------------------------- G1
client_setup "$READER"; client_clean
gen g1 1.0
publish g1 >"$OUT/G1.log" 2>&1 && client_update >>"$OUT/G1.log" 2>&1 &&
    client_install p3005a-sampleapp >>"$OUT/G1.log" 2>&1
rc=$?; out=$(installed_version)
[[ $rc -eq 0 && $out == 1.0 ]]
expect G1 $? "publish g1 through GenerationStore, update, install: rc=$rc version=$out generation=$(current)"

# ---------------------------------------------------------------- G2
client_setup "$PROXY"
gen g2 2.0
switch_during_update g1 g2; rc=$?
held=$(client_metadata_digests); match=other
[[ $held == "$(gen_metadata_digest g1)" ]] && match=g1
[[ $held == "$(gen_metadata_digest g2)" ]] && match=g2
holds=$(grep -c 'event=hold' "$OUT/switch-g1-g2.requests")
statuses=$(grep -o 'status=[0-9-]*' "$OUT/switch-g1-g2.requests" | sort | uniq -c | tr -s ' ' | tr '\n' ' ')
[[ $rc -eq 0 && $match == g1 && $holds -gt 0 ]]
expect G2 $? "switch g1->g2 between the signed file and its indexes ($holds held): update rc=$rc, client holds $match metadata; responses: $statuses"

# ---------------------------------------------------------------- G3 (control)
if [[ $FAMILY == apt ]]; then
    gen g3 3.0; gen g4 1.0; publish g3 >/dev/null
    switch_during_update g3 g4 -o Acquire::By-Hash=no; rc=$?
    out=$(grep -m1 -iE 'hash sum mismatch|mismatch|unexpected size' "$OUT/switch-g3-g4.log")
    [[ $rc -ne 0 || -n $out ]]
    expect G3 $? "control, client without By-Hash: update rc=$rc; ${out:-no mismatch message} (a failure here is the expected outcome)"
else
    gen c1 1.0 -- --simple-names
    publish c1 >"$OUT/G3.log" 2>&1; rc=$?
    out=$(grep -m1 -o 'unclassified[^,]*\|path[^,]*' "$OUT/G3.log")
    [[ $rc -ne 0 ]]
    expect G3 $? "control, non-unique repodata names: the publisher refuses the generation (rc=$rc: ${out:-$(head -c 200 "$OUT/G3.log")}); current stays $(current)"
fi

# ---------------------------------------------------------------- G4 (control)
reader_args --retention-seconds 0
gen g5 2.0; gen g6 3.0; publish g5 >/dev/null
sleep 1
switch_during_update g5 g6; rc=$?
out=$(grep -m1 -iE '404|not found|mismatch|failed' "$OUT/switch-g5-g6.log")
statuses=$(grep -o 'status=[0-9-]*' "$OUT/switch-g5-g6.requests" | sort | uniq -c | tr -s ' ' | tr '\n' ' ')
[[ $rc -ne 0 ]]
expect G4 $? "control, retention 0: update rc=$rc; ${out:-no client message}; responses: $statuses (a failure here is the expected outcome)"
reader_args

# ---------------------------------------------------------------- G5
client_setup "$READER"
client_remove p3005a-sampleapp >/dev/null 2>&1
gen g7 1.0; gen g8 3.0
publish g7 >/dev/null; client_clean; client_update >"$OUT/G5.log" 2>&1
publish g8 >/dev/null
g5since=$(date +%s)
if [[ $FAMILY == apt ]]; then
    client_install p3005a-sampleapp >>"$OUT/G5.log" 2>&1
else
    dnf -y --repo p3005a --setopt=p3005a.metadata_expire=-1 install p3005a-sampleapp >>"$OUT/G5.log" 2>&1
fi
rc=$?; out=$(installed_version)
journal_since "$g5since" >"$OUT/G5.journal"
client_update >>"$OUT/G5.log" 2>&1
if [[ $FAMILY == apt ]]; then client_install p3005a-sampleapp >>"$OUT/G5.log" 2>&1
else dnf -y --repo p3005a upgrade p3005a-sampleapp >>"$OUT/G5.log" 2>&1; fi
after=$(installed_version)
oldpath=$(pkg_path g7 p3005a-sampleapp); oldsha=$(sha_of "$GENS/g7/$oldpath")
served=$(curl -s "http://$READER/$REPO/$oldpath" | sha256sum | cut -d' ' -f1)
refreshed=no; grep -q 'repomd.xml' "$OUT/G5.journal" && refreshed=yes
if [[ $FAMILY == apt ]]; then
    [[ $rc -eq 0 && $out == 1.0 && $after == 3.0 && $served == "$oldsha" ]]
else
    [[ $rc -eq 0 && ($out == 1.0 || $refreshed == yes) && $after == 3.0 && $served == "$oldsha" ]]
fi
expect G5 $? "package of a superseded generation: old path serves old bytes=$([[ $served == "$oldsha" ]] && echo yes || echo no); install rc=$rc version=$out (metadata refreshed first: $refreshed); after update+upgrade version=$after"

# ---------------------------------------------------------------- G6
n=8 rounds=0 fails=0 inconsistent=0
stop=/run/p3005a-stop; rm -f "$stop" /run/p3005a-published
(
    k=0
    while [[ ! -e $stop ]]; do
        k=$((k + 1))
        gen "p$k" "$( (( k % 2 )) && echo 1.0 || echo 2.0)" && publish "p$k" >/dev/null 2>&1 &&
            echo "$k" >/run/p3005a-published
        rm -rf "${GENS:?}/p$((k - 1))"
    done
) &
ppid=$!
while (( rounds < 20 || $(cat /run/p3005a-published 2>/dev/null || echo 0) < 15 )) && (( rounds < 80 )); do
    rounds=$((rounds + 1)); pids=()
    for i in $(seq $n); do
        d=/tmp/p3005a-client-$i; rm -rf "$d"; mkdir -p "$d/lists/partial" "$d/cache/archives/partial"
        if [[ $FAMILY == apt ]]; then
            apt-get -q update -o Debug::NoLocking=1 -o Dir::State::Lists="$d/lists" -o Dir::Cache="$d/cache" \
                -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/p3005a.sources -o Dir::Etc::sourceparts=- >"$d/log" 2>&1 &
        else
            dnf -y --repo p3005a --setopt=cachedir="$d/cache" --setopt=system_cachedir="$d/cache" makecache --refresh >"$d/log" 2>&1 &
        fi
        pids[i]=$!
    done
    for i in $(seq $n); do
        d=/tmp/p3005a-client-$i ok=1
        wait "${pids[i]}" || { fails=$((fails + 1)); ok=0; }
        if [[ $ok == 1 ]]; then
            if [[ $FAMILY == apt ]]; then
                apt_lists_consistent "$d/lists" || inconsistent=$((inconsistent + 1))
            else
                repomd=$(find "$d/cache" -name repomd.xml | head -1); primary=$(find "$d/cache" -name '*primary.xml*' | head -1)
                [[ -n $repomd && -n $primary ]] && grep -q "$(sha_of "$primary")" "$repomd" || inconsistent=$((inconsistent + 1))
            fi
        fi
        cat "$d/log" >>"$OUT/G6.log"
    done
done
touch "$stop"; wait "$ppid"; published=$(cat /run/p3005a-published 2>/dev/null)
rm -rf /tmp/p3005a-client-* "$stop"
reasons=$(grep -hoiE 'Bad PGP signature|checksum doesn.t match|Hash Sum mismatch|unexpected size|Status code: [0-9]+|404' "$OUT/G6.log" | sort | uniq -c | tr -s ' ' | tr '\n' ';')
# APT: one signed InRelease and by-hash indexes, so nothing may fail. DNF
# fetches repomd.xml and repomd.xml.asc separately, so a switch between
# them fails closed (R-004 G6; ADR-024 point 4 keeps RPM switches rare);
# only a success with inconsistent metadata is a failure there.
if [[ $FAMILY == apt ]]; then [[ $inconsistent -eq 0 && $fails -eq 0 ]]; else [[ $inconsistent -eq 0 ]]; fi
expect G6 $? "$((n * rounds)) client updates in $rounds rounds of $n parallel while ${published:-0} generations were published: failed=$fails, succeeded with inconsistent metadata=$inconsistent ${reasons}"

# ---------------------------------------------------------------- H1 (N-025)
before=$(current); codes=""
for method in POST PUT DELETE PATCH; do
    codes+="$method=$(http_code -X "$method" --data x "http://$READER/$REPO/dists/stable/InRelease") "
done
allow=$(curl -s -o /dev/null -D - -X POST "http://$READER/$REPO/x" | grep -i '^allow:' | tr -d '\r')
[[ $codes == "POST=405 PUT=405 DELETE=405 PATCH=405 " && $(current) == "$before" ]]
expect H1 $? "N-025: $codes($allow); current unchanged: $before -> $(current)"

# ---------------------------------------------------------------- H2
index=$([[ $FAMILY == apt ]] && echo dists/stable/InRelease || echo repodata/repomd.xml)
ok=$(http_code "http://$READER/$REPO/$index")
foreign=$(http_code -H 'Host: evil.example:18080' "http://$READER/$REPO/$index")
dotdot=$(http_code --path-as-is "http://$READER/$REPO/../$REPO/$index")
encoded=$(http_code --path-as-is "http://$READER/$REPO/%2e%2e/etc/passwd")
body=$(http_code -X GET --data abc "http://$READER/$REPO/$index")
[[ $ok == 200 && $foreign == 400 && $dotdot == 404 && $encoded == 404 && $body == 400 ]]
expect H2 $? "GET=$ok, foreign Host=$foreign, ../=$dotdot, %2e%2e=$encoded, GET with a body=$body"

# ---------------------------------------------------------------- H3 (N-017)
client_remove p3005a-sampleapp >/dev/null 2>&1
gen h3 2.0; publish h3 >/dev/null; client_clean; client_update >"$OUT/H3.log" 2>&1
path=$(pkg_path h3 p3005a-sampleapp); object="$CAS/objects/$(sha_of "$GENS/h3/$path")"
# Flip one bit, so the byte always changes (writing a fixed byte may not:
# offset 100 of an RPM lead is already zero).
chmod 0644 "$object"
python3 -I -c 'import sys; f = open(sys.argv[1], "r+b"); f.seek(100); b = f.read(1); f.seek(100); f.write(bytes([b[0] ^ 1]))' "$object"
[[ $(sha_of "$object") != "$(sha_of "$GENS/h3/$path")" ]] || log "H3: the object did not change"
code=$(http_code "http://$READER/$REPO/$path")
leaked=$(curl -s "http://$READER/$REPO/$path" | head -c 64 | od -An -c | tr -s ' ' | head -c 60)
client_install p3005a-sampleapp >>"$OUT/H3.log" 2>&1; rc=$?
refused=$(journal_since "$(( $(date +%s) - 120 ))" | grep -m1 -o 'event=object-refused[^ ]* [^ ]*')
[[ $code == 500 && $rc -ne 0 && -n $refused ]]
expect H3 $? "N-017: changed package object: GET=$code, body starts '$leaked'; client install rc=$rc; log: $refused"
rm -f "$object"

# ---------------------------------------------------------------- H4
pid=$(systemctl show -p MainPID --value "$UNIT")
user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
write=$(runuser -u pakomichi-reader -- sh -c "touch $PUBLISH/probe 2>&1 || echo refused" | tail -1)
[[ $user == pakomichi-reader && $write == refused* ]]
expect H4 $? "reader process user=$user (pid $pid); write into the publish root as the reader: $write"

systemctl stop p3005a-proxy.service 2>/dev/null || true
journalctl -q -u "$UNIT" -o cat >"$OUT/reader.journal" 2>/dev/null
cat "$OUT/results.tsv"
grep -q $'\tFAIL\t' "$OUT/results.tsv" && exit 1
exit 0
