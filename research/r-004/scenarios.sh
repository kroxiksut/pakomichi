#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# R-004 scenarios on one prepared target. Usage (root, inside the target):
#   R004_OUT=<dir> bash /opt/r004/scenarios.sh AREA...
# Areas: env socket gen cas http db measure third (third last: it removes
# the service). Results: $R004_OUT/results.tsv, logs: $R004_OUT/*.log.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/r004/lib.sh
mkdir -p "$OUT"
cd /tmp || exit 1

sha_of() { sha256sum "$1" | cut -d' ' -f1; }
installed_version() { /usr/bin/r004-sampleapp 2>/dev/null | awk '{print $2}'; }
pkg_path() { # repository-relative path of a package file in a generation
    if [[ $FAMILY == apt ]]; then
        grep -A20 "^Package: $2\$" "$GENS/$1/dists/stable/main/binary-amd64/Packages" | awk '/^Filename:/ {print $2; exit}'
    else
        (cd "$GENS/$1" && find packages -name "$2-*.rpm" | head -1)
    fi
}
lazy_path() { cut -f1 "$GENS/$1.lazy.tsv" | head -1; }
lazy_sha() { cut -f2 "$GENS/$1.lazy.tsv" | head -1; }
bigapp_file() { basename "$(ls "$WORK"/pkg/r004-bigapp*."$PKG_EXT")"; }
# gen_lazy NAME MODE-URL: sampleapp 1.0 plus bigapp fetched lazily from URL.
gen_lazy() {
    local flag=--lazy-deb
    [[ $FAMILY == rpm ]] && flag=--lazy-rpm
    gen "$1" 1.0 -- "$flag" "$(ls "$WORK"/pkg/r004-bigapp*."$PKG_EXT")=$2"
}
upstream_count() { curl -s "$UPSTREAM/stats" | python3 -c "import json,sys; print(json.load(sys.stdin).get(sys.argv[1], 0))" "$1"; }
staging_count() { find "$ROOT/tmp" -type f 2>/dev/null | wc -l; }

# ------------------------------------------------------------------ env
area_env() {
    {
        echo "target: $(. /etc/os-release && echo "$PRETTY_NAME")"
        echo "kernel: $(uname -r)"
        echo "systemd: $(systemctl --version | head -1)"
        echo "glibc: $(ldd --version | head -1)"
        echo "gnupg: $(gpg --version | head -1)"
        if [[ $FAMILY == apt ]]; then
            echo "apt: $(apt-get --version | head -1)"
            echo "dpkg: $(dpkg --version | head -1)"
        else
            echo "dnf: $(dnf --version 2>/dev/null | head -1)"
            echo "rpm: $(rpm --version)"
            echo "createrepo_c: $(createrepo_c --version | head -1)"
            echo "libsqlite: $(rpm -q sqlite-libs)"
        fi
        echo "snapshotd sha256: $(sha_of "$BIN")"
        echo "fixtures:"; (cd "$WORK/pkg" && sha256sum ./*."$PKG_EXT")
        echo "third-party repository files:"
        sha256sum /etc/apt/sources.list /etc/apt/sources.list.d/* /etc/yum.repos.d/* 2>/dev/null | grep -v r004
    } >"$OUT/env.txt" 2>&1
    sha256sum /etc/apt/sources.list /etc/apt/sources.list.d/* /etc/yum.repos.d/* 2>/dev/null | grep -v r004 >"$OUT/third-party-before.sha256"
    cat "$OUT/env.txt" >&2
}

# ------------------------------------------------------------------ socket
area_socket() {
    fresh_root; service_reset; gen s1 1.0; publish alpha s1 >/dev/null
    local since out state codes starts pid1 pid2 rc

    systemctl stop "$UNIT"; state=$(systemctl is-active "$UNIT")
    out=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' "$BASE$INDEX")
    [[ $out == 200* && $(systemctl is-active "$UNIT") == active ]]
    expect S1 $? "cold activation: status/time=$out, unit before=$state"

    # The journal filter has one-second resolution: keep S1's start out.
    systemctl stop "$UNIT"; sleep 1.2; since=$(date +%s); sleep 1
    { for _ in $(seq 64); do curl -s -o /dev/null -w '%{http_code}\n' "$BASE$INDEX" & done; wait; } >"$OUT/S2.codes"
    codes=$(grep -c '^200$' "$OUT/S2.codes"); starts=$(journal_since "$since" | grep -c 'event=start')
    [[ $codes -eq 64 && $starts -eq 1 ]]
    expect S2 $? "64 parallel GETs on an inactive service: ok=$codes, service starts=$starts"

    "$BIN" bench 127.0.0.1:18080 "$INDEX" 8 20000 >"$OUT/S3.bench" 2>&1 &
    sleep 1; systemctl restart "$UNIT"; sleep 1; systemctl restart "$UNIT"; wait
    local s3=OBSERVED
    grep -q ' failed=0 ' "$OUT/S3.bench" && s3=PASS
    result S3 "$s3" "two restarts during 20000 GETs: $(tail -1 "$OUT/S3.bench")"

    service_env R004_IDLE_EXIT_SECS=3
    curl -s -o /dev/null "$BASE$INDEX"; pid1=$(main_pid); sleep 6
    state=$(systemctl is-active "$UNIT")
    out=$(http_code "$BASE$INDEX"); pid2=$(main_pid)
    [[ $state == inactive && $out == 200 && $pid1 != "$pid2" && $pid2 != 0 ]]
    expect S4 $? "idle exit after 3 s: state=$state, then GET=$out, pid $pid1 -> $pid2"

    service_reset
    curl -s -o /dev/null "$BASE$INDEX"; kill -9 "$(main_pid)"; sleep 1
    state="service=$(systemctl is-active "$UNIT") socket=$(systemctl is-active r004-snapshotd.socket)"
    out=$(http_code "$BASE$INDEX")
    [[ $out == 200 ]]
    expect S5 $? "SIGKILL while idle ($state), next GET=$out"

    rm -f "$GATE"; service_env "R004_TEST_HOLD=$INDEX" "R004_TEST_GATE=$GATE"
    since=$(date +%s)
    curl -s -o /dev/null -w '%{http_code}' --max-time 30 "$BASE$INDEX" >"$OUT/S6.code" 2>/dev/null & local cpid=$!
    journal_wait "$since" 'event=hold' 20; kill -9 "$(main_pid)"; wait "$cpid"; rc=$?
    service_reset; out=$(http_code "$BASE$INDEX")
    [[ $rc -ne 0 && $out == 200 ]]
    expect S6 $? "SIGKILL with a request in flight: client curl exit=$rc code=$(cat "$OUT/S6.code"), next GET=$out"

    service_reset; since=$(date +%s)
    local i fails=0
    for i in $(seq 10); do
        [[ $(http_code "$BASE$INDEX" 5) == 200 ]] || fails=$((fails + 1))
        pid1=$(main_pid); [[ $pid1 != 0 ]] && kill -9 "$pid1"; sleep 0.3
    done
    state="service=$(systemctl is-active "$UNIT") socket=$(systemctl is-active r004-snapshotd.socket)"
    out=$(http_code "$BASE$INDEX" 5)
    journalctl -q --since "@$since" -u "$UNIT" -u r004-snapshotd.socket -o cat >"$OUT/S7.journal" 2>&1
    local limit; limit=$(grep -E -m3 'start-limit|too quickly|trigger-limit' "$OUT/S7.journal" | tr '\n' ' ')
    systemctl reset-failed "$UNIT" r004-snapshotd.socket; systemctl start r004-snapshotd.socket
    local after; after=$(http_code "$BASE$INDEX")
    result S7 OBSERVED "10 crash/request cycles: failed GETs=$fails; then $state, GET=$out; systemd: ${limit:-no limit message}; after reset-failed + socket start GET=$after"

    service_reset; curl -s -o /dev/null "$BASE$INDEX"
    exec 3<>/dev/tcp/127.0.0.1/18080; printf 'GET /alpha/x HTTP/1.1\r\nHost: 127' >&3
    out=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' "$BASE$INDEX")
    local t0=$SECONDS; timeout 20 cat <&3 >/dev/null; local held=$((SECONDS - t0)); exec 3>&-
    [[ $out == 200* && $held -le 12 ]]
    expect S8 $? "one slow client: other GET=$out; slow connection closed after ${held}s"

    local fds=()
    for i in $(seq 70); do exec {fd}<>/dev/tcp/127.0.0.1/18080; printf 'GET /a' >&"$fd"; fds+=("$fd"); done
    out=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 30 "$BASE$INDEX")
    for fd in "${fds[@]}"; do exec {fd}>&-; done
    result S8b OBSERVED "70 slow clients (limit 64 connections): another GET=$out"

    systemctl stop r004-fallback.service 2>/dev/null; systemctl reset-failed r004-fallback.service 2>/dev/null
    systemd-run --quiet --unit=r004-fallback -p User=pakomichi-r004 -E R004_ROOT="$ROOT" \
        -E R004_LISTEN=127.0.0.1:18081 "$BIN" serve; sleep 1
    out=$(http_code "http://127.0.0.1:18081$INDEX"); systemctl stop r004-fallback.service
    systemd-run --quiet --unit=r004-fallback-bad -p User=pakomichi-r004 -E R004_ROOT="$ROOT" \
        -E R004_LISTEN=0.0.0.0:18082 "$BIN" serve; sleep 1
    state=$(systemctl is-active r004-fallback-bad.service)
    local why; why=$(journalctl -q -u r004-fallback-bad.service -o cat | grep -m1 refusing)
    systemctl reset-failed r004-fallback-bad.service 2>/dev/null
    [[ $out == 200 && $state != active && -n $why ]]
    expect S9 $? "ordinary service fallback on loopback: GET=$out; 0.0.0.0 listener: $state ($why)"

    # Run directly (not through runuser) so LISTEN_PID matches; the binary
    # must refuse before serving anything.
    systemd-socket-activate -l 0.0.0.0:18083 -E R004_ROOT="$ROOT" "$BIN" serve \
        >"$OUT/S10.log" 2>&1 & local spid=$!; sleep 1
    out=$(http_code "http://127.0.0.1:18083$INDEX" 5)
    # The binary starts on the first connection; give it time to log.
    for _ in $(seq 100); do grep -q refusing "$OUT/S10.log" && break; sleep 0.1; done
    kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
    grep -q refusing "$OUT/S10.log"
    expect S10 $? "socket-activated listener on 0.0.0.0: GET=$out, $(grep -m1 refusing "$OUT/S10.log")"
    service_reset
}

# ------------------------------------------------------------------ generations
# switch_during_update NAME-OLD NAME-NEW [client args]: hold index downloads
# after the signed top-level file, switch generations, release.
switch_during_update() {
    local old=$1 new=$2; shift 2
    local since rc
    client_clean
    rm -f "$GATE"
    since=$(date +%s)
    client_update "$@" >"$OUT/switch-$old-$new.log" 2>&1 & local cpid=$!
    journal_wait "$since" 'event=hold' 60 || log "no hold seen"
    publish alpha "$new" >/dev/null
    touch "$GATE"; wait "$cpid"; rc=$?
    rm -f "$GATE"
    journal_since "$since" | grep -E '^req |event=(hold|release|view-loaded)' >"$OUT/switch-$old-$new.requests"
    return $rc
}

area_gen() {
    fresh_root; service_reset; client_setup; client_clean
    client_remove r004-sampleapp >/dev/null 2>&1
    local rc out
    gen g1 1.0; gen g2 2.0; gen g3 3.0

    publish alpha g1 >"$OUT/G1.log" 2>&1 && client_update >>"$OUT/G1.log" 2>&1 &&
        client_install r004-sampleapp >>"$OUT/G1.log" 2>&1
    rc=$?; out=$(installed_version)
    [[ $rc -eq 0 && $out == 1.0 ]]
    expect G1 $? "publish g1, update, install: rc=$rc version=$out"

    service_env "R004_TEST_HOLD=$HOLD" "R004_TEST_GATE=$GATE"
    switch_during_update g1 g2; rc=$?
    client_metadata_digests >"$OUT/G2.client"; gen_digests g1 >"$OUT/G2.gen1"
    local match=no
    [[ $FAMILY == apt ]] && diff <(cut -d' ' -f1 "$OUT/G2.client") <(cut -d' ' -f1 "$OUT/G2.gen1") >/dev/null && match=g1
    [[ $FAMILY == rpm ]] && grep -qF "$(cut -d' ' -f1 "$OUT/G2.gen1")" "$OUT/G2.client" && match=g1
    local held_targets; held_targets=$(grep -o 'event=hold target=[^ ]*' "$OUT/switch-g1-g2.requests" | sed 's/.*target=\/alpha\///' | tr '\n' ' ')
    [[ $rc -eq 0 && $match == g1 ]]
    expect G2 $? "switch g1->g2 between the signed index and its referenced files: update rc=$rc, client metadata = $match; held requests: $held_targets"

    # Controls G3/G4 run without connection pinning to expose the race
    # itself; G3p repeats G3 with pinning on.
    local pin
    for pin in 0 1; do
        local id=G3; [[ $pin == 1 ]] && id=G3p
        service_env "R004_TEST_HOLD=$HOLD" "R004_TEST_GATE=$GATE" "R004_PIN_CONNECTION=$pin"
        if [[ $FAMILY == apt ]]; then
            gen "g3-$pin" 3.0; gen "g4-$pin" 1.0; publish alpha "g3-$pin" >/dev/null
            switch_during_update "g3-$pin" "g4-$pin" -o Acquire::By-Hash=no; rc=$?
            out=$(grep -m1 -iE 'hash sum mismatch|unexpected size|mismatch' "$OUT/switch-g3-$pin-g4-$pin.log")
            result "$id" OBSERVED "client without By-Hash, connection pinning=$pin: update rc=$rc; ${out:-no mismatch message}; client connections=$(grep -o 'peer_port=[0-9]*' "$OUT/switch-g3-$pin-g4-$pin.requests" | sort -u | wc -l)"
        else
            gen "c1-$pin" 1.0 -- --simple-names; gen "c2-$pin" 2.0 -- --simple-names
            publish alpha "c1-$pin" >/dev/null
            switch_during_update "c1-$pin" "c2-$pin"; rc=$?
            out=$(grep -m1 -iE 'checksum|mismatch|failed' "$OUT/switch-c1-$pin-c2-$pin.log")
            result "$id" OBSERVED "non-unique repodata names, connection pinning=$pin: makecache rc=$rc; ${out:-no checksum message}; client connections=$(grep -o 'peer_port=[0-9]*' "$OUT/switch-c1-$pin-c2-$pin.requests" | sort -u | wc -l)"
        fi
    done

    gen g5 2.0; gen g6 3.0
    publish alpha g5 >/dev/null
    service_env "R004_TEST_HOLD=$HOLD" "R004_TEST_GATE=$GATE" R004_RETENTION=0 R004_PIN_CONNECTION=0
    switch_during_update g5 g6; rc=$?
    out=$(grep -m1 -iE 'unexpected size|mismatch|checksum|404|not found' "$OUT/switch-g5-g6.log")
    local statuses; statuses=$(awk '/^req / {for (i=1;i<=NF;i++) if ($i ~ /^(target|status)=/) printf "%s ", $i; print ""}' "$OUT/switch-g5-g6.requests" | sed 's/target=\/alpha\///' | tr '\n' ';')
    result G4 OBSERVED "control, old generation not retained: update rc=$rc; ${out:-no client message}; requests: $statuses"
    service_reset

    client_remove r004-sampleapp >/dev/null 2>&1
    gen g7 1.0; gen g8 3.0
    publish alpha g7 >/dev/null; client_clean; client_update >"$OUT/G5.log" 2>&1
    publish alpha g8 >/dev/null
    local g5since; g5since=$(date +%s)
    if [[ $FAMILY == apt ]]; then
        client_install r004-sampleapp >>"$OUT/G5.log" 2>&1
    else
        dnf -y --repo r004 --setopt=r004.metadata_expire=-1 install r004-sampleapp >>"$OUT/G5.log" 2>&1
    fi
    rc=$?; out=$(installed_version)
    journal_since "$g5since" | grep '^req ' >"$OUT/G5.requests"
    client_update >>"$OUT/G5.log" 2>&1
    if [[ $FAMILY == apt ]]; then client_install r004-sampleapp >>"$OUT/G5.log" 2>&1; else dnf -y --repo r004 upgrade r004-sampleapp >>"$OUT/G5.log" 2>&1; fi
    local after; after=$(installed_version)
    # Server property: the old package path still serves the old bytes.
    local oldpath oldsha served
    oldpath=$(pkg_path g7 r004-sampleapp); oldsha=$(sha_of "$GENS/g7/$oldpath")
    served=$(curl -s "$BASE/alpha/$oldpath" | sha256sum | cut -d' ' -f1)
    local refreshed=no
    grep -q 'repomd.xml ' "$OUT/G5.requests" && refreshed=yes
    if [[ $FAMILY == apt ]]; then
        [[ $rc -eq 0 && $out == 1.0 && $after == 3.0 && $served == "$oldsha" ]]
    else
        # DNF may refresh metadata before installing despite metadata_expire=-1;
        # then it installs the new version consistently.
        [[ $rc -eq 0 && ($out == 1.0 || $refreshed == yes) && $after == 3.0 && $served == "$oldsha" ]]
    fi
    expect G5 $? "package of a superseded generation after the switch: old path serves old bytes=$([[ $served == "$oldsha" ]] && echo yes || echo no); client install rc=$rc version=$out (client refreshed metadata first: $refreshed); after update+upgrade version=$after"

    service_reset
    concurrent_updates G6
    service_env R004_PIN_CONNECTION=1
    concurrent_updates G6p
    service_reset

    if [[ $FAMILY == apt ]]; then
        gen v1 1.0 -- --valid 75; publish alpha v1 >/dev/null; client_clean
        client_update >"$OUT/G7.log" 2>&1; local first=$?
        sleep 80
        client_update >>"$OUT/G7.log" 2>&1; rc=$?
        out=$(grep -m1 -i 'expired' "$OUT/G7.log")
        local policy; policy=$(apt-cache policy r004-sampleapp | awk '/Candidate/ {print $2}')
        [[ $first -eq 0 && -n $out ]]
        expect G7 $? "Valid-Until passed while served: update before=$first after=$rc; '$out'; candidate still listed: $policy"
    else
        result G7 OBSERVED "not applicable: repomd.xml carries no signed expiry; see G8"
    fi

    gen x1 1.0 -- --valid -10; publish alpha x1 >"$OUT/G7b.log" 2>&1; rc=$?
    gen x2 1.0 -- --date-offset 3600; publish alpha x2 >>"$OUT/G7b.log" 2>&1; local rc2=$?
    if [[ $FAMILY == apt ]]; then
        [[ $rc -ne 0 && $rc2 -ne 0 ]]
        expect G7b $? "publisher refuses an expired InRelease (rc=$rc) and a future Date (rc=$rc2)"
    fi

    gen r-new 3.0; gen r-old 1.0
    publish alpha r-old >/dev/null; sleep 2; gen r-new 3.0; publish alpha r-new >/dev/null
    client_clean; client_update >"$OUT/G8.log" 2>&1
    cp -a "$GENS/r-old" "$GENS/r-replay"; cp "$GENS/r-old.lazy.tsv" "$GENS/r-replay.lazy.tsv"
    publish alpha r-replay >/dev/null
    client_update >>"$OUT/G8.log" 2>&1; rc=$?
    local candidate held
    if [[ $FAMILY == apt ]]; then
        candidate=$(apt-cache madison r004-sampleapp | awk '/18080/ {print $3}' | tr '\n' ' ')
        held=$(client_metadata_digests | head -1 | cut -d' ' -f1)
    else
        candidate=$(dnf -q --repo r004 --setopt=r004.metadata_expire=-1 repoquery --qf '%{version}\n' r004-sampleapp 2>/dev/null | sort -u | tr '\n' ' ')
        held=$(client_metadata_digests | head -1 | cut -d' ' -f1)
    fi
    local which=other
    [[ $held == "$(gen_digests r-old | head -1 | cut -d' ' -f1)" ]] && which=r-old/replay
    [[ $held == "$(gen_digests r-new | head -1 | cut -d' ' -f1)" ]] && which=r-new
    result G8 OBSERVED "older signed metadata served again after newer (replay): update rc=$rc; client now holds $which metadata; versions offered by our source: $candidate"

    local current; current=$(cat "$ROOT/repos/alpha/current")
    mv "$SIGNER" "$SIGNER.lost"
    gen k1 2.0; rc=$?
    # gpg may recreate an empty home; drop it before restoring the key.
    [[ -d $SIGNER ]] && rm -rf "$SIGNER"
    mv "$SIGNER.lost" "$SIGNER"
    local tmpkey; tmpkey=$(mktemp -d)
    gpg --homedir "$tmpkey" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Rogue R-004 TEST ONLY' ed25519 sign 1d 2>/dev/null
    local rogue; rogue=$(gpg --homedir "$tmpkey" --list-secret-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
    python3 -I /opt/r004/make_repo.py "$FAMILY" "$GENS/k2" --homedir "$tmpkey" --key "$rogue" \
        $( [[ $FAMILY == apt ]] && echo --deb "$WORK/pkg/r004-sampleapp_2.0_all.deb" || echo --rpm "$(ls "$WORK"/pkg/r004-sampleapp-2.0-1.noarch.rpm)" ) >/dev/null
    publish alpha k2 >"$OUT/G9.log" 2>&1; local rc2=$?
    rm -rf "$tmpkey"
    local now; now=$(cat "$ROOT/repos/alpha/current")
    client_update >>"$OUT/G9.log" 2>&1; local rc3=$?
    [[ $rc -eq 3 && $rc2 -ne 0 && $now == "$current" && $rc3 -eq 0 ]]
    expect G9 $? "signing key lost: build rc=$rc; metadata signed by another key: publish rc=$rc2 ($(grep -m1 -o 'signature check[^:]*' "$OUT/G9.log")); current stays $now; client update rc=$rc3"
}

# concurrent_updates ID: parallel isolated client updates while a publisher
# switches generations in a loop. G6 expects no failure; other IDs observe.
concurrent_updates() {
    local label=$1 n=8 rounds=0 i fails=0 inconsistent=0 published=0
    local stop=/run/r004-stop-publisher; rm -f "$stop" /run/r004-published
    (
        k=0
        while [[ ! -e $stop ]]; do
            k=$((k + 1)); gen "$label-p$k" "$( (( k % 2 )) && echo 1.0 || echo 2.0)" &&
                publish alpha "$label-p$k" >/dev/null 2>&1 && echo "$k" >/run/r004-published
        done
    ) &
    local ppid=$!
    # At least 20 rounds and 15 switches (at most 80 rounds).
    while (( rounds < 20 || $(cat /run/r004-published 2>/dev/null || echo 0) < 15 )) && (( rounds < 80 )); do
        rounds=$((rounds + 1))
        local pids=()
        for i in $(seq $n); do
            local d=/tmp/r004-client-$i
            rm -rf "$d"; mkdir -p "$d/lists/partial" "$d/cache/archives/partial"
            if [[ $FAMILY == apt ]]; then
                apt-get -q update -o Debug::NoLocking=1 -o Dir::State::Lists="$d/lists" -o Dir::Cache="$d/cache" \
                    -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/r004.sources -o Dir::Etc::sourceparts=- \
                    >"$d/log" 2>&1 &
            else
                dnf -y --repo r004 --setopt=cachedir="$d/cache" --setopt=system_cachedir="$d/cache" makecache --refresh \
                    >"$d/log" 2>&1 &
            fi
            pids[i]=$!
        done
        for i in $(seq $n); do
            local d=/tmp/r004-client-$i ok=1
            wait "${pids[i]}" || { fails=$((fails + 1)); ok=0; }
            # Safety: a client that reports success must hold consistent metadata.
            if [[ $ok == 1 ]]; then
                if [[ $FAMILY == apt ]]; then
                    apt_lists_consistent "$d/lists" || inconsistent=$((inconsistent + 1))
                else
                    local repomd; repomd=$(find "$d/cache" -name repomd.xml | head -1)
                    local primary; primary=$(find "$d/cache" -name '*primary.xml*' | head -1)
                    [[ -n $repomd && -n $primary ]] && grep -q "$(sha_of "$primary")" "$repomd" || inconsistent=$((inconsistent + 1))
                fi
            fi
            cat "$d/log" >>"$OUT/$label.log"
        done
    done
    touch "$stop"; wait "$ppid"; published=$(cat /run/r004-published 2>/dev/null)
    rm -rf /tmp/r004-client-* "$stop"
    local reasons; reasons=$(grep -hoiE 'Bad PGP signature|checksum doesn.t match|Hash Sum mismatch|unexpected size|Status code: [0-9]+' "$OUT/$label.log" | sort | uniq -c | tr -s ' ' | tr '\n' ';')
    local pin=off; [[ $label == G6p ]] && pin=on
    [[ $inconsistent -eq 0 ]]
    expect "$label" $? "connection pinning $pin: $((n * rounds)) client updates in $rounds rounds of $n parallel while ${published:-0} generations were published; succeeded with inconsistent metadata=$inconsistent; failed (fail closed)=$fails ${reasons}"
}

# ------------------------------------------------------------------ cas / lazy fetch
area_cas() {
    fresh_root; service_env R004_FETCH_IDLE_SECS=3; client_setup
    local file path sha out rc code before
    file=$(bigapp_file)
    gen_lazy c-ok "$UPSTREAM/files/$file"; publish alpha c-ok >/dev/null
    path=$(lazy_path c-ok); sha=$(lazy_sha c-ok)

    before=$(upstream_count "/files/$file")
    { for _ in $(seq 8); do curl -s --max-time 60 "$BASE/alpha/$path" | sha256sum | cut -d' ' -f1 & done; wait; } >"$OUT/C1.sums"
    local good; good=$(grep -c "^$sha\$" "$OUT/C1.sums")
    local fetched=$(( $(upstream_count "/files/$file") - before ))
    [[ $good -eq 8 && $fetched -eq 1 && -f $ROOT/objects/$sha ]]
    expect C1 $? "lazy object, 8 parallel first requests: correct bodies=$good, upstream downloads=$fetched"

    client_clean; client_update >"$OUT/C1b.log" 2>&1
    client_install r004-bigapp >>"$OUT/C1b.log" 2>&1; rc=$?
    client_remove r004-bigapp >/dev/null 2>&1
    expect C1b $rc "native client installs the lazily fetched package: rc=$rc"

    fail_mode() { # ID MODE EXPECTED-CODE NOTE
        local id=$1 mode=$2 want=$3 note=$4 g="c-$2"
        rm -f "$ROOT/objects/$sha"
        gen_lazy "$g" "$UPSTREAM/$mode/$file"; publish alpha "$g" >/dev/null
        local t0; t0=$(date +%s.%N)
        local got; got=$(curl -s -o "$OUT/$id.body" -w '%{http_code}' --max-time 60 "$BASE/alpha/$path")
        local secs; secs=$(python3 -c "import sys,time; print(round(time.time()-float(sys.argv[1]),1))" "$t0")
        local body; body=$(stat -c %s "$OUT/$id.body"); rm -f "$OUT/$id.body"
        local left; left=$(staging_count)
        [[ $got == "$want" && ! -e $ROOT/objects/$sha && $left -eq 0 && $body -lt 100 ]]
        expect "$id" $? "$note: HTTP $got after ${secs}s, body ${body} bytes, object stored=$([[ -e $ROOT/objects/$sha ]] && echo yes || echo no), staging files=$left"
    }
    fail_mode C2 truncate 502 "upstream closes after half the bytes"
    if [[ $FAMILY == apt ]]; then
        client_clean; client_update >/dev/null 2>&1
        client_install r004-bigapp >"$OUT/C2b.log" 2>&1; rc=$?
        result C2b "$( [[ $rc -ne 0 ]] && echo PASS || echo FAIL )" "native client on a failed lazy fetch: rc=$rc; $(grep -m1 -E '^E:|^Err' "$OUT/C2b.log")"
    else
        client_clean; client_update >/dev/null 2>&1
        client_install r004-bigapp >"$OUT/C2b.log" 2>&1; rc=$?
        result C2b "$( [[ $rc -ne 0 ]] && echo PASS || echo FAIL )" "native client on a failed lazy fetch: rc=$rc; $(grep -m1 -iE 'error|fail' "$OUT/C2b.log")"
    fi
    fail_mode C3 stall 504 "upstream stalls after 64 KiB (idle timeout 3 s)"
    fail_mode C4 wrong 502 "upstream sends other bytes of the same length"
    fail_mode C5 badlen 502 "upstream Content-Length differs from the pinned size"

    disk_full

    for point in fetch-after-write fetch-after-fsync fetch-after-rename; do
        rm -f "$ROOT/objects/$sha"
        gen_lazy "c-$point" "$UPSTREAM/files/$file"; publish alpha "c-$point" >/dev/null
        service_env R004_FETCH_IDLE_SECS=3 "R004_TEST_PAUSE_AT=$point"
        local since; since=$(date +%s)
        curl -s -o /dev/null -w '%{http_code}' --max-time 60 "$BASE/alpha/$path" >"$OUT/C7.code" 2>/dev/null & local cpid=$!
        journal_wait "$since" 'event=pause' 60
        kill -9 "$(main_pid)"; wait "$cpid"; rc=$?
        local left; left=$(staging_count)
        local stored; stored=$([[ -e $ROOT/objects/$sha ]] && echo yes || echo no)
        service_env R004_FETCH_IDLE_SECS=3; since=$(date +%s)
        local after; after=$(curl -s --max-time 60 "$BASE/alpha/$path" | sha256sum | cut -d' ' -f1)
        local cleaned; cleaned=$(journal_since "$since" | grep -c startup-remove-staging)
        runuser -u pakomichi-r004 -- "$BIN" check "$ROOT" >"$OUT/C7-$point.check" 2>&1; local chk=$?
        [[ $after == "$sha" && $chk -eq 0 ]]
        expect "C7-$point" $? "SIGKILL at $point: client exit=$rc code=$(cat "$OUT/C7.code"); after kill staging=$left object=$stored; restart removed staging=$cleaned; next GET digest ok=$([[ $after == "$sha" ]] && echo yes || echo no); check rc=$chk"
    done
    service_env R004_FETCH_IDLE_SECS=3

    publish_kills

    # The current generation must offer exactly the object that gets damaged.
    local spath ssha obj
    gen c9 1.0; publish alpha c9 >/dev/null
    spath=$(pkg_path c9 r004-sampleapp); ssha=$(grep -P "\t$spath\t" "$ROOT/repos/alpha/generations/c9.manifest" | cut -f1)
    obj=$ROOT/objects/$ssha
    chmod u+w "$obj"; python3 -c "import sys; f=open(sys.argv[1],'r+b'); b=f.read(1); f.seek(0); f.write(bytes([b[0]^1]))" "$obj"; chmod 0444 "$obj"
    code=$(http_code "$BASE/alpha/$spath")
    client_clean; client_update >/dev/null 2>&1; client_remove r004-sampleapp >/dev/null 2>&1
    client_install r004-sampleapp >"$OUT/C9.log" 2>&1; rc=$?
    service_env R004_VERIFY_ON_SERVE=0
    local code2 got2; code2=$(http_code "$BASE/alpha/$spath"); got2=$(curl -s "$BASE/alpha/$spath" | sha256sum | cut -d' ' -f1)
    client_clean; client_update >/dev/null 2>&1
    client_install r004-sampleapp >"$OUT/C9b.log" 2>&1; local rc2=$?
    local msg2; msg2=$(grep -m1 -iE 'hash sum|checksum|mismatch|digest' "$OUT/C9b.log")
    [[ $code == 500 && $rc -ne 0 && $rc2 -ne 0 ]]
    expect C9 $? "one flipped bit in a stored object: verify-on-serve HTTP $code, client rc=$rc; without verify-on-serve HTTP $code2 (served digest ok=$([[ $got2 == "$ssha" ]] && echo yes || echo no)), client rc=$rc2: ${msg2:-no client message}"
    service_env R004_FETCH_IDLE_SECS=3
    runuser -u pakomichi-r004 -- "$BIN" reconcile "$ROOT" >"$OUT/C9.reconcile" 2>&1
    gen c-repair 1.0; publish alpha c-repair >/dev/null; code=$(http_code "$BASE/alpha/$spath")
    result C9b "$( [[ $code == 200 ]] && echo PASS || echo FAIL )" "reconcile quarantined it ($(grep -c quarantined "$OUT/C9.reconcile")); republish restored it: HTTP $code"

    obj=$ROOT/objects/$ssha
    mv "$obj" "$obj.real"; ln -s /etc/passwd "$obj"
    out=$(python3 -I /opt/r004/rawhttp.py "GET /alpha/$spath HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nConnection: close\r\n\r\n")
    rm -f "$obj"; mv "$obj.real" "$obj"
    [[ $out == "500 "*" 0" ]]
    expect C10 $? "object replaced by a symlink to /etc/passwd: status bodylen leak = $out"

    local url id i=0
    for url in "$UPSTREAM/r/loopback" "$UPSTREAM/r/private" "$UPSTREAM/r/metadata" "$UPSTREAM/r/v6" \
        "$UPSTREAM/r/https" "$UPSTREAM/r/loop" "http://user@127.0.0.1:18090/files/$file" \
        "http://localhost:22/x" "http://169.254.169.254/latest/meta-data/" "http://10.0.0.1/x"; do
        i=$((i + 1)); id=C11-$i
        rm -f "$ROOT/objects/$sha"
        gen_lazy "s$i" "$url"; publish alpha "s$i" >/dev/null
        local since; since=$(date +%s)
        code=$(http_code "$BASE/alpha/$path" 20)
        local why; why=$(journal_since "$since" | grep -m1 -o 'fetch-failed.*' | sed 's/object=[0-9a-f]* //')
        [[ $code == 502 && ! -e $ROOT/objects/$sha ]]
        expect "$id" $? "lazy URL $url: HTTP $code; $why"
    done
    rm -f "$ROOT/objects/$sha"
    gen_lazy s-ok "$UPSTREAM/r/ok/$file"; publish alpha s-ok >/dev/null
    code=$(http_code "$BASE/alpha/$path" 30)
    expect C11-ok "$([[ $code == 200 ]]; echo $?)" "relative redirect to the allowed upstream: HTTP $code"
    service_reset
}

disk_full() {
    local small=/var/lib/pakomichi-r004-small file path sha code
    file=$(bigapp_file)
    systemctl stop r004-small.service 2>/dev/null; systemctl reset-failed r004-small.service 2>/dev/null
    umount "$small" 2>/dev/null; mkdir -p "$small"
    mount -t tmpfs -o size=12m,mode=0750 tmpfs "$small"; chown pakomichi-r004:pakomichi-r004 "$small"
    gen_lazy d1 "$UPSTREAM/files/$file"
    runuser -u pakomichi-r004 -- "$BIN" publish "$small" alpha d1 "$GENS/d1" --keyring "$KEYRING" --lazy "$GENS/d1.lazy.tsv" >/dev/null
    path=$(lazy_path d1); sha=$(lazy_sha d1)
    systemd-run --quiet --unit=r004-small -p User=pakomichi-r004 -E R004_ROOT="$small" -E R004_LISTEN=127.0.0.1:18081 \
        -E R004_UPSTREAM_ALLOW=127.0.0.1:18090 "$BIN" serve; sleep 1
    local used0; used0=$(df --output=used -B1 "$small" | tail -1)
    code=$(http_code "http://127.0.0.1:18081/alpha/$path" 60)
    local used1; used1=$(df --output=used -B1 "$small" | tail -1)
    local spath; spath=$(pkg_path d1 r004-sampleapp)
    local scode; scode=$(http_code "http://127.0.0.1:18081/alpha/$spath")
    local why; why=$(journalctl -q -u r004-small.service -o cat | grep -m1 -o 'fetch-failed.*' | sed 's/object=[0-9a-f]* //')
    [[ $code == 507 && $used1 -le $used0 && $scode == 200 ]]
    expect C6 $? "20 MiB lazy object into a 12 MiB store: HTTP $code ($why); used bytes $used0 -> $used1; stored package still HTTP $scode"

    local fill=$small/filler; dd if=/dev/zero of="$fill" bs=1M count=64 2>/dev/null
    local current; current=$(cat "$small/repos/alpha/current")
    gen d2 2.0
    runuser -u pakomichi-r004 -- "$BIN" publish "$small" alpha d2 "$GENS/d2" --keyring "$KEYRING" >"$OUT/C6b.log" 2>&1; local rc=$?
    local now; now=$(cat "$small/repos/alpha/current")
    local left; left=$(find "$small/tmp" -type f | wc -l)
    rm -f "$fill"
    runuser -u pakomichi-r004 -- "$BIN" check "$small" >>"$OUT/C6b.log" 2>&1; local chk=$?
    [[ $rc -ne 0 && $now == "$current" && $left -eq 0 && $chk -eq 0 ]]
    expect C6b $? "publish on a full disk: rc=$rc ($(grep -m1 -o 'error:.*' "$OUT/C6b.log")); current stays $now; staging=$left; check rc=$chk"
    systemctl stop r004-small.service; umount "$small"; rmdir "$small"
}

publish_kills() {
    local point base next rc current now chk2 out
    for point in publish-object-after-write publish-after-objects publish-before-switch publish-after-switch; do
        base=pk-$point-a next=pk-$point-b
        gen "$base" 1.0; publish alpha "$base" >/dev/null
        gen "$next" 2.0
        runuser -u pakomichi-r004 -- env R004_TEST_PAUSE_AT="$point" "$BIN" publish "$ROOT" alpha "$next" "$GENS/$next" \
            --keyring "$KEYRING" >"$OUT/C8-$point.log" 2>&1 &
        local ppid=$! i
        for i in $(seq 100); do grep -q 'event=pause' "$OUT/C8-$point.log" && break; sleep 0.1; done
        pkill -9 -f "publish $ROOT alpha $next" ; wait "$ppid" 2>/dev/null
        now=$(cat "$ROOT/repos/alpha/current")
        client_clean; client_update >>"$OUT/C8-$point.log" 2>&1; rc=$?
        runuser -u pakomichi-r004 -- "$BIN" check "$ROOT" >"$OUT/C8-$point.check" 2>&1
        out=$(grep -c . "$OUT/C8-$point.check")
        runuser -u pakomichi-r004 -- "$BIN" reconcile "$ROOT" >>"$OUT/C8-$point.check" 2>&1
        runuser -u pakomichi-r004 -- "$BIN" check "$ROOT" >>"$OUT/C8-$point.check" 2>&1; chk2=$?
        local again=republished
        publish alpha "$next" >"$OUT/C8-$point.again" 2>&1 || again=$(grep -o 'already exists' "$OUT/C8-$point.again" || echo failed)
        [[ $rc -eq 0 && $chk2 -eq 0 ]]
        expect "C8-$point" $? "SIGKILL of the publisher at $point: current=$now; client update rc=$rc; check lines before reconcile=$out; after reconcile check rc=$chk2; same id again: $again"
    done
}

# ------------------------------------------------------------------ http
area_http() {
    fresh_root; service_reset; gen h1 1.0; publish alpha h1 >/dev/null
    local ok="Host: 127.0.0.1:18080\r\nConnection: close\r\n\r\n" fails=0 line id req want got
    : >"$OUT/H.tsv"
    while IFS='|' read -r id want req; do
        [[ -z $id ]] && continue
        got=$(python3 -I /opt/r004/rawhttp.py "$req")
        printf '%s\t%s\t%s\t%s\n' "$id" "$want" "$got" "$req" >>"$OUT/H.tsv"
        [[ ${got%% *} == "$want" && $got == *" 0" ]] || { fails=$((fails + 1)); log "H mismatch $id: want $want got $got"; }
    done <<EOF
H01|200|GET $INDEX HTTP/1.1\r\n$ok
H02|404|GET /alpha/../../etc/passwd HTTP/1.1\r\n$ok
H03|404|GET /alpha/%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\n$ok
H04|404|GET /alpha/dists/..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\n$ok
H05|404|GET /alpha/a%5c..%5cpasswd HTTP/1.1\r\n$ok
H06|404|GET /alpha/a%00b HTTP/1.1\r\n$ok
H07|404|GET http://127.0.0.1:18080$INDEX HTTP/1.1\r\n$ok
H08|404|GET //etc/passwd HTTP/1.1\r\n$ok
H09|404|GET $INDEX?x=1 HTTP/1.1\r\n$ok
H10|404|GET /admin HTTP/1.1\r\n$ok
H11|404|GET /alpha/sync HTTP/1.1\r\n$ok
H12|405|POST /alpha/sync HTTP/1.1\r\nContent-Length: 0\r\n$ok
H13|405|PUT $INDEX HTTP/1.1\r\n$ok
H14|405|DELETE $INDEX HTTP/1.1\r\n$ok
H15|405|OPTIONS * HTTP/1.1\r\n$ok
H16|400|GET $INDEX HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n
H17|400|GET $INDEX HTTP/1.1\r\nConnection: close\r\n\r\n
H18|400|GET $INDEX HTTP/1.1\r\nContent-Length: 5\r\n${ok}hello
H19|400|GET $INDEX HTTP/1.1\r\nTransfer-Encoding: chunked\r\n${ok}0\r\n\r\n
H20|414|GET /alpha/$(printf 'a%.0s' $(seq 3000)) HTTP/1.1\r\n$ok
H21|431|GET $INDEX HTTP/1.1\r\nX-Pad: $(printf 'b%.0s' $(seq 9000))\r\n$ok
H22|400|GARBAGE\r\n\r\n
H23|400|GET $INDEX HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nHost: 127.0.0.1:18080\r\nConnection: close\r\n\r\n
H24|200|HEAD $INDEX HTTP/1.1\r\n$ok
EOF
    local total; total=$(wc -l <"$OUT/H.tsv")
    [[ $fails -eq 0 ]]
    expect H1 $? "$total crafted requests (traversal, encodings, methods, Host, bodies, limits): mismatches=$fails, file content leaked in none"

    local manifest=$ROOT/repos/alpha/generations/h1.manifest
    mv "$manifest" "$manifest.real"; ln -s /etc/passwd "$manifest"
    service_reset
    local code; code=$(http_code "$BASE$INDEX")
    rm -f "$manifest"; mv "$manifest.real" "$manifest"
    service_reset
    [[ $code == 503 ]]
    expect H2 $? "manifest replaced by a symlink: HTTP $code (fail closed)"
}

# ------------------------------------------------------------------ db
area_db() {
    fresh_root; service_reset; client_setup
    gen d-a 1.0; gen d-b 2.0; gen d-c 3.0; gen d-d 1.0
    publish alpha d-a >/dev/null
    local current rc rc2 out db=$ROOT/state.db
    python3 -c "import sys; f=open(sys.argv[1],'r+b'); f.seek(4096); f.write(b'\xa5'*4096)" "$db"
    current=$(cat "$ROOT/repos/alpha/current")
    publish alpha d-b >"$OUT/D1.log" 2>&1; rc=$?
    client_clean; client_update >>"$OUT/D1.log" 2>&1; rc2=$?
    [[ $rc -ne 0 && $(cat "$ROOT/repos/alpha/current") == "$current" && $rc2 -eq 0 ]]
    expect D1 $? "damaged page in state.db: publish rc=$rc ($(grep -m1 -o 'error:.*' "$OUT/D1.log")); current stays $current; client update rc=$rc2"

    runuser -u pakomichi-r004 -- "$BIN" reconcile "$ROOT" >"$OUT/D2.log" 2>&1; rc=$?
    publish alpha d-b >>"$OUT/D2.log" 2>&1; rc2=$?
    out=$(sqlite3 "$db" 'select count(*) from generations' 2>&1)
    [[ $rc -eq 0 && $rc2 -eq 0 ]]
    expect D2 $? "reconcile rebuilt state.db from manifests (rc=$rc, $(grep -c recorded "$OUT/D2.log") generation rows); publish after it rc=$rc2; generations rows=$out"

    python3 -c "import sys; f=open(sys.argv[1],'r+b'); f.write(b'\0'*100)" "$db"
    publish alpha d-c >"$OUT/D3.log" 2>&1; rc=$?
    runuser -u pakomichi-r004 -- "$BIN" reconcile "$ROOT" >>"$OUT/D3.log" 2>&1
    publish alpha d-d >>"$OUT/D3.log" 2>&1; rc2=$?
    [[ $rc -ne 0 && $rc2 -eq 0 ]]
    expect D3 $? "zeroed state.db header: publish rc=$rc ($(grep -m1 -o 'error:.*' "$OUT/D3.log")); after reconcile publish rc=$rc2"
}

# ------------------------------------------------------------------ measure
area_measure() {
    fresh_root; service_reset
    local file; file=$(bigapp_file)
    gen m1 1.0 -- $( [[ $FAMILY == apt ]] && echo --deb || echo --rpm ) "$(ls "$WORK"/pkg/r004-bigapp*."$PKG_EXT")"
    local t0; t0=$(date +%s.%N); publish alpha m1 >/dev/null
    local pub; pub=$(python3 -c "import sys,time; print(round(time.time()-float(sys.argv[1]),3))" "$t0")
    local big; big=$(pkg_path m1 r004-bigapp)
    local i times=()
    for i in 1 2 3 4 5; do
        systemctl stop "$UNIT"; sleep 0.5
        times+=("$(curl -s -o /dev/null -w '%{time_total}' "$BASE$INDEX")")
    done
    sleep 2
    local pid; pid=$(main_pid)
    local idle; idle=$(awk '/VmRSS|VmHWM|Threads/ {printf "%s=%s%s ", $1, $2, $3}' "/proc/$pid/status")
    "$BIN" bench 127.0.0.1:18080 "$INDEX" 8 5000 >"$OUT/M-small.bench"
    "$BIN" bench 127.0.0.1:18080 "/alpha/$big" 4 40 >"$OUT/M-large-verify.bench"
    local after; after=$(awk '/VmRSS|VmHWM/ {printf "%s=%s%s ", $1, $2, $3}' "/proc/$pid/status")
    service_env R004_VERIFY_ON_SERVE=0
    "$BIN" bench 127.0.0.1:18080 "/alpha/$big" 4 40 >"$OUT/M-large-noverify.bench"
    service_reset
    local cas; cas=$(du -sb "$ROOT/objects" | cut -f1)
    local man; man=$(stat -c %s "$ROOT/repos/alpha/generations/m1.manifest")
    {
        echo "publish (sampleapp + 20 MiB bigapp, sign excluded): ${pub}s"
        echo "cold activation, time to first response (5 runs): ${times[*]}"
        echo "idle after activation: $idle"
        echo "after benches: $after"
        cat "$OUT/M-small.bench" "$OUT/M-large-verify.bench" "$OUT/M-large-noverify.bench"
        echo "CAS bytes: $cas; manifest bytes: $man"
    } >"$OUT/measure.txt"
    cat "$OUT/measure.txt" >&2
    result M1 OBSERVED "$(tr '\n' ';' <"$OUT/measure.txt")"
}

# ------------------------------------------------------------------ third-party and removal
area_third() {
    fresh_root; service_reset; client_setup
    gen t1 1.0; publish alpha t1 >/dev/null; client_clean; client_update >/dev/null 2>&1
    client_remove r004-sampleapp >/dev/null 2>&1; client_install r004-sampleapp >/dev/null 2>&1
    local rc out marker
    marker=$(date +%s); sleep 1

    systemctl stop r004-snapshotd.socket "$UNIT"
    if [[ $FAMILY == apt ]]; then
        apt-get -q update >"$OUT/T1.log" 2>&1; rc=$?
        local fresh; fresh=$(grep -cE '^(Hit|Get):[0-9]+ http://deb\.debian\.org' "$OUT/T1.log")
        out=$(grep -m1 -E '^(W|E): .*127\.0\.0\.1:18080' "$OUT/T1.log")
        apt-get -q -y install --no-install-recommends tree >>"$OUT/T1.log" 2>&1; local rc2=$?
        apt-get -q -y purge tree >/dev/null 2>&1
        [[ $fresh -gt 0 && $rc2 -eq 0 ]]
        expect T1 $? "our service down: apt-get update rc=$rc, third-party indexes checked=$fresh, '$out'; install from Debian rc=$rc2"
    else
        dnf -y makecache --refresh >"$OUT/T1.log" 2>&1; rc=$?
        dnf -y install tree >>"$OUT/T1.log" 2>&1; local rc2=$?
        dnf -y --setopt=r004.skip_if_unavailable=True makecache --refresh >>"$OUT/T1.log" 2>&1; local rc3=$?
        dnf -y --setopt=r004.skip_if_unavailable=True install tree >>"$OUT/T1.log" 2>&1; local rc4=$?
        result T1 OBSERVED "our service down with skip_if_unavailable=False: makecache rc=$rc, install of a distro package rc=$rc2; with skip_if_unavailable=True: makecache rc=$rc3, install rc=$rc4"
        dnf -y remove tree >/dev/null 2>&1
    fi
    systemctl start r004-snapshotd.socket

    echo "not-a-generation!" >"$ROOT/repos/alpha/current"
    if [[ $FAMILY == apt ]]; then
        apt-get -q update >"$OUT/T2.log" 2>&1; rc=$?
        out=$(grep -m1 -E '503' "$OUT/T2.log")
    else
        dnf -y makecache --refresh >"$OUT/T2.log" 2>&1; rc=$?
        out=$(grep -m1 -iE '503|r004' "$OUT/T2.log")
    fi
    echo t1 >"$ROOT/repos/alpha/current"
    result T2 OBSERVED "invalid current pointer (fail closed): full update rc=$rc; '${out}'"

    systemctl disable --now r004-snapshotd.socket >/dev/null 2>&1; systemctl stop "$UNIT"
    rm -f /etc/systemd/system/r004-snapshotd.socket /etc/systemd/system/r004-snapshotd.service "$DROPIN/r004.conf"
    systemctl daemon-reload; rm -rf "${ROOT:?}"
    out=$(installed_version)
    if [[ $FAMILY == apt ]]; then
        apt-get -q update >"$OUT/T3a.log" 2>&1; rc=$?
    else
        dnf -y makecache --refresh >"$OUT/T3a.log" 2>&1; rc=$?
    fi
    result T3a OBSERVED "service removed, repository file left behind: full update rc=$rc; installed app still runs: version=$out"

    rm -f /etc/apt/sources.list.d/r004.sources /etc/apt/keyrings/r004-test.gpg /etc/yum.repos.d/r004.repo
    if [[ $FAMILY == apt ]]; then
        apt-get -q update >"$OUT/T3.log" 2>&1; rc=$?
        local errs; errs=$(grep -cE '^(E|W):' "$OUT/T3.log")
    else
        dnf -y makecache --refresh >"$OUT/T3.log" 2>&1; rc=$?
        local errs; errs=$(grep -ciE 'error' "$OUT/T3.log")
    fi
    out=$(installed_version)
    sha256sum /etc/apt/sources.list /etc/apt/sources.list.d/* /etc/yum.repos.d/* 2>/dev/null | grep -v r004 >"$OUT/third-party-after.sha256"
    diff -q "$OUT/third-party-before.sha256" "$OUT/third-party-after.sha256" >/dev/null; local same=$?
    [[ $rc -eq 0 && $errs -eq 0 && $out == 1.0 && $same -eq 0 ]]
    expect T3 $? "service, data, and repository file removed: full update rc=$rc, warnings/errors=$errs; installed app version=$out; third-party repository files unchanged=$([[ $same -eq 0 ]] && echo yes || echo no)"
}

for area in "$@"; do
    log "=== area $area"
    "area_$area" 2>>"$OUT/scenarios.log"
done
log "done; results in $OUT/results.tsv"
