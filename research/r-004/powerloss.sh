#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# R-004 power-loss check, run as root inside a disposable VM snapshot.
#   powerloss.sh load ROOT   publish generations in a loop; after each
#                            successful publish, append its ID to
#                            ROOT.ack and fsync that file
#   powerloss.sh verify ROOT after a hard power-off: every acknowledged
#                            generation and `current` must be intact
# The VM is powered off from the host while `load` runs.
set -uo pipefail

BIN=/usr/local/bin/r004-snapshotd
mode=$1 root=$2
ack="$root.ack"
src=/var/tmp/r004-pl-src

case "$mode" in
load)
    install -d -m 0750 "$root" "$src"
    touch "$ack"
    n=$(wc -l <"$ack")
    while true; do
        n=$((n + 1)); id="g$n-$(date +%s%N)"
        # files/ is a mutable path, so every generation may change its bytes.
        dir="$src/$id"; mkdir -p "$dir/files"
        # 4 objects of 256 KiB to 2 MiB with fresh random bytes.
        for i in 1 2 3 4; do head -c $(( (RANDOM % 8 + 1) * 262144 )) /dev/urandom >"$dir/files/f$i.bin"; done
        printf 'generation %s\n' "$id" >"$dir/index.txt"
        if "$BIN" publish "$root" pl "$id" "$dir" >/dev/null 2>>"$root.err"; then
            echo "$id" >>"$ack"; sync "$ack"
        fi
        rm -rf "$dir"
    done
    ;;
verify)
    acked=$(wc -l <"$ack")
    last=$(tail -1 "$ack")
    current=$(cat "$root/repos/pl/current" 2>/dev/null || echo none)
    "$BIN" check "$root" >"$root.check" 2>&1; check_rc=$?
    bad=$(grep -v -e '^staging leftover' -e '^check: ok' -e '^error: ' "$root.check" | grep -c .)
    leftovers=$(grep -c '^staging leftover' "$root.check")
    missing=0
    while read -r id; do
        [[ -f "$root/repos/pl/generations/$id.manifest" ]] || missing=$((missing + 1))
    done <"$ack"
    # `current` is switched (and fsynced) before publish returns, so it can
    # never be older than the last acknowledged generation.
    order=ok
    cur_n=${current%%-*}; last_n=${last%%-*}
    if [[ $cur_n == g* && $last_n == g* ]]; then
        (( ${cur_n#g} >= ${last_n#g} )) || order=older
    elif [[ -n $last ]]; then
        order=missing
    fi
    db=unavailable
    command -v sqlite3 >/dev/null && db=$(sqlite3 "$root/state.db" 'PRAGMA quick_check' 2>&1 | head -1)
    "$BIN" reconcile "$root" >"$root.reconcile" 2>&1; rec_rc=$?
    # reconcile rebuilds an unreadable state database and says so.
    grep -q 'unreadable state database' "$root.reconcile" && db=rebuilt-by-reconcile
    [[ $db == unavailable ]] && db=readable
    errors=$(sort "$root.err" 2>/dev/null | uniq -c | sort -rn | head -3 | tr -s ' ' | tr '\n' ';')
    "$BIN" check "$root" >/dev/null 2>&1; after_rc=$?
    echo "acknowledged=$acked last_ack=$last current=$current current_vs_last_ack=$order check_rc=$check_rc problems_other_than_staging=$bad staging_leftovers=$leftovers acknowledged_missing=$missing state_db=$db reconcile_rc=$rec_rc check_after_reconcile_rc=$after_rc publish_errors=${errors:-none}"
    ;;
*)
    echo "usage: powerloss.sh load|verify ROOT" >&2; exit 2 ;;
esac
