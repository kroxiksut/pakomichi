#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P4-001 `pchi doctor` on a prepared P4-001a target (real units, reader on
# 879, no source, no GitHub): a healthy installation, a stopped and a failed
# reader socket, the recovery the doctor prints, a port mismatch, a state
# owner that does not answer, and the same diagnosis without root. The
# doctor must never change anything; only this script breaks and repairs,
# and `pchi doctor --repair` after `yes` at a terminal (D09-D12).
# Output: $P4001_OUT/results.tsv and the transcripts.
set -uo pipefail
# shellcheck source=../p4-001a/lib.sh
source /opt/p4001a/lib.sh
OUT=${P4001_OUT:-/tmp/p4001-out}
mkdir -p "$OUT"
: >"$OUT/results.tsv"
log="$OUT/transcript.txt"
: >"$log"

run() { # name, command...: runs it, keeps the transcript, sets $out and $rc
    local name=$1
    shift
    out=$("$@" 2>&1)
    rc=$?
    printf '### %s (exit %s)\n$ %s\n%s\n\n' "$name" "$rc" "$*" "$out" >>"$log"
}
units_digest() { systemctl show --property=ActiveState,Result -- pakomichi-*.socket pakomichi-state.service | sha256sum; }

run healthy pchi doctor
[[ $rc -eq 0 && $out == "no problems found" ]]
expect D01-healthy-has-nothing-to-fix $? "exit $rc; $out"

before=$(units_digest)
run unprivileged runuser -u nobody -- pchi doctor
[[ $rc -eq 0 && $out == "no problems found" && $(units_digest) == "$before" ]]
expect D02-without-root-the-same-and-nothing-changed $? "exit $rc"

systemctl stop pakomichi-reader.socket
run stopped pchi doctor
[[ $rc -eq 1 && $out == *"pakomichi-reader.socket is not listening"* ]]
expect D03-a-stopped-reader-socket $? "exit $rc"
systemctl start pakomichi-reader.socket

# A crash loop: the reader service always fails, the second trigger hits
# the start limit, and the socket goes to `failed` (N-034, N-029).
crash_reader() {
    install -d /run/systemd/system/pakomichi-reader.service.d
    printf '[Unit]\nStartLimitIntervalSec=60\nStartLimitBurst=1\n[Service]\nExecStart=\nExecStart=/bin/false\n' \
        >/run/systemd/system/pakomichi-reader.service.d/crash.conf
    systemctl daemon-reload
    for _ in 1 2 3; do (exec 3<>/dev/tcp/127.0.0.1/879) 2>/dev/null || true; sleep 1; done
}
crash_reader
state=$(systemctl show -P ActiveState pakomichi-reader.socket)/$(systemctl show -P Result pakomichi-reader.socket)
run failed pchi doctor
fix=$(sed -n 's/^  fix: \(systemctl reset-failed pakomichi-reader.service pakomichi-reader.socket && systemctl start pakomichi-reader.socket\) (as root)$/\1/p' <<<"$out")
[[ $rc -eq 1 && $out == *"the Pakomichi repositories are down"* && -n $fix ]]
expect D04-a-failed-reader-socket-is-an-outage-with-the-fix $? "socket $state; exit $rc"

# The fix the doctor printed, once the cause is gone, brings it back.
rm -f /run/systemd/system/pakomichi-reader.service.d/crash.conf
systemctl daemon-reload
bash -c "$fix"
run repaired pchi doctor
[[ $rc -eq 0 && $out == "no problems found" ]]
expect D05-the-printed-fix-repairs-it $? "exit $rc; $(systemctl show -P ActiveState pakomichi-reader.socket)"

install -d /run/systemd/system/pakomichi-reader.socket.d
printf '[Socket]\nListenStream=\nListenStream=127.0.0.1:880\n' \
    >/run/systemd/system/pakomichi-reader.socket.d/port.conf
systemctl daemon-reload
systemctl restart pakomichi-reader.socket
run mismatch pchi doctor
[[ $rc -eq 1 && $out == *"listens on port 880, but the APT sources of Pakomichi name port 879"* ]]
expect D06-a-reader-on-another-port $? "exit $rc"
rm -f /run/systemd/system/pakomichi-reader.socket.d/port.conf
systemctl daemon-reload
systemctl restart pakomichi-reader.socket

systemctl stop pakomichi-status.socket pakomichi-admin.socket pakomichi-state.service
run silent pchi doctor
[[ $rc -eq 1 && $out == *"the state owner does not answer on status.sock"* &&
    $out == *"pakomichi-status.socket is not listening"* ]]
expect D07-a-silent-state-owner-is-found-and-the-rest-still-checked $? "exit $rc"
systemctl start pakomichi-status.socket pakomichi-admin.socket

run back pchi doctor
[[ $rc -eq 0 ]]
expect D08-healthy-again $? "exit $rc; $out"

# `pchi doctor --repair` (N-029): run by the CLI as root after `yes` at a
# terminal, never through the service. The same crash loop as D04.
crash_reader
reader_state() { systemctl show -P ActiveState pakomichi-reader.socket; }
before=$(units_digest)
run repair-no-terminal pchi doctor --repair </dev/null
[[ $rc -eq 3 && $out == *"systemctl start pakomichi-reader.socket"* &&
    $(reader_state) == failed && $(units_digest) == "$before" ]]
expect D09-repair-without-a-terminal-changes-nothing $? "exit $rc; socket $(reader_state)"

run repair-unprivileged runuser -u nobody -- pchi doctor --repair </dev/null
[[ $rc -eq 1 && $out == *"needs root"* && $(reader_state) == failed &&
    $(units_digest) == "$before" ]]
expect D10-repair-without-root-is-refused-and-changes-nothing $? "exit $rc; socket $(reader_state)"

# Once the cause is gone, the confirmed repair brings the socket back.
rm -f /run/systemd/system/pakomichi-reader.service.d/crash.conf
systemctl daemon-reload
run repair-confirmed confirm pchi doctor --repair
[[ $rc -eq 0 &&
    $out == *"ran: systemctl reset-failed pakomichi-reader.service pakomichi-reader.socket"* &&
    $out == *"ran: systemctl start pakomichi-reader.socket"* && $(reader_state) == active ]]
expect D11-the-confirmed-repair-recovers-the-reader-socket $? "exit $rc; socket $(reader_state)"

run after-repair pchi doctor
[[ $rc -eq 0 && $out == "no problems found" ]]
expect D12-healthy-after-the-repair $? "exit $rc; $out"

cat "$OUT/results.tsv"
! grep -q FAIL "$OUT/results.tsv"
