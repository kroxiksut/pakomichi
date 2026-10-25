#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P4-003a scenarios on a prepared target: the state owner's side (as user
# pakomichi) drives the root applier behind the real apply.sock units.
# Writes $OUT/results.tsv: scenario, PASS/FAIL, detail. Exit 1 on a FAIL.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p4003a/lib.sh

mkdir -p "$OUT"
: >"$OUT/results.tsv"
distribution_before=$(sha256sum /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list 2>/dev/null)
passwd_before=$(sha256sum /etc/passwd)

# A1: the first apply writes our three files, APT accepts them.
line=$(owner apply "$DB" "$SOCKET" "$CONFIGS/one.json")
status=$?
apt-cache policy >/dev/null 2>&1
apt_status=$?
[[ $status -eq 0 && $line == verified* && -f $OURS && -f $PREFS && -f $KEYRING && $apt_status -eq 0 ]]
expect A1-first-apply $? "$line; apt-cache policy exit $apt_status"

# A2: the files are what render() makes: loopback URI, our keyring, our
# origin pin at 990, root-owned 0644.
grep -qx 'URIs: http://127.0.0.1:18080/pakomichi-sampleapp-strict' "$OURS" &&
    grep -qx "Signed-By: $KEYRING" "$OURS" &&
    grep -qx 'Pin: release o=Pakomichi,l=pakomichi-sampleapp-strict' "$PREFS" &&
    grep -qx 'Pin-Priority: 990' "$PREFS" &&
    [[ "$(stat -c '%U %a' "$OURS" "$PREFS" "$KEYRING" | sort -u)" == "root 644" ]]
expect A2-rendered-files $? "$(stat -c '%n %U %a' "$OURS" "$PREFS" "$KEYRING" | tr '\n' ';')"
after_one=$(snapshot)

# A3 (N-024): a foreign sources file sets another Signed-By for the URI
# that the next configuration adds; APT refuses the result, and the
# previous configuration comes back byte for byte.
cat >/etc/apt/sources.list.d/zz-p4003a-conflict.sources <<'SRC'
Types: deb
URIs: http://127.0.0.1:18080/pakomichi-sampleapp-attested
Suites: pakomichi-sampleapp-attested
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
SRC
apt-cache policy >/dev/null 2>&1
alone=$?
line=$(owner apply "$DB" "$SOCKET" "$CONFIGS/two.json")
status=$?
apt-cache policy >/dev/null 2>&1
apt_status=$?
[[ $alone -eq 0 && $status -ne 0 && $line == "rolled_back E_ADMIN_APPLY_FAILED"* && $line == *Signed-By* &&
    "$(snapshot)" == "$after_one" && $apt_status -eq 0 ]]
expect A3-apt-refuses-rollback $? "$line"
rm -f /etc/apt/sources.list.d/zz-p4003a-conflict.sources

# A4: the same configuration without the conflict.
line=$(owner apply "$DB" "$SOCKET" "$CONFIGS/two.json")
[[ $? -eq 0 && $line == verified* ]] && grep -q 'sampleapp-data' "$PREFS"
expect A4-update $? "$line"
after_two=$(snapshot)

# A5 (N-021 for our files): a hand-edited file is drift; nothing is
# written, the edit stays, and after it is undone the apply goes through.
cp -p "$OURS" /tmp/p4003a-ours
echo '# local edit' >>"$OURS"
edited=$(sha256sum "$OURS")
line=$(owner apply "$DB" "$SOCKET" "$CONFIGS/three.json")
status=$?
[[ $status -ne 0 && $line == "drifted changed:$OURS" && "$(sha256sum "$OURS")" == "$edited" &&
    "$(sha256sum "$KEYRING")" == "$(grep -F "$KEYRING" <<<"$after_two")" &&
    "$(sha256sum "$PREFS")" == "$(grep -F "$PREFS" <<<"$after_two")" ]]
expect A5-drift-not-overwritten $? "$line"
cp -p /tmp/p4003a-ours "$OURS"
rm -f /tmp/p4003a-ours
line=$(owner apply "$DB" "$SOCKET" "$CONFIGS/three.json")
[[ $? -eq 0 && $line == verified* ]] && grep -q 'sampleapp-doc' "$PREFS"
expect A5b-after-undo $? "$line"
after_three=$(snapshot)

# A6: root is not the state owner: the instance refuses the peer before
# the first frame and answers nothing.
printf '{"schema_version":1,"type":"apply_apt"}' >/tmp/p4003a-frame
line=$(/usr/local/bin/p4003a-call raw "$SOCKET" /tmp/p4003a-frame 2>&1)
sleep 1
refused=$(journalctl -q -u 'pakomichi-apply@*' -o cat | grep -c 'peer uid 0 refused')
[[ $line == closed* && $refused -ge 1 && "$(snapshot)" == "$after_three" ]]
expect A6-root-peer-refused $? "$line; journal refusals=$refused"

# A7: another user cannot even open the socket (mode 0600).
line=$(runuser -u nobody -- /usr/local/bin/p4003a-call raw "$SOCKET" /tmp/p4003a-frame 2>&1)
[[ $line == *"Permission denied"* ]]
expect A7-other-user-cannot-connect $? "$line"

# A8: a request that records a system file as ours (it would be removed
# as "no longer wanted") is invalid; the file stays.
passwd_sha=$(sha256sum /etc/passwd | cut -d' ' -f1)
empty='{"port":18080,"keyring_hex":"","sources":[]}'
printf '{"schema_version":1,"type":"apply_apt","operation_id":"0123456789abcdef0123456789abcdef","desired":%s,"previous":%s,"known":[{"path":"/etc/passwd","sha256":"%s"}]}' \
    "$empty" "$empty" "$passwd_sha" >/tmp/p4003a-frame
chmod 0644 /tmp/p4003a-frame
line=$(owner raw "$SOCKET" /tmp/p4003a-frame)
[[ $line == *'"type":"invalid"'* && "$(sha256sum /etc/passwd)" == "$passwd_before" && "$(snapshot)" == "$after_three" ]]
expect A8-foreign-path-refused $? "$line"

# A9: an unknown field anywhere is refused before anything is read.
printf '{"schema_version":1,"type":"apply_apt","operation_id":"0123456789abcdef0123456789abcdef","desired":{"port":18080,"keyring_hex":"","sources":[],"uris":"http://mirror.example/"},"previous":%s,"known":[]}' \
    "$empty" >/tmp/p4003a-frame
line=$(owner raw "$SOCKET" /tmp/p4003a-frame)
[[ $line == *'"type":"error"'* && $line == *malformed* && "$(snapshot)" == "$after_three" ]]
expect A9-unknown-field-refused $? "$line"
rm -f /tmp/p4003a-frame

# A10: the applier writes but its answer is lost; the operation stays
# open, nothing new may start, and recovery settles it.
line=$(owner lose-answer "$DB" "$SOCKET" "$CONFIGS/one.json")
open=$(owner status "$DB")
blocked=$(owner apply "$DB" "$SOCKET" "$CONFIGS/two.json")
recovered=$(owner recover "$DB" "$SOCKET")
status=$?
[[ $open == open=1* && $blocked == *unfinished* && $status -eq 0 && $recovered == "recovered 1 "*reconciled &&
    "$(snapshot)" == "$after_one" && "$(owner status "$DB")" == open=0* ]]
expect A10-lost-answer-recovered $? "$line; $open; $blocked; $recovered"

# A11: a crash after the intent, before the applier was asked.
owner begin-only "$DB" "$CONFIGS/two.json" >/dev/null
recovered=$(owner recover "$DB" "$SOCKET")
[[ $? -eq 0 && $recovered == "recovered 1 "*reconciled && "$(snapshot)" == "$after_two" ]]
expect A11-intent-only-recovered $? "$recovered"

# A12: the applier refuses to run as anyone but root.
line=$(runuser -u pakomichi -- /usr/local/bin/pakomichi-applier --socket "$SOCKET" --lock /run/pakomichi/apply.lock </dev/null 2>&1)
[[ $? -ne 0 && $line == *"must run as root"* ]]
expect A12-applier-not-root-refused $? "$line"

# A13: a socket owned by root would admit root as the state owner.
rm -f /run/p4003a-root.sock
python3 -c 'import socket; s = socket.socket(socket.AF_UNIX); s.bind("/run/p4003a-root.sock")'
line=$(/usr/local/bin/pakomichi-applier --socket /run/p4003a-root.sock --lock /run/pakomichi/apply.lock </dev/null 2>&1)
[[ $? -ne 0 && $line == *"belongs to root"* ]]
expect A13-root-socket-refused $? "$line"
rm -f /run/p4003a-root.sock

# A14: removing every source leaves none of our files and the
# distribution's own sources as they were.
line=$(printf '{"port":18080,"keyring_hex":"","sources":[]}' >/tmp/p4003a-empty.json; chmod 0644 /tmp/p4003a-empty.json; owner apply "$DB" "$SOCKET" /tmp/p4003a-empty.json)
status=$?
rm -f /tmp/p4003a-empty.json
[[ $status -eq 0 && $line == verified* && ! -e $OURS && ! -e $PREFS && ! -e $KEYRING &&
    "$(sha256sum /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list 2>/dev/null)" == "$distribution_before" ]]
expect A14-remove-all $? "$line"

# A15: no staging file is left anywhere we write.
leftover=$(find /etc/apt -name '*.pakomichi-new~' | wc -l)
[[ $leftover -eq 0 ]]
expect A15-no-staging-left $? "staging files: $leftover"

systemd-analyze security pakomichi-apply@x.service 2>/dev/null | tail -1 >"$OUT/security.txt" || true
journalctl -q -u 'pakomichi-apply@*' -o cat >"$OUT/applier-journal.txt" || true
result A16-exposure INFO "$(cat "$OUT/security.txt")"

grep -q $'\tFAIL\t' "$OUT/results.tsv" && exit 1
exit 0
