#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P4-003a on Astra Linux with integrity control on (N-036, ADR-025):
#   B1 the applier unit (systemd, integrity level 63) applies;
#   B2 the same applier started at integrity level 0 (pdp-exec -l 0:0),
#      bypassing systemd, is refused every write: it answers
#      E_SECURITY_CONTEXT and /etc/apt is unchanged.
# Run as root after prepare.sh, with the harness in /opt/p4003a.
# Writes $OUT/results.tsv. Exit 1 on a FAIL.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p4003a/lib.sh
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin

mkdir -p "$OUT"
: >"$OUT/results.tsv"
apt_tree() { find /etc/apt -type f -print0 | sort -z | xargs -0 sha256sum; }
digests() {
    local first=1
    printf '['
    for file in "$KEYRING" "$OURS" "$PREFS"; do
        [[ -e $file ]] || continue
        [[ $first -eq 1 ]] || printf ','
        first=0
        printf '{"path":"%s","sha256":"%s"}' "$file" "$(sha256sum "$file" | cut -d' ' -f1)"
    done
    printf ']'
}

result B0-levels INFO "$(astra-modeswitch getname 2>&1 | tr '\n' ' ')/ mic: $(astra-mic-control status 2>&1 | tr '\n' ' ')/ service: $(systemd-run --wait --pipe --quiet /usr/bin/pdp-id 2>&1 | tr '\n' ' ')"

# B1: through the real unit.
line=$(owner apply "$DB" "$SOCKET" "$CONFIGS/one.json")
[[ $? -eq 0 && $line == verified* && -f $OURS ]]
expect B1-unit-applies $? "$line"

# B2: the same binary at integrity level 0, fed one connection by a
# small server that itself runs at level 0.
low=/tmp/p4003a-low
rm -rf "$low"
pdp-exec -l 0:0 -- install -d -m 0755 "$low"
cat >/opt/p4003a/low-server.py <<'PY'
import os, pwd, socket, sys
path, lock = sys.argv[1], sys.argv[2]
owner = pwd.getpwnam("pakomichi")
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
os.chown(path, owner.pw_uid, owner.pw_gid)
os.chmod(path, 0o600)
server.listen(1)
print("listening", flush=True)
connection, _ = server.accept()
os.dup2(connection.fileno(), 0)
os.dup2(connection.fileno(), 1)
applier = "/usr/local/bin/pakomichi-applier"
os.execv(applier, [applier, "--socket", path, "--lock", lock])
PY
pdp-exec -l 0:0 -- python3 /opt/p4003a/low-server.py "$low/apply.sock" "$low/apply.lock" \
    >"$OUT/low-server.out" 2>"$OUT/low-server.err" &
server=$!
for _ in $(seq 50); do [[ -S $low/apply.sock ]] && break; sleep 0.2; done
before=$(apt_tree)
# desired two, previous one, known = what the unit wrote in B1.
printf '{"schema_version":1,"type":"apply_apt","operation_id":"0123456789abcdef0123456789abcdef","desired":%s,"previous":%s,"known":%s}' \
    "$(cat "$CONFIGS/two.json")" "$(cat "$CONFIGS/one.json")" "$(digests)" >/tmp/p4003a-frame
chmod 0644 /tmp/p4003a-frame
line=$(owner raw "$low/apply.sock" /tmp/p4003a-frame)
wait "$server"
after=$(apt_tree)
[[ $line == *'"type":"rolled_back"'* && $line == *E_SECURITY_CONTEXT* && "$before" == "$after" ]]
expect B2-level-0-is-security-context $? "$line"
rm -f /tmp/p4003a-frame
pdp-ls -Md /etc/apt /etc/apt/keyrings "$low" >"$OUT/labels.txt" 2>&1
cp "$OUT/low-server.err" "$OUT/low-applier-stderr.txt" 2>/dev/null

# B3: the unit still works afterwards (nothing was left locked or staged).
line=$(owner apply "$DB" "$SOCKET" "$CONFIGS/two.json")
status=$?
leftover=$(find /etc/apt -name '*.pakomichi-new~' | wc -l)
[[ $status -eq 0 && $line == verified* && $leftover -eq 0 ]]
expect B3-unit-applies-after $? "$line; staging files: $leftover"

grep -q $'\tFAIL\t' "$OUT/results.tsv" && exit 1
exit 0
