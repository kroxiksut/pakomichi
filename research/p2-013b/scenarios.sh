#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P2-013b acceptance on one target: the process layout of ADR-035 with its
# real systemd units.
#   E1  socket modes and owners of sign.sock, inspect.sock, fetch.sock
#   E2  the state owner signs through sign.sock; root gets no answer, other
#       users cannot connect
#   E3  the metadata key is unreadable to the state owner's user
#   E4  a signer whose key directory others can enter refuses to sign
#   E5  the state owner inspects through inspect.sock; root gets no answer
#   E6  the inspector instance has no network and a read-only system
#   E7  a package missing from the CAS is fetched from GitHub through
#       fetch.sock while apt-get installs it, and served verified
#   E8  fetch.sock: an unpinned digest is refused, root gets no answer
#   E9  every unprivileged process refuses to run as root
# Run as root inside the target after prepare.sh.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p2013b/lib.sh

mkdir -p "$OUT"
: >"$OUT/results.tsv"
{ grep PRETTY_NAME /etc/os-release; systemctl --version | head -1; sha256sum /usr/local/bin/pakomichi-*; } \
    >"$OUT/environment.txt" 2>&1
as() { runuser -u "$1" -- "${@:2}"; }
since=$(date +%s)

# ---------------------------------------------------------------- E1
modes=$(stat -c '%n %a %U' /run/pakomichi/sign.sock /run/pakomichi/inspect.sock /run/pakomichi/fetch.sock | tr '\n' ';')
[[ $modes == "/run/pakomichi/sign.sock 600 pakomichi;/run/pakomichi/inspect.sock 600 pakomichi;/run/pakomichi/fetch.sock 600 pakomichi-reader;" ]]
expect E1 $? "$modes"

# ---------------------------------------------------------------- E2
printf 'Origin: Pakomichi\nLabel: p2013b\n' >/srv/p2013b/release
chmod 0644 /srv/p2013b/release
install -d -o pakomichi -m 0700 /srv/p2013b/out
signed=$(as pakomichi /usr/local/bin/p2013b-call sign /run/pakomichi/sign.sock /srv/p2013b/release /srv/p2013b/out/InRelease 2>&1); src=$?
gpgv --keyring "$KEYRING" /srv/p2013b/out/InRelease >"$OUT/E2.gpgv" 2>&1; vrc=$?
root=$(call sign /run/pakomichi/sign.sock /srv/p2013b/release /srv/p2013b/root.InRelease); rrc=$?
other=$(as pakomichi-reader /usr/local/bin/p2013b-call sign /run/pakomichi/sign.sock /srv/p2013b/release /tmp/x 2>&1); orc=$?
journalctl -q --since "@$since" -u 'pakomichi-sign@*' -o cat >"$OUT/E2.journal" 2>&1
grep -q 'peer uid 0 refused' "$OUT/E2.journal"; seen=$?
[[ $src -eq 0 && $vrc -eq 0 && $rrc -ne 0 && $orc -ne 0 && $seen -eq 0 && ! -e /srv/p2013b/root.InRelease ]]
expect E2 $? "pakomichi: $signed, gpgv rc=$vrc; root: rc=$rrc ($root), refusal logged rc=$seen; pakomichi-reader: rc=$orc ($other)"

# ---------------------------------------------------------------- E3
as pakomichi ls /var/lib/pakomichi-signer/gnupg >"$OUT/E3.log" 2>&1; lrc=$?
as pakomichi cat /var/lib/pakomichi-signer/gnupg/pubring.kbx >/dev/null 2>>"$OUT/E3.log"; crc=$?
modes=$(stat -c '%a %U' /var/lib/pakomichi-signer /var/lib/pakomichi-signer/gnupg | tr '\n' ';')
[[ $lrc -ne 0 && $crc -ne 0 && $modes == "700 pakomichi-signer;700 pakomichi-signer;" ]]
expect E3 $? "state owner lists the key dir rc=$lrc, reads the keyring rc=$crc; $modes"

# ---------------------------------------------------------------- E4
since=$(date +%s)
chmod 0750 /var/lib/pakomichi-signer/gnupg
open=$(as pakomichi /usr/local/bin/p2013b-call sign /run/pakomichi/sign.sock /srv/p2013b/release /srv/p2013b/out/open 2>&1); orc=$?
chmod 0700 /var/lib/pakomichi-signer/gnupg
sleep 1
journalctl -q --since "@$since" -u 'pakomichi-sign@*' -o cat >"$OUT/E4.journal" 2>&1
grep -q 'open to group or others' "$OUT/E4.journal"; seen=$?
[[ $orc -ne 0 && $seen -eq 0 && ! -e /srv/p2013b/out/open ]]
expect E4 $? "key dir 0750: sign rc=$orc ($open), refusal logged rc=$seen"

# ---------------------------------------------------------------- E5
since=$(date +%s)
inspected=$(as pakomichi /usr/local/bin/p2013b-call inspect /run/pakomichi/inspect.sock "$SHA" "$SIZE" 2>&1); irc=$?
root=$(call inspect /run/pakomichi/inspect.sock "$SHA" "$SIZE"); rrc=$?
sleep 1
journalctl -q --since "@$since" -u 'pakomichi-inspect@*' -o cat >"$OUT/E5.journal" 2>&1
[[ $irc -eq 0 && $inspected == "deb pakomichi-r003-fixture 0.2.0 all scripts=0" && $rrc -ne 0 ]] &&
    grep -q 'peer uid 0 refused' "$OUT/E5.journal"
expect E5 $? "pakomichi: $inspected; root: rc=$rrc ($root)"

# ---------------------------------------------------------------- E6
props=$(systemctl show 'pakomichi-inspect@probe.service' -p DynamicUser -p PrivateNetwork -p ProtectSystem \
    -p RestrictAddressFamilies -p ReadOnlyPaths | sort | tr '\n' ';')
printf '%s\n' "$props" >"$OUT/E6.props"
[[ $props == *"DynamicUser=yes"* && $props == *"PrivateNetwork=yes"* && $props == *"ProtectSystem=strict"* &&
    $props == *"RestrictAddressFamilies=AF_UNIX"* ]]
expect E6 $? "$props"

# ---------------------------------------------------------------- E7
since=$(date +%s)
rm -f "$CAS/objects/$SHA"
apt-get -q update -o Dir::Etc::sourcelist="$SOURCES" -o Dir::Etc::sourceparts=- >"$OUT/E7.log" 2>&1
apt-get -q -y install -o Dir::Etc::sourcelist="$SOURCES" -o Dir::Etc::sourceparts=- pakomichi-r003-fixture \
    >>"$OUT/E7.log" 2>&1; rc=$?
version=$(dpkg-query -W -f '${Version}' pakomichi-r003-fixture 2>/dev/null)
stored=$(sha256sum "$CAS/objects/$SHA" 2>/dev/null | cut -d' ' -f1)
journalctl -q --since "@$since" -u pakomichi-reader.service -u pakomichi-state.service -o cat >"$OUT/E7.journal" 2>&1
[[ $rc -eq 0 && $version == 0.2.0 && $stored == "$SHA" ]]
expect E7 $? "object removed; apt-get install rc=$rc version=$version; refetched object ${stored:0:12}"

# ---------------------------------------------------------------- E8
unpinned=$(as pakomichi-reader /usr/local/bin/p2013b-call fetch /run/pakomichi/fetch.sock "$(printf 'x' | sha256sum | cut -d' ' -f1)" 1 2>&1); urc=$?
root=$(call fetch /run/pakomichi/fetch.sock "$SHA" "$SIZE"); rrc=$?
[[ $urc -ne 0 && $unpinned == "failed 500 no pinned asset for this object"* && $rrc -ne 0 && $root == "failed 503"* ]]
expect E8 $? "unpinned: $unpinned; root: $root"

# ---------------------------------------------------------------- E9
refusals=""
for binary in pakomichi-reader pakomichi-state pakomichi-signer pakomichi-inspector; do
    output=$(/usr/local/bin/$binary --socket /run/pakomichi/sign.sock --cas-root "$CAS" --publish-root "$PUBLISH" 2>&1)
    [[ $output == *"refusing to run as root"* ]] && refusals+="$binary "
done
[[ $(wc -w <<<"$refusals") -eq 4 ]]
expect E9 $? "refused as root: $refusals"

fails=$(grep -c $'\tFAIL\t' "$OUT/results.tsv")
echo "P2-013b $(hostname): $(grep -c $'\tPASS\t' "$OUT/results.tsv") PASS, $fails FAIL"
[[ $fails -eq 0 ]]
