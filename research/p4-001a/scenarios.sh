#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P4-001a step 1e: the APT slice end to end on a real GitHub source.
# `pchi source add` finds and confirms the Attested signer, `pchi sync`
# proposes the family and publishes nothing, `pchi source activate`
# approves exactly the named package, publishes it, and pins it, and
# `apt-get install` then takes it from Pakomichi. Confirmations are typed
# at a terminal; `--yes` and a missing terminal change nothing.
# Output: $P4001A_OUT/results.tsv and the command transcripts.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p4001a/lib.sh
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
ours() { ls /etc/apt/sources.list.d/pakomichi-* /etc/apt/preferences.d/pakomichi-* 2>/dev/null; }

run status pchi status
[[ $rc -eq 0 && $out == *"no sources"* ]]
expect S01-status-empty $? "exit $rc"

run add-yes pchi source add "$URL" --yes
[[ $rc -eq 2 ]]
expect S02-yes-is-refused $? "exit $rc"

run add-no-tty pchi source add "$URL" </dev/null
[[ $rc -eq 3 ]] && ! pchi source list | grep -q "$SOURCE"
expect S03-no-terminal-changes-nothing $? "exit $rc"

run add confirm pchi source add "$URL"
signer=$(pchi source list | grep -o 'signer=[^ ]*')
[[ $rc -eq 0 && $signer == signer=.github/workflows/* ]]
expect S04-add-confirms-the-signer $? "exit $rc; $signer"

run activate-early pchi source activate "$SOURCE" --packages "$PACKAGE" </dev/null
[[ $rc -eq 1 && $out == *"pchi sync $SOURCE first"* ]]
expect S05-activate-needs-a-sync $? "exit $rc"

run sync confirm pchi sync "$SOURCE"
[[ $rc -eq 0 && -z "$(ours)" ]]
expect S06-sync-proposes-and-publishes-nothing $? "exit $rc; files: $(ours | tr '\n' ' ')"

run activate-unknown pchi source activate "$SOURCE" --packages "$PACKAGE-tools" </dev/null
[[ $rc -eq 1 && $out == *"never offered"* ]]
expect S07-unknown-name-is-refused $? "exit $rc"

run activate confirm pchi source activate "$SOURCE" --packages "$PACKAGE"
pref=/etc/apt/preferences.d/pakomichi-$SOURCE.pref
pinned=$(grep -h '^Package:\|^Pin:' "$pref" 2>/dev/null | tr '\n' ' ')
[[ $rc -eq 0 && $pinned == *"Package: $PACKAGE"*"l=pakomichi-$SOURCE-attested"* ]]
expect S08-activate-publishes-and-pins $? "exit $rc; $pinned"

run apt-update apt-get update
[[ $rc -eq 0 && $out != *"W: "* && $out != *"E: "* ]]
expect S09-apt-update-is-clean $? "exit $rc"

run policy apt-cache policy "$PACKAGE"
candidate=$(awk '/Candidate:/ {print $2}' <<<"$out")
# APT prints the pin on the version line and the repository's own priority
# (100, NotAutomatic with ButAutomaticUpgrades) on the source line under it.
pinned_line=$(grep -A1 -E "^ +(\*\*\* )?$candidate 990\$" <<<"$out" | tail -1)
[[ $candidate != "(none)" && $pinned_line == *"http://127.0.0.1:18080/pakomichi-$SOURCE-attested "* ]]
expect S10-candidate-from-pakomichi-at-990 $? "candidate $candidate"

run install apt-get install -y "$PACKAGE"
installed=$(dpkg-query -W -f '${Version}' "$PACKAGE" 2>/dev/null)
[[ $rc -eq 0 && $installed == "$candidate" ]]
expect S11-apt-installs-it $? "installed $installed"

run status-after pchi status
[[ $out == *"activated=$PACKAGE"* ]]
expect S12-status-shows-the-activation $? "$(grep "$SOURCE" <<<"$out")"

run sync-again confirm pchi sync
[[ $rc -eq 0 && $out == *"APT configuration unchanged"* ]]
expect S13-second-sync-changes-nothing $? "exit $rc"

journalctl -q -u pakomichi-state.service -o cat >"$OUT/state.log"
journalctl -q -u 'pakomichi-apply@*' -o cat >"$OUT/applier.log"
cp -r /etc/apt/sources.list.d /etc/apt/preferences.d "$OUT/" 2>/dev/null
cat "$OUT/results.tsv"
! grep -q FAIL "$OUT/results.tsv"
