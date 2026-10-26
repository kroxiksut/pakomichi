#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P3-007a (E2E-01) phase 1, before the new release exists: the source is
# added, synchronized, and activated; `apt install` takes the current
# release from Pakomichi. Then another source starts to offer a higher
# version of the same name (N-027), and the APT configuration that is not
# Pakomichi's is recorded for phase 2.
# Environment: NEW_VERSION (the release phase 2 expects).
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p3007a/lib.sh
: "${NEW_VERSION:?}"
mkdir -p "$OUT"
: >"$OUT/results.tsv"
: >"$log"

api_budget
run add confirm pchi source add "$URL"
[[ $rc -eq 0 ]]
expect E01-add-confirms-the-source $? "exit $rc; $(pchi source list | grep -o 'signer=[^ ]*')"

api_budget
run sync confirm pchi sync "$SOURCE"
[[ $rc -eq 0 ]]
expect E02-first-sync $? "exit $rc"

# The activation publishes; the pin waits until APT lists the name and can
# show that no other source offers an equal version (ADR-022 point 1).
api_budget
run activate confirm pchi source activate "$SOURCE" --packages "$PACKAGE"
pref=/etc/apt/preferences.d/pakomichi-$SOURCE.pref
[[ $rc -eq 0 && ! -e $pref && $out == *"run apt update, then pchi sync"* ]]
expect E03-activate-publishes-and-the-pin-waits $? "exit $rc; pref $([[ -e $pref ]] && echo present || echo absent)"

run apt-update apt update
[[ $rc -eq 0 ]] && clean
expect E04-apt-update-is-clean $? "exit $rc"

api_budget
run sync-pin confirm pchi sync "$SOURCE"
[[ $rc -eq 0 && -f $pref ]]
expect E04b-sync-pins-once-apt-lists-it $? "exit $rc; $(grep -h '^Pin' "$pref" 2>/dev/null | tr '\n' ' ')"

run install apt install -y "$PACKAGE"
old=$(installed)
[[ $rc -eq 0 && -n $old ]] && dpkg --compare-versions "$old" lt "$NEW_VERSION"
expect E05-apt-installs-the-current-release $? "installed $old"

# N-027: a higher version of the activated name appears in another source.
run other-source bash /opt/p3007a/other-source.sh
run apt-update-other apt update
[[ $rc -eq 0 ]] && clean
expect E06-other-source-is-read $? "exit $rc"

run policy apt-cache policy "$PACKAGE"
candidate=$(awk '/Candidate:/ {print $2}' <<<"$out")
[[ $candidate == "$old" && $out == *" $OTHER_VERSION "* ]]
expect E07-the-pin-keeps-the-publisher $? "candidate $candidate; other $OTHER_VERSION listed"

# The ordinary update command with only the other source's higher version
# on offer; it also brings the system up to date, so that phase 2 sees
# only the new release (a distribution keyring update would change
# /etc/apt on its own).
run upgrade-other $UPGRADE
[[ $rc -eq 0 && $(installed) == "$old" ]]
expect E08-apt-upgrade-keeps-the-publisher $? "installed $(installed)"

foreign_config >"$OUT/foreign-before.sha256"
printf '%s\n' "$old" >"$OUT/old-version"
cat "$OUT/results.tsv"
! grep -q FAIL "$OUT/results.tsv"
