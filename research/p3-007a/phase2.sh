#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P3-007a (E2E-01) phase 2, after the new release was published on GitHub:
# `pchi sync` publishes it, and the distribution's ordinary update command
# (`apt update && apt upgrade` on Debian, ADR-022 point 4) installs it from
# Pakomichi: the native version, the exact bytes of the release asset, no
# change to APT configuration that is not Pakomichi's, and no change of
# publisher although another source offers a higher version, which the
# status names (N-027).
# Environment: NEW_VERSION, EXPECTED_SHA256 (GitHub's digest of the asset).
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p3007a/lib.sh
: "${NEW_VERSION:?}" "${EXPECTED_SHA256:?}"

api_budget
run sync confirm pchi sync "$SOURCE"
[[ $rc -eq 0 && $out == *"APT configuration"* ]]
expect E09-sync-takes-the-new-release $? "exit $rc"

run apt-update apt update
[[ $rc -eq 0 ]] && clean
expect E10-apt-update-is-clean $? "exit $rc"

run upgrade $UPGRADE
now=$(installed)
[[ $rc -eq 0 && $now == "$NEW_VERSION" ]]
expect E11-apt-upgrade-installs-the-new-release $? "installed $now"

# `apt` removes the downloaded file after installing it, and dpkg keeps no
# digest. APT checks the download against the SHA256 of the index it came
# from, so that index entry names the installed bytes; the same file is
# downloaded once more to hash what the reader serves.
run show apt-cache show "$PACKAGE=$NEW_VERSION"
indexed=$(awk '/^SHA256:/ {print $2; exit}' <<<"$out")
download=$(mktemp -d)
(cd "$download" && apt-get download "$PACKAGE=$NEW_VERSION" >/dev/null 2>&1)
served=$(sha256sum "$download/${PACKAGE}_${NEW_VERSION}_all.deb" 2>/dev/null | cut -d' ' -f1)
rm -rf "$download"
[[ $indexed == "$EXPECTED_SHA256" && $served == "$EXPECTED_SHA256" ]]
expect E12-the-bytes-are-the-release-asset $? "index $indexed; served $served"

run policy apt-cache policy "$PACKAGE"
from_us=$(grep -A1 -E "^ \*\*\* $NEW_VERSION 990\$" <<<"$out" | tail -1)
[[ $from_us == *"http://127.0.0.1:$PORT/pakomichi-$SOURCE-"* ]]
expect E13-installed-from-pakomichi-at-990 $? "$(tr -s " " <<<"$from_us")"

[[ $out == *" $OTHER_VERSION "* && $now != "$OTHER_VERSION" ]]
expect E14-the-higher-version-elsewhere-is-not-taken $? "installed $now; other $OTHER_VERSION"

run full-upgrade apt full-upgrade -s
! grep -q "^Inst $PACKAGE " <<<"$out"
expect E15-full-upgrade-keeps-the-publisher $? "$(grep "^Inst $PACKAGE " <<<"$out")"

# The status is refreshed by an operation; this one changes nothing.
api_budget
run sync-again confirm pchi sync
[[ $rc -eq 0 && $out == *"APT configuration unchanged"* ]]
expect E16-second-sync-changes-nothing $? "exit $rc"

run status pchi status
notice=$(grep "notice: $PACKAGE $OTHER_VERSION is offered by file:$OTHER" <<<"$out")
[[ -n $notice ]]
expect E17-status-names-the-other-source-and-version $? "$(tr -s " " <<<"$notice")"
! grep -q PROBLEM <<<"$out"
expect E18-status-shows-no-broken-promise $? "$(grep PROBLEM <<<"$out" | tr -s " ")"

foreign_config >"$OUT/foreign-after.sha256"
diff "$OUT/foreign-before.sha256" "$OUT/foreign-after.sha256" >"$OUT/foreign.diff"
expect E19-foreign-apt-configuration-unchanged $? "$(wc -l <"$OUT/foreign-after.sha256") files"

eval "$(apt-config shell enable APT::Get::EnableUpgrade)"
[[ ${enable:-} != true && ${enable:-} != 1 ]]
expect E20-no-enable-upgrade $? "APT::Get::EnableUpgrade=${enable:-unset}"

journalctl -q -u pakomichi-state.service -o cat >"$OUT/state.log"
journalctl -q -u 'pakomichi-apply@*' -o cat >"$OUT/applier.log"
cp -r /etc/apt/sources.list.d /etc/apt/preferences.d "$OUT/" 2>/dev/null
cat "$OUT/results.tsv"
! grep -q FAIL "$OUT/results.tsv"
