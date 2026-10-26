#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P2-011b (E2E-07) phase 2, after the second release of the Pinned source
# was published on GitHub: the consent of phase 1 does not approve it.
# `pchi sync` holds it with `E_RELEASE_APPROVAL_REQUIRED` and prints its
# approve line, and the ordinary update command keeps the first version
# (N-039). After the approval, `apt update && apt upgrade` installs exactly
# the second release's bytes from the Pinned repository at 990.
# Environment: FIRST_VERSION, SECOND_VERSION, SECOND_RELEASE_ID,
# FIRST_RELEASE_ID, SECOND_SHA256 (GitHub's digest), P2011B_OUT.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p2011b/lib.sh
: "${FIRST_VERSION:?}" "${FIRST_RELEASE_ID:?}" "${SECOND_VERSION:?}" "${SECOND_RELEASE_ID:?}" "${SECOND_SHA256:?}"
load_source
second_tag=$(tag "$SECOND_VERSION")
second_asset=$(asset "$SECOND_VERSION")
first_tag=$(tag "$FIRST_VERSION")

# 10. The new release waits; the approved one stays.
api_budget
run sync-second confirm pchi sync "$SRC"
[[ $rc -eq 0 && $out == *"$(approve_line "$second_tag" "$SECOND_RELEASE_ID")"* &&
    $out != *"$(approve_line "$first_tag" "$FIRST_RELEASE_ID")"* && $out == *E_RELEASE_APPROVAL_REQUIRED* ]]
expect P10a-second-release-waits-for-approval $? "exit $rc; $(grep 'waits for approval' <<<"$out" | tr -d '\r' | tr '\n' ' ')"

snapshot P10-before-upgrade
run apt-update-unapproved apt update
update_rc=$rc
update_clean=$(clean && echo yes)
run upgrade-unapproved apt upgrade -y
snapshot P10-after-upgrade
now=$(installed)
[[ $update_rc -eq 0 && $update_clean == yes && $rc -eq 0 && $now == "$FIRST_VERSION" ]]
expect P10b-apt-upgrade-keeps-the-approved-version $? "apt update exit $update_rc, clean ${update_clean:-no}; upgrade exit $rc; installed ${now:-none}"

run madison-unapproved apt-cache madison "$PACKAGE"
! grep -qE "\| +$SECOND_VERSION +\|" <<<"$out"
expect P10c-the-unapproved-version-is-not-offered $? "$(tr -s ' ' <<<"$out" | tr '\n' ';')"

# 11. Approving the second release lists only its asset.
api_budget
run approve-second confirm pchi release approve "$SRC" "$SECOND_RELEASE_ID"
listed=$(approvals)
[[ $rc -eq 0 && $(wc -l <<<"$listed") -eq 1 && $listed == *" approve_release $second_asset (new: ${SECOND_SHA256:0:12})"* &&
    $out == *"approve release $second_tag ($SECOND_RELEASE_ID) of $SRC"* ]]
expect P11a-approve-lists-the-second-asset-and-its-digest $? "exit $rc; $(tr -s ' ' <<<"$listed")"

snapshot P11-before-upgrade
run apt-update apt update
update_rc=$rc
update_clean=$(clean && echo yes)
run upgrade apt upgrade -y
snapshot P11-after-upgrade
now=$(installed)
[[ $update_rc -eq 0 && $update_clean == yes && $rc -eq 0 && $now == "$SECOND_VERSION" ]]
expect P11b-apt-upgrade-installs-the-approved-release $? "upgrade exit $rc; installed ${now:-none}; dpkg: $(dpkg_change P11-before-upgrade P11-after-upgrade)"

served "$SECOND_VERSION"
[[ $indexed == "$SECOND_SHA256" && $downloaded == "$SECOND_SHA256" ]]
expect P11c-the-bytes-are-the-approved-asset $? "index $indexed; served $downloaded; github $SECOND_SHA256"

run policy apt-cache policy "$PACKAGE"
from=$(policy_source "$SECOND_VERSION")
[[ $from == *"http://127.0.0.1:$PORT/$LABEL "* ]]
expect P11d-installed-from-the-pinned-repository-at-990 $? "$from"

finish phase2
