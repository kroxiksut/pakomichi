#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P2-011b (E2E-07) phase 3, after the asset of the approved second release
# was replaced on GitHub with other bytes of the same name (no
# attestation): the approval binds to the approved digest only (N-039).
# `pchi sync --force` reports the replaced asset as `E_ASSET_MUTATED` and
# does not offer the new bytes for approval; the ordinary update command
# keeps the approved version, the reader still serves the approved bytes,
# and no index names the new ones; the status keeps the consent and shows
# no broken promise.
# Environment: SECOND_VERSION, SECOND_RELEASE_ID, SECOND_SHA256 (the
# approved digest), REPLACED_SHA256 (GitHub's digest of the replacement),
# P2011B_OUT.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p2011b/lib.sh
: "${SECOND_VERSION:?}" "${SECOND_RELEASE_ID:?}" "${SECOND_SHA256:?}" "${REPLACED_SHA256:?}"
load_source
second_tag=$(tag "$SECOND_VERSION")

# The bed is meaningful only if GitHub now states other bytes.
[[ $REPLACED_SHA256 =~ ^[0-9a-f]{64}$ && $REPLACED_SHA256 != "$SECOND_SHA256" ]]
expect P12-the-asset-was-replaced-with-other-bytes $? "approved $SECOND_SHA256; now $REPLACED_SHA256"

# 12. The replaced asset is E_ASSET_MUTATED, not a new release to approve.
api_budget
run sync-mutated confirm pchi sync "$SRC" --force
[[ $out == *E_ASSET_MUTATED* ]]
expect P12a-sync-reports-the-replaced-asset $? "exit $rc; $(grep -o '\[E_[A-Z_, ]*\]' <<<"$out" | tr -d '\r')"
[[ $out != *"$(approve_line "$second_tag" "$SECOND_RELEASE_ID")"* ]]
expect P12b-the-new-bytes-are-not-offered-for-approval $? "$(grep 'waits for approval' <<<"$out" | tr -d '\r' | tr '\n' ' ')"

snapshot P12-before-upgrade
run apt-update apt update
update_rc=$rc
update_clean=$(clean && echo yes)
run upgrade apt upgrade -y
snapshot P12-after-upgrade
now=$(installed)
[[ $update_rc -eq 0 && $update_clean == yes && $rc -eq 0 && $now == "$SECOND_VERSION" ]]
expect P12c-apt-upgrade-keeps-the-approved-version $? "apt update exit $update_rc, clean ${update_clean:-no}; upgrade exit $rc; installed ${now:-none}; dpkg: $(dpkg_change P12-before-upgrade P12-after-upgrade)"

served "$SECOND_VERSION"
[[ $indexed == "$SECOND_SHA256" && $downloaded == "$SECOND_SHA256" && $downloaded != "$REPLACED_SHA256" ]]
expect P12d-the-reader-serves-the-approved-bytes $? "index $indexed; served ${downloaded:-none}; approved $SECOND_SHA256; replaced $REPLACED_SHA256"

run show-all apt-cache show "$PACKAGE"
! grep -q "^SHA256: $REPLACED_SHA256" <<<"$out"
expect P12e-no-index-names-the-replaced-bytes $? "$(awk '/^(Version|SHA256):/ {printf "%s ", $2}' <<<"$out")"

# 13. The status keeps the consent and shows no broken promise.
run status pchi status
line=$(awk -v id="$SRC" '$1 == id' <<<"$out")
[[ $rc -eq 0 && $line == *"pinned_consent=yes"* && $line == *"activated=$PACKAGE"* ]]
expect P13a-status-keeps-the-pinned-consent $? "$(tr -s ' ' <<<"$line")"
! grep -q PROBLEM <<<"$out"
expect P13b-status-shows-no-broken-promise $? "$(grep PROBLEM <<<"$out" | tr -s ' ' | tr '\n' ';')"

finish phase3
