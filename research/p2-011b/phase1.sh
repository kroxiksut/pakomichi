#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P2-011b (E2E-07) phase 1, with the first release of the test repository
# published (no attestation): the source is added without an Attested
# signer and nothing of it is published; Pinned consent names the risk and
# needs a confirmation typed at a terminal (`--yes` and no terminal change
# nothing, N-040); `--policy preferred` is refused (N-037); the release is
# held with `E_RELEASE_APPROVAL_REQUIRED` and the synchronization prints the
# approve line (N-039); the approval lists the asset and its digest; then
# the Pinned logical repository serves it, `apt-cache policy` shows its
# label at 990, and `apt install` takes exactly the bytes GitHub states.
# Environment: FIRST_VERSION, FIRST_RELEASE_ID, FIRST_SHA256 (GitHub's
# digest of the asset), P2011B_OUT, SOURCE_URL.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p2011b/lib.sh
: "${FIRST_VERSION:?}" "${FIRST_RELEASE_ID:?}" "${FIRST_SHA256:?}"
mkdir -p "$OUT"
: >"$OUT/results.tsv"
: >"$log"
first_tag=$(tag "$FIRST_VERSION")
first_asset=$(asset "$FIRST_VERSION")

# The distribution brought up to date first, so that later snapshots of
# the package database show only what this bed changes.
run baseline-update apt-get update
run baseline-upgrade apt-get upgrade -y
snapshot P00-baseline

# 1. The source has no Attested signer: the plan says so.
api_budget
run add confirm pchi source add "$URL"
SRC=$(find_source)
printf '%s\n' "$SRC" >"$OUT/source-id"
set_source
signer=$(field signer)
[[ $rc -eq 0 && -n $SRC && $out == *"no Attested signer"* && $signer == signer=none ]]
expect P01-add-names-no-attested-signer $? "exit $rc; source ${SRC:-none}; $signer"
[[ -n $SRC ]] || { finish phase1; exit 1; }

# 2. Without consent the release is held and nothing is published.
api_budget
run sync-unconsented confirm pchi sync "$SRC"
held=$(grep -o 'held or rejected: [0-9]*' <<<"$out" | grep -o '[0-9]*$')
[[ $rc -eq 0 && ${held:-0} -ge 1 && $out == *"published: nothing"* && $out != *"waits for approval"* &&
    -z "$(pinned_published)" && ! -e $PREF ]]
expect P02-no-consent-publishes-nothing $? "exit $rc; held ${held:-?}; $(grep -o '\[E_[A-Z_, ]*\]' <<<"$out" | tr -d '\r')"

# An approval without consent is refused; it reads only the state.
run approve-unconsented pchi release approve "$SRC" "$FIRST_RELEASE_ID" </dev/null
[[ $rc -eq 1 && $out == *"has no Pinned consent"* ]]
expect P02b-approve-without-consent-is-refused $? "exit $rc"

# 3. Pinned consent: never by --yes or without a terminal (N-040); the plan
# names the risk.
run allow-yes pchi source allow-pinned "$SRC" --yes
consent=$(field pinned_consent)
[[ $rc -eq 2 && $consent == pinned_consent=no ]]
expect P03a-allow-pinned-refuses-yes $? "exit $rc; $consent"

run allow-no-tty pchi source allow-pinned "$SRC" </dev/null
consent=$(field pinned_consent)
[[ $rc -eq 3 && $consent == pinned_consent=no ]]
expect P03b-allow-pinned-without-terminal-changes-nothing $? "exit $rc; $consent"

run allow confirm pchi source allow-pinned "$SRC"
consent=$(field pinned_consent)
[[ $rc -eq 0 && $out == *"$RISK"* && $consent == pinned_consent=yes ]]
expect P03c-allow-pinned-names-the-risk-and-records-consent $? "exit $rc; $consent"

# 4. N-037: a source with Pinned consent is never preferred. Without a
# terminal, so that a plan that is not refused changes nothing either.
api_budget
run activate-preferred pchi source activate "$SRC" --packages "$PACKAGE" --policy preferred </dev/null
activated=$(field activated)
[[ $rc -eq 1 && $out == *"--policy supplemental"* && $activated == activated=- ]]
expect P04-preferred-is-refused $? "exit $rc; $activated"

# 5. N-039: with consent the release waits for approval; the sync names
# the exact approve command and publishes nothing.
api_budget
run sync-consented confirm pchi sync "$SRC"
[[ $rc -eq 0 && $out == *"$(approve_line "$first_tag" "$FIRST_RELEASE_ID")"* &&
    $out == *E_RELEASE_APPROVAL_REQUIRED* && -z "$(pinned_published)" ]]
expect P05-release-waits-for-approval $? "exit $rc; $(grep 'waits for approval' <<<"$out" | tr -d '\r')"

# 6. Activation (supplemental, the default) publishes nothing unapproved.
# `activated` in the status follows the pins APT holds, so the name shows
# there only once its approved release is pinned (P08b, P13a).
api_budget
run activate confirm pchi source activate "$SRC" --packages "$PACKAGE"
activated=$(field activated)
[[ $rc -eq 0 && $activated == "activated=-" && ! -e $PREF ]]
expect P06a-activate-supplemental-pins-nothing-unapproved $? "exit $rc; $activated; files: $(ours | tr '\n' ' ')"

# What APT is offered, whatever files the activation wrote.
run apt-update-unapproved apt update
update_rc=$rc
update_clean=$(clean && echo yes)
run madison-unapproved apt-cache madison "$PACKAGE"
[[ $update_rc -eq 0 && $update_clean == yes ]] && ! grep -q '|' <<<"$out"
expect P06b-apt-is-not-offered-the-unapproved-release $? "apt update exit $update_rc, clean ${update_clean:-no}; madison: $(tr '\n' ' ' <<<"$out")"

# 7. The approval: never by --yes or without a terminal (N-040); the plan
# lists the asset by name and GitHub's digest.
run approve-yes pchi release approve "$SRC" "$FIRST_RELEASE_ID" --yes
[[ $rc -eq 2 ]]
expect P07a-approve-refuses-yes $? "exit $rc"

snapshot P07-before-no-tty
run approve-no-tty pchi release approve "$SRC" "$FIRST_RELEASE_ID" </dev/null
snapshot P07-after-no-tty
[[ $rc -eq 3 ]] && cmp -s "$OUT/apt-P07-before-no-tty.sha256" "$OUT/apt-P07-after-no-tty.sha256"
expect P07b-approve-without-terminal-changes-nothing $? "exit $rc"

# Had the run without a terminal approved anything, this plan would be
# refused with "nothing left to approve".
snapshot P07-before-approve
api_budget
run approve confirm pchi release approve "$SRC" "$FIRST_RELEASE_ID"
listed=$(approvals)
[[ $rc -eq 0 && $(wc -l <<<"$listed") -eq 1 && $listed == *" approve_release $first_asset (new: ${FIRST_SHA256:0:12})"* &&
    $out == *"approve release $first_tag ($FIRST_RELEASE_ID) of $SRC"* ]]
expect P07c-approve-lists-the-asset-and-its-digest $? "exit $rc; $(tr -s ' ' <<<"$listed")"

grep -q "^URIs: http://127.0.0.1:$PORT/$LABEL\$" "$SOURCES" 2>/dev/null
expect P07d-approval-publishes-the-pinned-repository $? "$(grep -h '^URIs:' "$SOURCES" 2>/dev/null | tr '\n' ' ')"
snapshot P07-after-approve

# 8. APT lists it; the pin follows; the level is visible without pchi.
run apt-update apt update
[[ $rc -eq 0 ]] && clean
expect P08a-apt-update-is-clean $? "exit $rc"

api_budget
run sync-pin confirm pchi sync "$SRC"
pinned=$(grep -h '^Package:\|^Pin:' "$PREF" 2>/dev/null | tr '\n' ' ')
[[ $rc -eq 0 && $pinned == *"Package: $PACKAGE"*"l=$LABEL"* ]]
expect P08b-sync-pins-the-pinned-repository $? "exit $rc; $pinned"

run policy apt-cache policy "$PACKAGE"
candidate=$(awk '/Candidate:/ {print $2}' <<<"$out")
from=$(policy_source "$candidate")
[[ $candidate == "$FIRST_VERSION" && $from == *"http://127.0.0.1:$PORT/$LABEL "* ]]
expect P08c-candidate-from-the-pinned-repository-at-990 $? "candidate $candidate; $from"

run policy-all apt-cache policy
grep -qE "o=Pakomichi,.*l=$LABEL(,|\$)" <<<"$out"
expect P08d-apt-policy-shows-the-pinned-label $? "$(grep -m1 "l=$LABEL" <<<"$out" | tr -s ' ')"

# 9. apt install takes the approved bytes.
snapshot P09-before-install
run install apt install -y "$PACKAGE"
snapshot P09-after-install
now=$(installed)
[[ $rc -eq 0 && $now == "$FIRST_VERSION" ]]
expect P09a-apt-installs-the-approved-release $? "installed ${now:-none}; dpkg: $(dpkg_change P09-before-install P09-after-install)"

served "$FIRST_VERSION"
[[ $indexed == "$FIRST_SHA256" && $downloaded == "$FIRST_SHA256" ]]
expect P09b-the-bytes-are-the-approved-asset $? "index $indexed; served $downloaded; github $FIRST_SHA256"

finish phase1
