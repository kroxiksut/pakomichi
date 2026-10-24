#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# P3-002 acceptance on one APT target: the production APT adapter
# (render, plan, apply, read back) over repositories published by the
# production publisher and served by the production reader.
#   C1  activation holds eqapp (equal version elsewhere, N-010) and pins the
#       family; apt-cache policy agrees; nothing else in /etc/apt changes
#   C2  the family installs from the Strict level
#   C3  N-027 under apt upgrade, apt full-upgrade, apt-get dist-upgrade:
#       the publisher of both members stays; notices name the newer versions
#   C4  the source's own low priority: a published, not activated name never
#       replaces the distribution's; control: the same at priority 500 would
#   C5  a name only the source offers installs at that low priority
#   C6  N-010 observable: the held name is reported, never pinned
#   C7  a foreign preference that takes an activated name over is reported
#   C8  a changed Pakomichi file is drift: reported, not overwritten
#   C9  removal takes only Pakomichi's files; APT keeps working
# Run as root inside the target after prepare.sh.
set -uo pipefail
# shellcheck source=lib.sh
source /opt/p3002/lib.sh

mkdir -p "$OUT"
: >"$OUT/results.tsv"
{ grep PRETTY_NAME /etc/os-release; apt-get --version | head -1
  sha256sum /usr/local/bin/pakomichi-reader /usr/local/bin/p3001-publish /usr/local/bin/p3002-apt
} >"$OUT/environment.txt" 2>&1

REPOS=(--repo "$STRICT:sampleapp,sampleapp-helper" --repo "$STRICT:eqapp" --repo "$PINNED:")
ACTIVE=(--repo "$STRICT:sampleapp,sampleapp-helper" --repo "$PINNED:")
PUBLISHED=(--published distapp,freeapp,eqapp)
PREF=/etc/apt/preferences.d/pakomichi-sampleapp.pref

apt-get -q update >"$OUT/C0.log" 2>&1
apt-get -q -y install distapp >>"$OUT/C0.log" 2>&1
[[ $(state_of distapp) == distapp=1.0-1/distro ]] || { echo "baseline failed" >&2; exit 1; }
before=$(foreign_snapshot)

# ---------------------------------------------------------------- C1
adapter apply "${REPOS[@]}" >"$OUT/C1.log" 2>&1; arc=$?
apt-get -q update >>"$OUT/C1.log" 2>&1
adapter apply "${REPOS[@]}" >>"$OUT/C1.log" 2>&1; arc2=$?
adapter check "${ACTIVE[@]}" "${PUBLISHED[@]}" >"$OUT/C1.check" 2>&1; crc=$?
grep -q "^held	eqapp	E_SOURCE_AMBIGUOUS" "$OUT/C1.log"; held=$?
grep -q '^Package: sampleapp sampleapp-helper$' "$PREF" && ! grep -q eqapp "$PREF"; pins=$?
grep -q '^Pin: release o=Pakomichi,l=pakomichi-sampleapp-strict$' "$PREF" && ! grep -q 'Pin: origin' "$PREF"; match=$?
[[ "$(foreign_snapshot)" == "$before" ]]; untouched=$?
[[ $arc -eq 0 && $arc2 -eq 0 && $crc -eq 0 && $held -eq 0 && $pins -eq 0 && $match -eq 0 && $untouched -eq 0 ]]
expect C1 $? "apply rc=$arc/$arc2 check rc=$crc; eqapp held rc=$held; pins rc=$pins o=,l= rc=$match; other /etc/apt files unchanged rc=$untouched"

# ---------------------------------------------------------------- C2
apt-get -q -y install sampleapp >"$OUT/C2.log" 2>&1; rc=$?
s=$(state_of sampleapp) h=$(state_of sampleapp-helper)
[[ $rc -eq 0 && $s == sampleapp=1.0-1/strict && $h == sampleapp-helper=1.0-1/strict ]]
expect C2 $? "install rc=$rc: $s $h"

# ---------------------------------------------------------------- C3
for command in "apt upgrade" "apt full-upgrade" "apt-get dist-upgrade"; do
    id="C3 ${command// /-}"
    $command -s >"$OUT/$id.sim" 2>&1
    $command -q -y >"$OUT/$id.log" 2>&1; rc=$?
    adapter check "${ACTIVE[@]}" "${PUBLISHED[@]}" >"$OUT/$id.check" 2>&1; crc=$?
    s=$(state_of sampleapp) h=$(state_of sampleapp-helper) d=$(state_of distapp)
    notices=$(grep -c '^notice' "$OUT/$id.check")
    grep -q '^notice	sampleapp-helper	1.3-1	http://127.0.0.1:18090/distro' "$OUT/$id.check" &&
        grep -q '^notice	sampleapp	1.1-1	http://127.0.0.1:18090/other' "$OUT/$id.check"; named=$?
    ! grep -qE '^Inst (sampleapp|sampleapp-helper|distapp) ' "$OUT/$id.sim"; sim=$?
    [[ $rc -eq 0 && $crc -eq 0 && $sim -eq 0 && $named -eq 0 && $s == sampleapp=1.0-1/strict &&
        $h == sampleapp-helper=1.0-1/strict && $d == distapp=1.0-1/distro ]]
    expect "$id" $? "rc=$rc simulation clean rc=$sim; $s $h $d; check rc=$crc, $notices notices, distro and other named rc=$named"
done

# ---------------------------------------------------------------- C4
policy=$(apt-cache policy distapp)
printf '%s\n' "$policy" >"$OUT/C4.policy"
grep -qE '^ +2\.0-1 100$' "$OUT/C4.policy"; low=$?
printf 'Package: distapp\nPin: release o=Pakomichi,l=%s\nPin-Priority: 500\n' "$STRICT" \
    >/etc/apt/preferences.d/zz-p3002-control
apt-get -s upgrade >"$OUT/C4.control.sim" 2>&1
rm -f /etc/apt/preferences.d/zz-p3002-control
grep -qE '^Inst distapp \[1\.0-1\] \(2\.0-1' "$OUT/C4.control.sim"; control=$?
[[ $low -eq 0 && $control -eq 0 && $(state_of distapp) == distapp=1.0-1/distro ]]
expect C4 $? "our distapp 2.0-1 at priority 100 rc=$low, distapp stays $(state_of distapp); control at 500 would upgrade rc=$control"

# ---------------------------------------------------------------- C5
apt-get -q -y install freeapp >"$OUT/C5.log" 2>&1; rc=$?
[[ $rc -eq 0 && $(state_of freeapp) == freeapp=1.0-1/strict ]]
expect C5 $? "install rc=$rc: $(state_of freeapp)"

# ---------------------------------------------------------------- C6
adapter check "${REPOS[@]}" "${PUBLISHED[@]}" >"$OUT/C6.check" 2>&1; rc=$?
apt-cache policy eqapp >"$OUT/C6.policy" 2>&1
grep -q '^finding	eqapp	E_SOURCE_AMBIGUOUS' "$OUT/C6.check"; ambiguous=$?
! grep -q ' 990' "$OUT/C6.policy"; unpinned=$?
[[ $rc -eq 3 && $ambiguous -eq 0 && $unpinned -eq 0 ]]
expect C6 $? "checking eqapp as activated: rc=$rc, E_SOURCE_AMBIGUOUS rc=$ambiguous; no 990 for eqapp rc=$unpinned"

# ---------------------------------------------------------------- C7
printf 'Package: sampleapp\nPin: version 1.1-1\nPin-Priority: 1001\n' >/etc/apt/preferences.d/zz-p3002-foreign
adapter check "${ACTIVE[@]}" "${PUBLISHED[@]}" >"$OUT/C7.check" 2>&1; rc=$?
rm -f /etc/apt/preferences.d/zz-p3002-foreign
adapter check "${ACTIVE[@]}" "${PUBLISHED[@]}" >>"$OUT/C7.check" 2>&1; after=$?
grep -q '^finding	sampleapp	E_ADMIN_APPLY_FAILED	NotProtected' "$OUT/C7.check"; seen=$?
[[ $rc -eq 3 && $seen -eq 0 && $after -eq 0 ]]
expect C7 $? "foreign 1001 pin: check rc=$rc NotProtected rc=$seen; removed: rc=$after"

# ---------------------------------------------------------------- C8
cp "$PREF" /root/p3002-pref.saved
printf 'Package: sampleapp\nPin: release o=Pakomichi\nPin-Priority: 1001\n' >>"$PREF"
edited=$(sha256sum "$PREF")
adapter apply "${REPOS[@]}" >"$OUT/C8.log" 2>&1; rc=$?
grep -q "^drift	changed	$PREF" "$OUT/C8.log"; drift=$?
[[ "$(sha256sum "$PREF")" == "$edited" ]]; kept=$?
cp /root/p3002-pref.saved "$PREF"
adapter apply "${REPOS[@]}" >>"$OUT/C8.log" 2>&1; again=$?
[[ $rc -eq 3 && $drift -eq 0 && $kept -eq 0 && $again -eq 0 ]]
expect C8 $? "edited pin: apply rc=$rc drift rc=$drift, edit kept rc=$kept; restored: apply rc=$again"

# ---------------------------------------------------------------- C9
/usr/local/bin/p3002-apt apply --state "$ADAPTER_STATE" --port "$PORT" --keyring "$KEYRING" \
    --source sampleapp >"$OUT/C9.log" 2>&1; rc=$?
left=$(find /etc/apt -name 'pakomichi*' | wc -l)
[[ "$(foreign_snapshot)" == "$before" ]]; untouched=$?
apt-get -q update >>"$OUT/C9.log" 2>&1; urc=$?
warnings=$(grep -cE '^(W|E):' "$OUT/C9.log")
[[ $rc -eq 0 && $left -eq 0 && $untouched -eq 0 && $urc -eq 0 && $warnings -eq 0 &&
    $(state_of sampleapp) == sampleapp=1.0-1/strict ]]
expect C9 $? "remove rc=$rc, Pakomichi files left=$left, others unchanged rc=$untouched; update rc=$urc warnings=$warnings; $(state_of sampleapp) still installed"

cp "$ADAPTER_STATE" "$OUT/adapter.state" 2>/dev/null || true
fails=$(grep -c $'\tFAIL\t' "$OUT/results.tsv")
echo "P3-002 $(hostname): $(grep -c $'\tPASS\t' "$OUT/results.tsv") PASS, $fails FAIL"
[[ $fails -eq 0 ]]
