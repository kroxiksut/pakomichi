#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# R-001 APT matrix. Runs as root inside one freshly imported target
# distribution. Each cell resets the APT state, publishes one layout, and
# records three things separately: the solver decision, the URI and SHA-256
# of the file actually downloaded, and the payload marker after installation.
# Usage: apt-scenarios.sh PLATFORM
# R001_ISOLATE=1 is for a shared, non-disposable target (see remote-run.sh):
# the distribution sources are hidden from every APT client for the whole
# run, so no cell can upgrade or remove anything but the R-001 packages.
set -uo pipefail

readonly platform="$1"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readonly root="${R001_ROOT:-$project_root/.research-local/r-001}"
readonly served="$root/served/$platform" layouts="$root/layouts/deb"
readonly runs="$root/runs/$platform" http_log="$root/logs/http.log"
readonly sums="$root/fixtures/deb/SHA256SUMS" port=18081
readonly sources=/etc/apt/sources.list.d/pakomichi-r001.sources
readonly prefs=/etc/apt/preferences.d/pakomichi-r001
readonly isolate="${R001_ISOLATE:-0}" isolate_conf=/etc/apt/apt.conf.d/99pakomichi-r001-isolate
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
# Only our sources are refreshed per cell; distribution lists stay as prepared.
readonly update_opts=(-o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0)

mkdir -p "$runs"
results="$runs/results.tsv"
log=/dev/null
created_keyrings=0

say() { printf '%s\n' "$*" >> "$log"; }
run() {
    say "\$ $*"
    "$@" >> "$log" 2>&1
    local status=$?
    say "[exit $status]"
    return $status
}
instance_of() {
    local sha
    sha="$(sha256sum "$1" | cut -d' ' -f1)"
    grep "^$sha " "$sums" | sed 's#.*\./\([^/]*\)/.*#\1#' || echo "unknown:$sha"
}
marker() { cat /usr/share/sampleapp/marker 2>/dev/null | sed 's/ fixture=r-001//' || echo absent; }
candidate() { apt-cache policy sampleapp 2>/dev/null | awk '/Candidate:/ {print $2}'; }
fetched() { tail -n +"$((http_mark + 1))" "$http_log" | grep "/$platform/" | grep '\.deb ' | awk '{print $2 $4 " " $5}' | paste -sd, -; }
record() { printf '%s\t%s\n' "$cell" "$*" >> "$results"; say "RESULT: $*"; }

prepare() {
    log="$runs/prepare.log"
    : > "$log"
    run rm -f /etc/apt/apt.conf.d/docker-clean /etc/apt/apt.conf.d/docker-gzip-indexes \
        /etc/apt/apt.conf.d/docker-no-languages /etc/apt/apt.conf.d/docker-autoremove-suggests
    grep -q pakomichi.test /etc/hosts || printf '127.0.0.1 alpha.pakomichi.test beta.pakomichi.test system.pakomichi.test\n' >> /etc/hosts
    [[ -d /etc/apt/keyrings ]] || created_keyrings=1
    run install -d -m 0755 /etc/apt/keyrings
    for repo in alpha beta system; do
        run install -m 0644 "$root/keys/$repo.pub.asc" "/etc/apt/keyrings/pakomichi-r001-$repo.asc"
    done
    if [[ "$isolate" == 1 ]]; then
        printf 'Dir::Etc::sourcelist "%s";\nDir::Etc::sourceparts "-";\nAPT::Get::List-Cleanup "0";\nDPkg::Lock::Timeout "600";\n' \
            "$sources" > "$isolate_conf"
        run cat "$isolate_conf"
    else
        run apt-get update
    fi
    run cat /etc/os-release
    run dpkg-query -W apt dpkg libc6 gpgv sqv
    run sh -c 'ls -la /etc/apt/preferences.d; cat /etc/apt/preferences /etc/apt/preferences.d/* 2>/dev/null'
    run apt-config dump
    : > "$results"
}
# Remove every R-001 change from the target.
finish() {
    reset_cell cleanup "final reset"
    run rm -f "$isolate_conf" /etc/apt/keyrings/pakomichi-r001-alpha.asc \
        /etc/apt/keyrings/pakomichi-r001-beta.asc /etc/apt/keyrings/pakomichi-r001-system.asc
    [[ "$created_keyrings" == 1 ]] && run rmdir /etc/apt/keyrings
    sed -i '/pakomichi\.test/d' /etc/hosts
    run dpkg-query -W 'sampleapp*'
}

reset_cell() {
    cell="$1"
    log="$runs/$cell.log"
    : > "$log"
    say "## $cell: $2"
    local installed
    installed="$(dpkg-query -W -f '${Package} ${Status}\n' 'sampleapp*' 2>/dev/null | awk '/installed/ {print $1}')"
    [[ -n "$installed" ]] && run dpkg --purge $installed
    rm -f "$sources" "$prefs" /var/cache/apt/archives/*.deb
    rm -f /var/lib/apt/lists/*pakomichi.test*
    rm -rf "$served"
    mkdir -p "$served"
    http_mark="$(wc -l < "$http_log")"
}
layout() { rm -rf "$served"; mkdir -p "$served"; cp -r "$layouts/$1/." "$served/"; say "layout: $1"; }
# source REPO [PORT]: append one deb822 stanza; order of calls is source order.
source_repo() {
    printf 'Types: deb\nURIs: http://%s.pakomichi.test:%s/%s/%s/\nSuites: ./\nSigned-By: /etc/apt/keyrings/pakomichi-r001-%s.asc\n\n' \
        "$1" "${2:-$port}" "$platform" "$1" "$1" >> "$sources"
}
offline_beta() {
    sed -i '/pakomichi.test/d' /etc/hosts
    if [[ "$1" == on ]]; then
        printf '127.0.0.1 alpha.pakomichi.test system.pakomichi.test\n127.0.0.2 beta.pakomichi.test\n' >> /etc/hosts
    else
        printf '127.0.0.1 alpha.pakomichi.test beta.pakomichi.test system.pakomichi.test\n' >> /etc/hosts
    fi
    say "beta offline: $1"
}
pin() { printf 'Package: %s\nPin: %s\nPin-Priority: %s\n\n' "$1" "$2" "$3" >> "$prefs"; }
origin_of() { printf 'release o=Pakomichi R-001 TEST ONLY %s' "$1"; }
refresh() { run apt-get update "${update_opts[@]}"; run cat "$sources"; [[ -f "$prefs" ]] && run cat "$prefs"; run apt-cache policy sampleapp; }
download() {
    local dir
    dir="$(mktemp -d /tmp/pakomichi-r001-dl.XXXXXX)"
    (cd "$dir" && run apt-get download sampleapp)
    local file
    file="$(ls "$dir"/*.deb 2>/dev/null | head -1)"
    if [[ -n "$file" ]]; then echo "$(instance_of "$file")"; else echo none; fi
    rm -rf "$dir"
}

# Equal version, different bytes.
cell_equal_order() {
    local first="$1" second="$2"
    reset_cell "E-order-$first-$second" "equal version A/B, sources $first then $second, no pins"
    layout equal; source_repo "$first"; source_repo "$second"; refresh
    run apt-get -s install sampleapp
    local dl; dl="$(download)"
    run apt-get install -y sampleapp
    record "candidate=$(candidate) download=$dl installed=[$(marker)] fetched=$(fetched)"
}
cell_equal_pin() {
    local kind="$1" target="$2" pin_expr
    if [[ "$kind" == release ]]; then pin_expr="$(origin_of "$target")"; else pin_expr="origin $target.pakomichi.test"; fi
    reset_cell "E-pin-$kind-$target" "equal version A/B, sources alpha then beta, Pin: $pin_expr 990"
    layout equal; source_repo alpha; source_repo beta; pin '*' "$pin_expr" 990; refresh
    local dl; dl="$(download)"
    run apt-get install -y sampleapp
    record "candidate=$(candidate) download=$dl installed=[$(marker)] fetched=$(fetched)"
}
sim_sampleapp() { apt-get -s "$@" 2>/dev/null | grep '^Inst sampleapp' | paste -sd' ' - ; }
# Explicit target release on the command line (sampleapp/<suite>).
cell_equal_target_release() {
    reset_cell E-target-release-beta "equal version A/B, sources alpha then beta, install sampleapp/pakomichi-r001-beta"
    layout equal; source_repo alpha; source_repo beta; refresh
    run apt-get -s install sampleapp/pakomichi-r001-beta
    run apt-get install -y sampleapp/pakomichi-r001-beta
    record "installed=[$(marker)] fetched=$(fetched)"
}
# After A is installed, B becomes preferred by a pin or by source order.
cell_equal_installed() {
    local how="$1"
    reset_cell "E-installed-A-then-$how" "installed A (alpha listed first), then B preferred by $how"
    layout equal; source_repo alpha; source_repo beta; refresh
    run apt-get install -y sampleapp
    local before; before="$(marker)"
    if [[ "$how" == pin-beta ]]; then
        pin '*' "$(origin_of beta)" 990
    else
        rm -f "$sources"; source_repo beta; source_repo alpha
    fi
    refresh
    run apt-get -s upgrade
    run apt-get -s dist-upgrade
    local upgrade; upgrade="$(sim_sampleapp dist-upgrade)"
    run apt-get install -y sampleapp
    local after_install; after_install="$(marker)"
    run apt-get install -y --reinstall sampleapp
    local cached; cached="$(marker)"
    run apt-get clean
    run apt-get install -y --reinstall sampleapp
    record "before=[$before] dist-upgrade=[${upgrade:-none}] after-install=[$after_install] reinstall-cached=[$cached] reinstall-clean=[$(marker)] fetched=$(fetched)"
}
cell_dirty_cache() {
    reset_cell E-dirty-cache "A cached by download-only (alpha first), then install with beta first"
    layout equal; source_repo alpha; source_repo beta; refresh
    run apt-get install -y -d sampleapp
    run ls -l /var/cache/apt/archives/
    rm -f "$sources"; source_repo beta; source_repo alpha; refresh
    run apt-get install -y sampleapp
    record "installed=[$(marker)] fetched=$(fetched)"
}

# Different versions.
cell_versions() {
    local pinned="$1"
    reset_cell "V-lower-higher-pin-$pinned" "alpha 0.9, beta 1.0 B, pin=$pinned"
    layout versions; source_repo alpha; source_repo beta
    [[ "$pinned" != none ]] && pin '*' "$(origin_of "$pinned")" 990
    refresh
    run apt-get -s install sampleapp
    local dl; dl="$(download)"
    run apt-get install -y sampleapp
    record "candidate=$(candidate) download=$dl installed=[$(marker)] fetched=$(fetched)"
}
cell_versions_downgrade() {
    reset_cell V-installed-1.0-pin-alpha-1001 "installed 1.0 B, then alpha 0.9 pinned 1001"
    layout versions; source_repo alpha; source_repo beta; refresh
    run apt-get install -y sampleapp
    local before; before="$(marker)"
    pin '*' "$(origin_of alpha)" 1001; refresh
    run apt-get -s upgrade
    run apt-get -s dist-upgrade
    record "before=[$before] candidate-after-pin=$(candidate) simulated=[$(apt-get -s upgrade 2>/dev/null | grep -E '^(Inst|[0-9]+ upgraded)' | paste -sd' ' -)] simulated-dist-upgrade=[$(apt-get -s dist-upgrade 2>/dev/null | grep -E '^(Inst|Remv|[0-9]+ upgraded)' | paste -sd' ' -)]"
}
# An upgrade-style command (apt upgrade, apt-get upgrade or dist-upgrade).
# An isolated run first simulates it and refuses one that would touch
# anything but the R-001 packages.
whole_system() {
    if [[ "$isolate" == 1 ]]; then
        local others
        others="$("$@" -s 2>/dev/null | awk '/^(Inst|Remv|Purg) / {print $2}' | grep -v '^sampleapp' | paste -sd, -)"
        if [[ -n "$others" ]]; then
            say "REFUSED: $* would also touch: $others"
            return 99
        fi
    fi
    run "$@"
}

# Upgrade to a higher version from another publisher.
cell_upgrade() {
    local pinned="$1" tool="$2"
    reset_cell "U-upgrade-$tool-pin-$pinned" "installed 1.0 A from alpha; beta offers 1.1 + helper; pin=$pinned; $tool"
    layout upgrade; source_repo alpha; source_repo beta
    [[ "$pinned" != none ]] && pin '*' "$(origin_of "$pinned")" 990
    refresh
    run apt-get install -y sampleapp=1.0-1
    local before; before="$(marker)"
    case "$tool" in
        apt) whole_system apt upgrade -y ;;
        apt-get) whole_system apt-get upgrade -y ;;
        dist-upgrade) whole_system apt-get dist-upgrade -y ;;
    esac
    local upgrade_status=$?
    record "before=[$before] upgrade-exit=$upgrade_status after=[$(marker)] helper=$(dpkg-query -W -f '${Version}' sampleapp-helper 2>/dev/null || echo absent) fetched=$(fetched)"
}

# Package family.
cell_family() {
    reset_cell F-family-remove-base "alpha offers sampleapp 1.1 + helper; install, then remove helper"
    layout family; source_repo alpha; refresh
    run apt-get install -y sampleapp
    local before; before="$(marker)"
    run apt-get -s remove sampleapp-helper
    run apt-get remove -y sampleapp-helper
    record "before=[$before] after-helper-removal=[$(marker)] helper=$(dpkg-query -W -f '${Status}' sampleapp-helper 2>/dev/null || echo absent)"
}
cell_family_split() {
    reset_cell F-family-split "sampleapp 1.1 in alpha, its helper only in beta"
    layout family-split; source_repo alpha; source_repo beta; refresh
    run apt-get -s install sampleapp
    run apt-get install -y sampleapp
    record "installed=[$(marker)] helper=$(dpkg-query -W -f '${Version}' sampleapp-helper 2>/dev/null || echo absent) fetched=$(fetched)"
}

# A system source appears later with the same version.
cell_system() {
    local where="$1"
    reset_cell "S-system-appears-$where" "installed A from alpha, then a system repository with equal S is listed $where alpha"
    layout system; source_repo alpha; refresh
    run apt-get install -y sampleapp
    local before; before="$(marker)"
    if [[ "$where" == before ]]; then
        rm -f "$sources"; source_repo system; source_repo alpha
    else
        source_repo system
    fi
    refresh
    run apt-get -s dist-upgrade
    local upgrade; upgrade="$(sim_sampleapp dist-upgrade)"
    run apt-get install -y --reinstall sampleapp
    local cached; cached="$(marker)"
    run apt-get clean
    run apt-get install -y --reinstall sampleapp
    record "before=[$before] dist-upgrade=[${upgrade:-none}] reinstall-cached=[$cached] reinstall-clean=[$(marker)] fetched=$(fetched)"
}

# Source disappears (404) or goes offline (connection refused).
cell_removed() {
    local mode="$1"
    reset_cell "R-beta-$mode" "installed B (beta listed first), then beta is $mode"
    layout equal; source_repo beta; source_repo alpha; refresh
    run apt-get install -y sampleapp
    local before; before="$(marker)"
    # Offline keeps the same URI but points its host at an address nobody serves.
    if [[ "$mode" == removed ]]; then rm -rf "$served/beta"; else offline_beta on; fi
    run apt-get update "${update_opts[@]}"
    local update_status=$?
    run apt-cache policy sampleapp
    run apt-get -s upgrade
    run apt-get install -y --reinstall sampleapp
    local cached; cached="$(marker)"
    run apt-get clean
    run apt-get install -y --reinstall sampleapp
    local reinstall_status=$?
    [[ "$mode" == offline ]] && offline_beta off
    record "before=[$before] update-exit=$update_status candidate=$(candidate) reinstall-cached=[$cached] reinstall-clean-exit=$reinstall_status reinstall-clean=[$(marker)] fetched=$(fetched)"
}

# Mandatory negative fixtures: simulation only, never installed.
cell_negative() {
    reset_cell N-negative "missing dependency, Provides libc6 (N-008), libc6 >= 2.99 (N-009); simulation only"
    layout negative; source_repo alpha; refresh
    run apt-get -s install sampleapp-missingdep; local missing=$?
    run apt-get -s install sampleapp-glibc; local provides=$?
    run apt-get -s install sampleapp-nextglibc; local next=$?
    local resolved_by; resolved_by="$(apt-get -s install sampleapp-nextglibc 2>/dev/null | grep '^Inst' | awk '{print $2}' | paste -sd, -)"
    run apt-cache showpkg libc6
    record "missingdep-exit=$missing glibc-provides-exit=$provides nextglibc-with-provider-exit=$next nextglibc-resolved-by=$resolved_by"
}
cell_negative_next() {
    reset_cell N-009-next-glibc "libc6 >= 2.99 without any third-party provider; simulation only"
    layout negative-next; source_repo alpha; refresh
    run apt-get -s install sampleapp-nextglibc; local next=$?
    record "nextglibc-exit=$next"
}

prepare
cell_equal_order alpha beta
cell_equal_order beta alpha
cell_equal_pin release alpha
cell_equal_pin release beta
cell_equal_pin origin alpha
cell_equal_pin origin beta
cell_equal_target_release
cell_equal_installed pin-beta
cell_equal_installed beta-first
cell_dirty_cache
cell_versions none
cell_versions alpha
cell_versions_downgrade
cell_upgrade none apt
cell_upgrade none apt-get
cell_upgrade alpha apt
cell_upgrade none dist-upgrade
cell_upgrade alpha dist-upgrade
cell_family
cell_family_split
cell_system after
cell_system before
cell_removed removed
cell_removed offline
cell_negative
cell_negative_next
finish
cat "$results"
