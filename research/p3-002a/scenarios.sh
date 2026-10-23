#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# P3-002a: does `Pin: release o=…,l=…` with Pin-Priority 990 keep the
# publisher of an activated family when every logical repository is served
# from ONE loopback host (ADR-022 point 3, ADR-007)?
#
# Runs as root in a target. APT sees only the P3-002a sources for the whole
# run (the distribution sources are hidden, as R-001 did on shared targets),
# and every change is removed at the end. For each ordinary update command:
#   none     no preferences: the control, the publisher is expected to change
#   ol       Pin: release o=<Origin>,l=<Strict Label> 990 for both names
#   o-only   Pin: release o=<Origin> 990 (diagnostic: Strict and Pinned share
#            the Origin, so only the Label can tell them apart)
# Usage: scenarios.sh PLATFORM "COMMAND" ["COMMAND" ...]
#   e.g. scenarios.sh debian12 "apt upgrade" "apt full-upgrade"
set -uo pipefail

readonly platform="$1"
shift
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readonly root="${P3002A_ROOT:-$project_root/.research-local/p3-002a}"
readonly keys="${P3002A_KEYS:-$project_root/.research-local/r-001/keys}"
readonly port="${P3002A_PORT:-18082}" host=127.0.0.1
readonly runs="$root/runs/$platform" http_log="$root/logs/http.log"
readonly sources=/etc/apt/sources.list.d/pakomichi-p3002a.sources
readonly prefs=/etc/apt/preferences.d/pakomichi-p3002a
readonly isolate_conf=/etc/apt/apt.conf.d/99pakomichi-p3002a-isolate
readonly origin="Pakomichi TEST ONLY" strict_label=pakomichi-p3002a-strict
export DEBIAN_FRONTEND=noninteractive LC_ALL=C

mkdir -p "$runs"
find "$runs" -mindepth 1 -delete
results="$runs/results.tsv"
: > "$results"
log="$runs/prepare.log"
: > "$log"
created_keyrings=0

say() { printf '%s\n' "$*" >> "$log"; }
run() {
    say "\$ $*"
    "$@" >> "$log" 2>&1
    local status=$?
    say "[exit $status]"
    return $status
}
version_of() { dpkg-query -W -f '${Version}' "$1" 2>/dev/null || echo absent; }
publisher_of() { sed -n 's/.*publisher=\([^ ]*\).*/\1/p' "/usr/share/$1/marker" 2>/dev/null || echo absent; }
state() { printf 'sampleapp=%s/%s helper=%s/%s' "$(version_of sampleapp)" "$(publisher_of sampleapp)" \
    "$(version_of sampleapp-helper)" "$(publisher_of sampleapp-helper)"; }
# The priority APT gives each version: "1.0-1:990 1.2-1:500 ...".
priorities() {
    apt-cache policy "$1" 2>/dev/null | awk '
        /Version table:/ {table=1; next}
        table && /^( \*\*\* |     )[^ ]/ {sub(/\*\*\* /, ""); version=$1; prio=$2; out=out version ":" prio " "}
        END {print out}' | sed 's/ $//'
}
fetched() { tail -n +"$((http_mark + 1))" "$http_log" | grep '\.deb ' | awk '{print $2 $4 " " $5}' | paste -sd, -; }
record() { printf '%s\t%s\n' "$cell" "$*" >> "$results"; say "RESULT: $*"; }
source_repo() {
    printf 'Types: deb\nURIs: http://%s:%s/p3002a/%s/\nSuites: ./\nSigned-By: /etc/apt/keyrings/pakomichi-p3002a-%s.asc\n\n' \
        "$host" "$port" "$1" "$2" >> "$sources"
}
pin() { printf 'Package: sampleapp sampleapp-helper\nPin: %s\nPin-Priority: 990\n\n' "$1" >> "$prefs"; }

prepare() {
    rm -f /etc/apt/apt.conf.d/docker-clean
    [[ -d /etc/apt/keyrings ]] || created_keyrings=1
    run install -d -m 0755 /etc/apt/keyrings
    for key in alpha beta system; do
        run install -m 0644 "$keys/$key.pub.asc" "/etc/apt/keyrings/pakomichi-p3002a-$key.asc"
    done
    printf 'Dir::Etc::sourcelist "%s";\nDir::Etc::sourceparts "-";\nAPT::Get::List-Cleanup "0";\nDPkg::Lock::Timeout "600";\n' \
        "$sources" > "$isolate_conf"
    run cat "$isolate_conf"
    run cat /etc/os-release
    run dpkg-query -W apt dpkg
    run sh -c 'ls -la /etc/apt/preferences.d; cat /etc/apt/preferences /etc/apt/preferences.d/* 2>/dev/null'
}
reset_cell() {
    cell="$1"
    log="$runs/$cell.log"
    : > "$log"
    say "## $cell: $2"
    local installed
    installed="$(dpkg-query -W -f '${Package} ${Status}\n' 'sampleapp*' 2>/dev/null | awk '/ installed$/ {print $1}')"
    [[ -n "$installed" ]] && run dpkg --purge $installed
    rm -f "$sources" "$prefs" /var/cache/apt/archives/sampleapp*.deb
    rm -f /var/lib/apt/lists/*p3002a*
    http_mark="$(wc -l < "$http_log")"
}
finish() {
    reset_cell cleanup "final reset"
    rm -f "$isolate_conf" /etc/apt/keyrings/pakomichi-p3002a-alpha.asc \
        /etc/apt/keyrings/pakomichi-p3002a-beta.asc /etc/apt/keyrings/pakomichi-p3002a-system.asc
    [[ "$created_keyrings" == 1 ]] && rmdir /etc/apt/keyrings
    run dpkg-query -W 'sampleapp*'
    run ls /etc/apt/sources.list.d /etc/apt/preferences.d /etc/apt/apt.conf.d
}

# The ordinary command; refuses to run if it would touch anything but the
# P3-002a packages (the distribution sources are hidden, so it should not).
ordinary() {
    local others
    others="$("$@" -s 2>/dev/null | awk '/^(Inst|Remv|Purg) / {print $2}' | grep -v '^sampleapp' | paste -sd, -)"
    if [[ -n "$others" ]]; then
        say "REFUSED: $* would also touch: $others"
        return 99
    fi
    run "$@" -y
}

cell() {
    local mode="$1" command="$2" tag
    tag="$(echo "$command" | tr ' ' '-')"
    reset_cell "$mode-$tag" "installed family from strict; other repos offer higher versions; pin=$mode; $command"
    # Install the family from the Strict repository alone.
    source_repo strict alpha
    run apt-get update
    run apt-get install -y sampleapp
    local before; before="$(state)"
    # Every repository now, Strict listed last so source order cannot help it.
    rm -f "$sources"
    source_repo other beta
    source_repo distro system
    source_repo pinned alpha
    source_repo strict alpha
    case "$mode" in
        none) ;;
        ol) pin "release o=$origin,l=$strict_label" ;;
        o-only) pin "release o=$origin" ;;
    esac
    run apt-get update
    run cat "$sources"
    [[ -f "$prefs" ]] && run cat "$prefs"
    run apt-cache policy sampleapp sampleapp-helper
    local p_app p_helper
    p_app="$(priorities sampleapp)"
    p_helper="$(priorities sampleapp-helper)"
    # shellcheck disable=SC2086 # the command is split into words on purpose
    run $command -s
    ordinary $command
    local status=$?
    record "before=[$before] priorities-sampleapp=[$p_app] priorities-helper=[$p_helper] exit=$status after=[$(state)] fetched=$(fetched)"
}

prepare
for command in "$@"; do
    for mode in none ol o-only; do
        cell "$mode" "$command"
    done
done
finish
cat "$results"
