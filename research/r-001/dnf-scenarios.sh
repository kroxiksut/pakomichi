#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# R-001 DNF4/DNF5 matrix. Runs as root inside one freshly imported target
# distribution. Each cell resets the DNF state, publishes one layout, and
# records separately the solver decision, the URI and SHA-256 of the file
# actually downloaded, and the payload marker after installation.
# Usage: dnf-scenarios.sh PLATFORM
# R001_ISOLATE=1 is for a shared, non-disposable target (see remote-run.sh):
# the distribution repositories are hidden for the whole run, the base system
# is not upgraded, and a whole-system transaction that would touch anything
# but the R-001 packages is refused.
set -uo pipefail

readonly platform="$1"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
readonly root="${R001_ROOT:-$project_root/.research-local/r-001}"
readonly served="$root/served/$platform" layouts="$root/layouts/rpm"
readonly runs="$root/runs/$platform" http_log="$root/logs/http.log"
readonly sums="$root/fixtures/rpm/SHA256SUMS" port=18081
readonly isolate="${R001_ISOLATE:-0}"
if [[ "$isolate" == 1 ]]; then readonly reposdir=/etc/pakomichi-r001.repos.d; else readonly reposdir=/etc/yum.repos.d; fi
readonly repofile="$reposdir/pakomichi-r001.repo"
export LC_ALL=C
# R001_NOPLUGINS=1 runs every dnf command with --noplugins, to tell the
# effect of a distribution's DNF plugins from DNF's own behavior.
if [[ "${R001_NOPLUGINS:-0}" == 1 ]]; then dnf() { command dnf --noplugins "$@"; }; fi
if dnf --version 2>/dev/null | grep -q '^dnf5'; then readonly dnf5=1; else readonly dnf5=0; fi

mkdir -p "$runs"
results="$runs/results.tsv"
log=/dev/null

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
fetched() { tail -n +"$((http_mark + 1))" "$http_log" | grep "/$platform/" | grep '\.rpm ' | awk '{print $2 $4 " " $5}' | paste -sd, -; }
# `rpm -q` reports a missing package on stdout, so test before formatting.
helper_version() {
    if rpm -q sampleapp-helper >/dev/null 2>&1; then rpm -q --qf '%{VERSION}-%{RELEASE}' sampleapp-helper; else echo absent; fi
}
record() { printf '%s\t%s\n' "$cell" "$*" >> "$results"; say "RESULT: $*"; }
from_repo() {
    if [[ $dnf5 == 1 ]]; then
        dnf -q repoquery --installed --qf '%{from_repo}\n' sampleapp 2>/dev/null | head -1
    else
        dnf -q repoquery --installed --qf '%{from_repo}' sampleapp 2>/dev/null | head -1
    fi
}
# Which repository instance the solver would take for a fresh install.
plan() {
    dnf --assumeno install "$@" 2>&1 | awk '/^ *sampleapp/ {print $1 "-" $3 "@" $4}' | paste -sd, -
}

prepare() {
    log="$runs/prepare.log"
    : > "$log"
    if [[ "$isolate" == 1 ]]; then
        # reset_cell rewrites these [main] options, so never take over the
        # owner's own values.
        if grep -Eq '^(reposdir|allow_vendor_change)=' /etc/dnf/dnf.conf; then
            echo "dnf.conf already sets reposdir or allow_vendor_change; refusing to run" >&2
            exit 2
        fi
        install -d -m 0755 "$reposdir"
        printf 'reposdir=%s\n' "$reposdir" >> /etc/dnf/dnf.conf
    fi
    grep -q pakomichi.test /etc/hosts || printf '127.0.0.1 alpha.pakomichi.test beta.pakomichi.test system.pakomichi.test\n' >> /etc/hosts
    for repo in alpha beta system; do
        run install -m 0644 "$root/keys/$repo.pub.asc" "/etc/pki/rpm-gpg/pakomichi-r001-$repo.asc"
    done
    run cat /etc/os-release
    run dnf --version
    # The verbose header names the loaded plugins (none under R001_NOPLUGINS=1).
    say "R001_NOPLUGINS=${R001_NOPLUGINS:-0}"
    run dnf -v repolist --all
    run rpm -q rpm dnf glibc
    run cat /etc/dnf/dnf.conf
    # Bring the base image up to date once so later `dnf upgrade` cells only
    # move the R-001 packages. An isolated run sees no distribution
    # repositories, so there is nothing to bring up to date.
    [[ "$isolate" == 1 ]] || run dnf -y upgrade
    if [[ $dnf5 == 1 ]]; then
        run dnf --dump-main-config
    else
        run python3 -c 'import dnf; c = dnf.conf.Conf(); c.read(); print(c.dump())'
    fi
    : > "$results"
}
# Remove every R-001 change from the target, including the imported keys.
finish() {
    reset_cell cleanup "final reset"
    if [[ "$isolate" == 1 ]]; then
        sed -i "\\#^reposdir=$reposdir\$#d" /etc/dnf/dnf.conf
        rm -rf "$reposdir"
    fi
    run rm -f /etc/pki/rpm-gpg/pakomichi-r001-alpha.asc /etc/pki/rpm-gpg/pakomichi-r001-beta.asc \
        /etc/pki/rpm-gpg/pakomichi-r001-system.asc
    local key
    for key in $(rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n' 2>/dev/null | awk -F'\t' '/pakomichi\.test/ {print $1}'); do
        run rpm -e "$key"
    done
    sed -i '/pakomichi\.test/d' /etc/hosts
    run rpm -qa 'sampleapp*'
}
# dnf -y ARGS for a whole-system transaction (upgrade, distro-sync). An
# isolated run first checks the plan and refuses one that would touch
# anything but the R-001 packages.
whole_system() {
    if [[ "$isolate" == 1 ]]; then
        local others
        others="$(dnf --assumeno "$@" 2>&1 | awk '/^ [^ ]/ && $1 != "Package" {print $1}' | grep -v '^sampleapp' | paste -sd, -)"
        if [[ -n "$others" ]]; then
            say "REFUSED: dnf $* would also touch: $others"
            return 99
        fi
    fi
    run dnf -y "$@"
}

reset_cell() {
    cell="$1"
    log="$runs/$cell.log"
    : > "$log"
    say "## $cell: $2"
    local installed
    installed="$(rpm -qa --qf '%{NAME}\n' 'sampleapp*' | paste -sd' ' -)"
    [[ -n "$installed" ]] && run rpm -e --nodeps $installed
    rm -f "$repofile"
    sed -i '/^allow_vendor_change=/d' /etc/dnf/dnf.conf
    # Drop only our repository caches; distribution metadata stays.
    rm -rf /var/cache/dnf/pakomichi-r001-* /var/cache/libdnf5/pakomichi-r001-*
    rm -rf "$served"
    mkdir -p "$served"
    http_mark="$(wc -l < "$http_log")"
}
layout() { rm -rf "$served"; mkdir -p "$served"; cp -r "$layouts/$1/." "$served/"; say "layout: $1"; }
# repo NAME [extra option lines...]: append one repository section.
repo() {
    local name="$1"
    shift
    {
        printf '[pakomichi-r001-%s]\nname=Pakomichi R-001 TEST ONLY %s\n' "$name" "$name"
        printf 'baseurl=http://%s.pakomichi.test:%s/%s/%s/\n' "$name" "$port" "$platform" "$name"
        printf 'enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nmetadata_expire=0\n'
        printf 'gpgkey=file:///etc/pki/rpm-gpg/pakomichi-r001-alpha.asc file:///etc/pki/rpm-gpg/pakomichi-r001-beta.asc file:///etc/pki/rpm-gpg/pakomichi-r001-system.asc\n'
        local line
        for line in "$@"; do printf '%s\n' "$line"; done
        printf '\n'
    } >> "$repofile"
}
refresh() {
    run cat "$repofile"
    [[ "$isolate" == 1 ]] && run dnf repolist --all
    run dnf -y makecache
    if [[ $dnf5 == 1 ]]; then
        run dnf repoquery --qf '%{name}-%{evr} repo=%{repoid} location=%{location}\n' 'sampleapp*'
    else
        run dnf repoquery --qf '%{name}-%{evr} repo=%{repoid} location=%{location}' 'sampleapp*'
    fi
    run dnf list --available 'sampleapp*'
}
download() {
    local dir
    dir="$(mktemp -d /tmp/pakomichi-r001-dl.XXXXXX)"
    if [[ $dnf5 == 1 ]]; then
        # DNF5 `install` has no --destdir; its built-in `download` resolves the
        # same candidate.
        run dnf download --destdir "$dir" sampleapp
    else
        run dnf -y install --downloadonly --downloaddir "$dir" sampleapp
    fi
    local file
    file="$(ls "$dir"/sampleapp-[0-9]*.rpm 2>/dev/null | head -1)"
    if [[ -n "$file" ]]; then instance_of "$file"; else echo none; fi
    rm -rf "$dir"
}
install_and_record() {
    local plan_line dl
    plan_line="$(plan sampleapp)"
    dl="$(download)"
    run dnf -y install sampleapp
    record "plan=$plan_line download=$dl installed=[$(marker)] from=$(from_repo) fetched=$(fetched) $*"
}

# Equal NEVRA, different bytes.
cell_equal_order() {
    reset_cell "E-order-$1-$2" "equal NEVRA A/B, sections $1 then $2, default priority"
    layout equal; repo "$1"; repo "$2"; refresh
    install_and_record
}
cell_equal_priority() {
    local preferred="$1" other
    [[ "$preferred" == alpha ]] && other=beta || other=alpha
    reset_cell "E-priority-$preferred-10" "equal NEVRA A/B, $preferred priority=10, $other priority=90"
    layout equal; repo alpha "priority=$([[ $preferred == alpha ]] && echo 10 || echo 90)"
    repo beta "priority=$([[ $preferred == beta ]] && echo 10 || echo 90)"
    refresh
    install_and_record
}
cell_equal_excludepkgs() {
    reset_cell E-excludepkgs-alpha "equal NEVRA A/B, alpha excludepkgs=sampleapp"
    layout equal; repo alpha "excludepkgs=sampleapp"; repo beta; refresh
    install_and_record
}
cell_equal_includepkgs() {
    reset_cell E-includepkgs-beta "equal NEVRA A/B, beta includepkgs=sampleapp-helper (sampleapp filtered out)"
    layout equal; repo alpha; repo beta "includepkgs=sampleapp-helper"; refresh
    install_and_record
}
cell_equal_disableexcludes() {
    reset_cell E-disableexcludes "alpha priority=10 with excludepkgs=sampleapp, beta priority=90; install --disableexcludes=all"
    layout equal; repo alpha "priority=10" "excludepkgs=sampleapp"; repo beta "priority=90"; refresh
    local plan_default plan_disabled override
    # DNF4 spells it --disableexcludes=all; DNF5 only has the config option.
    if [[ $dnf5 == 1 ]]; then override='--setopt=disable_excludes=*'; else override='--disableexcludes=all'; fi
    plan_default="$(plan sampleapp)"
    plan_disabled="$(plan "$override" sampleapp)"
    run dnf -y install "$override" sampleapp
    record "plan-default=$plan_default plan-disableexcludes=$plan_disabled installed=[$(marker)] from=$(from_repo) fetched=$(fetched)"
}
cell_equal_explicit_repo() {
    local how="$1"
    reset_cell "E-explicit-$how" "equal NEVRA A/B, alpha priority=10, beta priority=90; $how selects beta"
    layout equal; repo alpha "priority=10"; repo beta "priority=90"; refresh
    if [[ "$how" == repo-option ]]; then
        run dnf -y install --repo pakomichi-r001-beta sampleapp
    else
        run dnf -y install --disablerepo pakomichi-r001-alpha sampleapp
    fi
    record "installed=[$(marker)] from=$(from_repo) fetched=$(fetched)"
}
cell_equal_installed() {
    reset_cell E-installed-A-then-priority-beta "installed A (alpha priority=10), then beta priority=10 and alpha priority=90"
    layout equal; repo alpha "priority=10"; repo beta "priority=90"; refresh
    run dnf -y install sampleapp
    local before; before="$(marker)"
    rm -f "$repofile"; repo alpha "priority=90"; repo beta "priority=10"; refresh
    whole_system upgrade
    local after_upgrade; after_upgrade="$(marker)"
    whole_system distro-sync
    local after_sync; after_sync="$(marker)"
    run dnf -y reinstall sampleapp
    record "before=[$before] after-upgrade=[$after_upgrade] after-distro-sync=[$after_sync] after-reinstall=[$(marker)] from=$(from_repo) fetched=$(fetched)"
}
cell_dirty_cache() {
    reset_cell E-dirty-cache "A kept in cache by --downloadonly (alpha priority=10), then beta priority=10 and install"
    layout equal; repo alpha "priority=10" "keepcache=1"; repo beta "priority=90" "keepcache=1"; refresh
    run dnf -y install --downloadonly sampleapp
    run find /var/cache/dnf /var/cache/libdnf5 -name 'sampleapp*.rpm'
    rm -f "$repofile"; repo alpha "priority=90" "keepcache=1"; repo beta "priority=10" "keepcache=1"; refresh
    run dnf -y install sampleapp
    record "installed=[$(marker)] from=$(from_repo) fetched=$(fetched)"
}

# Different versions.
cell_versions() {
    local preferred="$1"
    reset_cell "V-lower-higher-priority-$preferred" "alpha 0.9, beta 1.0 B; priority preference=$preferred"
    layout versions
    if [[ "$preferred" == alpha ]]; then repo alpha "priority=10"; repo beta "priority=90"; else repo alpha; repo beta; fi
    refresh
    install_and_record
}
cell_versions_installed() {
    reset_cell V-installed-1.0-then-priority-alpha "installed 1.0 B, then alpha 0.9 priority=10"
    layout versions; repo alpha; repo beta; refresh
    run dnf -y install sampleapp
    local before; before="$(marker)"
    rm -f "$repofile"; repo alpha "priority=10"; repo beta "priority=90"; refresh
    whole_system upgrade
    local after_upgrade; after_upgrade="$(marker)"
    run dnf --assumeno distro-sync
    record "before=[$before] after-upgrade=[$after_upgrade] distro-sync-plan=[$(dnf --assumeno distro-sync 2>&1 | awk '/^ *sampleapp/ {print $1 "-" $3 "@" $4}' | paste -sd, -)]"
}

# Higher version from another publisher (vendor).
cell_upgrade() {
    local variant="$1"
    reset_cell "U-upgrade-$variant" "installed 1.0 A (vendor alpha); beta offers 1.1 + helper (vendor beta); $variant"
    layout upgrade
    case "$variant" in
        priority-alpha) repo alpha "priority=10"; repo beta "priority=90" ;;
        excludepkgs-beta) repo alpha; repo beta "excludepkgs=sampleapp" ;;
        *) repo alpha; repo beta ;;
    esac
    # dnf.conf holds only [main], so an appended line lands in [main].
    [[ "$variant" == no-vendor-change ]] && printf 'allow_vendor_change=False\n' >> /etc/dnf/dnf.conf
    refresh
    run dnf -y install sampleapp-1.0-1
    local before; before="$(marker)"
    whole_system upgrade
    record "before=[$before] after=[$(marker)] vendor=$(rpm -q --qf '%{VENDOR}' sampleapp) helper=$(helper_version) fetched=$(fetched)"
}

# Package family.
cell_family() {
    reset_cell F-family-remove-base "alpha offers sampleapp 1.1 + helper; install, then remove helper"
    layout family; repo alpha; refresh
    run dnf -y install sampleapp
    local before; before="$(marker)"
    run dnf -y remove sampleapp-helper
    record "before=[$before] after-helper-removal=[$(marker)] helper=$(rpm -q sampleapp-helper >/dev/null 2>&1 && echo present || echo absent)"
}
cell_family_split() {
    reset_cell F-family-split "sampleapp 1.1 in alpha, its helper only in beta"
    layout family-split; repo alpha; repo beta; refresh
    run dnf -y install sampleapp
    record "installed=[$(marker)] helper=$(helper_version) fetched=$(fetched)"
}

# A system source with the same NEVRA appears later.
cell_system() {
    local system_priority="$1"
    reset_cell "S-system-appears-priority-$system_priority" "installed A from alpha (priority 50), then system repo with equal S, priority=$system_priority"
    layout system; repo alpha "priority=50"; refresh
    run dnf -y install sampleapp
    local before; before="$(marker)"
    repo system "priority=$system_priority"; refresh
    whole_system upgrade
    local after_upgrade; after_upgrade="$(marker)"
    run dnf -y reinstall sampleapp
    record "before=[$before] after-upgrade=[$after_upgrade] after-reinstall=[$(marker)] from=$(from_repo) fetched=$(fetched)"
}

# Source disappears (404) or goes offline (connection refused).
offline_beta() {
    sed -i '/pakomichi.test/d' /etc/hosts
    if [[ "$1" == on ]]; then
        printf '127.0.0.1 alpha.pakomichi.test system.pakomichi.test\n127.0.0.2 beta.pakomichi.test\n' >> /etc/hosts
    else
        printf '127.0.0.1 alpha.pakomichi.test beta.pakomichi.test system.pakomichi.test\n' >> /etc/hosts
    fi
    say "beta offline: $1"
}
cell_removed() {
    local mode="$1"
    reset_cell "R-beta-$mode" "installed B (beta priority=10), then beta is $mode"
    layout equal; repo alpha "priority=90"; repo beta "priority=10"; refresh
    run dnf -y install sampleapp
    local before; before="$(marker)"
    if [[ "$mode" == removed ]]; then rm -rf "$served/beta"; else offline_beta on; fi
    # Per-repository fail-closed first, then the distribution default, then
    # an explicit skip.
    run dnf -y --setopt=pakomichi-r001-beta.skip_if_unavailable=False reinstall sampleapp; local strict_status=$?
    local after_strict; after_strict="$(marker)"
    run dnf -y makecache; local makecache_status=$?
    whole_system upgrade; local upgrade_status=$?
    run dnf -y reinstall sampleapp; local reinstall_status=$?
    local after; after="$(marker)"
    run dnf -y --setopt=pakomichi-r001-beta.skip_if_unavailable=True reinstall sampleapp; local skip_status=$?
    [[ "$mode" == offline ]] && offline_beta off
    record "before=[$before] strict-reinstall-exit=$strict_status after-strict=[$after_strict] makecache-exit=$makecache_status upgrade-exit=$upgrade_status reinstall-exit=$reinstall_status after-reinstall=[$after] skip-unavailable-reinstall-exit=$skip_status after-skip=[$(marker)] from=$(from_repo) fetched=$(fetched)"
}

# Mandatory negative fixtures: simulation only, never installed.
outcome() {
    local out status
    out="$(dnf --assumeno install "$@" 2>&1)"; status=$?
    printf '%s\n' "$out" >> "$log"
    if grep -qiE 'problem|nothing provides|conflict' <<< "$out"; then echo "unresolvable(exit $status)"
    else echo "resolvable(exit $status):$(awk '/^ *sampleapp/ {print $1}' <<< "$out" | paste -sd, -)"; fi
}
cell_negative() {
    reset_cell N-negative "missing dependency, Provides glibc (N-008), glibc >= 2.99 with a provider; simulation only"
    layout negative; repo alpha; refresh
    record "missingdep=$(outcome sampleapp-missingdep) glibc-provides=$(outcome sampleapp-glibc) nextglibc-with-provider=$(outcome sampleapp-nextglibc)"
}
cell_negative_next() {
    reset_cell N-009-next-glibc "glibc >= 2.99 without any third-party provider; simulation only"
    layout negative-next; repo alpha; refresh
    record "nextglibc=$(outcome sampleapp-nextglibc)"
}

prepare
cell_equal_order alpha beta
cell_equal_order beta alpha
cell_equal_priority alpha
cell_equal_priority beta
cell_equal_excludepkgs
cell_equal_includepkgs
cell_equal_disableexcludes
cell_equal_explicit_repo repo-option
cell_equal_explicit_repo disablerepo
cell_equal_installed
cell_dirty_cache
cell_versions none
cell_versions alpha
cell_versions_installed
cell_upgrade default
cell_upgrade no-vendor-change
cell_upgrade priority-alpha
cell_upgrade excludepkgs-beta
cell_family
cell_family_split
cell_system 99
cell_system 10
cell_removed removed
cell_removed offline
cell_negative
cell_negative_next
finish
cat "$results"
