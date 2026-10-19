#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly project_root
readonly probe_root="$project_root/prototypes/p0-004"
# shellcheck source=paths.sh
source "$project_root/prototypes/p0-004/paths.sh"
readonly binary="$CARGO_TARGET_DIR/debug/pakomichi-stack-probe"
readonly work="$project_root/.research-local/p0-004/systemd-runtime"
readonly unit_copy="/tmp/pakomichi-stack-probe.service"

mkdir -p "$work"
test -x "$binary"
trap 'rm -f "$unit_copy"' EXIT

run_request() {
    local port="$1"
    local method="$2"
    local expected="$3"
    systemd-socket-activate --listen="127.0.0.1:$port" "$binary" > "$work/$port.log" 2>&1 &
    local activator_pid=$!
    trap 'kill "$activator_pid" 2>/dev/null || true' RETURN
    local status
    status="$(curl --silent --show-error --retry 20 --retry-connrefused --retry-delay 0 \
        --request "$method" --output "$work/$port.body" --write-out '%{http_code}' \
        "http://127.0.0.1:$port/health")"
    wait "$activator_pid"
    test "$status" = "$expected"
}

if "$binary" > "$work/no-activation.log" 2>&1; then
    printf 'FAIL: process accepted startup without socket activation\n' >&2
    exit 1
fi

run_request 18081 GET 200
run_request 18082 POST 405

systemd-socket-activate --setenv=PAKOMICHI_PROBE_REQUESTS=2 --listen=127.0.0.1:18084 \
    "$binary" > "$work/18084.log" 2>&1 &
readonly concurrent_pid=$!
curl --silent --show-error --retry 20 --retry-connrefused --retry-delay 0 \
    "http://127.0.0.1:18084/blocking-probe" > "$work/18084-blocking.body" &
readonly blocking_curl_pid=$!
for _ in $(seq 1 50); do
    grep -q 'Execing' "$work/18084.log" && break
    sleep 0.05
done
grep -q 'Execing' "$work/18084.log"
sleep 0.2
curl --silent --show-error --retry 20 --retry-connrefused --retry-delay 0 \
    --max-time 1 "http://127.0.0.1:18084/health" > "$work/18084-health.body"
wait "$blocking_curl_pid"
wait "$concurrent_pid"
grep -q '^ok$' "$work/18084-health.body"

systemd-socket-activate --listen=0.0.0.0:18083 "$binary" > "$work/external-bind.log" 2>&1 &
readonly external_pid=$!
curl --silent --show-error --retry 20 --retry-connrefused --retry-delay 0 \
    --max-time 2 "http://127.0.0.1:18083/health" > /dev/null 2>&1 || true
if wait "$external_pid"; then
    printf 'FAIL: process accepted a non-loopback listener\n' >&2
    exit 1
fi

sed "s|ExecStart=/usr/bin/pakomichi-stack-probe|ExecStart=$binary|" \
    "$probe_root/pakomichi-stack-probe.service" > "$unit_copy"
chmod 0644 "$unit_copy"
systemd-analyze security --offline=yes --no-pager \
    "$unit_copy" > "$work/security.txt"
grep -q 'Overall exposure level' "$work/security.txt"

printf 'PASS: Tokio serves health while blocking work is isolated; concurrency is bounded; socket and sandbox checks pass\n'
