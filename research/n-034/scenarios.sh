#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# N-034 (ADR-024 point 6, ADR-036 point 2): can an unprivileged local user
# take over the loopback port of the repository socket while the socket is
# down? Run as root inside a disposable distribution with systemd as PID 1
# (research/n-034/run.ps1). For a privileged port (879) and the current
# default (18080), a systemd socket unit holds 127.0.0.1:<port>; the test
# user tries to bind it while the socket listens, after `systemctl stop`,
# and after a crash loop has put the socket into `failed`. A last case binds
# the privileged port inside the user's own user and network namespace and
# checks that the host loopback does not see it.
#
# Output: $N034_OUT/results.tsv (id, port, expected, observed, verdict) and
# $N034_OUT/facts.txt.
set -uo pipefail

out=${N034_OUT:?N034_OUT is required}
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
probe="$here/probe.py"
user=n034
mkdir -p "$out"
results="$out/results.tsv"
printf 'id\tport\texpected\tobserved\tverdict\n' >"$results"
failures=0

getent passwd "$user" >/dev/null || useradd --create-home --shell /bin/bash "$user"
install -m 0755 "$probe" /usr/local/bin/n034-probe

{
    echo "kernel: $(uname -r)"
    echo "os: $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "systemd: $(systemctl --version | head -1)"
    echo "ip_unprivileged_port_start: $(sysctl -n net.ipv4.ip_unprivileged_port_start)"
    echo "test user: $(id "$user")"
    echo "test user capabilities: $(runuser -u "$user" -- grep CapEff /proc/self/status)"
    echo "unprivileged user namespaces: $(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 'no sysctl (allowed by default)')"
} >"$out/facts.txt"

record() { # id port expected observed
    local verdict=PASS
    [[ $3 == "$4" ]] || { verdict=FAIL; failures=$((failures + 1)); }
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$verdict" >>"$results"
}

as_user() { runuser -u "$user" -- "$@"; }

units() { # port
    cat >"/etc/systemd/system/n034-$1.socket" <<EOF
[Unit]
Description=N-034 loopback socket on port $1

[Socket]
ListenStream=127.0.0.1:$1
Accept=no
Service=n034-$1.service
EOF
    # A service that always fails: two failed starts put the socket into
    # failed (service-start-limit-hit), as a crash loop would (R-004 S7).
    cat >"/etc/systemd/system/n034-$1.service" <<EOF
[Unit]
Description=N-034 crashing service on port $1
StartLimitIntervalSec=300
StartLimitBurst=2

[Service]
ExecStart=/bin/false
EOF
    systemctl daemon-reload
}

crash_loop() { # port
    local state result
    for _ in 1 2 3 4 5 6; do
        as_user n034-probe connect 127.0.0.1 "$1" >/dev/null
        sleep 1
        state=$(systemctl show -p ActiveState --value "n034-$1.socket")
        [[ $state == failed ]] && break
    done
    result=$(systemctl show -p Result --value "n034-$1.socket")
    echo "$state/$result"
}

for port in 879 18080; do
    units "$port"
    systemctl reset-failed "n034-$port.socket" "n034-$port.service" 2>/dev/null
    systemctl start "n034-$port.socket"
    # The kernel checks the privileged range before the port is in use.
    if [[ $port -lt 1024 ]]; then
        down=EACCES up=EACCES
    else
        down=bound up=EADDRINUSE
    fi

    record S1-listening "$port" "$up" "$(as_user n034-probe bind 127.0.0.1 "$port")"
    record S1-listening-reuseport "$port" "$up" "$(as_user n034-probe bind 127.0.0.1 "$port" reuseport)"

    systemctl stop "n034-$port.socket"
    record S2-stopped-state "$port" inactive "$(systemctl show -p ActiveState --value "n034-$port.socket")"
    record S2-stopped "$port" "$down" "$(as_user n034-probe bind 127.0.0.1 "$port")"
    record S2-stopped-any-address "$port" "$down" "$(as_user n034-probe bind 0.0.0.0 "$port")"

    systemctl start "n034-$port.socket"
    record S3-failed-state "$port" failed/service-start-limit-hit "$(crash_loop "$port")"
    record S3-failed "$port" "$down" "$(as_user n034-probe bind 127.0.0.1 "$port")"

    systemctl stop "n034-$port.socket" "n034-$port.service" 2>/dev/null
    systemctl reset-failed "n034-$port.socket" "n034-$port.service" 2>/dev/null
done

# S4: in its own user and network namespace the user is root and may bind
# 879, but that loopback is not the host's: APT on the host cannot reach it.
inside=$(as_user unshare --user --map-root-user --net bash -c \
    'ip link set lo up && timeout 10 n034-probe bind 127.0.0.1 879' 2>&1 | tail -1)
record S4-own-namespace-bind 879 bound "$inside"
as_user unshare --user --map-root-user --net bash -c \
    'ip link set lo up && python3 -c "
import socket, time
s = socket.socket(); s.bind((\"127.0.0.1\", 879)); s.listen(1); time.sleep(8)"' &
holder=$!
sleep 2
record S4-host-sees-it 879 ECONNREFUSED "$(n034-probe connect 127.0.0.1 879)"
wait "$holder"

rm -f /etc/systemd/system/n034-*.socket /etc/systemd/system/n034-*.service
systemctl daemon-reload
cat "$results"
exit "$failures"
