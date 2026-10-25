#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare a P4-001a target (systemd running, disposable): every process of
# ADR-035 with its real units, the root applier, and the reader on
# 127.0.0.1:18080. Users pakomichi (state owner), pakomichi-reader,
# pakomichi-signer; the inspector runs with DynamicUser, the applier as
# root. The local metadata key is created by and for pakomichi-signer; its
# public part is exported for the state owner (gpgv) and, through the
# applier, for APT. Run as root with the harness in /opt/p4001a.
set -euo pipefail
# shellcheck source=lib.sh
source /opt/p4001a/lib.sh

[[ "$(ps -o comm= -p 1)" == systemd ]] || { echo "systemd is not PID 1" >&2; exit 1; }

install -m 0755 /opt/p4001a/bin/* /usr/local/bin/
install -m 0644 /opt/p4001a/units/* /etc/systemd/system/

for user in pakomichi pakomichi-signer; do
    getent group "$user" >/dev/null || groupadd --system "$user"
    getent passwd "$user" >/dev/null ||
        useradd --system --gid "$user" --home-dir /nonexistent --shell /usr/sbin/nologin "$user"
done
getent group pakomichi-reader >/dev/null || groupadd --system pakomichi-reader
getent passwd pakomichi-reader >/dev/null ||
    useradd --system --gid pakomichi-reader --groups pakomichi --home-dir /nonexistent \
        --shell /usr/sbin/nologin pakomichi-reader

rm -rf "$STATE" /var/lib/pakomichi-signer
install -d -o pakomichi -g pakomichi -m 0750 "$STATE" "$STATE/cas" "$STATE/publish"
install -d -o pakomichi -g pakomichi -m 0700 "$STATE/state" "$STATE/tuf" "$STATE/collector"
install -d -o pakomichi-signer -g pakomichi-signer -m 0700 /var/lib/pakomichi-signer "$SIGNER_HOME"
install -d -m 0755 /etc/pakomichi /etc/apt/keyrings

runuser -u pakomichi-signer -- gpg --homedir "$SIGNER_HOME" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "Pakomichi P4-001a TEST ONLY <p4001a@example.invalid>" ed25519 sign 1y 2>/dev/null
key=$(runuser -u pakomichi-signer -- gpg --homedir "$SIGNER_HOME" --batch --with-colons --list-secret-keys |
    awk -F: '/^fpr/ {print $10; exit}')
runuser -u pakomichi-signer -- gpgconf --homedir "$SIGNER_HOME" --kill all 2>/dev/null || true
runuser -u pakomichi-signer -- gpg --homedir "$SIGNER_HOME" --batch --export "$key" >"$METADATA_KEY"
chmod 0644 "$METADATA_KEY"
printf 'KEY=%s\n' "$key" >/etc/pakomichi/signer.env
# This host's DNS answers the asset host and tuf-repo.github.com from a
# fake-IP range of a local traffic router; the operator allows it
# explicitly (P3-005b, delivery-recovery.md).
printf 'KEY=%s\nSTATE_ARGS=--allow-range 198.18.0.0/15\n' "$key" >/etc/pakomichi/state.env

systemctl daemon-reload
systemctl enable --now pakomichi-sign.socket pakomichi-inspect.socket pakomichi-apply.socket \
    pakomichi-fetch.socket pakomichi-status.socket pakomichi-admin.socket pakomichi-reader.socket
for socket in sign inspect apply fetch status admin; do
    [[ -S /run/pakomichi/$socket.sock ]] || { echo "no $socket.sock" >&2; exit 1; }
done
# The state owner refreshes the trusted roots through TUF at start; it is
# started here so that the first command does not wait for that.
systemctl start pakomichi-state.service
for _ in $(seq 300); do
    journalctl -q -u pakomichi-state.service -o cat | grep -q event=start && break
    sleep 0.2
done
journalctl -q -u pakomichi-state.service -o cat | grep -q event=start ||
    { journalctl -q -u pakomichi-state.service -o cat >&2; echo "state owner did not start" >&2; exit 1; }
journalctl -q -u pakomichi-state.service -o cat
echo "prepared; metadata key $key"
