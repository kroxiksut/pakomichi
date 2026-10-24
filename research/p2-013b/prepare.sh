#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prepare a P2-013b target (systemd running, disposable): the process
# layout of ADR-035 with its real units. Users pakomichi (state owner),
# pakomichi-reader, pakomichi-signer; the inspector runs with DynamicUser.
# The local metadata key is created by and for pakomichi-signer only. One
# real GitHub asset of the public R-003 test repository is fetched once to
# publish a generation; the scenarios then drop it from the CAS again.
# Run as root with the harness in /opt/p2013b.
set -euo pipefail
# shellcheck source=lib.sh
source /opt/p2013b/lib.sh

[[ "$(ps -o comm= -p 1)" == systemd ]] || { echo "systemd is not PID 1" >&2; exit 1; }

install -m 0755 /opt/p2013b/bin/* /usr/local/bin/
install -m 0644 /opt/p2013b/units/* /etc/systemd/system/
install -d /etc/systemd/system/pakomichi-reader.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/local/bin/pakomichi-reader --publish-root %s --cas-root %s --fetch-socket /run/pakomichi/fetch.sock\n' \
    "$PUBLISH" "$CAS" >/etc/systemd/system/pakomichi-reader.service.d/fetch.conf

for user in pakomichi pakomichi-signer; do
    getent group "$user" >/dev/null || groupadd --system "$user"
    getent passwd "$user" >/dev/null ||
        useradd --system --gid "$user" --home-dir /nonexistent --shell /usr/sbin/nologin "$user"
done
getent group pakomichi-reader >/dev/null || groupadd --system pakomichi-reader
getent passwd pakomichi-reader >/dev/null ||
    useradd --system --gid pakomichi-reader --groups pakomichi --home-dir /nonexistent \
        --shell /usr/sbin/nologin pakomichi-reader

rm -rf "$STATE" /var/lib/pakomichi-signer /srv/p2013b
install -d -o pakomichi -g pakomichi -m 0750 "$STATE" "$CAS"
install -d -o pakomichi -g pakomichi -m 0700 "$STATE/state"
install -d -o pakomichi-signer -g pakomichi-signer -m 0700 /var/lib/pakomichi-signer "$SIGNER_HOME"
install -d -m 0755 /etc/pakomichi /etc/apt/keyrings /srv/p2013b

runuser -u pakomichi-signer -- gpg --homedir "$SIGNER_HOME" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "Pakomichi P2-013b TEST ONLY <p2013b@example.invalid>" ed25519 sign 1y 2>/dev/null
key=$(runuser -u pakomichi-signer -- gpg --homedir "$SIGNER_HOME" --batch --with-colons --list-secret-keys |
    awk -F: '/^fpr/ {print $10; exit}')
runuser -u pakomichi-signer -- gpgconf --homedir "$SIGNER_HOME" --kill all 2>/dev/null || true
runuser -u pakomichi-signer -- gpg --homedir "$SIGNER_HOME" --batch --export "$key" >"$KEYRING"
chmod 0644 "$KEYRING"
printf 'KEY=%s\n' "$key" >/etc/pakomichi/signer.env
printf '%s\n' "$key" >/srv/p2013b/key
# This host's DNS answers the GitHub asset host from a fake-IP range of a
# local traffic router; the operator allows it explicitly (P3-005b).
printf 'STATE_ARGS=--allow-range 198.18.0.0/15\n' >/etc/pakomichi/state.env

systemctl daemon-reload
systemctl enable --now pakomichi-sign.socket pakomichi-inspect.socket pakomichi-fetch.socket pakomichi-reader.socket
for socket in sign inspect fetch; do
    [[ -S /run/pakomichi/$socket.sock ]] || { echo "no $socket.sock" >&2; exit 1; }
done

# The state database: created by the state owner itself, then the pin of
# the fixture asset is recorded as an accepted artifact.
systemctl start pakomichi-state.service
# The database is ready once the owner reports its start (after the
# migrations), not when the file appears.
for _ in $(seq 100); do
    journalctl -q -u pakomichi-state.service -o cat | grep -q event=start && break
    sleep 0.2
done
journalctl -q -u pakomichi-state.service -o cat | grep -q event=start || { echo "state owner did not start" >&2; exit 1; }
systemctl stop pakomichi-state.service
runuser -u pakomichi -- sqlite3 "$STATE/state/state.db" <<SQL
PRAGMA foreign_keys = ON;
INSERT INTO forge_repository (id, forge, repository_id, owner_id, canonical_url, first_seen_at)
VALUES ('source-1', 'github', '$REPOSITORY', '2264172', 'https://github.com/pchi-test-org/pchi-test-renamed', '2026-10-22T00:00:00Z');
INSERT INTO package_family (id, source_id, name, purpose) VALUES ('family-1', 'source-1', 'fixture', 'test');
INSERT INTO package_identity (family_id, ecosystem, native_name, allowed_arches_json)
VALUES ('family-1', 'deb', 'pakomichi-r003-fixture', '["all"]');
INSERT INTO release_record (id, source_id, forge_release_id, tag, published_at, channel)
VALUES ('release-1', 'source-1', '420339762', 'v0.2.0-mutable', '2026-10-22T00:00:00Z', 'stable');
INSERT INTO trust_evidence (id, source_id, evidence_type, root_chain_json, signer_identity, repository_id,
    subject_sha256, predicate_type, verified_at, verifier_version, record_json)
VALUES ('evidence-1', 'source-1', 'attested', '[]', 'P2-013b TEST ONLY', '$REPOSITORY', '$SHA', 'test',
    '2026-10-23T00:00:00Z', '0.0.0', '{}');
INSERT INTO artifact (id, source_id, release_id, asset_id, family_id, ecosystem, native_name, native_version,
    architecture, filename, sha256, byte_size, evidence_id, state)
VALUES ('artifact-1', 'source-1', 'release-1', '$ASSET', 'family-1', 'deb', 'pakomichi-r003-fixture', '0.2.0',
    'all', 'pakomichi-r003-fixture_0.2.0_all.deb', '$SHA', $SIZE, 'evidence-1', 'published');
SQL

# The fixture bytes, once, through the production downloader.
rm -rf /tmp/p2013b-fetch
/usr/local/bin/p3005b-fetch --cas /tmp/p2013b-fetch --repository "$REPOSITORY" --asset "$ASSET" \
    --sha256 "$SHA" --size "$SIZE" --allow-range 198.18.0.0/15
install -m 0644 "/tmp/p2013b-fetch/objects/$SHA" "$FIXTURE"
rm -rf /tmp/p2013b-fetch

runuser -u pakomichi -- /usr/local/bin/p3001-publish --publish-root "$PUBLISH" --cas-root "$CAS" \
    --label "$LABEL" --source source-1 --sign-socket /run/pakomichi/sign.sock --key "$key" \
    --keyring "$KEYRING" --confirmed-ago 600 "$FIXTURE"
printf 'Types: deb\nURIs: http://127.0.0.1:18080/%s\nSuites: %s\nComponents: main\nSigned-By: %s\n' \
    "$LABEL" "$LABEL" "$KEYRING" >"$SOURCES"
echo "prepared $(hostname) key=$key"
