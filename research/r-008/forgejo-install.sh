#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Phase 2 (inside pakomichi-r008-forgejo): download the Forgejo release,
# verify SHA-256 and the OpenPGP signature, lay out an unprivileged install
# on 127.0.0.1:3300 (SQLite, INSTALL_LOCK=true) and write forgejo.lock.json.
set -euo pipefail
export LC_ALL=C
REPO=/mnt/d/Projects/pakomichi
OUT=/tmp/r008; mkdir -p "$OUT"
VER=${FORGEJO_VERSION:-17.0.0}
BASE=https://codeberg.org/forgejo/forgejo/releases/download/v$VER
NAME=forgejo-$VER-linux-amd64
# Fingerprint published on https://forgejo.org/download/ ("Verify GPG signature").
FPR=EB114F5E6C0DC2BCDD183550A4B61A2DC5923710

cd "$OUT"
for s in "" .sha256 .asc; do curl -fsSL "$BASE/$NAME$s" -o "$NAME$s"; done

export GNUPGHOME=$OUT/gnupg; rm -rf "$GNUPGHOME"; mkdir -m 700 "$GNUPGHOME"
gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$FPR" 2>&1 | tail -3
GOT=$(gpg --batch --with-colons --fingerprint "$FPR" | awk -F: '/^fpr/{print $10; exit}')
[ "$GOT" = "$FPR" ] || { echo "fingerprint mismatch: $GOT"; exit 1; }
gpg --batch --status-fd 1 --verify "$NAME.asc" "$NAME" 2>"$OUT/gpg-verify.txt" | tee "$OUT/gpg-status.txt" | grep -E 'GOODSIG|VALIDSIG|BADSIG|ERRSIG'
grep -q 'VALIDSIG' "$OUT/gpg-status.txt" || { echo "signature NOT verified"; exit 1; }
SIGFPR=$(awk '/VALIDSIG/{print $NF}' "$OUT/gpg-status.txt")
echo "primary key fingerprint of signature: $SIGFPR"
[ "$SIGFPR" = "$FPR" ] || { echo "signature primary fingerprint differs from published one"; exit 1; }
EXPECT=$(awk '{print $1}' "$NAME.sha256")
ACTUAL=$(sha256sum "$NAME" | awk '{print $1}')
[ "$EXPECT" = "$ACTUAL" ] || { echo "sha256 mismatch"; exit 1; }
echo "sha256 ok $ACTUAL"

install -m 755 "$NAME" /usr/local/bin/forgejo
id forgejo >/dev/null 2>&1 || adduser --system --shell /bin/bash --gecos 'Forgejo lab' --group --disabled-password --home /home/forgejo forgejo
mkdir -p /var/lib/forgejo /etc/forgejo
chown forgejo:forgejo /var/lib/forgejo; chmod 750 /var/lib/forgejo
chown root:forgejo /etc/forgejo; chmod 770 /etc/forgejo
SECRET=$(forgejo generate secret SECRET_KEY)
cat > /etc/forgejo/app.ini <<EOF
APP_NAME = r008-lab
RUN_USER = forgejo
WORK_PATH = /var/lib/forgejo
RUN_MODE = prod

[server]
PROTOCOL = http
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3300
DOMAIN = 127.0.0.1
ROOT_URL = http://127.0.0.1:3300/
DISABLE_SSH = true
START_SSH_SERVER = false
OFFLINE_MODE = true

[database]
DB_TYPE = sqlite3
PATH = /var/lib/forgejo/data/forgejo.db

[security]
INSTALL_LOCK = true
SECRET_KEY = $SECRET

[service]
DISABLE_REGISTRATION = true

[packages]
ENABLED = true

[log]
MODE = console
LEVEL = Info
EOF
chown forgejo:forgejo /etc/forgejo/app.ini; chmod 660 /etc/forgejo/app.ini

VERSION_OUT=$(forgejo --version | head -1)
cat > "$REPO/research/r-008/forgejo.lock.json" <<EOF
{
  "version": "$VER",
  "version_banner": "$VERSION_OUT",
  "url": "$BASE/$NAME",
  "sha256": "$ACTUAL",
  "sha256_source": "$BASE/$NAME.sha256",
  "signature": "$BASE/$NAME.asc",
  "signing_key_fingerprint": "$FPR",
  "fingerprint_source": "https://forgejo.org/download/ (section: Verify GPG signature)",
  "key_fetched_from": "hkps://keys.openpgp.org",
  "signature_status": "VALIDSIG, primary key fingerprint equals the published one"
}
EOF
cp "$OUT/gpg-status.txt" "$OUT/gpg-verify.txt" "$OUT"/*.sha256 /tmp/ 2>/dev/null || true
echo "installed: $VERSION_OUT"
