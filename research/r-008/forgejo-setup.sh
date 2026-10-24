#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Phase 1 (inside pakomichi-r008-forgejo): install tools, fetch the Forgejo
# docs page with the signing-key fingerprint and the latest release metadata.
set -euo pipefail
OUT=/tmp/r008; mkdir -p "$OUT"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq gnupg curl ca-certificates git sqlite3 python3 >/dev/null
curl -fsSL https://forgejo.org/docs/latest/admin/installation/binary/ -o "$OUT/docs-binary.html"
curl -fsSL https://codeberg.org/api/v1/repos/forgejo/forgejo/releases/latest -o "$OUT/latest.json"
grep -oiE '[0-9A-F]{4}( ?[0-9A-F]{4}){9}|[0-9A-F]{40}' "$OUT/docs-binary.html" | sort -u || true
python3 - <<'EOF'
import json
d=json.load(open('/tmp/r008/latest.json'))
print(d['tag_name'], d['published_at'])
for a in d['assets']:
    if 'linux-amd64' in a['name']: print(a['name'], a['browser_download_url'])
EOF
