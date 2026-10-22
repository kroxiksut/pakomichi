#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# R-004 step 3: how GitHub answers conditional requests for release metadata.
# Anonymous, read-only, six requests to the public cli/cli repository. Prints
# only the status line and selected headers (no cookies, no tokens).
set -euo pipefail

api=https://api.github.com/repos/cli/cli
headers() { grep -iE '^(HTTP/|etag:|last-modified:|x-ratelimit-remaining:|x-ratelimit-used:|cache-control:|vary:)' | tr -d '\r'; }
request() { # label url [extra curl args]
    local label=$1 url=$2; shift 2
    echo "== $label"
    curl -sS -D - -o /dev/null -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' "$@" "$url" | headers
}

first=$(curl -sS -D - -o /dev/null -H 'Accept: application/vnd.github+json' "$api/releases/latest" | tr -d '\r')
etag=$(sed -n 's/^[Ee][Tt]ag: //p' <<<"$first")
modified=$(sed -n 's/^[Ll]ast-[Mm]odified: //p' <<<"$first")
echo "== 1 unconditional GET releases/latest"; headers <<<"$first"
request "2 If-None-Match with the ETag from 1" "$api/releases/latest" -H "If-None-Match: $etag"
request "3 If-None-Match with a different ETag" "$api/releases/latest" -H 'If-None-Match: W/"0000"'
request "4 the ETag from 1 on another URL (releases?per_page=1)" "$api/releases?per_page=1" -H "If-None-Match: $etag"
request "5 If-Modified-Since with Last-Modified from 1" "$api/releases/latest" -H "If-Modified-Since: $modified"
request "6 unconditional GET again" "$api/releases/latest"
