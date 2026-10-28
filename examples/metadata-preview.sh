#!/usr/bin/env bash
set -euo pipefail
URL="${1:-https://example.com}"
curl --fail-with-body --silent --show-error \
  -X POST https://freysaai.freysa.dev/preview/metadata-audit \
  -H 'content-type: application/json' \
  --data "{\"url\":$(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$URL")}" | jq .
