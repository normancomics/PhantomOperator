#!/usr/bin/env bash
set -euo pipefail
curl --fail-with-body --silent --show-error \
  -X POST https://freysaai.freysa.dev/mcp \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | jq .
