#!/usr/bin/env bash
set -euo pipefail
# Prints the exact Base-USDC x402 requirement. This does not make a payment.
curl --silent --show-error --include \
  -X POST https://freysaai.freysa.dev/skills/metadata-audit \
  -H 'content-type: application/json' \
  --data '{"url":"https://example.com"}'
