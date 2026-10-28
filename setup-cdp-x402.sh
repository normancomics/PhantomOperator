#!/usr/bin/env bash
# Interactive local CDP x402 credential setup.
# Run only in a trusted terminal on this VPS. Input is not printed or logged.
set -euo pipefail

ENV_FILE="/home/nixos/PhantomOperator/.env"
umask 077
mkdir -p "$(dirname "$ENV_FILE")"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

printf 'Coinbase CDP x402 setup for PhantomOperator\n'
printf 'Credentials will be stored only in %s\n\n' "$ENV_FILE"
read -r -p 'CDP API Key ID: ' key_id
read -r -s -p 'CDP API Key Secret (hidden): ' key_secret
printf '\n'

if [[ -z "$key_id" || -z "$key_secret" ]]; then
  printf 'Both values are required; no changes made.\n' >&2
  exit 1
fi

# Avoid shell interpolation of secret values: remove existing CDP credential lines,
# then append exactly the fresh values to a mode-600 temporary file.
tmp_file="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
trap 'rm -f "$tmp_file"' EXIT
{ grep -vE '^(CDP_API_KEY_ID|CDP_API_KEY_SECRET|CDP_API_KEY_NAME|CDP_API_KEY_PRIVATE_KEY)=' "$ENV_FILE" || true; } > "$tmp_file"
printf 'CDP_API_KEY_ID=%s\nCDP_API_KEY_SECRET=%s\n' "$key_id" "$key_secret" >> "$tmp_file"
chmod 600 "$tmp_file"
mv "$tmp_file" "$ENV_FILE"
trap - EXIT

printf 'CDP x402 credentials saved. Restart PhantomOperator only after the CDP facilitator integration is deployed.\n'
