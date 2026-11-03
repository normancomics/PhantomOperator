#!/usr/bin/env bash
# Interactive, local-only Stripe card/Link MPP setup for PhantomOperator.
# It never prints the key and never enables the public rail automatically.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/.env"
TMP_ENV="$(mktemp "$ROOT/.env.stripe.XXXXXX")"
PROFILE_RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$TMP_ENV" "$PROFILE_RESPONSE_FILE"' EXIT

printf 'Stripe card/Link MPP setup for PhantomOperator\n'
printf 'This validates a Stripe Business Network profile only; it does not create a charge.\n'
read -r -s -p 'Paste restricted Stripe secret key (input hidden): ' STRIPE_SECRET_KEY
printf '\n'

if [[ ! "$STRIPE_SECRET_KEY" =~ ^(rk|sk)_(test|live)_[A-Za-z0-9_]+$ ]]; then
  printf 'Use a Stripe restricted or secret key beginning rk_live_, rk_test_, sk_live_, or sk_test_. Nothing was written.\n' >&2
  exit 1
fi

PROFILE_STATUS="$(curl --silent --show-error -o "$PROFILE_RESPONSE_FILE" -w '%{http_code}' \
  -u "$STRIPE_SECRET_KEY:" \
  -H 'Stripe-Version: 2026-07-29.preview' \
  https://api.stripe.com/v2/network/business_profiles/me)"
if [[ "$PROFILE_STATUS" != 2* ]]; then
  MESSAGE="$(node -e 'const fs=require("fs");try{const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(x.error?.message||"No Stripe error message returned")}catch{process.stdout.write("No parseable Stripe error message returned")}' "$PROFILE_RESPONSE_FILE")"
  printf 'Stripe profile validation failed (HTTP %s): %s\nNothing was written.\n' "$PROFILE_STATUS" "$MESSAGE" >&2
  exit 1
fi

STRIPE_PROFILE_ID="$(node -e 'const fs=require("fs");try{const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(!/^profile(_test)?_/.test(x.id||""))process.exit(2);process.stdout.write(x.id)}catch{process.exit(2)}' "$PROFILE_RESPONSE_FILE")" || {
  printf 'Stripe did not return a usable profile ID. Nothing was written.\n' >&2
  exit 1
}

if [[ -f "$ENV_FILE" ]]; then
  grep -vE '^(STRIPE_SECRET_KEY|STRIPE_PROFILE_ID|ENABLE_STRIPE_MPP)=' "$ENV_FILE" > "$TMP_ENV" || true
else
  : > "$TMP_ENV"
fi
{
  printf '\n# Stripe card/Link MPP (managed locally; never commit)\n'
  printf 'STRIPE_SECRET_KEY=%s\n' "$STRIPE_SECRET_KEY"
  printf 'STRIPE_PROFILE_ID=%s\n' "$STRIPE_PROFILE_ID"
  printf '# Stays false until the server challenge and a real authorized test payment pass.\n'
  printf 'ENABLE_STRIPE_MPP=false\n'
} >> "$TMP_ENV"
chmod 600 "$TMP_ENV"
mv "$TMP_ENV" "$ENV_FILE"

printf 'Stripe MPP profile stored securely. The rail is still disabled pending an end-to-end authorized test.\n'
