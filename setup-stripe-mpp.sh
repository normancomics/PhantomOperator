#!/usr/bin/env bash
# Secure local setup for Stripe MPP. Run interactively on the PhantomOperator host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/.env"
TMP_ENV="$(mktemp "$ROOT/.env.stripe.XXXXXX")"
RESPONSE_FILE=""
PROFILE_RESPONSE_FILE=""
trap 'rm -f "$TMP_ENV" "${RESPONSE_FILE:-}" "${PROFILE_RESPONSE_FILE:-}"' EXIT

printf 'Stripe MPP setup for PhantomOperator\n'
read -r -s -p 'Paste restricted Stripe secret key (input hidden): ' STRIPE_SECRET_KEY
printf '\n'
# Profile is resolved automatically using this key's Stripe Profiles read scope.
STRIPE_PROFILE_ID=""

# Stripe restricted keys use rk_live_/rk_test_; standard secret keys use sk_live_/sk_test_.
if [[ ! "$STRIPE_SECRET_KEY" =~ ^(rk|sk)_(test|live)_[A-Za-z0-9_]+$ ]]; then
  printf 'Use a Stripe restricted or secret key beginning rk_live_, rk_test_, sk_live_, or sk_test_. Nothing was written.\n' >&2
  exit 1
fi
if [[ -n "$STRIPE_PROFILE_ID" && ! "$STRIPE_PROFILE_ID" =~ ^profile(_test)?_[A-Za-z0-9_]+$ ]]; then
  printf 'The profile ID must start with profile_ or profile_test_. Nothing was written.\n' >&2
  exit 1
fi

if [[ -z "$STRIPE_PROFILE_ID" ]]; then
  PROFILE_RESPONSE_FILE="$(mktemp)"
  PROFILE_STATUS="$(curl --silent --show-error -o "$PROFILE_RESPONSE_FILE" -w '%{http_code}' \
    -u "$STRIPE_SECRET_KEY:" \
    -H 'Stripe-Version: 2026-07-29.preview' \
    https://api.stripe.com/v2/network/business_profiles/me)"
  PROFILE_RESPONSE="$(cat "$PROFILE_RESPONSE_FILE")"
  if [[ "$PROFILE_STATUS" != 2* ]]; then
    MESSAGE="$(printf '%s' "$PROFILE_RESPONSE" | node -e 'let d="";process.stdin.on("data",x=>d+=x).on("end",()=>{try{const x=JSON.parse(d);process.stdout.write((x.error&&x.error.message)||"No Stripe error message returned")}catch{process.stdout.write("No parseable Stripe error message returned")}})')"
    printf 'Stripe profile auto-detection failed (HTTP %s): %s\nNothing was written.\n' "$PROFILE_STATUS" "$MESSAGE" >&2
    exit 1
  fi
  STRIPE_PROFILE_ID="$(printf '%s' "$PROFILE_RESPONSE" | node -e 'let d="";process.stdin.on("data",x=>d+=x).on("end",()=>{try{const x=JSON.parse(d);if(!/^profile(_test)?_/.test(x.id||""))process.exit(2);process.stdout.write(x.id)}catch{process.exit(2)}})')" || {
    printf 'Stripe did not return a usable profile ID. Nothing was written.\n' >&2
    exit 1
  }
fi

# Stripe’s MPP documentation requires an account-owned Tempo deposit address.
RESPONSE_FILE="$(mktemp)"
HTTP_STATUS="$(curl --silent --show-error -o "$RESPONSE_FILE" -w '%{http_code}' \
  -u "$STRIPE_SECRET_KEY:" \
  -H 'Stripe-Version: 2026-07-29.preview' \
  -d network=tempo \
  https://api.stripe.com/v1/crypto/deposit_addresses)"
RESPONSE="$(cat "$RESPONSE_FILE")"
if [[ "$HTTP_STATUS" != 2* ]]; then
  MESSAGE="$(printf '%s' "$RESPONSE" | node -e 'let d="";process.stdin.on("data",x=>d+=x).on("end",()=>{try{const x=JSON.parse(d);process.stdout.write((x.error&&x.error.message)||"No Stripe error message returned")}catch{process.stdout.write("No parseable Stripe error message returned")}})')"
  printf 'Stripe deposit-address setup failed (HTTP %s): %s\nNothing was written.\n' "$HTTP_STATUS" "$MESSAGE" >&2
  exit 1
fi
TEMPO_DEPOSIT_ADDRESS="$(printf '%s' "$RESPONSE" | node -e 'let d="";process.stdin.on("data",x=>d+=x).on("end",()=>{try{const x=JSON.parse(d);if(!x.address)process.exit(2);process.stdout.write(x.address)}catch{process.exit(2)}})')" || {
  printf 'Stripe did not return a Tempo deposit address. Nothing was written.\n' >&2
  exit 1
}

# Replace prior Stripe MPP entries without displaying any secret.
if [[ -f "$ENV_FILE" ]]; then
  grep -vE '^(STRIPE_SECRET_KEY|STRIPE_PROFILE_ID|TEMPO_DEPOSIT_ADDRESS)=' "$ENV_FILE" > "$TMP_ENV" || true
else
  : > "$TMP_ENV"
fi
{
  printf '\n# Stripe MPP (managed locally; never commit)\n'
  printf 'STRIPE_SECRET_KEY=%s\n' "$STRIPE_SECRET_KEY"
  printf 'STRIPE_PROFILE_ID=%s\n' "$STRIPE_PROFILE_ID"
  printf 'TEMPO_DEPOSIT_ADDRESS=%s\n' "$TEMPO_DEPOSIT_ADDRESS"
} >> "$TMP_ENV"
chmod 600 "$TMP_ENV"
mv "$TMP_ENV" "$ENV_FILE"

printf 'Stripe MPP credentials stored securely. Tempo deposit address: %s\n' "$TEMPO_DEPOSIT_ADDRESS"
printf 'Next: tell the agent setup completed; it will wire and test the MPP Stripe payment method.\n'
