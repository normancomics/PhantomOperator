#!/usr/bin/env bash
# Interactive, local-only Stripe Checkout prepaid-credit & $19 Website Privacy
# Baseline setup for PhantomOperator.
# Never echoes secret keys and never exposes credentials on the process command line.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/.env"
TMP_ENV="$(mktemp "$ROOT/.env.stripe-credits.XXXXXX")"
RESP_FILE="$(mktemp)"
trap 'rm -f "$TMP_ENV" "$RESP_FILE"' EXIT

printf '=================================================================\n'
printf ' PhantomOperator — Stripe Prepaid Credits & $19 Baseline Setup\n'
printf '=================================================================\n'
printf 'Webhook endpoint to configure in Stripe Dashboard:\n'
printf '  URL:    https://freysaai.freysa.dev/billing/stripe/webhook\n'
printf '  Events: checkout.session.completed\n'
printf '          checkout.session.async_payment_succeeded\n\n'

read -r -s -p '1. Paste Stripe Secret/Restricted Key (sk_test_..., sk_live_..., rk_...): ' STRIPE_SECRET_KEY
printf '\n'
if [[ ! "$STRIPE_SECRET_KEY" =~ ^(rk|sk)_(test|live)_[A-Za-z0-9_]+$ ]]; then
  printf 'Error: Key must start with sk_test_, sk_live_, rk_test_, or rk_live_. Nothing was written.\n' >&2
  exit 1
fi

read -r -s -p '2. Paste Stripe Webhook Signing Secret (whsec_...): ' STRIPE_WEBHOOK_SECRET
printf '\n'
if [[ ! "$STRIPE_WEBHOOK_SECRET" =~ ^whsec_[A-Za-z0-9_]+$ ]]; then
  printf 'Error: Webhook secret must start with whsec_. Nothing was written.\n' >&2
  exit 1
fi

read -r -p '3. Enable Stripe prepaid credits immediately after validation? [Y/n]: ' ENABLE_CHOICE
ENABLE_STRIPE_CREDITS="true"
if [[ "${ENABLE_CHOICE:-Y}" =~ ^[Nn]$ ]]; then
  ENABLE_STRIPE_CREDITS="false"
fi

printf 'Validating Stripe API key against https://api.stripe.com/v1/checkout/sessions?limit=1 ...\n'
HTTP_STATUS="$(
  printf 'header = "Authorization: Bearer %s"\n' "$STRIPE_SECRET_KEY" | \
  curl --silent --show-error -K - -o "$RESP_FILE" -w '%{http_code}' \
    'https://api.stripe.com/v1/checkout/sessions?limit=1'
)"

if [[ "$HTTP_STATUS" != 2* ]]; then
  MESSAGE="$(node -e 'const fs=require("fs");try{const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(x.error?.message||"No Stripe error message returned")}catch{process.stdout.write("No parseable Stripe error message returned")}' "$RESP_FILE")"
  printf 'Stripe API validation failed (HTTP %s): %s\nNothing was written.\n' "$HTTP_STATUS" "$MESSAGE" >&2
  exit 1
fi

if [[ -f "$ENV_FILE" ]]; then
  grep -vE '^(STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|ENABLE_STRIPE_CREDITS)=' "$ENV_FILE" > "$TMP_ENV" || true
else
  : > "$TMP_ENV"
fi

{
  printf '\n# Stripe Checkout prepaid credits (managed locally; never commit)\n'
  printf 'STRIPE_SECRET_KEY=%s\n' "$STRIPE_SECRET_KEY"
  printf 'STRIPE_WEBHOOK_SECRET=%s\n' "$STRIPE_WEBHOOK_SECRET"
  printf 'ENABLE_STRIPE_CREDITS=%s\n' "$ENABLE_STRIPE_CREDITS"
} >> "$TMP_ENV"

chmod 600 "$TMP_ENV"
mv "$TMP_ENV" "$ENV_FILE"

printf '\nRunning offline ledger & webhook signature self-test...\n'
node "$ROOT/scripts/verify-stripe-credits.js" --self-test

printf '\nChecking environment readiness (no secrets printed)...\n'
node "$ROOT/scripts/verify-stripe-credits.js" --check-env

if command -v systemctl >/dev/null 2>&1; then
  printf '\nRestarting phantomoperator.service...\n'
  XDG_RUNTIME_DIR="/run/user/$(id -u)" systemctl --user restart phantomoperator.service
  sleep 2
  XDG_RUNTIME_DIR="/run/user/$(id -u)" systemctl --user is-active phantomoperator.service
fi

printf '\nDone. Stripe prepaid credits configuration updated securely in %s.\n' "$ENV_FILE"
