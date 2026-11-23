#!/usr/bin/env bash
# Interactive, local-only Stripe Checkout prepaid-credit & $19 Website Privacy
# Baseline setup for PhantomOperator.
#
# Supports automatic webhook endpoint creation via POST /v1/webhook_endpoints
# (Stripe-Version: 2026-11-18.endive) so you only need to paste STRIPE_SECRET_KEY!
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/.env"
TMP_ENV="$(mktemp "$ROOT/.env.stripe-credits.XXXXXX")"
RESP_FILE="$(mktemp)"
WEBHOOK_RESP_FILE="$(mktemp)"
trap 'rm -f "$TMP_ENV" "$RESP_FILE" "$WEBHOOK_RESP_FILE"' EXIT

WEBHOOK_URL="${PUBLIC_WEBHOOK_URL:-https://freysaai.freysa.dev/billing/stripe/webhook}"
STRIPE_API_VERSION="2026-11-18.endive"

printf '=================================================================\n'
printf ' PhantomOperator — Stripe Prepaid Credits & $19 Baseline Setup\n'
printf '=================================================================\n'
printf 'Target webhook URL: %s\n' "$WEBHOOK_URL"
printf 'Events: checkout.session.completed, checkout.session.async_payment_succeeded\n\n'

read -r -s -p '1. Paste Stripe Secret Key (sk_test_... or sk_live_...; input hidden): ' STRIPE_SECRET_KEY
printf '\n'
if [[ ! "$STRIPE_SECRET_KEY" =~ ^(rk|sk)_(test|live)_[A-Za-z0-9_]+$ ]]; then
  printf 'Error: Key must start with sk_test_, sk_live_, rk_test_, or rk_live_. Nothing was written.\n' >&2
  exit 1
fi

printf 'Validating Stripe API key against https://api.stripe.com/v1/checkout/sessions?limit=1 ...\n'
HTTP_STATUS="$(
  printf 'header = "Authorization: Bearer %s"\n' "$STRIPE_SECRET_KEY" | \
  curl --silent --show-error -K - -o "$RESP_FILE" -w '%{http_code}' \
    -H "Stripe-Version: $STRIPE_API_VERSION" \
    'https://api.stripe.com/v1/checkout/sessions?limit=1'
)"

if [[ "$HTTP_STATUS" != 2* ]]; then
  MESSAGE="$(node -e 'const fs=require("fs");try{const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(x.error?.message||"No Stripe error message returned")}catch{process.stdout.write("No parseable Stripe error message returned")}' "$RESP_FILE")"
  printf 'Stripe API validation failed (HTTP %s): %s\nNothing was written.\n' "$HTTP_STATUS" "$MESSAGE" >&2
  exit 1
fi

read -r -s -p '2. Paste existing Webhook Secret (whsec_...) OR press Enter to auto-create via POST /v1/webhook_endpoints: ' STRIPE_WEBHOOK_SECRET
printf '\n'

WEBHOOK_ENDPOINT_ID=""
if [[ -z "${STRIPE_WEBHOOK_SECRET:-}" ]]; then
  printf 'Creating webhook endpoint via POST https://api.stripe.com/v1/webhook_endpoints ...\n'
  WH_STATUS="$(
    printf 'header = "Authorization: Bearer %s"\n' "$STRIPE_SECRET_KEY" | \
    curl --silent --show-error -K - -o "$WEBHOOK_RESP_FILE" -w '%{http_code}' \
      -X POST 'https://api.stripe.com/v1/webhook_endpoints' \
      -H "Stripe-Version: $STRIPE_API_VERSION" \
      -d 'enabled_events[]=checkout.session.completed' \
      -d 'enabled_events[]=checkout.session.async_payment_succeeded' \
      --data-urlencode "url=$WEBHOOK_URL" \
      --data-urlencode 'description=PhantomOperator prepaid credits fulfillment webhook'
  )"
  if [[ "$WH_STATUS" != 2* ]]; then
    MESSAGE="$(node -e 'const fs=require("fs");try{const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(x.error?.message||"No Stripe error message returned")}catch{process.stdout.write("No parseable Stripe error message returned")}' "$WEBHOOK_RESP_FILE")"
    printf 'Auto-creating webhook endpoint failed (HTTP %s): %s\n' "$WH_STATUS" "$MESSAGE" >&2
    printf 'Tip: Use a full sk_test_ / sk_live_ key (or an rk_ key with Webhook Endpoints write permission), or paste whsec_ manually.\nNothing was written.\n' >&2
    exit 1
  fi
  STRIPE_WEBHOOK_SECRET="$(node -e 'const fs=require("fs");const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(!/^whsec_/.test(x.secret||""))process.exit(2);process.stdout.write(x.secret)' "$WEBHOOK_RESP_FILE")" || {
    printf 'Stripe did not return a whsec_ signing secret. Nothing was written.\n' >&2
    exit 1
  }
  WEBHOOK_ENDPOINT_ID="$(node -e 'const fs=require("fs");const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(x.id||"")' "$WEBHOOK_RESP_FILE")"
  LIVEMODE="$(node -e 'const fs=require("fs");const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(String(Boolean(x.livemode)))' "$WEBHOOK_RESP_FILE")"
  printf 'Created Stripe webhook endpoint: %s (livemode=%s)\n' "$WEBHOOK_ENDPOINT_ID" "$LIVEMODE"
else
  if [[ ! "$STRIPE_WEBHOOK_SECRET" =~ ^whsec_[A-Za-z0-9_]+$ ]]; then
    printf 'Error: Webhook secret must start with whsec_. Nothing was written.\n' >&2
    exit 1
  fi
fi

read -r -p '3. Enable Stripe prepaid credits immediately after validation? [Y/n]: ' ENABLE_CHOICE
ENABLE_STRIPE_CREDITS="true"
if [[ "${ENABLE_CHOICE:-Y}" =~ ^[Nn]$ ]]; then
  ENABLE_STRIPE_CREDITS="false"
fi

if [[ -f "$ENV_FILE" ]]; then
  grep -vE '^(STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|STRIPE_WEBHOOK_ENDPOINT_ID|ENABLE_STRIPE_CREDITS)=' "$ENV_FILE" > "$TMP_ENV" || true
else
  : > "$TMP_ENV"
fi

{
  printf '\n# Stripe Checkout prepaid credits (managed locally; never commit)\n'
  printf 'STRIPE_SECRET_KEY=%s\n' "$STRIPE_SECRET_KEY"
  printf 'STRIPE_WEBHOOK_SECRET=%s\n' "$STRIPE_WEBHOOK_SECRET"
  if [[ -n "$WEBHOOK_ENDPOINT_ID" ]]; then
    printf 'STRIPE_WEBHOOK_ENDPOINT_ID=%s\n' "$WEBHOOK_ENDPOINT_ID"
  fi
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
