# Stripe Checkout prepaid-credit activation

**Status:** owner-only production runbook. Do not paste Stripe keys or webhook secrets into chat, source code, GitHub issues, screenshots, or ticket systems.

## Purpose

Enable Stripe-hosted card/Link Checkout for reusable PhantomOperator prepaid credits. This is separate from Base-USDC x402 and does not change the live x402 settlement path.

## Preconditions

- A Stripe account able to create Checkout Sessions in the intended mode (test or live).
- Owner access to the Stripe Dashboard.
- The production service is healthy at `https://freysaai.freysa.dev/health`.
- Persistent filesystem access for the SQLite credit ledger.

## Configuration (local only)

Run the interactive zero-echo setup script directly on the PhantomOperator host over SSH. If you press Enter at the webhook secret prompt, it automatically creates the webhook endpoint via `POST https://api.stripe.com/v1/webhook_endpoints` (`Stripe-Version: 2026-11-18.endive`) for `checkout.session.completed` and `checkout.session.async_payment_succeeded`, captures the returned `whsec_...` signing secret, writes `.env` with `chmod 600`, runs `node scripts/verify-stripe-credits.js`, and restarts `phantomoperator.service`:

```bash
cd /home/nixos/PhantomOperator
./setup-stripe-credits.sh
```

Or manually store the following in the protected local `.env` file (never commit it):

```text
STRIPE_SECRET_KEY=...
STRIPE_WEBHOOK_SECRET=...
ENABLE_STRIPE_CREDITS=true
# optional, if a non-default persistent location is needed:
CREDIT_LEDGER_DB=/secure/persistent/path/credits.sqlite
```

`STRIPE_PROFILE_ID` and `ENABLE_STRIPE_MPP` are not required for ordinary Stripe Checkout credits. Leave MPP disabled unless its separate Stripe Business Network flow is fully tested.

## Stripe Dashboard webhook

Create one endpoint:

```text
https://freysaai.freysa.dev/billing/stripe/webhook
```

Subscribe only to:

```text
checkout.session.completed
checkout.session.async_payment_succeeded
```

Copy the endpoint signing secret into `STRIPE_WEBHOOK_SECRET` locally. The webhook handler verifies the raw signed request and rejects stale or invalid signatures.

## Required owner-authorized end-to-end test

Use Stripe test mode first where available. Do not advertise card payment before every check passes.

1. Restart the supervised PhantomOperator user service after local configuration.
2. Confirm `POST /billing/stripe/checkout` no longer returns `503` for a valid whole-cent amount (for example `500` for $5.00).
3. Open the returned Stripe-hosted Checkout URL and complete an authorized test payment.
4. Confirm Stripe delivered a successful signed webhook.
5. Query `GET /billing/credits/balance` with the returned bearer credit token; confirm the expected balance.
6. Redeem a small authorized audit through `POST /credits/skills/metadata-audit`.
7. Confirm the ledger debited exactly once and the audit result was returned.
8. Repeat the same webhook delivery or endpoint retry; confirm fulfillment is idempotent and credits are not doubled.
9. Test an execution failure; confirm credit is restored atomically.
10. Confirm Base-USDC x402 still returns a normal `402` and remains usable.

## Public-launch rules

Only after the above succeeds:

- add card/credit checkout to the human landing page;
- advertise the Website Privacy Baseline offer;
- disclose that credits are bearer tokens and should be stored like an access credential;
- retain Base-USDC x402 as the agent-native payment option.

## Rollback

Set `ENABLE_STRIPE_CREDITS=false`, restart the user service, and verify:

```text
POST /billing/stripe/checkout → 503
POST /billing/stripe/webhook  → 404
```

Existing credit balances remain durable in the ledger; disabling the rail must not delete records or expose tokens.
