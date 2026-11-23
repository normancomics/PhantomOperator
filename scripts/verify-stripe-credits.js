#!/usr/bin/env node
'use strict';

/**
 * scripts/verify-stripe-credits.js
 *
 * Verifies the Stripe Checkout prepaid-credit & $19 Website Privacy Baseline
 * lifecycle end-to-end without printing any secret keys.
 *
 * Modes:
 *   node scripts/verify-stripe-credits.js --self-test
 *   node scripts/verify-stripe-credits.js --check-env
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { CreditLedger } = require('../lib/credits');
const stripeCheckout = require('../lib/stripe-checkout');

function checkEnv() {
  const hasSecretKey = Boolean(
    process.env.STRIPE_SECRET_KEY && /^sk_(test|live)_/.test(process.env.STRIPE_SECRET_KEY)
  );
  const mode = hasSecretKey
    ? process.env.STRIPE_SECRET_KEY.startsWith('sk_live_')
      ? 'live'
      : 'test'
    : 'unconfigured';
  const hasWebhookSecret = Boolean(
    process.env.STRIPE_WEBHOOK_SECRET && /^whsec_/.test(process.env.STRIPE_WEBHOOK_SECRET)
  );
  const enabled = process.env.ENABLE_STRIPE_CREDITS === 'true';

  console.log(
    JSON.stringify(
      {
        stripeSecretKeyConfigured: hasSecretKey,
        stripeMode: mode,
        stripeWebhookSecretConfigured: hasWebhookSecret,
        enableStripeCreditsFlag: enabled,
        readyForActivation: hasSecretKey && hasWebhookSecret && enabled,
        webhookUrl: 'https://freysaai.freysa.dev/billing/stripe/webhook',
        requiredEvents: [
          'checkout.session.completed',
          'checkout.session.async_payment_succeeded',
        ],
      },
      null,
      2
    )
  );
}

function runSelfTest() {
  const tmpDb = path.join(os.tmpdir(), `stripe-credits-selftest-${process.pid}-${Date.now()}.sqlite`);
  const prevSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const testWebhookSecret = 'whsec_selftest_' + crypto.randomBytes(16).toString('hex');
  process.env.STRIPE_WEBHOOK_SECRET = testWebhookSecret;

  try {
    // 1. Bounds check ($0.50 to $500.00)
    assert.throws(() => stripeCheckout.assertAmount(49), /between 50 and 50000/);
    assert.throws(() => stripeCheckout.assertAmount(50001), /between 50 and 50000/);
    stripeCheckout.assertAmount(1900); // $19.00 Website Privacy Baseline

    // 2. Create pending purchase & attach Stripe Checkout session
    const ledger = new CreditLedger(tmpDb);
    const purchaseId = crypto.randomBytes(24).toString('base64url');
    const token = ledger.createToken();
    ledger.createPendingStripePurchase(purchaseId, token, 1900);
    const sessionId = 'cs_test_a1B2c3D4e5F6g7H8i9J0';
    ledger.attachStripeSession(purchaseId, sessionId);

    // Unfulfilled token has no balance yet
    assert.strictEqual(ledger.balance(token), null);

    // 3. Signed webhook verification + fulfillment
    const rawEvent = JSON.stringify({
      id: 'evt_test_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: sessionId,
          payment_status: 'paid',
          amount_total: 1900,
          metadata: { purchase_id: purchaseId },
        },
      },
    });
    const ts = Math.floor(Date.now() / 1000);
    const sigHex = crypto
      .createHmac('sha256', testWebhookSecret)
      .update(`${ts}.${rawEvent}`)
      .digest('hex');
    const verifiedEvent = stripeCheckout.verifyWebhook(rawEvent, `t=${ts},v1=${sigHex}`);
    assert.strictEqual(verifiedEvent.type, 'checkout.session.completed');

    const firstFulfill = ledger.fulfillStripePurchase(purchaseId, sessionId, 1900);
    assert.strictEqual(firstFulfill, true);

    // 4. Idempotent webhook replay must not double-credit
    const duplicateFulfill = ledger.fulfillStripePurchase(purchaseId, sessionId, 1900);
    assert.strictEqual(duplicateFulfill, false);
    assert.strictEqual(ledger.balance(token).balanceCents, 1900);

    // 5. Redeem $19.00 Website Privacy Baseline (1900 cents)
    assert.strictEqual(ledger.debit(token, 1900, 'website-privacy-baseline'), true);
    assert.strictEqual(ledger.balance(token).balanceCents, 0);

    // 6. Second debit with 0 balance fails
    assert.strictEqual(ledger.debit(token, 5, 'metadata-audit'), false);

    // 7. Atomic refund on execution failure restores balance
    ledger.refund(token, 1900, 'website-privacy-baseline');
    assert.strictEqual(ledger.balance(token).balanceCents, 1900);

    console.log('Stripe Checkout prepaid-credit & $19 Website Privacy Baseline self-test PASSED (7/7 checks).');
  } finally {
    if (prevSecret === undefined) delete process.env.STRIPE_WEBHOOK_SECRET;
    else process.env.STRIPE_WEBHOOK_SECRET = prevSecret;
    for (const suffix of ['', '-wal', '-shm']) {
      try {
        fs.unlinkSync(tmpDb + suffix);
      } catch {
        /* ignore */
      }
    }
  }
}

if (process.argv.includes('--check-env')) {
  checkEnv();
} else {
  runSelfTest();
}
