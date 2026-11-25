'use strict';

// Minimal Stripe Checkout adapter for PhantomOperator prepaid credits.
// All monetary amounts are integer cents; no card data enters this service.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MIN_CENTS = 50;
const MAX_CENTS = 50_000;
const STRIPE_API_VERSION = '2026-11-18.endive';

function configured() {
  return Boolean(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_WEBHOOK_SECRET && process.env.ENABLE_STRIPE_CREDITS === 'true');
}

function assertAmount(amountCents) {
  if (!Number.isSafeInteger(amountCents) || amountCents < MIN_CENTS || amountCents > MAX_CENTS) {
    throw new Error(`Credit purchases must be whole cents between ${MIN_CENTS} and ${MAX_CENTS}.`);
  }
}

async function stripeForm(path, fields, idempotencyKey) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) body.set(key, String(value));
  const response = await fetch(`https://api.stripe.com${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Idempotency-Key': idempotencyKey,
    },
    body,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload?.error?.message || `Stripe request failed (${response.status}).`);
  return payload;
}

async function createCheckout({
  purchaseId,
  amountCents,
  publicBaseUrl,
  productName = 'PhantomOperator prepaid credits',
  productDescription = 'Prepaid balance for authorized PhantomOperator audits',
  successPath = '/?credits=success',
  cancelPath = '/?credits=cancelled',
}) {
  assertAmount(amountCents);
  const session = await stripeForm('/v1/checkout/sessions', {
    mode: 'payment',
    success_url: `${publicBaseUrl}${successPath}`,
    cancel_url: `${publicBaseUrl}${cancelPath}`,
    client_reference_id: purchaseId,
    'metadata[purchase_id]': purchaseId,
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][product_data][name]': productName,
    'line_items[0][price_data][product_data][description]': productDescription,
    'line_items[0][price_data][unit_amount]': amountCents,
    'line_items[0][quantity]': 1,
  }, `po-checkout-${purchaseId}`);
  if (!session.id || !session.url) throw new Error('Stripe did not return a checkout session URL.');
  return { id: session.id, url: session.url };
}

function verifyWebhook(rawBody, signature) {
  if (!signature || !process.env.STRIPE_WEBHOOK_SECRET) throw new Error('Missing Stripe webhook signature or secret.');
  const pairs = Object.fromEntries(String(signature).split(',').map((part) => part.split('=', 2)).filter(([k, v]) => k && v));
  const timestamp = pairs.t;
  const signatureV1 = pairs.v1;
  if (!timestamp || !signatureV1 || !/^\d+$/.test(timestamp)) throw new Error('Invalid Stripe-Signature header.');
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp)) > 300) throw new Error('Expired Stripe webhook signature.');
  const expected = crypto.createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET).update(`${timestamp}.${rawBody}`).digest('hex');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(signatureV1, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('Invalid Stripe webhook signature.');
  return JSON.parse(rawBody);
}

async function provisionStripeCredits({
  secretKey,
  webhookSecret,
  enableCredits = true,
  webhookUrl = 'https://freysaai.freysa.dev/billing/stripe/webhook',
  envFilePath = path.join(__dirname, '..', '.env'),
}) {
  const cleanKey = String(secretKey || '').trim();
  if (!/^(rk|sk)_(test|live)_[A-Za-z0-9_]+$/.test(cleanKey)) {
    throw new Error('Stripe key must start with sk_test_, sk_live_, rk_test_, or rk_live_.');
  }

  // 1. Validate key against Stripe Checkout Sessions endpoint
  const checkRes = await fetch('https://api.stripe.com/v1/checkout/sessions?limit=1', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${cleanKey}`,
      'Stripe-Version': STRIPE_API_VERSION,
    },
    signal: AbortSignal.timeout(15000),
  });
  const checkJson = await checkRes.json().catch(() => ({}));
  if (!checkRes.ok) {
    throw new Error(
      (checkJson && checkJson.error && checkJson.error.message) ||
        `Stripe key validation failed (HTTP ${checkRes.status}).`
    );
  }

  // 2. Use provided whsec_ or auto-create via POST /v1/webhook_endpoints
  let finalWebhookSecret = String(webhookSecret || '').trim();
  let webhookEndpointId = '';
  let livemode = cleanKey.includes('_live_');

  if (!finalWebhookSecret) {
    const form = new URLSearchParams();
    form.append('url', webhookUrl);
    form.append('description', 'PhantomOperator prepaid credits fulfillment webhook');
    form.append('enabled_events[]', 'checkout.session.completed');
    form.append('enabled_events[]', 'checkout.session.async_payment_succeeded');

    const whRes = await fetch('https://api.stripe.com/v1/webhook_endpoints', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${cleanKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Stripe-Version': STRIPE_API_VERSION,
      },
      body: form,
      signal: AbortSignal.timeout(15000),
    });
    const whJson = await whRes.json().catch(() => ({}));
    if (!whRes.ok) {
      throw new Error(
        (whJson && whJson.error && whJson.error.message) ||
          `Auto-creating Stripe webhook endpoint failed (HTTP ${whRes.status}).`
      );
    }
    if (!whJson.secret || !/^whsec_[A-Za-z0-9_]+$/.test(whJson.secret)) {
      throw new Error('Stripe did not return a valid whsec_ signing secret.');
    }
    finalWebhookSecret = whJson.secret;
    webhookEndpointId = whJson.id || '';
    if (typeof whJson.livemode === 'boolean') livemode = whJson.livemode;
  } else if (!/^whsec_[A-Za-z0-9_]+$/.test(finalWebhookSecret)) {
    throw new Error('Webhook signing secret must start with whsec_.');
  }

  // 3. Persist atomically to .env (chmod 600) without echoing secrets
  const enabledStr = enableCredits ? 'true' : 'false';
  let existingLines = [];
  if (fs.existsSync(envFilePath)) {
    existingLines = fs
      .readFileSync(envFilePath, 'utf8')
      .split(/\r?\n/)
      .filter(
        (line) =>
          !/^(STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|STRIPE_WEBHOOK_ENDPOINT_ID|ENABLE_STRIPE_CREDITS)=/.test(
            line
          )
      );
  }
  existingLines.push('# Stripe Checkout prepaid credits (managed locally; never commit)');
  existingLines.push(`STRIPE_SECRET_KEY=${cleanKey}`);
  existingLines.push(`STRIPE_WEBHOOK_SECRET=${finalWebhookSecret}`);
  if (webhookEndpointId) {
    existingLines.push(`STRIPE_WEBHOOK_ENDPOINT_ID=${webhookEndpointId}`);
  }
  existingLines.push(`ENABLE_STRIPE_CREDITS=${enabledStr}`);

  const tmpPath = `${envFilePath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmpPath, existingLines.join('\n') + '\n', { mode: 0o600 });
  fs.chmodSync(tmpPath, 0o600);
  fs.renameSync(tmpPath, envFilePath);

  // 4. Activate in current running process immediately
  process.env.STRIPE_SECRET_KEY = cleanKey;
  process.env.STRIPE_WEBHOOK_SECRET = finalWebhookSecret;
  if (webhookEndpointId) process.env.STRIPE_WEBHOOK_ENDPOINT_ID = webhookEndpointId;
  process.env.ENABLE_STRIPE_CREDITS = enabledStr;

  return {
    configured: configured(),
    mode: livemode ? 'live' : 'test',
    webhookUrl,
    webhookEndpointId: webhookEndpointId || null,
    autoCreatedWebhook: Boolean(webhookEndpointId),
    enableStripeCredits: enableCredits,
  };
}

module.exports = {
  configured,
  createCheckout,
  verifyWebhook,
  assertAmount,
  provisionStripeCredits,
  MIN_CENTS,
  MAX_CENTS,
};
