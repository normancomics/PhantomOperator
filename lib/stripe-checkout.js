'use strict';

// Minimal Stripe Checkout adapter for PhantomOperator prepaid credits.
// All monetary amounts are integer cents; no card data enters this service.
const crypto = require('crypto');

const MIN_CENTS = 50;
const MAX_CENTS = 50_000;

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

async function createCheckout({ purchaseId, amountCents, publicBaseUrl }) {
  assertAmount(amountCents);
  const session = await stripeForm('/v1/checkout/sessions', {
    mode: 'payment',
    success_url: `${publicBaseUrl}/?credits=success`,
    cancel_url: `${publicBaseUrl}/?credits=cancelled`,
    client_reference_id: purchaseId,
    'metadata[purchase_id]': purchaseId,
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][product_data][name]': 'PhantomOperator prepaid credits',
    'line_items[0][price_data][product_data][description]': 'Prepaid balance for authorized PhantomOperator audits',
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

module.exports = { configured, createCheckout, verifyWebhook, assertAmount, MIN_CENTS, MAX_CENTS };
