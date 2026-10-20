/**
 * lib/x402.js
 *
 * Minimal x402 v2 "exact" scheme on Base mainnet, plain USDC, using the keyless
 * PayAI facilitator (no API keys, no accounts). Ported from repo-discovery-agent.
 * Flow: verify payment -> run skill -> settle only if the skill succeeded (< 400).
 */
'use strict';

const PAY_TO      = process.env.PAY_TO || '0x3d95D4A6DbaE0Cd0643a82b13A13b08921D6ADf7';
const FACILITATOR = process.env.FACILITATOR_URL || 'https://facilitator.payai.network';
const USDC_BASE   = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const NETWORK     = 'eip155:8453';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
const atomic = (usd) => String(Math.round(usd * 1e6));

function requirements(route) {
  return {
    scheme: 'exact', network: NETWORK, amount: atomic(route.priceUsd), asset: USDC_BASE, payTo: PAY_TO,
    maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' },
  };
}

function paymentRequired(route, base, error) {
  return {
    x402Version: 2, error,
    resource: { url: base + route.path, description: route.description, mimeType: 'application/json' },
    accepts: [requirements(route)],
    extensions: {
      bazaar: {
        info: {
          input: { type: 'http', method: 'POST', bodyType: 'json', body: route.inputExample },
          output: { type: 'json', example: route.outputExample },
        },
        schema: {
          type: 'object',
          properties: { input: { type: 'object', properties: { body: route.bodySchema } } },
        },
      },
    },
  };
}

async function facilitator(op, payload, route) {
  const res = await fetch(`${FACILITATOR}/${op}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ x402Version: 2, paymentPayload: payload, paymentRequirements: requirements(route) }),
    signal: AbortSignal.timeout(30000),
  });
  return res.json();
}

/** Returns { ok:true, payload } or { ok:false, status, body, headers } */
async function verify(req, route, base) {
  const deny = (err) => {
    const p = paymentRequired(route, base, err);
    return { ok: false, status: 402, body: p, headers: { 'PAYMENT-REQUIRED': b64(p) } };
  };
  const sig = req.headers['payment-signature'] || req.headers['x-payment'];
  if (!sig) return deny('Payment required');
  let payload;
  try { payload = JSON.parse(Buffer.from(String(sig), 'base64').toString('utf8')); }
  catch { return deny('Malformed payment header'); }
  try {
    const v = await facilitator('verify', payload, route);
    if (!v.isValid) return deny(v.invalidReason || 'Invalid payment');
  } catch {
    return { ok: false, status: 502, body: { error: 'Facilitator verify failed' }, headers: {} };
  }
  return { ok: true, payload };
}

/** Returns { ok:true, headers } or { ok:false, status, body } */
async function settle(payload, route) {
  try {
    const s = await facilitator('settle', payload, route);
    if (!s.success) return { ok: false, status: 402, body: { error: 'Settlement failed', detail: s } };
    return { ok: true, headers: { 'PAYMENT-RESPONSE': b64(s), 'X-PAYMENT-RESPONSE': b64(s) } };
  } catch {
    return { ok: false, status: 502, body: { error: 'Facilitator settle failed' } };
  }
}

module.exports = { PAY_TO, FACILITATOR, USDC_BASE, NETWORK, atomic, requirements, paymentRequired, verify, settle };
