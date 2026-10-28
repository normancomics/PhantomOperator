/**
 * lib/x402.js
 *
 * Dual x402 v1/v2 "exact" scheme on Base mainnet (eip155:8453), native USDC,
 * using Coinbase CDP's authenticated x402 facilitator in production, with
 * full Coinbase CDP Bazaar + x402scan discovery metadata extensions.
 *
 * Default PAY_TO is PhantomOperator's operational wallet:
 *   0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6
 */
'use strict';

const DEFAULT_PAY_TO = '0xC5f20C3Ad7B730B34620ecF39c2C5681482A6Cd6';
const FACILITATOR    = process.env.FACILITATOR_URL || 'https://api.cdp.coinbase.com/platform/v2/x402';
const USDC_BASE      = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const NETWORK        = 'eip155:8453';

function getPayTo() {
  const envAddr =
    process.env.PAY_TO ||
    process.env.PAYMENT_RECEIVER_ADDRESS ||
    process.env.PHANTOM_OPERATOR_ADDRESS ||
    process.env.SOVEREIGN_AGENT_ADDRESS;
  // Never fall back to builder personal address 0x3d95...
  if (envAddr && envAddr.toLowerCase() !== '0x3d95d4a6dbae0cd0643a82b13a13b08921d6adf7') {
    return envAddr;
  }
  return DEFAULT_PAY_TO;
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
const atomic = (usd) => String(Math.round(Number(usd) * 1e6));

function requirements(route, base = '') {
  const payTo = getPayTo();
  const amt = atomic(route.priceUsd);
  return {
    scheme: 'exact',
    network: NETWORK,
    amount: amt,
    maxAmountRequired: amt,
    resource: base ? base + route.path : route.path,
    description: route.description,
    mimeType: 'application/json',
    asset: USDC_BASE,
    payTo,
    maxTimeoutSeconds: 300,
    extra: { name: 'USD Coin', version: '2' },
    outputSchema: {
      input: {
        type: 'http',
        method: 'POST',
        bodyType: 'json',
        bodyFields: (route.bodySchema && route.bodySchema.properties) || {},
      },
      output: route.outputExample || { type: 'object' },
    },
  };
}

function paymentRequired(route, base, error = 'Payment Required') {
  const reqObj = requirements(route, base);
  return {
    x402Version: 2,
    error,
    resource: {
      url: base + route.path,
      description: route.description,
      mimeType: 'application/json',
    },
    accepts: [reqObj],
    paymentRequirements: [reqObj],
    extensions: {
      bazaar: {
        info: {
          input: { type: 'http', method: 'POST', bodyType: 'json', body: route.inputExample || {} },
          output: { type: 'json', example: route.outputExample || {} },
        },
        schema: {
          type: 'object',
          properties: { input: { type: 'object', properties: { body: route.bodySchema || {} } } },
        },
      },
    },
  };
}

let cdpFacilitator;
function getFacilitator() {
  if (cdpFacilitator) return cdpFacilitator;
  // CDP API credentials are mandatory in production. Do not silently fall back
  // to an unauthenticated third-party facilitator, because Bazaar requires CDP
  // settlement for discovery eligibility.
  const { createCdpFacilitatorClient } = require('@coinbase/cdp-sdk/x402');
  cdpFacilitator = createCdpFacilitatorClient();
  return cdpFacilitator;
}

async function facilitator(op, payload, route, base) {
  const client = getFacilitator();
  const paymentRequirements = requirements(route, base);
  if (op === 'verify') return client.verify(payload, paymentRequirements);
  if (op === 'settle') return client.settle(payload, paymentRequirements);
  throw new Error(`Unsupported facilitator operation: ${op}`);
}

/**
 * Verify an incoming x402 request.
 * Supports x402 v2 base64 JSON in `PAYMENT-SIGNATURE` or `X-PAYMENT`.
 * Raw transaction hashes are deliberately not accepted in production: a hash alone
 * does not prove that this endpoint's payment requirement was authorized or settled.
 */
async function verify(req, route, base) {
  const deny = (err) => {
    const p = paymentRequired(route, base, err);
    return { ok: false, status: 402, body: p, headers: { 'PAYMENT-REQUIRED': b64(p) } };
  };

  const sig = req.headers['payment-signature'] || req.headers['x-payment'];
  if (!sig) return deny('X-Payment header required');

  const rawSig = String(sig).trim();
  if (!rawSig) return deny('Empty X-Payment header');

  // Test-only escape hatch. Never enable this in the running public service.
  if (process.env.NODE_ENV === 'test' && /^0x[0-9a-fA-F]{64}$/.test(rawSig)) {
    return { ok: true, payload: { txHash: rawSig, directProof: true } };
  }

  let payload;
  try {
    if (rawSig.startsWith('{')) {
      payload = JSON.parse(rawSig);
    } else {
      payload = JSON.parse(Buffer.from(rawSig, 'base64').toString('utf8'));
    }
  } catch {
    return deny('Malformed payment header');
  }

  // Only tests may use a synthetic transaction proof; production always asks a facilitator.
  if (process.env.NODE_ENV === 'test' && payload && (payload.txHash || payload.transactionHash) && !payload.payload && !payload.signature) {
    return { ok: true, payload: { ...payload, directProof: true } };
  }

  try {
    const v = await facilitator('verify', payload, route, base);
    if (!v || !v.isValid) return deny((v && v.invalidReason) || 'Invalid payment');
  } catch {
    return { ok: false, status: 502, body: { error: 'Facilitator verify failed' }, headers: {} };
  }
  return { ok: true, payload };
}

async function settle(payload, route, base) {
  if (payload && payload.directProof) {
    const receipt = { success: true, transaction: payload.txHash || payload.transactionHash, network: NETWORK };
    return { ok: true, headers: { 'PAYMENT-RESPONSE': b64(receipt), 'X-PAYMENT-RESPONSE': b64(receipt) } };
  }
  try {
    const s = await facilitator('settle', payload, route, base);
    if (!s || !s.success) return { ok: false, status: 402, body: { error: 'Settlement failed', detail: s } };
    return { ok: true, headers: { 'PAYMENT-RESPONSE': b64(s), 'X-PAYMENT-RESPONSE': b64(s) } };
  } catch {
    return { ok: false, status: 502, body: { error: 'Facilitator settle failed' } };
  }
}

module.exports = {
  get PAY_TO() { return getPayTo(); },
  DEFAULT_PAY_TO,
  FACILITATOR,
  USDC_BASE,
  NETWORK,
  atomic,
  requirements,
  paymentRequired,
  verify,
  settle,
};
